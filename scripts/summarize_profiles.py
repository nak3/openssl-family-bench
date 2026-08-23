#!/usr/bin/env python3

import argparse
import csv
import json
import math
from pathlib import Path
import re
import statistics


CASE_PATTERN = re.compile(
    r"^(?P<backend>.+)__(?P<architecture>.+)__"
    r"(?P<category>.+)__(?P<subject>.+)__"
    r"(?P<operation>.+)__(?P<size>\d+)$"
)
HOTSPOT_PATTERN = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)%\s+(.+?)\s*$")
SUSPICIOUS_CHACHA_PREFIXES = (
    "ASN1_", "CBS_", "CAST_", "Camellia_", "ERR_load_",
)
BACKEND_LABELS = {
    "openssl": "OpenSSL",
    "libressl": "LibreSSL",
    "libressl-patched": "Patched",
}
BACKEND_PRIORITY = {"openssl": 0, "libressl": 1, "libressl-patched": 2}
CATEGORY_PRIORITY = {"aead": 0, "primitive": 1, "tls": 2}


def parse_case(path):
    suffix = ".stat.csv"
    match = CASE_PATTERN.match(path.name[:-len(suffix)])
    if match is None:
        raise ValueError(f"unexpected profile filename: {path}")
    result = match.groupdict()
    result["size"] = int(result["size"])
    return result


def parse_number(text):
    try:
        return float(text.strip())
    except ValueError:
        return None


def parse_stat(path):
    counters = {}
    with path.open(encoding="utf-8") as stream:
        for row in csv.reader(stream):
            if len(row) < 3 or row[0].lstrip().startswith("#"):
                continue
            value = parse_number(row[0])
            unit = row[1].strip().lower()
            event = row[2].strip()
            if value is not None and event:
                if event in {"task-clock", "cpu-clock"}:
                    if unit in {"", "ns", "nanoseconds"}:
                        value /= 1_000_000.0
                    elif unit in {"us", "usec", "microseconds"}:
                        value /= 1_000.0
                    elif unit in {"s", "sec", "seconds"}:
                        value *= 1_000.0
                counters[event] = value
    return counters


def parse_benchmark(path):
    if not path.exists():
        return None
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    for field, unit in (
        ("mib_per_second", "MiB/s"),
        ("handshakes_per_second", "handshakes/s"),
        ("iterations", "iterations"),
    ):
        values = [row[field] for row in rows if isinstance(row.get(field), (int, float))]
        if values:
            return {"value": statistics.median(values), "unit": unit}
    return None


def parse_hotspots(path, profiler, limit=10):
    hotspots = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if profiler == "gprof":
                fields = line.split()
                if len(fields) < 4:
                    continue
                try:
                    percent = float(fields[0])
                    float(fields[1])
                    float(fields[2])
                except ValueError:
                    continue
                if percent > 0:
                    hotspots.append((percent, fields[-1]))
            else:
                match = HOTSPOT_PATTERN.match(line)
                if match is not None:
                    hotspots.append((float(match.group(1)), match.group(2)))
    return hotspots[:limit]


def escape(text):
    return str(text).replace("|", "\\|")


def format_counter(value):
    if value is None:
        return "—"
    if abs(value) >= 1000:
        return f"{value:,.0f}"
    return f"{value:,.2f}"


def format_measurement(measurement):
    if measurement is None:
        return "—"
    value = measurement["value"]
    unit = measurement["unit"]
    if unit == "iterations":
        return f"{value:,.0f} {unit}"
    if value >= 1000:
        return f"{value:,.0f} {unit}"
    return f"{value:,.1f} {unit}"


def format_ratio(numerator, denominator):
    if numerator is None or denominator is None:
        return "—"
    if numerator["unit"] != denominator["unit"] or denominator["value"] == 0:
        return "—"
    return f"**{numerator['value'] / denominator['value']:.2f}×**"


def median_ratio(keys, measurements, numerator_backend, denominator_backend):
    ratios = []
    for key in keys:
        numerator = measurements.get((key, numerator_backend))
        denominator = measurements.get((key, denominator_backend))
        if (
            numerator is not None
            and denominator is not None
            and numerator["unit"] == denominator["unit"]
            and denominator["value"] != 0
        ):
            ratios.append(numerator["value"] / denominator["value"])
    if not ratios:
        return "—"
    return f"**{statistics.median(ratios):.2f}×**"


def case_sort_key(case):
    operation_priority = {"handshake": 0, "transfer": 1}
    return (
        case["subject"],
        operation_priority.get(case["operation"], 2),
        case["operation"],
        case["size"],
    )


def case_size_label(case):
    if case["category"] == "tls" and case["operation"] == "handshake":
        return "—"
    return f"{case['size']:,} B"


def render_overview(lines, selected):
    measurements = {}
    cases_by_key = {}
    for case, stat_path in selected:
        stem = stat_path.name[:-len(".stat.csv")]
        benchmark_path = stat_path.with_name(stem + ".benchmark.jsonl")
        key = (case["category"], case["subject"], case["operation"], case["size"])
        cases_by_key[key] = case
        measurements[(key, case["backend"])] = parse_benchmark(benchmark_path)

    available = [value for value in measurements.values() if value is not None]
    lines.extend([
        "## Performance comparison",
        "",
        ("> Higher values are better. Ratios above 1.00× favor the numerator. "
         "These runs use instrumented binaries, so use the Benchmark workflow "
         "for final performance numbers."),
        "",
    ])
    if not available:
        lines.extend([
            "> No captured benchmark results were found. This is expected for profiles",
            "> produced before benchmark-result capture was added.",
            "",
        ])
        return

    categories = sorted(
        {key[0] for key in cases_by_key},
        key=lambda name: (CATEGORY_PRIORITY.get(name, 99), name),
    )
    lines.extend([
        "### Quick comparison",
        "",
        "| Workload | Median OpenSSL / LibreSSL | Median patched / baseline |",
        "| --- | ---: | ---: |",
    ])
    for category in categories:
        keys = [key for key in cases_by_key if key[0] == category]
        lines.append(
            f"| `{category.upper()}` | "
            f"{median_ratio(keys, measurements, 'openssl', 'libressl')} | "
            f"{median_ratio(keys, measurements, 'libressl-patched', 'libressl')} |"
        )
    lines.extend([
        "",
        "> The medians summarize case-by-case ratios; expand the tables below before",
        "> drawing conclusions about a specific cipher, operation, or message size.",
        "",
    ])
    for category in categories:
        keys = [key for key in cases_by_key if key[0] == category]
        keys.sort(key=lambda key: case_sort_key(cases_by_key[key]))
        category_backends = {
            backend for key in keys for backend in BACKEND_LABELS
            if measurements.get((key, backend)) is not None
        }
        show_patched = "libressl-patched" in category_backends
        lines.extend([f"### {category.upper()}", ""])
        headers = ["Case", "Operation", "Size", "OpenSSL", "LibreSSL"]
        separators = ["---", "---", "---:", "---:", "---:"]
        if show_patched:
            headers.append("Patched")
            separators.append("---:")
        headers.append("OpenSSL / LibreSSL")
        separators.append("---:")
        if show_patched:
            headers.append("Patched / baseline")
            separators.append("---:")
        lines.extend([
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join(separators) + " |",
        ])
        for key in keys:
            case = cases_by_key[key]
            openssl = measurements.get((key, "openssl"))
            libressl = measurements.get((key, "libressl"))
            patched = measurements.get((key, "libressl-patched"))
            row = [
                f"`{escape(case['subject'])}`",
                f"`{escape(case['operation'])}`",
                case_size_label(case),
                format_measurement(openssl),
                format_measurement(libressl),
            ]
            if show_patched:
                row.append(format_measurement(patched))
            row.append(format_ratio(openssl, libressl))
            if show_patched:
                row.append(format_ratio(patched, libressl))
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")


def suspicious_chacha_symbols(case, profiler, hotspots):
    if profiler != "gprof" or "CHACHA20" not in case["subject"]:
        return []
    if case["category"] == "tls" and case["operation"] == "handshake":
        return []
    return [
        label for percent, label in hotspots
        if percent >= 5.0 and label.startswith(SUSPICIOUS_CHACHA_PREFIXES)
    ]


def render_case(lines, stat_path):
    case = parse_case(stat_path)
    stem = stat_path.name[:-len(".stat.csv")]
    mode_path = stat_path.with_name(stem + ".mode")
    sampling_path = stat_path.with_name(stem + ".sampling")
    report_path = stat_path.with_name(stem + ".report.txt")
    mode = mode_path.read_text(encoding="utf-8").strip()
    sampling = (
        sampling_path.read_text(encoding="utf-8").strip()
        if sampling_path.exists()
        else "unknown"
    )
    counters = parse_stat(stat_path)
    hotspots = parse_hotspots(report_path, sampling)
    suspicious_symbols = suspicious_chacha_symbols(case, sampling, hotspots)

    size_label = (
        "handshake"
        if case["category"] == "tls" and case["operation"] == "handshake"
        else f"{case['size']} bytes"
    )
    lines.extend([
        f"##### {case['subject']} {case['operation']} — {size_label}",
        "",
        f"Counter mode: `{mode}`",
        (
            "Profiler: `gprof` (PMU-independent fallback)"
            if sampling == "gprof"
            else f"Sampling event: `{sampling}`"
        ),
        "",
    ])
    if suspicious_symbols:
        labels = ", ".join(f"`{escape(label)}`" for label in suspicious_symbols)
        lines.extend([
            f"> ⚠️ Possible gprof symbol misattribution: {labels}.",
            "> Treat the percentage as unresolved ChaCha20 work until the raw profile is verified.",
            "",
        ])

    cycles = counters.get("cycles")
    instructions = counters.get("instructions")
    ipc = instructions / cycles if cycles else None
    counter_rows = [
        ("Cycles", cycles),
        ("Instructions", instructions),
        ("Instructions/cycle", ipc),
        ("Branches", counters.get("branches")),
        ("Branch misses", counters.get("branch-misses")),
        ("Cache references", counters.get("cache-references")),
        ("Cache misses", counters.get("cache-misses")),
        ("Task clock (ms)", counters.get("task-clock")),
        ("CPU clock (ms)", counters.get("cpu-clock")),
    ]
    counter_rows = [(name, value) for name, value in counter_rows if value is not None]
    lines.extend(["| Counter | Value |", "| --- | ---: |"])
    if counter_rows:
        lines.extend(
            f"| {name} | {format_counter(value)} |"
            for name, value in counter_rows
        )
    else:
        lines.append("| Status | perf returned no usable counters |")
    lines.append("")

    lines.extend(["| Hotspot share | Symbol / object |", "| --- | --- |"])
    if hotspots:
        for percent, label in hotspots:
            blocks = "█" * max(1, min(20, math.ceil(percent / 5.0)))
            lines.append(f"| `{blocks:<20}` {percent:5.1f}% | `{escape(label)}` |")
    else:
        if sampling == "unavailable":
            lines.append("| — | Sampling is not supported by this runner PMU |")
        else:
            lines.append("| — | No samples reported |")
    lines.append("")


def render(paths, title):
    stat_paths = []
    for path_text in paths:
        path = Path(path_text)
        stat_paths.extend(path.rglob("*.stat.csv") if path.is_dir() else [path])
    if not stat_paths:
        raise ValueError("no perf stat files found")

    cases = [(parse_case(path), path) for path in stat_paths]
    architecture_priority = {"x86_64": 0, "arm64": 1}
    architectures = sorted(
        {case["architecture"] for case, _ in cases},
        key=lambda name: (architecture_priority.get(name, 99), name),
    )
    lines = [
        f"# {title}",
        "",
        "> Hotspots use perf sampling when available and a PMU-independent gprof fallback otherwise.",
        "",
    ]
    for architecture in architectures:
        lines.extend([f"## Architecture: `{architecture}`", ""])
        architecture_cases = [
            (case, path) for case, path in cases
            if case["architecture"] == architecture
        ]
        render_overview(lines, architecture_cases)
        lines.extend(["## Detailed counters and hotspots", ""])
        categories = sorted({
            case["category"] for case, _ in cases
            if case["architecture"] == architecture
        }, key=lambda name: (CATEGORY_PRIORITY.get(name, 99), name))
        for category in categories:
            lines.extend([f"### Category: `{category.upper()}`", ""])
            backends = sorted({
                case["backend"] for case, _ in cases
                if case["architecture"] == architecture
                and case["category"] == category
            }, key=lambda name: (BACKEND_PRIORITY.get(name, 99), name))
            for backend in backends:
                selected = [
                    (case, path) for case, path in cases
                    if case["architecture"] == architecture
                    and case["category"] == category
                    and case["backend"] == backend
                ]
                selected.sort(key=lambda item: (
                    item[0]["subject"], item[0]["operation"], item[0]["size"]
                ))
                label = BACKEND_LABELS.get(backend, backend)
                case_word = "case" if len(selected) == 1 else "cases"
                lines.extend([
                    "<details>",
                    f"<summary><strong>{escape(label)}</strong> — {len(selected)} {case_word}</summary>",
                    "",
                ])
                for _, path in selected:
                    render_case(lines, path)
                lines.extend(["</details>", ""])
    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Render perf profiles as Markdown")
    parser.add_argument("paths", nargs="+", help="profile files or directories")
    parser.add_argument("--output", help="write Markdown to this file")
    parser.add_argument("--title", default="Crypto perf profiles")
    args = parser.parse_args()
    markdown = render(args.paths, args.title)
    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
    else:
        print(markdown, end="")


if __name__ == "__main__":
    main()
