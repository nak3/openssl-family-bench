#!/usr/bin/env python3

import argparse
import csv
import math
from pathlib import Path
import re


CASE_PATTERN = re.compile(
    r"^(?P<backend>.+)__(?P<architecture>.+)__"
    r"(?P<category>.+)__(?P<subject>.+)__"
    r"(?P<operation>.+)__(?P<size>\d+)$"
)
HOTSPOT_PATTERN = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)%\s+(.+?)\s*$")


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
            event = row[2].strip()
            if value is not None and event:
                counters[event] = value
    return counters


def parse_hotspots(path, limit=10):
    hotspots = []
    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
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
    hotspots = parse_hotspots(report_path)

    size_label = (
        "handshake"
        if case["category"] == "tls" and case["operation"] == "handshake"
        else f"{case['size']} bytes"
    )
    lines.extend([
        f"##### {case['subject']} {case['operation']} — {size_label}",
        "",
        f"Counter mode: `{mode}`",
        f"Sampling event: `{sampling}`",
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
        "> Profiles use separate instrumented builds and are not benchmark scores.",
        "> Hotspots use the first supported sampling event; some hosted runner PMUs expose counters only.",
        "",
    ]
    for architecture in architectures:
        lines.extend([f"## Architecture: `{architecture}`", ""])
        categories = sorted({
            case["category"] for case, _ in cases
            if case["architecture"] == architecture
        }, key=lambda name: ({"aead": 0, "primitive": 1, "tls": 2}.get(name, 99), name))
        for category in categories:
            lines.extend([f"### Category: `{category.upper()}`", ""])
            backends = sorted({
                case["backend"] for case, _ in cases
                if case["architecture"] == architecture
                and case["category"] == category
            })
            for backend in backends:
                lines.extend([f"#### Backend: `{backend}`", ""])
                selected = [
                    (case, path) for case, path in cases
                    if case["architecture"] == architecture
                    and case["category"] == category
                    and case["backend"] == backend
                ]
                selected.sort(key=lambda item: (
                    item[0]["subject"], item[0]["operation"], item[0]["size"]
                ))
                for _, path in selected:
                    render_case(lines, path)
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
