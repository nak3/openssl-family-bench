#!/usr/bin/env python3

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path


def load_rows(paths):
    files = []
    for path_text in paths:
        path = Path(path_text)
        if path.is_dir():
            files.extend(sorted(path.rglob("*.jsonl")))
        else:
            files.append(path)

    rows = []
    for path in files:
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError as error:
                        raise ValueError(f"{path}:{line_number}: {error}") from error
    if not rows:
        raise ValueError("no JSON Lines benchmark results found")
    return rows


def escape(value):
    return str(value).replace("|", "\\|")


def format_rate(value):
    return f"{value:,.2f}"


def display_backend(backend):
    return {
        "openssl": "OpenSSL",
        "libressl": "LibreSSL baseline",
        "libressl-patched": "LibreSSL patched",
    }.get(backend, backend)


def backend_order(backends):
    preferred = {"openssl": 0, "libressl": 1, "libressl-patched": 2}
    return sorted(backends, key=lambda name: (preferred.get(name, 99), name))


def ratio_cell(values):
    if "openssl" not in values or "libressl" not in values or values["libressl"] == 0:
        return "—"
    return f'{values["openssl"] / values["libressl"]:.2f}×'


def patched_ratio_cell(values):
    if ("libressl-patched" not in values or "libressl" not in values or
            values["libressl"] == 0):
        return "—"
    return f'{values["libressl-patched"] / values["libressl"]:.3f}×'


def append_ratio_headings(headings, backends):
    if "openssl" in backends and "libressl" in backends:
        headings.append("OpenSSL / baseline")
    if "libressl-patched" in backends and "libressl" in backends:
        headings.append("Patched / baseline")


def append_ratios(row, values, backends):
    if "openssl" in backends and "libressl" in backends:
        row.append(ratio_cell(values))
    if "libressl-patched" in backends and "libressl" in backends:
        row.append(patched_ratio_cell(values))


def append_table(lines, headings, rows):
    lines.append("| " + " | ".join(headings) + " |")
    lines.append("| " + " | ".join("---" for _ in headings) + " |")
    for row in rows:
        lines.append("| " + " | ".join(escape(cell) for cell in row) + " |")
    lines.append("")


def aggregate(rows, key_fields, metric):
    values = defaultdict(list)
    for row in rows:
        if metric in row:
            key = tuple(row[field] for field in key_fields)
            values[(key, row["backend"])].append(float(row[metric]))
    result = defaultdict(dict)
    for (key, backend), samples in values.items():
        result[key][backend] = statistics.median(samples)
    return result


def render(rows, title):
    backends = backend_order({row["backend"] for row in rows})
    versions = {}
    for row in rows:
        versions[row["backend"]] = row.get("version", "unknown")

    lines = [f"# {title}", ""]
    lines.append("> Values are medians of the raw samples. Higher is better.")
    lines.append("> GitHub-hosted runner performance can vary between workflow runs.")
    lines.append("")

    append_table(
        lines,
        ["Backend", "Version"],
        [[display_backend(backend), versions[backend]] for backend in backends],
    )

    primitive_rows = [row for row in rows if "algorithm" in row]
    if primitive_rows:
        lines.extend(["## AEAD primitive throughput", ""])
        data = aggregate(
            primitive_rows,
            ("algorithm", "operation", "message_bytes"),
            "mib_per_second",
        )
        headings = ["Algorithm", "Operation", "Bytes"]
        headings.extend(f"{display_backend(backend)} MiB/s" for backend in backends)
        append_ratio_headings(headings, backends)
        table_rows = []
        for key in sorted(data):
            values = data[key]
            row = [key[0], key[1], str(key[2])]
            row.extend(format_rate(values[backend]) if backend in values else "—"
                       for backend in backends)
            append_ratios(row, values, backends)
            table_rows.append(row)
        append_table(lines, headings, table_rows)

    handshake_rows = [
        row for row in rows if row.get("benchmark") == "tls-handshake"
    ]
    if handshake_rows:
        lines.extend(["## TLS 1.3 full handshake", ""])
        data = aggregate(handshake_rows, ("cipher",), "handshakes_per_second")
        headings = ["Cipher"]
        headings.extend(
            f"{display_backend(backend)} handshakes/s" for backend in backends
        )
        append_ratio_headings(headings, backends)
        table_rows = []
        for key in sorted(data):
            values = data[key]
            row = [key[0]]
            row.extend(format_rate(values[backend]) if backend in values else "—"
                       for backend in backends)
            append_ratios(row, values, backends)
            table_rows.append(row)
        append_table(lines, headings, table_rows)

    transfer_rows = [
        row for row in rows if row.get("benchmark") == "tls-transfer"
    ]
    if transfer_rows:
        lines.extend(["## TLS 1.3 application-data throughput", ""])
        data = aggregate(
            transfer_rows, ("cipher", "message_bytes"), "mib_per_second"
        )
        headings = ["Cipher", "Bytes"]
        headings.extend(f"{display_backend(backend)} MiB/s" for backend in backends)
        append_ratio_headings(headings, backends)
        table_rows = []
        for key in sorted(data):
            values = data[key]
            row = [key[0], str(key[1])]
            row.extend(format_rate(values[backend]) if backend in values else "—"
                       for backend in backends)
            append_ratios(row, values, backends)
            table_rows.append(row)
        append_table(lines, headings, table_rows)

    return "\n".join(lines).rstrip() + "\n"


def main():
    parser = argparse.ArgumentParser(description="Render JSONL benchmarks as Markdown")
    parser.add_argument("paths", nargs="+", help="JSONL files or directories")
    parser.add_argument("--output", help="write Markdown to this file")
    parser.add_argument("--title", default="Benchmark results")
    args = parser.parse_args()

    markdown = render(load_rows(args.paths), args.title)
    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
    else:
        print(markdown, end="")


if __name__ == "__main__":
    main()
