#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 BACKEND ARCHITECTURE BENCHMARK_BINARY OUTPUT_DIRECTORY" >&2
    exit 2
fi

backend=$1
architecture=$2
benchmark_binary=$3
output_directory=$4
perf_binary=${PERF_BINARY:-perf}

mkdir -p "${output_directory}"

if ! command -v "${perf_binary}" >/dev/null 2>&1; then
    echo "perf executable not found: ${perf_binary}" >&2
    exit 1
fi

counter_events="cycles,instructions,branches,branch-misses,cache-references,cache-misses"
counter_mode=hardware
if ! sudo "${perf_binary}" stat --event cycles --output /dev/null -- true; then
    counter_events="task-clock,cpu-clock,context-switches,cpu-migrations,page-faults"
    counter_mode=software
fi

for operation in seal open; do
    for message_size in 64 16384; do
        stem="${backend}__${architecture}__aes-128-gcm__${operation}__${message_size}"
        stat_path="${output_directory}/${stem}.stat.csv"
        mode_path="${output_directory}/${stem}.mode"
        data_path="${output_directory}/${stem}.perf.data"
        report_path="${output_directory}/${stem}.report.txt"
        command=(
            "${benchmark_binary}"
            --algorithm AES-128-GCM
            --operation "${operation}"
            --size "${message_size}"
            --samples 1
            --sample-ms 2000
        )

        printf '%s\n' "${counter_mode}" > "${mode_path}"
        sudo "${perf_binary}" stat \
            --no-big-num \
            --field-separator=, \
            --repeat 3 \
            --event "${counter_events}" \
            --output "${stat_path}" \
            -- "${command[@]}" >/dev/null

        sudo "${perf_binary}" record \
            --quiet \
            --event cpu-clock \
            --freq 499 \
            --call-graph dwarf \
            --output "${data_path}" \
            -- "${command[@]}" >/dev/null

        sudo "${perf_binary}" report \
            --stdio \
            --no-children \
            --percent-limit 0.5 \
            --sort symbol,dso \
            --input "${data_path}" > "${report_path}"

        sudo chmod 0644 "${stat_path}" "${data_path}"
    done
done
