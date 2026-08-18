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

run_perf()
{
    if [[ ${PERF_USE_SUDO:-1} == 0 ]]; then
        "${perf_binary}" "$@"
    else
        sudo "${perf_binary}" "$@"
    fi
}

run_privileged()
{
    if [[ ${PERF_USE_SUDO:-1} == 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

mkdir -p "${output_directory}"

if ! command -v "${perf_binary}" >/dev/null 2>&1; then
    echo "perf executable not found: ${perf_binary}" >&2
    exit 1
fi

counter_events="cycles,instructions,branches,branch-misses,cache-references,cache-misses"
counter_mode=hardware
if ! run_perf stat --event cycles --output /dev/null -- true; then
    counter_events="task-clock,cpu-clock,context-switches,cpu-migrations,page-faults"
    counter_mode=software
fi

for operation in seal open; do
    for message_size in 64 16384; do
        stem="${backend}__${architecture}__aes-128-gcm__${operation}__${message_size}"
        stat_path="${output_directory}/${stem}.stat.csv"
        mode_path="${output_directory}/${stem}.mode"
        sampling_path="${output_directory}/${stem}.sampling"
        data_path="${output_directory}/${stem}.perf.data"
        record_error_path="${output_directory}/${stem}.record.stderr.txt"
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
        run_perf stat \
            --no-big-num \
            --field-separator=, \
            --repeat 3 \
            --event "${counter_events}" \
            --output "${stat_path}" \
            -- "${command[@]}" >/dev/null

        sampling_event=unavailable
        : > "${record_error_path}"
        # Unmodified cpu-clock works on the x86_64 hosted runner. Some perf
        # versions reject privilege modifiers on software events, so only try
        # the :u variants after the portable spellings.
        for candidate_event in cpu-clock task-clock cycles cpu-clock:u task-clock:u cycles:u; do
            printf 'Trying sampling event: %s\n' "${candidate_event}" \
                >> "${record_error_path}"
            if run_perf record \
                --quiet \
                --force \
                --event "${candidate_event}" \
                --freq 499 \
                --call-graph dwarf \
                --output "${data_path}" \
                -- "${command[@]}" >/dev/null 2>> "${record_error_path}"; then
                sampling_event=${candidate_event}
                break
            fi
        done
        printf '%s\n' "${sampling_event}" > "${sampling_path}"

        if [[ ${sampling_event} != unavailable ]]; then
            run_perf report \
                --stdio \
                --no-children \
                --percent-limit 0.5 \
                --sort symbol,dso \
                --input "${data_path}" > "${report_path}"
        else
            printf '%s\n' \
                'Sampling unavailable on this runner; perf stat counters remain valid.' \
                > "${report_path}"
        fi

        run_privileged chmod 0644 "${stat_path}"
        if [[ -f ${data_path} ]]; then
            run_privileged chmod 0644 "${data_path}"
        fi
    done
done
