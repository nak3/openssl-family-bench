#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 8 ]]; then
    echo "usage: $0 BACKEND ARCHITECTURE CATEGORY SUBJECT OPERATION SIZE OUTPUT_DIRECTORY COMMAND [ARG ...]" >&2
    exit 2
fi

backend=$1
architecture=$2
category=$3
subject=$4
operation=$5
message_size=$6
output_directory=$7
shift 7
command=("$@")
perf_binary=${PERF_BINARY:-perf}
sample_repeat=${PROFILE_STAT_REPEAT:-2}

for component in "${backend}" "${architecture}" "${category}" "${subject}" "${operation}"; do
    if [[ ! ${component} =~ ^[A-Za-z0-9._+-]+$ ]]; then
        echo "profile label contains unsupported characters: ${component}" >&2
        exit 2
    fi
done
if [[ ! ${message_size} =~ ^[0-9]+$ ]]; then
    echo "profile size must be an integer: ${message_size}" >&2
    exit 2
fi

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

stem="${backend}__${architecture}__${category}__${subject}__${operation}__${message_size}"
stat_path="${output_directory}/${stem}.stat.csv"
mode_path="${output_directory}/${stem}.mode"
sampling_path="${output_directory}/${stem}.sampling"
data_path="${output_directory}/${stem}.perf.data"
record_error_path="${output_directory}/${stem}.record.stderr.txt"
report_path="${output_directory}/${stem}.report.txt"

# A successful perf invocation can still report <not supported>. Inspect the
# result before selecting hardware counters so the summary never shows an
# empty hardware-counter table as if it were valid.
probe_path=$(mktemp)
counter_events="cycles,instructions,branches,branch-misses,cache-references,cache-misses"
counter_mode=hardware
if ! run_perf stat --no-big-num --field-separator=, --event cycles \
    --output "${probe_path}" -- true >/dev/null 2>&1 ||
    ! awk -F, '$1 ~ /^[[:space:]]*[0-9]+([.][0-9]+)?[[:space:]]*$/ && $3 ~ /^cycles/ { found=1 } END { exit !found }' \
        "${probe_path}"; then
    counter_events="task-clock,cpu-clock,context-switches,cpu-migrations,page-faults"
    counter_mode=software
fi

printf '%s\n' "${counter_mode}" > "${mode_path}"
run_perf stat \
    --no-big-num \
    --field-separator=, \
    --repeat "${sample_repeat}" \
    --event "${counter_events}" \
    --output "${stat_path}" \
    -- "${command[@]}" >/dev/null

sampling_event=unavailable
: > "${record_error_path}"
# Unmodified software events work on hosted x86_64. ARM hosted PMUs commonly
# expose counting but no sampling interrupt, which is handled without failing.
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
