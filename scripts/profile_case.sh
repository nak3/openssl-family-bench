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
gprof_binary=${GPROF_BINARY:-${command[0]}}

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
benchmark_path="${output_directory}/${stem}.benchmark.jsonl"
mode_path="${output_directory}/${stem}.mode"
sampling_path="${output_directory}/${stem}.sampling"
data_path="${output_directory}/${stem}.perf.data"
record_error_path="${output_directory}/${stem}.record.stderr.txt"
report_path="${output_directory}/${stem}.report.txt"
gprof_binary_info_path="${output_directory}/${stem}.gprof-binary.txt"
gprof_symbol_table_path="${output_directory}/${stem}.gprof-symbols.txt"

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
    -- "${command[@]}" > "${benchmark_path}"

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

if [[ ${sampling_event} != unavailable ]]; then
    run_perf report \
        --stdio \
        --no-children \
        --percent-limit 0.5 \
        --sort symbol,dso \
        --input "${data_path}" > "${report_path}"
elif [[ ${GPROF_FALLBACK:-0} == 1 ]] && command -v gprof >/dev/null 2>&1; then
    gmon_prefix="${output_directory}/${stem}.gmon"
    gprof_command=("${command[@]}")
    gprof_command[0]="${gprof_binary}"
    printf '%s\n' 'perf sampling unavailable; trying gprof fallback' \
        >> "${record_error_path}"
    if GMON_OUT_PREFIX="${gmon_prefix}" "${gprof_command[@]}" \
        >/dev/null 2>> "${record_error_path}"; then
        shopt -s nullglob
        gmon_paths=("${gmon_prefix}".*)
        shopt -u nullglob
        # gprof rejects some GCC-generated local names such as *.part.N and
        # attributes their samples to the preceding accepted symbol. Supplying
        # an external nm table preserves those optimized function boundaries.
        if nm --defined-only --numeric-sort "${gprof_binary}" | \
            awk 'NF >= 3 && $2 ~ /^[tTwW]$/ {
                kind = ($2 ~ /^[TW]$/) ? "T" : "t"
                print $1, kind, $3
            }' > "${gprof_symbol_table_path}" &&
            [[ -s ${gprof_symbol_table_path} ]] &&
            [[ ${#gmon_paths[@]} -gt 0 ]] &&
            gprof -b -p -S "${gprof_symbol_table_path}" \
                "${gprof_binary}" "${gmon_paths[0]}" \
                > "${report_path}" 2>> "${record_error_path}"; then
            sampling_event="gprof"
            {
                printf 'binary=%s\n' "$(readlink -f "${gprof_binary}")"
                sha256sum "${gprof_binary}"
            } > "${gprof_binary_info_path}"
        fi
    fi
fi

if [[ ${sampling_event} == unavailable ]]; then
    printf '%s\n' \
        'Sampling unavailable on this runner; perf stat counters remain valid.' \
        > "${report_path}"
fi
printf '%s\n' "${sampling_event}" > "${sampling_path}"

if [[ ${sampling_event} == gprof ]]; then
    for gmon_path in "${gmon_paths[@]}"; do
        chmod 0644 "${gmon_path}"
    done
else
    :
fi

run_privileged chmod 0644 "${stat_path}"
run_privileged chmod 0644 "${benchmark_path}"
if [[ -f ${data_path} ]]; then
    run_privileged chmod 0644 "${data_path}"
fi
