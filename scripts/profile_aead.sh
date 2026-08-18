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
sample_ms=${PROFILE_SAMPLE_MS:-1000}
script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

for algorithm in AES-128-GCM AES-256-GCM CHACHA20-POLY1305; do
    for operation in seal open; do
        for message_size in 64 16384; do
            "${script_directory}/profile_case.sh" \
                "${backend}" "${architecture}" aead "${algorithm}" \
                "${operation}" "${message_size}" "${output_directory}" \
                "${benchmark_binary}" \
                --algorithm "${algorithm}" \
                --operation "${operation}" \
                --size "${message_size}" \
                --samples 1 \
                --sample-ms "${sample_ms}"
        done
    done
done
