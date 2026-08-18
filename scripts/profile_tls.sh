#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 BACKEND ARCHITECTURE TLS_BINARY OUTPUT_DIRECTORY" >&2
    exit 2
fi

backend=$1
architecture=$2
tls_binary=$3
output_directory=$4
sample_ms=${PROFILE_SAMPLE_MS:-1000}
script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

for cipher in \
    TLS_AES_128_GCM_SHA256 \
    TLS_AES_256_GCM_SHA384 \
    TLS_CHACHA20_POLY1305_SHA256; do
    "${script_directory}/profile_case.sh" \
        "${backend}" "${architecture}" tls "${cipher}" \
        handshake 0 "${output_directory}" \
        "${tls_binary}" \
        --benchmark handshake \
        --cipher "${cipher}" \
        --samples 1 \
        --sample-ms "${sample_ms}"

    for message_size in 1024 16384; do
        "${script_directory}/profile_case.sh" \
            "${backend}" "${architecture}" tls "${cipher}" \
            transfer "${message_size}" "${output_directory}" \
            "${tls_binary}" \
            --benchmark transfer \
            --cipher "${cipher}" \
            --size "${message_size}" \
            --samples 1 \
            --sample-ms "${sample_ms}"
    done
done
