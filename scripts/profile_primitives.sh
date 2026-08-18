#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "usage: $0 BACKEND ARCHITECTURE PRIMITIVE_BINARY OUTPUT_DIRECTORY" >&2
    exit 2
fi

backend=$1
architecture=$2
primitive_binary=$3
output_directory=$4
sample_ms=${PROFILE_SAMPLE_MS:-1000}
script_directory=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

profile_primitive()
{
    local primitive=$1
    local operation=$2
    local message_size=$3

    "${script_directory}/profile_case.sh" \
        "${backend}" "${architecture}" primitive "${primitive}" \
        "${operation}" "${message_size}" "${output_directory}" \
        "${primitive_binary}" \
        --primitive "${primitive}" \
        --operation "${operation}" \
        --size "${message_size}" \
        --sample-ms "${sample_ms}"
}

for message_size in 64 16384; do
    for primitive in AES-128-CBC AES-256-CBC; do
        profile_primitive "${primitive}" encrypt "${message_size}"
        profile_primitive "${primitive}" decrypt "${message_size}"
    done
    profile_primitive SHA-256 digest "${message_size}"
    profile_primitive SHA-512 digest "${message_size}"
    profile_primitive HMAC-SHA256 mac "${message_size}"
done
