#!/usr/bin/env bash
#
# AVXTO Wallet Manager
# Copyright (c) 2026, @REKTBuildr
#
# SPDX-License-Identifier: BSD-3-Clause
# See the LICENSE file in the project root for the full license text.

# Reads a mnemonic back from a running AVXTO Wallet Manager.
#
#   ./scripts/rpc-demo.sh <port> <session-password> [wallet.bin]
#
# The port is shown in the JSON-RPC endpoint box in the application window;
# the session password is issued when you open a wallet and is revoked the
# moment you close it.
set -euo pipefail

if [[ $# -lt 2 ]]; then
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit 64
fi

port=$1
password=$2
wallet=${3:-}

params="{\"password\":\"${password}\""
[[ -n "${wallet}" ]] && params="${params},\"wallet\":\"${wallet}\""
params="${params}}"

response=$(mktemp)
trap 'rm -f "${response}"' EXIT

status=$(curl -s -o "${response}" -w '%{http_code}' \
    -X POST "http://127.0.0.1:${port}/" \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"read\",\"params\":${params}}")

case "${status}" in
    200) echo "HTTP 200"; cat "${response}"; echo ;;
    403) echo "HTTP 403 — denied. Wrong session password, or the wallet was closed." >&2
         cat "${response}" >&2; echo >&2; exit 1 ;;
    429) echo "HTTP 429 — too many failed attempts; wait a minute." >&2; exit 1 ;;
    *)   echo "HTTP ${status}" >&2; cat "${response}" >&2; echo >&2; exit 1 ;;
esac
