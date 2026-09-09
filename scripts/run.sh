#!/usr/bin/env bash
#
# AVXTO Wallet Manager
# Copyright (c) 2026, @REKTBuildr
#
# SPDX-License-Identifier: BSD-3-Clause
# See the LICENSE file in the project root for the full license text.

# Builds (if needed) and launches AVXTO Wallet Manager.
#
#   ./scripts/run.sh [--no-build] [--clean] [--debug] [-- <args for the app>]
#
# --no-build skips scripts/build.sh entirely and runs whatever is already in
# the build directory; --clean and --debug are forwarded to build.sh.
# BUILD_DIR overrides the build tree location, same as build.sh.
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

build_dir="${BUILD_DIR:-build}"
no_build=0
build_args=()
app_args=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-build) no_build=1; shift ;;
        --clean|--debug) build_args+=("$1"); shift ;;
        --) shift; app_args+=("$@"); break ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "run.sh: unknown argument: $1" >&2; exit 64 ;;
    esac
done

if [[ "$no_build" -eq 0 ]]; then
    "$project_root/scripts/build.sh" "${build_args[@]+"${build_args[@]}"}"
fi

# The CMake target is a bundle on macOS, a plain executable elsewhere.
candidates=(
    "$build_dir/avxto-wallet-manager.app/Contents/MacOS/avxto-wallet-manager"  # macOS bundle
    "$build_dir/avxto-wallet-manager"                                          # Linux
    "$build_dir/avxto-wallet-manager.exe"                                      # Windows
    "$build_dir/Debug/avxto-wallet-manager.exe"                                # Windows, multi-config generators
    "$build_dir/RelWithDebInfo/avxto-wallet-manager.exe"
)

binary=""
for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
        binary="$candidate"
        break
    fi
done

if [[ -z "$binary" ]]; then
    echo "run.sh: no built executable found under $build_dir" >&2
    echo "run.sh: run ./scripts/build.sh first, or drop --no-build" >&2
    exit 1
fi

echo "run.sh: launching $binary"
exec "$binary" "${app_args[@]+"${app_args[@]}"}"
