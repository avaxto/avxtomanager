#!/usr/bin/env bash
#
# AVXTO Wallet Manager
# Copyright (c) 2026, @REKTBuildr
#
# SPDX-License-Identifier: BSD-3-Clause
# See the LICENSE file in the project root for the full license text.

# Configures and builds AVXTO Wallet Manager with CMake.
#
#   ./scripts/build.sh [--clean] [--debug] [-- <extra cmake args>]
#
# Environment overrides (all optional):
#   QT_PREFIX_PATH        Qt install prefix, e.g. /path/to/Qt/6.11.2/macos
#                          Auto-detected from qmake6/qmake on PATH, then by
#                          searching ~/Qt for the newest installed 6.x kit.
#   AVXTO_QT_MIN_VERSION  Passed straight to CMake. The project defaults to
#                          requiring Qt 6.11.2; if only an older Qt 6 is
#                          found this script lowers the requirement to match
#                          it and says so (see notes/initiallog.txt).
#   BUILD_DIR             Build tree location (default: build)
#   BUILD_TYPE            CMake build type (default: RelWithDebInfo, or
#                          Debug if --debug is passed)
#   GENERATOR             CMake generator (default: Ninja if installed,
#                          otherwise the platform default)
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"

build_dir="${BUILD_DIR:-build}"
build_type="${BUILD_TYPE:-RelWithDebInfo}"
extra_cmake_args=()
clean=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean) clean=1; shift ;;
        --debug) build_type="Debug"; shift ;;
        --) shift; extra_cmake_args+=("$@"); break ;;
        -h|--help)
            sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "build.sh: unknown argument: $1" >&2; exit 64 ;;
    esac
done

if [[ -z "${GENERATOR:-}" ]]; then
    if command -v ninja >/dev/null 2>&1; then
        generator="Ninja"
    else
        generator=""   # let CMake pick its platform default
    fi
else
    generator="$GENERATOR"
fi

# --- Locate Qt -----------------------------------------------------------
#
# CMakeLists.txt requires Qt 6.11.2 by default but only ever uses API present
# since Qt 6.5, so it also configures cleanly against an older Qt 6 kit for
# local development (this is how it was verified while only Qt 6.9.0 was
# available; see notes/initiallog.txt).
qt_prefix="${QT_PREFIX_PATH:-}"
qt_version=""

if [[ -z "$qt_prefix" ]]; then
    for qmake_bin in qmake6 qmake; do
        if command -v "$qmake_bin" >/dev/null 2>&1; then
            qt_prefix="$("$qmake_bin" -query QT_INSTALL_PREFIX 2>/dev/null || true)"
            [[ -n "$qt_prefix" ]] && break
        fi
    done
fi

if [[ -z "$qt_prefix" ]]; then
    # Search the default Qt Online Installer layout: ~/Qt/<version>/<kit>/
    shopt -s nullglob
    candidates=("$HOME"/Qt/*/macos "$HOME"/Qt/*/gcc_64 "$HOME"/Qt/*/clang_64 "$HOME"/Qt/*/mingw*)
    shopt -u nullglob
    if [[ ${#candidates[@]} -gt 0 ]]; then
        # Sort by the version path component (e.g. .../6.11.2/macos) and take
        # the newest.
        qt_prefix="$(printf '%s\n' "${candidates[@]}" \
            | awk -F/ '{print $(NF-1), $0}' \
            | sort -V \
            | tail -1 \
            | cut -d' ' -f2-)"
    fi
fi

if [[ -n "$qt_prefix" ]]; then
    qt_version="$(basename "$(dirname "$qt_prefix")")"
    echo "build.sh: using Qt $qt_version at $qt_prefix"
    extra_cmake_args+=("-DCMAKE_PREFIX_PATH=$qt_prefix")
else
    echo "build.sh: no Qt install found via qmake or ~/Qt;" \
         "relying on CMake's own search (set QT_PREFIX_PATH to override)" >&2
fi

# Lower the minimum-version requirement to match whatever was actually found,
# unless the caller already pinned one.
if [[ -z "${AVXTO_QT_MIN_VERSION:-}" && -n "$qt_version" ]]; then
    default_min="6.11.2"
    newest="$(printf '%s\n%s\n' "$qt_version" "$default_min" | sort -V | tail -1)"
    if [[ "$newest" != "$qt_version" ]]; then
        echo "build.sh: only Qt $qt_version is installed (< $default_min);" \
             "lowering AVXTO_QT_MIN_VERSION to match"
        extra_cmake_args+=("-DAVXTO_QT_MIN_VERSION=$qt_version")
    fi
elif [[ -n "${AVXTO_QT_MIN_VERSION:-}" ]]; then
    extra_cmake_args+=("-DAVXTO_QT_MIN_VERSION=$AVXTO_QT_MIN_VERSION")
fi

if [[ "$clean" -eq 1 ]]; then
    echo "build.sh: removing $build_dir"
    rm -rf "$build_dir"
fi

configure_args=(-S . -B "$build_dir" -DCMAKE_BUILD_TYPE="$build_type")
[[ -n "$generator" ]] && configure_args+=(-G "$generator")
configure_args+=("${extra_cmake_args[@]+"${extra_cmake_args[@]}"}")

echo "build.sh: configuring ($build_type)…"
cmake "${configure_args[@]}"

echo "build.sh: building…"
cmake --build "$build_dir" --parallel

echo "build.sh: done -> $build_dir"
