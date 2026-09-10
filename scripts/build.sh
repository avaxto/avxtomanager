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
# Auto-detects Qt (via qmake6/qmake on PATH, then by searching ~/Qt for the
# newest installed 6.x kit) and writes what it found into CMakeUserPresets.json
# — a "dev" preset inheriting the tracked, machine-independent CMakePresets.json
# — instead of exporting environment variables or passing one-off -D flags.
# A plain script cannot make an exported variable stick in your interactive
# shell anyway (it only affects its own subprocess), so this is what "set it
# up automatically" actually means here: run this once (and again whenever
# your Qt install changes) and both this script AND VS Code's CMake Tools
# read the same generated preset with no further setup. See
# notes/initiallog.txt and CMakePresets.json for the full rationale.
#
# Environment overrides (all optional — only needed to steer what gets
# written into the generated preset; CMAKE_PREFIX_PATH and AVXTO_QT_MIN_VERSION
# are also still honoured directly by CMakeLists.txt for anyone who prefers a
# plain `cmake -S -B` invocation over presets):
#   CMAKE_PREFIX_PATH     Qt install prefix, e.g. /path/to/Qt/6.11.2/macos.
#                          If unset, auto-detected as described above.
#   AVXTO_QT_MIN_VERSION  The project defaults to requiring Qt 6.11.2; if
#                          only an older Qt 6 is found (or given via
#                          CMAKE_PREFIX_PATH) this script lowers the
#                          requirement to match it and says so.
#   BUILD_DIR             Build tree location (default: build)
#   BUILD_TYPE            CMake build type (default: RelWithDebInfo, or
#                          Debug if --debug is passed)
#   GENERATOR             CMake generator (default: Ninja if installed,
#                          otherwise Unix Makefiles)
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
            sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "build.sh: unknown argument: $1" >&2; exit 64 ;;
    esac
done

if [[ -n "${GENERATOR:-}" ]]; then
    generator="$GENERATOR"
elif command -v ninja >/dev/null 2>&1; then
    generator="Ninja"
else
    generator="Unix Makefiles"
fi

# --- Locate Qt -----------------------------------------------------------
#
# If CMAKE_PREFIX_PATH is already exported, trust it as-is and skip
# auto-detection. Otherwise, CMakeLists.txt requires Qt 6.11.2 by default but
# only ever uses API present since Qt 6.5, so this falls back to searching
# for whatever Qt 6 is actually installed (this is how it was verified while
# only Qt 6.9.0 was available; see notes/initiallog.txt).
qt_prefix="${CMAKE_PREFIX_PATH:-}"
qt_version=""

if [[ -n "$qt_prefix" ]]; then
    echo "build.sh: using CMAKE_PREFIX_PATH from the environment: $qt_prefix"
else
    for qmake_bin in qmake6 qmake; do
        if command -v "$qmake_bin" >/dev/null 2>&1; then
            qt_prefix="$("$qmake_bin" -query QT_INSTALL_PREFIX 2>/dev/null || true)"
            qt_version="$("$qmake_bin" -query QT_VERSION 2>/dev/null || true)"
            [[ -n "$qt_prefix" ]] && break
        fi
    done

    if [[ -z "$qt_prefix" ]]; then
        # Search the default Qt Online Installer layout: ~/Qt/<version>/<kit>/
        shopt -s nullglob
        candidates=("$HOME"/Qt/*/macos "$HOME"/Qt/*/gcc_64 "$HOME"/Qt/*/clang_64 "$HOME"/Qt/*/mingw*)
        shopt -u nullglob
        if [[ ${#candidates[@]} -gt 0 ]]; then
            # Sort by the version path component (e.g. .../6.11.2/macos) and
            # take the newest.
            qt_prefix="$(printf '%s\n' "${candidates[@]}" \
                | awk -F/ '{print $(NF-1), $0}' \
                | sort -V \
                | tail -1 \
                | cut -d' ' -f2-)"
            qt_version="$(basename "$(dirname "$qt_prefix")")"
        fi
    fi

    if [[ -n "$qt_prefix" ]]; then
        echo "build.sh: using Qt $qt_version at $qt_prefix"
    else
        echo "build.sh: no Qt install found via qmake or ~/Qt;" \
             "relying on CMake's own search (export CMAKE_PREFIX_PATH to override)" >&2
    fi
fi

# Lower the minimum-version requirement to match whatever was actually found,
# unless the caller already pinned one.
qt_min_version="${AVXTO_QT_MIN_VERSION:-6.11.2}"
if [[ -z "${AVXTO_QT_MIN_VERSION:-}" && -n "$qt_version" ]]; then
    newest="$(printf '%s\n%s\n' "$qt_version" "$qt_min_version" | sort -V | tail -1)"
    if [[ "$newest" != "$qt_version" ]]; then
        echo "build.sh: only Qt $qt_version is installed (< $qt_min_version);" \
             "lowering the minimum-version requirement to match"
        qt_min_version="$qt_version"
    fi
fi

if [[ "$clean" -eq 1 ]]; then
    echo "build.sh: removing $build_dir"
    rm -rf "$build_dir"
fi

# --- Write CMakeUserPresets.json ------------------------------------------
#
# This is the "automatic" part: a gitignored, machine-local preset inheriting
# the tracked "base" preset from CMakePresets.json. cmake --preset and VS
# Code's CMake Tools both discover it with no further configuration, so this
# file (regenerated every run) is the single place these settings live —
# there is nothing to export in a shell profile and nothing to keep in sync
# by hand.
escape_json() {
    # Minimal escaping sufficient for real filesystem paths and version
    # strings: backslash and double-quote are the only characters JSON
    # requires escaping that a path is remotely likely to contain.
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '%s' "$value"
}

cat > CMakeUserPresets.json <<EOF
{
    "version": 5,
    "include": [
        "CMakePresets.json"
    ],
    "configurePresets": [
        {
            "name": "dev",
            "displayName": "Local development (auto-generated by scripts/build.sh — do not commit)",
            "inherits": "base",
            "binaryDir": "\${sourceDir}/$(escape_json "$build_dir")",
            "generator": "$(escape_json "$generator")",
            "cacheVariables": {
                "CMAKE_BUILD_TYPE": "$(escape_json "$build_type")",
                "CMAKE_PREFIX_PATH": "$(escape_json "$qt_prefix")",
                "AVXTO_QT_MIN_VERSION": "$(escape_json "$qt_min_version")"
            }
        }
    ],
    "buildPresets": [
        {
            "name": "dev",
            "configurePreset": "dev"
        }
    ]
}
EOF

echo "build.sh: configuring ($build_type)…"
cmake --preset dev "${extra_cmake_args[@]+"${extra_cmake_args[@]}"}"

echo "build.sh: building…"
cmake --build --preset dev --parallel

echo "build.sh: done -> $build_dir"
