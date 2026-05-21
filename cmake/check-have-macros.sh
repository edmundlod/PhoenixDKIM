#!/usr/bin/env bash
# Verify every HAVE_* macro used in C sources is also probed by CMake.
# Run from the project root.
set -euo pipefail

gaps=$(comm -23 \
    <(grep -rh --include='*.c' --include='*.h' \
               --exclude-dir='.git' --exclude-dir='build' \
               -oE 'HAVE_[A-Z0-9_]+' . | sort -u) \
    <(grep -rh --include='CMakeLists.txt' --include='*.cmake' \
               --include='*.cmake.in' \
               --exclude-dir='.git' --exclude-dir='build' \
               -oE 'HAVE_[A-Z0-9_]+' . | sort -u))

if [ -n "$gaps" ]; then
    echo "ERROR: HAVE_* macros used in C sources but missing from CMake:" >&2
    printf '%s\n' $gaps >&2
    exit 1
fi
