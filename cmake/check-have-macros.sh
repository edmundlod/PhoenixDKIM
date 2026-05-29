#!/bin/sh
# Verify every HAVE_* macro used in C sources is also probed by CMake.
# Run from the project root.
set -eu

tmp1=$(mktemp)
tmp2=$(mktemp)
trap 'rm -f "$tmp1" "$tmp2"' EXIT

grep -rh --include='*.c' --include='*.h' \
         --exclude-dir='.git' --exclude-dir='build' \
         -oE 'HAVE_[A-Z0-9_]+' . | sort -u > "$tmp1"

grep -rh --include='CMakeLists.txt' --include='*.cmake' \
         --include='*.cmake.in' \
         --exclude-dir='.git' --exclude-dir='build' \
         -oE 'HAVE_[A-Z0-9_]+' . | sort -u > "$tmp2"

gaps=$(comm -23 "$tmp1" "$tmp2")

if [ -n "$gaps" ]; then
    echo "ERROR: HAVE_* macros used in C sources but missing from CMake:" >&2
    printf '%s\n' $gaps >&2
    exit 1
fi
