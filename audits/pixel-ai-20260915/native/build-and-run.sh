#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_DIR="$SCRIPT_DIR/build"
OUTPUT="$BUILD_DIR/edgetpu_sb_probe"

command -v clang >/dev/null 2>&1 || {
    echo "clang is required" >&2
    exit 1
}

mkdir -p "$BUILD_DIR"
clang -x c -O2 -Wall -Wextra \
    -o "$OUTPUT" \
    "$SCRIPT_DIR/edgetpu_sb_probe.c" \
    -ldl

echo "Built: $OUTPUT"
sha256sum "$OUTPUT"
echo "Running in the caller's current UID and SELinux domain:"
id
cat /proc/self/attr/current
LD_LIBRARY_PATH="/vendor/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$OUTPUT"
