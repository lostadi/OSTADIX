#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail
PROBE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ANDROID_JAR=${ANDROID_JAR:-/data/data/com.termux/files/home/android-sdk/platforms/android-37.2/android.jar}
mkdir -p "$PROBE_ROOT/build/classes" "$PROBE_ROOT/build/dex"
mapfile -t SOURCES < <(/data/data/com.termux/files/usr/bin/rg --files "$PROBE_ROOT/src" -g '*.java' | sort)
javac -encoding UTF-8 -source 8 -target 8 -bootclasspath "$ANDROID_JAR" \
    -classpath "$ANDROID_JAR" -d "$PROBE_ROOT/build/classes" "${SOURCES[@]}"
jar cf "$PROBE_ROOT/build/classes.jar" -C "$PROBE_ROOT/build/classes" .
d8 --min-api 28 --lib "$ANDROID_JAR" --output "$PROBE_ROOT/build/dex" "$PROBE_ROOT/build/classes.jar"
jar cf "$PROBE_ROOT/build/nano-loader-probe.jar" -C "$PROBE_ROOT/build/dex" classes.dex
sha256sum "$PROBE_ROOT/build/nano-loader-probe.jar"
