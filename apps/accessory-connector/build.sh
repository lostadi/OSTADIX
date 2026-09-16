#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

APP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_ROOT="$APP_ROOT/build"
INTERMEDIATES="$BUILD_ROOT/intermediates"
OUTPUT_DIR="$BUILD_ROOT/outputs/apk/debug"
ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-$HOME/android-sdk}
ANDROID_JAR=${ANDROID_JAR:-$ANDROID_SDK_ROOT/platforms/android-34/android.jar}
DEBUG_KEYSTORE=${DEBUG_KEYSTORE:-$INTERMEDIATES/debug.keystore}
MIN_SDK=33
TARGET_SDK=34
VERSION_CODE=1
VERSION_NAME=0.1.0

require_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required build tool: $1" >&2
        exit 1
    }
}

for tool in aapt2 apksigner d8 jar java javac keytool python3 sed grep; do
    require_tool "$tool"
done

if [[ ! -f "$ANDROID_JAR" ]]; then
    echo "Android platform jar not found: $ANDROID_JAR" >&2
    exit 1
fi

echo "[1/6] Running dependency-free safety and unit tests"
"$APP_ROOT/tests/self-test.sh"

if [[ -d "$INTERMEDIATES" ]]; then
    find "$INTERMEDIATES" -mindepth 1 -delete
fi
mkdir -p \
    "$INTERMEDIATES/compiled-res" \
    "$INTERMEDIATES/generated" \
    "$INTERMEDIATES/classes" \
    "$INTERMEDIATES/dex" \
    "$OUTPUT_DIR"

echo "[2/6] Compiling and linking Android resources"
aapt2 compile \
    --dir "$APP_ROOT/app/src/main/res" \
    -o "$INTERMEDIATES/compiled-res/resources.zip"
aapt2 link \
    -o "$INTERMEDIATES/base-unsigned.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$APP_ROOT/app/src/main/AndroidManifest.xml" \
    --java "$INTERMEDIATES/generated" \
    --min-sdk-version "$MIN_SDK" \
    --target-sdk-version "$TARGET_SDK" \
    --version-code "$VERSION_CODE" \
    --version-name "$VERSION_NAME" \
    -R "$INTERMEDIATES/compiled-res/resources.zip" \
    --auto-add-overlay

echo "[3/6] Compiling Java and DEX bytecode"
SOURCE_ROOT="$APP_ROOT/app/src/main/java"
JAVA_SEARCH_ROOTS=("$INTERMEDIATES/generated" "$SOURCE_ROOT")
mapfile -t JAVA_SOURCES < <(find "${JAVA_SEARCH_ROOTS[@]}" -type f -name '*.java' -print | sort)
if [[ ${#JAVA_SOURCES[@]} -eq 0 ]]; then
    echo "No Java sources or generated R.java files were found" >&2
    exit 1
fi
javac \
    -encoding UTF-8 \
    -source 8 -target 8 \
    -bootclasspath "$ANDROID_JAR" \
    -classpath "$ANDROID_JAR" \
    -d "$INTERMEDIATES/classes" \
    "${JAVA_SOURCES[@]}"
jar cf "$INTERMEDIATES/classes.jar" -C "$INTERMEDIATES/classes" .
d8 \
    --min-api "$MIN_SDK" \
    --lib "$ANDROID_JAR" \
    --output "$INTERMEDIATES/dex" \
    "$INTERMEDIATES/classes.jar"

echo "[4/6] Packaging the unsigned APK"
UNSIGNED_APK="$INTERMEDIATES/AccessoryConnector-unsigned.apk"
cp "$INTERMEDIATES/base-unsigned.apk" "$UNSIGNED_APK"
jar uf "$UNSIGNED_APK" -C "$INTERMEDIATES/dex" classes.dex

echo "[5/6] Signing v3 and v2-compatible APKs"
if [[ ! -f "$DEBUG_KEYSTORE" ]]; then
    mkdir -p "$(dirname "$DEBUG_KEYSTORE")"
    keytool -genkeypair -noprompt \
        -keystore "$DEBUG_KEYSTORE" \
        -storepass android \
        -alias androiddebugkey \
        -keypass android \
        -dname 'CN=Android Debug,O=Android,C=US' \
        -keyalg RSA -keysize 2048 -validity 10000
fi

DEBUG_APK="$OUTPUT_DIR/AccessoryConnector-debug.apk"
UNIVERSAL_APK="$OUTPUT_DIR/AccessoryConnector-universal.apk"
apksigner sign \
    --ks "$DEBUG_KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --min-sdk-version "$MIN_SDK" \
    --v1-signing-enabled false \
    --v2-signing-enabled false \
    --v3-signing-enabled true \
    --v4-signing-enabled false \
    --alignment-preserved false \
    --out "$DEBUG_APK" \
    "$UNSIGNED_APK"

apksigner sign \
    --ks "$DEBUG_KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --min-sdk-version "$MIN_SDK" \
    --v1-signing-enabled false \
    --v2-signing-enabled true \
    --v3-signing-enabled false \
    --v4-signing-enabled false \
    --alignment-preserved false \
    --out "$UNIVERSAL_APK" \
    "$UNSIGNED_APK"

echo "[6/6] Verifying signatures and package metadata"
DEBUG_REPORT=$(apksigner verify --verbose --print-certs "$DEBUG_APK")
UNIVERSAL_REPORT=$(apksigner verify --verbose --print-certs "$UNIVERSAL_APK")
printf '%s\n' "$DEBUG_REPORT"
printf '%s\n' "$UNIVERSAL_REPORT"
grep -Fq 'Verified using v3 scheme (APK Signature Scheme v3): true' <<<"$DEBUG_REPORT"
grep -Fq 'Verified using v2 scheme (APK Signature Scheme v2): true' <<<"$UNIVERSAL_REPORT"
if grep -Fq 'Verified using v3 scheme (APK Signature Scheme v3): true' \
        <<<"$UNIVERSAL_REPORT"; then
    echo "Universal APK unexpectedly contains a v3 signature" >&2
    exit 1
fi

BADGING=$(aapt2 dump badging "$DEBUG_APK")
grep -Fq "package: name='org.ostadix.accessory'" <<<"$BADGING"
grep -Fq "sdkVersion:'33'" <<<"$BADGING"
grep -Fq "targetSdkVersion:'34'" <<<"$BADGING"
printf '%s\n' "$BADGING" | sed -n '1,8p'
ls -lh "$DEBUG_APK" "$UNIVERSAL_APK"
echo "$DEBUG_APK"
echo "$UNIVERSAL_APK"
