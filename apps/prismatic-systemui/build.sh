#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

APP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_ROOT="$APP_ROOT/build"
INTERMEDIATES="$BUILD_ROOT/intermediates"
OUTPUT_DIR="$BUILD_ROOT/outputs/apk/debug"
ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-$HOME/android-sdk}
ANDROID_JAR=${ANDROID_JAR:-$ANDROID_SDK_ROOT/platforms/android-34/android.jar}
LIBXPOSED_API_AAR=${LIBXPOSED_API_AAR:-/data/data/com.termux/files/usr/tmp/libxposed-api-102.0.0.aar}
DEBUG_KEYSTORE=${DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}
EXPECTED_API_SHA256=423484a6e1807e7a423c4b88fcd8176d104318259d91791877fed88fe91479d0
MIN_SDK=31
TARGET_SDK=34
VERSION_CODE=2
VERSION_NAME=0.2.0-stage2

require_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required build tool: $1" >&2
        exit 1
    }
}

for tool in aapt2 apksigner d8 jar javac keytool sed sha256sum unzip; do
    require_tool "$tool"
done

[[ -f "$ANDROID_JAR" ]] || { echo "Android platform jar not found: $ANDROID_JAR" >&2; exit 1; }
[[ -f "$LIBXPOSED_API_AAR" ]] || {
    echo "libxposed API AAR not found: $LIBXPOSED_API_AAR" >&2
    echo "Set LIBXPOSED_API_AAR to the official io.github.libxposed:api:102.0.0 AAR." >&2
    exit 1
}

ACTUAL_API_SHA256=$(sha256sum "$LIBXPOSED_API_AAR" | sed 's/[[:space:]].*$//')
if [[ "$ACTUAL_API_SHA256" != "$EXPECTED_API_SHA256" ]]; then
    echo "Refusing unverified libxposed API AAR: $ACTUAL_API_SHA256" >&2
    exit 1
fi

if [[ -d "$INTERMEDIATES" ]]; then
    find "$INTERMEDIATES" -mindepth 1 -delete
fi
mkdir -p \
    "$INTERMEDIATES/compiled-res" \
    "$INTERMEDIATES/generated" \
    "$INTERMEDIATES/classes" \
    "$INTERMEDIATES/dex" \
    "$INTERMEDIATES/lib" \
    "$OUTPUT_DIR"

echo "[1/6] Extracting pinned compile-only libxposed API 102"
unzip -jo "$LIBXPOSED_API_AAR" classes.jar -d "$INTERMEDIATES/lib" >/dev/null
LIBXPOSED_CLASSES="$INTERMEDIATES/lib/classes.jar"

echo "[2/6] Compiling and linking Android resources"
aapt2 compile --dir "$APP_ROOT/app/src/main/res" \
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
mapfile -t JAVA_SOURCES < <(find \
    "$INTERMEDIATES/generated" "$APP_ROOT/app/src/main/java" \
    -type f -name '*.java' -print | sort)
javac \
    -encoding UTF-8 \
    -source 8 -target 8 \
    -bootclasspath "$ANDROID_JAR" \
    -classpath "$ANDROID_JAR:$LIBXPOSED_CLASSES" \
    -d "$INTERMEDIATES/classes" \
    "${JAVA_SOURCES[@]}"
jar cf "$INTERMEDIATES/module-classes.jar" -C "$INTERMEDIATES/classes" .
d8 \
    --min-api "$MIN_SDK" \
    --lib "$ANDROID_JAR" \
    --classpath "$LIBXPOSED_CLASSES" \
    --output "$INTERMEDIATES/dex" \
    "$INTERMEDIATES/module-classes.jar"

echo "[4/6] Packaging DEX and modern Xposed metadata"
UNSIGNED_APK="$INTERMEDIATES/PrismaticSystemUi-unsigned.apk"
cp "$INTERMEDIATES/base-unsigned.apk" "$UNSIGNED_APK"
jar uf "$UNSIGNED_APK" -C "$INTERMEDIATES/dex" classes.dex
jar uf "$UNSIGNED_APK" -C "$APP_ROOT/app/src/main/resources" META-INF

echo "[5/6] Signing APK"
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

OUTPUT_APK="$OUTPUT_DIR/PrismaticSystemUi-debug.apk"
apksigner sign \
    --ks "$DEBUG_KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --min-sdk-version "$MIN_SDK" \
    --v1-signing-enabled false \
    --v2-signing-enabled true \
    --v3-signing-enabled true \
    --v4-signing-enabled false \
    --alignment-preserved false \
    --out "$OUTPUT_APK" \
    "$UNSIGNED_APK"

echo "[6/6] Verifying signature, metadata, and package"
VERIFY_REPORT=$(apksigner verify --verbose --print-certs "$OUTPUT_APK")
printf '%s\n' "$VERIFY_REPORT"
if ! grep -Fq 'Verified using v3 scheme (APK Signature Scheme v3): true' <<<"$VERIFY_REPORT"; then
    echo "Output APK is missing its v3 signature" >&2
    exit 1
fi
for entry in java_init.list module.prop scope.list; do
    jar tf "$OUTPUT_APK" | grep -Fx "META-INF/xposed/$entry" >/dev/null || {
        echo "Missing META-INF/xposed/$entry" >&2
        exit 1
    }
done
aapt2 dump badging "$OUTPUT_APK" | sed -n '1,8p'
ls -lh "$OUTPUT_APK"
echo "$OUTPUT_APK"

