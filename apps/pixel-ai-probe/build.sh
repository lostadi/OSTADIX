#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

APP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BUILD_ROOT="$APP_ROOT/build"
MAVEN_DIR="$BUILD_ROOT/maven"
INTERMEDIATES="$BUILD_ROOT/intermediates"
OUTPUT_DIR="$BUILD_ROOT/outputs/apk/debug"
ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT:-$HOME/android-sdk}
ANDROID_JAR=${ANDROID_JAR:-$ANDROID_SDK_ROOT/platforms/android-34/android.jar}
DEBUG_KEYSTORE="$BUILD_ROOT/keystore/debug.keystore"
MIN_SDK=26
TARGET_SDK=34
VERSION_CODE=2
VERSION_NAME=0.1.1
APP_PACKAGE=org.ostadix.pixelai.probe

require_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required build tool: $1" >&2
        exit 1
    }
}

for tool in aapt2 apksigner d8 gradle grep jar java javac keytool python3 sed sha256sum sort unzip; do
    require_tool "$tool"
done

if [[ ! -f "$ANDROID_JAR" ]]; then
    echo "Android platform jar not found: $ANDROID_JAR" >&2
    exit 1
fi

echo "[1/8] Checking the privacy and foreground contract"
python3 "$APP_ROOT/tests/source_contract_test.py"

echo "[2/8] Resolving pinned official ML Kit artifacts"
gradle --no-daemon --console=plain -q \
    -p "$APP_ROOT" syncMlKitRuntime printMlKitRuntime

if [[ -d "$INTERMEDIATES" ]]; then
    find "$INTERMEDIATES" -mindepth 1 -delete
fi
mkdir -p \
    "$INTERMEDIATES/aar" \
    "$INTERMEDIATES/compiled-res" \
    "$INTERMEDIATES/generated" \
    "$INTERMEDIATES/classes" \
    "$INTERMEDIATES/dex" \
    "$INTERMEDIATES/package-files" \
    "$OUTPUT_DIR"

echo "[3/8] Extracting AAR bytecode and compiling dependency resources"
declare -a CLASS_INPUTS=()
declare -a RESOURCE_INPUTS=()
declare -A EXTRA_PACKAGE_SET=()
aar_index=0
shopt -s nullglob
for aar in "$MAVEN_DIR"/*.aar; do
    aar_index=$((aar_index + 1))
    aar_name=$(basename "$aar" .aar)
    aar_dir="$INTERMEDIATES/aar/$aar_name"
    mkdir -p "$aar_dir"
    unzip -q -o "$aar" -d "$aar_dir"

    if [[ -f "$aar_dir/classes.jar" ]]; then
        CLASS_INPUTS+=("$aar_dir/classes.jar")
    fi
    for embedded_jar in "$aar_dir"/libs/*.jar; do
        CLASS_INPUTS+=("$embedded_jar")
    done

    if [[ -f "$aar_dir/AndroidManifest.xml" ]]; then
        library_package=$(
            sed -n 's/.*package="\([A-Za-z0-9_.]*\)".*/\1/p' \
                "$aar_dir/AndroidManifest.xml" | head -n 1
        )
        if [[ -n "$library_package" && "$library_package" != "$APP_PACKAGE" ]]; then
            EXTRA_PACKAGE_SET["$library_package"]=1
        fi
    fi

    if [[ -d "$aar_dir/res" ]] && find "$aar_dir/res" -type f -print -quit | grep -q .; then
        compiled="$INTERMEDIATES/compiled-res/dependency-$aar_index.zip"
        aapt2 compile --dir "$aar_dir/res" -o "$compiled"
        RESOURCE_INPUTS+=("$compiled")
    fi

    if [[ -d "$aar_dir/assets" ]]; then
        mkdir -p "$INTERMEDIATES/package-files/assets"
        cp -R "$aar_dir/assets/." "$INTERMEDIATES/package-files/assets/"
    fi
    if [[ -d "$aar_dir/jni" ]]; then
        mkdir -p "$INTERMEDIATES/package-files/lib"
        cp -R "$aar_dir/jni/." "$INTERMEDIATES/package-files/lib/"
    fi
done
for dependency_jar in "$MAVEN_DIR"/*.jar; do
    CLASS_INPUTS+=("$dependency_jar")
done

app_resources="$INTERMEDIATES/compiled-res/app.zip"
aapt2 compile --dir "$APP_ROOT/app/src/main/res" -o "$app_resources"
RESOURCE_INPUTS+=("$app_resources")

mapfile -t EXTRA_PACKAGES < <(printf '%s\n' "${!EXTRA_PACKAGE_SET[@]}" | sort)
extra_packages_joined=""
for library_package in "${EXTRA_PACKAGES[@]}"; do
    if [[ -z "$extra_packages_joined" ]]; then
        extra_packages_joined="$library_package"
    else
        extra_packages_joined="$extra_packages_joined:$library_package"
    fi
done

echo "[4/8] Linking resources and compiling Java"
declare -a LINK_ARGS=(
    -o "$INTERMEDIATES/base-unsigned.apk"
    -I "$ANDROID_JAR"
    --manifest "$APP_ROOT/app/src/main/AndroidManifest.xml"
    --java "$INTERMEDIATES/generated"
    --custom-package "$APP_PACKAGE"
    --min-sdk-version "$MIN_SDK"
    --target-sdk-version "$TARGET_SDK"
    --version-code "$VERSION_CODE"
    --version-name "$VERSION_NAME"
    --auto-add-overlay
)
if [[ -n "$extra_packages_joined" ]]; then
    LINK_ARGS+=(--extra-packages "$extra_packages_joined")
fi
for compiled_resources in "${RESOURCE_INPUTS[@]}"; do
    LINK_ARGS+=(-R "$compiled_resources")
done
aapt_link_log="$INTERMEDIATES/aapt2-link.stderr.log"
if ! aapt2 link "${LINK_ARGS[@]}" 2>"$aapt_link_log"; then
    cat "$aapt_link_log" >&2
    exit 1
fi
# This Termux aapt2 build emits non-fatal package-ID diagnostics while generating an identical
# R.java for every --extra-packages namespace. Preserve the complete diagnostics without flooding
# the interactive build output.
aapt_package_diagnostics=$(grep -c 'No package ID 7f found for resource ID' "$aapt_link_log" || true)
if [[ "$aapt_package_diagnostics" -gt 0 ]]; then
    echo "aapt2 preserved $aapt_package_diagnostics non-fatal extra-package diagnostics in $aapt_link_log"
fi

mapfile -t JAVA_SOURCES < <(
    find "$INTERMEDIATES/generated" "$APP_ROOT/app/src/main/java" \
        -type f -name '*.java' -print | sort
)
classpath=$(IFS=:; echo "${CLASS_INPUTS[*]}")
javac \
    -encoding UTF-8 \
    --release 8 \
    -classpath "$ANDROID_JAR:$classpath" \
    -d "$INTERMEDIATES/classes" \
    "${JAVA_SOURCES[@]}"
jar cf "$INTERMEDIATES/app-classes.jar" -C "$INTERMEDIATES/classes" .
CLASS_INPUTS+=("$INTERMEDIATES/app-classes.jar")

echo "[5/8] Converting the application and resolved runtime to DEX"
d8 \
    --min-api "$MIN_SDK" \
    --lib "$ANDROID_JAR" \
    --output "$INTERMEDIATES/dex" \
    "${CLASS_INPUTS[@]}"

echo "[6/8] Packaging and signing the debug APK"
unsigned_apk="$INTERMEDIATES/PixelAiProbe-unsigned.apk"
cp "$INTERMEDIATES/base-unsigned.apk" "$unsigned_apk"
jar uf "$unsigned_apk" -C "$INTERMEDIATES/dex" .
if find "$INTERMEDIATES/package-files" -type f -print -quit | grep -q .; then
    jar uf "$unsigned_apk" -C "$INTERMEDIATES/package-files" .
fi

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

debug_apk="$OUTPUT_DIR/PixelAiProbe-debug.apk"
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
    --out "$debug_apk" \
    "$unsigned_apk"

echo "[7/8] Verifying signature, package metadata, and DEX payload"
verification=$(apksigner verify --verbose --print-certs "$debug_apk")
printf '%s\n' "$verification"
grep -Fq 'Verified using v2 scheme (APK Signature Scheme v2): true' <<<"$verification"
grep -Fq 'Verified using v3 scheme (APK Signature Scheme v3): true' <<<"$verification"
badging=""
badging_ok=false
badging_error="$INTERMEDIATES/aapt2-badging.stderr.log"
for attempt in 1 2 3; do
    if badging=$(aapt2 dump badging "$debug_apk" 2>"$badging_error"); then
        badging_ok=true
        break
    fi
    if [[ "$attempt" -lt 3 ]]; then
        sleep 1
    fi
done
if [[ "$badging_ok" != true ]]; then
    cat "$badging_error" >&2
    echo "aapt2 could not read signed APK metadata after 3 attempts" >&2
    exit 1
fi
grep -Fq "package: name='$APP_PACKAGE'" <<<"$badging"
grep -Fq "minSdkVersion:'$MIN_SDK'" <<<"$badging"
grep -Fq "targetSdkVersion:'$TARGET_SDK'" <<<"$badging"
printf '%s\n' "$badging" | sed -n '1,10p'
dex_count=$(jar tf "$debug_apk" | grep -Ec '^classes([0-9]+)?\.dex$')
if [[ "$dex_count" -lt 1 ]]; then
    echo "Signed APK contains no DEX payload" >&2
    exit 1
fi

echo "[8/8] Build artifact"
ls -lh "$debug_apk"
sha256sum "$debug_apk"
echo "$debug_apk"
