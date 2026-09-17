#!/data/data/com.termux/files/usr/bin/bash
# Read-only fail-closed compatibility gate for a future OSTADIX extension.
# This script does not install, patch, enable, disable, or restart anything.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=extension-compatibility-policy.sh
source "$SCRIPT_DIR/extension-compatibility-policy.sh"

for tool in apksigner mktemp sha256sum su; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "extension_compatible=false reason=missing_tool tool=$tool"
        exit 3
    }
done

TMP_DIR=$(mktemp -d "${TMPDIR:-/data/data/com.termux/files/usr/tmp}/ostadix-aicore-gate.XXXXXX")
cleanup() {
    find "$TMP_DIR" -mindepth 1 -delete 2>/dev/null || true
    rmdir "$TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

inspect_package() {
    local package=$1 prefix=$2
    local dump path local_apk code name apk signer
    dump=$(su -c "dumpsys package '$package'")
    code=$(sed -n 's/^[[:space:]]*versionCode=\([0-9][0-9]*\).*/\1/p' <<<"$dump" | head -n 1)
    name=$(awk -F= '/versionName=/{print $2; exit}' <<<"$dump" | tr -d '\r')
    path=$(su -c "pm path '$package'" | sed -n 's/^package://p' | head -n 1)
    [[ -n $path ]] || return 10
    local_apk="$TMP_DIR/${package}.apk"
    su -c "cat '$path'" >"$local_apk"
    apk=$(sha256sum "$local_apk")
    apk=${apk%% *}
    signer=$(apksigner verify --print-certs "$local_apk" |
        sed -n 's/^V3\.0 Signer: certificate SHA-256 digest: //p' | head -n 1)

    printf 'package=%s versionCode=%s versionName=%s apkSha256=%s signerSha256=%s\n' \
        "$package" "$code" "$name" "$apk" "$signer"
    printf -v "${prefix}_CODE" '%s' "$code"
    printf -v "${prefix}_NAME" '%s' "$name"
    printf -v "${prefix}_APK" '%s' "$apk"
    printf -v "${prefix}_SIGNER" '%s' "$signer"
}

inspect_package com.google.android.aicore AICORE || {
    echo 'extension_compatible=false reason=aicore_inspection_failed action=disable_experimental_extension_only'
    exit 3
}
inspect_package com.google.android.as.oss ASOSS || {
    echo 'extension_compatible=false reason=asoss_inspection_failed action=disable_experimental_extension_only'
    exit 3
}

evaluate_extension_snapshot \
    "$AICORE_CODE" "$AICORE_NAME" "$AICORE_APK" "$AICORE_SIGNER" \
    "$ASOSS_CODE" "$ASOSS_NAME" "$ASOSS_APK" "$ASOSS_SIGNER"
