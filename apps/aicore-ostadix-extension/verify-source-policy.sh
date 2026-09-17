#!/data/data/com.termux/files/usr/bin/bash
# Ensure the in-process fail-closed gate matches the shared live policy.
set -euo pipefail

APP_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$APP_ROOT/../.." && pwd)
# shellcheck source=../../audits/pixel-ai-20260915/extension-compatibility-policy.sh
source "$REPO_ROOT/audits/pixel-ai-20260915/extension-compatibility-policy.sh"
GATE="$APP_ROOT/app/src/main/java/org/ostadix/aicore/extension/ExtensionGate.java"

for expected in \
        "$EXPECTED_AICORE_VERSION_CODE" "$EXPECTED_AICORE_VERSION_NAME" \
        "$EXPECTED_AICORE_APK_SHA256" "$EXPECTED_AICORE_SIGNER_SHA256" \
        "$EXPECTED_ASOSS_VERSION_CODE" "$EXPECTED_ASOSS_VERSION_NAME" \
        "$EXPECTED_ASOSS_APK_SHA256" "$EXPECTED_ASOSS_SIGNER_SHA256"; do
    grep -Fq "$expected" "$GATE" || {
        echo "source_policy_match=false missing=$expected"
        exit 3
    }
done

echo 'source_policy_match=true fields=8'
