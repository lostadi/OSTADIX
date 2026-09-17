#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=extension-compatibility-policy.sh
source "$SCRIPT_DIR/extension-compatibility-policy.sh"

expected=(
    "$EXPECTED_AICORE_VERSION_CODE"
    "$EXPECTED_AICORE_VERSION_NAME"
    "$EXPECTED_AICORE_APK_SHA256"
    "$EXPECTED_AICORE_SIGNER_SHA256"
    "$EXPECTED_ASOSS_VERSION_CODE"
    "$EXPECTED_ASOSS_VERSION_NAME"
    "$EXPECTED_ASOSS_APK_SHA256"
    "$EXPECTED_ASOSS_SIGNER_SHA256"
)

output=$(evaluate_extension_snapshot "${expected[@]}")
[[ $output == 'extension_compatible=true action=extension_may_continue' ]]

for index in "${!expected[@]}"; do
    snapshot=("${expected[@]}")
    snapshot[$index]="mismatch-$index"
    set +e
    output=$(evaluate_extension_snapshot "${snapshot[@]}")
    status=$?
    set -e
    [[ $status == 3 ]]
    [[ $output == 'extension_compatible=false action=disable_experimental_extension_only' ]]
done

set +e
output=$(evaluate_extension_snapshot)
status=$?
set -e
[[ $status == 3 ]]
[[ $output == 'extension_compatible=false reason=invalid_snapshot action=disable_experimental_extension_only' ]]

echo 'compatibility_policy_tests=passed cases=10'
