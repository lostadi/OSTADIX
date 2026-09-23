#!/data/data/com.termux/files/usr/bin/bash

# Pure compatibility policy shared by the live read-only inspector and its
# fixture tests. Sourcing this file performs no device or filesystem mutation.

EXPECTED_AICORE_VERSION_CODE=494417
EXPECTED_AICORE_VERSION_NAME=0.release.prod_aicore_20260723.00_RC11.964081323
EXPECTED_AICORE_APK_SHA256=67aa6c6cc457163d18b8cff35706eeffd60ac234fa10bf4f3b4b7bd8e1d45f57
EXPECTED_AICORE_SIGNER_SHA256=b7971ccc10a03932e14a3557a1b4c2a84be0ecb506777f0c72dd46cf5d7093c6
REVIEWED_AICORE_RC13_VERSION_CODE=494585
REVIEWED_AICORE_RC13_VERSION_NAME=0.release.prod_aicore_20260723.00_RC13.981368508
REVIEWED_AICORE_RC13_APK_SHA256=d3f749159f6d4b691093d6c8118b64fe3e7892b77180e8d473577e79114c864e

EXPECTED_ASOSS_VERSION_CODE=143685
EXPECTED_ASOSS_VERSION_NAME=1.0.release.962568596
EXPECTED_ASOSS_APK_SHA256=c08952bafbd19a4bcb4399aaebc17ae7b1685c8b20cad033a41b435fbfe3620c
EXPECTED_ASOSS_SIGNER_SHA256=071f09456bf1a8e8ad2e808ffe6a0ebc13582a7e6f9aba13e47280ad9a85d833

evaluate_extension_snapshot() {
    [[ $# == 8 ]] || {
        echo 'extension_compatible=false reason=invalid_snapshot action=disable_experimental_extension_only'
        return 3
    }
    local aicore_code=$1 aicore_name=$2 aicore_apk=$3 aicore_signer=$4
    local asoss_code=$5 asoss_name=$6 asoss_apk=$7 asoss_signer=$8

    local aicore_release_matches=false
    if [[ $aicore_code == "$EXPECTED_AICORE_VERSION_CODE" &&
          $aicore_name == "$EXPECTED_AICORE_VERSION_NAME" &&
          $aicore_apk == "$EXPECTED_AICORE_APK_SHA256" ]] ||
       [[ $aicore_code == "$REVIEWED_AICORE_RC13_VERSION_CODE" &&
          $aicore_name == "$REVIEWED_AICORE_RC13_VERSION_NAME" &&
          $aicore_apk == "$REVIEWED_AICORE_RC13_APK_SHA256" ]]; then
        aicore_release_matches=true
    fi
    if [[ $aicore_release_matches != true ||
          $aicore_signer != "$EXPECTED_AICORE_SIGNER_SHA256" ||
          $asoss_code != "$EXPECTED_ASOSS_VERSION_CODE" ||
          $asoss_name != "$EXPECTED_ASOSS_VERSION_NAME" ||
          $asoss_apk != "$EXPECTED_ASOSS_APK_SHA256" ||
          $asoss_signer != "$EXPECTED_ASOSS_SIGNER_SHA256" ]]; then
        echo 'extension_compatible=false action=disable_experimental_extension_only'
        return 3
    fi
    echo 'extension_compatible=true action=extension_may_continue'
}
