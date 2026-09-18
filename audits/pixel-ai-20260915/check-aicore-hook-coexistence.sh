#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Read-only gate for the exact prerequisite to a real system-chain replay:
# AICore must have usable model state while the pinned OSTADIX hook is loaded
# in AS.OSS. It prints identities and counts, never the activation token.

ASOSS=com.google.android.as.oss
AICORE=com.google.android.aicore
EXPECTED_TOKEN_OUTPUT_SHA256=fa7928586376938514db3dfcade3a16f14bde4c4586913601794891d45794ea8
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
READINESS="$ROOT/audits/pixel-ai-20260915/check-aicore-runtime-readiness.sh"

command -v su >/dev/null 2>&1 || {
    echo 'coexistence=false reason=root_unavailable'
    exit 2
}

asoss_pid=$(pidof "$ASOSS" 2>/dev/null | awk '{print $1}')
aicore_pid=$(pidof "$AICORE" 2>/dev/null | awk '{print $1}')
if [[ -z "$asoss_pid" || -z "$aicore_pid" ]]; then
    echo "asoss_pid=${asoss_pid:-stopped}"
    echo "aicore_pid=${aicore_pid:-stopped}"
    echo 'coexistence=false reason=required_process_stopped'
    exit 3
fi

maps=$(su -c "cat /proc/$asoss_pid/maps" 2>/dev/null || true)
vector_loaded=false
runtime_loaded=false
grep -Fq '/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so' <<<"$maps" && vector_loaded=true
grep -Eq '/org\.ostadix\.aicore\.extension-.*/lib/arm64/libostadix_runtime\.so' <<<"$maps" && runtime_loaded=true

token_hash=$(su -c 'settings get global ostadix_aicore_extension_token' | sha256sum | awk '{print $1}')
activation_matches=false
[[ "$token_hash" == "$EXPECTED_TOKEN_OUTPUT_SHA256" ]] && activation_matches=true

set +e
readiness_output=$("$READINESS" 2>&1)
readiness_status=$?
set -e
printf '%s\n' "$readiness_output"

inference_count=$(sed -n 's/^inference_info_count=//p' <<<"$readiness_output" | tail -1)
legacy_inference_count=$(sed -n 's/^aicore_legacy_inference_count=//p' <<<"$readiness_output" | tail -1)
mapping_count=$(sed -n 's/^loaded_model_mapping_count=//p' <<<"$readiness_output" | tail -1)
inference_count=${inference_count:-unknown}
legacy_inference_count=${legacy_inference_count:-unknown}
mapping_count=${mapping_count:-unknown}

model_ready=false
if [[ "$inference_count" =~ ^[0-9]+$ && "$inference_count" -gt 0 ]]; then
    model_ready=true
elif [[ "$legacy_inference_count" =~ ^[0-9]+$ && "$legacy_inference_count" -gt 0 ]]; then
    model_ready=true
elif [[ "$mapping_count" =~ ^[0-9]+$ && "$mapping_count" -gt 0 ]]; then
    model_ready=true
fi

echo "asoss_pid=$asoss_pid"
echo "aicore_pid=$aicore_pid"
echo "vector_loaded_in_asoss=$vector_loaded"
echo "ostadix_runtime_loaded_in_asoss=$runtime_loaded"
echo "activation_token_matches=$activation_matches"
echo "aicore_readiness_exit=$readiness_status"
echo "model_state_ready=$model_ready"

if [[ "$vector_loaded" == true && "$runtime_loaded" == true \
      && "$activation_matches" == true && "$model_ready" == true ]]; then
    echo 'coexistence=true action=run_correlated_system_request'
    exit 0
fi

echo 'coexistence=false reason=model_state_and_live_hook_not_simultaneously_ready'
exit 4
