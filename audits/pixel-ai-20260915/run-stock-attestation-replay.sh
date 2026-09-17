#!/system/bin/sh
set -eu

PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin
export PATH

MODULE_ID=tricky_store
MODULE_DIR=/data/adb/modules/$MODULE_ID
KSUD=/data/adb/ksu/bin/ksud
BASELINE=/data/adb/ostadix-stock-attestation-preboot.txt
TRIGGER_PACKAGE=com.google.android.apps.miphone.aiai.autofill.testapps.autofillapp
TRIGGER_COMPONENT=$TRIGGER_PACKAGE/.SmartReplyActivity
AUDIT_ROOT=/data/data/com.termux/files/home/Ostadix-lang/audits/pixel-ai-20260915
ANALYZER=$AUDIT_ROOT/analyze-stock-attestation-replay.py
PYTHON=/data/data/com.termux/files/usr/bin/python
EXPECTED_TRIGGER_SHA256=cdc1af5634054a189f8c525cd09ae56cb5a878c748459a21a1ebd5456735862a
EXPECTED_EXTENSION_SHA256=f025e13fe0d2fd1b83ea4aad18745eeef1d5d0bec2ae7d7f01fa1485f85a59a6
MODE=${1:-run}

say() {
    echo "$*"
}

module_object() {
    "$KSUD" module list | awk 'BEGIN { RS="}" } /"id": "tricky_store"/ { print $0 "}" }'
}

module_enabled_value() {
    object=$(module_object)
    printf '%s\n' "$object" | sed -n 's/.*"enabled": "\([^"]*\)".*/\1/p'
}

state_report() {
    current_boot_id=$(cat /proc/sys/kernel/random/boot_id)
    preboot_boot_id=$(sed -n 's/^preboot_boot_id=//p' "$BASELINE" 2>/dev/null || true)
    tee_supervisor_pid=$(ps -A -o PID,ARGS | awk '$0 ~ /supervisor \.\/daemon \/data\/adb\/modules\/tricky_store/ { print $1 }' | tr '\n' ' ')
    say "utc=$(/system/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
    say "boot_id=$current_boot_id"
    say "preboot_boot_id=$preboot_boot_id"
    say "boot_id_changed=$([ -n "$preboot_boot_id" ] && [ "$current_boot_id" != "$preboot_boot_id" ] && echo true || echo false)"
    say "boot_completed=$(/system/bin/getprop sys.boot_completed)"
    say "module_disable_marker=$([ -e "$MODULE_DIR/disable" ] && echo present || echo absent)"
    say "module_enabled=$(module_enabled_value)"
    say "tee_simulator_pid=$(pidof TEESimulator 2>/dev/null || true)"
    say "tee_supervisor_pid=$tee_supervisor_pid"
    say "user_state=$(dumpsys user 2>/dev/null | grep 'State:' | sed 's/^[[:space:]]*//' | tr '\n' ' ')"
    module_object
}

if [ "$(id -u)" != "0" ]; then
    say "error=must_run_as_root"
    exit 2
fi

# KernelSU runs service.d scripts serially. When this verifier is installed as
# a one-shot service, detach the long wait from that boot sequence and remove
# the copied service after the child finishes.
case "$0" in
    /data/adb/service.d/*)
        if [ "${OSTADIX_REPLAY_SERVICE_CHILD:-0}" != "1" ]; then
            (
                service_path=$0
                trap 'rm -f "$service_path"' EXIT
                export OSTADIX_REPLAY_SERVICE_CHILD=1
                "$service_path" run
            ) >/data/local/tmp/ostadix-stock-attestation-service.log 2>&1 &
            exit 0
        fi
        ;;
esac

if [ "$MODE" = "--preflight" ]; then
    state_report
    say "preflight_only=true"
    exit 0
fi

if [ "$MODE" != "run" ]; then
    say "usage: $0 [--preflight|run]"
    exit 2
fi

# This script may be launched by KernelSU before credential-encrypted app data
# is available. Wait for boot completion and the first user unlock.
waited=0
while [ "$(getprop sys.boot_completed)" != "1" ]; do
    sleep 2
    waited=$((waited + 2))
    [ "$waited" -lt 43200 ] || {
        say "error=boot_timeout"
        "$KSUD" module enable "$MODULE_ID" || true
        exit 3
    }
done
while ! dumpsys user 2>/dev/null | grep 'State: RUNNING_UNLOCKED' >/dev/null; do
    sleep 2
    waited=$((waited + 2))
    [ "$waited" -lt 43200 ] || {
        say "error=user_unlock_timeout"
        "$KSUD" module enable "$MODULE_ID" || true
        exit 3
    }
done
sleep 10

stamp=$(/system/bin/date -u +%Y%m%dT%H%M%SZ)
OUT_DIR=${OSTADIX_REPLAY_OUT_DIR:-$AUDIT_ROOT/stock-attestation-replay-$stamp}
mkdir -p "$OUT_DIR"
exec >"$OUT_DIR/runner.log" 2>&1

reenable_needed=0
restore_module_marker() {
    if [ "$reenable_needed" = "1" ]; then
        "$KSUD" module enable "$MODULE_ID" >>"$OUT_DIR/module-restore.log" 2>&1 || true
        if [ -e "$MODULE_DIR/disable" ]; then
            echo "module_staged_for_next_boot=false" >>"$OUT_DIR/module-restore.log"
        else
            echo "module_staged_for_next_boot=true" >>"$OUT_DIR/module-restore.log"
        fi
    fi
    rm -f "$BASELINE"
}
trap restore_module_marker EXIT

say "output_dir=$OUT_DIR"
state_report | tee "$OUT_DIR/pre-request-state.txt"

# Android properties can be rewritten after init. Preserve the kernel's boot
# parameters because hardware-backed attestation reflects the verified boot
# state, not necessarily the values returned by getprop.
{
    grep -E '^androidboot\.(vbmeta\.device_state|verifiedbootstate|verifiedbooterror|verifyerrorpart|veritymode)[[:space:]]*=' /proc/bootconfig 2>/dev/null || true
    echo "property_vbmeta_device_state=$(getprop ro.boot.vbmeta.device_state)"
    echo "property_verified_boot_state=$(getprop ro.boot.verifiedbootstate)"
} >"$OUT_DIR/hardware-boot-state.txt"

if [ ! -s "$BASELINE" ]; then
    say "error=missing_preboot_baseline"
    exit 4
fi
cp "$BASELINE" "$OUT_DIR/preboot-state.txt"
if ! grep -q '^boot_id_changed=true$' "$OUT_DIR/pre-request-state.txt"; then
    say "error=full_reboot_not_proven"
    exit 4
fi
if [ ! -e "$MODULE_DIR/disable" ]; then
    say "error=tricky_store_not_disabled"
    exit 4
fi
if [ -n "$(pidof TEESimulator 2>/dev/null || true)" ]; then
    say "error=tee_simulator_still_loaded"
    exit 4
fi
if ! grep -q '^module_enabled=false$' "$OUT_DIR/pre-request-state.txt"; then
    say "error=kernel_su_does_not_report_module_disabled"
    exit 4
fi
if grep -q '^tee_supervisor_pid=[0-9]' "$OUT_DIR/pre-request-state.txt"; then
    say "error=tricky_store_supervisor_still_loaded"
    exit 4
fi
reenable_needed=1

start_epoch=$(/system/bin/date +%s)
/system/bin/log -t OstadixStockReplay "event=start epoch=$start_epoch" || true

# Record identities without reading prompts, replies, accounts, or private app
# data. The trigger itself contains only fixed synthetic text.
{
    echo "trigger_component=$TRIGGER_COMPONENT"
    cmd package resolve-activity --brief "$TRIGGER_COMPONENT"
    trigger_apk=$(pm path "$TRIGGER_PACKAGE" | sed -n 's/^package://p' | head -n 1)
    echo "trigger_apk=$trigger_apk"
    trigger_installed_sha256=$([ -n "$trigger_apk" ] && sha256sum "$trigger_apk" | awk '{print $1}')
    echo "trigger_installed_sha256=$trigger_installed_sha256"
    extension_apk=$(pm path org.ostadix.aicore.extension | sed -n 's/^package://p' | head -n 1)
    echo "extension_apk=$extension_apk"
    extension_installed_sha256=$([ -n "$extension_apk" ] && sha256sum "$extension_apk" | awk '{print $1}')
    echo "extension_installed_sha256=$extension_installed_sha256"
    pm path com.google.android.as || true
    pm path com.google.android.as.oss || true
    pm path com.google.android.aicore || true
} >"$OUT_DIR/artifact-identities.txt" 2>&1
if ! grep -q "^trigger_installed_sha256=$EXPECTED_TRIGGER_SHA256$" "$OUT_DIR/artifact-identities.txt"; then
    say "error=unexpected_trigger_identity"
    exit 6
fi
if ! grep -q "^extension_installed_sha256=$EXPECTED_EXTENSION_SHA256$" "$OUT_DIR/artifact-identities.txt"; then
    say "error=unexpected_extension_identity"
    exit 6
fi

for package_name in \
    com.google.android.as \
    com.google.android.as.oss \
    com.google.android.aicore \
    com.google.android.apps.pixel.psi \
    "$TRIGGER_PACKAGE"
do
    am force-stop "$package_name"
done

run_request() {
    request_number=$1
    request_file="$OUT_DIR/request-$request_number.txt"
    echo "request=$request_number start_utc=$(/system/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" >"$request_file"
    am start -S -W -f 0x10008000 -n "$TRIGGER_COMPONENT" >>"$request_file" 2>&1 || true
    sleep 12
    echo "request=$request_number end_utc=$(/system/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$request_file"
}

capture_since_start() {
    logcat -b all -d -v epoch 2>/dev/null | awk -v start="$start_epoch" '$1 + 0 >= start'
}

filter_relevant() {
    grep -E 'OstadixStockReplay|OstadixAicoreExperiment|OstadixAicoreModule|ProtectedDownload|AiAiAutofill|AsiSmartReplyTrigger|RemoteAugmentedAutofillService|AICore|GenAiInference|TEESimulator' || true
}

run_request 1
capture_since_start | filter_relevant >"$OUT_DIR/relevant-after-request-1.log"

if grep -q 'PERMISSION_DENIED' "$OUT_DIR/relevant-after-request-1.log"; then
    say "manifest_denied_after_first_request=true"
    sleep 3
    run_request 2
else
    # Poll with real requests while an authorized manifest maps the factory
    # preload into the feature catalog. Stop on an OSTADIX callback, a concrete
    # remote denial, or the bounded provisioning deadline.
    say "manifest_denied_after_first_request=false"
    provision_timeout=${OSTADIX_PROVISION_TIMEOUT_SECONDS:-600}
    provision_deadline=$(($(date +%s) + provision_timeout))
    request_number=2
    while [ "$(date +%s)" -lt "$provision_deadline" ]; do
        if grep -q 'event=request_enter' "$OUT_DIR/relevant-after-request-1.log"; then
            break
        fi
        sleep 18
        run_request "$request_number"
        capture_since_start | filter_relevant >"$OUT_DIR/relevant-after-request-1.log"
        if grep -q 'event=request_enter\|PERMISSION_DENIED' "$OUT_DIR/relevant-after-request-1.log"; then
            break
        fi
        request_number=$((request_number + 1))
    done
fi

capture_since_start | filter_relevant >"$OUT_DIR/replay-relevant.log"
logcat -b all -d -v threadtime 2>/dev/null | filter_relevant >"$OUT_DIR/boot-relevant.log"
dumpsys activity service \
    com.google.android.as/com.google.android.apps.miphone.aiai.app.AiAiAugmentedAutofillService \
    >"$OUT_DIR/asi-service.txt" 2>&1 || true
dumpsys activity services com.google.android.as \
    >"$OUT_DIR/asi-services-fallback.txt" 2>&1 || true
dumpsys autofill | grep -A120 -B30 "$TRIGGER_PACKAGE" \
    >"$OUT_DIR/framework-autofill.txt" 2>&1 || true
dumpsys jobscheduler com.google.android.aicore \
    >"$OUT_DIR/aicore-jobs.txt" 2>&1 || true

set +e
"$PYTHON" "$ANALYZER" "$OUT_DIR" | tee "$OUT_DIR/analyzer.log"
analyzer_status=$?
set -e
say "test_finished=true"
say "tricky_store_will_be_staged_enabled_for_next_boot=true"
exit "$analyzer_status"
