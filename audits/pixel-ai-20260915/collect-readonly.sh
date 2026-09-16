#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

SYSTEM_BIN=/system/bin
DEVICE_TPU=/sys/class/edgetpu/edgetpu-soc/device

section() {
    printf '\n===== %s =====\n' "$1"
}

package_evidence() {
    local package_name=$1
    local package_dump
    local apk_path

    if ! pm path "$package_name" >/dev/null 2>&1; then
        printf '%s: not installed\n' "$package_name"
        return
    fi

    package_dump=$($SYSTEM_BIN/dumpsys package "$package_name")
    printf '\n[%s]\n' "$package_name"
    printf '%s\n' "$package_dump" \
        | grep -m1 -E 'versionCode=|versionName=' || true
    printf '%s\n' "$package_dump" \
        | grep -m1 -E 'versionName=' || true
    printf '%s\n' "$package_dump" \
        | grep -m1 -E 'lastUpdateTime=' || true
    while IFS= read -r apk_path; do
        printf 'split=%s\n' "$apk_path"
        sha256sum "$apk_path"
    done < <(pm path "$package_name" | sed -n 's/^package://p')
}

read_power_tpu() {
    $SYSTEM_BIN/dumpsys android.hardware.power.stats.IPowerStats/default 2>/dev/null \
        | awk '
            /^============= PowerStats HAL 2.0 energy consumers/ {
                section = "consumer"; next
            }
            /^============= PowerStats HAL 2.0 energy meter/ {
                section = "meter"; next
            }
            /^========== End of PowerStats HAL 2.0 energy/ {
                section = ""
            }
            section == "consumer" && $1 == "TPU" {
                print "consumer_tpu_mWs=" $(NF - 1)
            }
            section == "meter" && /\[S7M_VDD_TPU\]:TPU/ {
                print "rail_s7m_vdd_tpu_mWs=" $(NF - 1)
            }
            section == "meter" && /\[S9M_VDD_TPU_M\]:TPU/ {
                print "rail_s9m_vdd_tpu_m_mWs=" $(NF - 1)
            }
        '
}

section "reported device"
printf 'manufacturer=%s\n' "$(getprop ro.product.manufacturer)"
printf 'model=%s\n' "$(getprop ro.product.model)"
printf 'device=%s\n' "$(getprop ro.product.device)"
printf 'board_platform=%s\n' "$(getprop ro.board.platform)"
printf 'soc_model=%s\n' "$(getprop ro.soc.model)"
printf 'release=%s sdk=%s\n' "$(getprop ro.build.version.release)" \
    "$(getprop ro.build.version.sdk)"
printf 'build_id=%s incremental=%s\n' "$(getprop ro.build.id)" \
    "$(getprop ro.build.version.incremental)"
printf 'security_patch=%s\n' "$(getprop ro.build.version.security_patch)"
printf 'fingerprint=%s\n' "$(getprop ro.build.fingerprint)"
printf 'kernel=%s\n' "$(uname -a)"
printf 'flash_locked_reported=%s verified_boot_reported=%s\n' \
    "$(getprop ro.boot.flash.locked)" "$(getprop ro.boot.verifiedbootstate)"
id
printf 'selinux=%s\n' "$(/system/bin/getenforce)"

section "active packages and split hashes"
for package_name in \
    com.google.android.aicore \
    com.google.android.as \
    com.google.android.as.oss \
    com.google.android.apps.recorder \
    com.google.android.inputmethod.latin \
    com.google.android.apps.pixel.agent \
    com.google.android.GoogleCamera \
    com.google.android.apps.photos \
    com.google.android.dialer \
    com.google.android.apps.translate \
    org.ostadix.pixelai.probe; do
    package_evidence "$package_name"
done

section "binder and process state"
$SYSTEM_BIN/service list \
    | grep -Ei 'on_device_intelligence|edgetpu|neuralnetworks|contexthub|ambient_context|personal_context' \
    || true
$SYSTEM_BIN/ps -A -o PID,PPID,UID,NAME \
    | grep -Ei 'aicore|android\.as$|android\.as\.oss|edgetpu|darwinn|contexthub' \
    || true
printf 'edgetpu_app_service=%s\n' "$(getprop init.svc.edgetpu_app_service)"
printf 'edgetpu_vendor_service=%s\n' "$(getprop init.svc.edgetpu_vendor_service)"
printf 'darwinn_service=%s\n' "$(getprop init.svc.hal_neuralnetworks_darwinn)"
printf 'tachyon_service=%s\n' "$(getprop init.svc.edgetpu_tachyon_service)"

section "framework AICore binding"
$SYSTEM_BIN/dumpsys on_device_intelligence | sed -n '1,120p'

section "selected effective AI configuration"
$SYSTEM_BIN/device_config list aicore \
    | grep -E '^(AicCommon__enable_npu_manager_integration|AicInference__enable_system_prompt_feature|AicInference__enable_thinking_mode|AicInference__use_runtime_model_loader|AicModels__file_group_binary_transparency_allowlist|AicModels__preloaded_data_directories|AicModels__preloaded_data_files_enabled|AicOnDeviceIntelligence__enabled|AicOnDeviceIntelligence__platform_embedding_feature_ids|AicOnDeviceIntelligence__platform_image_description_feature_ids|AicQuota__caller_app_visibility_check_enabled|AicQuota__client_side_caller_app_visibility_check_enabled)='
$SYSTEM_BIN/device_config list device_personalization_services \
    | grep -E '^(PcsAi__enable_genai_inference_service|PccSecurity__enable_genai_inference_service_security_policy|PcsAi__genai_service_connection_timeout_ms)=' \
    || true
$SYSTEM_BIN/aflags list \
    | grep -E '^com\.android\.npumanager\.' \
    || true

section "preloaded AICore model store"
if [[ -d /data/vendor/intelligence ]]; then
    du -sh /data/vendor/intelligence
    printf 'file_count=%s\n' "$(find /data/vendor/intelligence -type f | wc -l)"
    for model_metadata in \
        /data/vendor/intelligence/manifest.binarypb \
        /data/vendor/intelligence/config.binarypb \
        /data/vendor/intelligence/checkpoint.binarypb; do
        if [[ -f "$model_metadata" ]]; then
            stat -c '%n size=%s' "$model_metadata"
            sha256sum "$model_metadata"
        fi
    done
    find /data/vendor/intelligence -maxdepth 1 -type f \
        -name '*graph-custom_op.tflite' -printf '%f %s bytes\n' \
        | sort | sed -n '1,30p'
else
    echo '/data/vendor/intelligence is absent'
fi

section "Google Tensor runtime"
grep -E '^lib(edgetpu|OpenCL|gxp|_aion)' /vendor/etc/public.libraries.txt || true
for tensor_library in \
    /vendor/lib64/libedgetpu_litert.so \
    /vendor/lib64/libedgetpu_tflite_compiler.so \
    /vendor/lib64/libedgetpu_tachyon.google.so; do
    if [[ -f "$tensor_library" ]]; then
        stat -c '%n size=%s' "$tensor_library"
        sha256sum "$tensor_library"
    fi
done

section "EdgeTPU counters and energy"
for counter in \
    inference_count tpu_op_count device_utilization tpu_utilization \
    tpu_active_cycle_count tpu_throttle_stall_count \
    param_cache_hit_count param_cache_miss_count \
    reconfigurations hardware_preempt_count context_preempt_count \
    firmware_crash_count watchdog_timeout_count firmware_version; do
    if [[ -r "$DEVICE_TPU/$counter" ]]; then
        printf '%s=' "$counter"
        tr '\n' ' ' < "$DEVICE_TPU/$counter"
        printf '\n'
    fi
done
read_power_tpu

section "back-gesture ML lead"
printf 'effective_resource='
$SYSTEM_BIN/cmd overlay lookup --verbose \
    com.android.systemui com.android.systemui:bool/config_useBackGestureML \
    2>&1 | tail -n 1
printf 'device_config_use_model=%s\n' \
    "$($SYSTEM_BIN/device_config get systemui use_back_gesture_ml_model)"
printf 'device_config_model_name=%s\n' \
    "$($SYSTEM_BIN/device_config get systemui back_gesture_ml_model_name)"
printf 'device_config_threshold=%s\n' \
    "$($SYSTEM_BIN/device_config get systemui back_gesture_ml_model_threshold)"

section "context hub summary (no sensor-event payloads)"
$SYSTEM_BIN/dumpsys contexthub \
    | grep -E 'Name : CHRE|SwVersion|PeakMips|package: com\.google\.android\.as|=================== NANOAPPS|^handle :' \
    | sed -n '1,80p'

section "probe installation state"
$SYSTEM_BIN/dumpsys package org.ostadix.pixelai.probe 2>/dev/null \
    | grep -m1 -E 'User 0:.*installed=' \
    || true
echo 'rollback: pm uninstall org.ostadix.pixelai.probe'
