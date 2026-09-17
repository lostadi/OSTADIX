#!/data/data/com.termux/files/usr/bin/bash
# Measure one foreground-only PixelAiProbe request without changing security or service state.
#
# This harness deliberately refuses to run while the device is locked or when the probe is not
# both resumed and the focused window. It reads only PixelAiProbe log entries and synthetic probe
# results. Redirect stdout to a chosen evidence file if a durable capture is wanted.

set -Eeuo pipefail

PROBE_PACKAGE="org.ostadix.pixelai.probe"
PROBE_COMPONENT="${PROBE_PACKAGE}/.MainActivity"
TRACE_ROOT="/sys/kernel/tracing"
TRACE_NAME="ostadix_pixel_ai_${$}"
TRACE_DIR="${TRACE_ROOT}/instances/${TRACE_NAME}"
TRACE_CREATED=0

usage() {
    printf 'Usage: %s prompt|summary|image|speech\n' "${0##*/}" >&2
}

die() {
    printf 'REFUSED: %s\n' "$*" >&2
    exit 2
}

cleanup() {
    local cleanup_status=$?
    set +e
    if (( TRACE_CREATED )); then
        su -c "printf '0\\n' > '${TRACE_DIR}/tracing_on'" >/dev/null 2>&1
        su -c "rmdir '${TRACE_DIR}'" >/dev/null 2>&1
    fi
    return "$cleanup_status"
}

trap cleanup EXIT
trap 'exit 130' INT TERM HUP

[[ $# -eq 1 ]] || {
    usage
    exit 2
}

case "$1" in
    prompt)
        ANDROID_ACTION="${PROBE_PACKAGE}.RUN_PROMPT"
        SCOPES=(prompt)
        TIMEOUT_SECONDS=180
        ;;
    summary)
        ANDROID_ACTION="${PROBE_PACKAGE}.RUN_SUMMARY"
        SCOPES=(summary)
        TIMEOUT_SECONDS=180
        ;;
    image)
        ANDROID_ACTION="${PROBE_PACKAGE}.RUN_IMAGE"
        SCOPES=(image)
        TIMEOUT_SECONDS=180
        ;;
    speech)
        ANDROID_ACTION="${PROBE_PACKAGE}.RUN_SPEECH_STATUS"
        SCOPES=(speech)
        TIMEOUT_SECONDS=60
        ;;
    *)
        usage
        exit 2
        ;;
esac

command -v su >/dev/null 2>&1 || die "root shell is unavailable; private trace capture cannot be configured"
/system/bin/pm path "$PROBE_PACKAGE" >/dev/null 2>&1 || die "${PROBE_PACKAGE} is not installed"

# Fail closed if lock state cannot be read. A resumed ActivityRecord alone is insufficient because
# Android can retain one behind the secure keyguard.
TRUST_STATE="$(/system/bin/dumpsys trust 2>/dev/null || true)"
if ! grep -Eq 'deviceLocked=0([,[:space:]]|$)' <<<"$TRUST_STATE"; then
    LOCK_LINE="$(grep -m1 -E 'deviceLocked=' <<<"$TRUST_STATE" || true)"
    die "device is locked or lock state is unavailable (${LOCK_LINE:-no deviceLocked state}); unlock it without changing security settings"
fi

ACTIVITY_STATE="$(/system/bin/dumpsys activity activities 2>/dev/null || true)"
if ! grep -Eq '(ResumedActivity:|topResumedActivity=|mResumedActivity:).*org\.ostadix\.pixelai\.probe/\.MainActivity' <<<"$ACTIVITY_STATE"; then
    die "PixelAiProbe MainActivity is not the resumed activity; open it and leave it visible"
fi

WINDOW_STATE="$(/system/bin/dumpsys window 2>/dev/null || true)"
if ! grep -Eq 'mCurrentFocus=.*org\.ostadix\.pixelai\.probe/org\.ostadix\.pixelai\.probe\.MainActivity' <<<"$WINDOW_STATE"; then
    CURRENT_FOCUS="$(grep -m1 -E 'mCurrentFocus=' <<<"$WINDOW_STATE" || true)"
    die "PixelAiProbe is not the focused top window (${CURRENT_FOCUS:-focus unavailable})"
fi

read_root_file() {
    local path=$1
    su -c "/system/bin/cat '${path}'" 2>/dev/null || true
}

read_power_stats() {
    su -c '/system/bin/dumpsys android.hardware.power.stats.IPowerStats/default' 2>/dev/null || true
}

read_memory() {
    local package=$1
    /system/bin/dumpsys meminfo "$package" 2>/dev/null | awk '
        $1 == "TOTAL" {
            printf "pss_kb=%s rss_kb=%s swap_pss_kb=%s", $2, $6, $5
            found = 1
            exit
        }
        END {
            if (!found) {
                printf "not_running_or_unavailable"
            }
        }
    '
}

collect_snapshot() {
    local label=$1
    local inference_raw inference_total power_stats thermal_status
    local energy_tpu energy_s7 energy_s9 probe_mem aicore_mem asoss_mem

    inference_raw="$(read_root_file /sys/class/edgetpu/edgetpu-soc/device/inference_count)"
    inference_total="$(awk '{ for (i = 1; i <= NF; i++) total += $i } END { print total + 0 }' <<<"$inference_raw")"
    power_stats="$(read_power_stats)"
    energy_tpu="$(awk '/^[[:space:]]*TPU[[:space:]]*:/ { print $(NF - 1); exit }' <<<"$power_stats")"
    energy_s7="$(awk '/\[S7M_VDD_TPU\]:TPU/ { print $(NF - 1); exit }' <<<"$power_stats")"
    energy_s9="$(awk '/\[S9M_VDD_TPU_M\]:TPU/ { print $(NF - 1); exit }' <<<"$power_stats")"
    thermal_status="$(/system/bin/dumpsys thermalservice 2>/dev/null | awk -F': ' '/^Thermal Status:/ { print $2; exit }')"
    probe_mem="$(read_memory "$PROBE_PACKAGE")"
    aicore_mem="$(read_memory com.google.android.aicore)"
    asoss_mem="$(read_memory com.google.android.as.oss)"

    printf '\nSNAPSHOT %s utc=%s\n' "$label" "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    printf 'edgetpu_inference_count_raw=%s total=%s\n' "${inference_raw:-unavailable}" "${inference_total:-unavailable}"
    printf 'energy_tpu_mWs=%s rail_s7_tpu_mWs=%s rail_s9_tpu_mWs=%s\n' \
        "${energy_tpu:-unavailable}" "${energy_s7:-unavailable}" "${energy_s9:-unavailable}"
    printf 'thermal_status=%s\n' "${thermal_status:-unavailable}"
    printf 'memory_probe=%s\n' "$probe_mem"
    printf 'memory_aicore=%s\n' "$aicore_mem"
    printf 'memory_as_oss=%s\n' "$asoss_mem"

    if [[ $label == before ]]; then
        BEFORE_INFERENCE_TOTAL=$inference_total
        BEFORE_ENERGY_TPU=$energy_tpu
        BEFORE_ENERGY_S7=$energy_s7
        BEFORE_ENERGY_S9=$energy_s9
    else
        AFTER_INFERENCE_TOTAL=$inference_total
        AFTER_ENERGY_TPU=$energy_tpu
        AFTER_ENERGY_S7=$energy_s7
        AFTER_ENERGY_S9=$energy_s9
    fi
}

numeric_delta() {
    local after=${1:-}
    local before=${2:-}
    if [[ $after =~ ^-?[0-9]+([.][0-9]+)?$ && $before =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
        awk -v after="$after" -v before="$before" 'BEGIN { printf "%.2f", after - before }'
    else
        printf 'unavailable'
    fi
}

fresh_probe_logs() {
    /system/bin/logcat -d -v epoch 'PixelAiProbe:I' '*:S' 2>/dev/null |
        awk -v start="$LOG_START_EPOCH" '$1 + 0 >= start + 0'
}

scope_is_terminal() {
    local scope=$1
    grep -Eq "\[${scope}\] (complete|setup[.]failure)" <<<"$FRESH_LOGS"
}

all_scopes_terminal() {
    local scope
    for scope in "${SCOPES[@]}"; do
        scope_is_terminal "$scope" || return 1
    done
    return 0
}

[[ -d "${TRACE_ROOT}/instances" && -d "${TRACE_ROOT}/events/edgetpu" ]] ||
    die "Edge TPU tracepoints or trace instances are unavailable"

if ! su -c "/system/bin/mkdir '${TRACE_DIR}'" >/dev/null 2>&1; then
    die "could not create private trace instance ${TRACE_NAME}"
fi
TRACE_CREATED=1

if ! su -c "printf '0\\n' > '${TRACE_DIR}/tracing_on' && \
printf '2048\\n' > '${TRACE_DIR}/buffer_size_kb' && \
printf '1\\n' > '${TRACE_DIR}/events/edgetpu/enable' && \
: > '${TRACE_DIR}/trace'" >/dev/null 2>&1; then
    die "could not configure private Edge TPU trace instance"
fi

printf 'PixelAiProbe foreground measurement\n'
printf 'action=%s android_action=%s timeout_seconds=%s\n' "$1" "$ANDROID_ACTION" "$TIMEOUT_SECONDS"
printf 'inputs=probe-owned synthetic constants only; speech is readiness-only and opens no microphone\n'
printf 'placement_rule=TPU/NPU use requires correlated Edge TPU events/counters; API completion alone is not proof\n'

collect_snapshot before

LOG_START_EPOCH="$(date +%s.%3N)"
WALL_START_MS="$(date +%s%3N)"
su -c "printf '1\\n' > '${TRACE_DIR}/tracing_on'" >/dev/null
su -c "printf 'OSTADIX_PIXEL_AI_BEGIN action=%s\\n' '$1' > '${TRACE_DIR}/trace_marker'" >/dev/null 2>&1 || true

# The manifest exposes these as Activity intent actions (not a BroadcastReceiver), so the existing
# visibly resumed singleTop Activity receives this explicit action through onNewIntent().
set +e
START_OUTPUT="$(/system/bin/am start -W -n "$PROBE_COMPONENT" -a "$ANDROID_ACTION" --activity-single-top 2>&1)"
START_STATUS=$?
set -e
printf '\nACTIVITY_TRIGGER\n%s\n' "$START_OUTPUT"

DEADLINE=$(( $(date +%s) + TIMEOUT_SECONDS ))
RUN_STATUS=0
RUN_OUTCOME="completed"
FRESH_LOGS=""

if (( START_STATUS != 0 )); then
    RUN_STATUS=3
    RUN_OUTCOME="activity_trigger_failed"
else
    while :; do
        FRESH_LOGS="$(fresh_probe_logs)"
        if all_scopes_terminal; then
            if grep -Eq '\[[^]]+\] [^[:space:]]*[.]failure' <<<"$FRESH_LOGS"; then
                RUN_STATUS=4
                RUN_OUTCOME="completed_with_api_failure"
            fi
            break
        fi

        if grep -Fq '[lifecycle] paused' <<<"$FRESH_LOGS"; then
            RUN_STATUS=5
            RUN_OUTCOME="aborted_when_activity_paused"
            break
        fi

        if (( $(date +%s) >= DEADLINE )); then
            RUN_STATUS=6
            RUN_OUTCOME="timeout"
            break
        fi
        sleep 1
    done
fi

WALL_END_MS="$(date +%s%3N)"
su -c "printf 'OSTADIX_PIXEL_AI_END outcome=%s\\n' '$RUN_OUTCOME' > '${TRACE_DIR}/trace_marker'" >/dev/null 2>&1 || true
su -c "printf '0\\n' > '${TRACE_DIR}/tracing_on'" >/dev/null 2>&1 || true

collect_snapshot after

TRACE_OUTPUT="$(su -c "/system/bin/cat '${TRACE_DIR}/trace'" 2>/dev/null || true)"
TRACE_EVENT_COUNT="$(awk '!/^#/ && NF { count++ } END { print count + 0 }' <<<"$TRACE_OUTPUT")"
TRACE_EDGETPU_EVENT_COUNT="$(grep -Ec ': edgetpu_[^:]+:' <<<"$TRACE_OUTPUT" || true)"
TRACE_LINE_COUNT="$(awk 'END { print NR + 0 }' <<<"$TRACE_OUTPUT")"

printf '\nDELTAS wall_ms=%s edgetpu_inference_total=%s energy_tpu_mWs=%s rail_s7_tpu_mWs=%s rail_s9_tpu_mWs=%s\n' \
    "$(( WALL_END_MS - WALL_START_MS ))" \
    "$(numeric_delta "$AFTER_INFERENCE_TOTAL" "$BEFORE_INFERENCE_TOTAL")" \
    "$(numeric_delta "$AFTER_ENERGY_TPU" "$BEFORE_ENERGY_TPU")" \
    "$(numeric_delta "$AFTER_ENERGY_S7" "$BEFORE_ENERGY_S7")" \
    "$(numeric_delta "$AFTER_ENERGY_S9" "$BEFORE_ENERGY_S9")"

printf '\nPROBE_LOGS_BEGIN\n%s\nPROBE_LOGS_END\n' "${FRESH_LOGS:-<no PixelAiProbe entries observed>}"

printf '\nEDGETPU_TRACE_SUMMARY records=%s edgetpu_events=%s lines=%s\n' \
    "$TRACE_EVENT_COUNT" "$TRACE_EDGETPU_EVENT_COUNT" "$TRACE_LINE_COUNT"
if (( TRACE_LINE_COUNT > 500 )); then
    printf 'trace_output=first_500_lines; redirect a rerun and narrow interference if a complete trace is required\n'
fi
printf 'EDGETPU_TRACE_BEGIN\n'
sed -n '1,500p' <<<"$TRACE_OUTPUT"
printf 'EDGETPU_TRACE_END\n'

FINAL_TRUST_STATE="$(/system/bin/dumpsys trust 2>/dev/null || true)"
FINAL_WINDOW_STATE="$(/system/bin/dumpsys window 2>/dev/null || true)"
if grep -Eq 'deviceLocked=0([,[:space:]]|$)' <<<"$FINAL_TRUST_STATE" &&
        grep -Eq 'mCurrentFocus=.*org\.ostadix\.pixelai\.probe/org\.ostadix\.pixelai\.probe\.MainActivity' <<<"$FINAL_WINDOW_STATE"; then
    FOREGROUND_AFTER="verified_unlocked_and_focused"
else
    FOREGROUND_AFTER="not_verified_after_run"
fi

printf '\nRESULT outcome=%s exit_status=%s foreground_after=%s\n' \
    "$RUN_OUTCOME" "$RUN_STATUS" "$FOREGROUND_AFTER"
printf 'CAUTION energy and global TPU counters are cumulative and can include concurrent system workloads; correlate them with trace events and probe timing.\n'

exit "$RUN_STATUS"
