#!/system/bin/sh
set -eu

PATH=/system/bin:/system/xbin:/vendor/bin:/data/adb/ksu/bin
export PATH

MODULE_ID=tricky_store
MODULE_DIR=/data/adb/modules/$MODULE_ID
KSUD=/data/adb/ksu/bin/ksud
SOURCE=/data/data/com.termux/files/home/Ostadix-lang/audits/pixel-ai-20260915/run-stock-attestation-replay.sh
ANALYZER=/data/data/com.termux/files/home/Ostadix-lang/audits/pixel-ai-20260915/analyze-stock-attestation-replay.py
SERVICE=/data/adb/service.d/60-ostadix-stock-attestation-replay.sh
BASELINE=/data/adb/ostadix-stock-attestation-preboot.txt
MODE=${1:-arm}

if [ "$(id -u)" != "0" ]; then
    echo "error=must_run_as_root"
    exit 2
fi

if [ "$MODE" = "--preflight" ]; then
    [ -x "$SOURCE" ] || { echo "error=missing_replay_runner"; exit 3; }
    /system/bin/sh -n "$SOURCE"
    /data/data/com.termux/files/usr/bin/python -c \
        'import sys; compile(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1], "exec")' \
        "$ANALYZER"
    echo "source=$SOURCE"
    echo "source_sha256=$(sha256sum "$SOURCE" | awk '{print $1}')"
    echo "service_exists=$([ -e "$SERVICE" ] && echo true || echo false)"
    echo "baseline_exists=$([ -e "$BASELINE" ] && echo true || echo false)"
    echo "tricky_store_disable_marker=$([ -e "$MODULE_DIR/disable" ] && echo present || echo absent)"
    echo "tee_simulator_pid=$(pidof TEESimulator 2>/dev/null || true)"
    echo "preflight_only=true"
    exit 0
fi

if [ "$MODE" = "--undo" ]; then
    rm -f "$SERVICE"
    rm -f "$BASELINE"
    "$KSUD" module enable "$MODULE_ID"
    echo "armed=false"
    echo "tricky_store_staged_enabled=true"
    exit 0
fi
if [ "$MODE" != "arm" ]; then
    echo "usage: $0 [--preflight|arm|--undo]"
    exit 2
fi

[ -x "$SOURCE" ] || { echo "error=missing_replay_runner"; exit 3; }
[ -r "$ANALYZER" ] || { echo "error=missing_replay_analyzer"; exit 3; }
[ -d "$MODULE_DIR" ] || { echo "error=missing_tricky_store_module"; exit 3; }
[ ! -e "$SERVICE" ] || { echo "error=one_shot_service_already_exists"; exit 3; }
[ ! -e "$BASELINE" ] || { echo "error=preboot_baseline_already_exists"; exit 3; }

staged=$SERVICE.tmp.$$
baseline_staged=$BASELINE.tmp.$$
rollback() {
    rm -f "$staged"
    rm -f "$baseline_staged"
    rm -f "$SERVICE"
    rm -f "$BASELINE"
    "$KSUD" module enable "$MODULE_ID" >/dev/null 2>&1 || true
}
trap rollback EXIT

{
    echo "preboot_boot_id=$(cat /proc/sys/kernel/random/boot_id)"
    echo "armed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "runner_sha256=$(sha256sum "$SOURCE" | awk '{print $1}')"
    echo "analyzer_sha256=$(sha256sum "$ANALYZER" | awk '{print $1}')"
} >"$baseline_staged"
chmod 0600 "$baseline_staged"
mv "$baseline_staged" "$BASELINE"
cp "$SOURCE" "$staged"
chmod 0755 "$staged"
mv "$staged" "$SERVICE"
"$KSUD" module disable "$MODULE_ID"

[ -e "$MODULE_DIR/disable" ] || { echo "error=disable_marker_missing"; exit 4; }
[ -x "$SERVICE" ] || { echo "error=one_shot_service_missing"; exit 4; }
[ -s "$BASELINE" ] || { echo "error=preboot_baseline_missing"; exit 4; }

trap - EXIT
echo "armed=true"
echo "service=$SERVICE"
echo "service_sha256=$(sha256sum "$SERVICE" | awk '{print $1}')"
echo "preboot_boot_id=$(sed -n 's/^preboot_boot_id=//p' "$BASELINE")"
echo "tricky_store_disable_marker=present"
echo "next_action=/system/bin/reboot"
