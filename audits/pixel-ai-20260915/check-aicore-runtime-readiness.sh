#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

# Read-only evidence gate for deciding whether a real AICore inference can be
# traced. It does not start, stop, clear, download, or modify any package.

DUMPSYS=/system/bin/dumpsys
SERVICE=/system/bin/service
AICORE_PACKAGE=com.google.android.aicore
AICORE_DATA=/data/user/0/com.google.android.aicore
WORK_DB="$AICORE_DATA/no_backup/androidx.work.workdb"

if ! command -v su >/dev/null 2>&1; then
  echo "readiness=false reason=root_unavailable"
  exit 2
fi

pid="$(pidof "$AICORE_PACKAGE" 2>/dev/null | awk '{print $1}')"
if [[ -z "$pid" ]]; then
  echo "aicore_process=stopped"
  echo "readiness=false reason=no_live_aicore_process"
  exit 3
fi

odi_dump="$($DUMPSYS on_device_intelligence 2>/dev/null)"
inference_count="$(printf '%s\n' "$odi_dump" | sed -n 's/.*inferenceInfos (\([0-9][0-9]*\) total).*/\1/p' | head -1)"
inference_count="${inference_count:-unknown}"

private_files="$(su -c "find '$AICORE_DATA/files' -type f ! -path '*/datastore/*' ! -path '*/mdd_pds_config/*' ! -name 'gms_icing_mdd_garbage_file' 2>/dev/null" || true)"
private_payload_count="$(printf '%s\n' "$private_files" | sed '/^$/d' | wc -l | tr -d ' ')"

loaded_model_maps="$(su -c "cat '/proc/$pid/maps' 2>/dev/null" \
  | grep -Eic '(^|/)(model|models|.*\.(tflite|litert|bin|task|weights))($|/|[[:space:]])' || true)"

client_packages="$($DUMPSYS activity services "$AICORE_PACKAGE" 2>/dev/null \
  | sed -n 's/.*Client AppBindRecord{[^ ]* ProcessRecord{[^ ]* [0-9][0-9]*:\([^/}]*\).*/\1/p' \
  | sort -u \
  | paste -sd, -)"

service_registered="$($SERVICE list 2>/dev/null | grep -c 'on_device_intelligence:' || true)"

preload_work="unavailable"
if command -v sqlite3 >/dev/null 2>&1; then
  sqlite_bin="$(command -v sqlite3)"
  preload_work="$(su -c "$sqlite_bin '$WORK_DB' \"select 'state=' || case state when 0 then 'ENQUEUED' when 1 then 'RUNNING' when 2 then 'SUCCEEDED' when 3 then 'FAILED' when 4 then 'BLOCKED' when 5 then 'CANCELLED' else 'UNKNOWN' end || '(' || state || '),attempts=' || run_attempt_count || ',stop_reason=' || stop_reason from workspec where worker_class_name like '%PreloadModel%' order by period_count desc limit 1;\"" 2>/dev/null || true)"
  preload_work="${preload_work:-absent}"
fi

echo "aicore_process=running pid=$pid"
echo "on_device_intelligence_registered=$service_registered"
echo "inference_info_count=$inference_count"
echo "app_private_payload_candidate_count=$private_payload_count"
echo "loaded_model_mapping_count=$loaded_model_maps"
echo "bound_client_packages=${client_packages:-none}"
echo "preload_model_work=$preload_work"

if [[ "$inference_count" == "0" && "$loaded_model_maps" == "0" ]]; then
  echo "readiness=false reason=no_observed_inference_or_loaded_model"
  exit 4
fi

echo "readiness=indeterminate action=trace_one_authorized_client_request"
