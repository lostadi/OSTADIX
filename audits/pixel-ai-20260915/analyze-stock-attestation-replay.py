#!/data/data/com.termux/files/usr/bin/python
"""Evaluate one stock-KeyMint replay without reading generated reply text."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


EXPECTED_INTENT = "3a044ddbad08687073ec95031f0de36649149da20e225c5fac050829a3de7790"
EXPECTED_TRIGGER = "cdc1af5634054a189f8c525cd09ae56cb5a878c748459a21a1ebd5456735862a"
EXPECTED_EXTENSION = "f025e13fe0d2fd1b83ea4aad18745eeef1d5d0bec2ae7d7f01fa1485f85a59a6"
EVENT_RE = re.compile(r"\bevent=([a-z_]+)\b.*?\brequest_id=(\d+)\b")
FIELD_RE = re.compile(r"\b([a-z0-9_]+)=([^\s]+)")
PROVIDER_25_RE = re.compile(r"cp=\[25-([1-9][0-9]*)/([1-9][0-9]*)\]")


def read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def epoch(line: str) -> float | None:
    token = line.split(maxsplit=1)[0] if line else ""
    try:
        value = float(token)
    except ValueError:
        return None
    return value if value > 1_000_000_000 else None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: analyze-stock-attestation-replay.py OUTPUT_DIR", file=sys.stderr)
        return 2

    output = Path(sys.argv[1])
    replay = read(output / "replay-relevant.log")
    boot = read(output / "boot-relevant.log")
    asi = read(output / "asi-service.txt") + "\n" + read(output / "asi-services-fallback.txt")
    framework = read(output / "framework-autofill.txt")
    identities = read(output / "artifact-identities.txt")
    state = read(output / "pre-request-state.txt")
    hardware_boot = read(output / "hardware-boot-state.txt")

    requests: dict[str, dict[str, tuple[float | None, dict[str, str]]]] = {}
    input_shown_times: list[float] = []
    for line in replay.splitlines():
        timestamp = epoch(line)
        if "event=autofill_event value=input_shown" in line and timestamp is not None:
            input_shown_times.append(timestamp)
        match = EVENT_RE.search(line)
        if not match:
            continue
        event, request_id = match.groups()
        fields = dict(FIELD_RE.findall(line))
        requests.setdefault(request_id, {})[event] = (timestamp, fields)

    correlated: list[dict[str, object]] = []
    for request_id, events in requests.items():
        required = ("request_enter", "request_dispatched", "ostadix_selected", "result_forwarded")
        if any(name not in events for name in required):
            continue
        times = [events[name][0] for name in required]
        if any(value is None for value in times) or times != sorted(times):
            continue
        selected = events["ostadix_selected"][1]
        forwarded = events["result_forwarded"][1]
        if selected.get("intent_sha256") != EXPECTED_INTENT:
            continue
        if selected.get("source_index") != forwarded.get("selected_source_index"):
            continue
        forwarded_at = events["result_forwarded"][0]
        assert forwarded_at is not None
        shown_after = [value for value in input_shown_times if 0 <= value - forwarded_at <= 10]
        correlated.append(
            {
                "request_id": request_id,
                "source_index": selected.get("source_index"),
                "forwarded_epoch": forwarded_at,
                "caller_input_shown_after_forward": bool(shown_after),
            }
        )

    provider_25 = [(int(a), int(b)) for a, b in PROVIDER_25_RE.findall(asi)]
    manifest_success = "Successfully handled GetManifestConfig" in boot
    manifest_denied = "PERMISSION_DENIED" in boot
    manifest_failed = "Failed to handle GetManifestConfig" in boot
    tee_boot_lines = sum("TEESimulator" in line for line in boot.splitlines())
    feature_error_re = re.compile(
        r"Feature \d+ is not available|FEATURE_NOT_FOUND|RuntimeException: Uninitialized service"
    )
    feature_errors = sum(bool(feature_error_re.search(line)) for line in replay.splitlines())
    trigger_hash_ok = f"trigger_installed_sha256={EXPECTED_TRIGGER}" in identities
    extension_hash_ok = f"extension_installed_sha256={EXPECTED_EXTENSION}" in identities
    module_disabled = "module_enabled=false" in state
    different_boot = "boot_id_changed=true" in state
    no_simulator_process = "tee_simulator_pid=" in state and not re.search(
        r"^tee_simulator_pid=\d+", state, re.MULTILINE
    )
    no_simulator_supervisor = "tee_supervisor_pid=" in state and not re.search(
        r"^tee_supervisor_pid=\d+", state, re.MULTILINE
    )
    hardware_boot_eligible = all(
        (
            'androidboot.vbmeta.device_state = "locked"' in hardware_boot,
            'androidboot.verifiedbootstate = "green"' in hardware_boot,
            "androidboot.verifiedbooterror" not in hardware_boot,
            "androidboot.verifyerrorpart" not in hardware_boot,
        )
    )
    caller_correlated = any(item["caller_input_shown_after_forward"] for item in correlated)
    normalized_asi = asi.replace("rc=[31,11,1]", "rc=[31, 11, 1]")
    asi_ok = all(
        (
            bool(provider_25),
            "rc=[31, 11, 1]" in normalized_asi,
            re.search(r"hl=\[[1-9][0-9]*\]", asi) is not None,
            "component: com.google.android.apps.miphone.aiai.autofill.testapps.autofillapp/.SmartReplyActivity" in asi,
            "smartSuggestion:" in asi,
            re.search(r"response time: \+[0-9]+ms", asi) is not None,
        )
    )
    framework_ok = all(
        (
            "com.google.android.apps.miphone.aiai.autofill.testapps.autofillapp" in framework,
            "mHasCallback: true" in framework,
            "number augmented requests:" in framework,
        )
    )

    checks = {
        "boot_id_changed": different_boot,
        "kernel_su_reports_module_disabled": module_disabled,
        "no_tee_simulator_process": no_simulator_process,
        "no_tee_supervisor": no_simulator_supervisor,
        "hardware_verified_boot_eligible": hardware_boot_eligible,
        "no_tee_simulator_log_for_boot": tee_boot_lines == 0,
        "trigger_hash_matches": trigger_hash_ok,
        "extension_hash_matches": extension_hash_ok,
        "manifest_success_recorded": manifest_success,
        "manifest_permission_denied_absent": not manifest_denied,
        "manifest_failure_absent": not manifest_failed,
        "aicore_feature_errors_absent": feature_errors == 0,
        "single_request_ostadix_chain": bool(correlated),
        "asi_provider_25_nonempty_and_response_ok": asi_ok,
        "framework_augmented_session_recorded": framework_ok,
        "caller_shown_after_same_request_forward": caller_correlated,
    }
    result = {
        "candidate_end_to_end_result": "pass" if all(checks.values()) else "incomplete",
        "checks": checks,
        "correlated_requests": correlated,
        "provider_25_counts": provider_25,
        "tee_boot_line_count": tee_boot_lines,
        "feature_error_marker_count": feature_errors,
    }
    (output / "result-summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["candidate_end_to_end_result"] == "pass" else 5


if __name__ == "__main__":
    raise SystemExit(main())
