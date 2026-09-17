#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
ANALYZER = HERE / "analyze-stock-attestation-replay.py"
INTENT = "3a044ddbad08687073ec95031f0de36649149da20e225c5fac050829a3de7790"
TRIGGER = "cdc1af5634054a189f8c525cd09ae56cb5a878c748459a21a1ebd5456735862a"
EXTENSION = "f025e13fe0d2fd1b83ea4aad18745eeef1d5d0bec2ae7d7f01fa1485f85a59a6"


def write_fixture(
    root: Path, *, denied: bool = False, split_ids: bool = False, feature_error: bool = False
) -> None:
    root.joinpath("pre-request-state.txt").write_text(
        "boot_id_changed=true\nmodule_enabled=false\n"
        "tee_simulator_pid=\ntee_supervisor_pid=\n"
    )
    root.joinpath("artifact-identities.txt").write_text(
        f"trigger_installed_sha256={TRIGGER}\n"
        f"extension_installed_sha256={EXTENSION}\n"
    )
    root.joinpath("hardware-boot-state.txt").write_text(
        'androidboot.vbmeta.device_state = "locked"\n'
        'androidboot.verifiedbootstate = "green"\n'
        "property_vbmeta_device_state=locked\n"
        "property_verified_boot_state=green\n"
    )
    boot = "09-16 I ProtectedDownload: Successfully handled GetManifestConfig\n"
    if denied:
        boot += "09-16 E ProtectedDownload: PERMISSION_DENIED\n"
    root.joinpath("boot-relevant.log").write_text(boot)
    forwarded_id = "8" if split_ids else "7"
    replay = (
        "1789581000.000 I OstadixAicoreExperiment: event=request_enter request_id=7 caller_uid=10201\n"
        "1789581000.010 I OstadixAicoreExperiment: event=request_dispatched request_id=7 cancellation_handle=true\n"
        f"1789581000.020 I OstadixAicoreExperiment: event=ostadix_selected request_id=7 source_index=1 intent_sha256={INTENT}\n"
        f"1789581000.030 I OstadixAicoreExperiment: event=result_forwarded request_id={forwarded_id} selected_source_index=1\n"
        "1789581000.040 I AsiSmartReplyTrigger: event=autofill_event value=input_shown\n"
    )
    if feature_error:
        replay += "1789581000.050 E AICore: FEATURE_NOT_FOUND: Feature 614 is not available.\n"
    root.joinpath("replay-relevant.log").write_text(replay)
    root.joinpath("asi-service.txt").write_text(
        "component: com.google.android.apps.miphone.aiai.autofill.testapps.autofillapp/.SmartReplyActivity\n"
        "smartSuggestion:\nresponse time: +84ms\n"
        "rc=[31, 11, 1], hl=[1], cp=[25-1/1][:r 20]\n"
    )
    root.joinpath("asi-services-fallback.txt").write_text("")
    root.joinpath("framework-autofill.txt").write_text(
        "com.google.android.apps.miphone.aiai.autofill.testapps.autofillapp\n"
        "mHasCallback: true\nnumber augmented requests: 1\n"
    )


def run_fixture(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ANALYZER), str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


with tempfile.TemporaryDirectory() as temp:
    passing = Path(temp) / "pass"
    passing.mkdir()
    write_fixture(passing)
    result = run_fixture(passing)
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads(passing.joinpath("result-summary.json").read_text())
    assert summary["candidate_end_to_end_result"] == "pass"

    failing = Path(temp) / "fail"
    failing.mkdir()
    write_fixture(failing, denied=True, split_ids=True)
    result = run_fixture(failing)
    assert result.returncode == 5, result.stdout + result.stderr
    summary = json.loads(failing.joinpath("result-summary.json").read_text())
    assert summary["candidate_end_to_end_result"] == "incomplete"
    assert not summary["checks"]["manifest_permission_denied_absent"]
    assert not summary["checks"]["single_request_ostadix_chain"]

    feature_failure = Path(temp) / "feature-fail"
    feature_failure.mkdir()
    write_fixture(feature_failure, feature_error=True)
    result = run_fixture(feature_failure)
    assert result.returncode == 5, result.stdout + result.stderr
    summary = json.loads(feature_failure.joinpath("result-summary.json").read_text())
    assert not summary["checks"]["aicore_feature_errors_absent"]
    assert summary["feature_error_marker_count"] == 1

print("stock-attestation analyzer tests passed")
