"""Run retained Rust replay DATA controls without invoking a native compiler."""
import argparse
import json
import sys
from pathlib import Path

EXPECTED_IDS = ('baseline_actual_worker_shape_reaches_missing_unit_replay', 'candidate_maps_complete_emitted_names_across_uuid_index_reorder', 'multiline_frontend_metadata_raw_lineage_and_inputs_retained', 'missing_emitted_output_is_not_partial_success', 'extra_emitted_output_rejects_complete_inventory', 'duplicate_emitted_filename_with_distinct_ids_is_ambiguous', 'duplicate_capture_unit_id_with_distinct_filenames_rejects', 'ir_must_belong_to_exact_replay_directory', 'emitted_artifact_requires_ll_suffix', 'wrong_replay_emit_contract_rejects', 'different_replay_outdir_cannot_rebind_existing_units', 'noncanonical_replay_directory_rejects', 'duplicate_replay_emit_option_rejects', 'separate_output_option_cannot_replace_worker_contract', 'per_unit_replay_command_is_not_default_worker_evidence', 'actual_event_replay_failure_rejects', 'injected_executed_argv_is_not_default_worker_evidence', 'unit_producer_must_match_owning_registered_rustc', 'unit_kind_must_match_owning_rustc', 'unit_frontend_version_must_equal_full_owner_version', 'unknown_frontend_metadata_drift_changes_action', 'effective_sysroot_drift_changes_action', 'default_sysroot_drift_changes_action', 'sysroot_source_drift_changes_action', 'ir_layout_drift_changes_unit', 'unknown_ir_metadata_drift_changes_unit', 'recorded_dependency_order_is_not_sorted_away', 'missing_dependency_changes_unit', 'semantic_flags_drift_changes_actual_action_contract', 'cargo_parent_remains_explicitly_unsupported', 'sealed_occurrence_order_rejects_equal_counter_reordering', 'sealed_occurrence_multiplicity_rejects_independently')
FALSE_QUALIFICATIONS = (
    "capture_admitted", "compiler_execution", "decoder_execution",
    "original_order_producer_qualified", "provider_closure_qualified",
    "runtime_qualified", "cross_ISA_qualified", "PYC_native_semantics_qualified",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path, label):
    namespace = {"__name__": "AUTHORED_DATA_" + label, "__file__": str(path)}
    exec(compile(path.read_bytes(), str(path), "exec"), namespace)
    return namespace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    root = parser.parse_args().root.resolve(strict=True)
    require(sys.flags.optimize == 0 and __debug__, "optimization must be disabled")
    fixture = root / "tests/fixtures/ocore_rust_replay"
    controls = load(fixture / "profile_controls.py", "CONTROLS")
    result = controls["run_controls"](
        load(fixture / "source_order_baseline.py", "BASELINE"),
        load(root / "src/bin/olangc/native_runtime/general_source_order_join.py", "CANDIDATE"),
        (fixture / "registry.json").read_bytes(),
    )
    require(type(result) is dict and type(result.get("controls")) is list,
            "control result inventory absent")
    rows = result["controls"]
    require(len(rows) == 32 and all(type(row) is dict for row in rows),
            "exactly 32 control rows required")
    identities = [row.get("name") for row in rows]
    require(identities == list(EXPECTED_IDS) and len(set(identities)) == 32,
            "control membership or order differs")
    require(result.get("all_pass") is True and all(row.get("pass") is True for row in rows),
            "DATA controls failed")
    require(not any(row.get(key) for row in rows
                    for key in ("skip", "skipped", "ignored", "error", "xfail", "xpass")),
            "forbidden outcome marker")
    require(all(result.get(key) is False for key in FALSE_QUALIFICATIONS),
            "qualification flags must remain false")
    print(json.dumps({"schema": "ocore-rust-replay-portable-controls-v1",
                      "success": True, "controls": 32, "qualification": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
