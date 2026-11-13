"""Qualification guards for the aggregate O10 guest regression runner."""
import importlib.util
import copy
import json
import tempfile
import threading
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("o10_m1_regression_gate", ROOT / "scripts/verify_o10_m1_regressions.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

class O10M1RegressionGuards(unittest.TestCase):
    def test_missing_failure_or_cleanup_error_never_passes(self):
        for receipt in [{}, {"ok": False}, {"ok": 1},
                        {"ok": True, "error": "failed"},
                        {"ok": True, "cleanup_stop_error": "still running"}]:
            with self.subTest(receipt=receipt):
                self.assertFalse(gate.receipt_passes(receipt))
        self.assertTrue(gate.receipt_passes({"ok": True, "checks": ["actual pass"]}))

    def test_nested_skips_disqualify_even_with_success_status(self):
        for receipt in [{"ok": True, "skips": ["missing tool"]},
                        {"ok": True, "tests": [{"status": "skipped"}]},
                        {"ok": True, "nested": {"skipped": 1}}]:
            self.assertFalse(gate.receipt_passes(receipt))
        self.assertTrue(gate.receipt_passes({"ok": True, "skips": [], "skipped": 0}))

    def identities(self):
        return {"source_revision": "revision", "mcp_release": "revision",
                "profile_sha256": "profile", "monitor_sha256": "monitor",
                "seed_head_sha256": "seed", "frozen_runtime": {"sha256": "runtime"},
                "resident_result": {"sha256": "resident"},
                "hostile_mmio_result": {"sha256": "hostile"},
                "source_sha256": {"scripts/guest-gate.py": "guest",
                                  "scripts/verify_o10_m1_regressions.py": "driver"}, "gates": []}

    def test_resume_refuses_different_build_revision_or_gate_source(self):
        current = self.identities()
        for field in ("source_revision", "mcp_release", "profile_sha256", "monitor_sha256", "seed_head_sha256"):
            previous = copy.deepcopy(current)
            previous[field] = "different"
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.resumable_entries(previous, current)
        previous = copy.deepcopy(current)
        previous["source_sha256"]["scripts/guest-gate.py"] = "changed"
        with self.assertRaisesRegex(ValueError, "gate source"):
            gate.resumable_entries(previous, current)
        previous = copy.deepcopy(current)
        previous["source_sha256"]["scripts/verify_o10_m1_regressions.py"] = "old bookkeeping"
        self.assertEqual(gate.resumable_entries(previous, current), {})

    def test_resume_never_promotes_unknown_exit_or_incomplete_gate(self):
        current = self.identities()
        previous = copy.deepcopy(current)
        previous["gates"] = [
            {"gate_id": "provider", "ok": False},
            {"gate_id": "client", "ok": True, "command": {}},
            {"gate_id": "runtime", "ok": True, "command": {"returncode": 0, "timed_out": True}},
        ]
        self.assertEqual(gate.resumable_entries(previous, current), {})

    def test_resume_requires_unchanged_positive_child_receipt(self):
        current = self.identities()
        previous = copy.deepcopy(current)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            result = {"ok": True, "checks": ["fixture"]}
            path.write_text(json.dumps(result))
            previous["gates"] = [{"gate_id": "two_domains", "ok": True,
                "command": {"returncode": 0, "timed_out": False},
                "receipt": {"path": str(path), "sha256": gate.digest(path), "result": result}}]
            self.assertEqual(set(gate.resumable_entries(previous, current)), {"two_domains"})
            path.write_text(json.dumps({"ok": False}))
            with self.assertRaisesRegex(ValueError, "receipt"):
                gate.resumable_entries(previous, current)

    def test_parallel_scheduler_never_exceeds_two_workers(self):
        lock = threading.Lock()
        barrier = threading.Barrier(2)
        active = 0
        peak = 0
        def worker(item):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            barrier.wait(timeout=5)
            with lock:
                active -= 1
            return {"ok": True}
        items = [{"gate_id": str(i)} for i in range(4)]
        results = list(gate.bounded_results(items, worker, 2))
        self.assertEqual(len(results), 4)
        self.assertEqual(peak, 2)
        self.assertTrue(all(result["ok"] for _, result in results))

    def test_failure_stops_feeding_and_drains_already_running_gate(self):
        barrier = threading.Barrier(2)
        release_survivor = threading.Event()
        started = []
        def worker(item):
            barrier.wait(timeout=5)
            if item["gate_id"] == "first":
                return {"ok": False}
            if not release_survivor.wait(timeout=5):
                raise RuntimeError("survivor was not drained after observed failure")
            return {"ok": True}
        items = [{"gate_id": name} for name in ("first", "second", "never-third", "never-fourth")]
        results = []
        for item, result in gate.bounded_results(items, worker, 2,
                           on_start=lambda item: started.append(item["gate_id"])):
            results.append((item, result))
            if item["gate_id"] == "first":
                release_survivor.set()
        self.assertEqual(set(started), {"first", "second"})
        self.assertEqual({item["gate_id"] for item, _ in results}, {"first", "second"})
        self.assertEqual(sum(result["ok"] for _, result in results), 1)

    def test_resource_admission_can_serialize_two_worker_queue_without_losing_gates(self):
        rejected = []
        def admit(item, active):
            if active:
                rejected.append(item["gate_id"])
                return False
            return True
        items = [{"gate_id": str(i)} for i in range(3)]
        results = list(gate.bounded_results(items, lambda item: {"ok": True}, 2, admit=admit))
        self.assertEqual([item["gate_id"] for item, _ in results], ["0", "1", "2"])
        self.assertTrue(rejected)
        with self.assertRaises(ValueError):
            list(gate.bounded_results(items, lambda item: {"ok": True}, 3))

    def test_both_prerequisites_use_the_final_binder_semantic_validator(self):
        primary = {"gate_passed": True}
        hostile = {"gate_passed": True, "gate_id": "verify_o10_hostile_mmio"}
        with patch("verify_o10_m1.validate_resident", side_effect=[
                (primary, {"/private/primary/state/session"}, []),
                (hostile, {"/private/hostile/state/session"}, [])]) as validate:
            actual = gate.validate_m1_prerequisites(
                ROOT, Path("/build"), {"profile": "fixture"}, "revision",
                Path("/primary/result.json"), Path("/hostile/result.json"))
        self.assertEqual(actual, (primary, hostile))
        self.assertEqual(validate.call_count, 2)
        self.assertEqual(validate.call_args_list[0].kwargs, {})
        self.assertEqual(validate.call_args_list[1].kwargs, {"hostile": True})
        self.assertEqual(validate.call_args_list[0].args[-1], "revision")

    def test_rejected_component_cannot_be_promoted_by_driver_metadata(self):
        with patch("verify_o10_m1.validate_resident", side_effect=ValueError("bad actual gate")) as validate:
            with self.assertRaisesRegex(ValueError, "bad actual gate"):
                gate.validate_m1_prerequisites(
                    ROOT, Path("/build"), {}, "revision",
                    Path("/primary/result.json"), Path("/hostile/result.json"))
        self.assertEqual(validate.call_count, 1)

    def test_primary_and_hostile_must_have_distinct_real_guest_sessions(self):
        shared = {"/private/same/state/session"}
        with patch("verify_o10_m1.validate_resident", side_effect=[
                ({}, shared, []), ({}, shared, [])]):
            with self.assertRaisesRegex(ValueError, "distinct private VM"):
                gate.validate_m1_prerequisites(
                    ROOT, Path("/build"), {}, "revision",
                    Path("/primary/result.json"), Path("/hostile/result.json"))

    def test_resume_refuses_changed_component_prerequisite(self):
        current = self.identities()
        for name in ("resident_result", "hostile_mmio_result"):
            previous = copy.deepcopy(current)
            previous[name]["sha256"] = "another gate"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "prerequisite"):
                gate.resumable_entries(previous, current)

    def test_all_six_gates_use_distinct_forks_of_one_selected_seed(self):
        args = SimpleNamespace(output=Path("/private/evidence"), seed_state=Path("/private/seed"),
                               runtime=Path("/private/frozen"), build=Path("/private/build"))
        plan = gate.plan(args)
        self.assertEqual(len(plan), 6)
        self.assertEqual(len({entry["state"] for entry in plan}), 6)
        self.assertEqual({entry["fork_argv"][-3] for entry in plan}, {str(args.seed_state)})
        self.assertEqual(sum("--runtime" in entry["argv"] for entry in plan), 1)
        self.assertEqual(sum("--build" in entry["argv"] for entry in plan), 5)
        for entry in plan:
            self.assertEqual(entry["fork_argv"][-1], entry["state"])

if __name__ == "__main__":
    unittest.main()
