"""Negative controls for the M0 evidence binder; fixtures execute no guests."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("o10_acceptance", ROOT / "scripts/verify_o10_m0.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class M0EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="o10-m0-receipts-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.revision = "a" * 40
        self.build = self.root / "build"
        self.paths = {}

        def write(name, data):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data) if not isinstance(data, str) else data)
            return path
        self.write = write
        helper_names = {"scripts/verify_o10_m0.py", "scripts/verify_o10_journal.py",
                        "scripts/verify_o10_live.py", "scripts/verify_o10_regressions.py",
                        "scripts/o10.py", "scripts/okernel_unified_world.py",
                        "scripts/fork_okernel_state.py", "scripts/check_language_sources.py",
                        "ci/language-sources.json"} | {"scripts/" + x for x in gate.GATES.values()}
        names = gate.COMPILED | helper_names | {"tests/test_o10_fixture.py", "tests/test_okernel_fixture.py"}
        for name in names:
            write(name, "fixture " + name)
        self.compiler = write("bin/ocorec", "compiled compiler fixture")
        self.evaluator = write("bin/O", "compiled evaluator fixture")
        self.mcp = write("bin/mcp", "compiled MCP fixture")
        compiler_sha = gate.digest(self.compiler)
        hashes = {name: gate.digest(self.root / name) for name in names}
        profile = {"schema": "ostadix.unified-world-monitor/v1",
                   "source_sha256": {name: hashes[name] for name in gate.COMPILED},
                   "source_artifacts": {}, "artifacts": {},
                   "tools": {"ocorec": {"path": str(self.compiler), "sha256": compiler_sha}}}
        for name in gate.COMPILED:
            capture = write("build/sources/" + name, (self.root / name).read_text())
            profile["source_artifacts"][name] = {"path": str(capture.relative_to(self.build)),
                                                 "sha256": gate.digest(capture)}
        monitor = write("build/monitor.elf", "monitor fixture")
        profile["artifacts"]["monitor.elf"] = {"path": "monitor.elf", "sha256": gate.digest(monitor)}
        self.profile = write("build/monitor-profile.json", profile)
        profile_sha, monitor_sha = gate.digest(self.profile), gate.digest(monitor)
        write("runtime/build/monitor-profile.json", self.profile.read_text())
        write("runtime/build/monitor.elf", monitor.read_text())
        frozen = write("runtime/runtime.json", {"passed": True})
        seed = write("seed/head.json", {"fixture": "private seed"})

        def session(name):
            base = self.root / name
            write(name + "/monitor-profile.json", self.profile.read_text())
            write(name + "/inputs/monitor.elf", monitor.read_text())
            return str(base)
        binding = {"source_revision": self.revision, "mcp_release": self.revision}
        shared = {**binding, "build": str(self.build), "monitor_sha256": monitor_sha,
                  "profile_sha256": profile_sha, "build_tools": profile["tools"], "ok": True}
        live = {**shared, "schema": "ostadix.o10-live-component/v1", "milestone": "M0",
                "source_sha256": hashes, "checks": sorted(gate.LIVE_CHECKS), "paired_save": True,
                "session": session("live/session"),
                "preclaim_legacy": {"old_dom": (1 << 32) | 1, "new_dom": (2 << 32) | 1,
                    "old_handle_error": {"type": "Rerror", "code": 5, "detail": 2}, "mailbox_operations": [1, 2]},
                "lifecycle": {"old_dom": (2 << 32) | 1, "new_dom": (3 << 32) | 1}}
        self.paths["live_result"] = write("receipts/live.json", live)
        guest = {**shared, "schema": "ostadix.o10-guest-regressions/v1", "source_sha256": hashes,
                 "skips": [], "seed_state": str(seed.parent), "seed_head_sha256": gate.digest(seed),
                 "live_result": gate.identity(self.paths["live_result"]),
                 "frozen_runtime": gate.identity(frozen), "gates": []}
        for name, script in gate.GATES.items():
            state = self.root / "states" / name
            child_session = session("states/" + name + "/session")
            child = {"schema": gate.CHILD_SCHEMAS[name], "ok": True}
            if name in ("recovery", "default_compile"):
                child["session"] = child_session
            elif name == "runtime":
                child["sessions"] = [{"session": child_session}]
            else:
                child["sessions"] = [child_session]
            receipt = write("states/" + name + "/result.json", child)
            guest["gates"].append({"gate_id": name, "script": script, "state": str(state), "ok": True,
                "fork": {"argv": ["python3", "fork_okernel_state.py", "--source", str(seed.parent), "--output", str(state)],
                         "returncode": 0, "timed_out": False},
                "command": {"argv": ["python3", script], "returncode": 0, "timed_out": False},
                "receipt": {**gate.identity(receipt), "result": child}})
        self.paths["guest_result"] = write("receipts/guest.json", guest)
        component = {**binding, "gate_id": "verify_o10_journal", "component_ok": True,
                     "source_unchanged": True, "source_sha256": hashes, "compiler_sha256": compiler_sha,
                     "tests_run": 1, "failures": 0, "errors": 0, "skips": []}
        self.paths["component_result"] = write("component/result.json", component)
        write("component/tests.log", "test_fixture (test_o10_fixture.Fixture.test_fixture) ... ok\n\nRan 1 test in 0.001s\n\nOK\n")
        language_names = sorted(name for name in gate.COMPILED if name.endswith((".oc", ".O")))
        for i in range(261 - len(language_names)):
            name = "language/source-" + str(i) + ".oc"
            write(name, "language fixture")
            language_names.append(name)
        language = {"schema": "ostadix.language-source-check/v1", "action": "check", "sources": 261,
                    "results": [{"path": name, "sha256": gate.digest(self.root / name), "status": "passed", "exit_code": 0}
                                for name in language_names],
                    "binaries": {"ocorec": {"sha256": compiler_sha}, "O": {"sha256": gate.digest(self.evaluator)}}}
        language_path = write("receipts/language.json", language)
        self.inventory = set(language_names)
        unit = {**binding, "schema": "ostadix.o10-m0-unit-regressions/v1", "ok": True,
                "source_unchanged": True, "source_sha256": hashes, "compiler_sha256": compiler_sha,
                "results": [{"group": "all", "command": ["python3", "-m", "unittest", "discover", "-p", "test_okernel_*.py"],
                             "rc": 0, "timed_out": False, "skipped": False, "summary": "Ran 288 tests in 1.0s\n\nOK\n"}],
                "component": {**gate.identity(self.paths["component_result"]), "command": ["python3", "verify_o10_journal.py"],
                              "returncode": 0, "timed_out": False},
                "language": {**gate.identity(language_path), "command": ["python3", "check_language_sources.py", "check"],
                             "returncode": 0, "timed_out": False}}
        self.paths["unit_result"] = write("receipts/unit.json", unit)
        prov = {"schema": "ostadix.runtime-provenance/v1",
                "buildCommitMatchesRuntimeSource": True, "buildSource": {"commit": self.revision, "sourceRoot": str(self.root)},
                "runtimeSource": {"commit": self.revision, "status": "observed", "canonicalRoot": str(self.root)},
                "binary": {"status": "hashed", "hashSource": "running_process_inode",
                           "canonicalPath": str(self.mcp), "sha256": gate.digest(self.mcp)},
                "tools": [{"name": "O", "binary": {"sha256": gate.digest(self.evaluator)}}]}
        self.paths["provenance"] = write("receipts/provenance.json", {"structuredContent": prov, "isError": False})

    def mutate(self, which, change):
        path = self.paths[which]
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def validate(self):
        with patch.object(gate, "tracked_language", return_value=self.inventory):
            return gate.validate_acceptance(root=self.root, build=self.build, compiler=self.compiler,
                                            expected_revision=self.revision, **self.paths)

    def test_truncated_fork_argument_is_explicit_error(self):
        original = json.loads(self.paths["guest_result"].read_text())
        for missing in ("--source", "--output"):
            with self.subTest(flag=missing):
                data = copy.deepcopy(original)
                other = "--output" if missing == "--source" else "--source"
                data["gates"][0]["fork"]["argv"] = ["python3", "fork.py", other, "/fixture", missing]
                self.paths["guest_result"].write_text(json.dumps(data))
                with self.assertRaisesRegex(gate.EvidenceError, "fork argument value missing"):
                    self.validate()

    def test_mcp_build_root_is_bound(self):
        self.mutate("provenance", lambda x: x["structuredContent"]["buildSource"].update(sourceRoot="/another/root"))
        with self.assertRaisesRegex(gate.EvidenceError, "MCP build source root"):
            self.validate()

    def test_preclaim_legacy_proof_is_required(self):
        self.mutate("live_result", lambda x: x.pop("preclaim_legacy"))
        with self.assertRaisesRegex(gate.EvidenceError, "preclaim legacy transition missing"):
            self.validate()

    def test_preclaim_legacy_old_generation_cannot_alias(self):
        self.mutate("live_result", lambda x: x["preclaim_legacy"].update(new_dom=(1 << 32) | 1))
        with self.assertRaisesRegex(gate.EvidenceError, "preclaim legacy domain generation"):
            self.validate()

    def test_preclaim_legacy_error_detail_must_name_new_generation(self):
        self.mutate("live_result", lambda x: x["preclaim_legacy"]["old_handle_error"].update(detail=1))
        with self.assertRaisesRegex(gate.EvidenceError, "stale handle evidence"):
            self.validate()

    def test_claimed_restore_cannot_double_advance(self):
        self.mutate("live_result", lambda x: x["lifecycle"].update(new_dom=(4 << 32) | 1))
        with self.assertRaisesRegex(gate.EvidenceError, "exactly one generation"):
            self.validate()

    def mutate_child(self, gate_id, change):
        path = self.paths["guest_result"]
        guest = json.loads(path.read_text())
        entry = next(row for row in guest["gates"] if row["gate_id"] == gate_id)
        child_path = Path(entry["receipt"]["path"])
        child = json.loads(child_path.read_text())
        change(child)
        child_path.write_text(json.dumps(child))
        entry["receipt"] = {**gate.identity(child_path), "result": child}
        path.write_text(json.dumps(guest))

    def test_client_inherited_head_session_is_not_an_executed_vm(self):
        # The real foreground receipt carries its seed/update producer here.
        # It must not be mistaken for a VM belonging to this gate fork.
        old_producer = str(self.root / "seed/guest-tools-updates/update-prior")
        self.mutate_child("client", lambda x: x.update(inputs={"before": {"session": old_producer}}))
        result = self.validate()
        self.assertTrue(result["ok"])
        self.assertNotIn(old_producer, result["sessions_checked"])

    def test_explicit_runtime_session_outside_private_fork_is_rejected(self):
        outside = str(self.root / "another-fork/unified-session-wrong")
        self.mutate_child("runtime", lambda x: x["sessions"].append({"session": outside}))
        with self.assertRaisesRegex(gate.EvidenceError, "session outside private fork"):
            self.validate()

    def test_completed_bound_evidence_passes(self):
        result = self.validate()
        self.assertTrue(result["full_milestone_qualified"])
        self.assertEqual(result["okernel_unit_tests"], 288)

    def test_guest_pending_rejected(self):
        self.mutate("guest_result", lambda x: x.update(ok=False))
        with self.assertRaisesRegex(gate.EvidenceError, "guest not completed"):
            self.validate()

    def test_missing_gate_rejected(self):
        self.mutate("guest_result", lambda x: x["gates"].pop())
        with self.assertRaisesRegex(gate.EvidenceError, "six"):
            self.validate()

    def test_unknown_exit_is_not_a_pass(self):
        self.mutate("guest_result", lambda x: x["gates"][0]["command"].update(returncode=None))
        with self.assertRaisesRegex(gate.EvidenceError, "exit status"):
            self.validate()

    def test_boolean_exit_is_not_observed_zero(self):
        self.mutate("guest_result", lambda x: x["gates"][0]["command"].update(returncode=False))
        with self.assertRaisesRegex(gate.EvidenceError, "exit status"):
            self.validate()

    def test_timeout_is_rejected(self):
        self.mutate("guest_result", lambda x: x["gates"][0]["command"].update(timed_out=True))
        with self.assertRaisesRegex(gate.EvidenceError, "timeout"):
            self.validate()

    def test_misbound_live_monitor_rejected(self):
        self.mutate("live_result", lambda x: x.update(monitor_sha256="0" * 64))
        with self.assertRaisesRegex(gate.EvidenceError, "binding"):
            self.validate()

    def test_changed_profile_file_rejected(self):
        self.profile.write_text(self.profile.read_text() + "\n")
        with self.assertRaisesRegex(gate.EvidenceError, "binding"):
            self.validate()

    def test_compiled_source_drift_rejected(self):
        (self.root / next(iter(gate.COMPILED))).write_text("changed source")
        with self.assertRaisesRegex(gate.EvidenceError, "source drift"):
            self.validate()

    def test_changed_captured_source_rejected(self):
        profile = json.loads(self.profile.read_text())
        captured = next(iter(profile["source_artifacts"].values()))
        (self.build / captured["path"]).write_text("changed capture")
        with self.assertRaisesRegex(gate.EvidenceError, "capture changed"):
            self.validate()

    def test_unmatched_running_mcp_rejected(self):
        self.mutate("provenance", lambda x: x["structuredContent"].update(buildCommitMatchesRuntimeSource=False))
        with self.assertRaisesRegex(gate.EvidenceError, "MCP release"):
            self.validate()

    def test_caller_commit_string_cannot_replace_observed_provenance(self):
        self.mutate("provenance", lambda x: x["structuredContent"].update(buildSource={"commit": "b" * 40}))
        with self.assertRaisesRegex(gate.EvidenceError, "MCP commit"):
            self.validate()

    def test_compiler_file_mismatch_rejected(self):
        self.compiler.write_text("another compiler")
        with self.assertRaisesRegex(gate.EvidenceError, "compiler/build"):
            self.validate()

    def test_component_skip_rejected(self):
        self.mutate("component_result", lambda x: x.update(skips=[{"test": "native", "reason": "missing compiler"}]))
        with self.assertRaisesRegex(gate.EvidenceError, "component failed or skipped"):
            self.validate()

    def test_unit_skip_rejected(self):
        self.mutate("unit_result", lambda x: x["results"][0].update(skipped=True))
        with self.assertRaisesRegex(gate.EvidenceError, "skip"):
            self.validate()

    def test_unit_summary_skip_cannot_hide_behind_flag(self):
        self.mutate("unit_result", lambda x: x["results"][0].update(summary="Ran 288 tests in 1.0s\n\nOK (skipped=1)\n"))
        with self.assertRaises(gate.EvidenceError):
            self.validate()

    def test_unit_count_cannot_shrink(self):
        self.mutate("unit_result", lambda x: x["results"][0].update(summary="Ran 287 tests in 1.0s\n\nOK\n"))
        with self.assertRaisesRegex(gate.EvidenceError, "288"):
            self.validate()

    def test_component_wrapper_unknown_exit_rejected(self):
        self.mutate("unit_result", lambda x: x["component"].update(returncode=None))
        with self.assertRaisesRegex(gate.EvidenceError, "component wrapper exit"):
            self.validate()

    def test_child_receipt_mutation_rejected(self):
        guest = json.loads(self.paths["guest_result"].read_text())
        Path(guest["gates"][0]["receipt"]["path"]).write_text('{"ok":true}')
        with self.assertRaisesRegex(gate.EvidenceError, "hash changed"):
            self.validate()

    def test_frozen_runtime_profile_rebinding_rejected(self):
        (self.root / "runtime/build/monitor-profile.json").write_text("another profile")
        with self.assertRaisesRegex(gate.EvidenceError, "frozen runtime"):
            self.validate()

    def test_session_monitor_rebinding_rejected(self):
        (self.root / "states/provider/session/inputs/monitor.elf").write_text("another monitor")
        with self.assertRaisesRegex(gate.EvidenceError, "session uses"):
            self.validate()

    def test_empty_component_source_closure_rejected(self):
        self.mutate("component_result", lambda x: x.update(source_sha256={}))
        with self.assertRaisesRegex(gate.EvidenceError, "closure incomplete"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
