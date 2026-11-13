"""Negative controls for the M1 evidence binder; fixtures execute no guests."""
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
spec = importlib.util.spec_from_file_location("o10_acceptance", ROOT / "scripts/verify_o10_m1.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class M1EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="o10-m1-receipts-")
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
        helper_names = {"scripts/verify_o10_m1.py", "scripts/verify_o10_journal.py",
                        "scripts/verify_o10_live.py", "scripts/verify_o10_regressions.py",
                        "scripts/o10.py", "scripts/okernel_unified_world.py",
                        "scripts/fork_okernel_state.py", "scripts/check_language_sources.py",
                        "ci/language-sources.json", "ocore/guest/plan9/unified/protocol.py",
                        "scripts/verify_o10_resident.py", "scripts/verify_o10_hostile_mmio.py", "scripts/verify_o10_m1_regressions.py"} | {"scripts/" + x for x in gate.GATES.values()}
        names = gate.COMPILED | helper_names | {"tests/test_o10_fixture.py", "tests/test_o10_resident_native.py", "tests/test_okernel_fixture.py"}
        for name in names:
            write(name, "fixture " + name)
        protocol_path = self.root / "ocore/guest/plan9/unified/protocol.py"
        protocol_path.write_text((ROOT / "ocore/guest/plan9/unified/protocol.py").read_text())
        self.compiler = write("bin/ocorec", "compiled compiler fixture")
        self.evaluator = write("bin/O", "compiled evaluator fixture")
        self.mcp = write("bin/mcp", "compiled MCP fixture")
        compiler_sha = gate.digest(self.compiler)
        hashes = {name: gate.digest(self.root / name) for name in names}
        profile = {"schema": "ostadix.unified-world-monitor/v1", "o10_qualification": True,
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

        def live_gate(hostile=False):
            name = "hostile" if hostile else "resident"
            outer = self.root / name
            guest_session = session(name + "/state/session")
            inst = {"bytes_hex": "00" * 16}
            linux = {"type": "Rstat", "dom": 1 << 32, "inst": inst, "state": 4, "leases": 0}
            plan9 = {"type": "Rstat", "dom": (1 << 32) | 1, "inst": inst, "state": 5, "leases": 0}
            source_names = ["scripts/verify_o10_resident.py", "scripts/okernel_unified_world.py", "scripts/o10.py"]
            if hostile:
                source_names += ["scripts/verify_o10_hostile_mmio.py", "scripts/verify_okernel_unified_provider.py"]
            captures = {}
            for source in source_names:
                capture = write(name + "/sources/" + source, (self.root / source).read_text())
                captures[source] = gate.identity(capture)
            generation, instance = "b" * 16, "c" * 32
            marker = f"OC9READY1 {generation} {instance}\n".encode()
            value = {**binding, "schema": "ostadix.o10-resident-gate/v1", "milestone": "M1",
                "gate_id": "verify_o10_hostile_mmio" if hostile else "verify_o10_resident",
                "gate_passed": True, "milestone_qualified": False, "session": str(outer),
                "guest_session": guest_session, "source_state": str(seed.parent),
                "build": gate.identity(self.profile), "checked_build_sources": profile["source_sha256"],
                "build_sources_unchanged": True, "source_artifacts": captures,
                "host": {"uname": ["Linux", "fixture"]}, "qemu_argv": ["qemu-system-aarch64", "-machine", "virt"],
                "fork": {"schema": "ostadix.okernel-state-fork/v1", "ok": True,
                         "source": str(seed.parent), "output": str(outer / "state"), "source_head_changed_during_copy": False},
                "zero_runnable_seconds": 60.1, "samples": [{"seconds": second, "linux": linux, "plan9": plan9,
                    "counters": {"live_domains": 0}} for second in (0.1, 30.1, 59.9)],
                "linux_fault_source": "actual Linux guest MMIO" if hostile else "qualification Tinjection fault1",
                "linux_fault": {**linux, "esr": 0x24 << 26, "ipa": 0x0a0000fc} if hostile else
                               {"type": "Rinject", "dom": linux["dom"]},
                "provider": {"path": f"/services/plan9/g{generation}/s{instance}/ready",
                    "sha256": gate.hashlib.sha256(marker).hexdigest(), "service": {"generation": generation, "instance": instance},
                    "stat": {**plan9, "dom": (2 << 32) | 1, "inst": {"bytes_hex": "11" * 16}, "state": 2}}}
            if hostile:
                path = "/n/work/o10-hostile-" + "d" * 16
                request_id = "e" * 32
                value["mmio_commands"] = ['test "$(busybox devmem 0x0a000000 32)" = 0x74726976',
                                           "busybox devmem 0x0a0000fc 32 1"]
                value["plan9_counter"] = {"path": path, "before": {"bytes_hex": b"0\n".hex()},
                    "after": {"bytes_hex": b"0\n1\n2\n3\n4\n5\n6\n7\n".hex()}, "request_id": request_id,
                    "domain_before": {**plan9, "state": 2}, "domain_after": {**plan9, "state": 2}}
                module_spec = importlib.util.spec_from_file_location("fixture_o10_protocol", protocol_path)
                protocol = importlib.util.module_from_spec(module_spec)
                sys.modules[module_spec.name] = protocol
                module_spec.loader.exec_module(protocol)
                request = protocol.encode_request(generation, instance, request_id,
                    ["/bin/rc", "-c", "for(i in 0 1 2 3 4 5 6 7) { echo $i; sleep 1 } > " + path],
                    cwd="/n/work", timeout_ms=120000)
                result = protocol.encode_result(request, flags=0, stdout=b"", stderr=b"", status=b"")
                captures_dir = Path(guest_session) / "o10-hostile-provider"
                captures_dir.mkdir()
                files = {"request": request, "submit": protocol.submit_marker(request), "started": protocol.submit_marker(request),
                    "result": result, "stdout": b"", "stderr": b"", "status": b"", "done": protocol.done_marker(request, result)}
                for key, data in files.items():
                    (captures_dir / key).write_bytes(data)
                (captures_dir / "invocation.json").write_text(json.dumps({"id": request_id,
                    "service": {"generation": generation, "instance": instance}}))
            return write(name + "/result.json", value)
        self.paths["resident_result"] = live_gate()
        self.paths["hostile_mmio_result"] = live_gate(True)
        guest = {**shared, "schema": "ostadix.o10-guest-regressions/v1", "source_sha256": hashes,
                 "milestone": "M1", "skips": [], "seed_state": str(seed.parent), "seed_head_sha256": gate.digest(seed),
                 "resident_result": gate.identity(self.paths["resident_result"]),
                 "hostile_mmio_result": gate.identity(self.paths["hostile_mmio_result"]),
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
                     "tests_run": 2, "failures": 0, "errors": 0, "skips": []}
        self.paths["component_result"] = write("component/result.json", component)
        write("component/tests.log", "test_fixture (test_o10_fixture.Fixture.test_fixture) ... ok\n"
              "test_resident_paths_and_qualification_boundary (test_o10_resident_native.O10ResidentNativeTests.test_resident_paths_and_qualification_boundary) ... ok\n\nRan 2 tests in 0.001s\n\nOK\n")
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
        unit = {**binding, "schema": "ostadix.o10-m1-unit-regressions/v1", "ok": True,
                "source_unchanged": True, "source_sha256": hashes, "compiler_sha256": compiler_sha,
                "results": [{"group": "all", "command": ["python3", "-m", "unittest", "discover", "-p", "test_okernel_*.py"],
                             "rc": 0, "timed_out": False, "skipped": False, "summary": "Ran 288 tests in 1.0s\n\nOK\n"}],
                "component": {**gate.identity(self.paths["component_result"]), "command": ["python3", "verify_o10_journal.py"],
                              "returncode": 0, "timed_out": False},
                "language": {**gate.identity(language_path), "command": ["python3", "check_language_sources.py", "check"],
                             "returncode": 0, "timed_out": False}}
        unit_log = write("receipts/unit.log", "test_fixture (test_okernel_fixture.Fixture.test_fixture) ... ok\n\nRan 288 tests in 1.0s\n\nOK\n")
        unit["results"][0]["log"] = gate.identity(unit_log)
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


    def validate(self, **overrides):
        def git_identity(root, revision, name):
            return {"sha256": "b" * 64 if revision == gate.BASELINE_M0 else gate.digest(self.root / name),
                    "git_blob": "a" * 40 if revision == gate.BASELINE_M0 else "c" * 40}
        arguments = {**self.paths, **overrides}
        with patch.object(gate, "tracked_language", return_value=self.inventory), patch.object(
                gate, "git_source_identity", side_effect=git_identity):
            return gate.validate_acceptance(root=self.root, build=self.build, compiler=self.compiler,
                                            expected_revision=self.revision, **arguments)


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



    def test_required_resident_gate_cannot_be_replaced_by_mmio_gate(self):
        self.mutate("resident_result", lambda x: x.update(gate_id="verify_o10_hostile_mmio"))
        with self.assertRaisesRegex(gate.EvidenceError, "resident wrong receipt"):
            self.validate()

    def test_live_mcp_alignment_is_exact(self):
        self.mutate("resident_result", lambda x: x.update(mcp_release=self.revision + " unqualified"))
        with self.assertRaisesRegex(gate.EvidenceError, "source/MCP mismatch"):
            self.validate()

    def test_short_resident_window_rejected(self):
        self.mutate("resident_result", lambda x: x.update(zero_runnable_seconds=59.9))
        with self.assertRaisesRegex(gate.EvidenceError, "60 seconds"):
            self.validate()

    def test_stale_single_observation_is_not_residency(self):
        self.mutate("resident_result", lambda x: x.update(samples=x["samples"][:1]))
        with self.assertRaisesRegex(gate.EvidenceError, "repeated resident"):
            self.validate()

    def test_observations_must_span_resident_window(self):
        self.mutate("resident_result", lambda x: x["samples"][-1].update(seconds=31.0))
        with self.assertRaisesRegex(gate.EvidenceError, "span the resident"):
            self.validate()

    def test_resident_runnable_guest_rejected(self):
        self.mutate("resident_result", lambda x: x["samples"][1]["counters"].update(live_domains=1))
        with self.assertRaisesRegex(gate.EvidenceError, "runnable guest"):
            self.validate()

    def test_explicit_live_session_outside_private_fork_rejected(self):
        self.mutate("resident_result", lambda x: x.update(guest_session=str(self.root / "seed/unified-session-old")))
        with self.assertRaisesRegex(gate.EvidenceError, "outside private fork"):
            self.validate()

    def test_live_gate_source_capture_is_bound(self):
        self.mutate("resident_result", lambda x: x["source_artifacts"]["scripts/o10.py"].update(sha256="0" * 64))
        with self.assertRaisesRegex(gate.EvidenceError, "gate source drift"):
            self.validate()

    def test_mmio_cannot_fall_back_to_tinject(self):
        self.mutate("hostile_mmio_result", lambda x: x.update(linux_fault_source="qualification Tinjection fault1"))
        with self.assertRaisesRegex(gate.EvidenceError, "wrong fault source"):
            self.validate()

    def test_mmio_must_fault_the_recorded_address(self):
        self.mutate("hostile_mmio_result", lambda x: x["linux_fault"].update(ipa=0x0a000000))
        with self.assertRaisesRegex(gate.EvidenceError, "ESR/IPA"):
            self.validate()

    def test_counter_must_advance(self):
        self.mutate("hostile_mmio_result", lambda x: x["plan9_counter"].update(before=x["plan9_counter"]["after"]))
        with self.assertRaisesRegex(gate.EvidenceError, "counter did not advance"):
            self.validate()

    def test_counter_survivor_instance_unchanged(self):
        self.mutate("hostile_mmio_result", lambda x: x["plan9_counter"]["domain_after"].update(inst={"bytes_hex": "aa" * 16}))
        with self.assertRaisesRegex(gate.EvidenceError, "counter instance changed"):
            self.validate()

    def test_original_provider_capture_integrity_is_rechecked(self):
        receipt = json.loads(self.paths["hostile_mmio_result"].read_text())
        path = Path(receipt["guest_session"]) / "o10-hostile-provider/stdout"
        path.write_bytes(b"corruption")
        with self.assertRaisesRegex(ValueError, "stdout length or digest"):
            self.validate()

    def test_original_provider_capture_request_is_bound_to_counter(self):
        receipt = json.loads(self.paths["hostile_mmio_result"].read_text())
        path = Path(receipt["guest_session"]) / "o10-hostile-provider/invocation.json"
        value = json.loads(path.read_text())
        value["id"] = "0" * 32
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(gate.EvidenceError, "counter request identity"):
            self.validate()

    def test_restored_provider_marker_is_exact(self):
        self.mutate("resident_result", lambda x: x["provider"].update(sha256="0" * 64))
        with self.assertRaisesRegex(gate.EvidenceError, "provider marker"):
            self.validate()

    def test_unit_full_log_cannot_omit_current_module(self):
        unit = json.loads(self.paths["unit_result"].read_text())
        log = Path(unit["results"][0]["log"]["path"])
        log.write_text("test_fixture (test_other.Fixture.test_fixture) ... ok\n\nRan 288 tests in 1.0s\n\nOK\n")
        unit["results"][0]["log"] = gate.identity(log)
        self.paths["unit_result"].write_text(json.dumps(unit))
        with self.assertRaisesRegex(gate.EvidenceError, "okernel test module omitted"):
            self.validate()

    def test_unit_count_comes_from_actual_matching_logs(self):
        unit = json.loads(self.paths["unit_result"].read_text())
        unit["results"][0]["summary"] = unit["results"][0]["summary"].replace("288", "123")
        log = Path(unit["results"][0]["log"]["path"])
        log.write_text(log.read_text().replace("288", "123"))
        unit["results"][0]["log"] = gate.identity(log)
        self.paths["unit_result"].write_text(json.dumps(unit))
        self.assertEqual(self.validate()["okernel_unit_tests"], 123)

    def test_current_language_inventory_count_is_generic(self):
        unit = json.loads(self.paths["unit_result"].read_text())
        path = Path(unit["language"]["path"])
        value = json.loads(path.read_text())
        removed = next(x for x in value["results"] if x["path"].startswith("language/"))
        value["results"].remove(removed)
        value["sources"] -= 1
        self.inventory.remove(removed["path"])
        path.write_text(json.dumps(value))
        unit["language"] = {**unit["language"], **gate.identity(path)}
        self.paths["unit_result"].write_text(json.dumps(unit))
        self.assertEqual(self.validate()["language_sources"], 260)

    def draft0_mapping(self):
        def row(name, expected):
            category, diagnostic, detail, scenario = expected
            result = {"id": name,
                "baseline": {"path": gate.WORLD_SOURCE, "line": 1, "sha256": "b" * 64, "git_blob": "a" * 40},
                "current": {"path": gate.WORLD_SOURCE, "line": 1, "sha256": gate.digest(self.root / gate.WORLD_SOURCE),
                            "git_blob": "c" * 40},
                "classification": category,
                "test": {"path": gate.CLASSIFIED_TEST, "method": gate.CLASSIFIED_METHOD,
                         "sha256": gate.digest(self.root / gate.CLASSIFIED_TEST), "scenario_ids": [scenario],
                         "configurations": [[0, 1], [1, 1], [0, 0], [1, 0]],
                         "scope": "native-host-register-model-diagnostic-only" if name == "defensive_selected_result"
                                  else "native-host-register-model"},
                "execution": {"source": "component_receipt",
                              "method_log_token": "test_resident_paths_and_qualification_boundary"}}
            if diagnostic is not None: result["diagnostic"] = diagnostic
            if detail is not None: result["detail"] = detail
            if name == "defensive_selected_result":
                result["note"] = "not reachable under serialized scheduler state; direct diagnostic invocation only"
            if name == "psci_unsupported_result": result["value"] = "18446744073709551615"
            return result
        return self.write("receipts/classification.json", {"schema": "ostadix.o10-m1-max-classification/v1",
            "contract_id": gate.CONTRACTS["draft0"], "baseline_revision": gate.BASELINE_M0,
            "implementation_revision": self.revision,
            "rows": [row(k, v) for k, v in gate.CLASSIFIED_ROWS.items()],
            "auxiliary_rows": [row(k, v) for k, v in gate.AUXILIARY_ROWS.items()]})

    def draft0(self, *, extra=True, mapping=None):
        def update_guest(guest):
            guest.update(acceptance_scope="draft0", contract_id=gate.CONTRACTS["draft0"])
            if extra:
                extra_record = gate.observe_extra_probe(self.paths["hostile_mmio_result"])
                guest["hostile_mmio_result"] = extra_record["reference"]
                guest["extra_probe"] = extra_record
            else:
                guest.pop("hostile_mmio_result", None)
                guest.pop("extra_probe", None)
        self.mutate("guest_result", update_guest)
        return self.validate(acceptance_scope="draft0", classified_paths_result=mapping or self.draft0_mapping(),
                             hostile_mmio_result=self.paths["hostile_mmio_result"] if extra else None)

    def test_explicit_draft0_qualifies_without_extra_probe(self):
        result = self.draft0(extra=False)
        self.assertTrue(result["full_milestone_qualified"])
        self.assertEqual(result["acceptance_scope"], "draft0")
        self.assertEqual(result["contract_id"], "O10-Draft0-M1")
        self.assertIsNone(result["extra_probe"])
        self.assertNotIn("hostile_mmio", result["inputs"])

    def test_draft0_preserves_failed_extra_probe_as_unqualified(self):
        self.mutate("hostile_mmio_result", lambda x: x.update(gate_passed=False, error="prerequisite failed"))
        result = self.draft0()
        self.assertTrue(result["ok"])
        self.assertFalse(result["extra_probe"]["qualified"])
        self.assertIs(result["extra_probe"]["observed_gate_passed"], False)
        self.assertEqual(result["extra_probe"]["observed_error"], "prerequisite failed")
        self.assertEqual(result["extra_probe"]["reference"], gate.identity(self.paths["hostile_mmio_result"]))
        self.assertNotIn(json.loads(self.paths["hostile_mmio_result"].read_text())["guest_session"], result["sessions_checked"])

    def test_default_extended_still_rejects_failed_extra_probe(self):
        self.mutate("hostile_mmio_result", lambda x: x.update(gate_passed=False, error="prerequisite failed"))
        with self.assertRaisesRegex(gate.EvidenceError, "gate not passed"):
            self.validate()

    def test_default_extended_still_requires_extra_probe(self):
        with self.assertRaisesRegex(gate.EvidenceError, "extended acceptance requires"):
            self.validate(hostile_mmio_result=None)

    def test_draft0_requires_explicit_guest_scope(self):
        with self.assertRaisesRegex(gate.EvidenceError, "guest acceptance scope"):
            self.validate(acceptance_scope="draft0", classified_paths_result=self.draft0_mapping())

    def test_draft0_requires_classified_path_mapping(self):
        self.mutate("guest_result", lambda x: x.update(acceptance_scope="draft0", contract_id="O10-Draft0-M1"))
        with self.assertRaisesRegex(gate.EvidenceError, "mapping required"):
            self.validate(acceptance_scope="draft0", hostile_mmio_result=None)

    def test_draft0_does_not_silently_drop_guest_extra_reference(self):
        self.mutate("hostile_mmio_result", lambda x: x.update(gate_passed=False))
        extra = gate.observe_extra_probe(self.paths["hostile_mmio_result"])
        self.mutate("guest_result", lambda x: x.update(acceptance_scope="draft0", contract_id="O10-Draft0-M1",
                    hostile_mmio_result=extra["reference"], extra_probe=extra))
        result = self.validate(acceptance_scope="draft0", hostile_mmio_result=None,
                               classified_paths_result=self.draft0_mapping())
        self.assertEqual(result["extra_probe"]["reference"], extra["reference"])

    def test_draft0_rejects_extra_probe_promoted_by_driver(self):
        extra = gate.observe_extra_probe(self.paths["hostile_mmio_result"])
        self.mutate("guest_result", lambda x: x.update(acceptance_scope="draft0", contract_id="O10-Draft0-M1",
                    hostile_mmio_result=extra["reference"], extra_probe={**extra, "qualified": True}))
        with self.assertRaisesRegex(gate.EvidenceError, "explicitly unqualified"):
            self.validate(acceptance_scope="draft0", classified_paths_result=self.draft0_mapping())

    def test_draft0_rejects_missing_reclassified_max_row(self):
        mapping = self.draft0_mapping()
        value = json.loads(mapping.read_text()); value["rows"].pop(); mapping.write_text(json.dumps(value))
        with self.assertRaisesRegex(gate.EvidenceError, "rows incomplete"):
            self.draft0(mapping=mapping)

    def test_draft0_rejects_mapping_test_source_drift(self):
        mapping = self.draft0_mapping()
        value = json.loads(mapping.read_text()); value["rows"][0]["test"]["sha256"] = "0" * 64
        mapping.write_text(json.dumps(value))
        with self.assertRaisesRegex(gate.EvidenceError, "test binding"):
            self.draft0(mapping=mapping)

    def test_draft0_mapping_requires_actual_component_method_log(self):
        path = self.paths["component_result"].parent / "tests.log"
        path.write_text(path.read_text().replace("test_resident_paths_and_qualification_boundary", "another_method"))
        with self.assertRaisesRegex(gate.EvidenceError, "method missing"):
            self.draft0()

    def test_draft0_diagnostic_guard_claim_cannot_expand_to_real_dispatch(self):
        mapping = self.draft0_mapping()
        value = json.loads(mapping.read_text())
        value["auxiliary_rows"][0]["test"]["scope"] = "actual-el2"
        mapping.write_text(json.dumps(value))
        with self.assertRaisesRegex(gate.EvidenceError, "test binding"):
            self.draft0(mapping=mapping)

    def test_unknown_acceptance_scope_rejected(self):
        with self.assertRaisesRegex(gate.EvidenceError, "unknown acceptance scope"):
            self.validate(acceptance_scope="implicit-downgrade")


    def test_draft0_preserves_extra_reference_in_explicit_extra_field(self):
        self.mutate("hostile_mmio_result", lambda x: x.update(gate_passed=False))
        extra = gate.observe_extra_probe(self.paths["hostile_mmio_result"])
        self.mutate("guest_result", lambda x: (x.pop("hostile_mmio_result"),
            x.update(acceptance_scope="draft0", contract_id="O10-Draft0-M1", extra_probe=extra)))
        result = self.validate(acceptance_scope="draft0", hostile_mmio_result=None,
                               classified_paths_result=self.draft0_mapping())
        self.assertEqual(result["extra_probe"]["reference"], extra["reference"])

    def test_draft0_rejects_baseline_source_misbinding(self):
        mapping = self.draft0_mapping()
        value = json.loads(mapping.read_text()); value["rows"][0]["baseline"]["sha256"] = "0" * 64
        mapping.write_text(json.dumps(value))
        with self.assertRaisesRegex(gate.EvidenceError, "source binding"):
            self.draft0(mapping=mapping)

    def test_draft0_rejects_missing_native_configuration(self):
        mapping = self.draft0_mapping()
        value = json.loads(mapping.read_text()); value["rows"][0]["test"]["configurations"].pop()
        mapping.write_text(json.dumps(value))
        with self.assertRaisesRegex(gate.EvidenceError, "scenario coverage"):
            self.draft0(mapping=mapping)

    def test_draft0_cannot_fabricate_successful_extra_observation(self):
        self.mutate("hostile_mmio_result", lambda x: x.update(gate_passed=False, error="prerequisite unavailable"))
        extra = gate.observe_extra_probe(self.paths["hostile_mmio_result"])
        self.mutate("guest_result", lambda x: x.update(acceptance_scope="draft0", contract_id="O10-Draft0-M1",
                    hostile_mmio_result=extra["reference"],
                    extra_probe={**extra, "observed_gate_passed": True, "observed_error": None}))
        with self.assertRaisesRegex(gate.EvidenceError, "observation differs"):
            self.validate(acceptance_scope="draft0", classified_paths_result=self.draft0_mapping())
