from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

SPEC = importlib.util.spec_from_file_location("ocore_observe_cargo", Path(__file__).with_name("observe_cargo.py"))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class CargoObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / "capture"
        self.capture.mkdir()
        self.capture_worker = self.capture / "worker.py"
        self.capture_worker.write_bytes(b"# source capture fixture worker\n")
        worker = {"schema": "ocore-runtime-capture-worker-v1", "artifact": module.read_artifact(self.capture_worker)[1]}
        (self.capture / "session.json").write_text(json.dumps({"capture_worker": worker, "build_steps": []}))
        self.tool = self.root / "cargo"
        self.tool.write_text(f'''#!{sys.executable}
import json,os,signal,subprocess,sys,time
with open(os.environ['TOOL_LOG'],'a') as stream:
    stream.write(json.dumps({{'argv':sys.argv[1:],'stage':os.environ.get('RUSTC_STAGE'),'cwd':os.getcwd(),'parent':os.environ.get('OCORE_CAPTURE_CARGO_PARENT'),'jobserver_open':(os.fstat(int(os.environ['JOBSERVER_FD'])).st_mode if os.environ.get('JOBSERVER_FD') else None)}})+'\\n')
if '--unit-graph' in sys.argv:
    if os.environ.get('QUERY_SLEEP'):
        open(os.environ['QUERY_STARTED'],'w').close()
        time.sleep(30)
    print(json.dumps({{'version':1,'units':[{{'pkg_id':'complete-original-package'}}],'roots':[0]}}))
    print('supplementary query stderr',file=sys.stderr)
    sys.exit(int(os.environ.get('QUERY_EXIT','0')))
if os.environ.get('NESTED_WRAPPER') and not os.environ.get('IS_NESTED'):
    nested=dict(os.environ,IS_NESTED='1')
    subprocess.run([os.environ['NESTED_WRAPPER'],'build','--nested'],env=nested,check=True)
if os.environ.get('MOCK_CHILDREN'):
    children=[subprocess.Popen([sys.executable,os.environ['MOCK_COMPILER']],env=os.environ) for _ in range(int(os.environ['MOCK_CHILDREN']))]
    for child in children:
        child.wait()
if os.environ.get('ORIGINAL_SIGNAL'):
    os.kill(os.getpid(),signal.SIGTERM)
sys.stdout.buffer.write(b'original stdout\\x00bytes\\n')
sys.stderr.buffer.write(b'original stderr\\xffbytes\\n')
sys.exit(int(os.environ.get('ORIGINAL_EXIT','0')))
''')
        self.mock_compiler = self.root / "mock-compiler.py"
        self.mock_compiler.write_text('''import hashlib,json,os,pathlib,uuid
binding=json.loads(os.environ['OCORE_CAPTURE_CARGO_PARENT'])
root=pathlib.Path(os.environ['MOCK_CAPTURE'])
child=uuid.uuid4().hex
def artifact(path):
    raw=path.read_bytes()
    return {'path':str(path.absolute()),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def atomic(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
    temp.write_text(json.dumps(value,sort_keys=True))
    os.replace(temp,path)
event=root/'events'/(child+'.json')
atomic(event,{'id':child,'kind':'rustc','state':'finished','exit_code':int(os.environ.get('MOCK_CHILD_EXIT','0')),
    'capture_worker':binding['source_capture_worker'],'cargo_parent_invocation_id':binding['id'],
    'cargo_parent':binding})
observer=pathlib.Path(binding['observer_session']['path']).parent
atomic(observer/'children'/binding['id']/(child+'.json'),{
    'schema':'ocore-cargo-compiler-child-v1','cargo_parent_invocation_id':binding['id'],
    'capture_invocation_id':child,'capture_event':artifact(event),
    'observer_session':binding['observer_session'],'source_capture_worker':binding['source_capture_worker']})
''')
        self.tool.chmod(0o755)
        self.directory = self.root / "observer"
        module.prepare(self.directory, self.tool, self.capture)
        self.environment = {**os.environ, "TOOL_LOG": str(self.root / "tool.log"),
                            "RUSTC_STAGE": "1", "CARGO_TARGET_DIR": str(self.root / "stage2-rustc"),
                            "MOCK_COMPILER": str(self.mock_compiler), "MOCK_CAPTURE": str(self.capture)}

    def tearDown(self):
        destination = os.environ.get("OCORE_CARGO_OBSERVER_TEST_EVIDENCE")
        if destination:
            root = Path(destination) / self._testMethodName
            shutil.copytree(self.root, root)
            root.chmod(0o700)
            files = []
            for original in sorted(self.root.rglob("*")):
                if original.is_file():
                    copied = root / original.relative_to(self.root)
                    copied.chmod(0o600)
                    files.append({"original": module.read_artifact(original)[1],
                                  "retained": module.read_artifact(copied)[1]})
            module.write_json(root / "retained-artifacts.json", {"mock_fixture_only": True,
                "original_directory": str(self.root), "files": files})

    def run_wrapper(self, arguments=None, environment=None):
        return subprocess.run([str(self.directory / "cargo"), *(arguments or ["build", "--features", "full,unwind"])],
                              cwd=self.root, env={**self.environment, **(environment or {})}, capture_output=True)

    def events(self):
        return [json.loads(path.read_bytes()) for path in (self.directory / "events").glob("*.json")]

    def test_exact_upstream_output_status_arguments_and_environment_are_preserved(self):
        result = self.run_wrapper(environment={"ORIGINAL_EXIT": "7"})
        self.assertEqual(7, result.returncode)
        self.assertEqual(b'original stdout\x00bytes\n', result.stdout)
        self.assertEqual(b'original stderr\xffbytes\n', result.stderr)
        calls = [json.loads(line) for line in (self.root / "tool.log").read_text().splitlines()]
        self.assertEqual(["build", "--features", "full,unwind"], calls[1]["argv"])
        self.assertEqual("1", calls[1]["stage"])
        event = self.events()[0]
        self.assertEqual(7, event["upstream_exit_code"])
        self.assertEqual("recorded", event["graph_query"]["status"])
        self.assertEqual("1", event["build_environment"]["RUSTC_STAGE"])
        env_path = Path(event["inherited_environment_record"]["path"])
        self.assertEqual(0o600, env_path.stat().st_mode & 0o777)
        self.assertEqual("1", json.loads(env_path.read_bytes())["RUSTC_STAGE"])
        self.assertFalse(event["runtime_complete"])

    def test_query_failure_is_explicit_and_never_replaces_upstream_success(self):
        result = self.run_wrapper(environment={"QUERY_EXIT": "23"})
        self.assertEqual(0, result.returncode)
        event = self.events()[0]
        self.assertEqual("failed", event["graph_query"]["status"])
        self.assertEqual(23, event["graph_query"]["exit_code"])
        self.assertEqual(0, event["upstream_exit_code"])

    def test_tool_mutation_skips_query_but_preserves_actual_upstream_status(self):
        self.tool.write_text(self.tool.read_text() + "\n# changed tool bytes\n")
        result = self.run_wrapper(environment={"ORIGINAL_EXIT": "4"})
        self.assertEqual(4, result.returncode)
        event = self.events()[0]
        self.assertEqual("capture-error", event["graph_query"]["status"])
        self.assertTrue(any("tool bytes changed" in value for value in event["capture_errors"]))
        self.assertEqual(1, len((self.root / "tool.log").read_text().splitlines()))

    def test_capture_snapshot_mutation_remains_explicit(self):
        self.capture_worker.write_bytes(b"# tampered capture worker\n")
        result = self.run_wrapper()
        self.assertEqual(0, result.returncode)
        self.assertTrue(any("snapshot bytes changed" in value for value in self.events()[0]["capture_errors"]))

    def test_observer_snapshot_tamper_falls_back_without_output_or_status_changes(self):
        (self.directory / "worker.py").chmod(0o644)
        (self.directory / "worker.py").write_bytes(b"# tampered observer\n")
        result = self.run_wrapper(environment={"ORIGINAL_EXIT": "6"})
        self.assertEqual(6, result.returncode)
        self.assertEqual(b'original stdout\x00bytes\n', result.stdout)
        self.assertEqual(b'original stderr\xffbytes\n', result.stderr)
        self.assertEqual(1, len(list((self.directory / "errors").glob("*.json"))))
        with self.assertRaisesRegex(ValueError, "trusted worker"):
            module.verify(self.directory)

    def test_unit_graph_is_not_requested_for_queries_or_unknown_commands(self):
        self.assertIsNone(module.query_arguments(["--version"]))
        self.assertIsNone(module.query_arguments(["rustc", "--", "--emit=llvm-ir"]))
        self.assertIsNone(module.query_arguments(["metadata", "--format-version", "1"]))
        self.assertEqual(["-Z", "warnings", "build", "--profile=release", "-Zunstable-options", "--unit-graph"],
                         module.query_arguments(["-Z", "warnings", "build", "--profile=release"]))
        result = self.run_wrapper(["--version"])
        self.assertEqual(0, result.returncode)
        self.assertEqual("not-applicable", self.events()[0]["graph_query"]["status"])

    def test_verifier_rejects_changed_graph_bytes(self):
        self.run_wrapper()
        event = self.events()[0]
        Path(event["graph_query"]["stdout"]["path"]).write_bytes(b'{"units":[]}')
        with self.assertRaisesRegex(ValueError, "query artifact changed"):
            module.verify(self.directory)

    def test_verifier_rejects_rewritten_query_arguments(self):
        self.run_wrapper()
        path = next((self.directory / "events").glob("*.json"))
        event = json.loads(path.read_bytes())
        event["graph_query"]["argv"].insert(2, "--no-default-features")
        path.write_text(json.dumps(event))
        with self.assertRaisesRegex(ValueError, "changed original arguments"):
            module.verify(self.directory)

    def test_trusted_digest_cannot_be_replaced_with_mutually_consistent_worker_fields(self):
        path = self.directory / "worker.py"
        path.chmod(0o644)
        path.write_bytes(path.read_bytes() + b"\n# attacker-controlled variant\n")
        session = json.loads((self.directory / "session.json").read_bytes())
        session["observer_worker"] = module.read_artifact(path)[1]
        (self.directory / "session.json").chmod(0o644)
        (self.directory / "session.json").write_text(json.dumps(session))
        with self.assertRaisesRegex(ValueError, "trusted worker"):
            module.verify(self.directory)

    def test_upstream_signal_status_is_preserved(self):
        result = self.run_wrapper(["--version"], {"ORIGINAL_SIGNAL": "1"})
        self.assertEqual(-signal.SIGTERM, result.returncode)
        self.assertEqual(-signal.SIGTERM, self.events()[0]["upstream_exit_code"])

    def test_cancelling_supplementary_query_does_not_start_original_build(self):
        marker = self.root / "query-started"
        environment = {**self.environment, "QUERY_SLEEP": "1", "QUERY_STARTED": str(marker)}
        process = subprocess.Popen([str(self.directory / "cargo"), "build"], cwd=self.root,
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.terminate()
            process.communicate(timeout=5)
            self.assertEqual(-signal.SIGTERM, process.returncode)
            self.assertEqual(1, len((self.root / "tool.log").read_text().splitlines()))
            event = self.events()[0]
            self.assertFalse(event["upstream_started"])
            self.assertNotIn("upstream_exit_code", event)
            self.assertEqual("cancelled", event["graph_query"]["status"])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_verified_observer_still_never_claims_source_or_lowering_admission(self):
        self.run_wrapper()
        receipt = module.verify(self.directory)
        self.assertEqual(1, len(receipt["events"]))
        self.assertFalse(receipt["source_production_inventory_complete"])
        self.assertFalse(receipt["ocore_lowering_complete"])
        self.assertFalse(receipt["runtime_complete"])

    def test_explicit_manifest_and_lock_metadata_are_hash_bound_candidates(self):
        manifest = self.root / "Cargo.toml"
        manifest.write_text('[package]\nname="original"\nversion="0.0.0"\n')
        lock = self.root / "Cargo.lock"
        lock.write_text('version=4\n')
        self.run_wrapper(["build", "--manifest-path", str(manifest)])
        event = self.events()[0]
        inputs = {value["original"]["path"]: value for value in event["parent_source_inputs"]}
        self.assertIn(str(manifest), inputs)
        self.assertIn(str(lock), inputs)
        self.assertIn("explicit_parent_manifest_argument", inputs[str(manifest)]["discovery_reasons"])
        self.assertFalse(inputs[str(manifest)]["cargo_consumption_proven"])
        self.assertFalse(inputs[str(manifest)]["source_ownership_admitted"])
        self.assertTrue(inputs[str(manifest)]["unchanged_after_graph_query"])
        self.assertEqual([0], event["graph_query"]["root_unit_indices"])

    def test_parent_metadata_snapshot_tamper_is_rejected(self):
        manifest = self.root / "Cargo.toml"
        manifest.write_text('[package]\nname="original"\nversion="0.0.0"\n')
        self.run_wrapper(["build", "--manifest-path=" + str(manifest)])
        inputs = self.events()[0]["parent_source_inputs"]
        Path(inputs[0]["snapshot"]["path"]).write_bytes(b"different source metadata")
        with self.assertRaisesRegex(ValueError, "source metadata snapshot changed"):
            module.verify(self.directory)

    def test_legacy_unbound_source_capture_is_rejected_before_observer_creation(self):
        (self.capture / "session.json").write_text(json.dumps({"capture_worker": {"path": str(self.capture_worker)}}))
        other = self.root / "new-observer"
        with self.assertRaisesRegex(ValueError, "snapshot-bound source capture"):
            module.prepare(other, self.tool, self.capture)
        self.assertFalse(other.exists())

    def test_supplied_trusted_observer_digest_is_required_to_match(self):
        other = self.root / "new-observer"
        with self.assertRaisesRegex(ValueError, "supplied trusted worker"):
            module.prepare(other, self.tool, self.capture, expected_worker_sha256="0" * 64)
        self.assertFalse(other.exists())


    def child_run(self, count=1, extra=None):
        result = self.run_wrapper(environment={"MOCK_CHILDREN": str(count), **(extra or {})})
        self.assertEqual(0, result.returncode)
        return self.events()[0]

    def rewrite_child(self, event, update_receipt=None, update_journal=None, rebind=False):
        child = event["compiler_children"][0]
        receipt_path = Path(child["receipt"]["path"])
        receipt = json.loads(receipt_path.read_bytes())
        if update_journal:
            journal_path = Path(receipt["capture_event"]["path"])
            journal = json.loads(journal_path.read_bytes())
            journal.update(update_journal)
            journal_path.write_text(json.dumps(journal))
            if rebind:
                receipt["capture_event"] = module.read_artifact(journal_path)[1]
        if update_receipt:
            receipt.update(update_receipt)
        receipt_path.write_text(json.dumps(receipt))
        if rebind:
            child.update(receipt=module.read_artifact(receipt_path)[1], capture_event=receipt["capture_event"])
            (self.directory / "events" / (event["id"] + ".json")).write_text(json.dumps(event))

    def test_real_original_receives_current_binding_query_never_receives_a_parent(self):
        event = self.child_run(3)
        calls = [json.loads(line) for line in (self.root / "tool.log").read_text().splitlines()]
        self.assertIsNone(calls[0]["parent"])
        self.assertEqual(event["cargo_parent_binding"], json.loads(calls[1]["parent"]))
        binding = event["cargo_parent_binding"]
        self.assertEqual({"id", "observer_session", "observer_worker", "source_capture_worker"}, set(binding))
        self.assertEqual(module.read_artifact(self.directory / "session.json")[1], binding["observer_session"])
        self.assertEqual(module.read_artifact(self.capture_worker)[1], binding["source_capture_worker"])
        self.assertEqual(3, len(event["compiler_children"]))
        self.assertEqual(event["compiler_children"], module.verify(self.directory)["events"][0]["compiler_children"])
        self.assertEqual({"variable": module.PARENT_VARIABLE, "inherited": None,
                          "original": calls[1]["parent"], "query": None}, event["parent_observation_environment"])

    def test_nested_parent_is_explicit_and_nested_query_removes_inherited_marker(self):
        result = self.run_wrapper(environment={"MOCK_CHILDREN": "2", "NESTED_WRAPPER": str(self.directory / "cargo")})
        self.assertEqual(0, result.returncode)
        events = self.events()
        self.assertEqual(2, len(events))
        outer = next(e for e in events if e["cargo_parent_invocation_id"] is None)
        inner = next(e for e in events if e["cargo_parent_invocation_id"] is not None)
        self.assertEqual(outer["id"], inner["cargo_parent_invocation_id"])
        self.assertEqual(2, len(outer["compiler_children"]))
        self.assertEqual(2, len(inner["compiler_children"]))
        self.assertTrue(set(c["capture_invocation_id"] for c in outer["compiler_children"]).isdisjoint(
            c["capture_invocation_id"] for c in inner["compiler_children"]))
        calls = [json.loads(line) for line in (self.root / "tool.log").read_text().splitlines()]
        self.assertTrue(all(c["parent"] is None for c in calls if "--unit-graph" in c["argv"]))
        self.assertFalse(inner["graph_query"]["same_parent_environment"])
        self.assertEqual(2, len(module.verify(self.directory)["events"]))

    def test_parallel_cargo_invocations_and_children_have_disjoint_exact_sets(self):
        processes = [subprocess.Popen([str(self.directory / "cargo"), "build", f"--parallel-{i}"],
            cwd=self.root, env={**self.environment, "MOCK_CHILDREN": "4"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE) for i in range(3)]
        for process in processes:
            self.addCleanup(lambda p=process: p.kill() if p.poll() is None else None)
            out, err = process.communicate(timeout=10)
            self.assertEqual(0, process.returncode)
            self.assertEqual(b'original stdout\x00bytes\n', out)
            self.assertEqual(b'original stderr\xffbytes\n', err)
        events = self.events()
        self.assertEqual(3, len(events))
        ids = [c["capture_invocation_id"] for e in events for c in e["compiler_children"]]
        self.assertEqual(12, len(ids))
        self.assertEqual(12, len(set(ids)))
        self.assertEqual(3, len(module.verify(self.directory)["events"]))

    def test_failed_compiler_child_is_retained_without_replacing_cargo_status(self):
        event = self.child_run(extra={"MOCK_CHILD_EXIT": "19"})
        journal = json.loads(Path(event["compiler_children"][0]["capture_event"]["path"]).read_bytes())
        self.assertEqual(19, journal["exit_code"])
        self.assertEqual(0, event["upstream_exit_code"])
        self.assertFalse(module.verify(self.directory)["runtime_complete"])

    def test_missing_or_unrecorded_child_receipts_cannot_disappear(self):
        event = self.child_run(2)
        Path(event["compiler_children"][0]["receipt"]["path"]).unlink()
        with self.assertRaisesRegex(ValueError, "receipt set differs"):
            module.verify(self.directory)

    def test_parent_child_array_cannot_omit_a_valid_receipt(self):
        event = self.child_run(2)
        event["compiler_children"].pop()
        (self.directory / "events" / (event["id"] + ".json")).write_text(json.dumps(event))
        with self.assertRaisesRegex(ValueError, "recorded compiler-child set changed"):
            module.verify(self.directory)

    def test_child_journal_hash_and_final_state_are_required(self):
        event = self.child_run()
        self.rewrite_child(event, update_journal={"state": "running"})
        with self.assertRaisesRegex(ValueError, "artifact identity changed"):
            module.verify(self.directory)
        self.rewrite_child(event, update_journal={"state": "running"}, rebind=True)
        with self.assertRaisesRegex(ValueError, "journal final parent/worker"):
            module.verify(self.directory)

    def test_mutually_rehashed_cross_session_receipt_cannot_claim_another_parent(self):
        other = self.root / "other-observer"
        module.prepare(other, self.tool, self.capture)
        event = self.child_run()
        self.rewrite_child(event, update_receipt={"observer_session": module.read_artifact(other / "session.json")[1]}, rebind=True)
        with self.assertRaisesRegex(ValueError, "receipt binding mismatch"):
            module.verify(self.directory)

    def test_rehashed_wrong_capture_worker_or_full_parent_binding_is_rejected(self):
        event = self.child_run()
        original = json.loads(Path(event["compiler_children"][0]["capture_event"]["path"]).read_bytes())
        self.rewrite_child(event, update_journal={"capture_worker": {**original["capture_worker"], "sha256": "0" * 64}}, rebind=True)
        with self.assertRaisesRegex(ValueError, "journal final parent/worker"):
            module.verify(self.directory)
        self.rewrite_child(event, update_journal={"capture_worker": original["capture_worker"],
            "cargo_parent": {**original["cargo_parent"], "id": "f" * 32}}, rebind=True)
        with self.assertRaisesRegex(ValueError, "journal final parent/worker"):
            module.verify(self.directory)

    def test_receipt_path_cannot_redirect_to_a_different_journal(self):
        event = self.child_run()
        child = event["compiler_children"][0]
        alternate = self.root / "copied-journal.json"
        alternate.write_bytes(Path(child["capture_event"]["path"]).read_bytes())
        self.rewrite_child(event, update_receipt={"capture_event": module.read_artifact(alternate)[1]}, rebind=True)
        with self.assertRaisesRegex(ValueError, "artifact path mismatch"):
            module.verify(self.directory)

    def test_orphan_receipts_and_extra_schema_fields_are_rejected(self):
        event = self.child_run()
        self.rewrite_child(event, update_receipt={"timestamp_guessed_owner": event["id"]}, rebind=True)
        with self.assertRaisesRegex(ValueError, "receipt schema"):
            module.verify(self.directory)
        orphan = self.directory / "children" / ("f" * 32)
        orphan.mkdir()
        # Check the orphan independently of the already malformed receipt.
        Path(event["compiler_children"][0]["receipt"]["path"]).unlink()
        Path(event["compiler_children"][0]["capture_event"]["path"]).unlink()
        event["compiler_children"] = []
        (self.directory / "events" / (event["id"] + ".json")).write_text(json.dumps(event))
        with self.assertRaisesRegex(ValueError, "lack a final parent"):
            module.verify(self.directory)

    def test_invalid_inherited_parent_is_diagnostic_and_never_replaces_upstream_status(self):
        result = self.run_wrapper(environment={module.PARENT_VARIABLE: '{"id":"forged"}', "ORIGINAL_EXIT": "9"})
        self.assertEqual(9, result.returncode)
        event = self.events()[0]
        self.assertIsNone(event["cargo_parent_binding"])
        self.assertTrue(any("invalid Cargo parent binding" in e for e in event["capture_errors"]))
        self.assertEqual('{"id":"forged"}', event["parent_observation_environment"]["original"])

    def test_no_query_policy_and_jobserver_descriptor_preserve_original_process(self):
        other = self.root / "no-query-observer"
        module.prepare(other, self.tool, self.capture, graph_query=False)
        read_fd, write_fd = os.pipe()
        try:
            result = subprocess.run([str(other / "cargo"), "build"], cwd=self.root,
                env={**self.environment, "JOBSERVER_FD": str(read_fd), "MAKEFLAGS": f"--jobserver-auth={read_fd},{write_fd}"},
                pass_fds=(read_fd, write_fd), capture_output=True)
            self.assertEqual(0, result.returncode)
            calls = [json.loads(line) for line in (self.root / "tool.log").read_text().splitlines()]
            self.assertEqual(1, len(calls))
            self.assertIsNotNone(calls[0]["jobserver_open"])
            event = json.loads(next((other / "events").glob("*.json")).read_bytes())
            self.assertEqual("not-applicable", event["graph_query"]["status"])
            self.assertEqual(f"--jobserver-auth={read_fd},{write_fd}", event["build_environment"]["MAKEFLAGS"])
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_receipt_free_orphan_journal_with_rehashed_parent_cannot_mint_ownership(self):
        event = self.child_run()
        child = event["compiler_children"][0]
        journal = json.loads(Path(child["capture_event"]["path"]).read_bytes())
        journal["id"] = "e" * 32
        journal["cargo_parent_invocation_id"] = "f" * 32
        journal["cargo_parent"] = {**event["cargo_parent_binding"], "id": "f" * 32}
        orphan = self.capture / "events" / (journal["id"] + ".json")
        orphan.write_text(json.dumps(journal))
        with self.assertRaisesRegex(ValueError, "lacks a final parent"):
            module.verify(self.directory)

    def test_nested_parent_reference_requires_an_actual_final_parent_event(self):
        self.run_wrapper(environment={"NESTED_WRAPPER": str(self.directory / "cargo")})
        outer = next(e for e in self.events() if e["cargo_parent_invocation_id"] is None)
        (self.directory / "events" / (outer["id"] + ".json")).unlink()
        with self.assertRaises(FileNotFoundError):
            module.verify(self.directory)

    def test_artifact_field_types_and_cross_capture_binding_are_strict(self):
        event = self.child_run()
        original = event["cargo_parent_binding"]["source_capture_worker"]
        self.rewrite_child(event, update_receipt={"source_capture_worker": {**original, "bytes": True}}, rebind=True)
        with self.assertRaisesRegex(ValueError, "receipt binding mismatch"):
            module.verify(self.directory)
        with self.assertRaisesRegex(ValueError, "identity fields"):
            module.checked_artifact({**original, "bytes": True})
        other_capture = self.root / "other-capture-worker.py"
        other_capture.write_bytes(self.capture_worker.read_bytes())
        other = module.read_artifact(other_capture)[1]
        self.rewrite_child(event, update_receipt={"source_capture_worker": other}, rebind=True)
        with self.assertRaisesRegex(ValueError, "receipt binding mismatch"):
            module.verify(self.directory)

    def test_private_environment_never_leaks_into_original_streams_and_zero_admission_is_verified(self):
        secret = "mock-private-environment-secret"
        result = self.run_wrapper(environment={"UNLISTED_PRIVATE_TEST_VALUE": secret})
        self.assertNotIn(secret.encode(), result.stdout + result.stderr)
        event = self.events()[0]
        self.assertNotIn("UNLISTED_PRIVATE_TEST_VALUE", event["build_environment"])
        self.assertEqual(secret, json.loads(Path(event["inherited_environment_record"]["path"]).read_bytes())["UNLISTED_PRIVATE_TEST_VALUE"])
        event["runtime_complete"] = True
        (self.directory / "events" / (event["id"] + ".json")).write_text(json.dumps(event))
        with self.assertRaisesRegex(ValueError, "cannot establish source or lowering admission"):
            module.verify(self.directory)


if __name__ == "__main__":
    unittest.main()
