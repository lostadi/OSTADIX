"""Hermetic Cargo-parent capture tests; no compiler or runtime is executed.

The original-command and LLVM replay subprocesses are mocked. Hashed source,
worker, session and journal artifacts are real temporary files. These tests
establish capture bindings and status preservation, not production ownership,
native-member/CGU edges, dependency closure, or O-core/native execution.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("OCORE_TEST_CAPTURE_WORKER", ROOT / "scripts/ocore_runtime_capture.py")).resolve()
OBSERVER = Path(os.environ.get("OCORE_TEST_CARGO_OBSERVER", ROOT / "tools/ocore-runtime/rust/observe_cargo.py")).resolve()
OBSERVER_SHA256 = "9e10e5fd5a95c196bc1f8403a3180d450b477a419abc4774316a12fbe3f40993"


def load_worker(path: Path):
    spec = importlib.util.spec_from_file_location("capture_cargo_parent_" + hashlib.sha256(str(path).encode()).hexdigest(), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capture = load_worker(SCRIPT)


class CaptureCargoParentTests(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get("OCORE_TEST_CAPTURE_CARGO_PARENT_OUTPUT_DIR")
        if retained:
            base = Path(retained).expanduser().resolve()
            base.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=base))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="capture-cargo-parent-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name).resolve()
        self.records = []
        self.source = self.directory / "source-capture"
        self.source.mkdir()
        self.worker_record = capture.snapshot_worker(self.source)
        self.worker = load_worker(Path(self.worker_record["artifact"]["path"]))
        self.compiler_identity = self.write("inert-stage-compiler", b"identity fixture; never executed\n")
        tool = {**self.compiler_identity, "invoked_path": self.compiler_identity["path"],
                "version": "inert test LLVM22 frontend", "llvm_version": "22.1.6"}
        self.session = {"capture_worker": self.worker_record,
            "recipe": {"toolchain": {"llvm_version": "22.1.6", "rustc_release": "1.97.1"}},
            "tools": {"clang": tool, "cxx": tool, "rustc": tool, "nm": tool},
            "build_steps": []}
        self.worker.write_json(self.source / "session.json", self.session)
        self.observer = self.directory / "observer"
        self.observer.mkdir()
        self.assertEqual(hashlib.sha256(OBSERVER.read_bytes()).hexdigest(), OBSERVER_SHA256)
        self.assertEqual(self.worker.REGISTERED_CARGO_OBSERVER_SHA256, OBSERVER_SHA256)
        self.observer_worker = self.write("observer/worker.py", OBSERVER.read_bytes())
        self.observer_session = {"schema": "ocore-cargo-parent-observer-session-v1",
            "observer_worker": self.observer_worker, "source_capture": str(self.source),
            "source_capture_worker": self.worker_record,
            "scope": "hermetic parent binding; no production/compiler admission"}
        self.bind_session()
        patch = mock.patch.object(self.worker.subprocess, "run",
            side_effect=AssertionError("hermetic capture tests must never execute an external tool"))
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self):
        report = {"test_id": self.id(), "scope": "hermetic compiler-parent journal and receipt evidence",
            "worker": self.worker.file_info(Path(self.worker.__file__)),
            "observer": self.worker.file_info(OBSERVER), "records": self.records,
            "native_execution_qualified": False, "ocore_lowering_complete": False,
            "runtime_complete": False, "dependency_closure_complete": False,
            "native_member_cgu_edges_proven": False}
        self.worker.write_json(self.directory / "cargo-parent-conformance.json", report)

    def write(self, name, data):
        path = self.directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return capture.file_info(path)

    def bind_session(self):
        self.worker.write_json(self.observer / "session.json", self.observer_session)
        self.binding = {"id": "1" * 32,
            "observer_session": self.worker.file_info(self.observer / "session.json"),
            "observer_worker": self.observer_worker,
            "source_capture_worker": self.worker_record["artifact"]}

    def validate(self, binding=..., session=None, expected=None):
        return self.worker.validate_cargo_parent(self.binding if binding is ... else binding,
            self.source, self.session if session is None else session,
            self.worker_record["artifact"], expected)

    def journal(self, ident="2" * 32):
        event = {"id": ident, "kind": "clang", "state": "finished", "exit_code": 0,
            "capture_worker": self.worker_record["artifact"],
            "cargo_parent_invocation_id": self.binding["id"], "cargo_parent": self.binding,
            "classification": "compile", "capture_errors": [], "units": []}
        path = self.source / "events" / (ident + ".json")
        self.worker.write_json(path, event)
        return event, path

    def publish(self, event, path):
        return self.worker.publish_cargo_child(self.binding, self.source, path, event)

    def receipt_path(self, ident):
        return self.observer / "children" / self.binding["id"] / (ident + ".json")

    def invoke(self, kind="clang", args=None, status=0, parent="valid", env=None,
               publication_error=None, mutate_during_command=None):
        if args is None:
            args = ["--version"] if kind != "rustc" else ["--print", "sysroot"]
        original = [self.compiler_identity["path"], *args] if kind == "rustc" else list(args)
        environment = dict(env or {})
        if parent == "valid":
            environment[self.worker.CARGO_PARENT_VARIABLE] = json.dumps(self.binding)
        elif parent is not None:
            environment[self.worker.CARGO_PARENT_VARIABLE] = parent
        calls = []

        def original_or_replay(argv, **kwargs):
            calls.append({"argv": list(argv), "environment": kwargs.get("env")})
            if len(calls) == 1:
                if mutate_during_command is not None:
                    mutate_during_command()
                return subprocess.CompletedProcess(argv, status)
            if "-emit-llvm" in argv:
                output = Path(argv[argv.index("-o") + 1])
                depfile = Path(argv[argv.index("-MF") + 1])
            elif "--emit=llvm-ir,dep-info" in argv:
                output = Path(argv[argv.index("--out-dir") + 1]) / "whole-crate.ll"
                depfile = output.with_suffix(".d")
            else:
                raise AssertionError("unexpected mocked command: " + repr(argv))
            source = next(arg for arg in args if arg.endswith((".c", ".cc", ".rs")))
            output.write_text('target triple = "x86_64-unknown-linux-gnu"\n'
                'target datalayout = "e-p:64:64"\ndefine void @fixture() { ret void }\n')
            depfile.write_text(str(output) + ": " + source + "\n")
            return subprocess.CompletedProcess(argv, 0)

        rust_info = {**self.compiler_identity, "invoked_path": self.compiler_identity["path"],
            "version": "inert Rust identity", "llvm_version": "22.1.6", "release": "1.97.1",
            "default_sysroot": "/queried/stage/sysroot"}
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(self.worker.Path, "cwd", return_value=self.directory), \
                mock.patch.object(self.worker.subprocess, "run", side_effect=original_or_replay), \
                mock.patch.object(self.worker, "tool_info", return_value=rust_info):
            if publication_error is None:
                result = self.worker.compiler(self.source, kind, original)
            else:
                with mock.patch.object(self.worker, "write_exclusive_json", side_effect=publication_error):
                    result = self.worker.compiler(self.source, kind, original)
        events = sorted((self.source / "events").glob("*.json"))
        event = self.worker.read_json(events[-1]) if len(events) == 1 else next(
            self.worker.read_json(path) for path in events if self.worker.read_json(path)["argv"] == args)
        self.records.append({"kind": kind, "original": original, "calls": calls,
            "status": result, "journal": event, "journal_artifact": self.worker.file_info(
                self.source / "events" / (event["id"] + ".json"))})
        return result, event, calls

    def assert_receipt(self, event):
        path = self.receipt_path(event["id"])
        receipt = self.worker.read_json(path)
        self.assertEqual(set(receipt), {"schema", "cargo_parent_invocation_id", "capture_invocation_id",
            "capture_event", "observer_session", "source_capture_worker"})
        self.assertEqual(receipt, {"schema": "ocore-cargo-compiler-child-v1",
            "cargo_parent_invocation_id": self.binding["id"], "capture_invocation_id": event["id"],
            "capture_event": self.worker.file_info(self.source / "events" / (event["id"] + ".json")),
            "observer_session": self.binding["observer_session"],
            "source_capture_worker": self.binding["source_capture_worker"]})
        self.records.append({"child_receipt": self.worker.file_info(path), "receipt": receipt})

    def test_known_registered_observer_binds_actual_frozen_source_worker(self):
        self.assertEqual(self.validate(), self.binding)
        self.assertEqual(self.worker.verify_worker(self.session, self.source), self.worker_record)
        self.assertEqual(set(self.binding), {"id", "observer_session", "observer_worker", "source_capture_worker"})

    def test_parent_field_uuid_and_artifact_types_are_exact(self):
        malformed = [None, [], {}, {**self.binding, "extra": True}]
        malformed.extend({**self.binding, "id": value} for value in
            ["", "A" * 32, "1" * 31, "1" * 33, "12345678-1234-1234-1234-123456789012", True, 1])
        for field in ("observer_session", "observer_worker", "source_capture_worker"):
            for value in [None, [], {}, {**self.binding[field], "extra": 0},
                          {**self.binding[field], "bytes": True}, {**self.binding[field], "bytes": -1},
                          {**self.binding[field], "sha256": "F" * 64},
                          {**self.binding[field], "path": "relative.json"}]:
                malformed.append({**self.binding, field: value})
        for binding in malformed:
            with self.subTest(binding=binding), self.assertRaises(self.worker.CaptureError):
                self.validate(binding)

    def test_self_consistent_arbitrary_observer_is_rejected_by_registered_pin(self):
        self.observer_worker = self.write("observer/worker.py", b"unregistered supplied observer source\n")
        self.observer_session["observer_worker"] = self.observer_worker
        self.bind_session()
        with self.assertRaisesRegex(self.worker.CaptureError, "independently registered worker"):
            self.validate()
        # The explicit internal seam supports inert hermetic fixtures only.
        self.assertEqual(self.validate(expected=self.observer_worker["sha256"]), self.binding)

    def test_changed_observer_session_or_worker_bytes_reject_without_new_digest(self):
        for field in ("observer_session", "observer_worker"):
            path = Path(self.binding[field]["path"])
            original = path.read_bytes()
            with self.subTest(field=field):
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(self.worker.CaptureError, "bytes or identity changed"):
                    self.validate()
                path.write_bytes(original)

    def test_source_worker_bytes_and_current_wrapper_context_cannot_be_rebound(self):
        path = Path(self.worker_record["artifact"]["path"])
        original = path.read_bytes()
        path.chmod(0o644)
        path.write_bytes(original + b"\n# changed\n")
        with self.assertRaisesRegex(self.worker.CaptureError, "bytes or identity changed"):
            self.validate()
        path.write_bytes(original)
        for value in (None, [], {}, {**self.worker_record, "schema": "other"}):
            with self.subTest(value=value), self.assertRaises(self.worker.CaptureError):
                self.validate(session={**self.session, "capture_worker": value})

    def test_cross_session_same_worker_bytes_never_establish_parentage(self):
        other = self.directory / "different-source-capture"
        other.mkdir()
        other_record = capture.snapshot_worker(other)
        self.assertEqual(other_record["artifact"]["sha256"], self.worker_record["artifact"]["sha256"])
        self.observer_session["source_capture"] = str(other)
        self.observer_session["source_capture_worker"] = other_record
        self.bind_session()
        with self.assertRaisesRegex(self.worker.CaptureError, "different source-capture session or worker"):
            self.validate()

    def test_session_schema_source_path_worker_and_observer_identity_must_match(self):
        changes = [{"schema": "unknown"}, {"source_capture": str(self.directory)},
            {"source_capture_worker": {"artifact": self.worker_record["artifact"]}},
            {"observer_worker": {**self.observer_worker, "path": str(self.directory / "other.py")}}]
        original = copy.deepcopy(self.observer_session)
        for change in changes:
            with self.subTest(change=change):
                self.observer_session = {**original, **change}
                self.bind_session()
                with self.assertRaises(self.worker.CaptureError):
                    self.validate()

    def test_artifact_symlink_and_noncanonical_paths_are_not_immutable_identities(self):
        link = self.directory / "observer-link.py"
        link.symlink_to(self.observer / "worker.py")
        for path in (str(link), str(self.observer / ".." / "observer" / "worker.py")):
            with self.subTest(path=path), self.assertRaises(self.worker.CaptureError):
                self.validate({**self.binding, "observer_worker": {**self.observer_worker, "path": path}})

    def test_mutable_capture_build_steps_do_not_redefine_frozen_parent_worker(self):
        updated = {**self.session, "build_steps": [{"name": "next", "exit_code": None}]}
        self.worker.write_json(self.source / "session.json", updated)
        self.assertEqual(self.validate(session=updated), self.binding)
        event, path = self.journal()
        self.publish(event, path)
        self.assert_receipt(event)

    def test_final_child_receipt_has_exact_six_fields_and_complete_journal_hash(self):
        event, path = self.journal()
        artifact = self.publish(event, path)
        self.assertEqual(artifact, self.worker.file_info(self.receipt_path(event["id"])))
        self.assert_receipt(event)
        self.assertEqual(list(self.receipt_path(event["id"]).parent.glob("*.tmp")), [])

    def test_duplicate_child_publication_is_exclusive_and_preserves_original_receipt(self):
        event, path = self.journal()
        self.publish(event, path)
        receipt = self.receipt_path(event["id"])
        before = receipt.read_bytes()
        with self.assertRaises(FileExistsError):
            self.publish(event, path)
        self.assertEqual(receipt.read_bytes(), before)
        self.assertEqual(list(receipt.parent.glob("*.tmp")), [])

    def test_tampered_final_journal_or_wrong_finished_parent_contract_cannot_publish(self):
        original, path = self.journal()
        malformed = [{**original, "state": "running"}, {**original, "exit_code": True},
            {**original, "kind": "archive"}, {**original, "cargo_parent_invocation_id": "3" * 32},
            {**original, "cargo_parent": {**self.binding, "id": "3" * 32}},
            {**original, "capture_worker": {**self.worker_record["artifact"], "bytes": 0}},
            {**original, "id": "invalid"}]
        for event in malformed:
            with self.subTest(event=event), self.assertRaises(self.worker.CaptureError):
                self.publish(event, path)
        self.worker.write_json(path, {**original, "capture_errors": ["changed after finish"]})
        with self.assertRaisesRegex(self.worker.CaptureError, "changed before child publication"):
            self.publish(original, path)
        self.assertFalse((self.observer / "children").exists())

    def test_failed_clang_cxx_and_rust_commands_keep_actual_result_and_parent_receipts(self):
        for kind in ("clang", "cxx", "rustc"):
            suffix = ".rs" if kind == "rustc" else ".c"
            source = self.write("original-" + kind + suffix, b"original unit; inert mocked frontend\n")
            args = ([source["path"], "--emit", "link"] if kind == "rustc" else
                ["-c", source["path"], "-o", str(self.directory / (kind + ".o"))])
            result, event, calls = self.invoke(kind, args, status=37)
            self.assertEqual(result, 37)
            self.assertEqual(event["exit_code"], 37)
            self.assertEqual(event["state"], "finished")
            self.assertEqual(event["driver_kind"], kind)
            self.assertEqual(event["kind"], "rustc" if kind == "rustc" else "clang")
            self.assertEqual(event["argv"], args)
            self.assertEqual(calls[0]["argv"], [self.compiler_identity["path"], *args])
            self.assertEqual(event["sources"], [source])
            self.assertEqual(event["units"], [])
            self.assertEqual(event["capture_errors"], [])
            self.assert_receipt(event)

    def test_mocked_whole_clang_translation_retains_source_replay_and_final_parent(self):
        source = self.write("whole.c", b"void fixture(void) {}\n")
        args = ["-c", source["path"], "-o", str(self.directory / "whole.o")]
        result, event, calls = self.invoke(args=args)
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 2)
        self.assertTrue(event["translation_required"])
        self.assertEqual(event["classification"], "compile")
        self.assertEqual(event["sources"], [source])
        self.assertEqual(len(event["units"]), 1)
        self.assertEqual(event["units"][0]["source"], source)
        self.assertEqual(event["units"][0]["dependencies"], [source])
        self.assertEqual(event["units"][0]["replay_exit_code"], 0)
        self.assertEqual(event["cargo_parent"], self.binding)
        self.assert_receipt(event)

    def test_mocked_rust_translation_keeps_actual_stage_compiler_and_original_argv(self):
        source = self.write("whole.rs", b"pub fn fixture() {}\n")
        args = [source["path"], "--crate-name", "whole", "--emit", "link"]
        result, event, calls = self.invoke("rustc", args=args)
        self.assertEqual(result, 0)
        self.assertEqual(event["compiler"], self.compiler_identity["path"])
        self.assertEqual(event["argv"], args)
        self.assertEqual(calls[0]["argv"], [self.compiler_identity["path"], *args])
        self.assertEqual(len(event["units"]), 1)
        self.assertEqual(event["units"][0]["source"], source)
        self.assertEqual(event["units"][0]["kind"], "rustc")
        self.assert_receipt(event)

    def test_invalid_parent_json_never_skips_original_command_or_replaces_its_status(self):
        for parent in ("not-json", "[]", json.dumps({**self.binding, "id": "wrong"})):
            # Different argv identifies each retained event independently.
            args = ["--version", "--inert-case=" + str(len(self.records))]
            result, event, calls = self.invoke(args=args, status=23, parent=parent)
            self.assertEqual(result, 23)
            self.assertEqual(calls[0]["argv"], [self.compiler_identity["path"], *args])
            self.assertNotIn("cargo_parent", event)
            self.assertNotIn("cargo_parent_invocation_id", event)
            self.assertTrue(any(error.startswith("Cargo parent provenance: ") for error in event["capture_errors"]))
            self.assertFalse(self.receipt_path(event["id"]).exists())

    def test_unbound_source_worker_parent_is_error_and_original_result_survives(self):
        self.worker.write_json(self.source / "session.json", {**self.session, "capture_worker": None})
        result, event, calls = self.invoke(status=29)
        self.assertEqual(result, 29)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("cargo_parent", event)
        self.assertTrue(any("currently executing bound capture worker" in error for error in event["capture_errors"]))
        self.assertFalse((self.observer / "children").exists())

    def test_child_publication_error_rewrites_final_journal_without_status_replacement(self):
        result, event, calls = self.invoke(status=31, publication_error=PermissionError("inert receipt failure"))
        self.assertEqual(result, 31)
        self.assertEqual(event["exit_code"], 31)
        self.assertEqual(len(calls), 1)
        self.assertEqual(event["cargo_parent"], self.binding)
        self.assertIn("Cargo compiler-child receipt: inert receipt failure", event["capture_errors"])
        self.assertFalse(self.receipt_path(event["id"]).exists())

    def test_parent_changed_during_command_blocks_receipt_but_keeps_original_status(self):
        def change():
            with (self.observer / "session.json").open("ab") as stream:
                stream.write(b" ")
        result, event, _ = self.invoke(status=19, mutate_during_command=change)
        self.assertEqual(result, 19)
        self.assertTrue(any(error.startswith("Cargo compiler-child receipt: ") for error in event["capture_errors"]))
        self.assertFalse(self.receipt_path(event["id"]).exists())

    def test_no_parent_query_journals_never_create_cargo_child_edges(self):
        for kind in ("clang", "rustc"):
            args = ["--version", "--inert-kind=" + kind] if kind == "clang" else ["--print", "sysroot"]
            result, event, _ = self.invoke(kind, args=args, parent=None)
            self.assertEqual(result, 0)
            self.assertEqual(event["classification"], "query")
            self.assertFalse(event["translation_required"])
            self.assertNotIn(self.worker.CARGO_PARENT_VARIABLE, event["build_environment"])
            self.assertNotIn("cargo_parent_invocation_id", event)
            self.assertEqual(event["units"], [])
        self.assertFalse((self.observer / "children").exists())

    def test_bound_query_and_metadata_only_rust_are_observed_without_translation_admission(self):
        _, query, _ = self.invoke()
        self.assertEqual(query["classification"], "query")
        self.assertFalse(query["translation_required"])
        self.assert_receipt(query)
        source = self.write("only-metadata.rs", b"pub fn metadata() {}\n")
        _, event, calls = self.invoke("rustc", [source["path"], "--emit=metadata"])
        self.assertEqual(event["classification"], "analysis-only")
        self.assertFalse(event["translation_required"])
        self.assertEqual(event["units"], [])
        self.assertEqual(len(calls), 1)
        self.assert_receipt(event)
        self.assertNotIn("native_execution_qualified", event)

    def test_queried_default_sysroot_is_preserved_separately_from_explicit_and_stage_environment(self):
        for extra, effective, origin in [([], "/queried/stage/sysroot", "queried-default"),
            (["--sysroot", "/explicit/argv/sysroot"], "/explicit/argv/sysroot", "explicit-argv"),
            (["--sysroot=/equal/argv/sysroot"], "/equal/argv/sysroot", "explicit-argv")]:
            args = ["--print", "sysroot", *extra]
            _, event, calls = self.invoke("rustc", args=args,
                env={"RUSTC_STAGE": "2", "RUSTC_SYSROOT": "/different/environment/sysroot", "RUSTC_REAL": "/stage2/rustc"})
            self.assertEqual(event["frontend"]["default_sysroot"], "/queried/stage/sysroot")
            self.assertEqual(event["frontend"]["effective_sysroot"], effective)
            self.assertEqual(event["frontend"]["sysroot_source"], origin)
            self.assertEqual(event["build_environment"]["RUSTC_STAGE"], "2")
            self.assertEqual(event["build_environment"]["RUSTC_SYSROOT"], "/different/environment/sysroot")
            self.assertEqual(event["argv"], args)
            self.assertEqual(calls[0]["argv"], [self.compiler_identity["path"], *args])
            self.assert_receipt(event)

    def test_rust_response_file_sysroot_overrides_default_with_original_response_evidence(self):
        response = self.write("rust-args.rsp", b"--print\nsysroot\n--sysroot\n/response/sysroot\n")
        _, event, calls = self.invoke("rustc", args=["@" + response["path"]])
        self.assertEqual(event["frontend"]["effective_sysroot"], "/response/sysroot")
        self.assertEqual(event["response_files"], [response])
        self.assertEqual(event["expanded_argv"], ["--print", "sysroot", "--sysroot", "/response/sysroot"])
        self.assertEqual(calls[0]["argv"], [self.compiler_identity["path"], "@" + response["path"]])
        self.assert_receipt(event)

    def test_tool_info_records_actual_default_query_and_stage_executable_identity(self):
        version = "rustc 1.97.1\nrelease: 1.97.1\ncommit-hash: " + "a" * 40 + "\nLLVM version: 22.1.6"
        distinct = self.write("queried-sysroot/bin/rustc", b"inert unrelated queried compiler\n")
        same_content = self.write("same-content-sysroot/bin/rustc",
            Path(self.compiler_identity["path"]).read_bytes())
        direct = self.write("direct-sysroot/bin/rustc", b"inert directly invoked compiler\n")
        self.assertEqual(same_content["sha256"], self.compiler_identity["sha256"])
        self.assertEqual(same_content["bytes"], self.compiler_identity["bytes"])
        self.assertNotEqual(same_content["path"], self.compiler_identity["path"])
        for label, invoked, candidate, complete in [
                ("unmatched-proxy", self.compiler_identity, distinct, False),
                ("same-content-distinct-path", self.compiler_identity, same_content, False),
                ("direct-compiler", direct, direct, True)]:
            with self.subTest(identity=label):
                sysroot = Path(candidate["path"]).parent.parent
                with mock.patch.object(self.worker.shutil, "which", return_value=invoked["path"]), \
                        mock.patch.object(self.worker, "run_text", side_effect=[version, str(sysroot)]) as query:
                    result = self.worker.tool_info(invoked["path"], "rustc")
                self.assertEqual(query.call_args_list, [mock.call([invoked["path"], "-vV"]),
                    mock.call([invoked["path"], "--print", "sysroot"])])
                self.assertEqual(result["default_sysroot"], str(sysroot))
                self.assertEqual(result["invoked_path"], invoked["path"])
                self.assertEqual({key: result[key] for key in ("path", "sha256", "bytes")}, invoked)
                self.assertEqual(result["queried_sysroot_compiler"], candidate)
                self.assertIs(result["actual_producer_identity_complete"], complete)
                if complete:
                    self.assertEqual(result["executing_binary"], invoked)
                else:
                    self.assertNotIn("executing_binary", result)
                self.assertEqual(result["release"], "1.97.1")
                self.assertEqual(result["commit"], "a" * 40)
                self.assertEqual(result["llvm_version"], "22.1.6")
                self.records.append({"identity_case": label, "invoked_fixture": invoked,
                    "queried_candidate_fixture": candidate, "tool_info": result,
                    "queries": [call.args[0] for call in query.call_args_list],
                    "scope": "mocked queries and inert identity files; no actual compiler execution or CGU ownership"})

    def test_internal_expected_observer_digest_has_no_cli_or_environment_override(self):
        import ast
        tree = ast.parse(SCRIPT.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        self.assertNotIn("expected_cargo_observer_sha256", ast.unparse(main))
        self.assertNotIn("expected_observer_sha256", ast.unparse(main))
        self.assertEqual(self.worker.REGISTERED_CARGO_OBSERVER_SHA256, OBSERVER_SHA256)
        # An ambient-looking override cannot change the independently pinned worker.
        self.observer_worker = self.write("observer/worker.py", b"arbitrary graph source\n")
        self.observer_session["observer_worker"] = self.observer_worker
        self.bind_session()
        with mock.patch.dict(os.environ, {"OCORE_CAPTURE_CARGO_OBSERVER_SHA256": self.observer_worker["sha256"]}):
            with self.assertRaisesRegex(self.worker.CaptureError, "independently registered worker"):
                self.validate()


if __name__ == "__main__":
    unittest.main()
