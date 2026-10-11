"""Opt-in Rust producer byte-edge capture, with explicit bounded scope.

Hermetic tests use authored ELF containers and mock the metadata decoder; they
claim no LLVM semantics. The required real test uses original pinned Cargo/rustc
on three offline local crates. Installed std and executable-only CGU/provider
edges remain gaps; none of these tests establishes whole Rust/O-core support.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("OCORE_TEST_CAPTURE_WORKER", ROOT / "scripts/ocore_runtime_capture.py")).resolve()
OBSERVER = ROOT / "tools/ocore-runtime/rust/observe_cargo.py"
SDK = Path(os.environ.get("OCORE_TEST_RUST_CGU_LLVM_BIN", str(
    Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin")))


def load(path):
    spec = importlib.util.spec_from_file_location("rust_cgu_" + hashlib.sha256(str(path).encode()).hexdigest(), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capture = load(SCRIPT)


def elf(bitcode=b"BC\xc0\xdeauthored-byte-fixture", duplicate=False):
    """Independent minimal ELF64 container; executable instructions are inert."""
    names = b"\0.text\0.llvmbc\0.shstrtab\0"
    pieces = [(1, b"\xc3"), (7, bitcode), (15, names)]
    if duplicate:
        pieces.insert(2, (7, bitcode))
    data = bytearray(64)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, body in pieces:
        offset = len(data)
        data.extend(body)
        sections.append((name, 3 if name == 15 else 1, 6 if name == 1 else 0,
                         0, offset, len(body), 0, 0, 1, 0))
    while len(data) % 8:
        data.append(0)
    shoff = len(data)
    for section in sections:
        data.extend(struct.pack("<IIQQQQIIQQ", *section))
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    data[:64] = struct.pack("<16sHHIQQQIHHHHHH", ident, 1, 62, 1, 0, 0, shoff, 0,
                            64, 0, 0, 64, len(sections), len(sections) - 1)
    return bytes(data)


def archive(members):
    data = bytearray(b"!<arch>\n")
    for name, body in members:
        header = (name + "/").encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
        header += b"100644".ljust(8) + str(len(body)).encode().ljust(10) + b"`\n"
        data.extend(header + body)
        if len(body) % 2:
            data.extend(b"\n")
    return bytes(data)


def metadata_elf():
    names, payload = b"\0.rmeta\0.shstrtab\0", b"authored Rust metadata resource"
    data = bytearray(64)
    data.extend(payload + names)
    while len(data) % 8:
        data.append(0)
    shoff = len(data)
    for section in [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                    (1, 1, 0, 0, 64, len(payload), 0, 0, 1, 0),
                    (8, 3, 0, 0, 64 + len(payload), len(names), 0, 0, 1, 0)]:
        data.extend(struct.pack("<IIQQQQIIQQ", *section))
    data[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF" + bytes([2, 1, 1]) + bytes(9),
                           1, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 2)
    return bytes(data)


class RustCguCaptureTests(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get("OCORE_TEST_CAPTURE_RUST_CGU_OUTPUT_DIR")
        if retained:
            base = Path(retained).resolve()
            base.mkdir(parents=True, exist_ok=True)
            self.root = Path(tempfile.mkdtemp(prefix="run-", dir=base))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="rust-cgu-capture-")
            self.addCleanup(temporary.cleanup)
            self.root = Path(temporary.name)
        self.directory = self.root / "capture"
        self.directory.mkdir()
        self.worker_record = capture.snapshot_worker(self.directory, capture.RUST_EMBEDDED_POLICY)
        self.worker = load(Path(self.worker_record["artifact"]["path"]))
        self.source = self.write("probe.rs", b"pub fn probe()->u8 { 1 }\n")
        tool = {**self.write("inert-driver", b"not an executable; hermetic fixture\n"),
                "invoked_path": str(self.root / "inert-driver"), "version": "inert LLVM22", "llvm_version": "22.1.6"}
        self.session = {"capture_worker": self.worker_record,
            "recipe": {"toolchain": {"llvm_version": "22.1.6", "rustc_release": "1.97.1",
                                      "rust_capture_policy": capture.RUST_EMBEDDED_POLICY}},
            "tools": {"rustc": tool, "nm": tool, "llvm_dis": tool}, "build_steps": []}
        self.worker.write_json(self.directory / "session.json", self.session)

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return capture.file_info(path)

    def event(self, outputs):
        event_id = "1" * 32
        directory = self.directory / "units" / event_id
        directory.mkdir(parents=True)
        return {"id": event_id, "sources": [self.source], "outputs": outputs, "units": [],
                "frontend": self.session["tools"]["rustc"], "capture_errors": [],
                "cargo_parent_invocation_id": "2" * 32}, directory

    def decode(self, path, decoder=None):
        return {**capture.file_info(path), "format": "llvm-bitcode", "target_triple": "authored-container-only",
                "data_layout": "e-p:64:64", "decoder": decoder}

    def collect(self, outputs):
        event, directory = self.event(outputs)
        with mock.patch.object(self.worker, "ir_info", side_effect=self.decode):
            self.worker.capture_rust_cgus(event, directory, self.session)
        return event

    def test_opt_in_recipe_is_exact_and_absence_preserves_default(self):
        recipe = {"schema": capture.RECIPE_SCHEMA, "name": "test",
            "source": {"url": "fixture", "revision": "a" * 40},
            "toolchain": {"llvm_version": "22.1.6"}, "commands": [{"argv": ["inert"]}],
            "coverage": {"required_units": [{"id": "x", "kind": "rustc", "source": "probe.rs"}]}}
        capture.validate_recipe(recipe)
        for wrong in [None, "", "embedded", "rust-embedded-bc-v2", True, {}]:
            with self.subTest(value=wrong):
                bad = copy.deepcopy(recipe)
                bad["toolchain"]["rust_capture_policy"] = wrong
                with self.assertRaisesRegex(capture.CaptureError, "rust_capture_policy"):
                    capture.validate_recipe(bad)
        recipe["toolchain"]["rust_capture_policy"] = capture.RUST_EMBEDDED_POLICY
        capture.validate_recipe(recipe)
        args = ["@original-response", "-Cembed-bitcode=no", "-Csave-temps=no"]
        self.assertEqual(capture.rust_instrumentation(args, False), (args, []))

    def test_every_codegen_spelling_is_recorded_and_capture_options_are_unique(self):
        for prefix in [["-C"], ["--codegen"], ["-C"], ["--codegen="]]:
            attached = prefix in [["--codegen="]]
            args = [prefix[0] + "embed-bitcode=no"] if attached else [*prefix, "embed-bitcode=no"]
            args += ["-Cembed-bitcode=no", "-C", "embed-bitcode=yes", "--codegen=save-temps=no",
                     "-C", "save-temps=yes", "-Copt-level=2", "source.rs"]
            result, changes = capture.rust_instrumentation(args, True)
            self.assertEqual(result.count("embed-bitcode=yes"), 1)
            self.assertEqual(result.count("save-temps=yes"), 1)
            self.assertNotIn("-Cembed-bitcode=no", result)
            self.assertIn("-Copt-level=2", result)
            self.assertEqual(changes[0]["incoming"], args[:1] if attached else args[:2])
            self.assertEqual(result[-1], "source.rs")

    def test_queries_and_metadata_only_keep_original_argv(self):
        inputs = [Path(self.source["path"])]
        for args in [["--print", "sysroot"], ["--print=sysroot"], ["-vV"],
                     ["--emit=metadata,dep-info", "probe.rs"], ["--emit", "metadata=out", "probe.rs"]]:
            self.assertFalse(capture.rust_translation(args, inputs))
        for emit in ["link", "obj", "link,metadata", "llvm-bc", "llvm-ir"]:
            self.assertTrue(capture.rust_translation(["--emit=" + emit, "probe.rs"], inputs))

    def test_queried_sysroot_candidate_is_not_a_distinct_executing_binary(self):
        candidate = self.write("queried-sysroot/bin/rustc", b"a different compiler identity\n")
        version = "rustc 1.97.1\nrelease: 1.97.1\nLLVM version: 22.1.6"
        with mock.patch.object(self.worker.shutil, "which", return_value=self.session["tools"]["rustc"]["invoked_path"]), \
                mock.patch.object(self.worker, "run_text", side_effect=[version, str(self.root / "queried-sysroot")]):
            info = self.worker.tool_info("inert-compiler", "rustc")
        self.assertEqual(info["queried_sysroot_compiler"], candidate)
        self.assertNotIn("executing_binary", info)
        self.assertFalse(info["actual_producer_identity_complete"])

    def test_cargo_candidate_requires_exact_selected_artifact_even_at_same_version(self):
        candidate = self.write("queried-sysroot/bin/cargo", b"same-version Cargo identity\n")
        unrelated = self.write("unrelated/bin/cargo", b"same-version Cargo identity\n")
        for selected, expected_direct in [(candidate, True), (unrelated, False)]:
            with self.subTest(selected=selected["path"]):
                tool = {**selected, "invoked_path": selected["path"], "version": "cargo 1.97.1", "release": "1.97.1"}
                with mock.patch.object(self.worker, "tool_info", return_value=tool):
                    info = self.worker.cargo_tool_info(selected["path"], {"default_sysroot": str(self.root / "queried-sysroot")})
                self.assertEqual(info["queried_sysroot_cargo"], candidate)
                self.assertEqual(info["actual_producer_identity_complete"], expected_direct)
                if expected_direct:
                    self.assertEqual(info["executing_binary"], selected)
                else:
                    self.assertNotIn("executing_binary", info)

    def test_missing_rust_producer_never_labels_cwd_cargo_as_executing(self):
        self.write("cargo", b"unrelated cwd Cargo\n")
        selected = self.write("selected/bin/cargo", b"selected Cargo\n")
        tool = {**selected, "invoked_path": selected["path"], "version": "cargo 1.97.1", "release": "1.97.1"}
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            with mock.patch.object(self.worker, "tool_info", return_value=tool):
                info = self.worker.cargo_tool_info(selected["path"], {})
        finally:
            os.chdir(previous)
        self.assertFalse(info["actual_producer_identity_complete"])
        self.assertNotIn("executing_binary", info)
        self.assertNotIn("queried_sysroot_cargo", info)

    def test_invalid_original_codegen_values_are_not_erased(self):
        args = ["-C", "embed-bitcode=invalid", "--codegen=save-temps=invalid", "probe.rs"]
        executed, changes = capture.rust_instrumentation(args, True)
        self.assertEqual(executed, args)
        self.assertEqual(changes, [])

    def test_rust_response_is_single_level_and_only_lf_crlf_split_lines(self):
        raw = b"first\r\nsecond\rbare\nvertical\vtab\n" + "unicode\u2028separator".encode() + b"\nlast\r"
        self.assertEqual(capture.rust_response_lines(raw),
                         ["first", "second\rbare", "vertical\vtab", "unicode\u2028separator", "last\r"])
        self.assertEqual(capture.rust_response_lines(b""), [])
        outer = self.write("outer.rsp", b"@inner.rsp\n-Cembed-bitcode=no\n")
        self.write("inner.rsp", b"a-different-source.rs\n")
        args, files = capture.expand_response_files(["@" + outer["path"]], self.root, rust=True)
        self.assertEqual(args, ["@inner.rsp", "-Cembed-bitcode=no"])
        self.assertEqual(files, [outer])
        self.assertEqual(capture.rust_argfile_gap(args)["kind"], "rust_literal_response_argument_unsupported")

    def test_terminator_and_nul_arguments_keep_original_argv_and_no_transformations(self):
        for args, kind in [(["--", "source.rs", "-Cembed-bitcode=no"], "rust_option_terminator_unsupported"),
                           (["-C", "--", "source.rs"], "rust_option_terminator_unsupported"),
                           (["source\0.rs"], "rust_nul_response_argument_unsupported")]:
            with self.subTest(args=args):
                self.assertEqual(capture.rust_argfile_gap(args)["kind"], kind)
                self.assertEqual(capture.rust_instrumentation(args, True), (args, []))

    def test_original_object_edge_uses_exact_bytes_and_no_replay(self):
        output = self.write("original.o", elf())
        event = self.collect([output])
        self.assertEqual(event["capture_errors"], [])
        record = event["saved_cgus"][0]
        extractor = self.worker.rust_payload_extractor(self.session, self.directory)
        verified = extractor["verify_saved_cgu"](record, event)
        self.assertEqual(verified["object"]["sha256"], output["sha256"])
        self.assertEqual(Path(record["bitcode"]["path"]).read_bytes(), b"BC\xc0\xdeauthored-byte-fixture")
        self.assertNotIn("replay_argv", event)
        self.assertFalse(event["units"][0]["post_lto_equivalence_verified"])

    def test_same_named_archive_members_have_distinct_raw_ranges(self):
        output = self.write("original.rlib", archive([("same.o", elf(b"BC\xc0\xdefirst")),
                                                     ("same.o", elf(b"BC\xc0\xdesecond"))]))
        event = self.collect([output])
        self.assertEqual(len(event["saved_cgus"]), 2)
        left, right = event["saved_cgus"]
        self.assertEqual(left["container"]["member"]["name"], right["container"]["member"]["name"])
        self.assertNotEqual(left["edge"]["container_offset"], right["edge"]["container_offset"])
        self.assertNotEqual(left["bitcode"]["sha256"], right["bitcode"]["sha256"])
        for record in event["saved_cgus"]:
            self.worker.rust_payload_extractor(self.session, self.directory)["verify_saved_cgu"](record, event)

    def test_metadata_members_are_retained_resources_not_code(self):
        output = self.write("original.rlib", archive([("lib.rmeta", metadata_elf()), ("body.o", elf())]))
        event = self.collect([output])
        self.assertEqual(len(event["saved_cgus"]), 1)
        self.assertEqual(len(event["rust_native_resources"]), 1)
        self.assertEqual(event["rust_native_resources"][0]["member"]["name"], "lib.rmeta")
        self.assertEqual(event["rust_native_resources"][0]["kind"], "embedded_bitcode_missing")
        self.assertEqual(event["capture_errors"], [])

    def test_missing_duplicate_and_truncated_embedded_edges_are_typed_gaps(self):
        for name, raw, kind in [("duplicate", elf(duplicate=True), "ambiguous_embedded_bitcode"),
                                ("truncated", elf()[:70], "malformed_object"),
                                ("missing", b"original executable; no same-producer edge", "unsupported_object")]:
            with self.subTest(name=name):
                # Each collector owns an exclusive invocation directory.
                self.worker_record["artifact"] = self.session["capture_worker"]["artifact"]
                event, directory = self.event([self.write(name + ".o", raw)]) if name == "duplicate" else (
                    {"id": name, "sources": [self.source], "outputs": [self.write(name + ".o", raw)],
                     "units": [], "frontend": self.session["tools"]["rustc"], "capture_errors": []},
                    self.directory / "units" / name)
                directory.mkdir(parents=True, exist_ok=True)
                self.worker.capture_rust_cgus(event, directory, self.session)
                self.assertEqual(event["rust_cgu_gaps"][0]["kind"], kind)
                self.assertTrue(event["capture_errors"])

    def test_tampered_extractor_snapshot_cannot_choose_its_own_trust(self):
        record = self.session["capture_worker"]["rust_payload_extractor"]
        Path(record["artifact"]["path"]).chmod(0o644)
        Path(record["artifact"]["path"]).write_bytes(b"raise RuntimeError('untrusted')\n")
        record["artifact"] = capture.file_info(Path(record["artifact"]["path"]))
        record["source"] = record["artifact"]
        with self.assertRaisesRegex(self.worker.CaptureError, "independently registered"):
            self.worker.rust_payload_extractor(self.session, self.directory)

    def test_original_response_bytes_and_executed_policy_are_readmitted(self):
        response = self.write("incoming.rsp", (self.source["path"] + "\n-Cembed-bitcode=no\n--sysroot\n/exact/sysroot\n").encode())
        args, files = capture.expand_response_files(["@" + response["path"]], self.root, rust=True)
        executed, changes = capture.rust_instrumentation(args, True)
        event = {"kind": "rustc", "cwd": str(self.root), "argv": ["@" + response["path"]],
            "expanded_argv": args, "response_files": files, "executed_argv": executed, "exit_code": 9,
            "rust_response_files": [{"source": response,
                "artifact": self.write("capture/retained-original.rsp", Path(response["path"]).read_bytes())}],
            "rust_capture": {"policy": capture.RUST_EMBEDDED_POLICY, "applied": True,
                "transformations": changes, "original_command_executed": False,
                "frontend_replay_used": False, "post_lto_equivalence_verified": False, "argfile_gap": None}}
        self.worker.verify_rust_capture_event(event, self.session, self.directory)
        for field in ["executed_argv", "expanded_argv", "response_files", "rust_capture"]:
            bad = copy.deepcopy(event)
            bad[field] = [] if field != "rust_capture" else {}
            with self.assertRaises(self.worker.CaptureError):
                self.worker.verify_rust_capture_event(bad, self.session, self.directory)
        bad = copy.deepcopy(event)
        bad["replay_argv"] = ["other-rustc", "--emit=llvm-ir"]
        with self.assertRaisesRegex(self.worker.CaptureError, "replay"):
            self.worker.verify_rust_capture_event(bad, self.session, self.directory)
        Path(response["path"]).write_text("different incoming source\n")
        self.worker.verify_rust_capture_event(event, self.session, self.directory)
        Path(event["rust_response_files"][0]["artifact"]["path"]).write_text("tampered retained original\n")
        with self.assertRaises(self.worker.CaptureError):
            self.worker.verify_rust_capture_event(event, self.session, self.directory)

    def test_native_failure_forwards_executed_status_and_never_replays(self):
        tool = {**self.session["tools"]["rustc"], "release": "1.97.1", "default_sysroot": "/actual/sysroot"}
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 17)
        with mock.patch.object(self.worker, "tool_info", return_value=tool), \
                mock.patch.object(self.worker.subprocess, "run", side_effect=run), \
                mock.patch.dict(os.environ, {}, clear=True):
            result = self.worker.compiler(self.directory, "rustc", [tool["invoked_path"], self.source["path"], "-Cembed-bitcode=no"])
        self.assertEqual(result, 17)
        self.assertEqual(len(calls), 1)
        event = capture.read_json(next((self.directory / "events").glob("*.json")))
        self.assertEqual(event["exit_code"], 17)
        self.assertFalse(event["rust_capture"]["original_command_executed"])
        self.assertEqual(calls[0][1:], event["executed_argv"])
        self.assertNotIn("replay_argv", event)
        self.assertEqual(event["frontend"]["effective_sysroot"], "/actual/sysroot")

    def test_applied_policy_records_when_executed_argv_remains_exactly_original(self):
        tool = {**self.session["tools"]["rustc"], "release": "1.97.1", "default_sysroot": "/actual/sysroot"}
        args = [self.source["path"], "-C", "embed-bitcode=yes", "-C", "save-temps=yes"]
        with mock.patch.object(self.worker, "tool_info", return_value=tool), \
                mock.patch.object(self.worker.subprocess, "run", return_value=subprocess.CompletedProcess(args, 1)) as call, \
                mock.patch.dict(os.environ, {}, clear=True):
            result = self.worker.compiler(self.directory, "rustc", [tool["invoked_path"], *args])
        event = capture.read_json(next((self.directory / "events").glob("*.json")))
        self.assertEqual(result, 1)
        self.assertTrue(event["rust_capture"]["applied"])
        self.assertTrue(event["rust_capture"]["original_command_executed"])
        self.assertEqual(call.call_args.args[0][1:], event["argv"])

    def test_saved_cgu_bitcode_and_archive_offsets_cannot_be_rewritten(self):
        output = self.write("original.rlib", archive([("body.o", elf())]))
        event = self.collect([output])
        helper = self.worker.rust_payload_extractor(self.session, self.directory)
        for field in ["container_offset", "object_offset", "section_index", "sha256"]:
            bad = copy.deepcopy(event)
            value = bad["saved_cgus"][0]["edge"][field]
            bad["saved_cgus"][0]["edge"][field] = value + 1 if isinstance(value, int) else "0" * 64
            with self.assertRaises(helper["PayloadError"]):
                helper["verify_saved_cgu"](bad["saved_cgus"][0], bad)
        Path(event["saved_cgus"][0]["bitcode"]["path"]).write_bytes(b"BC\xc0\xdeforged")
        with self.assertRaises(helper["PayloadError"]):
            helper["verify_saved_cgu"](event["saved_cgus"][0], event)

    def test_readmission_rejects_dropped_or_duplicated_original_member_edges(self):
        output = self.write("original.rlib", archive([("same.o", elf(b"BC\xc0\xdefirst")),
                                                     ("same.o", elf(b"BC\xc0\xdesecond"))]))
        event = self.collect([output])
        args = [self.source["path"]]
        executed, changes = capture.rust_instrumentation(args, True)
        event.update({"kind": "rustc", "cwd": str(self.root), "argv": args, "expanded_argv": args,
            "response_files": [], "rust_response_files": [], "executed_argv": executed, "exit_code": 0,
            "rust_capture": {"policy": capture.RUST_EMBEDDED_POLICY, "applied": True,
                "transformations": changes, "original_command_executed": False,
                "frontend_replay_used": False, "post_lto_equivalence_verified": False, "argfile_gap": None}})
        self.worker.verify_rust_capture_event(event, self.session, self.directory)
        dropped = copy.deepcopy(event)
        dropped["saved_cgus"].pop()
        dropped["units"].pop()
        with self.assertRaisesRegex(self.worker.CaptureError, "all original embedded"):
            self.worker.verify_rust_capture_event(dropped, self.session, self.directory)
        duplicate = copy.deepcopy(event)
        duplicate["saved_cgus"].append(copy.deepcopy(duplicate["saved_cgus"][0]))
        with self.assertRaisesRegex(self.worker.CaptureError, "repeats"):
            self.worker.verify_rust_capture_event(duplicate, self.session, self.directory)
        duplicate = copy.deepcopy(event)
        duplicate["units"].append(copy.deepcopy(duplicate["units"][0]))
        with self.assertRaisesRegex(self.worker.CaptureError, "duplicates"):
            self.worker.verify_rust_capture_event(duplicate, self.session, self.directory)

    def test_readmission_rederives_missing_members_and_metadata_resources(self):
        output = self.write("original.rlib", archive([("good.o", elf()),
            ("lib.rmeta", metadata_elf()), ("missing.o", b"unsupported original member")]))
        event = self.collect([output])
        args = [self.source["path"]]
        executed, changes = capture.rust_instrumentation(args, True)
        event.update({"kind": "rustc", "cwd": str(self.root), "argv": args, "expanded_argv": args,
            "response_files": [], "rust_response_files": [], "executed_argv": executed, "exit_code": 0,
            "rust_capture": {"policy": capture.RUST_EMBEDDED_POLICY, "applied": True,
                "transformations": changes, "original_command_executed": False,
                "frontend_replay_used": False, "post_lto_equivalence_verified": False, "argfile_gap": None}})
        self.worker.verify_rust_capture_event(event, self.session, self.directory)
        for field in ["rust_native_resources", "rust_cgu_gaps", "capture_errors"]:
            bad = copy.deepcopy(event)
            bad[field] = []
            with self.subTest(field=field), self.assertRaises(self.worker.CaptureError):
                self.worker.verify_rust_capture_event(bad, self.session, self.directory)


class OriginalRustWorkspaceTests(unittest.TestCase):
    def test_required_original_offline_three_crate_workspace_and_response_invocation(self):
        rustc_name = os.environ.get("OCORE_TEST_RUST_CGU_RUSTC")
        cargo_name = os.environ.get("OCORE_TEST_RUST_CGU_CARGO")
        if not rustc_name or not cargo_name:
            self.fail("real Rust CGU qualification requires explicit OCORE_TEST_RUST_CGU_RUSTC and OCORE_TEST_RUST_CGU_CARGO; no fixture fallback")
        rustc, cargo = Path(rustc_name).resolve(), Path(cargo_name).resolve()
        info = capture.tool_info(str(rustc), "rustc")
        self.assertEqual((info["release"], info["llvm_version"]), ("1.97.1", "22.1.6"))
        self.assertEqual(info["executing_binary"], capture.file_info(rustc))
        self.assertTrue(info["actual_producer_identity_complete"])
        retained = Path(os.environ.get("OCORE_TEST_CAPTURE_RUST_CGU_OUTPUT_DIR", ROOT / "target/ocore-rust-cgu-capture-real")).resolve()
        retained.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix="original-workspace-", dir=retained))
        source, build, directory = root / "source", root / "build", root / "capture"
        for path in [source, build, directory]:
            path.mkdir()
        files = {
            "Cargo.toml": '[workspace]\nmembers=["alpha","beta","app"]\nresolver="2"\n',
            "alpha/Cargo.toml": '[package]\nname="alpha"\nversion="0.1.0"\nedition="2021"\n',
            "alpha/src/lib.rs": '#![no_std]\npub fn alpha(x:u64)->u64{x.wrapping_mul(17).wrapping_add(3)}\n',
            "beta/Cargo.toml": '[package]\nname="beta"\nversion="0.1.0"\nedition="2021"\nbuild="build.rs"\n',
            "beta/build.rs": 'fn main(){println!("cargo:rustc-env=LOCAL_BETA=29");}\n',
            "beta/src/lib.rs": '#![no_std]\npub fn beta(x:u64)->u64{x.wrapping_add(29)}\n',
            "app/Cargo.toml": '[package]\nname="app"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nalpha={path="../alpha"}\nbeta={path="../beta"}\n',
            "app/src/main.rs": 'fn main(){println!("{}",beta::beta(alpha::alpha(7)));}\n'}
        for name, raw in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(raw)
        tools = {name: capture.tool_info(str(SDK / program), program) for name, program in
                 [("clang", "clang"), ("cxx", "clang++"), ("nm", "llvm-nm"), ("llvm_dis", "llvm-dis")]}
        self.assertTrue(all(tool["llvm_version"] == "22.1.6" for tool in tools.values()))
        tools["rustc"] = info
        tools["cargo"] = capture.cargo_tool_info(str(cargo), info)
        self.assertEqual(tools["cargo"]["executing_binary"], capture.file_info(cargo))
        self.assertTrue(tools["cargo"]["actual_producer_identity_complete"])
        worker = capture.snapshot_worker(directory, capture.RUST_EMBEDDED_POLICY)
        recipe = {"toolchain": {"llvm_version": "22.1.6", "rustc_release": "1.97.1",
                               "rust_capture_policy": capture.RUST_EMBEDDED_POLICY}}
        session = {"capture_worker": worker, "recipe": recipe, "tools": tools, "build_steps": [],
                   "source": {"path": str(source)}}
        capture.write_json(directory / "session.json", session)
        observer = load(OBSERVER)
        self.assertEqual(capture.file_info(OBSERVER)["sha256"], capture.REGISTERED_CARGO_OBSERVER_SHA256)
        observer.prepare(root / "observer", cargo, directory, graph_query=False,
                         expected_worker_sha256=capture.REGISTERED_CARGO_OBSERVER_SHA256)
        environment = dict(os.environ)
        environment.pop(capture.CARGO_PARENT_VARIABLE, None)
        environment.update({"RUSTC": str(rustc), "RUSTC_WRAPPER": str(directory / "wrappers/rustc-wrapper"),
            "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
            "RUSTFLAGS": "--sysroot " + info["default_sysroot"] + " -Cembed-bitcode=no -Ccodegen-units=2"})
        command = [str(root / "observer/cargo"), "build", "--offline", "--jobs", "3", "--target-dir", str(build)]
        result = subprocess.run(command, cwd=source, env=environment, capture_output=True)
        (root / "original-cargo.stdout").write_bytes(result.stdout)
        (root / "original-cargo.stderr").write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(subprocess.check_output([str(build / "debug/app")]), b"151\n")
        observer_receipt = observer.verify(root / "observer", capture.REGISTERED_CARGO_OBSERVER_SHA256)
        observer_session = capture.read_json(root / "observer/session.json")
        self.assertEqual(observer_session["original_cargo"], capture.file_info(cargo))
        events = [capture.read_json(path) for path in (directory / "events").glob("*.json")]
        applied = [event for event in events if event.get("rust_capture", {}).get("applied")]
        self.assertGreaterEqual(len(applied), 4)  # alpha, beta, build script, app
        library = [event for event in applied if event.get("saved_cgus")]
        self.assertGreaterEqual(len(library), 2)
        concurrent = [(left["id"], right["id"]) for index, left in enumerate(applied) for right in applied[index + 1:]
                      if max(left["started_ns"], right["started_ns"]) < min(left["finished_ns"], right["finished_ns"])]
        self.assertTrue(concurrent, "jobs=3 must actually observe concurrent original compiler children")
        helper = capture.rust_payload_extractor(session, directory)
        byte_edges = []
        for event in applied:
            self.assertEqual(event["exit_code"], 0)
            self.assertNotIn("replay_argv", event)
            self.assertEqual(event["frontend"]["effective_sysroot"], info["default_sysroot"])
            self.assertIsNotNone(event.get("cargo_parent_invocation_id"))
            capture.verify_rust_capture_event(event, session, directory)
            for record in event.get("saved_cgus", []):
                byte_edges.append(helper["verify_saved_cgu"](record, event))
        self.assertTrue(all(not event["capture_errors"] for event in library))
        self.assertTrue(any(event.get("rust_cgu_gaps") for event in applied))
        # A separate original same-profile response-file compile is retained,
        # without inventing Cargo parentage for a directly invoked compiler.
        unicode_source = source / "alpha/src/literal\u2028source.rs"
        unicode_source.write_bytes((source / "alpha/src/lib.rs").read_bytes())
        response = root / "original-response.rsp"
        response.write_text(str(unicode_source) + "\n--crate-name\nresponse_probe\n--crate-type\nrlib\n"
                            "--out-dir\n" + str(build / "response") + "\n--sysroot\n" + info["default_sysroot"] +
                            "\n-Cembed-bitcode=no\n-Csave-temps=no\n")
        (build / "response").mkdir()
        response_command = [str(directory / "wrappers/rustc-wrapper"), str(rustc), "@" + str(response)]
        response_result = subprocess.run(response_command, cwd=source, env=environment, capture_output=True)
        self.assertEqual(response_result.returncode, 0, response_result.stderr.decode(errors="replace"))
        response_event = next(capture.read_json(path) for path in (directory / "events").glob("*.json")
                              if capture.read_json(path).get("argv") == ["@" + str(response)])
        self.assertEqual(response_event["response_files"], [capture.file_info(response)])
        self.assertEqual(response_event["frontend"]["sysroot_source"], "explicit-argv")
        self.assertTrue(response_event["saved_cgus"])
        capture.verify_rust_capture_event(response_event, session, directory)
        # Rust expands outer lines verbatim; @inner is not a recursive include.
        # Compare actual original and wrapper statuses, rather than the mocked
        # parser alone, so instrumentation cannot create a successful compile.
        nested_output = build / "nested-control"
        nested_output.mkdir()
        inner, outer = root / "inner.rsp", root / "outer.rsp"
        inner.write_text(str(source / "alpha/src/lib.rs") + "\n--crate-type\nrlib\n--out-dir\n" + str(nested_output) + "\n")
        outer.write_text("@" + str(inner) + "\n")
        nested_args = ["@" + str(outer)]
        original_nested = subprocess.run([str(rustc), *nested_args], cwd=source, env=environment, capture_output=True)
        wrapped_nested = subprocess.run([str(directory / "wrappers/rustc-wrapper"), str(rustc), *nested_args],
                                       cwd=source, env=environment, capture_output=True)
        self.assertNotEqual(original_nested.returncode, 0)
        self.assertEqual(wrapped_nested.returncode, original_nested.returncode)
        self.assertEqual(list(nested_output.iterdir()), [])
        nested_event = next(capture.read_json(path) for path in (directory / "events").glob("*.json")
                            if capture.read_json(path).get("argv") == nested_args)
        self.assertTrue(nested_event["rust_capture"]["original_command_executed"])
        self.assertFalse(nested_event["rust_capture"]["applied"])
        self.assertEqual(nested_event["rust_capture"]["argfile_gap"]["kind"], "rust_literal_response_argument_unsupported")
        capture.verify_rust_capture_event(nested_event, session, directory)
        # Stateful shell argfiles remain explicitly unsupported and forward a
        # real successful original command without claiming captured IR.
        shell_output = build / "shell-control"
        shell_output.mkdir()
        shell = root / "shell.rsp"
        shell.write_text(str(source / "alpha/src/lib.rs") + " --crate-type rlib --crate-name shell_probe --out-dir " + str(shell_output))
        shell_args = ["-Zshell-argfiles", "@shell:" + str(shell)]
        shell_environment = {**environment, "RUSTC_BOOTSTRAP": "1"}
        original_shell = subprocess.run([str(rustc), *shell_args], cwd=source, env=shell_environment, capture_output=True)
        wrapped_shell = subprocess.run([str(directory / "wrappers/rustc-wrapper"), str(rustc), *shell_args],
                                      cwd=source, env=shell_environment, capture_output=True)
        self.assertEqual(original_shell.returncode, 0, original_shell.stderr.decode(errors="replace"))
        self.assertEqual(wrapped_shell.returncode, original_shell.returncode)
        shell_event = next(capture.read_json(path) for path in (directory / "events").glob("*.json")
                           if capture.read_json(path).get("argv") == shell_args)
        self.assertTrue(shell_event["rust_capture"]["original_command_executed"])
        self.assertFalse(shell_event["rust_capture"]["applied"])
        self.assertTrue(shell_event["capture_errors"])
        self.assertEqual(shell_event["units"], [])
        capture.verify_rust_capture_event(shell_event, session, directory)
        # The terminator is a valid original compiler boundary. This bounded
        # profile forwards it unchanged instead of appending capture options as
        # free inputs or guessing whether -- was consumed as an option value.
        terminator_output = build / "terminator-control"
        terminator_output.mkdir()
        terminator_args = ["--crate-type", "rlib", "--crate-name", "terminator_probe", "--out-dir",
                           str(terminator_output), "--", str(source / "alpha/src/lib.rs")]
        original_terminator = subprocess.run([str(rustc), *terminator_args], cwd=source, env=environment, capture_output=True)
        wrapped_terminator = subprocess.run([str(directory / "wrappers/rustc-wrapper"), str(rustc), *terminator_args],
                                           cwd=source, env=environment, capture_output=True)
        self.assertEqual(original_terminator.returncode, 0, original_terminator.stderr.decode(errors="replace"))
        self.assertEqual(wrapped_terminator.returncode, original_terminator.returncode)
        terminator_event = next(capture.read_json(path) for path in (directory / "events").glob("*.json")
                                if capture.read_json(path).get("argv") == terminator_args)
        self.assertEqual(terminator_event["executed_argv"], terminator_args)
        self.assertTrue(terminator_event["rust_capture"]["original_command_executed"])
        self.assertFalse(terminator_event["rust_capture"]["applied"])
        self.assertEqual(terminator_event["rust_capture"]["argfile_gap"]["kind"], "rust_option_terminator_unsupported")
        self.assertEqual(terminator_event["units"], [])
        capture.verify_rust_capture_event(terminator_event, session, directory)
        membership = capture.runtime_output_membership(
            {"coverage": {"required_outputs": ["terminator-control/libterminator_probe.rlib"]}},
            None, [terminator_event], build)
        self.assertEqual(membership["issues"], [])
        self.assertIn(terminator_event["id"], membership["contributing_invocation_ids"])
        # read_to_string accepts NUL, but OS argv cannot. Preserve the original
        # @ locator so the actual Rust driver, rather than Python, diagnoses it.
        nul_response = root / "nul.rsp"
        nul_response.write_bytes(b"invalid\0source.rs\n")
        nul_args = ["@" + str(nul_response)]
        original_nul = subprocess.run([str(rustc), *nul_args], cwd=source, env=environment, capture_output=True)
        wrapped_nul = subprocess.run([str(directory / "wrappers/rustc-wrapper"), str(rustc), *nul_args],
                                     cwd=source, env=environment, capture_output=True)
        self.assertNotEqual(original_nul.returncode, 0)
        self.assertEqual(wrapped_nul.returncode, original_nul.returncode)
        nul_event = next(capture.read_json(path) for path in (directory / "events").glob("*.json")
                         if capture.read_json(path).get("argv") == nul_args)
        self.assertEqual(nul_event["executed_argv"], nul_args)
        self.assertTrue(nul_event["rust_capture"]["original_command_executed"])
        self.assertFalse(nul_event["rust_capture"]["applied"])
        self.assertEqual(nul_event["rust_capture"]["argfile_gap"]["kind"], "rust_nul_response_argument_unsupported")
        self.assertEqual(nul_event["sources"], [])
        self.assertEqual(nul_event["link_inputs"], capture.observed_link_inputs([], source))
        self.assertEqual(nul_event["units"], [])
        capture.verify_rust_capture_event(nul_event, session, directory)
        receipt = {"schema": "ocore-rust-embedded-cgu-real-probe-v1", "worker": worker,
            "observer": capture.file_info(OBSERVER), "test": capture.file_info(Path(__file__)),
            "tools": tools, "command": command, "observed_executed_native_status": result.returncode,
            "events": [capture.file_info(path) for path in sorted((directory / "events").glob("*.json"))],
            "observer_verification": observer_receipt, "original_embedded_byte_edges": byte_edges,
            "observed_concurrent_children": concurrent,
            "response_file": capture.file_info(response), "response_event": response_event,
            "original_nested_status": original_nested.returncode, "wrapped_nested_status": wrapped_nested.returncode,
            "nested_event": nested_event, "original_shell_status": original_shell.returncode,
            "wrapped_shell_status": wrapped_shell.returncode, "shell_event": shell_event,
            "original_terminator_status": original_terminator.returncode,
            "wrapped_terminator_status": wrapped_terminator.returncode, "terminator_event": terminator_event,
            "terminator_runtime_output_membership": membership,
            "original_nul_status": original_nul.returncode, "wrapped_nul_status": wrapped_nul.returncode,
            "nul_event": nul_event,
            "gaps": [gap for event in applied for gap in event.get("rust_cgu_gaps", [])],
            "installed_sysroot_provider_ownership_complete": False, "source_production_inventory_complete": False,
            "dependency_closure_complete": False, "ocore_lowering_complete": False,
            "native_execution_qualified": False, "runtime_complete": False,
            "scope": "original pinned three-local-crate Cargo/Rust ELF embedded-byte plumbing only"}
        capture.write_json(root / "receipt.json", receipt)


if __name__ == "__main__":
    unittest.main()
