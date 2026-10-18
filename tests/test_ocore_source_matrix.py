"""Synthetic rejection receipts exercise matrix integrity, not native compilation.

Real compiler/object/execution qualification belongs to the retained source-build
audits. These tests check omissions, tampering and diagnostic exit semantics.
"""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import check_ocore_source_matrix as matrix


class SourceMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.compiler = self.root / "compiler"
        self.compiler.write_text("#!/bin/sh\nexit 42\n")
        self.compiler.chmod(0o755)
        self.compiler_file = matrix.audit.file_info(self.compiler)
        self.units = []
        for name in ("first", "second"):
            source = self.root / (name + ".c")
            source.write_text("int " + name + "(void);\n")
            ir = self.root / (name + ".ll")
            ir.write_text('target triple = "riscv64-unknown-linux-gnu"\n')
            self.units.append({"id": name, "source": matrix.audit.file_info(source),
                               "ir": {**matrix.audit.file_info(ir), "target_triple": "riscv64-unknown-linux-gnu",
                                      "data_layout": "e-p:64:64"}})
        self.capture = self.root / "capture.json"
        self.capture_data = {"schema": "ocore-runtime-capture-v1", "capture_complete": False,
                             "source": {"revision": "original-source-pin"}, "units": self.units,
                             "build_steps": [{"name": "build-original", "exit_code": 0, "started_ns": 1, "finished_ns": 5}],
                             "invocations": [{"build_step": {"index": 0, "name": "build-original"},
                                              "started_ns": 2, "finished_ns": 4, "units": self.units}]}
        self.capture.write_text(json.dumps(self.capture_data))
        self.manifest = self.root / "matrix.json"
        self.profile_entry = {"name": "original", "language": "any-implementation-language",
                              "capture": "capture.json", "step": "build-original"}
        self.write_manifest([self.profile_entry])
        self.profile = matrix.load_profiles(self.manifest)[0]
        self.log = self.root / "compiler.stderr"
        self.log.write_text("unsupported construct\n")
        self.raw = self.result(self.compiler)
        self.report_path = self.root / "report.json"

    def write_manifest(self, profiles):
        self.manifest.write_text(json.dumps({"schema": "ocore-source-audit-matrix-v1", "profiles": profiles}))

    def result(self, compiler):
        tool = matrix.audit.file_info(compiler)
        return {"schema": "ocore-runtime-import-diagnostics-v1", "audit_complete": True, "issues": [],
                "target": "riscv64-unknown-none", "source_capture": matrix.audit.file_info(self.capture),
                "selection": {"mode": "recorded-build-step", "step": self.profile["selected_step"],
                              "for_runtime_acceptance": False},
                "tools": {"ocorec": tool, "snapshot": tool}, "selected_unit_count": 2,
                "provenance_units": copy.deepcopy(self.units), "provenance_unit_count": 2,
                "units": [{"id": u["id"], "source": u["source"], "input": u["ir"], "status": "failed",
                           "stages": [{"stage": "import", "argv": [str(compiler), u["ir"]["path"]], "exit_code": 1,
                                       "stdout": matrix.audit.file_info(self.log), "stderr": matrix.audit.file_info(self.log)}],
                           "failed_stage": "import", "first_diagnostic": {"stage": "types", "message": "unsupported construct"}}
                          for u in self.units],
                "imported_unit_count": 0, "independently_verified_unit_count": 0, "verified_object_count": 0,
                "first_failure_groups": [{"stage": "import", "diagnostic_stage": "types", "message": "unsupported construct",
                                          "unit_ids": ["first", "second"], "count": 2}],
                "dependency_closure_complete": False, "native_execution_qualified": False, "runtime_complete": False}

    def check(self, raw=None, decoder_sha256=None):
        self.report_path.write_text(json.dumps(self.raw if raw is None else raw))
        return matrix.checked_result(self.report_path, self.profile, self.compiler_file["sha256"], "riscv64-unknown-none", decoder_sha256)

    def bitcode_fixture(self, magic=b"BC\xc0\xde"):
        # Synthetic bytes and receipts exercise the matrix's provenance checks;
        # they are never passed off as a real decoded/compiler-qualified unit.
        original = self.root / "original.bc"
        original.write_bytes(magic + b"synthetic whole bitcode fixture")
        self.units[0]["ir"] = {**matrix.audit.file_info(original),
                               "target_triple": "riscv64-unknown-linux-gnu",
                               "data_layout": "e-p:64:64"}
        self.capture.write_text(json.dumps(self.capture_data))
        self.profile = matrix.load_profiles(self.manifest)[0]
        self.decoder = self.root / "llvm-dis"
        self.decoder.write_text("#!/bin/sh\nexit 44\n")
        self.decoder.chmod(0o755)
        snapshot = self.root / "decoder-snapshot"
        snapshot.write_bytes(self.decoder.read_bytes())
        version_stdout = self.root / "decoder-version.stdout"
        version_stdout.write_text("Debian LLVM version 22.1.6\n")
        version_stderr = self.root / "decoder-version.stderr"
        version_stderr.write_text("")
        decoded = self.root / "decoded.ll"
        decoded.write_text('target triple = "riscv64-unknown-linux-gnu"\n'
                           'target datalayout = "e-p:64:64"\n'
                           'define i64 @whole_fixture(i64 %x) { ret i64 %x }\n')
        decode_stderr = self.root / "decode.stderr"
        decode_stderr.write_text("")
        self.raw = self.result(self.compiler)
        decoder = {**matrix.audit.file_info(self.decoder),
                   "snapshot": matrix.audit.file_info(snapshot), "llvm_version": "22.1.6",
                   "version_exit_code": 0, "version_argv": [str(snapshot), "--version"],
                   "version_stdout": matrix.audit.file_info(version_stdout),
                   "version_stderr": matrix.audit.file_info(version_stderr)}
        self.raw["tools"]["llvm_dis"] = decoder
        self.raw["units"][0].update(
            llvm_decode={"argv": [str(snapshot), str(original), "-o", "-"],
                         "input": matrix.audit.file_info(original),
                         "decoder": copy.deepcopy(decoder["snapshot"]), "exit_code": 0,
                         "stdout": matrix.audit.file_info(decoded),
                         "stderr": matrix.audit.file_info(decode_stderr)},
            decoded_llvm=matrix.audit.file_info(decoded))
        return decoder["sha256"]

    def mocked_bitcode_child(self, argv, **kwargs):
        destination = Path(argv[argv.index("--output") + 1])
        destination.mkdir()
        compiler = Path(argv[argv.index("--ocorec") + 1])
        frozen_decoder = Path(argv[argv.index("--llvm-dis") + 1])
        self.assertEqual(kwargs["stdin"], matrix.subprocess.DEVNULL)
        self.assertEqual(frozen_decoder, destination.parent / "tools/llvm-dis")
        self.assertEqual(frozen_decoder.read_bytes(), self.decoder.read_bytes())
        raw = copy.deepcopy(self.raw)
        raw["tools"].update(ocorec=matrix.audit.file_info(compiler), snapshot=matrix.audit.file_info(compiler))
        decoder = raw["tools"]["llvm_dis"]
        decoder.update(matrix.audit.file_info(frozen_decoder))
        decoder["snapshot"] = matrix.audit.file_info(frozen_decoder)
        decoder["version_argv"] = [str(frozen_decoder), "--version"]
        for unit in raw["units"]:
            unit["stages"][0]["argv"][0] = str(compiler)
            if "llvm_decode" in unit:
                unit["llvm_decode"]["argv"][0] = str(frozen_decoder)
                unit["llvm_decode"]["decoder"] = decoder["snapshot"]
        (destination / "report.json").write_text(json.dumps(raw))
        return matrix.subprocess.CompletedProcess(argv, 1)

    def test_raw_and_wrapper_bitcode_keep_original_input_and_decoder_provenance(self):
        for magic in (b"BC\xc0\xde", b"\xde\xc0\x17\x0b"):
            with self.subTest(magic=magic):
                decoder_sha256 = self.bitcode_fixture(magic)
                checked = self.check(decoder_sha256=decoder_sha256)
                self.assertTrue(checked["audit_complete"])
                self.assertFalse(checked["all_units_lowered"])
                self.assertEqual(checked["attempted_unit_ids"], ["first", "second"])
                self.assertEqual(self.raw["units"][0]["stages"][0]["argv"][1],
                                 self.units[0]["ir"]["path"])

    def test_bitcode_requires_the_frozen_decoder_and_complete_decode_record(self):
        digest = self.bitcode_fixture()
        with self.assertRaisesRegex(ValueError, "not frozen"):
            self.check()
        raw = copy.deepcopy(self.raw)
        raw["tools"].pop("llvm_dis")
        with self.assertRaisesRegex(ValueError, "decoder presence"):
            self.check(raw, digest)
        for key in ("llvm_decode", "decoded_llvm"):
            raw = copy.deepcopy(self.raw)
            raw["units"][0].pop(key)
            with self.subTest(key=key), self.assertRaises((KeyError, ValueError)):
                self.check(raw, digest)

    def test_decode_input_argv_and_decoder_substitution_are_rejected(self):
        digest = self.bitcode_fixture()
        for mutate in (
                lambda decode: decode["argv"].__setitem__(1, self.units[1]["ir"]["path"]),
                lambda decode: decode["argv"].append("--filtered"),
                lambda decode: decode["input"].update(sha256="0" * 64),
                lambda decode: decode["decoder"].update(sha256="0" * 64),
                lambda decode: decode.update(exit_code=1)):
            raw = copy.deepcopy(self.raw)
            mutate(raw["units"][0]["llvm_decode"])
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "bitcode"):
                self.check(raw, digest)

    def test_decoded_target_contract_cannot_be_relabelled_with_matching_hashes(self):
        digest = self.bitcode_fixture()
        decoded = Path(self.raw["units"][0]["decoded_llvm"]["path"])
        original = decoded.read_text()
        for old, changed in (("riscv64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"),
                             ("e-p:64:64", "e-p:32:32")):
            decoded.write_text(original.replace(old, changed))
            raw = copy.deepcopy(self.raw)
            record = matrix.audit.file_info(decoded)
            raw["units"][0]["decoded_llvm"] = record
            raw["units"][0]["llvm_decode"]["stdout"] = record
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "target contract"):
                self.check(raw, digest)
        decoded.write_text(original)

    def test_import_must_consume_original_bitcode_even_after_successful_decode(self):
        digest = self.bitcode_fixture()
        raw = copy.deepcopy(self.raw)
        raw["units"][0]["stages"][0]["argv"][1] = raw["units"][0]["decoded_llvm"]["path"]
        with self.assertRaisesRegex(ValueError, "complete captured LLVM"):
            self.check(raw, digest)

    def test_decoder_bytes_version_and_decode_logs_are_independently_bound(self):
        digest = self.bitcode_fixture()
        decoder = self.raw["tools"]["llvm_dis"]
        records = [decoder, decoder["snapshot"], decoder["version_stdout"], decoder["version_stderr"],
                   self.raw["units"][0]["llvm_decode"]["stdout"],
                   self.raw["units"][0]["llvm_decode"]["stderr"]]
        for record in records:
            path = Path(record["path"])
            original = path.read_bytes()
            path.write_bytes(original + b"tampered")
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "artifact changed"):
                self.check(decoder_sha256=digest)
            path.write_bytes(original)
        version = Path(decoder["version_stdout"]["path"])
        version.write_text("LLVM version 22.1.7\n")
        raw = copy.deepcopy(self.raw)
        raw["tools"]["llvm_dis"]["version_stdout"] = matrix.audit.file_info(version)
        with self.assertRaisesRegex(ValueError, "pinned LLVM version"):
            self.check(raw, digest)

    def test_exact_decoder_version_accepts_stderr_and_rejects_duplicate_or_mixed_reports(self):
        digest = self.bitcode_fixture()
        decoder = self.raw["tools"]["llvm_dis"]
        stdout = Path(decoder["version_stdout"]["path"])
        stderr = Path(decoder["version_stderr"]["path"])
        for out, err, accepted in (("", "LLVM version 22.1.6\n", True),
                                   ("LLVM version 22.1.6\n", "LLVM version 22.1.6\n", False),
                                   ("LLVM version 22.1.6\n", "LLVM version 22.1.7\n", False),
                                   ("LLVM version 22.1.60\n", "", False)):
            stdout.write_text(out)
            stderr.write_text(err)
            raw = copy.deepcopy(self.raw)
            raw["tools"]["llvm_dis"].update(version_stdout=matrix.audit.file_info(stdout),
                                             version_stderr=matrix.audit.file_info(stderr))
            with self.subTest(stdout=out, stderr=err):
                if accepted:
                    self.assertTrue(self.check(raw, digest)["audit_complete"])
                else:
                    with self.assertRaisesRegex(ValueError, "pinned LLVM version"):
                        self.check(raw, digest)

    def test_textual_ir_cannot_forge_a_bitcode_decode_stage(self):
        self.raw["units"][0].update(llvm_decode={}, decoded_llvm={})
        with self.assertRaisesRegex(ValueError, "forged decode"):
            self.check()

    def test_cli_freezes_explicit_decoder_and_forwards_only_its_snapshot(self):
        self.bitcode_fixture()
        output = self.root / "bitcode-complete"
        with patch.object(matrix.subprocess, "run", side_effect=self.mocked_bitcode_child) as child:
            code = matrix.main([str(self.manifest), "--ocorec", str(self.compiler),
                                "--llvm-dis", str(self.decoder), "--jobs", "1", "--output", str(output)])
        self.assertEqual(code, 0)
        child.assert_called_once()
        report = json.loads((output / "report.json").read_text())
        self.assertTrue(report["audit_complete"])
        self.assertEqual(report["llvm_dis"]["snapshot"]["path"], str(output / "tools/llvm-dis"))
        self.assertEqual(report["llvm_dis"]["sha256"], matrix.audit.file_info(self.decoder)["sha256"])
        self.assertFalse(report["all_units_lowered"])

    def test_cli_rejects_missing_decoder_before_launching_diagnostics(self):
        self.bitcode_fixture()
        with patch.object(matrix.subprocess, "run") as child:
            code = matrix.main([str(self.manifest), "--ocorec", str(self.compiler),
                                "--llvm-dis", str(self.root / "absent-decoder"),
                                "--output", str(self.root / "missing-decoder")])
        self.assertEqual(code, 2)
        child.assert_not_called()

    def test_cli_rechecks_original_decoder_after_child_finishes(self):
        self.bitcode_fixture()
        output = self.root / "changed-decoder"
        def child(argv, **kwargs):
            result = self.mocked_bitcode_child(argv, **kwargs)
            self.decoder.write_text("#!/bin/sh\nexit 45\n")
            return result
        with patch.object(matrix.subprocess, "run", side_effect=child):
            code = matrix.main([str(self.manifest), "--ocorec", str(self.compiler),
                                "--llvm-dis", str(self.decoder), "--output", str(output)])
        self.assertEqual(code, 2)
        report = json.loads((output / "report.json").read_text())
        self.assertFalse(report["audit_complete"])
        self.assertIn("artifact changed", report["issues"][-1]["error"])

    def test_complete_diagnostics_preserve_every_failed_unit_without_claiming_support(self):
        checked = self.check()
        self.assertTrue(checked["audit_complete"])
        self.assertEqual(checked["attempted_unit_ids"], ["first", "second"])
        self.assertFalse(checked["all_units_lowered"])
        self.assertFalse(checked["runtime_complete"])

    def test_missing_or_duplicated_selected_unit_is_rejected(self):
        for units in (self.raw["units"][:1], [self.raw["units"][0]] * 2):
            raw = copy.deepcopy(self.raw)
            raw["units"] = units
            with self.subTest(units=[u["id"] for u in units]), self.assertRaisesRegex(ValueError, "omitted, duplicated"):
                self.check(raw)

    def test_provenance_omission_is_rejected_even_with_selected_units_present(self):
        self.raw["provenance_units"].pop()
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.check()

    def test_changed_original_input_or_log_is_rejected(self):
        for path in (Path(self.units[0]["ir"]["path"]), self.log):
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, "artifact changed"):
                self.check()
            path.write_bytes(original)

    def test_wrong_compiler_and_filtered_import_path_are_rejected(self):
        changed = copy.deepcopy(self.raw)
        changed["tools"]["snapshot"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            self.check(changed)
        changed = copy.deepcopy(self.raw)
        changed["units"][0]["stages"][0]["argv"][1] = self.units[1]["ir"]["path"]
        with self.assertRaisesRegex(ValueError, "complete captured LLVM"):
            self.check(changed)

    def test_failure_group_forgery_and_runtime_qualification_are_rejected(self):
        for mutate in (lambda raw: raw["first_failure_groups"][0].update(count=1),
                       lambda raw: raw["first_failure_groups"].append(copy.deepcopy(raw["first_failure_groups"][0])),
                       lambda raw: raw.update(runtime_complete=True)):
            raw = copy.deepcopy(self.raw)
            mutate(raw)
            with self.subTest(raw=raw["runtime_complete"]), self.assertRaises(ValueError):
                self.check(raw)

    def test_manifest_rejects_duplicate_names_and_directory_escape(self):
        for entries in ([self.profile_entry, self.profile_entry], [{**self.profile_entry, "name": "../escape"}]):
            self.write_manifest(entries)
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                matrix.load_profiles(self.manifest)

    def test_capture_inventory_must_match_complete_invocation_journal(self):
        self.capture_data["units"] = self.units[:1]
        self.capture.write_text(json.dumps(self.capture_data))
        with self.assertRaisesRegex(ValueError, "inventory"):
            matrix.load_profiles(self.manifest)

    def test_cli_accepts_completed_rejections_and_continues_after_independent_failure(self):
        for fail_first in (False, True):
            entries = [self.profile_entry]
            if fail_first:
                entries.insert(0, {**self.profile_entry, "name": "broken"})
            self.write_manifest(entries)
            output = self.root / ("with-failure" if fail_first else "completed-rejections")

            def child(argv, **kwargs):
                destination = Path(argv[argv.index("--output") + 1])
                self.assertEqual(kwargs["stdin"], matrix.subprocess.DEVNULL)
                if destination.name == "broken":
                    return matrix.subprocess.CompletedProcess(argv, 2)
                destination.mkdir()
                compiler = Path(argv[argv.index("--ocorec") + 1])
                self.assertEqual(compiler, output / "tools/ocorec")
                (destination / "report.json").write_text(json.dumps(self.result(compiler)))
                return matrix.subprocess.CompletedProcess(argv, 1)

            with patch.object(matrix.subprocess, "run", side_effect=child):
                code = matrix.main([str(self.manifest), "--ocorec", str(self.compiler), "--jobs", "1", "--output", str(output)])
            self.assertEqual(code, 2 if fail_first else 0)
            report = json.loads((output / "report.json").read_text())
            self.assertEqual([p["name"] for p in report["profiles"]], ["original"])
            self.assertEqual(report["audit_complete"], not fail_first)
            self.assertFalse(report["all_units_lowered"])
            self.assertFalse(report["runtime_complete"])

    def test_cli_records_a_changed_compiler_in_the_durable_report(self):
        output = self.root / "changed-compiler"

        def child(argv, **kwargs):
            destination = Path(argv[argv.index("--output") + 1])
            destination.mkdir()
            snapshot = Path(argv[argv.index("--ocorec") + 1])
            (destination / "report.json").write_text(json.dumps(self.result(snapshot)))
            self.compiler.write_text("#!/bin/sh\nexit 43\n")
            return matrix.subprocess.CompletedProcess(argv, 1)

        with patch.object(matrix.subprocess, "run", side_effect=child):
            code = matrix.main([str(self.manifest), "--ocorec", str(self.compiler), "--output", str(output)])
        self.assertEqual(code, 2)
        report = json.loads((output / "report.json").read_text())
        self.assertFalse(report["audit_complete"])
        self.assertFalse(report["all_units_lowered"])
        self.assertIn("artifact changed", report["issues"][0]["error"])


if __name__ == "__main__":
    unittest.main()
