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

    def check(self, raw=None):
        self.report_path.write_text(json.dumps(self.raw if raw is None else raw))
        return matrix.checked_result(self.report_path, self.profile, self.compiler_file["sha256"], "riscv64-unknown-none")

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
