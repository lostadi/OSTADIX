"""Bitcode audit plumbing; authored decoder fixtures claim no LLVM semantics."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_import_checker", ROOT / "scripts/check_ocore_runtime_imports.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
TEXT = 'target datalayout = "e-p:64:64"\ntarget triple = "riscv64-unknown-linux-gnu"\n'


class RuntimeImportBitcodeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def executable(self, name, text):
        path = self.root / name
        path.write_text('#!/usr/bin/env python3\n' + text)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def decoder(self, version="22.1.6", failure=False):
        return self.executable("decoder", 'import sys\nif "--version" in sys.argv:\n print("LLVM version ' + version + '");sys.exit(0)\n' +
                               ('print("authored decoder failure",file=sys.stderr);sys.exit(9)\n' if failure else 'sys.stdout.write(' + repr(TEXT) + ')\n'))

    def unit(self, raw):
        path = self.root / "original.bc"
        path.write_bytes(raw)
        return {"id":"original-cgu", "ir":{**checker.file_info(path), "target_triple":"riscv64-unknown-linux-gnu", "data_layout":"e-p:64:64"}}

    def selected_decoder(self, **kwargs):
        tools = self.root / "tools"
        tools.mkdir()
        return checker.snapshot_llvm_decoder(self.decoder(**kwargs), tools)

    def test_raw_and_wrapped_bitcode_keep_original_compiler_input_and_semantic_stages(self):
        decoder = self.selected_decoder()
        compiler = self.executable("compiler", 'import sys\nprint("authored stop before import",file=sys.stderr)\nsys.exit(17)\n')
        for index, magic in enumerate((b"BC\xc0\xde", b"\xde\xc0\x17\x0b")):
            unit = self.unit(magic+b"authored-bitcode")
            result = checker.check_unit(unit, self.root / ("unit"+str(index)), compiler, "riscv64-unknown-none", [], decoder)
            self.assertEqual(result["failed_stage"], "import")
            self.assertEqual([stage["stage"] for stage in result["stages"]], ["import"])
            self.assertEqual(result["stages"][0]["argv"][1], unit["ir"]["path"])
            self.assertEqual(result["llvm_decode"]["input"]["sha256"], unit["ir"]["sha256"])
            self.assertEqual(Path(result["decoded_llvm"]["path"]).read_text(), TEXT)
            self.assertEqual(result["llvm_decode"]["decoder"], decoder["snapshot"])

    def test_wrong_version_and_changed_decoder_are_rejected_before_import(self):
        with self.assertRaisesRegex(ValueError, "exact LLVM22.1.6"):
            self.selected_decoder(version="21.1.0")
        decoder = checker.snapshot_llvm_decoder(self.decoder(), self.root / "tools")
        Path(decoder["snapshot"]["path"]).write_text("changed snapshot")
        result = checker.check_unit(self.unit(b"BC\xc0\xdeauthored"), self.root / "bad-snapshot", self.root / "absent-compiler", "riscv64-unknown-none", [], decoder)
        self.assertEqual(result["failed_stage"], "llvm_decode")
        self.assertEqual(result["stages"], [])
        self.assertIn("snapshot changed", result["first_diagnostic"]["message"])

    def test_decoder_failure_retains_stderr_and_never_substitutes_decoded_input(self):
        decoder = self.selected_decoder(failure=True)
        result = checker.check_unit(self.unit(b"BC\xc0\xdeauthored"), self.root / "decode-failed", self.root / "absent-compiler", "riscv64-unknown-none", [], decoder)
        self.assertEqual(result["failed_stage"], "llvm_decode")
        self.assertEqual(result["llvm_decode"]["exit_code"], 9)
        self.assertIn("authored decoder failure", Path(result["llvm_decode"]["stderr"]["path"]).read_text())
        self.assertEqual(result["stages"], [])

    def test_textual_llvm_needs_no_decoder(self):
        unit = self.unit(TEXT.encode())
        result = checker.check_unit(unit, self.root / "textual", self.root / "absent-compiler", "riscv64-unknown-none", [])
        self.assertEqual(result["failed_stage"], "import")
        self.assertNotIn("llvm_decode", result)


    def capture_report(self):
        unit = self.unit(b"BC\xc0\xdeauthored")
        path = self.root / "capture.json"
        path.write_text(json.dumps({"schema":"ocore-runtime-capture-v1", "capture_complete":True,
            "unit_inventory_complete":True,"units":[unit],"build_steps":[{"name":"original-library",
            "argv":[],"exit_code":0,"started_ns":0,"finished_ns":4}],"invocations":[{"units":[unit],
            "build_step":{"index":0,"name":"original-library"},"started_ns":1,"finished_ns":2}]}))
        return path

    def run_cli(self, output, compiler, decoder):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return checker.main([str(self.capture_report()),"--step","original-library","--ocorec",str(compiler),
                "--target","riscv64-unknown-none","--llvm-dis",str(decoder),"--output",str(output)])

    def test_cli_decoder_failure_is_incomplete_infrastructure_not_unsupported_compiler(self):
        marker = self.root / "unexpected-compiler-call"
        compiler = self.executable("compiler", 'from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
        output = self.root / "failed-decode-audit"
        self.assertEqual(self.run_cli(output, compiler, self.decoder(failure=True)), 2)
        result = json.loads((output / "report.json").read_text())
        self.assertFalse(result["audit_complete"])
        self.assertTrue(result["issues"])
        self.assertEqual(result["first_failure_groups"], [])
        self.assertEqual(result["units"][0]["failed_stage"], "llvm_decode")
        self.assertEqual(result["units"][0]["stages"], [])
        self.assertFalse(marker.exists())

    def test_cli_rechecks_original_snapshot_and_version_evidence_after_actual_children(self):
        for index, relative in enumerate((None,"llvm-dis","llvm-dis-version.stdout","llvm-dis-version.stderr")):
            with self.subTest(artifact=relative):
                output = self.root / ("changed-decoder-audit-"+str(index))
                decoder = self.decoder()
                artifact = decoder if relative is None else output / "tools" / relative
                compiler = self.executable("compiler", 'from pathlib import Path\nimport sys\nPath(' + repr(str(artifact)) + ').write_text("changed")\nsys.exit(17)\n')
                self.assertEqual(self.run_cli(output, compiler, decoder), 2)
                result = json.loads((output / "report.json").read_text())
                self.assertFalse(result["audit_complete"])
                self.assertTrue(any("decoder evidence changed" in issue for issue in result["issues"]))
                self.assertEqual([s["stage"] for s in result["units"][0]["stages"]], ["import"])


if __name__ == "__main__":
    unittest.main()
