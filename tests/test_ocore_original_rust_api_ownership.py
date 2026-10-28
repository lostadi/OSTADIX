"""Actual original Rust/API ownership checks; no authored native emitter or IR."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
QUALIFIER = ROOT / "tools/ocore-runtime/rust-crates/qualify_adler2.py"


class OriginalRustApiOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = ["CAPTURE", "AUDIT", "OCOREC", "LLVM_LIBRARY", "LLVM_SHA256", "CLANG", "LLVM_NM"]
        cls.values = {name:os.environ.get("OCORE_TEST_RUST_API_"+name) for name in names}
        if not all(cls.values.values()):
            raise unittest.SkipTest("requires explicit original Rust capture/audit and trusted compiler/LLVM tool selections")

    def execute(self, audit, name):
        parent = os.environ.get("OCORE_TEST_RUST_API_OUTPUT_DIR")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix=name+"-", dir=parent)).resolve()
        argv = ["python3",str(QUALIFIER),self.values["CAPTURE"],str(audit),"--ocorec",self.values["OCOREC"],
                "--llvm-library",self.values["LLVM_LIBRARY"],"--llvm-sha256",self.values["LLVM_SHA256"],
                "--clang",self.values["CLANG"],"--llvm-nm",self.values["LLVM_NM"],"--output",str(directory/"qualification")]
        result = subprocess.run(argv, capture_output=True, timeout=600)
        (directory/"stdout.log").write_bytes(result.stdout)
        (directory/"stderr.log").write_bytes(result.stderr)
        (directory/"command.json").write_text(json.dumps({"argv":argv,"exit_code":result.returncode},indent=2)+"\n")
        report = json.loads((directory/"qualification/report.json").read_text())
        return result, report

    def test_all_original_cgus_are_freshly_generated_and_twelve_actual_native_cases_pass(self):
        result, report = self.execute(self.values["AUDIT"], "actual-native-api")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertTrue(report["success"])
        self.assertEqual(report["case_count"], 12)
        self.assertEqual(len(report["fresh_owned_units"]), report["whole_cgu_count"])
        self.assertEqual(report["owned_objects"], [unit["object"] for unit in report["fresh_owned_units"]])
        self.assertTrue(report["input_artifacts_unchanged"])

    def test_original_reference_object_substituted_as_owned_is_rejected_after_real_generation(self):
        capture = json.loads(Path(self.values["CAPTURE"]).read_text())
        audit = json.loads(Path(self.values["AUDIT"]).read_text())
        originals = {unit["id"]:event["saved_cgus"][unit["saved_cgu_index"]]["object"]
                     for event in capture["invocations"] for unit in event.get("units", [])}
        for unit in audit["units"]:
            unit["object"] = {**originals[unit["id"]],"elf_type":1,"machine":243}
        parent = Path(os.environ.get("OCORE_TEST_RUST_API_OUTPUT_DIR", ROOT/"target"))
        parent.mkdir(parents=True,exist_ok=True)
        path = Path(tempfile.mkdtemp(prefix="forged-owned-audit-",dir=parent))/"audit.json"
        path.write_text(json.dumps(audit,indent=2)+"\n")
        result, report = self.execute(path, "reject-original-as-owned")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(report["success"])
        self.assertIn("fresh owned object differs", report["error"])
        names = [command["name"] for command in report["commands"]]
        self.assertIn("cgu-0-import", names)
        self.assertIn("cgu-0-verify", names)
        self.assertIn("cgu-0-object", names)
        self.assertTrue(all(command["exit_code"] == 0 for command in report["commands"]))
        self.assertNotEqual(report["fresh_owned_units"][0]["object"]["sha256"], audit["units"][0]["object"]["sha256"])
        self.assertNotIn("owned-execute", names)
        self.assertNotIn("original-execute", names)


if __name__ == "__main__":
    unittest.main()
