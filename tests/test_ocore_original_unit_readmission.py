"""Real compiler body-admission controls; authored LLVM, no runtime acceptance."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools/ocore-runtime/acceptance/check_runtime.py"
SOURCE = """source_filename = "authored-body-readmission.ll"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "riscv64-unknown-linux-gnu"
@cold_data = internal global i64 9, align 8
@cold_slot = global ptr @cold_data, align 8
@cold_callback = global ptr @cold_external, align 8
declare i64 @cold_external(i64)
define i64 @probe(i64 %x) {
entry:
  %sum = add i64 %x, VALUE
  ret i64 %sum
}
"""


def pin(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class OriginalUnitReadmissionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = Path(os.environ["OCORE_BODY_READMISSION_OUTPUT"])
        cls.out.mkdir(parents=True, exist_ok=False)
        cls.tools_path = Path(os.environ["OCORE_BODY_READMISSION_TOOLS"])
        cls.tools = json.loads(cls.tools_path.read_text())
        cls.environment = dict(os.environ, **cls.tools["environment"])
        cls.core = cls.tools["tools"]["ocorec"]
        cls.library = cls.tools["tools"]["llvm_library"]
        cls.tracked = [CHECKER, Path(__file__), cls.tools_path] + [Path(item["path"]) for item in cls.tools["tools"].values()]
        cls.record = {"schema": "ocore-real-original-unit-readmission-controls-v1", "scope": "authored whole LLVM unit with cold globals/dependencies; real compiler import/verification and arithmetic-body forgery rejection, not original-runtime acceptance", "before": [pin(p) for p in cls.tracked], "commands": [], "cases": [], "runtime_accepted": False, "native_execution_qualified": False}
        cls.original = cls.out / "original.ll"
        cls.changed = cls.out / "changed-add-two.ll"
        cls.original.write_text(SOURCE.replace("VALUE", "1"));cls.changed.write_text(SOURCE.replace("VALUE", "2"))
        modules = []
        for name, source in (("original", cls.original), ("changed", cls.changed)):
            native = cls.out / (name + ".native-ir.json")
            argv = [cls.core["path"], str(source), "--input-kind", "llvm-ir", "--emit", "mir", "--target", "riscv64-unknown-none", "--llvm-library", cls.library["path"], "--llvm-sha256", cls.library["sha256"], "-o", str(native)]
            assert cls.command(argv, name + "-import") == 0
            module = json.loads(native.read_text());assert module["provenance"]["input_sha256"] == pin(source)["sha256"]
            modules.append(module)
        cls.original_module = modules[0]
        assert modules[0]["types"] == modules[1]["types"]
        forged = copy.deepcopy(modules[0])
        source_function, = [f for f in modules[1]["functions"] if f["name"] == "probe"]
        destination, = [f for f in forged["functions"] if f["name"] == "probe"]
        assert destination["params"] == source_function["params"] and destination["signature"] == source_function["signature"] and destination["entry"] == source_function["entry"]
        assert destination["blocks"] != source_function["blocks"]
        destination["blocks"] = copy.deepcopy(source_function["blocks"])
        assert forged["provenance"] == cls.original_module["provenance"]
        assert forged["globals"] == cls.original_module["globals"]
        cls.forged = cls.out / "forged-body-original-provenance.native-ir.json"
        cls.forged.write_text(json.dumps(forged, indent=2) + "\n")
        cls.source_files = [cls.original, cls.changed, cls.out / "original.native-ir.json", cls.forged]
        cls.record["source_before"] = [pin(p) for p in cls.source_files];cls.save()

    @classmethod
    def save(cls):
        (cls.out / "report.json").write_text(json.dumps(cls.record, indent=2) + "\n")

    @classmethod
    def command(cls, argv, label):
        stdout, stderr = cls.out / (label + ".stdout"), cls.out / (label + ".stderr")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            run = subprocess.run(list(map(str, argv)), env=cls.environment, stdout=out, stderr=err)
        cls.record["commands"].append({"argv": list(map(str, argv)), "exit_code": run.returncode, "stdout": pin(stdout), "stderr": pin(stderr)});cls.save()
        return run.returncode

    def diagnose(self, name, claimed):
        request = self.out / (name + ".request.json")
        data = {"schema": "ocore-original-unit-readmission-request-v1", "unit_id": "authored-probe", "original_unit": {"id": "authored-probe", "llvm_ir": pin(self.original)}, "claimed_module": pin(claimed), "target": {"target": "riscv64-unknown-none", "native_target": self.original_module["target"], "import_profiles": {}}}
        request.write_text(json.dumps(data, indent=2) + "\n")
        output = self.out / (name + "-diagnostic")
        code = self.command([sys.executable, "-I", CHECKER, "readmit-unit", request, "--tools", self.tools_path, "--output", output], name)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["schema"], "ocore-original-unit-readmission-result-v1")
        for key in ("runtime_accepted", "native_execution_qualified", "complete_olangc_artifact", "original_capture_admitted", "complete_original_inventory_admitted", "complete"):
            self.assertIs(report[key], False)
        self.assertTrue(report["tools_and_request_stable"])
        return code, report, output, request

    def test_genuine_body_passes_fresh_real_import_and_owned_emission(self):
        code, report, output, request = self.diagnose("genuine-original-body", self.out / "original.native-ir.json")
        self.assertEqual(code, 0, report)
        self.assertIs(report["unit_readmission_complete"], True)
        self.assertEqual(report["unit"]["status"], "GREEN")
        self.assertEqual(len(report["commands"]), 5)
        self.assertTrue(all(c["exit_code"] == 0 for c in report["commands"]))
        admission = json.loads((output / "unit/readmission.json").read_text())
        self.assertIs(admission["same_typed_module"], True)
        self.assertEqual((output / "unit/diagnostic.o").read_bytes()[:4], b"\x7fELF")
        self.record["cases"].append({"id": "genuine_original_body", "report": pin(output / "report.json"), "request": pin(request), "exit_code": code});self.save()

    def test_well_typed_changed_body_with_original_identity_is_rejected(self):
        code, report, output, request = self.diagnose("well-typed-changed-body", self.forged)
        self.assertEqual(code, 1, report)
        self.assertIs(report["unit_readmission_complete"], False)
        self.assertEqual(report["unit"]["diagnostic"], "fresh original LLVM import does not match claimed typed NativeModule")
        self.assertEqual(len(report["commands"]), 3)
        self.assertTrue(all(c["exit_code"] == 0 for c in report["commands"]))
        verification = json.loads((output / "unit/claimed-verification.json").read_text())
        self.assertIs(verification["verified"], True)
        self.assertEqual(verification["module_sha256"], pin(self.forged)["sha256"])
        self.assertTrue((output / "unit/preservation.json").is_file())
        admission = json.loads((output / "unit/readmission.json").read_text())
        self.assertIs(admission["same_typed_module"], False)
        self.assertFalse((output / "unit/diagnostic.o").exists())
        self.record["cases"].append({"id": "well_typed_changed_body", "report": pin(output / "report.json"), "request": pin(request), "exit_code": code});self.save()

    @classmethod
    def tearDownClass(cls):
        cls.record["after"] = [pin(p) for p in cls.tracked]
        cls.record["source_after"] = [pin(p) for p in cls.source_files]
        cls.record["source_tools_stable"] = cls.record["before"] == cls.record["after"] and cls.record["source_before"] == cls.record["source_after"]
        cls.save()
