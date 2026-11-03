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
TLS_PROFILE = "linux-elf-static-nonpreemptive-v1"
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

    @classmethod
    def tls_fixture(cls):
        if not hasattr(cls, "tls_original"):
            cls.tls_original = cls.out / "tls-original.ll"
            cls.tls_original.write_text(SOURCE.split("@cold_data", 1)[0] + """@tls_counter = internal thread_local(localexec) global i64 9, align 8
declare ptr @llvm.threadlocal.address.p0(ptr)
define i64 @tls_probe(i64 %delta) {
entry:
  %address = call ptr @llvm.threadlocal.address.p0(ptr @tls_counter)
  %current = load i64, ptr %address, align 8
  %sum = add i64 %current, %delta
  store i64 %sum, ptr %address, align 8
  ret i64 %sum
}
""")
            cls.tls_claimed = cls.out / "tls-original.native-ir.json"
            argv = [cls.core["path"], str(cls.tls_original), "--input-kind", "llvm-ir", "--emit", "mir",
                    "--target", "riscv64-unknown-none", "--llvm-library", cls.library["path"],
                    "--llvm-sha256", cls.library["sha256"], "--tls-profile", TLS_PROFILE,
                    "-o", str(cls.tls_claimed)]
            if cls.command(argv, "tls-fixture-import") != 0:
                raise AssertionError("selected compiler did not import the TLS-bearing control; see retained command logs")
            cls.tls_module = json.loads(cls.tls_claimed.read_text())
            if cls.tls_module["target"]["tls_profile"] != "linux_elf_static_nonpreemptive_v1":
                raise AssertionError("selected compiler did not preserve the explicit TLS profile")
            cls.source_files += [cls.tls_original, cls.tls_claimed]
            cls.record["source_before"] += [pin(cls.tls_original), pin(cls.tls_claimed)]
            cls.save()
        return cls.tls_original, cls.tls_claimed, cls.tls_module

    def diagnose(self, name, claimed, *, original=None, module=None, import_profiles=None):
        request = self.out / (name + ".request.json")
        original = self.original if original is None else original
        module = self.original_module if module is None else module
        data = {"schema": "ocore-original-unit-readmission-request-v1", "unit_id": "authored-probe", "original_unit": {"id": "authored-probe", "llvm_ir": pin(original)}, "claimed_module": pin(claimed), "target": {"target": "riscv64-unknown-none", "native_target": module["target"], "import_profiles": {} if import_profiles is None else import_profiles}}
        request.write_text(json.dumps(data, indent=2) + "\n")
        output = self.out / (name + "-diagnostic")
        code = self.command([sys.executable, "-I", CHECKER, "readmit-unit", request, "--tools", self.tools_path, "--output", output], name)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["schema"], "ocore-original-unit-readmission-result-v1")
        for key in ("runtime_accepted", "native_execution_qualified", "complete_olangc_artifact", "original_capture_admitted", "complete_original_inventory_admitted", "complete"):
            self.assertIs(report[key], False)
        self.assertTrue(report["tools_and_request_stable"])
        return code, report, output, request

    def test_tls_profile_is_forwarded_only_to_the_fresh_llvm_import(self):
        original, claimed, module = self.tls_fixture()
        code, report, output, request = self.diagnose(
            "tls-profile-forwarding", claimed, original=original, module=module,
            import_profiles={"--tls-profile": TLS_PROFILE})
        self.assertEqual(code, 0, report)
        self.assertIs(report["unit_readmission_complete"], True)
        commands = [row["argv"] for row in report["commands"]]
        imported, = [argv for argv in commands if argv[argv.index("--input-kind") + 1] == "llvm-ir"]
        self.assertEqual(imported.count("--tls-profile"), 1)
        self.assertEqual(imported[imported.index("--tls-profile") + 1], TLS_PROFILE)
        self.assertEqual(imported[0], self.core["path"])
        self.assertEqual(imported[1], str(original))
        self.assertTrue(all("--tls-profile" not in argv for argv in commands if argv is not imported))
        admission = json.loads((output / "unit/readmission.json").read_text())
        self.assertIs(admission["same_typed_module"], True)
        self.assertEqual((output / "unit/diagnostic.o").read_bytes()[:4], b"\x7fELF")
        self.record["cases"].append({"id": "tls_profile_forwarding", "report": pin(output / "report.json"), "request": pin(request), "exit_code": code});self.save()

    def test_tls_global_without_a_profile_reaches_import_and_is_rejected(self):
        original, claimed, module = self.tls_fixture()
        code, report, output, request = self.diagnose("tls-profile-omitted", claimed, original=original, module=module)
        self.assertEqual(code, 1, report)
        self.assertIs(report["unit_readmission_complete"], False)
        imported, = [row for row in report["commands"] if row["argv"][row["argv"].index("--input-kind") + 1] == "llvm-ir"]
        self.assertNotEqual(imported["exit_code"], 0)
        self.assertNotIn("--tls-profile", imported["argv"])
        self.assertIn("TLS globals require explicit --tls-profile", Path(imported["stderr"]["path"]).read_text())
        self.assertFalse((output / "unit/diagnostic.o").exists())
        self.record["cases"].append({"id": "tls_profile_omitted", "report": pin(output / "report.json"), "request": pin(request), "exit_code": code});self.save()

    def test_unsupported_tls_string_reaches_the_selected_compiler_unchanged(self):
        original, claimed, module = self.tls_fixture()
        value = "unsupported TLS control profile"
        code, report, output, request = self.diagnose(
            "tls-profile-unsupported", claimed, original=original, module=module,
            import_profiles={"--tls-profile": value})
        self.assertEqual(code, 1, report)
        self.assertIs(report["unit_readmission_complete"], False)
        imported, = [row for row in report["commands"] if row["argv"][row["argv"].index("--input-kind") + 1] == "llvm-ir"]
        self.assertEqual(imported["argv"][imported["argv"].index("--tls-profile") + 1], value)
        self.assertNotEqual(imported["exit_code"], 0)
        diagnostic = Path(imported["stderr"]["path"]).read_text()
        self.assertIn(value, diagnostic)
        self.assertTrue(("invalid value" in diagnostic and "--tls-profile" in diagnostic)
                        or "unsupported TLS profile" in diagnostic, diagnostic)
        self.assertFalse((output / "unit/diagnostic.o").exists())
        self.record["cases"].append({"id": "tls_profile_unsupported", "report": pin(output / "report.json"), "request": pin(request), "exit_code": code});self.save()

    def test_malformed_import_profiles_are_rejected_before_tool_execution(self):
        invalid = [[], None, {"--tls-profil": "x"}, {"--tls-profile=x": "x"},
                   {"--tls-profile": TLS_PROFILE, "--unknown-profile": "x"}]
        invalid += [{"--tls-profile": value} for value in [None, 1, True, [], {}]]
        for index, declaration in enumerate(invalid):
            with self.subTest(declaration=declaration):
                name = "malformed-profile-" + str(index)
                request = self.out / (name + ".request.json")
                request.write_text(json.dumps({"schema": "ocore-original-unit-readmission-request-v1", "unit_id": "authored-probe", "original_unit": {"id": "authored-probe", "llvm_ir": pin(self.original)}, "claimed_module": pin(self.out / "original.native-ir.json"), "target": {"target": "riscv64-unknown-none", "native_target": self.original_module["target"], "import_profiles": declaration}}))
                output = self.out / (name + "-diagnostic")
                code = self.command([sys.executable, "-I", CHECKER, "readmit-unit", request, "--tools", self.tools_path, "--output", output], name)
                self.assertEqual(code, 1)
                self.assertIn("unknown or malformed import profile", Path(self.record["commands"][-1]["stderr"]["path"]).read_text())
                self.assertFalse(output.exists(), "malformed declaration reached tool setup")

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
