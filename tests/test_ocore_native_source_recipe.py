"""One olangc invocation captures and lowers an unchanged pinned C fixture.

The fixture owns its original Make build and derives its complete inventory
from that build's evaluated source list. These tests never manufacture frontend
IR, compiler invocations, capture journals or verification receipts. The native
execution below qualifies fixture arithmetic on the host, not a whole external
runtime or native OSTADIX services.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from test_ocore_native_runtime import FLAGS, ROOT, SDK_DEFAULT


def run(argv, **kwargs):
    return subprocess.run([str(value) for value in argv], capture_output=True,
                          text=True, timeout=240, **kwargs)


INVENTORY_SOURCE = r'''import hashlib,json,pathlib,subprocess,sys
source,build,output=map(pathlib.Path,sys.argv[1:])
names=subprocess.check_output(["make","--no-print-directory","-s","-f",str(source/"Makefile"),
    "SOURCE="+str(source),"BUILDDIR="+str(build),"list-sources"],text=True).splitlines()
if not names or len(names)!=len(set(names)):
    raise SystemExit("original Make source inventory is missing or ambiguous")
units=[]
outputs=[]
for name in names:
    path=pathlib.Path(name)
    if path.name!=name or path.suffix!=".c" or not (source/path).is_file():
        raise SystemExit("original Make source escaped the pinned checkout")
    obj=(build/path.with_suffix(".o")).resolve()
    data=obj.read_bytes()
    units.append({"id":"original-"+path.stem,"kind":"clang","source":name,
        "role":"runtime","build_step":"build-original-fixture"})
    outputs.append({"path":str(obj),"sha256":hashlib.sha256(data).hexdigest(),"bytes":len(data)})
output.write_text(json.dumps({"schema":"ocore-runtime-unit-inventory-v1","complete":True,
    "units":units,"non_lowering_units":[],"runtime_outputs":outputs})+"\n")
'''


class NativeSourceRecipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.olangc = ROOT / "target/debug/olangc"
        cls.ocorec = ROOT / "target/debug/ocorec"
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(SDK_DEFAULT)))
        for path in (cls.olangc, cls.ocorec, *[cls.sdk / name for name in ("clang", "clang++", "llvm-nm")]):
            if not path.is_file() or not os.access(path, os.X_OK):
                raise unittest.SkipTest(f"actual compiler and exact scoped LLVM22 SDK required: {path}")
        for name in ("git", "make"):
            if shutil.which(name) is None:
                raise unittest.SkipTest(f"{name} required for the original source fixture")
        for name in ("clang", "clang++", "llvm-nm"):
            result = run([cls.sdk / name, "--version"])
            if result.returncode or not re.search(r"\b(?:clang version|LLVM version) 22\.1\.6(?:\s|$)", result.stdout):
                raise RuntimeError(f"exact LLVM22.1.6 {name} required: {result.stdout}{result.stderr}")
        help_result = run([cls.olangc, "--help"])
        if help_result.returncode or "--native-runtime-source" not in help_result.stdout:
            raise RuntimeError("rebuild olangc with the direct native source-recipe interface")
        arch = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
        cls.machine = {"x86_64": 62, "aarch64": 183, "riscv64": 243}.get(arch)
        if cls.machine is None:
            raise unittest.SkipTest(f"host fixture requires a supported native ISA: {arch}")
        target_result = run([cls.sdk / "clang", "-dumpmachine"])
        if target_result.returncode or target_result.stdout.strip().split("-")[0] != arch:
            raise unittest.SkipTest("LLVM22 must target the host for this native execution fixture")
        cls.target = f"{arch}-unknown-none"
        cls.import_options = []
        library = os.environ.get("OCORE_TEST_LLVM_LIBRARY")
        expected = os.environ.get("OCORE_TEST_LLVM_SHA256")
        if expected and not library:
            raise RuntimeError("OCORE_TEST_LLVM_SHA256 requires OCORE_TEST_LLVM_LIBRARY")
        if library:
            path = Path(library).expanduser().resolve(strict=True)
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if expected and expected != actual:
                raise RuntimeError("the explicit LLVM parser library digest differs")
            cls.import_options = ["--llvm-library", str(path), "--llvm-sha256", actual]
        retained = os.environ.get("OCORE_TEST_NATIVE_SOURCE_RECIPE_OUTPUT_DIR")
        if retained:
            evidence = Path(retained).expanduser().resolve()
            evidence.mkdir(parents=True, exist_ok=True)
            cls.directory = Path(tempfile.mkdtemp(prefix="run-", dir=evidence))
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="ocore-source-recipe-tests-")
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.directory = Path(cls.temporary.name)

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.directory))
        self.source = self.case / "source"
        self.source.mkdir()
        (self.source / "runtime.c").write_text(
            "unsigned long long engine_add(unsigned long long a, unsigned long long b) { return a + b; }\n")
        (self.source / "cold.c").write_text("int cold_path(int value) { return value - 7; }\n")
        (self.source / "inventory.py").write_text(INVENTORY_SOURCE)
        (self.source / ".gitignore").write_text("local-notes.txt\n")
        (self.source / "Makefile").write_text(
            "SOURCES := runtime.c cold.c\n"
            "OBJECTS := $(addprefix $(BUILDDIR)/,$(SOURCES:.c=.o))\n"
            ".PHONY: all list-sources\n"
            "all: $(OBJECTS)\n"
            "$(BUILDDIR)/%.o: $(SOURCE)/%.c\n"
            "\t$(CC) $(CFLAGS) -c $< -o $@\n"
            "list-sources:\n\t@printf '%s\\n' $(SOURCES)\n")
        for argv in (["git", "init", "-q"], ["git", "add", "."],
                     ["git", "-c", "user.name=Native Source Recipe Test", "-c", "user.email=test@example.invalid",
                      "commit", "-qm", "original complete source fixture"]):
            result = run(argv, cwd=self.source)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        revision = run(["git", "rev-parse", "HEAD"], cwd=self.source).stdout.strip()
        (self.source / "local-notes.txt").write_bytes(b"unrelated ignored source bytes\x00stay unchanged\n")
        self.original_source = self.source_snapshot()
        self.recipe = {
            "schema": "ocore-runtime-recipe-v1", "name": "original-pure-c-source-cli-fixture",
            "source": {"url": "local-pinned-source-recipe-test-fixture", "revision": revision},
            "toolchain": {"llvm_version": "22.1.6"},
            "commands": [
                {"name": "build-original-fixture", "argv": ["make", "--no-print-directory", "-f", "{source}/Makefile",
                    "SOURCE={source}", "BUILDDIR={build}", "CC={cc}", "CFLAGS=" + " ".join(FLAGS), "all"]},
                {"name": "inventory-original-build", "argv": [sys.executable, "{source}/inventory.py",
                    "{source}", "{build}", "{build}/unit-inventory.json"]}],
            "coverage": {"require_full_unit_inventory": True, "audit_roots": ["{build}"],
                "required_outputs": ["runtime.o", "cold.o"], "required_units": [
                    {"id": "engine-floor", "kind": "clang", "source": "runtime.c", "role": "runtime"},
                    {"id": "cold-floor", "kind": "clang", "source": "cold.c", "role": "runtime"}]}}
        self.recipe_path = self.case / "recipe.json"
        self.write_recipe()

    def source_snapshot(self):
        return {str(path.relative_to(self.source)): path.read_bytes()
                for path in self.source.rglob("*") if path.is_file() and ".git" not in path.relative_to(self.source).parts}

    def write_recipe(self):
        self.recipe_path.write_text(json.dumps(self.recipe))

    def invoke(self, output=None, kind="ir", extra=(), jobs=2):
        output = output or self.case / "compiled"
        result = run([self.olangc, self.recipe_path, "--native-runtime", "--native-runtime-source", self.source,
                      "--native-isa", self.target, "--native-runtime-output", kind,
                      "--native-runtime-cc", self.sdk / "clang", "--native-runtime-cxx", self.sdk / "clang++",
                      "--native-runtime-llvm-nm", self.sdk / "llvm-nm", "--native-runtime-jobs", str(jobs),
                      *self.import_options, *extra, "-o", output])
        return result, output

    def assert_original_source(self):
        self.assertEqual(self.source_snapshot(), self.original_source)

    def assert_bound_receipt_files(self, receipt):
        records = []
        def visit(value):
            if isinstance(value, dict):
                if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                    records.append(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(receipt)
        self.assertGreaterEqual(len(records), 3, "source/capture/lowering provenance must retain bound files")
        for record in records:
            path = Path(record["path"])
            self.assertTrue(path.is_file(), record)
            data = path.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"], record)
            if "bytes" in record:
                self.assertEqual(len(data), record["bytes"], record)

    def successful_lowering(self, kind):
        result, output = self.invoke(kind=kind)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads((output / "source-recipe.json").read_text())
        self.assertEqual(receipt["schema"], "ocore-native-source-recipe-v1")
        self.assertEqual(receipt["stage"], "complete")
        for field in ("success", "capture_complete", "worker_capture_complete", "lowering_complete"):
            self.assertTrue(receipt[field], field)
        for field in ("runtime_complete", "native_execution_qualified"):
            self.assertFalse(receipt[field], field)
        self.assert_bound_receipt_files(receipt)
        capture = json.loads((output / "capture/report.json").read_text())
        self.assertTrue(capture["capture_complete"])
        self.assertEqual(len(capture["units"]), 2)
        self.assertEqual(len(capture["lowering_unit_ids"]), 2)
        self.assertEqual(capture["non_lowering_units"], [])
        self.assertEqual({Path(unit["source"]["path"]).name for unit in capture["units"]}, {"runtime.c", "cold.c"})
        coverage = json.loads((output / "lowered/coverage.json").read_text())
        self.assertTrue(coverage["module_set_complete"])
        self.assertTrue(coverage["native_module_dependency_closure_complete"])
        self.assertEqual(coverage["required_lowering_unit_count"], 2)
        self.assertEqual(coverage["lowered_unit_count"], 2)
        self.assertFalse(coverage["runtime_complete"])
        self.assertFalse(coverage["native_execution_qualified"])
        artifact_path = output / "lowered/runtime.native-ir.json"
        artifact = json.loads(artifact_path.read_text())
        self.assertEqual(artifact["format"], "ocore-native-module-set-v1")
        self.assertEqual(len(artifact["modules"]), 2)
        self.assertEqual({function["name"] for module in artifact["modules"]
                          for function in json.loads(module["native_ir"])["functions"]}, {"engine_add", "cold_path"})
        self.assert_original_source()
        return output

    def test_one_invocation_captures_and_lowers_all_original_sources_to_verified_ir(self):
        self.successful_lowering("ir")

    def test_one_invocation_emits_owned_native_objects_and_executes_fixture_arithmetic(self):
        output = self.successful_lowering("obj")
        objects = sorted((output / "lowered").glob("unit-*/module.o"))
        self.assertEqual(len(objects), 2)
        for path in objects:
            data = path.read_bytes()
            self.assertEqual(data[:6], b"\x7fELF\x02\x01")
            self.assertEqual(struct.unpack_from("<H", data, 18)[0], self.machine)
        harness = self.case / "harness.c"
        harness.write_text("extern unsigned long long engine_add(unsigned long long,unsigned long long);\n"
                           "extern int cold_path(int);\n"
                           "int main(void) { return engine_add(20,22) != 42 || cold_path(12) != 5; }\n")
        carrier = self.case / "host-fixture-arithmetic"
        linked = run([self.sdk / "clang", harness, *objects, "-no-pie", "-o", carrier])
        self.assertEqual(linked.returncode, 0, linked.stdout + linked.stderr)
        executed = run([carrier])
        self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
        self.assert_original_source()

    def capture_failure(self):
        result, output = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads((output / "source-recipe.json").read_text())
        self.assertEqual(receipt["schema"], "ocore-native-source-recipe-v1")
        self.assertEqual(receipt["stage"], "capture")
        self.assertFalse(receipt["success"])
        self.assertFalse(receipt["capture_complete"])
        self.assertFalse(receipt["lowering_complete"])
        self.assertFalse(receipt["runtime_complete"])
        self.assertFalse((output / "lowered/runtime.native-ir.json").exists())
        self.assertFalse(any((output / "lowered").glob("unit-*/module.o")))
        self.assert_original_source()
        diagnostics = [result.stdout, result.stderr, (output / "capture.log").read_text()]
        report_path = output / "capture/report.json"
        if report_path.is_file():
            report = json.loads(report_path.read_text())
            for step in report.get("build_steps", []):
                log = step.get("log")
                if isinstance(log, str) and Path(log).is_file():
                    diagnostics.append(Path(log).read_text())
        return "\n".join(diagnostics)

    def test_wrong_original_source_pin_rejects_before_frontend_compilation(self):
        self.recipe["source"]["revision"] = "0" * 40
        self.write_recipe()
        self.assertIn("source commit mismatch", self.capture_failure())
        self.assertFalse(any((self.case / "compiled/build").rglob("*.o")))

    def test_original_build_failure_retains_diagnostics_without_lowering(self):
        self.recipe["commands"][0]["argv"] = [sys.executable, "-c", "raise SystemExit('original-fixture-build-failed')"]
        self.write_recipe()
        self.assertIn("original-fixture-build-failed", self.capture_failure())

    def test_exact_frontend_toolchain_pin_failure_rejects_actual_wrong_version(self):
        self.recipe["toolchain"]["llvm_version"] = "22.1.7"
        self.write_recipe()
        diagnostics = self.capture_failure()
        self.assertIn("version mismatch", diagnostics)
        self.assertIn("22.1.7", diagnostics)
        self.assertFalse(any((self.case / "compiled/build").rglob("*.o")))

    def test_output_inside_original_source_is_rejected_after_path_normalization(self):
        alias = self.case / "source-alias"
        alias.symlink_to(self.source, target_is_directory=True)
        for output in (self.source / ".." / "source" / "generated", alias / "generated"):
            with self.subTest(output=output):
                result, _ = self.invoke(output=output)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.source / "generated").exists())
                self.assert_original_source()

    def test_existing_output_directory_and_unrelated_bytes_are_preserved(self):
        output = self.case / "existing"
        output.mkdir()
        sentinel = output / "unrelated.bin"
        sentinel.write_bytes(b"existing unrelated output bytes\x00\xff")
        result, _ = self.invoke(output=output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual({str(path.relative_to(output)): path.read_bytes() for path in output.rglob("*") if path.is_file()},
                         {"unrelated.bin": b"existing unrelated output bytes\x00\xff"})
        self.assert_original_source()

    def test_output_containing_the_recipe_input_is_rejected_without_overwrite(self):
        recipe_before = self.recipe_path.read_bytes()
        result, _ = self.invoke(output=self.case)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.recipe_path.read_bytes(), recipe_before)
        self.assertFalse((self.case / "source-recipe.json").exists())
        self.assert_original_source()

    def test_inventory_option_cannot_escape_the_new_build_directory(self):
        outside = self.case / "unrelated-inventory.json"
        outside.write_bytes(b"unrelated data, not a capture inventory")
        result, output = self.invoke(extra=("--native-runtime-unit-inventory", str(outside)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outside.read_bytes(), b"unrelated data, not a capture inventory")
        self.assertFalse(output.exists())
        self.assert_original_source()

    def test_zero_build_jobs_rejects_before_output_creation(self):
        result, output = self.invoke(jobs=0)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assert_original_source()

    def test_source_options_reject_real_saved_capture_and_embedded_module_set(self):
        captured = self.successful_lowering("ir")
        inputs = (captured / "capture/report.json", captured / "lowered/runtime.native-ir.json")
        for index, input_path in enumerate(inputs):
            with self.subTest(input=input_path):
                output = self.case / f"rejected-source-options-{index}"
                result = run([self.olangc, input_path, "--native-runtime", "--native-runtime-source", self.source,
                              "--native-runtime-cc", self.sdk / "clang", "--native-runtime-cxx", self.sdk / "clang++",
                              "--native-runtime-llvm-nm", self.sdk / "llvm-nm", "--native-isa", self.target,
                              *self.import_options, "-o", output])
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assert_original_source()


if __name__ == "__main__":
    unittest.main()
