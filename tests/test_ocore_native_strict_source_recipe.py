"""Required strict-FP profile through actual public source capture and reload.

The complete two-unit fixture owns its original Make build. This is a compiler
regression with an explicit original reference, not a libc/runtime qualification.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_ocore_native_source_recipe as fixture

SDK_DEFAULT = fixture.SDK_DEFAULT


class StrictSourceRecipeTests(unittest.TestCase):
    setUp = fixture.NativeSourceRecipeTests.setUp
    source_snapshot = fixture.NativeSourceRecipeTests.source_snapshot
    write_recipe = fixture.NativeSourceRecipeTests.write_recipe
    invoke = fixture.NativeSourceRecipeTests.invoke
    assert_original_source = fixture.NativeSourceRecipeTests.assert_original_source
    assert_bound_receipt_files = fixture.NativeSourceRecipeTests.assert_bound_receipt_files
    successful_lowering = fixture.NativeSourceRecipeTests.successful_lowering

    @classmethod
    def setUpClass(cls):
        cls.olangc = Path(os.environ.get("OCORE_TEST_OLANGC", "target/debug/olangc")).resolve()
        cls.ocorec = Path(os.environ.get("OCOREC_BIN", str(cls.olangc.with_name("ocorec")))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(SDK_DEFAULT)))
        for tool in (cls.olangc, cls.ocorec, cls.sdk/"clang", cls.sdk/"clang++", cls.sdk/"llvm-nm"):
            if not tool.is_file():
                raise unittest.SkipTest(f"actual public compiler and LLVM22 SDK required: {tool}")
        arch = {"amd64":"x86_64", "arm64":"aarch64"}.get(platform.machine().lower(), platform.machine().lower())
        if arch not in {"x86_64", "aarch64", "riscv64"}:
            raise unittest.SkipTest(f"supported native host required for real carrier execution: {arch}")
        cls.target = arch+"-unknown-none"
        library = os.environ.get("OCORE_TEST_LLVM_LIBRARY")
        cls.import_options = []
        if library:
            digest = hashlib.sha256(Path(library).read_bytes()).hexdigest()
            if os.environ.get("OCORE_TEST_LLVM_SHA256", digest) != digest:
                raise RuntimeError("explicit LLVM parser digest differs")
            cls.import_options = ["--llvm-library", library, "--llvm-sha256", digest]
        retained = os.environ.get("OCORE_TEST_STRICT_SOURCE_RECIPE_OUTPUT_DIR")
        if retained:
            Path(retained).mkdir(parents=True, exist_ok=True)
            cls.directory = Path(tempfile.mkdtemp(prefix="run-", dir=retained))
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="ocore-strict-source-recipe-")
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.directory = Path(cls.temporary.name)

    def command(self, argv, **kwargs):
        result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=240, **kwargs)
        self.commands.append({"argv":[str(x) for x in argv], "exit":result.returncode,
                              "stdout":result.stdout.hex(), "stderr":result.stderr.hex()})
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        return result

    def test_required_profile_survives_public_recipe_detached_reload_and_real_reference(self):
        self.commands = []
        # Source and original Make stay unchanged; the recipe requests the
        # original compiler's strict environment for both evaluated units.
        args = self.recipe["commands"][0]["argv"]
        args[:] = [arg+" -frounding-math" if arg.startswith("CFLAGS=") else arg for arg in args]
        self.write_recipe()
        output = self.successful_lowering("obj")
        packet_path = output/"lowered/runtime.native-ir.json"
        packet = json.loads(packet_path.read_text())
        self.assertEqual(packet["target"]["strict_fp_profile"], "integer_only_v1")
        for module in packet["modules"]:
            self.assertEqual(json.loads(module["native_ir"])["target"]["strict_fp_profile"], "integer_only_v1")
        # Move the complete admitted packet away from source/capture and invoke
        # copied public tools from an unrelated directory, with no resource tree.
        installed = self.case/"detached"
        installed.mkdir()
        for tool in (self.olangc, self.ocorec):
            shutil.copy2(tool, installed/tool.name)
        detached = installed/"runtime.native-ir.json"
        detached.write_bytes(packet_path.read_bytes())
        reloaded = self.case/"reloaded"
        self.command([installed/"olangc", detached, "--native-runtime", "--native-isa", self.target,
                      "--native-runtime-output", "obj", "-o", reloaded], cwd=installed)
        coverage = json.loads((reloaded/"coverage.json").read_text())
        self.assertTrue(coverage["native_module_dependency_closure_complete"])
        self.assertFalse(coverage["runtime_complete"])
        self.assertFalse(coverage["native_execution_qualified"])
        reopened = json.loads((reloaded/"runtime.native-ir.json").read_text())
        self.assertEqual(reopened["target"]["strict_fp_profile"], "integer_only_v1")
        harness = self.case/"carrier.c"
        harness.write_text("extern unsigned long long engine_add(unsigned long long,unsigned long long);\n"
                           "extern int cold_path(int);\n"
                           "int main(void){for(unsigned long long i=0;i<4096;++i)"
                           "if(engine_add(i,~i)!=~0ULL||cold_path((int)i)!=(int)i-7)return 31;return 0;}\n")
        original = sorted((output/"build").glob("*.o"))
        owned = sorted(reloaded.glob("unit-*/module.o"))
        self.assertEqual(len(original), 2)
        self.assertEqual(len(owned), 2)
        for label, objects in (("original", original), ("owned", owned)):
            carrier = self.case/(label+"-carrier")
            self.command([self.sdk/"clang", "-no-pie", harness, *objects, "-o", carrier])
            self.command([carrier])
        self.assert_original_source()
        (self.case/"strict-source-recipe-result.json").write_text(json.dumps({
            "ok":True, "schema":"ostadix.strict-source-recipe-qualification/v1",
            "profile":"integer_only_v1", "units":2,"checks_per_carrier":8192,
            "commands":self.commands,"source_recipe":str(output/"source-recipe.json"),
            "scope":"complete compiler fixture capture and detached profile-preserving object reload; not full libc or runtime"},indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
