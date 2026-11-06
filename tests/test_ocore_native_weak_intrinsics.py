"""LLVM owned intrinsics cannot also become optional ELF weak providers."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_optimizer_promises as promises


DECLARATIONS = (
    "void @llvm.trap()",
    "void @llvm.assume(i1)",
    "i32 @llvm.ctpop.i32(i32)",
    "i32 @llvm.fshl.i32(i32,i32,i32)",
)


class WeakIntrinsicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ocore-weak-intrinsics-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_original_external_weak_intrinsics_reject_without_partial_import(self):
        for triple in baseline.TRIPLES:
            for declaration in DECLARATIONS:
                with self.subTest(triple=triple, declaration=declaration):
                    source = self.root / "weak.ll"
                    source.write_text(promises.module_text(triple, "declare extern_weak " + declaration))
                    with self.assertRaisesRegex(importer.ImportFailure, "extern_weak does not apply"):
                        importer.import_module(source, library_path=self.library)

    def test_independent_native_verifier_rejects_forged_weak_owned_intrinsics(self):
        compiler = Path(os.environ.get("OCOREC", str(baseline.ROOT / "target/debug/ocorec")))
        if not compiler.is_file():
            self.skipTest("built O-core compiler required")
        for triple in baseline.TRIPLES:
            for declaration in DECLARATIONS:
                with self.subTest(triple=triple, declaration=declaration):
                    source = self.root / "external.ll"
                    source.write_text(promises.module_text(triple, "declare " + declaration))
                    original = importer.import_module(source, library_path=self.library)
                    altered = copy.deepcopy(original)
                    altered["functions"][0]["linkage"] = "extern_weak"
                    path = self.root / "forged.json"
                    path.write_text(json.dumps(altered))
                    receipt = self.root / "receipt.json"
                    result = subprocess.run([str(compiler), str(path), "--input-kind", "native-ir",
                                             "--verify-native", "--receipt", str(receipt)],
                                            capture_output=True, text=True, timeout=30)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("intrinsic", result.stderr.lower())
                    self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
