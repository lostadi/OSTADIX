"""Whole real CPython token-unit proof and fail-closed input regressions.

Set OCORE_TEST_CPYTHON_CAPTURE, OCORE_TEST_CPYTHON_MODULE and
OCORE_TEST_CPYTHON_OBJECT to actual immutable capture/import artifacts. No
replacement token implementation or fabricated native module is used.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ocore_token_proof", ROOT / "scripts/check_ocore_cpython_token.py")
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class WholeCPythonTokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = ("OCORE_TEST_CPYTHON_CAPTURE", "OCORE_TEST_CPYTHON_MODULE", "OCORE_TEST_CPYTHON_OBJECT")
        if not all(os.environ.get(name) for name in names):
            raise unittest.SkipTest("actual immutable CPython capture/native module/own object inputs required: " + ", ".join(names))
        cls.capture, cls.module, cls.object = [Path(os.environ[name]).resolve() for name in names]
        sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(Path.home() / ".cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin")))
        cls.args = argparse.Namespace(capture=cls.capture, native_ir=cls.module, object=cls.object,
                                      ocorec=Path(os.environ.get("OCORE_TEST_OCOREC", str(ROOT / "target/debug/ocorec"))),
                                      clang=str(sdk / "clang"), objcopy=str(sdk / "llvm-objcopy"), nm=str(sdk / "llvm-nm"))
        for path in [cls.capture, cls.module, cls.object, cls.args.ocorec,
                     *[Path(getattr(cls.args, name)) for name in ("clang", "objcopy", "nm")]]:
            if not path.is_file():
                raise RuntimeError("declared real proof input missing: " + str(path))
        cls.original_module = json.loads(cls.module.read_text())
        cls.capture_hash = proof.info(cls.capture)["sha256"]

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-cpython-token-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.args = copy.copy(type(self).args)

    def changed_module(self):
        module = copy.deepcopy(self.original_module)
        path = self.directory / "changed.native-ir.json"
        self.args.native_ir = path
        return module, path

    def test_whole_original_source_exhaustive_and_corrupt_oracle(self):
        receipt = proof.prove(self.args, self.directory)
        self.assertEqual(receipt["capture"]["sha256"], self.capture_hash)
        self.assertEqual(receipt["exhaustive_byte_cases"], {"one": 256, "two": 65536, "three": 16777216})
        self.assertEqual(receipt["int32_boundary_cases"], 12719)
        self.assertEqual(receipt["function_definitions"], 3)
        self.assertEqual(receipt["globals"], 69)
        self.assertEqual(receipt["token_name_count"], 67)
        self.assertTrue(receipt["independently_corrupted_oracle_rejected"])
        self.assertTrue(receipt["reproducible_own_object"])
        for name in ("all_three_equivalent", "dependency_closure_complete", "native_execution_qualified", "runtime_complete"):
            self.assertFalse(receipt[name], name)

    def test_changed_llvm_provenance_rejected_before_lowering(self):
        module, path = self.changed_module()
        module["provenance"]["input_sha256"] = "0" * 64
        path.write_text(json.dumps(module))
        with self.assertRaisesRegex(ValueError, "exact captured whole LLVM unit"):
            proof.prove(self.args, self.directory)
        self.assertFalse((self.directory / "ocorec").exists())

    def test_missing_original_function_rejected_before_lowering(self):
        module, path = self.changed_module()
        module["functions"].pop()
        path.write_text(json.dumps(module))
        with self.assertRaisesRegex(ValueError, "all three original function definitions"):
            proof.prove(self.args, self.directory)
        self.assertFalse((self.directory / "ocorec").exists())

    def test_retargeted_host_module_rejected_before_lowering(self):
        module, path = self.changed_module()
        module["target"]["triple"] = "aarch64-unknown-linux-gnu"
        path.write_text(json.dumps(module))
        with self.assertRaisesRegex(ValueError, "original frontend target or DataLayout"):
            proof.prove(self.args, self.directory)
        self.assertFalse((self.directory / "ocorec").exists())


if __name__ == "__main__":
    unittest.main()
