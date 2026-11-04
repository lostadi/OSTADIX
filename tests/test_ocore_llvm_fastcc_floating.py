"""Original LLVM source/witness accounting; no Rust or native execution proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def load(name, relative):
    path = (ROOT / relative).resolve()
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    assert Path(module.__file__).resolve() == path
    return module

BITCODE = load("ocore_llvm_bitcode", "scripts/ocore_llvm_bitcode.py")
IMPORT = load("fastcc_source_importer", "scripts/ocore_llvm_import.py")
INV = load("fastcc_independent_inventory", "tests/ocore_llvm_source_inventory.py")
PROFILES = (
    ("x86_64", "x86_64-unknown-linux-gnu", None, "x86-64", "+sse,+sse2"),
    ("aarch64", "aarch64-unknown-linux-gnu", None, "generic", "+fp-armv8,+neon,+v8a"),
    ("rv-lp64", "riscv64-unknown-linux-gnu", "lp64", "generic-rv64", "+64bit,+d,-d,+d,+f,+zicsr,-e"),
    ("rv-lp64d", "riscv64-unknown-linux-gnu", "lp64d", "generic-rv64", "+64bit,+d,-d,+d,+f,+zicsr,-e"),
)
LCODE = Path("/home/orangepi/ostadix-BM/target/original-lua-source-recipe-20261017-ndpqjeew/compiled/capture/units/6e43423129c743c88ba0d6fa84eb8840/unit-0.ll")
LCODE_SHA = "e5720886ca921015c497c8d3fc8309642dc1de5eec8a7efac9727a284df78b61"

class FastFloatingSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Missing required source/parser prerequisites are failures, never skips.
        cls.library = Path(os.environ["OCORE_TEST_LLVM_LIBRARY"]).resolve()
        cls.pin = os.environ["OCORE_TEST_LLVM_SHA256"]
        if not re.fullmatch(r"[0-9a-f]{64}", cls.pin):
            raise RuntimeError("explicit lowercase LLVM SHA-256 required")
        if hashlib.sha256(cls.library.read_bytes()).hexdigest() != cls.pin:
            raise RuntimeError("actual LLVM parser hash differs")
        cls.reader = INV.Reader(cls.library, cls.pin)

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_RETAIN_SOURCE_FIXTURES")
        if retained:
            Path(retained).mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="fastcc-source-", dir=retained))
        else:
            temp = tempfile.TemporaryDirectory(prefix="fastcc-source-")
            self.addCleanup(temp.cleanup)
            self.directory = Path(temp.name)

    def import_path(self, path, stem):
        module = IMPORT.import_module(path, library_path=self.library, expected_sha256=self.pin)
        source = self.reader.read(path)
        proof = INV.check_inventory(source, module)  # mandatory genuine baseline
        for suffix, data in [("module", module), ("source", source), ("inventory", proof)]:
            (self.directory / f"{stem}.{suffix}.json").write_text(json.dumps(data, indent=2) + "\n")
        return module, source

    def fixture(self, profile):
        name, triple, abi, cpu, features = profile
        metadata = ('\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"' + abi + '"}\n') if abi else ""
        body = f'''target triple = "{triple}"
target datalayout = "e-p:64:64-i64:64-i128:128-n32:64-S128"
@anchor = global i64 7, align 8
@function_slot = constant ptr @callee, align 8
define fastcc double @callee(double %x) #0 {{ ret double %x }}
define double @caller(double %x) #1 {{
entry:
 %r = call fastcc double @callee(double %x)
 ret double %r
}}
declare fastcc float @external_fast(float)
declare i64 @kept_external(i64)
attributes #0 = {{ "target-cpu"="{cpu}" "target-features"="{features}" }}
attributes #1 = {{ "target-cpu"="{cpu}" "target-features"="{features}" }}
{metadata}'''
        path = self.directory / (name + ".ll")
        path.write_text(body)
        return self.import_path(path, name)

    def reject_inventory(self, source, module, message, stem):
        (self.directory / (stem + ".mutant.json")).write_text(json.dumps(module, indent=2) + "\n")
        with self.assertRaisesRegex(INV.InventoryMismatch, re.escape(message)) as raised:
            INV.check_inventory(source, module)
        (self.directory / (stem + ".rejection.txt")).write_text(str(raised.exception) + "\n")
        # New native verification of these mutations remains explicitly UNRUN
        # until a compiler embedding this exact source is built and admitted.

    def test_verbatim_witnesses_on_four_source_profiles(self):
        for profile in PROFILES:
            with self.subTest(profile=profile[0]):
                module, source = self.fixture(profile)
                self.assertEqual(module["target"]["triple"], profile[1])
                self.assertEqual(module["target"].get("abi"), profile[2])
                self.assertEqual(len(module["functions"]), 4)
                self.assertEqual(len(module["globals"]), 2)
                for function in module["functions"]:
                    if function["entry"] is not None:
                        self.assertEqual(function["source_abi"], {"target_cpu": profile[3], "target_features": profile[4]})
                self.assertEqual(source["target_triple"], profile[1])

    def test_original_complete_lcode_inventory_and_both_callers(self):
        path = Path(os.environ.get("OCORE_TEST_LUA_LCODE_LL", str(LCODE)))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), LCODE_SHA)
        module, source = self.import_path(path, "original-whole-lcode")
        self.assertEqual(len(module["functions"]), 73)
        self.assertEqual(sum(f["entry"] is not None for f in module["functions"]), 51)
        self.assertEqual(len(module["globals"]), 10)
        functions = {f["name"]: f for f in module["functions"]}
        for name in ["luaK_exp2K", "discharge2reg", "luaK_numberK"]:
            self.assertEqual(functions[name]["source_abi"], source["functions"][name]["source_abi"])
            self.assertEqual(functions[name]["source_abi"]["target_cpu"], "generic-rv64")
        calls = [i["operation"] for f in module["functions"] for b in f["blocks"] for i in b["instructions"]
                 if i["operation"]["op"] == "call" and i["operation"]["callee"].get("name") == "luaK_numberK"]
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(c["signature"] == functions["luaK_numberK"]["signature"] for c in calls))

    def test_changed_missing_and_extra_witness_rejected(self):
        module, source = self.fixture(PROFILES[2])
        for change in ["missing", "ordered_features", "extra_payload"]:
            with self.subTest(change=change):
                mutant = copy.deepcopy(module)
                f = next(f for f in mutant["functions"] if f["name"] == "callee")
                if change == "missing":
                    del f["source_abi"]
                elif change == "ordered_features":
                    f["source_abi"]["target_features"] += ",+d"  # same proved map, changed original bytes
                else:
                    f["source_abi"]["replacement_ir"] = "forbidden"
                self.reject_inventory(source, mutant, "function source ABI witness changed: callee", change)

    def test_caller_and_callee_witnesses_accounted_independently(self):
        module, source = self.fixture(PROFILES[0])
        for name in ["caller", "callee"]:
            with self.subTest(function=name):
                mutant = copy.deepcopy(module)
                next(f for f in mutant["functions"] if f["name"] == name)["source_abi"]["target_features"] += ",+sse2"
                self.reject_inventory(source, mutant, "function source ABI witness changed: " + name, name)

    def test_original_module_os_triple_accounted(self):
        for profile in PROFILES:
            with self.subTest(profile=profile[0]):
                module, source = self.fixture(profile)
                mutant = copy.deepcopy(module)
                mutant["target"]["triple"] = profile[1].replace("-unknown-", "-pc-")
                self.reject_inventory(source, mutant, "original source target triple changed", profile[0] + "-triple")

    def test_external_declarations_remain_open_without_invented_witness(self):
        module, source = self.fixture(PROFILES[3])
        for name in ["external_fast", "kept_external"]:
            function = next(f for f in module["functions"] if f["name"] == name)
            self.assertIsNone(function["entry"])
            self.assertNotIn("source_abi", function)
            self.assertIsNone(source["functions"][name]["source_abi"])

if __name__ == "__main__":
    unittest.main()
