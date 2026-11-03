"""The optional monitor rejects incomplete/tampered native codec closures."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_codec", ROOT / "scripts/okernel_native_codec.py")
codec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codec)


@unittest.skipUnless(shutil.which("clang") and shutil.which("nm"), "native ELF fixture requires clang/nm")
class NativeCodecAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="native-codec-admission-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # These minimal objects test admission boundaries; they are not claimed
        # as original implementations or used for monitor/semantic qualification.
        definitions = [("convM2S",), ("convS2M",), ("convM2D", "statcheck"),
                       ("convD2M", "sizeD2M"), ("memcpy",), ("memmove",), ("strlen",)]
        objects = []
        for index, names in enumerate(definitions):
            source = self.root / f"unit-{index}.c"
            source.write_text("\n".join(f"unsigned long {name}(void) {{ return 0; }}" for name in names))
            output = source.with_suffix(".o")
            subprocess.run(["clang", "--target=aarch64-unknown-none", "-ffreestanding", "-c", str(source), "-o", str(output)], check=True, capture_output=True)
            objects.append(codec.identity(output))
        recipes, coverage, modules = [], [], []
        for index, selected in enumerate((objects[:4], objects[4:])):
            module = self.write_json(f"module-set-{index}.json", {"format": "ocore-native-module-set-v1"})
            modules.append(codec.identity(module))
            cover = self.write_json(f"coverage-{index}.json", {
                "schema": "ocore-runtime-lowering-v1", "architecture": "aarch64",
                "requested_target": "aarch64-unknown-none", "output_kind": "obj",
                "capture_complete": True, "module_set_complete": True,
                "native_module_dependency_closure_complete": True, "symbol_closure_complete": True,
                "required_lowering_unit_count": len(selected), "lowered_unit_count": len(selected),
                "module_set_artifact": modules[-1],
                "units": [{"required_for_lowering": True, "verified": True, "lowered": True, "object": item} for item in selected]})
            coverage.append(codec.identity(cover))
            recipe = self.write_json(f"recipe-{index}.json", {
                "schema": "ocore-native-source-recipe-v1", "stage": "complete",
                "requested_target": "aarch64-unknown-none", "output_kind": "obj",
                "success": True, "capture_complete": True, "lowering_complete": True,
                "lowering_receipt": coverage[-1]})
            recipes.append(codec.identity(recipe))
        evidence = self.root / "semantic-fixture"
        evidence.write_bytes(b"synthetic admission-only fixture, not execution evidence")
        semantic = {"ok": True, "stdout": "Original u9fs and musl via O-core: PASS; checks=fixture", **{name: codec.identity(evidence) for name in ("binary", "harness", "carrier")}}
        commands = self.write_json("commands.json", {"commands": [{"argv": [str(evidence)], "exit_code": 0, "stdout": semantic["stdout"]}]})
        self.manifest = {"schema": "ostadix.native-u9fs-codec/v1", "isa": "aarch64", "objects": objects,
                         "source_recipe_receipts": recipes, "coverage_receipts": coverage,
                         "native_module_sets": modules, "abi": codec.ABI,
                         "symbols": sorted(codec.SYMBOLS), "unresolved_symbols": [],
                         "semantic_test": semantic, "commands": codec.identity(commands)}
        self.path = self.write_json("manifest.json", self.manifest)

    def write_json(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return path

    def publish(self):
        self.write_json("manifest.json", self.manifest)

    def test_captures_exact_objects_and_receipts(self):
        result = codec.stage(self.path, self.root / "build")
        self.assertEqual(len(result["objects"]), 7)
        for source, captured in zip(self.manifest["objects"], result["objects"]):
            self.assertEqual(source["sha256"], captured["sha256"])
            self.assertNotEqual(source["path"], captured["path"])
            self.assertEqual(Path(captured["path"]).stat().st_mode & 0o222, 0)
        original = Path(self.manifest["objects"][0]["path"])
        original.write_bytes(b"changed after snapshot")
        self.assertTrue(codec.checked(result["objects"][0])[1].startswith(b"\x7fELF"))
        self.assertEqual(codec.checked(result["captured_manifest"])[1], self.path.read_bytes())

    def test_rejects_tampered_bytes_before_build_output(self):
        Path(self.manifest["objects"][0]["path"]).write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            codec.stage(self.path, self.root / "build")
        self.assertFalse((self.root / "build").exists())

    def test_rejects_wrong_isa_and_incomplete_semantics(self):
        for field, value in (("isa", "x86_64"), ("semantic_test", None), ("unresolved_symbols", ["host_function"])):
            original = self.manifest[field]
            self.manifest[field] = value; self.publish()
            with self.subTest(field=field), self.assertRaises(ValueError):
                codec.validate(self.path, "aarch64")
            self.manifest[field] = original

    def test_rejects_object_not_owned_by_lowering_receipt(self):
        # Updating a top-level digest does not authorize an object that was not
        # emitted by the recorded compiler-owned unit.
        path = Path(self.manifest["objects"][0]["path"])
        data = bytearray(path.read_bytes()); data[18:20] = (62).to_bytes(2, "little"); path.write_bytes(data)
        self.manifest["objects"][0] = codec.identity(path); self.publish()
        with self.assertRaisesRegex(ValueError, "compiler-owned"):
            codec.validate(self.path, "aarch64")

    def test_rejects_unverified_coverage_and_duplicate_recipe_chain(self):
        original = copy.deepcopy(self.manifest)
        self.manifest["source_recipe_receipts"][1] = self.manifest["source_recipe_receipts"][0]
        self.publish()
        with self.assertRaisesRegex(ValueError, "distinct coverage"):
            codec.validate(self.path, "aarch64")
        self.manifest = original
        record = self.manifest["coverage_receipts"][0]
        path = Path(record["path"]); value = json.loads(path.read_text()); value["symbol_closure_complete"] = False
        path.write_text(json.dumps(value)); self.manifest["coverage_receipts"][0] = codec.identity(path)
        recipe_record = self.manifest["source_recipe_receipts"][0]
        recipe_path = Path(recipe_record["path"]); value = json.loads(recipe_path.read_text())
        value["lowering_receipt"] = self.manifest["coverage_receipts"][0]
        recipe_path.write_text(json.dumps(value)); self.manifest["source_recipe_receipts"][0] = codec.identity(recipe_path)
        self.publish()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            codec.validate(self.path, "aarch64")

    def test_rejects_duplicate_module_chain_and_unbound_execution(self):
        original = copy.deepcopy(self.manifest)
        self.manifest["native_module_sets"][1] = self.manifest["native_module_sets"][0]
        self.publish()
        with self.assertRaises(ValueError):
            codec.validate(self.path, "aarch64")
        self.manifest = original
        self.manifest["semantic_test"]["stdout"] += " unbound"
        self.publish()
        with self.assertRaisesRegex(ValueError, "recorded successful"):
            codec.validate(self.path, "aarch64")

    def test_optional_profile_requires_native_namespace(self):
        import os
        for profile, namespace in (("withdrawal", "0"), ("package-domain", "0")):
            env = dict(os.environ, OCORE_LINUX_NATIVE_9P_MANIFEST=str(self.path), OCORE_LINUX_PROFILE=profile,
                       OCORE_LINUX_NAMESPACE=namespace, OCORE_LINUX_NETWORK="0", OCORE_LINUX_BUILD_DIR=str(self.root / "untouched"))
            result = subprocess.run(["bash", str(ROOT / "ocore/kernel/build-aarch64-kernel-world-linux.sh")], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("requires namespace=1", result.stderr)
            self.assertFalse((self.root / "untouched").exists())

if __name__ == "__main__":
    unittest.main()
