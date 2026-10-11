"""Original bytecode inventory and fail-closed native method coverage tests."""

import copy
import io
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

from scripts import ocore_java_inventory as java
from scripts import check_ocore_foreign_frontends as frontends


def u2(value):
    return struct.pack(">H", value)


def u4(value):
    return struct.pack(">I", value)


class ClassFixture:
    def __init__(self, name="test/Compiler"):
        self.pool = []
        self.name = self.class_entry(name)
        self.parent = self.class_entry("java/lang/Object")
        self.code_name = self.utf("Code")
        self.methods = []
        self.attributes = []
        self.access = 0x0421

    def entry(self, data):
        self.pool.append(data)
        return len(self.pool)

    def utf(self, text):
        data = text.encode("utf-8")
        return self.entry(b"\x01" + u2(len(data)) + data)

    def class_entry(self, name):
        return self.entry(b"\x07" + u2(self.utf(name)))

    def method(self, name, flags=0x0001, descriptor="()V", code=b"\xb1", code_count=None, handlers=()):
        method_name, method_type = self.utf(name), self.utf(descriptor)
        if code_count is None:
            code_count = 0 if flags & (0x0100 | 0x0400) else 1
        body = u2(1) + u2(1) + u4(len(code)) + code + u2(len(handlers))
        body += b"".join(u2(value) for handler in handlers for value in handler)
        body += u2(0)
        attrs = b"".join(u2(self.code_name) + u4(len(body)) + body for _ in range(code_count))
        self.methods.append(u2(flags) + u2(method_name) + u2(method_type) + u2(code_count) + attrs)
        return self

    def data(self, extra=b"", major=69):
        return (b"\xca\xfe\xba\xbe" + u2(0) + u2(major) + u2(len(self.pool) + 1) +
                b"".join(self.pool) + u2(self.access) + u2(self.name) + u2(self.parent) +
                u2(0) + u2(0) + u2(len(self.methods)) + b"".join(self.methods) +
                u2(len(self.attributes)) + b"".join(self.attributes) + extra)


class JavaInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.verifier = self.root / "ocorec"
        self.verifier.write_text("#!/bin/sh\nexit 0\n")
        self.verifier.chmod(0o755)

    def inventory(self, fixture=None):
        fixture = fixture or ClassFixture().method("compile")
        path = self.root / "Compiler.class"
        path.write_bytes(fixture.data())
        return java.inventory([("jdk.compiler", path)])

    def native_module(self, inventory, native_provider=False):
        functions = []
        for index, method in enumerate(inventory["methods"]):
            if method["kind"] != "code":
                continue
            functions.append({"name": f"java_method_{index}", "linkage": "external",
                              "signature": {"params": [], "result": 0, "abi": "C", "variadic": False},
                              "params": [], "entry": 0,
                              "blocks": [{"id": 0, "instructions": [], "terminator": {"op": "return", "value": None}}],
                              "managed_method": method["identity"]})
        if native_provider:
            functions.append({"name": "native_compile", "linkage": "external", "signature": functions[0]["signature"],
                              "params": [], "entry": 0, "blocks": functions[0]["blocks"], "managed_method": None})
        module = {"format": "ocore-native-module-v1", "name": "test", "types": [{"kind": "void"}],
                  "target": {"triple": "x86_64-unknown-none", "data_layout": "e-p:64:64", "pointer_bits": 64, "little_endian": True},
                  "semantics": "llvm_defined_behavior_v1", "globals": [], "functions": functions,
                  "provenance": {"input_sha256": "0" * 64, "frontend": "fixture", "frontend_version": "1",
                                 "importer": "fixture", "importer_version": "1", "source_function_count": len(functions),
                                 "source_global_count": 0, "refinements": []}}
        return module

    def write_module(self, value, name="module.json"):
        path = self.root / name
        java.write_json(path, value)
        return path

    def verification(self, command, **kwargs):
        staged, receipt = Path(command[1]), Path(command[-1])
        java.write_json(receipt, {"format": "ocore-native-verification-v1", "verifier": "ocore-native-v1",
                                  "module_sha256": java.sha256(staged.read_bytes()), "verified": True})
        return mock.Mock(returncode=0, stderr="")

    def compare(self, inventory, module, bindings=None):
        path = self.write_module(module)
        with mock.patch.object(java.subprocess, "run", side_effect=self.verification) as run:
            result = java.compare_inventory(inventory, [path], self.verifier, bindings)
            self.assertIn("--verify-native", run.call_args.args[0])
        return result

    def test_private_synthetic_constructors_and_class_initializers_are_included(self):
        fixture = (ClassFixture().method("<init>").method("<clinit>", 0x0008)
                   .method("privateCompile", 0x0002).method("lambda$compile$0", 0x100A)
                   .method("bridge", 0x1041).method("abstractCompile", 0x0401)
                   .method("nativeCompile", 0x0101))
        value = self.inventory(fixture)
        self.assertEqual(value["summary"]["code"], 5)
        self.assertEqual(value["summary"]["native"], 1)
        self.assertEqual(value["summary"]["abstract"], 1)
        self.assertFalse(value["lowering_complete"])
        self.assertEqual({m["identity"]["method_name"] for m in value["methods"]},
                         {"<init>", "<clinit>", "privateCompile", "lambda$compile$0", "bridge", "abstractCompile", "nativeCompile"})

    def test_malformed_class_magic_version_truncation_and_trailing_bytes(self):
        data = ClassFixture().method("compile").data()
        for malformed in (b"wrong", data[:-1], data + b"x", data[:6] + u2(70) + data[8:]):
            with self.subTest(malformed=malformed[:10]), self.assertRaises(java.InventoryError):
                java.parse_class(malformed)

    def test_malformed_constant_pool_reference(self):
        fixture = ClassFixture().method("compile")
        fixture.parent = 65535
        with self.assertRaisesRegex(java.InventoryError, "constant-pool reference"):
            java.parse_class(fixture.data())

    def test_invalid_constant_pool_tag_and_wide_slot(self):
        fixture = ClassFixture().method("compile")
        fixture.entry(b"\x02")
        with self.assertRaisesRegex(java.InventoryError, "tag"):
            java.parse_class(fixture.data())
        fixture = ClassFixture().method("compile")
        fixture.entry(b"\x05" + b"\0" * 8)
        with self.assertRaisesRegex(java.InventoryError, "long/double"):
            java.parse_class(fixture.data())

    def test_modified_utf8_null_and_supplementary_characters(self):
        self.assertEqual(java.modified_utf8(b"a\xc0\x80\xed\xa0\xbd\xed\xb8\x80"), "a\0😀")
        for data in (b"\0", b"\xc0\x81", b"\xe0\x80\x80", b"\xf0\x9f\x98\x80", b"\xed\xa0"):
            with self.subTest(data=data), self.assertRaises(java.InventoryError):
                java.modified_utf8(data)

    def test_duplicate_or_missing_code_and_native_code_are_rejected(self):
        for fixture in (ClassFixture().method("compile", code_count=0),
                        ClassFixture().method("compile", code_count=2),
                        ClassFixture().method("nativeCompile", 0x0101, code_count=1)):
            with self.assertRaisesRegex(java.InventoryError, "Code count"):
                java.parse_class(fixture.data())

    def test_duplicate_methods_and_invalid_descriptors(self):
        with self.assertRaisesRegex(java.InventoryError, "duplicate method"):
            java.parse_class(ClassFixture().method("compile").method("compile").data())
        for descriptor in ("V", "(V)V", "([V)V", "(L;)V", "()VX", "(I", "(" + "I" * 256 + ")V"):
            with self.subTest(descriptor=descriptor), self.assertRaisesRegex(java.InventoryError, "descriptor"):
                java.parse_class(ClassFixture().method("compile", descriptor=descriptor).data())

    def test_empty_code_and_bad_exception_ranges(self):
        with self.assertRaisesRegex(java.InventoryError, "code length"):
            java.parse_class(ClassFixture().method("compile", code=b"").data())
        with self.assertRaisesRegex(java.InventoryError, "exception-handler range"):
            java.parse_class(ClassFixture().method("compile", handlers=[(0, 2, 0, 0)]).data())

    def test_jmod_and_class_directory_have_identical_method_sets(self):
        fixture = ClassFixture().method("compile")
        directory = self.root / "classes"
        (directory / "test").mkdir(parents=True)
        (directory / "test/Compiler.class").write_bytes(fixture.data())
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("classes/test/Compiler.class", fixture.data())
        jmod = self.root / "jdk.compiler.jmod"
        jmod.write_bytes(b"JM\x01\x00" + buffer.getvalue())
        self.assertEqual(java.inventory([("jdk.compiler", directory)])["methods"],
                         java.inventory([("jdk.compiler", jmod)])["methods"])
        jmod.write_bytes(b"bad!" + buffer.getvalue())
        with self.assertRaisesRegex(java.InventoryError, "JMOD header"):
            java.inventory([("jdk.compiler", jmod)])

    def test_archive_path_traversal_and_class_name_mismatch(self):
        for name in ("../Compiler.class", "/Compiler.class", "wrong/Name.class"):
            path = self.root / "fixture.jar"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, ClassFixture().method("compile").data())
            with self.subTest(name=name), self.assertRaises(java.InventoryError):
                java.inventory([("jdk.compiler", path)])

    def test_multi_release_jar_selects_complete_current_version(self):
        path = self.root / "fixture.jar"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n")
            archive.writestr("test/Compiler.class", ClassFixture().method("oldCompile").data(major=52))
            archive.writestr("META-INF/versions/25/test/Compiler.class", ClassFixture().method("newCompile").data())
            archive.writestr("META-INF/versions/26/test/Compiler.class", ClassFixture().method("futureCompile").data(major=70))
        value = java.inventory([("jdk.compiler", path)])
        self.assertEqual([m["identity"]["method_name"] for m in value["methods"]], ["newCompile"])

    def test_exact_coverage_pass_is_not_runtime_or_semantic_completion(self):
        inventory = self.inventory()
        result = self.compare(inventory, self.native_module(inventory))
        self.assertTrue(result["exact_body_inventory_complete"])
        self.assertFalse(result["semantic_equivalence_verified"])
        self.assertFalse(result["runtime_complete"])

    def test_real_verifier_cannot_turn_source_identity_tags_into_java_semantics(self):
        """Real Java source + real verifier; deliberately wrong native bodies."""
        verifier = frontends.ROOT / "target/debug/ocorec"
        java_tool = shutil.which("java")
        if not verifier.is_file() or java_tool is None:
            self.skipTest("build current ocorec and install Java25 for the actual receipt counterexample")
        version = subprocess.run([java_tool,"-version"],capture_output=True,timeout=15)
        if b'version "25.' not in version.stderr:
            self.skipTest("Java25 source compiler/reference runtime unavailable")
        frontends.check_java(java_tool,self.root)
        inventory = java.load_json(self.root / "java-method-inventory.json")
        self.assertTrue(any(method["identity"]["descriptor"] == "(II)I"
                            for method in inventory["methods"]))
        # Every fake definition returns void and accepts no arguments, even
        # though its real original descriptor and bytecode hash are attached.
        module = self.native_module(inventory)
        path = self.write_module(module,"metadata-only-negative-control.json")
        result = java.compare_inventory(inventory,[path],verifier)
        self.assertEqual(result["code_methods"],24)
        self.assertTrue(result["exact_body_inventory_complete"])
        self.assertFalse(result["semantic_equivalence_verified"])
        self.assertFalse(result["runtime_complete"])
        evidence = result["verification"][0]
        self.assertEqual(evidence["module_sha256"],java.sha256(path.read_bytes()))
        self.assertEqual(evidence["receipt"]["scope"],"structural_ir_verification")
        # An empty definition cannot even acquire structural body coverage.
        module["functions"][0]["blocks"] = []
        empty = self.write_module(module,"empty-negative-control.json")
        with self.assertRaisesRegex(java.InventoryError,"verification failed"):
            java.compare_inventory(inventory,[empty],verifier)

    def test_declaration_empty_body_wrong_hash_or_duplicate_cannot_count(self):
        inventory = self.inventory()
        for change in ("declaration", "empty", "hash", "duplicate"):
            module = self.native_module(inventory)
            if change == "declaration":
                module["functions"][0].update(entry=None, blocks=[])
            elif change == "empty":
                module["functions"][0]["blocks"] = []
            elif change == "hash":
                module["functions"][0]["managed_method"] = copy.deepcopy(module["functions"][0]["managed_method"])
                module["functions"][0]["managed_method"]["code_sha256"] = "0" * 64
            else:
                module["functions"].append(copy.deepcopy(module["functions"][0]))
            with self.subTest(change=change), self.assertRaises(java.InventoryError):
                self.compare(inventory, module)

    def test_native_binding_requires_actual_verified_provider_body(self):
        inventory = self.inventory(ClassFixture().method("compile").method("nativeCompile", 0x0101))
        module = self.native_module(inventory, native_provider=True)
        native = next(m["identity"] for m in inventory["methods"] if m["kind"] == "native")
        with self.assertRaisesRegex(java.InventoryError, "unresolved native"):
            self.compare(inventory, module)
        path = self.write_module(module)
        bindings = {"format": java.EXPORT_FORMAT, "native_bindings": [{"method": native,
                    "provider_module_sha256": java.sha256(path.read_bytes()), "provider_symbol": "native_compile"}]}
        self.assertEqual(self.compare(inventory, module, bindings)["native_bindings"], 1)
        bindings["native_bindings"][0]["provider_symbol"] = "absent"
        with self.assertRaisesRegex(java.InventoryError, "no verified definition"):
            self.compare(inventory, module, bindings)

    def test_no_receipt_self_reported_verified_and_mismatched_receipt_fail(self):
        inventory = self.inventory()
        module = self.native_module(inventory)
        module["verified"] = True
        path = self.write_module(module)
        with mock.patch.object(java.subprocess, "run", return_value=mock.Mock(returncode=0, stderr="")):
            with self.assertRaisesRegex(java.InventoryError, "no verification receipt"):
                java.compare_inventory(inventory, [path], self.verifier)
        def wrong_receipt(command, **kwargs):
            java.write_json(Path(command[-1]), {"format": "ocore-native-verification-v1", "verifier": "ocore-native-v1",
                            "module_sha256": "0" * 64, "verified": True})
            return mock.Mock(returncode=0, stderr="")
        with mock.patch.object(java.subprocess, "run", side_effect=wrong_receipt):
            with self.assertRaisesRegex(java.InventoryError, "mismatched verification receipt"):
                java.compare_inventory(inventory, [path], self.verifier)

    def test_verifier_rejection_fails_closed(self):
        inventory = self.inventory()
        path = self.write_module(self.native_module(inventory))
        with mock.patch.object(java.subprocess, "run", return_value=mock.Mock(returncode=1, stderr="invalid SSA")):
            with self.assertRaisesRegex(java.InventoryError, "verification failed.*invalid SSA"):
                java.compare_inventory(inventory, [path], self.verifier)

    def test_duplicate_json_fields_and_altered_inventory_are_rejected(self):
        path = self.root / "bad.json"
        path.write_text('{"format":"good","format":"bad"}')
        with self.assertRaisesRegex(java.InventoryError, "duplicate JSON field"):
            java.load_json(path)
        inventory = self.inventory()
        inventory["methods"].append(copy.deepcopy(inventory["methods"][0]))
        with self.assertRaisesRegex(java.InventoryError, "duplicate inventory"):
            java.validate_inventory(inventory)

    def test_unresolved_declared_modules_are_not_complete(self):
        inventory = self.inventory()
        inventory["declared_dependency_closure"] = {"complete": False, "missing_modules": ["java.base"]}
        with self.assertRaisesRegex(java.InventoryError, "unresolved declared module"):
            java.validate_inventory(inventory)

    def test_loader_identity_differences_do_not_match(self):
        inventory = self.inventory()
        module = self.native_module(inventory)
        module["functions"][0]["managed_method"] = copy.deepcopy(module["functions"][0]["managed_method"])
        module["functions"][0]["managed_method"]["loader_namespace"] = "application"
        with self.assertRaisesRegex(java.InventoryError, "coverage mismatch"):
            self.compare(inventory, module)

    def test_different_target_realizations_are_compared_separately(self):
        inventory = self.inventory()
        first = self.native_module(inventory)
        second = copy.deepcopy(first)
        second["target"]["triple"] = "aarch64-unknown-none"
        with mock.patch.object(java.subprocess, "run", side_effect=self.verification):
            with self.assertRaisesRegex(java.InventoryError, "target layouts differ"):
                java.compare_inventory(inventory, [self.write_module(first), self.write_module(second, "second.json")], self.verifier)

    def test_cli_recomputes_source_inventory_instead_of_trusting_a_shrunk_list(self):
        inventory = self.inventory(ClassFixture().method("compile").method("coldCompile", 0x0002))
        inventory["methods"].pop()
        inventory_path = self.root / "inventory.json"
        java.write_json(inventory_path, inventory)
        path = self.write_module(self.native_module(inventory))
        with mock.patch.object(java.subprocess, "run") as run, mock.patch("sys.stderr", new=io.StringIO()) as error:
            status = java.main(["compare", "--inventory", str(inventory_path), "--native-module", str(path), "--verifier", str(self.verifier)])
        self.assertEqual(status, 1)
        self.assertIn("stale or altered Java inventory field: methods", error.getvalue())
        run.assert_not_called()

    def test_failed_recheck_removes_previous_coverage_receipt_and_preserves_inputs(self):
        inventory = self.inventory()
        inventory_path = self.root / "inventory.json"
        java.write_json(inventory_path, inventory)
        module = self.native_module(inventory)
        module["functions"][0].update(entry=None, blocks=[])
        module_path = self.write_module(module)
        output = self.root / "coverage.json"
        java.write_json(output, {"format": "ocore-java-method-coverage-v1", "exact_body_inventory_complete": True})
        with mock.patch.object(java.subprocess, "run", side_effect=self.verification), mock.patch("sys.stderr", new=io.StringIO()):
            status = java.main(["compare", "--inventory", str(inventory_path), "--native-module", str(module_path),
                                "--verifier", str(self.verifier), "--output", str(output)])
        self.assertEqual(status, 1)
        self.assertFalse(output.exists())
        original = inventory_path.read_bytes()
        with mock.patch("sys.stderr", new=io.StringIO()):
            status = java.main(["compare", "--inventory", str(inventory_path), "--native-module", str(module_path),
                                "--verifier", str(self.verifier), "--output", str(inventory_path)])
        self.assertEqual(status, 1)
        self.assertEqual(inventory_path.read_bytes(), original)

    def test_full_server_profile_cannot_silently_drop_jit_gc_desktop_or_source_modules(self):
        script = java.ROOT / "tools/ocore-runtime/java/check_profile.py"
        spec = importlib.util.spec_from_file_location("ocore_java_profile", script)
        profile = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profile)
        recipe = json.loads(script.with_name("openjdk.recipe.json").read_text())
        features = " ".join(recipe["required_hotspot_features"])
        text = (f"JVM_VARIANTS := server\nJVM_FEATURES_server := {features}\nENABLE_HEADLESS_ONLY := false\n"
                "IMPORT_MODULES_CLASSES :=\nIMPORT_MODULES_LIBS :=\nIMPORT_MODULES_CMDS :=\n")
        path = self.root / "spec.gmk"
        path.write_text(text)
        self.assertTrue(profile.check_spec(path, recipe)["full_profile_retained"])
        for changed in (text.replace("compiler2", ""), text.replace("g1gc", ""),
                        text.replace("server\n", "zero\n", 1), text.replace("false", "true"),
                        text.replace("IMPORT_MODULES_CLASSES :=", "IMPORT_MODULES_CLASSES := /ambient/classes")):
            path.write_text(changed)
            with self.subTest(spec=changed), self.assertRaises(ValueError):
                profile.check_spec(path, recipe)


if __name__ == "__main__":
    unittest.main()
