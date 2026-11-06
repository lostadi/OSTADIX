"""Independent source inventory for the combined strict-FP and funnel profiles.

These are preservation checks, not runtime/provider/executable qualification.
They read actual unchanged LLVM through a separate C-API reader.
"""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_optimizer_promises as promises

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "source_inventory_union", ROOT / "src/bin/olangc/native_runtime/source_inventory.py")
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class SourceInventoryUnionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="ocore-inventory-union-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def imported(self, body, triple="x86_64-unknown-linux-gnu"):
        path = self.root / "input.ll"
        path.write_text(promises.module_text(triple, body))
        before = path.read_bytes()
        native = importer.import_module(path, library_path=self.library)
        source = inventory.Reader(self.library, importer.PINNED_SHA256).read(path)
        self.assertEqual(path.read_bytes(), before)
        return source, native

    def test_function_and_callsite_strictfp_require_the_real_serialized_profile(self):
        for attributes in ("function", "callsite"):
            with self.subTest(attributes=attributes):
                source, native = self.imported(
                    'declare i64 @provider(i64)\n'
                    'define i64 @subject(i64 %x) '+('strictfp ' if attributes == "function" else '')+'{\n'
                    ' %r = call i64 @provider(i64 %x) '+('strictfp' if attributes == "callsite" else '')+'\n ret i64 %r\n}\n')
                self.assertTrue(source["strict_fp_required"])
                self.assertEqual(native["target"]["strict_fp_profile"], "integer_only_v1")
                inventory.check_inventory(source, native)
                for value in (None, "invented"):
                    changed = copy.deepcopy(native)
                    if value is None:
                        changed["target"].pop("strict_fp_profile")
                    else:
                        changed["target"]["strict_fp_profile"] = value
                    with self.assertRaisesRegex(inventory.InventoryMismatch, "strictfp requires"):
                        inventory.check_inventory(source, changed)

    def test_all_original_generic_widths_and_wide_funnels_have_exact_independent_graphs(self):
        for triple in baseline.TRIPLES:
            for width in (1, 7, 8, 37, 64, 128):
                with self.subTest(triple=triple, width=width):
                    body = (f'declare i{width} @llvm.fshl.i{width}(i{width},i{width},i{width})\n'
                            f'define i{width} @subject(i{width} %a,i{width} %b,i{width} %c) {{\n'
                            f' %r = call i{width} @llvm.fshl.i{width}(i{width} %a,i{width} %b,i{width} %c)\n'
                            f' ret i{width} %r\n}}\n')
                    source, native = self.imported(body, triple)
                    receipt = inventory.check_inventory(source, native)
                    self.assertFalse(receipt["executable_semantics_qualified"])
                    changed = copy.deepcopy(native)
                    fn = next(f for f in changed["functions"] if f["name"] == "subject")
                    operation = next(i["operation"] for b in fn["blocks"] for i in b["instructions"]
                                     if i["operation"].get("kind") == "u_rem")
                    operation["kind"] = "and"
                    with self.assertRaises(inventory.InventoryMismatch):
                        inventory.check_inventory(source, changed)

    def test_extra_unexecuted_funnel_graph_nodes_are_not_accepted_as_preservation(self):
        source, native = self.imported('''
declare i7 @llvm.fshr.i7(i7,i7,i7)
define i7 @subject(i7 %a,i7 %b,i7 %c) {
 %r = call i7 @llvm.fshr.i7(i7 %a,i7 %b,i7 %c)
 ret i7 %r
}
''')
        inventory.check_inventory(source, native)
        fn = next(f for f in native["functions"] if f["name"] == "subject")
        block = fn["blocks"][0]
        new_id = 1 + max(i["result"]["id"] for i in block["instructions"] if i.get("result"))
        original = next(i for i in block["instructions"] if i["operation"]["op"] == "freeze")
        extra = copy.deepcopy(original)
        extra["result"]["id"] = new_id
        block["instructions"].append(extra)
        with self.assertRaisesRegex(inventory.InventoryMismatch, "primitive inventory"):
            inventory.check_inventory(source, native)

    def test_rich_vector_census_rejects_mutation_omission_and_unused_extra_operations(self):
        for triple in baseline.TRIPLES:
            with self.subTest(triple=triple):
                source, native = self.imported('''
define void @subject(ptr %out,ptr %a,ptr %b) {
 %x = load <2 x i64>, ptr %a, align 16
 %y = load <2 x i64>, ptr %b, align 16
 %r = add <2 x i64> %x,%y
 store <2 x i64> %r,ptr %out,align 16
 ret void
}
''', triple)
                self.assertEqual(len(source["functions"]["subject"]["vector_sites"]), 4)
                inventory.check_inventory(source, native)
                for mutation in ("operation", "omission", "extra"):
                    altered = copy.deepcopy(native)
                    block = altered["functions"][0]["blocks"][0]
                    addition = next(i for i in block["instructions"]
                                    if i["operation"].get("kind") == "add")
                    if mutation == "operation":
                        addition["operation"]["kind"] = "sub"
                    elif mutation == "omission":
                        block["instructions"].remove(addition)
                    else:
                        extra = copy.deepcopy(addition)
                        extra["result"]["id"] += 1000
                        block["instructions"].append(extra)
                    with self.assertRaisesRegex(inventory.InventoryMismatch, "vector operation"):
                        inventory.check_inventory(source, altered)


if __name__ == "__main__":
    unittest.main()
