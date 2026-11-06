"""Actual public source/provider path preserves the richer vector inventory.

This complete authored project and scalar-API reference check are compiler
regressions, not qualification of an unchanged upstream runtime or hardware.
"""
import json
from pathlib import Path
import subprocess
import unittest

from tests import test_ocore_native_strict_source_recipe as strict


class VectorSourceRecipeTests(unittest.TestCase):
    setUpClass = classmethod(strict.StrictSourceRecipeTests.setUpClass.__func__)
    setUp = strict.StrictSourceRecipeTests.setUp
    source_snapshot = strict.StrictSourceRecipeTests.source_snapshot
    write_recipe = strict.StrictSourceRecipeTests.write_recipe
    invoke = strict.StrictSourceRecipeTests.invoke
    assert_original_source = strict.StrictSourceRecipeTests.assert_original_source
    assert_bound_receipt_files = strict.StrictSourceRecipeTests.assert_bound_receipt_files
    command = strict.StrictSourceRecipeTests.command

    def test_full_original_make_capture_vector_inventory_and_native_execution(self):
        self.commands = []
        (self.source/"runtime.c").write_text(
            "typedef unsigned long long v2 __attribute__((vector_size(16)));\n"
            "void engine_vector_add(v2 *out,const v2 *left,const v2 *right){*out=*left+*right;}\n")
        # A distinct complete original fixture is pinned before its original
        # Make executes; no post-capture source or frontend IR surgery occurs.
        for argv in (["git","add","runtime.c"], ["git","-c","user.name=Compiler QA",
                    "-c","user.email=compiler-qa@localhost","commit","-qm","vector source fixture"]):
            self.command(argv, cwd=self.source)
        revision = subprocess.check_output(["git","rev-parse","HEAD"],cwd=self.source,text=True).strip()
        self.recipe["source"]["revision"] = revision
        self.write_recipe()
        self.original_source = self.source_snapshot()
        result, output = self.invoke(kind="obj")
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        receipt = json.loads((output/"source-recipe.json").read_text())
        self.assertTrue(receipt["lowering_complete"])
        self.assertFalse(receipt["runtime_complete"])
        self.assertFalse(receipt["native_execution_qualified"])
        self.assert_bound_receipt_files(receipt)
        packet = json.loads((output/"lowered/runtime.native-ir.json").read_text())
        self.assertEqual(len(packet["modules"]), 2)
        modules = [json.loads(item["native_ir"]) for item in packet["modules"]]
        self.assertTrue(any(ty["kind"]=="vector" for m in modules for ty in m["types"]))
        self.assertTrue(any(i["operation"]["op"]=="binary" and i.get("result") is not None
                            and m["types"][i["result"]["ty"]]["kind"]=="vector"
                            for m in modules for fn in m["functions"] for b in fn["blocks"]
                            for i in b["instructions"]))
        harness = self.case/"vector-carrier.c"
        harness.write_text("typedef unsigned long long u64;\n"
            "extern void engine_vector_add(u64*,const u64*,const u64*);\n"
            "int main(void){_Alignas(16) u64 a[2],b[2],r[2];for(u64 i=0;i<4096;++i){"
            "a[0]=i;a[1]=~i;b[0]=~i;b[1]=i+7;engine_vector_add(r,a,b);"
            "if(r[0]!=a[0]+b[0]||r[1]!=a[1]+b[1])return 31;}return 0;}\n")
        for label, objects in (("original",sorted((output/"build").glob("*.o"))),
                               ("owned",sorted((output/"lowered").glob("unit-*/module.o")))):
            self.assertEqual(len(objects), 2)
            executable=self.case/(label+"-vector-carrier")
            self.command([self.sdk/"clang","-no-pie",harness,*objects,"-o",executable])
            self.command([executable])
        self.assert_original_source()
        (self.case/"vector-source-recipe-result.json").write_text(json.dumps({
            "ok":True,"schema":"ostadix.vector-source-recipe-qualification/v1",
            "source_recipe":str(output/"source-recipe.json"),"checks_per_carrier":8192,
            "commands":self.commands,"scope":"complete compiler fixture public capture, independent vector inventory and scalar-API native/reference execution"},indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
