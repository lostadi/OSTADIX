"""Source packaging controls only; these do not execute the new Rust route."""
import hashlib
import importlib.util
from pathlib import Path
import posixpath
import unittest
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('provider_closure_lexer',ROOT/'tests/test_ocore_aot_native_source_closure.py')
LEX=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEX)
ENTRY='src/bin/olangc/native_runtime.rs'
ASSET='src/bin/olangc/native_runtime/source_inventory.py'

def closure(root=ENTRY):
    files={};pending=[root]
    while pending:
        name=pending.pop()
        if name in files:continue
        text=(ROOT/name).read_text();files[name]=text
        if not name.endswith('.rs'):continue
        for _,path in LEX.source_dependencies(name,text):
            pending.append(path)
        tokens=LEX.runtime_tokens(text);values=[v for _,v in tokens]
        for i,token in enumerate(tokens):
            if token in [('word','include_str'),('word','include_bytes')] and values[i+1:i+3]==['!','(']:
                if tokens[i+3][0]!='string':raise AssertionError('nonliteral source asset')
                pending.append(posixpath.normpath(posixpath.join(posixpath.dirname(name),tokens[i+3][1])))
    return files

class ProviderGroupSourceClosureTests(unittest.TestCase):
    def test_new_rust_and_python_dependencies_are_in_actual_compiler_closure(self):
        files=closure()
        for name in ['provider_group.rs','whole_artifact.rs','artifact.rs','source_recipe.rs','source_inventory.py']:
            self.assertIn('src/bin/olangc/native_runtime/'+name,files)
    def test_omitted_production_python_asset_is_detected(self):
        files=closure();self.assertIn(ASSET,files)
        files.pop(ASSET)
        referenced=False
        for name,text in files.items():
            if not name.endswith('.rs'):continue
            tokens=LEX.runtime_tokens(text);values=[v for _,v in tokens]
            for i,t in enumerate(tokens):
                if t==('word','include_str') and values[i+1:i+3]==['!','(']:
                    path=posixpath.normpath(posixpath.join(posixpath.dirname(name),tokens[i+3][1]))
                    if path==ASSET:
                        referenced=True
                        with self.assertRaises(KeyError):files[path]
        self.assertTrue(referenced)
    def test_embedded_inventory_is_the_exact_reviewed_independent_source(self):
        self.assertEqual(hashlib.sha256((ROOT/ASSET).read_bytes()).hexdigest(),
            '22081d1138e4b8b021206d6e840a114f1bb8fbbda35c91acaab6cb46ad763793')
        self.assertEqual((ROOT/ASSET).read_bytes(),(ROOT/'tests/ocore_llvm_source_inventory.py').read_bytes())
    def test_production_inventory_driver_is_valid_python_without_test_imports(self):
        source=(ROOT/'src/bin/olangc/native_runtime/provider_group.rs').read_text()
        driver=source.split('const INVENTORY_DRIVER: &str = r#"',1)[1].split('"#;',1)[0]
        compile(driver,'embedded-production-inventory-driver','exec')
        self.assertNotIn('sys.path',driver)
        self.assertNotIn('tests/',driver)

    def test_unknown_intrinsic_mapping_fails_with_specific_inventory_mismatch(self):
        spec=importlib.util.spec_from_file_location('provider_unknown_intrinsic_guard',ROOT/ASSET)
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        # A source sqrt site cannot be relabeled as a different typed operation.
        # This exercises the independent predicate only, not frontend execution.
        ty={'kind':'float','bits':64}
        site={'name':'llvm.sqrt.f64','args':[{'kind':'value','id':0}],
            'arg_types':[ty],'result_type':ty,'block':0,'source_instruction':0,'result_id':1}
        function={'name':'authored_inventory_boundary','params':[{'id':0,'ty':0}],
            'blocks':[{'id':0,'instructions':[{'result':{'id':1,'ty':0},
                'operation':{'op':'float_neg','value':{'kind':'value','id':0}}}]}]}
        with self.assertRaisesRegex(helper.InventoryMismatch,
                r'^independent intrinsic mapping is unavailable: llvm\.sqrt\.f64$'):
            helper.intrinsic_mapping(site,function,[ty])

if __name__=='__main__':unittest.main(verbosity=2)
