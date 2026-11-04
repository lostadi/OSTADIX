"""Exact source effects; new Rust/native/package phases are explicitly unrun."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
LIB = Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/riscv64-linux-gnu/libLLVM.so.22.1')
PIN = '8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83'
package = types.ModuleType('scripts'); package.__path__ = [str(ROOT/'scripts')]; sys.modules['scripts'] = package

def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
importer=load('scripts.ocore_llvm_import',ROOT/'scripts/ocore_llvm_import.py')
inventory=load('nonlocal_effect_inventory',ROOT/'tests/ocore_llvm_source_inventory.py')
HEADER='target triple = "riscv64-unknown-linux-gnu"\ntarget datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"\n'

def fixture(call_effect=True, declaration_effect=True):
    return HEADER+f'''@original_marker = global i64 1234567,align 8
    declare i32 @checkpoint(ptr) {'returns_twice' if declaration_effect else ''}
    declare i32 @original_cold(ptr) returns_twice
    define i32 @caller(ptr %first,ptr %second) {{
      %result=call i32 @checkpoint(ptr %first) {'returns_twice' if call_effect else ''}
      ret i32 %result
    }}
    !llvm.module.flags = !{{!0}}
    !0 = !{{i32 1, !"target-abi", !"lp64d"}}
    '''

def artifact(path):
    p=Path(path);b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

class NonlocalEffectSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=Path(tempfile.mkdtemp(prefix='nonlocal-effects-',dir=os.environ.get('OCORE_NONLOCAL_RETAIN','/tmp')))
        cls.reader=inventory.Reader(LIB,PIN);cls.records=[]
    @classmethod
    def tearDownClass(cls):
        p=cls.directory/'source-controls.json'
        p.write_text(json.dumps({'records':cls.records,'rust_verifier_executed':False,
            'native_execution_qualified':False,'package_admission_qualified':False,
            'provider_closure_complete':False,'runtime_accepted':False},indent=2)+'\n')
    def original(self,label,text=None,path=None):
        p=Path(path) if path else self.directory/(label+'.ll')
        if path is None:p.write_text(text)
        before=artifact(p)
        module=importer.import_module(p,LIB,expected_sha256=PIN)
        source=self.reader.read(p);proof=inventory.check_inventory(source,module)
        outputs={}
        for key,value in [('module',module),('source',source),('inventory',proof)]:
            out=self.directory/(label+'.'+key+'.json');out.write_text(json.dumps(value,indent=2)+'\n');outputs[key]=artifact(out)
        self.assertEqual(artifact(p),before)
        self.records.append({'positive':label,'original':before,**outputs})
        return module,source
    def mutation(self,label,module,source,message):
        p=self.directory/(label+'.mutant.native.json');p.write_text(json.dumps(module,indent=2)+'\n')
        with self.assertRaisesRegex(inventory.InventoryMismatch,message):inventory.check_inventory(source,module)
        self.records.append({'mutation':label,'module':artifact(p),'expected_diagnostic':message,
            'designed_native_verifier_validity_pending_new_compiler':True})
    def test_full_unchanged_original_ldo_retains_every_body_and_effect(self):
        p=Path('/home/orangepi/ostadix-BM/target/original-lua-source-recipe-20261017-ndpqjeew/compiled/capture/units/8af97646dd65432b9300e59054c1eb2a/unit-0.ll')
        self.assertEqual(artifact(p)['sha256'],'e27d6423252c664f74d85306e2d04faa6338cf99aad06eab975c5e539848b3fe')
        module,source=self.original('whole-original-ldo',path=p)
        self.assertEqual(len(module['functions']),61)
        self.assertEqual(sum(f['entry'] is not None for f in module['functions']),29)
        self.assertEqual({f['name'] for f in module['functions']},set(source['functions']))
        self.assertEqual({g['name'] for g in module['globals']},set(source['globals']))
        declaration=next(f for f in module['functions'] if f['name']=='_setjmp')
        self.assertEqual(declaration['control_effects'],{'returns_twice':True})
        f=next(f for f in module['functions'] if f['name']=='luaD_rawrunprotected')
        calls=[i['operation'] for b in f['blocks'] for i in b['instructions'] if i['operation']['op']=='call' and i['operation']['callee'].get('name')=='_setjmp']
        self.assertEqual(len(calls),1);self.assertEqual(calls[0]['control_effects'],{'returns_twice':True})
        self.assertEqual(calls[0]['signature']['result_attributes'],['signext'])
        self.assertEqual(module['target']['abi'],'lp64d')
    def test_declaration_and_site_effects_are_independent(self):
        for call,decl in [(True,True),(True,False),(False,True)]:
            with self.subTest(call=call,declaration=decl):
                module,source=self.original(f'independent-{call}-{decl}',fixture(call,decl))
                f=next(f for f in module['functions'] if f['name']=='checkpoint')
                c=next(f for f in module['functions'] if f['name']=='caller')['blocks'][0]['instructions'][0]['operation']
                self.assertEqual(f.get('control_effects',{}),{'returns_twice':True} if decl else {})
                self.assertEqual(c.get('control_effects',{}),{'returns_twice':True} if call else {})
                self.assertNotIn('control_effects',c['signature'])
    def test_declaration_and_site_omissions_do_not_pass_inventory(self):
        module,source=self.original('effect-positive',fixture())
        for kind in ['declaration','site','both','unused-declaration']:
            m=copy.deepcopy(module)
            if kind in ('declaration','both'):next(f for f in m['functions'] if f['name']=='checkpoint').pop('control_effects')
            if kind in ('site','both'):next(f for f in m['functions'] if f['name']=='caller')['blocks'][0]['instructions'][0]['operation'].pop('control_effects')
            if kind=='unused-declaration':next(f for f in m['functions'] if f['name']=='original_cold').pop('control_effects')
            self.mutation(kind,m,source,'function control effects changed' if kind!='site' else 'ordinary call control-effect site/operand inventory changed')
    def test_copied_declaration_effect_is_not_a_raw_site_effect(self):
        module,source=self.original('declaration-only',fixture(False,True));m=copy.deepcopy(module)
        next(f for f in m['functions'] if f['name']=='caller')['blocks'][0]['instructions'][0]['operation']['control_effects']={'returns_twice':True}
        self.mutation('invented-site-effect',m,source,'ordinary call control-effect site/operand inventory changed')
    def test_duplicate_unused_call_and_same_typed_operand_changes_fail(self):
        module,source=self.original('operand-positive',fixture())
        expected = {
            'duplicate': 'unaccounted ordinary direct call: caller',
            'different-buffer': 'ordinary direct call extension/operand site changed: caller/checkpoint',
        }
        for kind in ['duplicate','different-buffer']:
            with self.subTest(mutation=kind):
                m=copy.deepcopy(module)
                caller=next(f for f in m['functions'] if f['name']=='caller')
                b=caller['blocks'][0]
                if kind=='duplicate':
                    extra=copy.deepcopy(b['instructions'][0])
                    extra['result']['id']+=1
                    b['instructions'].append(extra)
                    self.assertEqual(len(b['instructions']),2)
                else:
                    original=b['instructions'][0]['operation']['args'][0]
                    replacement={'kind':'value','id':1}
                    self.assertEqual(original['kind'],'value')
                    self.assertNotEqual(original,replacement)
                    parameter_types={p['id']:p['ty'] for p in caller['params']}
                    self.assertEqual(parameter_types[original['id']],parameter_types[1])
                    self.assertEqual(m['types'][parameter_types[1]]['kind'],'pointer')
                    b['instructions'][0]['operation']['args'][0]=replacement
                self.mutation(kind,m,source,expected[kind])
    def test_indirect_returns_twice_is_an_explicit_import_refusal(self):
        text=HEADER+'define i32 @indirect(ptr %fn,ptr %buffer) { %r=call i32 %fn(ptr %buffer) returns_twice\n ret i32 %r }\n'
        p=self.directory/'unsupported-indirect.ll';p.write_text(text)
        with self.assertRaisesRegex(importer.ImportFailure,'returns_twice requires a direct ordinary'):
            importer.import_module(p,LIB,expected_sha256=PIN)
        self.records.append({'refused_source':artifact(p),'phase':'Python source import','native_execution':False})
    def test_non_c_effect_declaration_is_an_explicit_import_refusal(self):
        p=self.directory/'unsupported-fastcc.ll';p.write_text(HEADER+'declare fastcc i32 @foreign(ptr) returns_twice\n')
        with self.assertRaisesRegex(importer.ImportFailure,'returns_twice declaration requires an ordinary nonvariadic C function'):
            importer.import_module(p,LIB,expected_sha256=PIN)
        self.records.append({'refused_source':artifact(p),'phase':'Python source import','native_execution':False})

if __name__=='__main__':unittest.main()
