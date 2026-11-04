"""Source-preservation controls for narrowly proved C argument transport.

These run the candidate Python importer and an independent pinned LLVM22 reader.
They do not claim that the new Rust ABI admission has been compiled or executed.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from scripts import ocore_llvm_import as importer
from tests.ocore_llvm_source_inventory import Reader, check_inventory, InventoryMismatch

ROOT=Path(__file__).resolve().parents[1]
LIBRARY=Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/riscv64-linux-gnu/libLLVM.so.22.1')
PIN='8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83'
HEADER='target triple = "riscv64-unknown-linux-gnu"\ntarget datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"\n'
FLAGS='!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64d"}\n'

def artifact(path):
    p=Path(path).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def fixture():
    return HEADER+r'''
@original_marker = global i64 123456789,align 8
declare i64 @consume(i32 signext,ptr)
declare void @sink(i32)
declare signext i32 @original_unused(i16 signext)
define signext i32 @original_cold(i32 signext %a) { ret i32 %a }
define i64 @literal() {
 %r=call i64 @consume(i32 10,ptr @original_marker)
 ret i64 %r
}
define i64 @from_byte(i8 %a,i8 %b) {
 %x=zext i8 %a to i32
 %y=zext i8 %b to i32
 %r=call i64 @consume(i32 %x,ptr @original_marker)
 ret i64 %r
}
define void @twice() {
 call void @sink(i32 9)
 call void @sink(i32 9)
 ret void
}
'''+FLAGS

class CallAbiExtensionSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=Path(tempfile.mkdtemp(prefix='call-abi-source-',dir=os.environ.get('OCORE_CALL_ABI_RETAIN')))
        cls.reader=Reader(LIBRARY,PIN);cls.records=[]
        cls.paths=[ROOT/p for p in ['scripts/ocore_llvm_import.py','scripts/ocore_llvm_bitcode.py','crates/ostadix-api/src/ocore/native_abi.rs','crates/ostadix-api/src/ocore/native_verify.rs','tests/ocore_llvm_source_inventory.py','tests/test_ocore_llvm_call_abi_extensions.py']]
        cls.before=[artifact(p) for p in cls.paths]
    @classmethod
    def tearDownClass(cls):
        after=[artifact(p) for p in cls.paths]
        d={'schema':'ocore-call-abi-extension-source-controls-v1','before':cls.before,'after':after,'source_stable':cls.before==after,'records':cls.records,'new_compiler_built':False,'rust_admission_executed':False,'native_execution_qualified':False,'runtime_accepted':False,'provider_closure_complete':False,'other_abi_storage_metadata_semantics_qualified':False}
        (cls.directory/'receipt.json').write_text(json.dumps(d,indent=2)+'\n')
        if cls.before!=after:raise AssertionError('source changed during source controls')
    def existing(self,label,path):
        before=artifact(path);module=importer.import_module(Path(path),LIBRARY,expected_sha256=PIN);source=self.reader.read(path);proof=check_inventory(source,module)
        outputs={}
        for suffix,value in [('native',module),('source',source),('preservation',proof)]:
            p=self.directory/(label+'.'+suffix+'.json');p.write_text(json.dumps(value,indent=2)+'\n');outputs[suffix]=artifact(p)
        self.assertEqual(artifact(path),before)
        self.records.append({'label':label,'original':before,**outputs})
        return module,source
    def imported(self,label,text=None):
        path=self.directory/(label+'.ll');path.write_text(fixture() if text is None else text);return self.existing(label,path)
    def mutant(self,label,source,module,diagnostic):
        p=self.directory/(label+'.mutant.native.json');p.write_text(json.dumps(module,indent=2)+'\n')
        with self.assertRaisesRegex(InventoryMismatch,diagnostic):check_inventory(source,module)
        self.records.append({'mutant':label,'module':artifact(p),'diagnostic':diagnostic,'native_verifier_validity_pending_new_compiler':True})
    def test_preserves_actual_declaration_and_call_extension_vectors(self):
        module,source=self.imported('extensions-positive')
        declaration=next(f for f in module['functions'] if f['name']=='consume')
        caller=next(f for f in module['functions'] if f['name']=='from_byte')
        operation=next(i['operation'] for i in caller['blocks'][0]['instructions'] if i['operation']['op']=='call')
        self.assertEqual(declaration['signature']['param_attributes'],[['signext'],[]])
        self.assertTrue(all(not attrs for attrs in operation['signature']['param_attributes']))
        self.assertEqual(source['functions']['from_byte']['direct_call_sites'][0]['extension_attributes'],{'params':[[],[]],'result':[]})
        self.assertEqual(source['functions']['consume']['extension_attributes'],{'params':[['signext'],[]],'result':[]})
    def test_all_three_unchanged_original_lua_units_remain_whole(self):
        root=Path('/home/orangepi/ostadix-BM/target/original-lua-source-recipe-20261017-ndpqjeew/compiled/capture/units')
        for name,uid,pin in [('lauxlib','8173005d64a1415b9774d85142de841c','8c1520893a424b6165d71d485036d485270a40fee82b42b313d03bbc4972c9ae'),('lbaselib','e026707dae024cf4b1466b7906f9fc64','e7c8a52ba24a7b4be56f7dee5cb9fe0e46c80b37a71e6c4bb073f6a6094dc486'),('liolib','f4115f7922524b8cb6d4e11ec4736e79','3735b84b7fdc7906413ef23fc3200cce95951b39fac8a8df87686d5e5577790d')]:
            with self.subTest(unit=name):
                path=root/uid/'unit-0.ll';self.assertEqual(artifact(path)['sha256'],pin)
                module,source=self.existing('whole-'+name,path)
                self.assertEqual(module['target']['abi'],'lp64d')
                self.assertEqual({f['name'] for f in module['functions']},set(source['functions']))
                self.assertEqual({g['name'] for g in module['globals']},set(source['globals']))
    def test_changed_declaration_or_copied_call_attrs_cannot_pass(self):
        module,source=self.imported('extension-mutation-positive')
        for fault in ('drop-declaration','copy-into-call','zeroext-call','drop-cold-result'):
            mutant=copy.deepcopy(module)
            if fault=='drop-declaration':next(f for f in mutant['functions'] if f['name']=='consume')['signature']['param_attributes']=[]
            elif fault=='drop-cold-result':next(f for f in mutant['functions'] if f['name']=='original_cold')['signature']['result_attributes']=[]
            else:
                f=next(f for f in mutant['functions'] if f['name']=='from_byte');call=next(i['operation'] for i in f['blocks'][0]['instructions'] if i['operation']['op']=='call')
                call['signature']['param_attributes']=[['signext' if fault=='copy-into-call' else 'zeroext'],[]]
            message='function integer extension attributes changed' if fault in ('drop-declaration','drop-cold-result') else 'ordinary direct call extension/operand site changed'
            self.mutant(fault,source,mutant,message)
    def test_typed_zext_operand_and_producer_changes_cannot_pass(self):
        module,source=self.imported('producer-positive')
        for fault in ('other-byte','other-extended-value','wrong-kind','missing-producer'):
            mutant=copy.deepcopy(module);f=next(f for f in mutant['functions'] if f['name']=='from_byte');block=f['blocks'][0]
            cast=block['instructions'][0];call=next(i['operation'] for i in block['instructions'] if i['operation']['op']=='call')
            if fault=='other-byte':cast['operation']['value']={'kind':'value','id':1}
            elif fault=='other-extended-value':call['args'][0]={'kind':'value','id':block['instructions'][1]['result']['id']}
            elif fault=='wrong-kind':cast['operation']['kind']='s_ext'
            else:
                # Typed replacement deliberately supplies a literal to the call
                # rather than leaving an invalid dangling SSA use.
                call['args'][0]={'kind':'int','ty':cast['result']['ty'],'bits':'0'};block['instructions'].pop(0)
            self.mutant(fault,source,mutant,'ordinary direct call extension/operand site changed' if fault in ('other-extended-value','missing-producer') else 'ordinary call z_ext witness changed')
    def test_repeated_void_and_extra_unused_calls_are_accounted_once(self):
        module,source=self.imported('call-count-positive')
        for fault in ('drop-call','extra-call'):
            mutant=copy.deepcopy(module);f=next(f for f in mutant['functions'] if f['name']=='twice');block=f['blocks'][0]
            if fault=='drop-call':block['instructions'].pop()
            else:block['instructions'].append(copy.deepcopy(block['instructions'][0]))
            self.mutant(fault,source,mutant,'ordinary direct call extension/operand site changed' if fault=='drop-call' else 'unaccounted ordinary direct call')
    def test_all_31_zext_input_widths_have_exact_independent_witnesses(self):
        text=HEADER+'declare i64 @consume(i32 signext,ptr)\n@marker=global i64 17,align 8\n'
        for width in range(1,32):
            text+=f'define i64 @from_{width}(i{width} %a) {{ %x=zext i{width} %a to i32\n %r=call i64 @consume(i32 %x,ptr @marker)\n ret i64 %r }}\n'
        module,source=self.imported('all31',text+FLAGS)
        for width in range(1,32):
            witness=source['functions'][f'from_{width}']['direct_call_sites'][0]['z_ext_producers']['0']
            self.assertEqual(witness['source_type'],{'kind':'int','bits':width})
            self.assertEqual(witness['result_type'],{'kind':'int','bits':32})

if __name__=='__main__':unittest.main()
