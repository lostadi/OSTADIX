"""Whole-source saturation import/inventory controls; no new native embedding proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from scripts import ocore_llvm_import as importer
from tests.ocore_llvm_source_inventory import Reader, check_inventory, InventoryMismatch

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = Path('/home/orangepi/.local/share/ostadix/llvm22/rootfs/usr/lib/riscv64-linux-gnu/libLLVM.so.22.1')
PIN = '8617d27fecff5e31785eed07ee1cd7665e083bb689b6fb13266956d5231afe83'
WIDTHS = (*range(1, 65), 128)
HEADER = 'target triple = "riscv64-unknown-linux-gnu"\ntarget datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"\n'

def identity(path):
    path = Path(path).resolve(); raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def fixture(widths=(32,), args=('%a', '%b')):
    text = HEADER + '@original_marker = global i64 123456789, align 8\ndeclare i64 @original_unused_provider(i64)\ndefine i64 @original_cold() { ret i64 17 }\n'
    for bits in widths:
        text += (f'declare i{bits} @llvm.usub.sat.i{bits}(i{bits}, i{bits})\n'
                 f'define i{bits} @sat_{bits}(i{bits} %a, i{bits} %b) {{\n'
                 f' %v = call i{bits} @llvm.usub.sat.i{bits}(i{bits} {args[0]}, i{bits} {args[1]})\n ret i{bits} %v\n}}\n')
    return text

class SaturationSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retain = os.environ.get('OCORE_SAT_RETAIN')
        cls.directory = Path(tempfile.mkdtemp(prefix='saturation-source-', dir=retain))
        cls.reader = Reader(LIBRARY, PIN)
        cls.paths = [ROOT / name for name in ('scripts/ocore_llvm_import.py', 'scripts/ocore_llvm_bitcode.py',
                     'crates/ostadix-api/src/ocore/native_verify.rs', 'crates/ostadix-api/src/ocore/native_interpret.rs',
                     'tests/ocore_llvm_source_inventory.py', 'tests/test_ocore_llvm_saturation.py')]
        cls.before, cls.records = [identity(path) for path in cls.paths], []
    @classmethod
    def tearDownClass(cls):
        after = [identity(path) for path in cls.paths]
        report = {'schema':'ocore-saturation-source-controls-v1', 'before':cls.before, 'after':after,
                  'stable':cls.before==after, 'records':cls.records,
                  'source_worker_only':True, 'native_mutant_verification_pending_new_compiler':True,
                  'new_compiler_built':False, 'native_execution_qualified':False,
                  'provider_closure_complete':False, 'original_runtime_complete':False}
        (cls.directory/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
        if cls.before != after: raise AssertionError('source changed during saturation controls')
    def imported(self, label, text):
        path = self.directory/(label+'.ll'); path.write_text(text)
        return self.existing(label, path)
    def existing(self, label, path):
        original = identity(path)
        module = importer.import_module(path, LIBRARY, expected_sha256=PIN)
        source = self.reader.read(path)
        proof = check_inventory(source,module)
        for suffix,value in (('.native.json',module),('.source-inventory.json',source),('.preservation.json',proof)):
            (self.directory/(label+suffix)).write_text(json.dumps(value,indent=2)+'\n')
        self.assertEqual(identity(path),original)
        self.records.append({'label':label,'original':original,
            'native':identity(self.directory/(label+'.native.json')),
            'source_inventory':identity(self.directory/(label+'.source-inventory.json')),
            'preservation':identity(self.directory/(label+'.preservation.json'))})
        return module,source
    def import_rejected(self,label,text,message=None,stage='import'):
        path=self.directory/(label+'.ll');path.write_text(text)
        original=identity(path)
        with self.assertRaises(importer.ImportFailure) as failure:
            importer.import_module(path,LIBRARY,expected_sha256=PIN)
        self.assertEqual(failure.exception.stage,stage)
        if message:self.assertRegex(str(failure.exception),message)
        self.assertEqual(identity(path),original)
        self.records.append({'rejected_original':original,'stage':failure.exception.stage,
                             'diagnostic':str(failure.exception),'expected_stage':stage})
    def rejected(self,label,source,module,message):
        path=self.directory/(label+'.mutant.native.json');path.write_text(json.dumps(module,indent=2)+'\n')
        with self.assertRaisesRegex(InventoryMismatch,message):check_inventory(source,module)
        self.records.append({'mutant':label,'module':identity(path),'expected_mismatch':message,
                             'native_verifier_checked':False,'well_typed_construction_requires_new_compiled_verifier':True})
    def test_all_65_native_scalar_widths_keep_full_unit_and_exact_five_nodes(self):
        module,source=self.imported('all65',fixture(WIDTHS))
        self.assertEqual(len(module['functions']),132)
        self.assertEqual(len(module['globals']),1)
        for function in module['functions']:
            if function['name'].startswith('sat_'):
                instructions=function['blocks'][0]['instructions']
                self.assertEqual([x['operation']['op'] for x in instructions],['freeze','freeze','binary','i_cmp','select'])
                self.assertEqual(instructions[2]['operation']['flags'],[])
                self.assertEqual(instructions[3]['operation']['predicate'],'ult')
                self.assertNotEqual(instructions[0]['result']['id'],instructions[1]['result']['id'])
    def test_complete_unchanged_original_lparser(self):
        path=Path('/home/orangepi/ostadix-BM/target/original-lua-source-recipe-20261017-ndpqjeew/compiled/capture/units/f428ca4d0c9f4966bef097123e885dcd/unit-0.ll')
        self.assertEqual(identity(path)['sha256'],'671b0c6f968b327a8e6e2f03c5b69b4eab24c657a45e91afae8b82a5bf40a471')
        module,source=self.existing('original-whole-lparser',path)
        self.assertEqual(set(x['name'] for x in module['functions']),set(source['functions']))
        self.assertEqual(set(x['name'] for x in module['globals']),set(source['globals']))
    def test_typed_poison_undef_and_same_source_argument_keep_distinct_choices(self):
        for args in [('poison','undef'),('undef','poison'),('%a','%a')]:
            label='inputs-'+str(len(self.records));module,source=self.imported(label,fixture(args=args))
            f=next(x for x in module['functions'] if x['name']=='sat_32');instructions=f['blocks'][0]['instructions'];a,b=instructions[:2]
            if args[0] in ('poison','undef'):
                self.assertEqual(a['operation']['value']['kind'],args[0]);self.assertEqual(b['operation']['value']['kind'],args[1])
            else:
                self.assertEqual(a['operation']['value'],b['operation']['value'])
                mutant=copy.deepcopy(module);block=next(x for x in mutant['functions'] if x['name']=='sat_32')['blocks'][0]
                old,new=b['result']['id'],a['result']['id']
                def replace(value):
                    if isinstance(value,dict):
                        if value.get('kind')=='value' and value.get('id')==old:value['id']=new
                        for child in value.values():replace(child)
                    elif isinstance(value,list):
                        for child in value:replace(child)
                replace(block);block['instructions']=[x for x in block['instructions'] if x['result']['id']!=old]
                self.rejected('shared-choice',source,mutant,'missing/changed intrinsic operation')
    def test_unknown_attributes_and_unadmitted_overloads_fail_closed(self):
        self.imported('negative-positive-baseline',fixture())
        for bits in (65,127,256):
            self.import_rejected('unsupported-'+str(bits),fixture((bits,)))
        ordinary=HEADER+'declare i32 @ordinary(i32) nocreateundeforpoison\ndefine i32 @main(i32 %a) { %r=call i32 @ordinary(i32 %a)\n ret i32 %r }\n'
        self.import_rejected('ordinary-declaration-promise',ordinary,'27|nocreateundeforpoison')
        ordinary_call=HEADER+'declare i32 @ordinary(i32)\ndefine i32 @main(i32 %a) { %r=call i32 @ordinary(i32 %a) #1\n ret i32 %r }\nattributes #1 = { nocreateundeforpoison }\n'
        self.import_rejected('ordinary-call-promise',ordinary_call,'27|nocreateundeforpoison')
        text=fixture().replace('i32 %a, i32 %b)\n ret','i32 %a, i32 %b) #1\n ret')+'attributes #1 = { "ocore_saturation_unknown" }\n'
        self.import_rejected('unknown-call-attribute',text,'unsupported|string|ocore_saturation_unknown')
        vector=HEADER+'declare <2 x i32> @llvm.usub.sat.v2i32(<2 x i32>,<2 x i32>)\ndefine <2 x i32> @vector(<2 x i32> %a,<2 x i32> %b) { %r=call <2 x i32> @llvm.usub.sat.v2i32(<2 x i32> %a,<2 x i32> %b)\n ret <2 x i32> %r }\n'
        self.import_rejected('unadmitted-vector',vector)
    def test_semantic_graph_mutants_cannot_pass_source_accounting(self):
        module,source=self.imported('mutant-baseline',fixture())
        for fault in ('predicate','operands','flags','zero','select','extra-unused','duplicate-unused','missing','result-width'):
            mutant=copy.deepcopy(module);f=next(x for x in mutant['functions'] if x['name']=='sat_32');block=f['blocks'][0];a,b,difference,comparison,select=block['instructions']
            if fault=='predicate':comparison['operation']['predicate']='slt'
            elif fault=='operands':difference['operation']['lhs'],difference['operation']['rhs']=difference['operation']['rhs'],difference['operation']['lhs']
            elif fault=='flags':difference['operation']['flags']=['nuw']
            elif fault=='zero':select['operation']['on_true']['bits']='1'
            elif fault=='select':select['operation']['on_true'],select['operation']['on_false']=select['operation']['on_false'],select['operation']['on_true']
            elif fault=='missing':select['operation']={'op':'freeze','value':select['operation']['on_false']}
            elif fault=='result-width':
                # The select itself has a well-typed widened value and a truncation
                # restores the original function result. The intrinsic result graph
                # must still retain the original i32 type at its root.
                ty64=next(i for i,x in enumerate(mutant['types']) if x=={'kind':'int','bits':64})
                nextid=max(x['result']['id'] for x in block['instructions'])+1
                old_result=select['result']['id'];original_ty=select['result']['ty']
                extend={'result':{'id':nextid,'ty':ty64},'operation':{'op':'cast','kind':'z_ext','value':copy.deepcopy(select['operation']['on_false'])}}
                select['result']['ty']=ty64
                select['operation']['on_true']={'kind':'int','ty':ty64,'bits':'0'}
                select['operation']['on_false']={'kind':'value','id':nextid}
                block['instructions'].insert(4,extend)
                block['instructions'].append({'result':{'id':nextid+1,'ty':original_ty},'operation':{'op':'cast','kind':'trunc','value':{'kind':'value','id':old_result}}})
                block['terminator']['value']={'kind':'value','id':nextid+1}
            elif fault=='extra-unused':
                i=max(x['result']['id'] for x in block['instructions'])+1
                block['instructions'].append({'result':{'id':i,'ty':a['result']['ty']},'operation':{'op':'binary','kind':'add','lhs':a['operation']['value'],'rhs':b['operation']['value'],'flags':[]}})
            else:
                copies=copy.deepcopy(block['instructions']);nextid=max(x['result']['id'] for x in copies)+1;mapping={x['result']['id']:nextid+i for i,x in enumerate(copies)}
                def remap(value):
                    if isinstance(value,dict):
                        if value.get('kind')=='value' and value.get('id') in mapping:value['id']=mapping[value['id']]
                        for child in value.values():remap(child)
                    elif isinstance(value,list):
                        for child in value:remap(child)
                for instruction in copies:
                    instruction['result']['id']=mapping[instruction['result']['id']];remap(instruction['operation'])
                block['instructions'].extend(copies)
            message='primitive inventory changed' if fault in ('extra-unused','duplicate-unused') else 'missing/changed intrinsic operation'
            self.rejected(fault,source,mutant,message)
    def test_gep_counts_follow_typed_indices_and_original_datalayout(self):
        # The dynamic source i32 index is sign-extended to this layout's
        # 64-bit pointer index width before computing the byte offset.
        for alignment,dynamic,expected in [(8,True,{'cast:s_ext':1,'binary:add':1}),(16,True,{'cast:s_ext':1,'binary:mul':1,'binary:add':1}),(8,False,{})]:
            layout=f'e-m:e-p:64:64-i1:{alignment}-i64:64-i128:128-n32:64-S128'
            text=(f'target triple = "riscv64-unknown-linux-gnu"\ntarget datalayout = "{layout}"\n'
                  'declare i32 @llvm.usub.sat.i32(i32,i32)\n'
                  'define i32 @gep_case(ptr %p,i32 %index,i32 %a,i32 %b) {\n'
                  ' %v=call i32 @llvm.usub.sat.i32(i32 %a,i32 %b)\n'
                  f' %at=getelementptr i1,ptr %p,i32 {"%index" if dynamic else "0"}\n'
                  ' %byte=load i1,ptr %at,align 1\n %value=zext i1 %byte to i32\n %result=add i32 %v,%value\n ret i32 %result\n}\n')
            module,source=self.imported(f'gep-{alignment}-{dynamic}',text)
            self.assertEqual(source['functions']['gep_case']['gep_offset_graph_counts'],expected)
            if dynamic:
                changed_extension=copy.deepcopy(module)
                changed_function=next(x for x in changed_extension['functions'] if x['name']=='gep_case')
                extension=next(x['operation'] for x in changed_function['blocks'][0]['instructions']
                               if x['operation'].get('op')=='cast' and x['operation'].get('kind')=='s_ext')
                extension['kind']='z_ext'
                self.rejected('wrong-gep-index-extension-'+str(alignment),source,changed_extension,'primitive inventory changed')
            mutant=copy.deepcopy(module);f=next(x for x in mutant['functions'] if x['name']=='gep_case');block=f['blocks'][0]
            if alignment==16:
                multiply=next(x for x in block['instructions'] if x['operation'].get('kind')=='mul');old=multiply['result']['id'];replacement=multiply['operation']['lhs']
                def drop(value):
                    if isinstance(value,dict):
                        if value.get('kind')=='value' and value.get('id')==old:value.clear();value.update(copy.deepcopy(replacement));return
                        for child in list(value.values()):drop(child)
                    elif isinstance(value,list):
                        for child in value:drop(child)
                drop(block);block['instructions']=[x for x in block['instructions'] if x['result']['id']!=old]
                self.rejected('missing-datalayout-stride',source,mutant,'primitive inventory changed')
            elif dynamic:
                i=max(x['result']['id'] for x in block['instructions'])+1;ty=next(i for i,x in enumerate(mutant['types']) if x=={'kind':'int','bits':64})
                block['instructions'].append({'result':{'id':i,'ty':ty},'operation':{'op':'binary','kind':'mul','lhs':{'kind':'int','ty':ty,'bits':'1'},'rhs':{'kind':'int','ty':ty,'bits':'1'},'flags':[]}})
                self.rejected('invented-byte-stride-multiply',source,mutant,'primitive inventory changed')
            mismatch=copy.deepcopy(module);mismatch['target']['data_layout']+='-i32:64'
            self.rejected('changed-datalayout-'+str(alignment)+'-'+str(dynamic),source,mismatch,'source data layout changed')

if __name__=='__main__':unittest.main()
