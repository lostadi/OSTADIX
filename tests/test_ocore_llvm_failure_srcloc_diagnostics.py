"""Required failure-only diagnostic custody tests; LLVM22 is a prerequisite.

No assembler, object emitter, native target program, provider or compiler build
is invoked. The suite parses original LLVM fixtures and keeps whole-unit import
refusals. Stage A code review must precede executing these genuine CAPI tests.
"""
from pathlib import Path
import copy
import ctypes as c
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import ocore_llvm_import as production
from ocore_llvm_source_inventory import (Reader, InventoryMismatch,
    failure_srcloc_inventory, check_failure_srcloc_diagnostics)

PREFIX = ('target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"\n'
          'target triple = "x86_64-unknown-linux-musl"\n')
CALL = '%v = call i64 asm sideeffect "opaque $1, $0", "=r,r"(i64 %x), !srcloc !0'
SIMPLE = PREFIX + 'define i64 @f(i64 %x) {\nentry:\n  ' + CALL + '\n  ret i64 %x\n}\n!0 = !{i64 -1}\n'


class FailureSrclocDiagnosticsTests(unittest.TestCase):
    @staticmethod
    def pin(path):
        path=Path(path);data=path.read_bytes()
        return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

    @classmethod
    def setUpClass(cls):
        # Missing required source/library inputs are failures, never skips or
        # replacement tools. The explicit pin is independent of a filename.
        cls.library = Path(os.environ.get("OCORE_LLVM_LIBRARY") or production.discover_library())
        cls.expected = os.environ.get("OCORE_LLVM_SHA256", production.PINNED_SHA256)
        cls.api = production.LLVM(cls.library, cls.expected)
        cls.reader = Reader(cls.library, cls.expected)
        required=os.environ.get('OCORE_FAILURE_SRCLOC_REQUIRED')
        destination=os.environ.get('OCORE_FAILURE_SRCLOC_OUTPUT')
        if required=='1' and not destination:
            raise RuntimeError('required failure-srcloc suite needs OCORE_FAILURE_SRCLOC_OUTPUT')
        cls.output=Path(destination).resolve() if destination else None
        cls.source_before=[cls.pin(ROOT/p) for p in ['scripts/ocore_llvm_import.py',
            'scripts/ocore_llvm_bitcode.py','tests/ocore_llvm_source_inventory.py',
            'src/bin/olangc/native_runtime/source_inventory.py',
            'tests/test_ocore_llvm_failure_srcloc_diagnostics.py']]
        cls.library_before=cls.pin(cls.library)
        if cls.output:
            cls.output.mkdir(parents=True,exist_ok=True)
            (cls.output/'cases').mkdir()
            with (cls.output/'inputs-before.json').open('x') as stream:
                json.dump({'required':required,'source':cls.source_before,'library':cls.library_before},stream,indent=2)

    @classmethod
    def tearDownClass(cls):
        after=[cls.pin(row['path']) for row in cls.source_before]
        library=cls.pin(cls.library)
        if cls.output:
            with (cls.output/'inputs-after.json').open('x') as stream:
                json.dump({'source':after,'library':library,
                           'unchanged':after==cls.source_before and library==cls.library_before},stream,indent=2)
        if after!=cls.source_before or library!=cls.library_before:
            raise AssertionError('failure diagnostic suite source/library changed')

    def setUp(self):
        if self.output:
            self.directory=self.output/'cases'/self._testMethodName
            self.directory.mkdir()
        else:
            self.temp = tempfile.TemporaryDirectory(prefix="srcloc-failure-")
            self.addCleanup(self.temp.cleanup)
            self.directory=Path(self.temp.name)
        self.path = self.directory / "original.ll"
        self.sequence=0

    def capture(self,label,value,source=None):
        self.sequence+=1
        path=self.directory/('%04d-%s.json'%(self.sequence,label))
        record={'record':value}
        if source is not None:
            source_path=path.with_suffix('.input.ll')
            with source_path.open('xb') as stream:stream.write(source)
            record['input']=self.pin(source_path)
        with path.open('x') as stream:json.dump(record,stream,indent=2)

    def cli(self,command):
        result=subprocess.run(command,capture_output=True,timeout=30)
        self.sequence+=1
        prefix=self.directory/('%04d-cli'%self.sequence)
        for suffix,raw in [('stdout',result.stdout),('stderr',result.stderr)]:
            with prefix.with_suffix('.'+suffix).open('xb') as stream:stream.write(raw)
        with prefix.with_suffix('.json').open('x') as stream:
            json.dump({'command':command,'status':result.returncode,
                       'stdout':self.pin(prefix.with_suffix('.stdout')),
                       'stderr':self.pin(prefix.with_suffix('.stderr'))},stream,indent=2)
        return result

    def source(self, text=SIMPLE):
        self.path.write_text(text)
        return self.path

    def refused(self, text=SIMPLE, diagnostics=True):
        path = self.source(text)
        report = {} if diagnostics else None
        old = {}
        with self.assertRaises(production.ImportFailure) as caught:
            production.import_module(path, self.library, expected_sha256=self.expected,
                metadata_diagnostics=old, failure_srcloc_diagnostics=report)
        error = caught.exception
        primary = {"stage":error.stage, "symbol":error.symbol, "message":str(error)}
        self.assertEqual(path.read_bytes(),text.encode(),'original diagnostic input changed')
        self.capture('import-refusal',{'primary':primary,'diagnostics':report,'raw_v1':old},text.encode())
        return primary, report, old

    def original_inventory(self, text):
        # Independent parser/context; never import or share a translated module.
        raw = text.encode()
        context = self.reader.ContextCreate()
        module, message = c.c_void_p(), c.c_void_p()
        buffer = self.reader.CreateMemoryBufferWithMemoryRangeCopy(raw,len(raw),b"independent-failure-original")
        parse = self.reader.dll.LLVMParseIRInContext2
        parse.restype,parse.argtypes = c.c_int,[c.c_void_p,c.c_void_p,c.POINTER(c.c_void_p),c.POINTER(c.c_void_p)]
        release = self.reader.dll.LLVMDisposeMemoryBuffer
        release.restype,release.argtypes = None,[c.c_void_p]
        try:
            status = parse(context,buffer,c.byref(module),c.byref(message))
            if message:
                self.reader.DisposeMessage(message)
                message = c.c_void_p()
            self.assertEqual(status,0,"independent fixture must actually parse")
            status = self.reader.VerifyModule(module,2,c.byref(message))
            if message:
                self.reader.DisposeMessage(message)
                message = c.c_void_p()
            self.assertEqual(status,0,"independent fixture must actually verify")
            value=failure_srcloc_inventory(self.reader,context,module,raw)
            self.capture('independent-original-survey',value,raw)
            return value
        finally:
            if module:self.reader.DisposeModule(module)
            release(buffer)
            self.reader.ContextDispose(context)

    def compared(self, text=SIMPLE):
        primary, report, _ = self.refused(text)
        self.assertEqual(report["status"],"rejected_valid_source")
        original = self.original_inventory(text)
        result = check_failure_srcloc_diagnostics(original,report,primary)
        self.assertFalse(result["native_module"])
        self.assertFalse(result["source_authentication"])
        return primary,report,original

    def test_01_success_is_not_applicable_and_native_and_raw_v1_stay_exact(self):
        path = self.source(PREFIX+'define i64 @add(i64 %x) { %v = add i64 %x, 1\n ret i64 %v\n}\n')
        first = {}
        normal = production.import_module(path,self.library,expected_sha256=self.expected,metadata_diagnostics=first)
        second, failure = {}, {}
        with mock.patch.object(production,"_failure_srcloc_scan",side_effect=AssertionError("success must not scan")):
            observed = production.import_module(path,self.library,expected_sha256=self.expected,
                metadata_diagnostics=second,failure_srcloc_diagnostics=failure)
        self.capture('success-not-applicable',{'default':normal,'observed':observed,
            'old_raw_v1':first,'new_raw_v1':second,'failure':failure},path.read_bytes())
        self.assertEqual(normal,observed)
        self.assertEqual(first,second)
        self.assertEqual(first["schema"],"ocore.raw-llvm-metadata-diagnostics/v1")
        self.assertEqual(failure["status"],"not_applicable_success")
        self.assertTrue(failure["import_complete"])
        self.assertIsNone(failure["scan"])
        self.assertTrue(all(v is False for v in failure["authority"].values()))

    def test_02_failure_primary_and_old_raw_v1_are_unchanged(self):
        first,_,old = self.refused(diagnostics=False)
        second,report,new_old = self.refused()
        self.assertEqual(first,second)
        self.assertEqual(old,new_old)
        self.assertEqual(report["primary_import_error"],first)
        self.assertFalse(report["import_complete"])
        self.assertNotIn("format",report)
        self.assertEqual(report["scan"]["roots"][0]["owner"]["assembly"],list(b"opaque $1, $0"))
        self.assertIn("unsupported metadata kind",first["message"])
        self.compared()

    def test_03_all_original_sites_survive_translation_normalization_and_dead_blocks(self):
        text = PREFIX+'declare i64 @unused()\n'+'define i64 @f(i64 %x) {\nentry:\n  '+CALL+'\n  ret i64 %x\ndead:\n  '+CALL.replace('%v','%w')+'\n  unreachable\n}\n!0 = !{i64 -1}\n'
        def delete_unused(a,context,module,audit):
            unused = a.GetNamedFunction(module,b"unused")
            self.assertTrue(unused)
            self.assertFalse(a.GetFirstUse(unused))
            a.DeleteFunction(unused)
            return []
        with mock.patch.object(production,"normalize_legacy_lifetime_artifacts",side_effect=delete_unused):
            primary,report,_ = self.refused(text)
        self.assertEqual(report["scan"]["functions"],2)
        self.assertEqual(report["scan"]["blocks"],2)
        self.assertEqual(len(report["scan"]["roots"]),2)
        self.assertEqual([r["site"]["block"] for r in report["scan"]["roots"]],[0,1])
        check_failure_srcloc_diagnostics(self.original_inventory(text),report,primary)

    def test_04_contextual_name_shift_never_promotes_another_name(self):
        text = PREFIX+'define i64 @f(i64 %x) {\nentry:\n  '+CALL.replace('!srcloc !0','!ostadix_other !0')+'\n  '+CALL.replace('%v','%w').replace('!0','!1')+'\n  ret i64 %x\n}\n!0 = !{i64 17}\n!1 = !{i64 18}\n'
        _,report,_ = self.compared(text)
        self.assertEqual(len(report["scan"]["roots"]),1)
        self.assertEqual(report["scan"]["other_attachments"],1)
        self.assertEqual(report["scan"]["nodes"][0]["operands"],[{"width":64,"bits":"18"}])
        a=self.api
        for precursor,wanted in [(None,47),(b"ostadix.context.negative",48)]:
            context=a.ContextCreate()
            try:
                if precursor:self.assertEqual(a.GetMDKindIDInContext(context,precursor,len(precursor)),47)
                self.assertEqual(a.GetMDKindIDInContext(context,b"srcloc",6),wanted)
            finally:a.ContextDispose(context)

    def test_05_original_tuple_bits_order_storage_and_sharing(self):
        calls='\n'.join('  '+CALL.replace('%v','%v'+str(i)).replace('!0','!'+str(md)) for i,md in enumerate([0,0,1,2,3]))
        text=PREFIX+'define i64 @f(i64 %x) {\n'+calls+'\n ret i64 %x\n}\n!0 = !{i64 -1}\n!1 = distinct !{i64 -1}\n!2 = distinct !{i64 -1}\n!3 = !{i8 -1, i64 0, i1 1}\n'
        _,report,_=self.compared(text);s=report['scan']
        self.assertEqual([r['node'] for r in s['roots']],[0,0,1,2,3])
        self.assertEqual([n['storage'] for n in s['nodes']],['uniqued','distinct','distinct','uniqued'])
        self.assertEqual(s['nodes'][0]['operands'],[{'width':64,'bits':str((1<<64)-1)}])
        self.assertEqual(s['nodes'][3]['operands'],[{'width':8,'bits':'255'},{'width':64,'bits':'0'},{'width':1,'bits':'1'}])

    def test_06_genuine_invalid_tuple_payloads_are_explicit_refusals(self):
        # Pinned LLVM MetadataAsValue canonicalizes an original singleton-null
        # tuple to an empty operand adapter; it remains an explicit refusal.
        cases=[('!DIExpression()','not_original_mdtuple'),('!{null}','empty_tuple'),
               ('!{!"cookie"}','not_constant_integer'),('!{double 1.0}','not_constant_integer'),
               ('!{}','empty_tuple'),('!{i128 1}','integer_width_outside_1_64')]
        for node,error in cases:
            with self.subTest(node=node):
                _,report,_=self.compared(SIMPLE.replace('!{i64 -1}',node))
                self.assertEqual(report['scan']['roots'][0]['error'],error)
                self.assertFalse(report['scan']['typed_custody_complete'])
                self.assertEqual(report['scan']['nodes'],[])

    def test_07_wrong_owners_never_reach_callinst_only_getters(self):
        invoke=(PREFIX+'declare i32 @personality(...)\ndefine i64 @f() personality ptr @personality {\nentry:\n'
                ' %v = invoke i64 asm sideeffect unwind "opaque", "=r"() to label %normal unwind label %exception, !srcloc !0\n'
                'normal:\n ret i64 %v\nexception:\n %lp = landingpad {ptr, i32} cleanup\n resume {ptr, i32} %lp\n}\n!0 = !{i64 7}\n')
        callbr=(PREFIX+'define void @f() {\nentry:\n callbr void asm sideeffect "jmp ${0:l}", "!i"() to label %normal [label %other], !srcloc !0\nnormal:\n ret void\nother:\n ret void\n}\n!0 = !{i64 7}\n')
        cases=[PREFIX+'@g = global i64 0, !srcloc !0\ndefine void @f() { ret void }\n!0 = !{i64 7}\n',
               PREFIX+'define void @f() !srcloc !0 { ret void }\n!0 = !{i64 7}\n',
               PREFIX+'define i64 @f(ptr %p) { %v = load i64, ptr %p, !srcloc !0\n ret i64 %v\n}\n!0 = !{i64 7}\n',
               PREFIX+'declare i64 @named()\ndefine i64 @f() { %v = call i64 @named(), !srcloc !0\n ret i64 %v\n}\n!0 = !{i64 7}\n',invoke,callbr]
        for text in cases:
            with self.subTest(source=text):
                _,report,_=self.compared(text)
                self.assertEqual(report['scan']['roots'][0]['error'],'owner_not_ordinary_inline_asm_call')
                self.assertEqual(report['scan']['nodes'],[])

    def test_08_local_ssa_and_bad_parse_or_verification_stay_unavailable(self):
        for text in ['this is not LLVM',SIMPLE.replace('!0 = !{i64 -1}','!0 = !{i64 %x}')]:
            with self.subTest(source=text):
                first,_,_=self.refused(text,diagnostics=False)
                second,report,_=self.refused(text)
                self.assertEqual(first,second)
                self.assertIn(first['stage'],{'parse','llvm-verify'})
                self.assertEqual(report['status'],'unavailable_unverified_source')
                self.assertIsNone(report['scan'])
        # Both predecessors reach merge, but %only_lhs is unavailable on rhs.
        # The input is syntactically valid; its failure must be verification,
        # with no diagnostic clone/parse/scan of the unverified module.
        dominance=PREFIX+'''define i64 @dominance_failure(i1 %choose, i64 %x) {
entry:
  br i1 %choose, label %lhs, label %rhs
lhs:
  %only_lhs = add i64 %x, 1
  br label %merge
rhs:
  br label %merge
merge:
  ret i64 %only_lhs
}
'''
        constructor=production.LLVM
        created=[]
        def monitored_llvm(*args,**kwargs):
            api=constructor(*args,**kwargs)
            for name in ['ContextCreate','ParseIRInContext2','VerifyModule']:
                setattr(api,name,mock.Mock(wraps=getattr(api,name)))
            created.append(api)
            return api
        with mock.patch.object(production,'LLVM',side_effect=monitored_llvm), \
             mock.patch.object(production,'_failure_srcloc_scan',side_effect=AssertionError('unverified source must not scan')):
            first,_,_=self.refused(dominance,diagnostics=False)
            second,report,_=self.refused(dominance)
        self.assertEqual(first,second)
        self.assertEqual(first['stage'],'llvm-verify')
        self.assertIn('does not dominate',first['message'])
        self.assertEqual(report['primary_import_error'],first)
        self.assertEqual(report['status'],'unavailable_unverified_source')
        self.assertEqual(report['parse_status'],'accepted')
        self.assertEqual(report['verification_status'],'rejected')
        self.assertEqual(report['diagnostic_parse_status'],'not_started')
        self.assertEqual(report['diagnostic_verification_status'],'not_started')
        self.assertIsNone(report['scan'])
        self.assertEqual(len(created),2)
        for api in created:
            self.assertEqual(api.ContextCreate.call_count,1)
            self.assertEqual(api.ParseIRInContext2.call_count,1)
            self.assertEqual(api.VerifyModule.call_count,1)

    def test_09_secondary_scanner_or_reparse_errors_do_not_replace_primary(self):
        primary,_,_=self.refused(diagnostics=False)
        with mock.patch.object(production,'_failure_srcloc_scan',side_effect=RuntimeError('diagnostic fault')):
            actual,report,_=self.refused()
        self.assertEqual(primary,actual)
        self.assertEqual(report['primary_import_error'],primary)
        self.assertEqual(report['status'],'diagnostic_error')
        self.assertEqual(report['diagnostic_error']['message'],'diagnostic fault')
        self.assertEqual(report['diagnostic_error']['stage'],'diagnostic_scan')
        self.assertIsNone(report['scan'])
        original=production.preflight_scoped_alias_metadata
        visits=[]
        def fault_second_parse(a,context,module):
            visits.append(context)
            if len(visits)==2:raise RuntimeError('diagnostic pre-verifier fault')
            return original(a,context,module)
        with mock.patch.object(production,'preflight_scoped_alias_metadata',side_effect=fault_second_parse):
            actual,report,_=self.refused()
        self.assertEqual(primary,actual)
        self.assertEqual(len(visits),2)
        self.assertEqual(report['diagnostic_error']['stage'],'diagnostic_pre_verifier_safety')
        self.assertEqual(report['diagnostic_parse_status'],'accepted')
        self.assertEqual(report['diagnostic_verification_status'],'not_started')

    def test_10_output_paths_are_distinct_and_failure_never_publishes_module(self):
        self.source();base=[sys.executable,str(ROOT/'scripts/ocore_llvm_import.py'),str(self.path),
                           '--llvm-library',str(self.library),'--llvm-sha256',self.expected]
        output=self.directory/'native.json';diagnostic=self.directory/'failure.json';raw=self.directory/'raw.json'
        run=self.cli(base+['--output',str(output),'--metadata-diagnostics',str(raw),
                           '--failure-srcloc-diagnostics',str(diagnostic)])
        self.assertEqual(run.returncode,1);self.assertFalse(output.exists())
        record=json.loads(diagnostic.read_bytes());self.assertNotIn('format',record)
        self.assertEqual(record['schema'],'ocore.llvm.srcloc-failure-diagnostics/v1')
        self.assertEqual(json.loads(raw.read_bytes())['schema'],'ocore.raw-llvm-metadata-diagnostics/v1')
        self.assertEqual(json.loads(run.stderr)['error'],record['primary_import_error'])
        for destination in [self.path,output,raw]:
            with self.subTest(destination=destination):
                run=self.cli(base+['--output',str(output),'--metadata-diagnostics',str(raw),
                    '--failure-srcloc-diagnostics',str(destination)])
                self.assertEqual(run.returncode,1)
                self.assertEqual(json.loads(run.stderr)['error']['stage'],'command')

    def test_11_independent_comparison_rejects_node_site_owner_and_header_forgeries(self):
        primary,record,original=self.compared()
        mutations=[lambda p:p.update(input_sha256='0'*64),lambda p:p.update(target_triple='aarch64-linux-musl'),
                   lambda p:p['scan']['nodes'][0]['operands'][0].update(bits='0'),
                   lambda p:p['scan']['nodes'][0].update(storage='distinct'),
                   lambda p:p['scan']['nodes'][0].update(id=False),
                   lambda p:p['scan']['roots'][0]['site'].update(source_instruction=1),
                   lambda p:p['scan']['roots'][0]['site'].update(function_index=1),
                   lambda p:p['scan']['roots'][0]['owner'].update(assembly=[]),
                   lambda p:p['scan']['roots'].append(copy.deepcopy(p['scan']['roots'][0])),
                   lambda p:p['scan']['nodes'].append(copy.deepcopy(p['scan']['nodes'][0])),
                   lambda p:p['scan'].update(roots=[]),lambda p:p['scan'].update(scan_complete=False),
                   lambda p:p['authority'].update(provider=True),lambda p:p.update(primary_import_error={})]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                altered=copy.deepcopy(record);mutate(altered)
                with self.assertRaises(InventoryMismatch):check_failure_srcloc_diagnostics(original,altered,primary)
        with self.assertRaises(InventoryMismatch):check_failure_srcloc_diagnostics(original,{'format':'ocore-native-module-v1'},primary)
        primary,multi,original=self.compared(SIMPLE.replace('!{i64 -1}','!{i8 -1, i64 0}'))
        multi['scan']['nodes'][0]['operands'].reverse()
        with self.assertRaises(InventoryMismatch):check_failure_srcloc_diagnostics(original,multi,primary)

    def test_12_original_source_mutations_remain_bound_beyond_claimed_header(self):
        primary,record,_=self.compared()
        variants=[SIMPLE.replace('opaque $1, $0','different $1, $0'),
                  SIMPLE.replace('asm sideeffect','asm'),SIMPLE.replace('"=r,r"','"=r,0"'),
                  SIMPLE.replace('"=r,r"','"=r,r,~{memory}"'),
                  SIMPLE.replace('call i64 asm','call i32 asm'),
                  SIMPLE.replace('define i64 @f(i64 %x) {','define i64 @f(i64 %x) #0 {')+'attributes #0 = { strictfp }\n']
        for changed in variants:
            with self.subTest(source=changed):
                original=self.original_inventory(changed);forged=copy.deepcopy(record)
                # Rebind the easy claimed input header so exact original site,
                # owner flags/types/bytes and complete function binding matter.
                for key in ['input_sha256','input_bytes','target_triple','data_layout']:
                    forged[key]=original[key]
                with self.assertRaises(InventoryMismatch):check_failure_srcloc_diagnostics(original,forged,primary)
        floating=PREFIX+'define double @f(double %x) {\n %v = call double asm sideeffect "opaque", "=x,0"(double %x), !srcloc !0\n ret double %x\n}\n!0 = !{i64 5}\n'
        primary,record,_=self.compared(floating)
        changed=floating.replace('call double','call fast double')
        original=self.original_inventory(changed);forged=copy.deepcopy(record)
        for key in ['input_sha256','input_bytes','target_triple','data_layout']:forged[key]=original[key]
        with self.assertRaises(InventoryMismatch):check_failure_srcloc_diagnostics(original,forged,primary)

    def test_13_failure_dictionary_cannot_alias_raw_v1_and_tools_are_required(self):
        self.source();shared={'unchanged':True}
        with self.assertRaisesRegex(production.ImportFailure,'must not share'):
            production.import_module(self.path,self.library,expected_sha256=self.expected,
                metadata_diagnostics=shared,failure_srcloc_diagnostics=shared)
        self.assertEqual(shared,{'unchanged':True})
        report={}
        with self.assertRaises(production.ImportFailure):
            production.import_module(self.path,self.library,expected_sha256='0'*64,
                failure_srcloc_diagnostics=report)
        self.capture('required-parser-pin-refusal',report,self.path.read_bytes())
        self.assertEqual(report['status'],'unavailable_parser')
        self.assertIsNone(report['scan'])


if __name__ == '__main__':
    unittest.main()
