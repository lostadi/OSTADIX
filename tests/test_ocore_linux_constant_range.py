"""Typed source ranges are not an optimizer, provider or no-return proof."""
import copy
import hashlib
import json
import os
import re
import struct
from pathlib import Path
import unittest

from scripts import ocore_llvm_import as producer
from tests import test_ocore_linux_syscall as base


# Authored complete LLVM units, distinct from unchanged original musl inputs.
# Every defined child value lies in these declared ranges; INT64_MIN is the
# single excluded value for the near-full wrapping range, never normalized.
def range_source_module(isa, original):
    template,fixed,inputs,clobbers=base.RAW[isa]
    header='\n'.join(line for line in original.splitlines() if line.startswith(('target datalayout','target triple')))
    broad='range(i64 -9223372036854775807, -9223372036854775808)'
    lines=[header]
    for arity in range(7):
        names=['nr']+['a'+str(i) for i in range(arity)]
        params=', '.join('i64 %'+name for name in names)
        args=', '.join('i64 '+('range(i64 0, 1024)' if name=='nr' else broad)+' %'+name for name in names)
        constraints=','.join(fixed+inputs[:arity]+clobbers)
        lines.append(f'define i64 @raw{arity}({params}) strictfp {{\n %r = call {broad} i64 asm sideeffect "{template}", "{constraints}"({args}) nounwind strictfp, !srcloc !0\n ret i64 %r\n}}')
    constraints=','.join(fixed+inputs[:3]+clobbers)
    number=1 if isa=='x86_64' else 64
    lines.append(f'define i64 @ordered_write(i64 %fd, ptr %p) strictfp {{\n store i8 65, ptr %p\n %address = ptrtoint ptr %p to i64\n %r = call {broad} i64 asm sideeffect "{template}", "{constraints}"(i64 range(i64 0, 1024) {number}, i64 {broad} %fd, i64 {broad} %address, i64 {broad} 1) nounwind strictfp, !srcloc !0\n store i8 66, ptr %p\n ret i64 %r\n}}')
    if isa=='riscv64':lines.extend(['!llvm.module.flags = !{!1}','!1 = !{i32 1, !"target-abi", !"lp64d"}'])
    lines.append('!0 = !{i64 0, i64 18446744073709551615}')
    return '\n'.join(lines)+'\n'


class ConstantRangeTransportTests(unittest.TestCase):
    def test_exact_printer_candidates_include_i1_empty_wrap_and_wide_bits(self):
        cases = {
            'range(i1 0, 0)': (1,0,0),
            'range(i1 0, -1)': (1,0,1),
            'range(i1 -1, 0)': (1,1,0),
            'range(i64 -2147483648, 2147483648)': (64,18446744071562067968,2147483648),
            'range(i128 -170141183460469231731687303715884105728, 0)': (128,1<<127,0),
        }
        for text,wanted in cases.items():
            with self.subTest(text=text):
                self.assertEqual(producer.constant_range_candidates(text),[wanted])
                # A safe distinct-range negative must also work for singleton i1.
                width,lower,upper=wanted
                wrong=(upper,lower) if lower!=upper else (0,1)
                self.assertNotEqual(wrong,(lower,upper))
                self.assertTrue(wrong[0]!=wrong[1] or wrong==(0,0))
                self.assertTrue(all(0<=value<1<<width for value in wrong))

    def test_quoted_decoys_duplicates_unknown_grammar_and_full_bounds(self):
        text='call i64 asm "range(i64 9, 13)\\22", ""(i64 range(i64 -8, 8) %x, i64 range(i64 -8, 8) %y)'
        self.assertEqual(producer.constant_range_candidates(text),[(64,2**64-8,8)])
        for text in ['range(i0 0, 1)','range(i65 0, 1)','range(i64 -0, 1)',
                     'range(i64 18446744073709551615, 1)','range(i64 -1, -1)',
                     'range(i1 -1, -1)','range(i64 7, 7)','range(i64 0,1)',
                     'range(i64 0, 1','"unterminated range(i64 0, 1)']:
            with self.subTest(text=text),self.assertRaises(producer.ImportFailure):
                producer.constant_range_candidates(text)

    def test_invalid_slots_are_rejected_before_any_capi_operand_or_type_getter(self):
        class Api:
            def GetNumArgOperands(self,_):return 2
            def __getattr__(self,name):raise AssertionError('native getter reached: '+name)
        class Importer:
            a=Api()
            def reject(self,text):raise producer.ImportFailure(text)
        for slot in [-1,3,0xffffffff]:
            with self.subTest(slot=slot),self.assertRaises(producer.ImportFailure):
                producer.Importer.linux_constant_range(Importer(),1,slot,2)


class ConstantRangeCompilerTests(base.LinuxSyscallTests):
    # Reuse custody helpers, without rerunning inherited unrelated gates here.
    test_compiler_owned_original_recipe_provider_and_strict_source_readmission=None
    test_original_complete_getuid_three_isa_source_and_required_linux_provider=None
    test_owned_child_all_twenty_one_register_forms_and_fenv_against_original=None
    test_original_call_contracts_do_not_become_generic_assembly_or_metadata_waivers=None
    test_source_witness_and_profile_negative_controls_fail_closed=None

    def original_exit(self,isa):
        report=json.loads((self.source_root/isa/'capture/report.json').read_text())
        units=[unit for unit in report['units'] if Path(unit['source']['path']).name=='_Exit.c']
        self.assertEqual(len(units),1)
        unit=units[0];path=Path(unit['ir']['path'])
        self.assertEqual(base.identity(path)['sha256'],unit['ir']['sha256'])
        return path

    def test_complete_original_exit_ll_bc_and_source_ranges_three_actual_isas(self):
        records=[]
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();original=self.original_exit(isa)
            bitcode=case/'original.bc';self.command([self.sdk/'llvm-as',original,'-o',bitcode])
            for form,source in [('ll',original),('bc',bitcode)]:
                native=case/(form+'.native.json');self.import_(source,isa,native)
                module=json.loads(native.read_text());self.assertEqual(len(module['functions']),1)
                self.assertEqual(module['functions'][0]['name'],'_Exit');self.assertEqual(module['globals'],[])
                self.command([self.compiler,native,'--input-kind','native-ir','--verify-native','--receipt',case/(form+'.verified.json')])
                proof=self.inventory.audit_native_module(source,module,self.library,base.LIB_SHA)
                operations=[item['operation'] for block in module['functions'][0]['blocks'] for item in block['instructions'] if item['operation']['op']=='linux_syscall']
                self.assertEqual(len(operations),2)
                self.assertEqual([operation['number']['bits'] for operation in operations],['231','60'] if isa=='x86_64' else ['94','93'])
                for operation in operations:
                    witness=operation['source'];self.assertEqual(witness['schema'],'ocore.llvm-linux-syscall-source/v2')
                    self.assertEqual(witness['constant_ranges'],[{'index':2,'name':'range','schema':'ocore.llvm-constant-range-attribute/v1','storage':'context_uniqued_constant_range_attribute','width':64,'lower':'18446744071562067968','upper':'2147483648'}])
                obj=case/(form+'.o');self.command([self.compiler,native,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',obj])
                interface=base.platform_note(obj);self.assertEqual(interface['privilege'],'user_mode_only');self.assertEqual(len(interface['sites']),2)
                self.assertEqual(self.command([self.sdk/'llvm-nm','--undefined-only',obj]).stdout,b'')
                records.append({'isa':isa,'representation':form,'original':base.identity(source),'module':base.identity(native),'object':base.identity(obj),'independent_proof':proof,'platform':interface,'runtime_complete':False})
        (self.directory/'whole-original-exit.json').write_text(json.dumps(records,indent=2)+'\n')

    def test_legacy_enum_only_v1_packets_and_diagnostics_remain_exact(self):
        old=Path(os.environ['OCORE_TEST_PREVIOUS_OCOREC']).resolve()
        expected=os.environ['OCORE_TEST_PREVIOUS_OCOREC_SHA256'];self.assertEqual(base.identity(old)['sha256'],expected)
        for isa in base.UNITS:
            source=self.original(isa);new=self.directory/(isa+'-new.json');prior=self.directory/(isa+'-prior.json')
            argv=[source,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'--linux-syscall-profile','linux-user-raw-v1']
            self.command([old,*argv,'-o',prior]);self.command([self.compiler,*argv,'-o',new]);self.assertEqual(prior.read_bytes(),new.read_bytes())
            oldfail=self.command([old,self.original_exit(isa),*argv[1:],'-o',self.directory/(isa+'-old-exit-must-not-exist.json')],success=False)
            self.assertIn(b'raw-syscall source attributes require supported enum-zero witnesses',oldfail.stderr)

    def test_welltyped_range_forgers_fail_independent_source_and_geometry_is_closed(self):
        isa='x86_64';source=self.original_exit(isa);valid=self.directory/'valid.json';self.import_(source,isa,valid);original=json.loads(valid.read_text())
        def source_witness(module):
            return next(i['operation']['source'] for b in module['functions'][0]['blocks'] for i in b['instructions'] if i['operation']['op']=='linux_syscall')
        # These change real source semantics/association while retaining valid IR.
        for name,change in [
            ('lower',lambda s:s['constant_ranges'][0].__setitem__('lower','18446744071562067969')),
            ('slot',lambda s:s['constant_ranges'][0].__setitem__('index',1)),
            ('return',lambda s:s['constant_ranges'][0].__setitem__('index',0)),
            ('empty',lambda s:s['constant_ranges'][0].update(lower='0',upper='0')),
            ('drop-v1',lambda s:(s.pop('constant_ranges'),s.__setitem__('schema','ocore.llvm-linux-syscall-source/v1'))),
        ]:
            module=copy.deepcopy(original);change(source_witness(module));path=self.directory/(name+'.json');path.write_text(json.dumps(module))
            self.command([self.compiler,path,'--input-kind','native-ir','--verify-native'])
            with self.assertRaisesRegex(self.inventory.InventoryMismatch,'Linux syscall original operands/signature/constraints/effects/attributes/srcloc/site changed|source schema changed'):
                self.inventory.audit_native_module(source,module,self.library,base.LIB_SHA)
        for name,change in [
            ('badslot',lambda r:r.__setitem__('index',0xffffffff)),('width',lambda r:r.__setitem__('width',32)),
            ('negative',lambda r:r.__setitem__('lower','-1')),('noncanonical',lambda r:r.__setitem__('lower','01')),
            ('overflow',lambda r:r.__setitem__('upper','18446744073709551616')),
            ('full',lambda r:r.update(lower='18446744073709551615',upper='18446744073709551615')),
            ('equal',lambda r:r.update(lower='1',upper='1')),('storage',lambda r:r.__setitem__('storage','distinct')),
        ]:
            module=copy.deepcopy(original);change(source_witness(module)['constant_ranges'][0]);path=self.directory/(name+'.invalid.json');path.write_text(json.dumps(module));response=self.command([self.compiler,path,'--input-kind','native-ir','--verify-native'],success=False)
            self.assertIn(b'ConstantRange',response.stderr)
        # Direct source-inventory slot checks are ordered before native indexing.
        class Reader:
            def GetNumArgOperands(self,_):return 2
            def __getattr__(self,name):raise AssertionError('C API getter reached: '+name)
        for slot in [-1,3,0xffffffff]:
            with self.assertRaises(self.inventory.InventoryMismatch):
                self.inventory.Reader.linux_constant_range(Reader(),1,slot,2)

    def test_range_bearing_all_twenty_one_forms_and_fenv_against_reference(self):
        results=[]
        for isa in base.UNITS:
            directory=self.directory/isa;directory.mkdir()
            original=self.original(isa);text=original.read_text();source=directory/'arity.ll'
            source.write_text(range_source_module(isa,text))
            triple=re.search(r'target triple = "([^\"]+)"',text)[1]
            flags=['-march=rv64gc','-mabi=lp64d'] if isa=='riscv64' else []
            modulepath=directory/'arity.native.json';self.import_(source,isa,modulepath)
            module=json.loads(modulepath.read_text());self.assertEqual(len(module['functions']),8)
            for function in module['functions']:
                for block in function['blocks']:
                    for item in block['instructions']:
                        operation=item['operation']
                        if operation['op']!='linux_syscall':continue
                        witness=operation['source'];self.assertEqual(witness['schema'],'ocore.llvm-linux-syscall-source/v2')
                        ranges=witness['constant_ranges'];self.assertEqual([entry['index'] for entry in ranges],list(range(len(operation['arguments'])+2)))
                        self.assertEqual(ranges[0]['lower'],str(2**63+1));self.assertEqual(ranges[0]['upper'],str(2**63))
                        self.assertEqual((ranges[1]['lower'],ranges[1]['upper']),('0','1024'))
                        self.assertTrue(all(entry==dict(ranges[0],index=entry['index']) for entry in ranges[2:]))

            ordered=next(f for f in module['functions'] if f['name']=='ordered_write')
            operations=[item['operation']['op'] for b in ordered['blocks'] for item in b['instructions']]
            syscall=operations.index('linux_syscall');self.assertIn('store',operations[:syscall]);self.assertIn('store',operations[syscall+1:])
            self.inventory.audit_native_module(source,module,self.library,base.LIB_SHA)
            originalmodule=directory/'getuid.native.json';self.import_(original,isa,originalmodule)
            own=directory/'arity.own.o';uidown=directory/'getuid.own.o'
            self.command([self.compiler,modulepath,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',own])
            self.command([self.compiler,originalmodule,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',uidown])
            triple=json.loads(originalmodule.read_text())['target']['triple'];flags=['-march=rv64gc','-mabi=lp64d'] if isa=='riscv64' else []
            reference=directory/'arity.clang.o';uidref=directory/'getuid.clang.o'
            for src,obj in [(source,reference),(original,uidref)]:
                self.command([self.sdk/'clang','--target='+triple,*flags,'-O0','-c',src,'-o',obj])
            recipe_pair=self.ensure_recipe_pair(isa)
            self.assertIsNotNone(recipe_pair,"execution must use this run's actual original source-recipe reference/O-core pair")
            uidown=recipe_pair['owned'];uidref=recipe_pair['reference']
            carrier=directory/'carrier.c';carrier.write_text(base.CARRIER)
            if isa==os.uname().machine:prefix=[]
            else:
                runner=Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/{'x86_64':'qemu-x86_64','aarch64':'qemu-aarch64','riscv64':'qemu-riscv64'}[isa]
                self.assertTrue(runner.is_file(),'guarded foreign ISA runner is mandatory')
                prefix=[str(runner)]
                version=self.command([runner,'--version']);(directory/'runner.json').write_text(json.dumps({'base.identity':base.identity(runner),'version':version.stdout.decode(errors='replace'),'scope':'test-only external emulator, not lowered implementation'},indent=2)+'\n')
            observations=[]
            for mode in range(5 if isa=='riscv64' else 4):
                for implementation,objects in [('reference',[reference,uidref]),('owned',[own,uidown])]:
                    cwd=directory/(implementation+'-round-'+str(mode));cwd.mkdir();executable=cwd/'run'
                    self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-DFENV_ROUND='+str(mode),carrier,*objects,'-o',executable])
                    base.executable_elf(executable,isa)
                    p=self.command([*prefix,executable],cwd=cwd,timeout=30)
                    self.assertEqual(len(p.stdout),640)
                    values=list(struct.unpack('<80Q',p.stdout))
                    self.assertEqual(len(p.stderr),720)
                    records=[list(struct.unpack_from('<9Q',p.stderr,i*72)) for i in range(10)]
                    self.assertEqual([record[0] for record in records],list(range(10)))
                    self.assertEqual([record[8] for record in records],[32]+[64]*9)
                    self.assertEqual([record[1] for record in records],[values[i] for i in [0,1,14,2,15,16,17,18,5,6]])
                    expected_env=([0x1f80|(mode<<13)|63,0x037f|(mode<<10),63] if isa=='x86_64' else [mode<<22,0x0800009f,0] if isa=='aarch64' else [(mode<<5)|31,0,0])
                    for record in records:
                        self.assertEqual(record[2:5],expected_env);self.assertEqual(record[5:8],expected_env)
                    self.assertEqual(values[19],10)
                    self.assertEqual(values[0],os.getuid());self.assertEqual(values[1],os.getuid());self.assertEqual(values[2],2**64-9)
                    self.assertEqual(values[4],values[5]);self.assertEqual(values[8:11],values[11:14])
                    self.assertEqual((cwd/'raw4-created').stat().st_mode&0o777,0o421)
                    self.assertEqual((cwd/'raw4-created').read_bytes(),bytes([0,255,17,38,9,10,128,1,2,3,4,5,6,7,8,9,10,11,12,13]))
                    if implementation == "reference" and mode == 0:
                        corrupt=cwd/"corrupt-oracle"
                        self.command([self.sdk/"clang","--target="+triple,*flags,"--ld-path="+str(self.sdk/"ld.lld"),"-O1","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-vectorize","-fno-slp-vectorize","-fno-pic","-fno-pie","-nostdlib","-static","-Wl,--no-relax","-Wl,-e,_start","-DCORRUPT_ORACLE","-DFENV_ROUND=0",carrier,*objects,"-o",corrupt])
                        corruptcwd=directory/"corrupt";corruptcwd.mkdir()
                        rejected=self.command([*prefix,corrupt],cwd=corruptcwd,timeout=30,success=False)
                        self.assertEqual(rejected.returncode,31,'corrupt oracle must fail at its deliberate check, not an unrelated fault')
                        self.assertEqual(rejected.stdout,b'')
                    observations.append({'implementation':implementation,'rounding_mode':mode,'executable':base.identity(executable),'raw_values':values,'per_call_raw_and_fenv_records':records,'file':base.identity(cwd/'raw4-created')})
            # Predeclared ASLR/allocation fields remain in raw evidence; compare
            # only fixed semantic values plus proven own-mapping relationships.
            excluded={3,4,5,6}
            for reference_run,owned_run in zip(observations[::2],observations[1::2]):
                self.assertEqual(reference_run['rounding_mode'],owned_run['rounding_mode'])
                self.assertEqual([v for i,v in enumerate(reference_run['raw_values']) if i not in excluded],[v for i,v in enumerate(owned_run['raw_values']) if i not in excluded])
                for ref_record,own_record in zip(reference_run['per_call_raw_and_fenv_records'],owned_run['per_call_raw_and_fenv_records']):
                    self.assertEqual(ref_record[:1]+ref_record[2:],own_record[:1]+own_record[2:])
                    if ref_record[0] not in [8,9]:self.assertEqual(ref_record[1],own_record[1])
            results.append({'architecture':isa,'arity_forms':7,'observations':observations,'source_recipe_pair':{key:(base.identity(value) if isinstance(value,Path) else value) for key,value in recipe_pair.items()},'externals':['Clang test driver/bootstrap','Linux syscall provider',*prefix],'runtime_closure_complete':False})
        (self.directory/'execution.json').write_text(json.dumps({'scope':'authored range-bearing LLVM register-form and unchanged original getuid component execution','results':results,'nondeterministic_fields_predeclared':[3,4,5,6],'whole_runtime_lowered':False},indent=2)+'\n')


    def original_process_product(self,isa):
        manifest=Path(os.environ['OCORE_TEST_RANGE_PROCESS_PRODUCTS'])
        rows=json.loads(manifest.read_text());row=rows[isa]
        for field in ['receipt','reference','owned','native','packet','plan']:
            self.assertEqual(base.identity(row[field]['path']),row[field])
        receipt=json.loads(Path(row['receipt']['path']).read_text())
        self.assertTrue(receipt['ok'] and receipt['source_unchanged'])
        self.assertEqual(receipt['isa'],isa)
        self.assertEqual(receipt['source_before'],receipt['source_after'])
        self.assertTrue(any(item['sha256']==base.identity(self.compiler)['sha256'] for item in receipt['source_before']))
        native=json.loads(Path(row['native']['path']).read_text());self.assertEqual([f['name'] for f in native['functions']],['_Exit'])
        self.assertEqual(Path(row['owned']['path']).parent,Path(row['native']['path']).parent)
        return {key:Path(row[key]['path']) for key in ['receipt','reference','owned','native','packet','plan']}

    def test_original_exit_ten_i32_statuses_and_causal_return_sentinel_three_isas(self):
        results=[]
        # These exact status values exhaust the i32 extrema/sign/truncation
        # boundaries without calling arbitrary syscall numbers in the parent.
        statuses=[0,1,42,127,128,255,-1,-42,-2147483648,2147483647]
        prefix_text=base.CARRIER.split('static U observed')[0]
        entry=base.CARRIER[base.CARRIER.rindex('#if defined(__x86_64__)'):]
        body=r"""
extern void selected_exit(int) __asm__("_Exit");
int conformance_main(void){
 int code; S n=setup(NR_READ,0,(U)&code,sizeof code,0,0,0);
 if(n!=sizeof code)return 93;
 selected_exit(code);
 static const char after[]="AFTER-original-_Exit-returned\n";
 if(setup(NR_WRITE,1,(U)after,sizeof(after)-1,0,0,0)!=sizeof(after)-1)return 94;
 return 91;
}
"""
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();pair=self.original_process_product(isa)
            carrier=case/'test-only-exit-bootstrap.c';carrier.write_text(prefix_text+body+entry)
            stub=case/'causal-returning-test-stub.c';stub.write_text('void returning_test_stub(int x) __asm__("_Exit");\nvoid returning_test_stub(int x){(void)x;}\n')
            packet=json.loads(pair['packet'].read_text());embedded=next(m for m in packet['module_set']['modules'] if any(f['name']=='_Exit' for f in json.loads(m['native_ir'])['functions']))
            native=json.loads(embedded['native_ir']);triple=native['target']['triple'];flags=['-march=rv64gc','-mabi=lp64d'] if isa=='riscv64' else []
            prefix=[]
            if isa!=os.uname().machine:
                runner=Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/('qemu-'+isa);self.assertTrue(runner.is_file());prefix=[runner]
                self.command([runner,'--version'])
            observations=[]
            for implementation,obj in [('reference',pair['reference']),('owned',pair['owned']),('returning-control',stub)]:
                exe=case/implementation
                self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start',carrier,obj,'-o',exe]);base.executable_elf(exe,isa)
                for code in statuses if implementation!='returning-control' else [42]:
                    data=struct.pack('<i',code);input_path=case/(implementation+'-input-'+str(code)+'.bin');input_path.write_bytes(data)
                    argv=list(map(str,[*prefix,exe]));index=len(self.records);record={'argv':argv,'cwd':str(case),'timeout_seconds':15,'stdin':base.identity(input_path),'meaning':'owned child only; external Linux provider'};self.records.append(record)
                    child=__import__('subprocess').run(argv,cwd=case,input=data,capture_output=True,timeout=15)
                    record.update(exit=child.returncode,stdout=base.identity_bytes(self.directory/f'{index:03}.stdout',child.stdout),stderr=base.identity_bytes(self.directory/f'{index:03}.stderr',child.stderr))
                    self.assertEqual(child.stderr,b'')
                    self.assertEqual(child.returncode,91 if implementation=='returning-control' else code&255)
                    self.assertEqual(child.stdout,b'AFTER-original-_Exit-returned\n' if implementation=='returning-control' else b'')
                    observations.append({'implementation':implementation,'i32_input':code,'exit_status':child.returncode,'stdout':record['stdout'],'stderr':record['stderr'],'executable':base.identity(exe),'input':record['stdin']})
            results.append({'isa':isa,'source_product':{k:base.identity(v) for k,v in pair.items()},'observations':observations,'externals':['Clang static test-only entry/bootstrap','actual Linux user syscall provider',*map(str,prefix)],'runtime_complete':False,'native_kernel_provider_qualified':False})
        (self.directory/'original-exit-execution.json').write_text(json.dumps({'scope':'unchanged original _Exit source/reference-owned component exit behavior; returning sentinel proves after-call detection; no libc CRT/FENV return/native kernel provider closure','statuses':statuses,'results':results},indent=2)+'\n')

    def test_range_and_body_forgers_fail_public_fresh_original_source_readmission(self):
        for isa in base.UNITS:
            case=self.directory/isa;case.mkdir();pair=self.original_process_product(isa);packet=json.loads(pair['packet'].read_text())
            for kind in ['range-lower','drop-ranges-v1','return-loop-body']:
                forged=copy.deepcopy(packet);embedded=next(m for m in forged['module_set']['modules'] if any(f['name']=='_Exit' for f in json.loads(m['native_ir'])['functions']));module=json.loads(embedded['native_ir']);function=next(f for f in module['functions'] if f['name']=='_Exit')
                ops=[i['operation'] for b in function['blocks'] for i in b['instructions'] if i['operation']['op']=='linux_syscall']
                if kind=='range-lower':ops[0]['source']['constant_ranges'][0]['lower']='18446744071562067969'
                elif kind=='drop-ranges-v1':
                    for op in ops:op['source'].pop('constant_ranges');op['source']['schema']='ocore.llvm-linux-syscall-source/v1'
                else:
                    function['blocks'][-1]['terminator']={'op':'return','value':None}
                encoded=json.dumps(module);np=case/(kind+'.native.json');np.write_text(encoded)
                self.command([self.compiler,np,'--input-kind','native-ir','--verify-native'])
                source=case/(kind+'.original.ll')
                original_units=[u for component in packet['components'] for u in component['units']]
                matches=[bytes.fromhex(unit['original_ir_hex']) for unit in original_units if unit['input']['sha256']==module['provenance']['input_sha256']]
                self.assertEqual(len(matches),1);source.write_bytes(matches[0])
                self.assertEqual(base.identity(source)['sha256'],module['provenance']['input_sha256'])
                if kind=='return-loop-body':self.inventory.audit_native_module(source,module,self.library,base.LIB_SHA)
                else:
                    with self.assertRaises(self.inventory.InventoryMismatch):self.inventory.audit_native_module(source,module,self.library,base.LIB_SHA)
                embedded['native_ir']=encoded;embedded['sha256']=hashlib.sha256(encoded.encode()).hexdigest();fp=case/(kind+'.group.json');fp.write_text(json.dumps(forged));out=case/(kind+'-rejected')
                self.command([self.olangc,fp,'--native-runtime','--native-runtime-provider-plan',pair['plan'],'--native-isa',isa+'-unknown-none','--native-runtime-output','obj','--llvm-library',self.library,'--llvm-sha256',base.LIB_SHA,'-o',out],success=False,timeout=180)
                failure=(out/'source-readmission.json').read_text()
                self.assertIn('fresh original LLVM import does not match embedded typed NativeModule' if kind=='return-loop-body' else 'independent source inventory failed',failure)


if __name__=='__main__':unittest.main()
