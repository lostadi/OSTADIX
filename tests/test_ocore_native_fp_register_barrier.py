"""Closed original AArch64 scalar register-barrier source contract.

The unchanged musl headers differ by ISA: AArch64 uses a tied empty register
asm; x86/RV use volatile memory. Foreign objects are not executed implicitly.
Native matching-profile observations are not universal exception guarantees.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from tests import test_ocore_native_constrained_fmul as common
from tests.ocore_llvm_source_inventory import Reader, check_inventory, InventoryMismatch

ROOT=Path(__file__).resolve().parents[1]
LIBRARY_SHA='ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09'
WRAPPER='''#include "libm.h"
void original_force32(float x){ fp_force_evalf(x*x); }
void original_force64(double x){ fp_force_eval(x*x); }
float original_barrier32(float x){ return fp_barrierf(x); }
double original_barrier64(double x){ return fp_barrier(x); }
'''
CARRIER=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fenv.h>
#pragma STDC FENV_ACCESS ON
extern void reference_original_force32(float), owned_original_force32(float);
extern void reference_original_force64(double), owned_original_force64(double);
extern float reference_original_barrier32(float), owned_original_barrier32(float);
extern double reference_original_barrier64(double), owned_original_barrier64(double);
static const uint64_t d[]={0,0x8000000000000000ULL,1,0xfffffffffffffULL,0x10000000000000ULL,0x3ff0000000000000ULL,0xbff0000000000000ULL,0x3ff0000000000001ULL,0x7fefffffffffffffULL,0xffefffffffffffffULL,0x7ff0000000000000ULL,0xfff0000000000000ULL,0x7ff8000000001234ULL,0xfff8000000004321ULL,0x7ff0000000001234ULL,0xfff0000000004321ULL};
static const uint32_t f[]={0,0x80000000U,1,0x7fffffU,0x800000U,0x3f800000U,0xbf800000U,0x3f800001U,0x7f7fffffU,0xff7fffffU,0x7f800000U,0xff800000U,0x7fc01234U,0xffc04321U,0x7f801234U,0xff804321U};
struct record{uint64_t bits,control,status;int flags,round;};
static struct record run(unsigned which,int owned,uint64_t input,int mode,int seed){
 struct record r={0};float x;double y;uint32_t low=(uint32_t)input;
 if(fesetround(mode)||feclearexcept(FE_ALL_EXCEPT)||feraiseexcept(seed))exit(91);
 if(!(which&1)){memcpy(&x,&low,4);if(which<2){if(owned)owned_original_force32(x);else reference_original_force32(x);r.bits=low;}else{x=owned?owned_original_barrier32(x):reference_original_barrier32(x);memcpy(&low,&x,4);r.bits=low;}}
 else{memcpy(&y,&input,8);if(which<2){if(owned)owned_original_force64(y);else reference_original_force64(y);r.bits=input;}else{y=owned?owned_original_barrier64(y):reference_original_barrier64(y);memcpy(&r.bits,&y,8);}}
 r.flags=fetestexcept(FE_ALL_EXCEPT);r.round=fegetround();
#if defined(__x86_64__)
 unsigned mx;unsigned short cw,sw;__asm__ volatile("stmxcsr %0":"=m"(mx));__asm__ volatile("fnstcw %0":"=m"(cw));__asm__ volatile("fnstsw %0":"=m"(sw));r.control=((uint64_t)cw<<32)|(mx&~63U);r.status=((uint64_t)sw<<32)|(mx&63U);
#elif defined(__aarch64__)
 __asm__ volatile("mrs %0,fpcr":"=r"(r.control));__asm__ volatile("mrs %0,fpsr":"=r"(r.status));
#elif defined(__riscv) && __riscv_xlen==64 && __riscv_flen==64
 unsigned csr;__asm__ volatile("frcsr %0":"=r"(csr));r.control=csr&~31U;r.status=csr&31U;
#else
#error A matching native FP control/status profile is required
#endif
 return r;
}
int main(void){const int modes[]={FE_TONEAREST,FE_UPWARD,FE_DOWNWARD,FE_TOWARDZERO};unsigned c=0;
 for(unsigned w=0;w<4;w++)for(unsigned m=0;m<4;m++)for(unsigned seed=0;seed<2;seed++)for(unsigned i=0;i<16;i++){
  uint64_t in=(w&1)?d[i]:f[i];struct record a=run(w,0,in,modes[m],seed?FE_INVALID:0),b=run(w,1,in,modes[m],seed?FE_INVALID:0);c++;
  printf("%u %u %u %u %016llx %016llx %x %x %llx %llx %016llx %x %x %llx %llx\n",c,w,m,seed,(unsigned long long)in,(unsigned long long)a.bits,a.flags,a.round,(unsigned long long)a.control,(unsigned long long)a.status,(unsigned long long)b.bits,b.flags,b.round,(unsigned long long)b.control,(unsigned long long)b.status);
  if(a.bits!=b.bits||a.flags!=b.flags||a.round!=b.round||a.control!=b.control||a.status!=b.status){fprintf(stderr,"fp barrier mismatch case=%u function=%u input=%016llx reference=%016llx flags=%x owned=%016llx flags=%x\n",c,w,(unsigned long long)in,(unsigned long long)a.bits,a.flags,(unsigned long long)b.bits,b.flags);return 93;}
 }printf("PASS %u\n",c);return 0;}
'''


def barrier_instructions(module):
    return [item for function in module['functions'] for block in function['blocks']
            for item in block['instructions'] if item['operation']['op']=='fp_register_barrier']


class FpRegisterBarrierTests(unittest.TestCase):
    command=classmethod(common.ConstrainedMultiplyTests.command.__func__)

    @classmethod
    def setUpClass(cls):
        cls.compiler=Path(os.environ.get('OCOREC_BIN',ROOT/'target/debug/ocorec')).resolve()
        cls.source=Path(os.environ.get('OCORE_MUSL_SOURCE','/missing')).resolve()
        cls.clang=Path(os.environ.get('OCORE_TEST_CLANG',shutil.which('clang') or '/missing')).resolve()
        cls.library=Path(os.environ.get('OCORE_TEST_LLVM_LIBRARY','/missing')).resolve()
        cls.nm=Path(os.environ.get('OCORE_TEST_LLVM_NM',cls.clang.parent/'llvm-nm')).resolve()
        cls.objcopy=Path(os.environ.get('OCORE_TEST_LLVM_OBJCOPY',cls.clang.parent/'llvm-objcopy')).resolve()
        cls.library_sha=os.environ.get('OCORE_TEST_LLVM_SHA256','')
        required=os.environ.get('OCORE_FP_REGISTER_BARRIER_REQUIRED')=='1'
        if any(not p.is_file() for p in (cls.compiler,cls.clang,cls.library,cls.nm,cls.objcopy)) or not (cls.source/'configure').is_file():
            if required:raise AssertionError('mandatory FP register barrier prerequisites are missing')
            raise unittest.SkipTest('provided pinned source/compiler/Clang22/LLVM prerequisites required')
        if os.environ.get('OCOREC_BIN_SHA256'):
            assert common.identity(cls.compiler)['sha256']==os.environ['OCOREC_BIN_SHA256']
        assert common.identity(cls.library)['sha256']==cls.library_sha
        assert subprocess.check_output(['git','-C',cls.source,'rev-parse','HEAD'],text=True).strip()==common.MUSL
        assert not subprocess.check_output(['git','-C',cls.source,'status','--porcelain'])
        assert re.findall(r'clang version (\d+\.\d+\.\d+)',subprocess.check_output([cls.clang,'--version'],text=True))==['22.1.6']
        selected=os.environ.get('OCORE_FP_REGISTER_BARRIER_OUTPUT')
        cls.cleanup=None if selected else tempfile.TemporaryDirectory(prefix='ocore-fp-register-barrier-')
        cls.out=Path(selected or cls.cleanup.name)
        if selected:cls.out.mkdir(exist_ok=False)
        cls.commands=[];cls.units={};cls.reader=Reader(cls.library,cls.library_sha)
        cls.pins=[common.identity(p) for p in (cls.compiler,cls.clang,cls.library,cls.nm,cls.objcopy,Path(__file__),ROOT/'scripts/ocore_llvm_import.py',ROOT/'tests/ocore_llvm_source_inventory.py',cls.source/'src/internal/libm.h',cls.source/'arch/aarch64/fp_arch.h')]
        cls.catalog=json.loads(cls.command('canonical-targets',[cls.compiler,'--list-targets']).stdout)
        common.require_catalog_profiles(cls.catalog)
        for isa,(triple,flags) in common.PROFILES.items():
            build=cls.out/isa;build.mkdir();cc=[str(cls.clang),'--target='+triple,*flags,'-Qunused-arguments','-fuse-ld=lld']
            cls.command(isa+'-configure',[cls.source/'configure','--srcdir='+str(cls.source),'--target='+triple,'--enable-static','--disable-shared','CC='+shlex.join(cc),'AR='+str(cls.clang.parent/'llvm-ar'),'RANLIB='+str(cls.clang.parent/'llvm-ranlib')],cwd=build)
            cls.command(isa+'-headers',['make','obj/include/bits/alltypes.h','obj/include/bits/syscall.h','obj/src/internal/version.h'],cwd=build)
            original=cls.source/'src/math/__math_xflow.c'
            plan=cls.command(isa+'-plan',['make','-n','obj/src/math/__math_xflow.lo'],cwd=build).stdout.decode()
            rows=[shlex.split(line) for line in plan.splitlines() if str(original) in line and ' -c ' in ' '+line+' ']
            assert len(rows)==1
            argv=rows[0];at=argv.index('-o');del argv[at:at+2];argv.remove('-c')
            source=build/'force.c';source.write_text(WRAPPER);argv[argv.index(str(original))]=str(source)
            ir=build/'force.ll';reference=build/'force.reference.o';module=build/'force.native.json';assembly=build/'force.s';owned=build/'force.owned.o'
            cls.command(isa+'-frontend',[*argv,'-S','-emit-llvm','-o',ir],cwd=build)
            cls.command(isa+'-reference',[*argv,'-c','-o',reference],cwd=build)
            cls.command(isa+'-import',[cls.compiler,ir,'--input-kind','llvm-ir','--emit','mir','--target',isa+'-unknown-none','--llvm-library',cls.library,'--llvm-sha256',cls.library_sha,'-o',module])
            cls.command(isa+'-verify',[cls.compiler,module,'--input-kind','native-ir','--verify-native','--receipt',build/'verification.json'])
            cls.command(isa+'-assembly',[cls.compiler,module,'--input-kind','native-ir','--emit','asm','--target',isa+'-unknown-none','-o',assembly])
            cls.command(isa+'-assemble',[*cc,'-c','-x','assembler',assembly,'-o',owned])
            data=json.loads(module.read_text());inventory=cls.reader.read(ir);check_inventory(inventory,data)
            (build/'source-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
            cls.units[isa]={'ir':ir,'reference':reference,'module':module,'data':data,'inventory':inventory,'assembly':assembly,'owned':owned,'frontend':argv,'cc':cc,'build':build}

    @classmethod
    def tearDownClass(cls):
        assert subprocess.check_output(['git','-C',cls.source,'rev-parse','HEAD'],text=True).strip()==common.MUSL
        assert not subprocess.check_output(['git','-C',cls.source,'status','--porcelain'])
        after=[common.identity(pin['path']) for pin in cls.pins]
        (cls.out/'result.json').write_text(json.dumps({'schema':'ostadix.fp-register-barrier-tests/v1','commands':cls.commands,'inputs_before':cls.pins,'inputs_after':after,'inputs_unchanged':after==cls.pins,'canonical_target_catalog':cls.catalog,'new_operation_realization':{'aarch64':'object-only unless separately matching-executed','x86_64':'UNMET closed original-AArch source profile','riscv64':'UNMET closed original-AArch source profile'},'native_execution_host':platform.machine(),'universal_flags_traps_guarantee':False,'kernel_FP':False,'whole_runtime_qualified':False,'cross_ISA_new_operation_qualified':False,'scope':__doc__},indent=2)+'\n')
        assert after==cls.pins
        if cls.cleanup:cls.cleanup.cleanup()

    def test_original_headers_keep_actual_unused_operand_chain(self):
        unit=self.units['aarch64'];sites=barrier_instructions(unit['data']);self.assertEqual(len(sites),4)
        for function in unit['data']['functions']:
            if function['name'].startswith('original_force'):
                instructions=function['blocks'][0]['instructions']
                self.assertEqual([x['operation']['op'] for x in instructions],['constrained_float_binary','fp_register_barrier'])
                self.assertEqual(instructions[1]['operation']['value'],{'kind':'value','id':instructions[0]['result']['id']})
                self.assertEqual(function['blocks'][0]['terminator'],{'op':'return','value':None})
        for item in sites:
            src=item['operation']['source'];self.assertEqual(src['tail_kind'],1);self.assertEqual(src['fast_math'],0);self.assertEqual(src['operand_bundles'],0)
            self.assertEqual(src['attributes'],[{'index':4294967295,'name':'nounwind','value':0},{'index':4294967295,'name':'strictfp','value':0}])
            self.assertEqual(src['srcloc']['storage'],'uniqued');self.assertEqual(src['srcloc']['operands'][0]['width'],64)

    def test_whole_objects_follow_three_actual_source_ABIs(self):
        for isa,unit in self.units.items():
            for key in ('reference','owned'):
                common.require_elf_arch(unit[key],isa,{1})
                self.assertEqual(self.command(isa+key+'-undefined',[self.nm,'-u',unit[key]]).stdout,b'')
            self.assertEqual(len(barrier_instructions(unit['data'])),4 if isa=='aarch64' else 0)
            self.assertEqual(unit['data']['target']['strict_fp_profile'],'scalar_dynamic_mul_register_barrier_v1' if isa=='aarch64' else 'scalar_dynamic_mul_v1')
        for isa in ('x86_64','riscv64'):
            self.command('closed-source-guard-'+isa,[self.compiler,self.units['aarch64']['module'],'--input-kind','native-ir','--emit','asm','--target',isa+'-unknown-none','-o',self.out/('invalid-'+isa+'.s')],expected=1)

    def test_actual_source_refuses_other_asm_shapes_attributes_and_effects(self):
        original=self.units['aarch64']['ir'].read_text()
        variants={
            'code':original.replace('asm sideeffect "", "=w,0"','asm sideeffect "fmov d0, d0", "=w,0"'),
            'tie':original.replace('"=w,0"','"=w,w"'),
            'class':original.replace('"=w,0"','"=r,0"'),
            'no-effect':original.replace('asm sideeffect','asm'),
            'align':original.replace('asm sideeffect','asm sideeffect alignstack'),
            'dialect':original.replace('asm sideeffect','asm sideeffect inteldialect'),
            'unwind':original.replace('asm sideeffect','asm sideeffect unwind'),
            'fast':original.replace('tail call float asm','tail call fast float asm'),
            'musttail':original.replace('tail call float asm','musttail call float asm'),
            'attr':original.replace('attributes #3 = { nounwind strictfp }','attributes #3 = { nounwind strictfp willreturn }'),
            'wrong-target':original.replace('aarch64-unknown-linux-musl','x86_64-unknown-linux-musl'),
            'bad-location':original.replace('!{i64 90630}','!{!"not-an-integer"}'),
        }
        for label,text in variants.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, original, 'source corruption must change original bytes')
                source=self.out/(label+'.ll');source.write_text(text)
                result=self.command('source-negative-'+label,[self.compiler,source,'--input-kind','llvm-ir','--emit','mir','--target','aarch64-unknown-none','--llvm-library',self.library,'--llvm-sha256',self.library_sha,'-o',self.out/(label+'.json')],expected=1)
                self.assertTrue(result.stderr)

    def test_non_strict_identity_and_distinct_srcloc_are_source_preserved(self):
        text=self.units['aarch64']['ir'].read_text()
        # Remove only helper functions' strictfp via their shared call/function
        # attr groups? A standalone exact identity has no environment arithmetic.
        text='''target triple = "aarch64-unknown-linux-musl"
target datalayout = "e-p:64:64-i64:64-f64:64"
define double @identity(double %x) { %r = call double asm sideeffect "", "=w,0"(double %x), !srcloc !0
ret double %r }
!0 = distinct !{i16 7, i64 9}
'''
        path=self.out/'non-strict.ll';path.write_text(text);out=self.out/'non-strict.json'
        self.command('non-strict-import',[self.compiler,path,'--input-kind','llvm-ir','--emit','mir','--target','aarch64-unknown-none','--llvm-library',self.library,'--llvm-sha256',self.library_sha,'-o',out])
        module=json.loads(out.read_text());self.assertEqual(module['target']['strict_fp_profile'],'scalar_dynamic_mul_register_barrier_v1')
        self.assertEqual(barrier_instructions(module)[0]['operation']['source']['srcloc']['storage'],'distinct')
        check_inventory(self.reader.read(path),module)
        self.command('non-strict-verify',[self.compiler,out,'--input-kind','native-ir','--verify-native'])

    def test_native_verifier_rejects_malformed_remaining_operations_even_dead(self):
        base=self.units['aarch64']['data'];mutations=[]
        for key,value in [('schema','invented'),('assembly',[0]),('constraints',[61,114,44,48]),('side_effects',False),('align_stack',True),('dialect',1),('can_unwind',True),('calling_convention',8),('tail_kind',2),('fast_math',1),('operand_bundles',1),('call_opcode',67),('original_target','x86_64-unknown-linux-musl')]:
            bad=copy.deepcopy(base);barrier_instructions(bad)[0]['operation']['source'][key]=value;mutations.append((key,bad))
        for profile in (None,'scalar_dynamic_mul_v1','integer_linux_syscall_v1'):
            bad=copy.deepcopy(base);bad['target']['strict_fp_profile']=profile;mutations.append(('profile-'+str(profile),bad))
        bad=copy.deepcopy(base);barrier_instructions(bad)[0]['operation']['source']['srcloc']['operands'][0]['bits']='18446744073709551616';mutations.append(('location-width',bad))
        bad=copy.deepcopy(base);barrier_instructions(bad)[0]['operation']['source']['attributes'].append({'index':4294967295,'name':'willreturn','value':0});mutations.append(('attribute',bad))
        # Copy a malformed barrier into a cold unreachable block: every block
        # must still be structurally audited, not only executed/reachable ones.
        bad=copy.deepcopy(base);function=next(f for f in bad['functions'] if f['name']=='original_force32');item=copy.deepcopy(barrier_instructions(bad)[0]);item['result']['id']=100;item['operation']['value']={'kind':'value','id':0};item['operation']['source']['site']['block']=99;item['operation']['source']['fast_math']=1
        function['blocks'].append({'id':99,'instructions':[item],'terminator':{'op':'return','value':None}});mutations.append(('dead-block',bad))
        for label,bad in mutations:
            with self.subTest(label=label):
                path=self.out/('native-'+label+'.json');path.write_text(json.dumps(bad))
                result=self.command('native-negative-'+label,[self.compiler,path,'--input-kind','native-ir','--verify-native'],expected=1);self.assertTrue(result.stderr)

    def test_independent_source_inventory_rejects_erasure_and_witness_changes(self):
        unit=self.units['aarch64'];mutations=[]
        bad=copy.deepcopy(unit['data']);item=barrier_instructions(bad)[0];item['operation']={'op':'freeze','value':item['operation']['value']};mutations.append(bad)
        for key,value in [('fast_math',1),('tail_kind',0),('srcloc',None),('attributes',[])]:
            bad=copy.deepcopy(unit['data']);barrier_instructions(bad)[0]['operation']['source'][key]=value;mutations.append(bad)
        for bad in mutations:
            with self.assertRaises(InventoryMismatch):check_inventory(unit['inventory'],bad)

    def test_all_implemented_backends_require_declared_profiles(self):
        common.require_catalog_profiles(self.catalog)
        for row in ({'id':'new','architecture':'new'},{'id':'duplicate-isa','architecture':'aarch64'}):
            added=copy.deepcopy(self.catalog);added['targets'].append(row)
            with self.assertRaisesRegex(AssertionError,'uncovered canonical'):common.require_catalog_profiles(added)

    def link_and_run(self,label,owned,expected=0):
        host=platform.machine();self.assertIn(host,self.units,'matching native execution profile is missing, not a skipped pass')
        unit=self.units[host];carrier=self.out/(label+'.c');carrier.write_text(CARRIER);objects=[]
        for key,prefix,source in [('reference','reference_',unit['reference']),('owned','owned_',owned)]:
            output=self.out/(label+'.'+key+'.o');self.command(label+'-'+key+'-rename',[self.objcopy,'--prefix-symbols='+prefix,source,output]);objects.append(output)
        binary=self.out/label
        self.command(label+'-link',[self.clang,'-O2','-frounding-math','-ffp-contract=off',carrier,*objects,'-lm','-o',binary])
        common.require_elf_arch(binary,host,{2,3})
        return self.command(label+'-run',[binary],expected=expected)

    def test_matching_native_original_bits_rounding_and_unused_evaluation(self):
        result=self.link_and_run('native-original',self.units[platform.machine()]['owned'])
        self.assertEqual(result.stderr,b'');self.assertEqual(result.stdout.splitlines()[-1],b'PASS 512')

    def test_arithmetic_copy_and_lost_unused_chain_have_semantic_diagnostics(self):
        host=platform.machine();unit=self.units[host]
        wrong=WRAPPER.replace('return fp_barrierf(x);','return x + 0.0f;').replace('return fp_barrier(x);','return x + 0.0;')
        source=self.out/'arithmetic-copy.c';source.write_text(wrong);obj=self.out/'arithmetic-copy.o'
        argv=[str(source) if x==str(unit['build']/'force.c') else x for x in unit['frontend']]
        self.command('arithmetic-copy-build',[*argv,'-c','-o',obj],cwd=unit['build'])
        arithmetic=self.link_and_run('arithmetic-copy',obj,93)
        self.assertRegex(arithmetic.stderr,rb'^fp barrier mismatch case=\d+ function=[23] input=[0-9a-f]{16} reference=[0-9a-f]{16} flags=[0-9a-f]+ owned=[0-9a-f]{16} flags=[0-9a-f]+\n$')
        fields=arithmetic.stdout.splitlines()[-1].split();self.assertNotEqual((fields[5],fields[6]),(fields[10],fields[11]))
        bad=copy.deepcopy(unit['data'])
        for function in bad['functions']:
            if function['name'].startswith('original_force'):
                function['blocks'][0]['instructions']=[]
        with self.assertRaises(InventoryMismatch):check_inventory(unit['inventory'],bad)
        module=self.out/'bad-dce-chain.json';module.write_text(json.dumps(bad));assembly=self.out/'bad-dce-chain.s';obj=self.out/'bad-dce-chain.o'
        self.command('bad-dce-chain-assembly',[self.compiler,module,'--input-kind','native-ir','--emit','asm','--target',host+'-unknown-none','-o',assembly])
        self.command('bad-dce-chain-assemble',[*unit['cc'],'-x','assembler','-c',assembly,'-o',obj])
        lost=self.link_and_run('bad-dce-chain',obj,93)
        self.assertRegex(lost.stderr,rb'^fp barrier mismatch case=\d+ function=[01] input=[0-9a-f]{16} reference=[0-9a-f]{16} flags=[0-9a-f]+ owned=[0-9a-f]{16} flags=[0-9a-f]+\n$')
        fields=lost.stdout.splitlines()[-1].split();self.assertEqual(fields[5],fields[10]);self.assertNotEqual(fields[6],fields[11])

if __name__=='__main__':unittest.main()
