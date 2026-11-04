"""Complete authored LLVM ABI fixtures, not original-runtime acceptance.

Reference/reference must pass before any owned pairing. The separate source
controls retain the three unchanged Lua units; no foreign source is retargeted
or rewritten here. A newly admitted compiler and strict launcher are required.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import struct
import unittest
from tests import test_ocore_native_variadic_abi as support

MASK=(1<<64)-1
SEEDS=(0,1,0x8000000000000000,0xFEDCBA9876543210)
LITERALS=(0,9,10,255,2147483647)
BASE_CASES=tuple([('literal',x,False) for x in LITERALS]+[('byte',x,False) for x in range(256)]+[('width',n,False) for n in range(1,32)]+[('literal',x,True) for x in LITERALS]+[('byte',x,True) for x in range(256)])

# Observe the return value and post-call state independently. Combining them
# with xor could cancel exactly the upper-bit defect this test must expose.
CASES=tuple((*case,observation) for case in BASE_CASES for observation in ('return','state'))

def value(case,seed):
    kind,n,_,_=case
    if kind=='literal':return n
    if kind=='byte':return (seed+n)&255
    return seed&((1<<n)-1)

def oracle(case,seed):
    x=value(case,seed)
    if not case[2]:
        returned=(x+17)&MASK;state=seed^x
    else:
        returned=((seed+sum(17*i for i in range(1,9)))&MASK)^x
        state=(seed+returned)&MASK
    return returned if case[3]=='return' else state

def corrupt_rv_argument(assembly,kind):
    # Deliberately corrupt a single concrete outgoing argument in a copied
    # owned assembly file, never the positive artifact. The stack slot belongs
    # to this controlled nine-i64-prefix fixture; the shared planner's test
    # independently asserts argument 9 is Stack{offset:8} for both RV profiles.
    if kind=='register-upper':
        symbol='register_entry'
        instructions='  li t0,1099511627776\n  or a0,a0,t0\n'
    elif kind=='stack-low':
        symbol='stack_entry'
        instructions='  ld t0,8(sp)\n  xori t0,t0,1\n  sd t0,8(sp)\n'
    else:raise AssertionError('unknown intentional corruption')
    pattern=re.compile(r'(?m)^([ \t]*call[ \t]+'+symbol+r'(?:@plt)?[ \t]*)$')
    matches=list(pattern.finditer(assembly))
    if not matches:raise AssertionError('expected concrete owned call site absent')
    match=matches[0]
    return assembly[:match.start()]+instructions+assembly[match.start():]

def header(profile):
    isa=support.PROFILES[profile][0]
    text=f'target triple = "{isa}-unknown-linux-gnu"\ntarget datalayout = "e-m:e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"\n'
    if profile.startswith('riscv64-'):
        abi=profile.removeprefix('riscv64-')
        text+=f'!llvm.module.flags = !{{!0}}\n!0 = !{{i32 1, !"target-abi", !"{abi}"}}\n'
    return text

def provider_source(profile):
    text=header(profile)+'''@provider_marker = global i64 3141592653589793,align 8

define i64 @register_entry(i32 signext %x,ptr %state) {
 %v=sext i32 %x to i64
 %old=load i64,ptr %state,align 8
 %next=xor i64 %old,%v
 store i64 %next,ptr %state,align 8
 %result=add i64 %v,17
 ret i64 %result
}
'''
    params=','.join(f'i64 %a{i}' for i in range(9))
    text+=f'define i64 @stack_entry({params},i32 signext %x,ptr %state) {{\n'
    previous='%a0'
    for i in range(1,9):
        text+=f' %sum{i}=add i64 {previous},%a{i}\n';previous=f'%sum{i}'
    text+=f''' %v=sext i32 %x to i64
 %result=xor i64 {previous},%v
 %old=load i64,ptr %state,align 8
 %next=add i64 %old,%result
 store i64 %next,ptr %state,align 8
 ret i64 %result
}}
define i64 @original_cold(i64 %x) {{ %r=xor i64 %x,2718281828459045
 ret i64 %r }}
'''
    return text

def caller_source(profile):
    text=header(profile)+'@caller_state=global i64 0,align 8\n'
    text+='declare i64 @register_entry(i32 signext,ptr)\n'
    text+='declare i64 @stack_entry('+','.join(['i64']*9)+',i32 signext,ptr)\n'
    text+='define i64 @call_abi_case(i64 %id,i64 %seed) {\nentry:\n store i64 %seed,ptr @caller_state,align 8\n switch i64 %id,label %bad [\n'
    for i in range(len(CASES)):text+=f' i64 {i},label %case{i}\n'
    text+=']\n'
    for i,(kind,n,stack,observation) in enumerate(CASES):
        text+=f'case{i}:\n'
        if kind=='literal':argument=str(n)
        elif kind=='byte':
            text+=f' %small{i}=trunc i64 %seed to i8\n %byte{i}=add i8 %small{i},{n}\n %wide{i}=zext i8 %byte{i} to i32\n';argument=f'%wide{i}'
        else:
            text+=f' %small{i}=trunc i64 %seed to i{n}\n %wide{i}=zext i{n} %small{i} to i32\n';argument=f'%wide{i}'
        if stack:
            args=['i64 %seed']+[f'i64 {17*j}' for j in range(1,9)]+[f'i32 {argument}','ptr @caller_state']
            text+=f' %r{i}=call i64 @stack_entry('+','.join(args)+')\n'
        else:text+=f' %r{i}=call i64 @register_entry(i32 {argument},ptr @caller_state)\n'
        text+=f' %state{i}=load i64,ptr @caller_state,align 8\n'
        text+=f' ret i64 %r{i}\n' if observation=='return' else f' ret i64 %state{i}\n'
    return text+'bad:\n ret i64 0\n}\n'

def carrier_source():
    text=support.carrier_source().replace('variadic_case','call_abi_case')
    text=text.replace(f'output[{len(support.CASES)*len(support.SEEDS)}]',f'output[{len(CASES)*len(SEEDS)}]')
    text=text.replace(f'test<{len(support.CASES)}',f'test<{len(CASES)}').replace(f'seed<{len(support.SEEDS)}',f'seed<{len(SEEDS)}')
    old='static const u64 seeds[]={'+','.join(f'{x}ULL' for x in support.SEEDS)+'};'
    new='static const u64 seeds[]={'+','.join(f'{x}ULL' for x in SEEDS)+'};'
    return text.replace(old,new)

class NativeCallAbiExtensionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('OCORE_REQUIRE_ALL_ISAS')!='1' or not os.environ.get('OCORE_TEST_OCOREC'):
            raise AssertionError('explicit admitted compiler and complete no-skip execution required')
        expected=os.environ.get('OCORE_CALL_ABI_COMPILER_SHA256')
        if not expected or support.artifact(os.environ['OCORE_TEST_OCOREC'])['sha256']!=expected:
            raise AssertionError('compiler must match the reviewed explicit new-compiler SHA256')
        support.NativeVariadicAbiTests.setUpClass.__func__(cls)
    tearDownClass=classmethod(support.NativeVariadicAbiTests.tearDownClass.__func__)
    setUp=support.NativeVariadicAbiTests.setUp
    save=support.NativeVariadicAbiTests.save
    command=support.NativeVariadicAbiTests.command
    frontend_flags=support.NativeVariadicAbiTests.frontend_flags
    original=support.NativeVariadicAbiTests.original
    owned=support.NativeVariadicAbiTests.owned
    assert_elf=support.NativeVariadicAbiTests.assert_elf
    execution_prefix=support.NativeVariadicAbiTests.execution_prefix

    def original_ir(self,name,source,profile):
        llvm=self.directory/(name+'.ll');llvm.write_text(source)
        obj=self.directory/(name+'.reference.o')
        self.command([self.clang,*self.frontend_flags(profile),'-x','ir','-c',llvm,'-o',obj])
        self.assert_elf(obj,support.PROFILES[profile][2],1)
        return llvm,obj
    def check_profile(self,profile):
        isa,mode,machine,_=support.PROFILES[profile];runner=self.execution_prefix(isa)
        self.record.update(schema='ocore-c-i32-argument-transport-mechanism-v1',profile=profile,
            source_kind='authored complete LLVM mechanism modules, not an upstream runtime',
            logical_profile='defined-nonnegative-i32-argument-and-separate-i64-return-state-v1',
            cases=list(CASES),seeds=list(SEEDS),
            logical_cases_sha256=hashlib.sha256(json.dumps([CASES,SEEDS],separators=(',',':')).encode()).hexdigest(),
            runtime_accepted=False,all_isa_identity_qualified=False,foundation_profiles_unqualified=['i686','armv7'])
        pl,po=self.original_ir('provider',provider_source(profile),profile)
        cl,co=self.original_ir('caller',caller_source(profile),profile)
        hc,hl,ho=self.original('carrier',carrier_source(),profile)
        originals=[support.artifact(p) for p in [pl,cl,hc,hl]];self.record['original_inputs']=originals
        expected_values=[oracle(case,seed) for case in CASES for seed in SEEDS]
        expected=struct.pack('<'+'Q'*len(expected_values),*expected_values)
        self.record['comparisons_per_pairing']=len(expected_values)
        self.record['expected_output_sha256']=hashlib.sha256(expected).hexdigest();self.save()
        def execute(cname,caller,pname,provider,corruption=None):
            executable=self.directory/f'{cname}-caller-{pname}-provider.elf'
            self.command([self.linker,'-static','--no-relax','-m',mode,'-e','_start',ho,caller,provider,'-o',executable])
            self.assert_elf(executable,machine,2)
            result=self.command([*runner,executable],timeout=60)
            self.assertEqual(len(result.stdout),len(expected),'complete raw observation inventory required')
            item={'caller':cname,'provider':pname,'comparisons':len(expected_values),
                'caller_object':support.artifact(caller),'provider_object':support.artifact(provider),
                'carrier_object':support.artifact(ho),'executable':support.artifact(executable),
                'output_sha256':hashlib.sha256(result.stdout).hexdigest()}
            if corruption is None:
                self.assertEqual(result.stdout,expected,f'{profile}/{cname}/{pname}: raw return/state oracle mismatch')
                self.record['pairings'].append(item)
            else:
                self.assertNotEqual(result.stdout,expected,'intentional corruption was not observable; harness remains RED')
                actual=struct.unpack('<'+'Q'*len(expected_values),result.stdout)
                mismatch=next(i for i,(a,b) in enumerate(zip(actual,expected_values)) if a!=b)
                first_case=next(i for i,c in enumerate(CASES) if c[2]==(corruption=='stack-low'))
                self.assertEqual(mismatch//len(SEEDS),first_case,'failure must expose the deliberately corrupted first call')
                item.update(kind=corruption,first_mismatch=mismatch,case=list(CASES[mismatch//len(SEEDS)]),
                    expected=expected_values[mismatch],actual=actual[mismatch],
                    scope='reference callee observes deliberate outgoing owned argument corruption')
                self.record.setdefault('corruption_controls',[]).append(item)
            self.save()
        execute('reference',co,'reference',po)
        own_provider=self.owned('provider',pl,profile);own_caller=self.owned('caller',cl,profile)
        execute('reference',co,'owned',own_provider)
        execute('owned',own_caller,'reference',po)
        execute('owned',own_caller,'owned',own_provider)
        if profile.startswith('riscv64-'):
            assembly=self.directory/'caller.owned.s';positive=support.artifact(assembly)
            for kind in ('register-upper','stack-low'):
                mutant=self.directory/f'caller.{kind}.corrupt.s'
                mutant.write_text(corrupt_rv_argument(assembly.read_text(),kind))
                obj=self.directory/f'caller.{kind}.corrupt.o'
                self.command([self.clang,*self.frontend_flags(profile),'-x','assembler','-c',mutant,'-o',obj])
                self.assert_elf(obj,machine,1)
                execute(kind,obj,'reference',po,corruption=kind)
                self.record['corruption_controls'][-1]['assembly']=support.artifact(mutant);self.save()
            self.assertEqual(support.artifact(assembly),positive)
            self.assertEqual(len(self.record['corruption_controls']),2)
        self.assertEqual([support.artifact(x['path']) for x in originals],originals)
        self.assertEqual(len(self.record['original_source_inventory_checks']),2)
        module=json.loads((self.directory/'caller.native.json').read_text())
        for function in module['functions']:
            for block in function['blocks']:
                for instruction in block['instructions']:
                    if instruction['operation']['op']=='call':
                        self.assertTrue(all(not x for x in instruction['operation']['signature']['param_attributes']))
        self.record['complete']=len(self.record['pairings'])==4
        self.record['native_execution_qualified']=self.record['complete'];self.save()

    def test_x86_64(self):self.check_profile('x86_64')
    def test_aarch64(self):self.check_profile('aarch64')
    def test_riscv64_lp64(self):self.check_profile('riscv64-lp64')
    def test_riscv64_lp64d(self):self.check_profile('riscv64-lp64d')


class CallAbiFixtureSourceControls(unittest.TestCase):
    """No frontend, native compiler, assembler, linker, or execution occurs."""
    def test_raw_return_and_state_are_separate_and_oracle_is_defined(self):
        self.assertEqual(len(BASE_CASES),553);self.assertEqual(len(CASES),1106)
        for base in BASE_CASES:
            returned=(*base,'return');state=(*base,'state')
            for seed in SEEDS:
                self.assertGreaterEqual(value(returned,seed),0)
                self.assertLess(value(returned,seed),1<<31)
                self.assertGreaterEqual(oracle(returned,seed),0)
                self.assertLessEqual(oracle(state,seed),MASK)
        # The former xor would hide a shared bit40 fault in both observations.
        r=oracle(('literal',0,False,'return'),0)
        t=oracle(('literal',0,False,'state'),0)
        self.assertEqual(r^t,(r^(1<<40))^(t^(1<<40)))
        self.assertNotEqual((r,t),(r^(1<<40),t^(1<<40)))

    def test_corruption_is_separate_and_exactly_at_first_selected_call(self):
        assembly='before\n  call register_entry\nmid\n  call register_entry\n  call stack_entry\nafter\n'
        for kind,marker in [('register-upper','  or a0,a0,t0\n'),('stack-low','  sd t0,8(sp)\n')]:
            changed=corrupt_rv_argument(assembly,kind)
            self.assertEqual(changed.count(marker),1)
            self.assertEqual(changed.count('  call register_entry\n'),2)
            self.assertEqual(changed.count('  call stack_entry\n'),1)
            self.assertEqual(changed.replace('  li t0,1099511627776\n  or a0,a0,t0\n','').replace('  ld t0,8(sp)\n  xori t0,t0,1\n  sd t0,8(sp)\n',''),assembly)
        with self.assertRaisesRegex(AssertionError,'call site absent'):
            corrupt_rv_argument('no calls\n','register-upper')

    def test_whole_fixture_membership_and_original_signature_distinction(self):
        for profile in support.PROFILES:
            caller=caller_source(profile);provider=provider_source(profile)
            self.assertEqual(len(re.findall(r'^case\d+:',caller,re.M)),1106)
            self.assertEqual(len(re.findall(r' =?call i64|=call i64',caller)),1106)
            self.assertNotIn('%observable',caller)
            self.assertIn('declare i64 @register_entry(i32 signext,ptr)',caller)
            self.assertIn('define i64 @register_entry(i32 signext %x,ptr %state)',provider)
            self.assertNotRegex(caller,r'=call i64 @\w+\([^\n]*i32 signext')
            self.assertIn('@provider_marker',provider);self.assertIn('@original_cold',provider)
            self.assertIn(f'output[{len(CASES)*len(SEEDS)}]',carrier_source())

if __name__=='__main__':unittest.main()
