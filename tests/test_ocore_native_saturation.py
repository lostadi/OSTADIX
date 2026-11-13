"""Unsigned saturation mechanism controls, never original-runtime acceptance.

The full authored C caller/provider units must pass original Clang reference
execution before any owned pairing is attempted. Native execution requires a
new admitted compiler embedding the saturation importer and an independently
reviewed strict launcher; discovery/oracle checks alone do not qualify it.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest
from tests import test_ocore_native_variadic_abi as support

MASK = (1 << 64) - 1
SEEDS = (0, 1, 0x8000000000000000, 0xFEDCBA9876543210)
PROVIDER = r"""
typedef unsigned long long u64;
typedef unsigned __int128 u128;
unsigned sat32(unsigned a,unsigned b){return __builtin_elementwise_sub_sat(a,b);}
u64 sat64(u64 a,u64 b){return __builtin_elementwise_sub_sat(a,b);}
u128 sat128(u128 a,u128 b){return __builtin_elementwise_sub_sat(a,b);}
u64 original_cold(u64 a){return a^0x3141592653589793ULL;}
const u64 original_marker=0x2718281828459045ULL;
"""

def pairs(width):
    limit = (1 << width) - 1
    boundary = (0, 1, 2, (1 << (width-1))-1, 1 << (width-1),
                (1 << (width-1))+1, limit-1, limit)
    output = [(a,b) for a in boundary for b in boundary]
    for bit in range(width):
        value=1 << bit
        output.extend(((value,value), (value-1,value), (value,value-1), (value+1,value)))
    state=0x243F6A8885A308D3
    for _ in range(128):
        words=[]
        for _ in range(4):
            state=(state*0x5851F42D4C957F2D+0x14057B7EF767814F)&MASK
            words.append(state)
        output.append(((words[0] | words[1]<<64)&limit, (words[2] | words[3]<<64)&limit))
    return output

CASES = tuple((width,a,b,word) for width in (32,64,128)
              for a,b in pairs(width) for word in range(2 if width==128 else 1))

def inputs(case, seed):
    width,a,b,_=case; limit=(1 << width)-1
    other=((seed << 17)|(seed >> 47))&MASK
    seed_a=seed|(seed<<64); seed_b=other|(other<<64)
    return (a^seed_a)&limit,(b^seed_b)&limit

def oracle(case, seed):
    a,b=inputs(case,seed)
    return max(a-b,0) >> (64*case[3]) & MASK

def values():
    return [oracle(case,seed) for case in CASES for seed in SEEDS]

def array(name, data, ctype='u64'):
    return 'static const '+ctype+' '+name+'[]={'+','.join(str(x)+('ULL' if ctype=='u64' else '') for x in data)+'};\n'

def caller_source():
    text='typedef unsigned long long u64;typedef unsigned __int128 u128;\n'
    text+='extern unsigned sat32(unsigned,unsigned);extern u64 sat64(u64,u64);extern u128 sat128(u128,u128);\n'
    for name,data,typ in [('a_lo',[a&MASK for _,a,_,_ in CASES],'u64'),
                           ('a_hi',[a>>64 for _,a,_,_ in CASES],'u64'),
                           ('b_lo',[b&MASK for _,_,b,_ in CASES],'u64'),
                           ('b_hi',[b>>64 for _,_,b,_ in CASES],'u64'),
                           ('width',[w for w,_,_,_ in CASES],'unsigned'),
                           ('part',[w for _,_,_,w in CASES],'unsigned')]:
        text+=array(name,data,typ)
    text+=r"""
u64 saturation_case(u64 id,u64 seed){
    u64 other=(seed<<17)|(seed>>47);
    u64 al=a_lo[id]^seed,ah=a_hi[id]^seed;
    u64 bl=b_lo[id]^other,bh=b_hi[id]^other;
    if(width[id]==32)return sat32((unsigned)al,(unsigned)bl);
    if(width[id]==64)return sat64(al,bl);
    u128 a=((u128)ah<<64)|al,b=((u128)bh<<64)|bl;
    u128 result=sat128(a,b);return part[id]?(u64)(result>>64):(u64)result;
}
"""
    return text

def carrier_source():
    text=support.carrier_source().replace('variadic_case','saturation_case')
    text=text.replace(f'output[{len(support.CASES)*len(support.SEEDS)}]',f'output[{len(CASES)*len(SEEDS)}]')
    text=text.replace(f'test<{len(support.CASES)}',f'test<{len(CASES)}')
    text=text.replace(f'seed<{len(support.SEEDS)}',f'seed<{len(SEEDS)}')
    original='static const u64 seeds[]={'+','.join(f'{s}ULL' for s in support.SEEDS)+'};'
    return text.replace(original,array('seeds',SEEDS).strip())

class NativeSaturationControls(unittest.TestCase):
    # Reuse helpers, not inherited test methods or a selected subset of source.
    @classmethod
    def setUpClass(cls):
        if os.environ.get('OCORE_REQUIRE_ALL_ISAS') != '1':
            raise AssertionError('saturation native controls require an explicit complete no-skip matrix')
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

    def check_profile(self,profile):
        isa,mode,machine,_=support.PROFILES[profile]
        runner=self.execution_prefix(isa)
        self.record.update(schema='ocore-unsigned-saturation-mechanism-v1',profile=profile,
                           logical_profile='unsigned-bitvectors-32-64-128-defined-v1',
                           source_cases=list(CASES),seeds=list(SEEDS),
                           source_cases_sha256=hashlib.sha256(json.dumps([CASES,SEEDS],separators=(',',':')).encode()).hexdigest(),
                           original_runtime_complete=False,all_isa_functional_identity_qualified=False,
                           foundation_profiles_unqualified=['i686','armv7'])
        self.save()
        pc,pl,po=self.original('saturation-provider',PROVIDER,profile)
        cc,cl,co=self.original('saturation-caller',caller_source(),profile)
        hc,hl,ho=self.original('saturation-carrier',carrier_source(),profile)
        originals=[support.artifact(p) for p in (pc,pl,cc,cl,hc,hl)]
        self.record['original_inputs']=originals
        for bits in (32,64,128):
            self.assertIn('@llvm.usub.sat.i'+str(bits)+'(',pl.read_text())
        expected=struct.pack('<'+'Q'*len(values()),*values())
        self.record['expected_output_sha256']=hashlib.sha256(expected).hexdigest()
        self.record['comparisons_per_pairing']=len(values())
        self.save()
        def execute(caller_name,caller,provider_name,provider):
            executable=self.directory/f'{caller_name}-caller-{provider_name}-provider.elf'
            self.command([self.linker,'-static','--no-relax','-m',mode,'-e','_start',ho,caller,provider,'-o',executable])
            self.assert_elf(executable,machine,2)
            result=self.command([*runner,executable],timeout=60)
            self.assertEqual(result.stdout,expected,f'{profile}: {caller_name}/{provider_name} differs from defined integer oracle')
            self.record['pairings'].append({'caller':caller_name,'provider':provider_name,
                'comparisons':len(values()),'executable':support.artifact(executable),
                'output_sha256':hashlib.sha256(result.stdout).hexdigest()})
            self.save()
        # A failed original reference must never be mislabeled an owned mismatch.
        execute('reference',co,'reference',po)
        owned_provider=self.owned('saturation-provider',pl,profile)
        owned_caller=self.owned('saturation-caller',cl,profile)
        execute('reference',co,'owned',owned_provider)
        execute('owned',owned_caller,'reference',po)
        execute('owned',owned_caller,'owned',owned_provider)
        self.assertEqual([support.artifact(p['path']) for p in originals],originals)
        self.assertEqual(len(self.record['original_source_inventory_checks']),2)
        self.record['complete']=len(self.record['pairings'])==4
        self.record['native_execution_qualified']=self.record['complete']
        self.save()

    def test_x86_64(self):self.check_profile('x86_64')
    def test_aarch64(self):self.check_profile('aarch64')
    def test_riscv64_lp64(self):self.check_profile('riscv64-lp64')
    def test_riscv64_lp64d(self):self.check_profile('riscv64-lp64d')

if __name__=='__main__':unittest.main()
