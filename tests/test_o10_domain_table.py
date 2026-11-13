"""Real compiled eight-row state/identity/scheduler mechanism component tests."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define T(n) _O_runtime__aarch64__domain_table__##n
extern uint64_t T(boot)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t T(boot_start)(uint64_t,uint64_t,uint64_t);
extern uint64_t T(state)(uint64_t),T(generation)(uint64_t),T(retired)(uint64_t);
extern uint64_t T(handle)(uint64_t),T(lookup)(uint64_t),T(owner)(uint64_t);
extern uint64_t T(kind)(uint64_t),T(backend)(uint64_t),T(ram_base)(uint64_t),T(ram_bytes)(uint64_t);
extern uint64_t T(kernel_image)(uint64_t),T(aux_image)(uint64_t),T(entry_pc)(uint64_t),T(entry_x0)(uint64_t);
extern uint64_t T(instance_byte)(uint64_t,uint64_t);
extern uint64_t T(next)(uint64_t),T(live_mask)(void),T(blocked_mask)(void),T(waiting)(uint64_t);
extern _Bool T(live)(uint64_t),T(runnable)(uint64_t);
extern uint64_t T(block)(uint64_t),T(wake)(uint64_t),T(fault)(uint64_t),T(withdraw)(uint64_t);
extern uint64_t T(next_generation)(uint64_t),T(restored)(uint64_t,uint64_t,const unsigned char*),T(bound)(uint64_t);
extern void T(test_generation)(uint64_t,uint64_t);
extern uint64_t T(empty_slot)(void),T(set_entry)(uint64_t,uint64_t,uint64_t),T(start)(uint64_t,const unsigned char*),T(destroy)(uint64_t);
static void admit(unsigned slot,unsigned kind,unsigned backend){
 uint64_t pa=UINT64_C(0xe2600000)+slot*UINT64_C(0x200000);
 assert(T(boot)(slot,kind,backend,pa,0x200000,5+slot,0)==1);
 assert(T(kind)(slot)==kind&&T(backend)(slot)==backend&&T(ram_base)(slot)==pa&&T(ram_bytes)(slot)==0x200000);
 assert(T(kernel_image)(slot)==5+slot&&!T(aux_image)(slot));
 assert(T(state)(slot)==1&&!T(runnable)(slot));
 assert(!T(boot_start)(slot,0x40200000,0)&&!T(boot_start)(slot,0x40000001,0));
 assert(T(boot_start)(slot,0x40000000,slot)==1);
 assert(T(entry_pc)(slot)==0x40000000&&T(entry_x0)(slot)==slot);
}
static void invalid_and_closed(void){
 for(unsigned slot=0;slot<8;slot++){
  assert(!T(state)(slot)&&T(generation)(slot)==1&&!T(retired)(slot));
  assert(!T(handle)(slot)&&T(lookup)((1ull<<32)|slot)==8);
  assert(!T(live)(slot)&&!T(runnable)(slot)&&!T(block)(slot)&&!T(wake)(slot));
  assert(!T(fault)(slot)&&!T(withdraw)(slot)&&!T(next_generation)(slot));
 }
 assert(T(next)(8)==8&&!T(live_mask)()&&!T(blocked_mask)());
 assert(!T(boot)(8,3,3,0xe2600000,0x200000,5,0));
 assert(!T(boot)(0,0,3,0xe2600000,0x200000,5,0));
 assert(!T(boot)(0,2,3,0xe2600000,0x200000,5,0));
 assert(!T(boot)(0,3,1,0xe2600000,0x200000,5,0));
 assert(!T(boot)(0,3,3,0xe2600001,0x200000,5,0));
 assert(!T(boot)(0,3,3,0xe2600000,0,5,0));
 assert(!T(boot)(0,3,3,UINT64_MAX-0x1fffff,0x200000,5,0));
 assert(!T(boot)(0,3,3,0xe2600000,0x200000,0,0));
 assert(!T(state)(0)&&T(next)(8)==8);
}
static void ownership_and_round_robin(void){
 // Put singleton personalities in non-boot slots. Slot2 is a normal row.
 admit(7,2,1);admit(2,2,2);
 assert(T(owner)(1)==((1ull<<32)|7)&&T(owner)(2)==((1ull<<32)|2));
 assert(!T(owner)(0)&&!T(owner)(3));
 assert(!T(boot)(0,2,1,0xe2600000,0x200000,5,0));
 for(unsigned slot=0;slot<8;slot++)if(slot!=7&&slot!=2)admit(slot,3,3);
 assert(T(live_mask)()==255&&!T(blocked_mask)());
 for(unsigned slot=0;slot<8;slot++)assert(T(next)(slot)==(slot+1)%8);
 assert(T(next)(8)==0&&T(next)(UINT64_MAX)==0);
 assert(T(block)(0)&&T(block)(2)&&T(block)(7));
 assert(T(blocked_mask)()==(1|4|128));
 assert(T(next)(6)==1&&T(next)(1)==3);
 assert(T(wake)(2)&&T(next)(1)==2);
 assert(T(fault)(2)&&T(state)(2)==4&&T(next)(1)==3);
 assert(T(withdraw)(7)&&T(state)(7)==5&&!T(wake)(7));
 for(unsigned slot=0;slot<8;slot++)if(T(runnable)(slot))assert(T(block)(slot));
 assert(T(next)(8)==8);
 assert(T(wake)(4)&&T(next)(4)==4);
}
static void replacement_identity_and_retirement(void){
 unsigned char instance[16];for(unsigned i=0;i<16;i++)instance[i]=(unsigned char)(0x80+i);
 uint64_t old=T(handle)(2);
 assert(T(next_generation)(2)==2&&!T(restored)(2,99,instance));
 assert(T(state)(2)==4&&T(generation)(2)==1);
 assert(T(restored)(2,1,instance)&&T(state)(2)==3&&T(waiting)(2)==1);
 assert(T(lookup)(old)==8&&T(lookup)(T(handle)(2))==2);
 assert(T(owner)(2)==((2ull<<32)|2));
 for(unsigned i=0;i<16;i++)assert(T(instance_byte)(2,i)==instance[i]);
 assert(!T(wake)(2)&&!T(runnable)(2)&&T(next)(1)==4);
 assert(T(bound)(2)&&T(runnable)(2)&&!T(waiting)(2)&&!T(bound)(2));
 assert(T(next)(1)==2);
 // Retire an exhausted stopped row. Its last handle remains observable,
 // but no restore or boot can issue a reused (slot,generation) pair.
 assert(T(fault)(2));T(test_generation)(2,0xffffffff);
 assert(!T(restored)(2,0xfffffffe,instance)&&T(retired)(2)==0);
 assert(!T(next_generation)(2)&&T(retired)(2)==1);
 assert(!T(restored)(2,0xffffffff,instance)&&T(generation)(2)==0xffffffff);
 assert(!T(boot)(2,2,2,0xe2a00000,0x200000,7,0));
 assert(!T(state)(8)&&!T(generation)(8)&&T(retired)(8)&&T(lookup)(UINT64_MAX)==8);
}
static void provisioning_and_destruction(void){
 unsigned char instance[16];memset(instance,0x5b,16);
 uint64_t old=T(handle)(0);
 assert(T(destroy)(old)&&!T(handle)(0)&&T(lookup)(old)==8&&T(empty_slot)()==0);
 assert(T(generation)(0)==2&&!T(kind)(0)&&!T(ram_base)(0));
 for(unsigned i=0;i<16;i++)assert(!T(instance_byte)(0,i));
 assert(!T(destroy)(old)&&!T(set_entry)(old,0x40000000,0)&&!T(start)(old,instance));
 assert(T(boot)(0,3,3,0xe2600000,0x200000,5,6));
 uint64_t fresh=T(handle)(0);assert(fresh==((2ull<<32)|0)&&T(state)(0)==1);
 assert(!T(start)(fresh,instance)&&!T(set_entry)(fresh,0x40200000,0));
 assert(!T(set_entry)(fresh,0x40000001,0)&&T(state)(0)==1);
 assert(T(set_entry)(fresh,0x40000000,0x40100000)&&T(state)(0)==1);
 assert(T(start)(fresh,instance)&&T(state)(0)==2&&!T(start)(fresh,instance));
 for(unsigned i=0;i<16;i++)assert(T(instance_byte)(0,i)==0x5b);
 assert(T(destroy)(fresh)&&T(generation)(0)==3);
 assert(T(boot)(0,3,3,0xe2600000,0x200000,5,6));
 T(test_generation)(0,0xffffffff);assert(T(destroy)(T(handle)(0)));
 assert(T(retired)(0)&&!T(handle)(0)&&T(empty_slot)()==8);
 assert(!T(boot)(0,3,3,0xe2600000,0x200000,5,6));
}
int main(void){
 invalid_and_closed();ownership_and_round_robin();replacement_identity_and_retirement();provisioning_and_destruction();
 puts("eight-row checked state, ownership, scheduler, replacement and exhaustion: PASS");
 return 0;
}
"""


TABLE_TEST_API = r"""
pub unsafe fn test_mask(mask:u64)->void {
    let mut slot:u64=0;
    while slot<8 {
        if STATE[slot as usize]!=0 {
            STATE[slot as usize]=4;
            if ((mask>>slot)&1)!=0 { STATE[slot as usize]=2; }
            WAIT_BIND[slot as usize]=0;
        }
        slot+=1;
    }
}
pub unsafe fn test_generation(slot:u64,value:u64)->void { GENERATION[slot as usize]=value; }
"""



def extend_world(source, wrapper):
    # O-core imports precede all item definitions. Fixture helpers may import
    # test-only table accessors, while the production file stays unchanged.
    lines = wrapper.splitlines()
    imports = [line for line in lines if line.startswith("use ")]
    body = "\n".join(line for line in lines if not line.startswith("use "))
    declaration = "module runtime::aarch64::unified_world;"
    return source.replace(declaration, declaration + "\n" + "\n".join(imports), 1) + "\n" + body + "\n"

def write_table_fixture(output):
    source = output / "domain_table.oc"
    source.write_text((ROOT / "ocore/runtime/aarch64/domain_table.oc").read_text() + TABLE_TEST_API)
    return source


class DomainTableTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                         "native component fixture requires Linux x86_64")
    def test_real_table_and_aarch64_lowering(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang = shutil.which("clang")
        self.assertTrue(compiler.is_file())
        self.assertIsNotNone(clang)
        with tempfile.TemporaryDirectory(prefix="o10-domain-table-") as temporary:
            output = Path(temporary)
            source = output / "table.oc"
            source.write_text((ROOT / "ocore/runtime/aarch64/domain_table.oc").read_text() +
                "\npub unsafe fn test_generation(slot:u64,value:u64)->void { GENERATION[slot as usize]=value; }\n")
            for target, name in [("aarch64-unknown-none", "arm.o"), ("x86_64-unknown-none", "native.o")]:
                result = subprocess.run([str(compiler), str(source), "--target", target, "--emit", "obj",
                                         "-o", str(output / name)], capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            (output / "harness.c").write_text(HARNESS)
            result = subprocess.run([clang, "-O2", str(output / "harness.c"), str(output / "native.o"),
                                     "-o", str(output / "test")], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(output / "test")], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
