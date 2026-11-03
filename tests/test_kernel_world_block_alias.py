"""Execute real virtio-blk SG copies and retain strict writable isolation."""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define B(name) _O_runtime__aarch64__kernel_world_virtio__##name
extern uint64_t B(configure_backing)(uintptr_t,uintptr_t,uint64_t),B(init)(uint64_t,uint64_t,uint64_t);
extern uint64_t B(mmio_read)(uint64_t),B(mmio_write)(uint64_t,uint64_t),B(poll)(void);
extern uint64_t B(healthy)(void),B(diagnostic)(void),B(detail)(uint64_t),B(writes)(void);
uintptr_t kw_guest_address(uint64_t gpa,uint64_t size) {
    if(!size || gpa<0x40000000 || size>0x20000000 || gpa-0x40000000>0x20000000-size)return 0;
    return gpa+0x08000000;
}
void kw_memory_barrier(void) { __sync_synchronize(); }
void kw_irq_level(uint64_t level) { (void)level; }
static void map(uintptr_t start,size_t size) {
    assert(mmap((void *)start,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)!=MAP_FAILED);
}
static uintptr_t host(uint64_t gpa) { return kw_guest_address(gpa,1); }
static void put(uint64_t gpa,uint64_t value,unsigned bytes) {
    for(unsigned i=0;i<bytes;i++)((uint8_t *)host(gpa))[i]=(uint8_t)(value>>(i*8));
}
static uint64_t get(uint64_t gpa,unsigned bytes) {
    uint64_t v=0;for(unsigned i=0;i<bytes;i++)v|=(uint64_t)((uint8_t *)host(gpa))[i]<<(i*8);return v;
}
static void desc(unsigned id,uint64_t pointer,unsigned length,unsigned flags,unsigned next) {
    uint64_t at=0x40010000+id*16;put(at,pointer,8);put(at+8,length,4);put(at+12,flags,2);put(at+14,next,2);
}
static void wr(unsigned offset,unsigned value) { assert(B(mmio_write)(offset,value)==1); }
int main(int argc,char **argv) {
    assert(argc==2);unsigned scenario=(unsigned)atoi(argv[1]);
    map(0x48000000,0x20000000);map(0x70000000,0x20000);
    memset((void *)0x70000000,0xcc,0x20000);
    assert(B(configure_backing)(0x70000000,0x20000,1)==1 && B(init)(0x40000000,0x20000000,1)==1);
    uint64_t header=0x40013000,first=0x40014000,second=first,status=0x40016000;
    unsigned a=4096,b=4096,type=1,flags=1;
    uint8_t *payload=(uint8_t *)host(first);
    if(scenario==1) {
        a=1024;b=512;second=first+512;
        for(unsigned i=0;i<4096;i++)payload[i]=(uint8_t)(i^(i>>8)^0x5a);
    }
    if(scenario==2) { type=0;flags=3; }
    if(scenario==3)status=first+32;
    if(scenario==4)first=header;
    if(scenario==5)first=0x40010000;
    if(scenario==6)first=0x40011000;
    if(scenario==7)first=0x40012000;
    if(scenario==8)first=0x70000000;
    put(header,type,4);put(header+8,1,8);put(status,0xa5,1);
    desc(0,header,16,1,1);desc(1,first,a,flags,2);desc(2,second,b,flags,3);desc(3,status,1,2,0);
    uint8_t expected[8192];
    if(scenario<2) {memcpy(expected,(void *)host(first),a);memcpy(expected+a,(void *)host(second),b);}
    uint8_t *guest_before=malloc(0x20000);assert(guest_before);memcpy(guest_before,(void *)0x48010000,0x20000);
    wr(112,1);wr(112,3);wr(36,0);wr(32,582);wr(36,1);wr(32,1);wr(112,11);wr(48,0);wr(56,32);
    wr(128,0x40010000);wr(132,0);wr(144,0x40011000);wr(148,0);wr(160,0x40012000);wr(164,0);
    wr(68,1);wr(112,15);put(0x40011004,0,2);put(0x40011002,1,2);
    memcpy(guest_before,(void *)0x48010000,0x20000);
    if(scenario<2) {
        assert(B(poll)()==1 && B(healthy)()==1 && B(writes)()==1);
        assert(get(status,1)==0 && get(0x40012002,2)==1 && get(0x40012008,4)==1);
        assert(!memcmp((void *)0x70000200,expected,a+b));
        for(unsigned i=0;i<512;i++)assert(((uint8_t *)0x70000000)[i]==0xcc);
        for(unsigned i=512+a+b;i<0x20000;i++)assert(((uint8_t *)0x70000000)[i]==0xcc);
        assert(!memcmp((void *)host(first),expected,a));
    } else {
        assert(B(poll)()==0 && B(healthy)()==0 && B(writes)()==0);
        assert(!memcmp(guest_before,(void *)0x48010000,0x20000));
        for(unsigned i=0;i<0x20000;i++)assert(((uint8_t *)0x70000000)[i]==0xcc);
        unsigned reason=scenario<=4?217:(scenario==5?214:(scenario==6?215:(scenario==7?216:213)));
        assert(B(diagnostic)()==reason);
    }
    free(guest_before);printf("production block SG scenario %u: PASS\n",scenario);return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "production native fixture requires Linux x86_64")
class BlockAliasTests(unittest.TestCase):
    def test_legal_readonly_aliases_and_writable_metadata_ring_isolation(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang required")
        with tempfile.TemporaryDirectory(prefix="ocore-block-alias-") as directory:
            output = Path(directory)
            (output / "fixture.c").write_text(HARNESS)
            source = str(ROOT / "ocore/runtime/aarch64/kernel_world_virtio.oc")
            commands = [
                [str(compiler), source, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), source, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "block.o")],
                [clang, "-O2", "-no-pie", str(output / "fixture.c"), str(output / "block.o"), "-o", str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for scenario in range(9):
                result = subprocess.run([str(output / "selftest"), str(scenario)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, f"scenario {scenario}: {result.stdout}{result.stderr}")


if __name__ == "__main__":
    unittest.main()
