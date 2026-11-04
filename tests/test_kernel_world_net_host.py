"""Execute the production outer NIC driver against bounded native MMIO rings."""

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
#define HOST(name) _O_runtime__aarch64__kernel_world_net_host__##name
extern uint64_t HOST(init)(void), HOST(healthy)(void), HOST(sent)(void), HOST(received)(void);
extern uint64_t HOST(diagnostic)(void), HOST(detail)(void);
extern void HOST(poll)(void);
extern uint64_t HOST(send)(const uint8_t *,size_t);
extern size_t HOST(receive)(uint8_t *,size_t);
static volatile uint32_t *mmio;
static unsigned selected, ready[2];
static uint32_t desc[2],avail[2],used[2];
static void *map(uintptr_t base,size_t length) {
    void *p=mmap((void *)base,length,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(p!=(void *)-1);return p;
}
void kw_memory_barrier(void) {
    __sync_synchronize();
    if (!mmio) return;
    unsigned next=mmio[0x30/4];
    assert(next<2);
    ready[selected]=mmio[0x44/4];
    desc[selected]=mmio[0x80/4]; avail[selected]=mmio[0x90/4]; used[selected]=mmio[0xa0/4];
    if (next!=selected) {
        selected=next;
        mmio[0x44/4]=ready[selected];
        mmio[0x80/4]=desc[selected]; mmio[0x90/4]=avail[selected]; mmio[0xa0/4]=used[selected];
    }
    mmio[0x10/4]=mmio[0x14/4] ? 1:32;
    mmio[0x60/4]&=~mmio[0x64/4];mmio[0x64/4]=0;
}
static uint16_t r16(uintptr_t address) { return *(volatile uint16_t *)address; }
static uint32_t r32(uintptr_t address) { return *(volatile uint32_t *)address; }
static uint64_t r64(uintptr_t address) { return *(volatile uint64_t *)address; }
static void p16(uintptr_t address,uint16_t value) { *(volatile uint16_t *)address=value; }
static void p32(uintptr_t address,uint32_t value) { *(volatile uint32_t *)address=value; }
int main(int argc,char **argv) {
    assert(argc==2);unsigned scenario=(unsigned)atoi(argv[1]);
    map(0x08000000,65536); map(0x0a000000,0x4000); map(0x6e000000,0x200000);
    mmio=(volatile uint32_t *)0x0a003e00;
    mmio[0]=0x74726976;mmio[1]=2;mmio[2]=1;mmio[0x34/4]=16;
    mmio[0x100/4]=0x12005452;mmio[0x104/4]=0x5634;
    if (scenario==1) mmio[1]=1;
    if (scenario==2) mmio[0x100/4]=0;
    if (scenario==3) {
        volatile uint32_t *other=(volatile uint32_t *)0x0a003c00;
        other[0]=0x74726976;other[1]=2;other[2]=1;
    }
    if (scenario>=1 && scenario<=3) {
        assert(HOST(init)()==0 && HOST(healthy)()==0);return 0;
    }
    assert(HOST(init)()==1 && HOST(healthy)()==1);
    assert(ready[0]==1 && ready[1]==1);
    for(unsigned q=0;q<2;q++) {
        assert(desc[q]>=0x6e000000 && desc[q]<0x6e200000);
        assert(avail[q]>=0x6e000000 && avail[q]<0x6e200000);
        assert(used[q]>=0x6e000000 && used[q]<0x6e200000);
    }
    assert(r16(0x6e001000)==1 && r16(0x6e005000)==1); // NO_INTERRUPT.
    assert(r16(0x6e001002)==16);
    for(unsigned id=0;id<16;id++) {
        uintptr_t entry=0x6e000000+id*16;
        assert(r64(entry)==0x6e010000+id*2048 && r32(entry+8)==2048 && r16(entry+12)==2);
    }
    uint8_t frame[1514], output[1514];for(unsigned i=0;i<1514;i++)frame[i]=(uint8_t)(i^0x5a);
    assert(HOST(send)(frame,13)==0 && HOST(send)(frame,1515)==0);
    assert(HOST(healthy)()==1 && HOST(sent)()==0);
    if (scenario==13) {
        mmio[0x70/4]=0;HOST(poll)();assert(HOST(healthy)()==0);
        assert(HOST(diagnostic)()==601 && HOST(detail)()==0);return 0;
    }
    if (scenario>=4 && scenario<=7) {
        if (scenario!=5) assert(HOST(send)(frame,14)==1);
        p32(0x6e006004,scenario==4 ? 16:0);
        p32(0x6e006008,scenario==6 ? 2049:0);
        p16(0x6e006002,scenario==7 ? 17:1);
        HOST(poll)();assert(HOST(healthy)()==0);
        assert(HOST(diagnostic)()==(scenario==4 ? 603:(scenario==5 ? 605:(scenario==6 ? 604:602))));
        assert(HOST(detail)()==(scenario==4 ? 16:(scenario==5 ? 0:(scenario==6 ? 2049:17ull<<32))));return 0;
    }
    if (scenario>=8) {
        uintptr_t buffer=0x6e010000; memset((void *)buffer,0,2048);
        memcpy((void *)(buffer+12),frame,14);
        p32(0x6e002004,scenario==8 ? 16:0);
        p32(0x6e002008,scenario==9 ? 25:(scenario==10 ? 1527:26));
        p16(0x6e002002,scenario==11 ? 17:1);
        if(scenario==12) *(uint8_t *)buffer=1;
        assert(HOST(receive)(output,sizeof output)==0 && HOST(healthy)()==0);
        assert(HOST(diagnostic)()==(scenario==8 ? 702:(scenario==9 || scenario==10 ? 703:(scenario==11 ? 701:705))));return 0;
    }
    for(unsigned i=0;i<16;i++) assert(HOST(send)(frame,14)==1);
    assert(HOST(send)(frame,14)==0 && HOST(healthy)()==1);
    for(unsigned id=0;id<16;id++) {
        uintptr_t entry=0x6e004000+id*16, buffer=0x6e020000+id*2048;
        assert(r64(entry)==buffer && r32(entry+8)==26 && r16(entry+12)==0);
        for(unsigned i=0;i<12;i++)assert(*(uint8_t *)(buffer+i)==0);
        assert(memcmp((void *)(buffer+12),frame,14)==0);
        p32(0x6e006004+id*8,id);p32(0x6e006008+id*8,0);
    }
    p16(0x6e006002,16);HOST(poll)();
    assert(HOST(send)(frame,1514)==1 && HOST(sent)()==17);
    memset((void *)0x6e010000,0,2048);memcpy((void *)0x6e01000c,frame,1514);
    p32(0x6e002004,0);p32(0x6e002008,1526);p16(0x6e002002,1);
    assert(HOST(receive)(output,sizeof output)==1514 && memcmp(output,frame,1514)==0);
    assert(r16(0x6e001002)==17 && HOST(received)()==1 && HOST(healthy)()==1);
    puts("outer NIC private DMA, frame copies, queue backpressure and negative tests: PASS");
    return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "host MMIO/ring execution fixture requires Linux x86_64")
class KernelWorldNetHostTests(unittest.TestCase):
    def test_real_outer_driver_owned_dma_and_ring_validation(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-net-host-") as directory:
            output = Path(directory)
            (output / "harness.c").write_text(HARNESS)
            source = str(ROOT / "ocore/runtime/aarch64/kernel_world_net_host.oc")
            commands = [
                [str(compiler), source, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), source, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "net.o")],
                [clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "net.o"), "-o", str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for scenario in range(14):
                result = subprocess.run([str(output / "selftest"), str(scenario)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, f"scenario {scenario}: {result.stdout}{result.stderr}")


if __name__ == "__main__":
    unittest.main()
