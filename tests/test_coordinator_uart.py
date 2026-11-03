"""Compile and execute the production Linux-private coordinator PL011.

Only its native interrupt/barrier hooks are fixtures. This covers exact-byte
queues and native private-memory effects, not Linux boot or baud timing.
"""
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define U(n) _O_runtime__aarch64__coordinator_uart__##n
#define MAIL ((uint8_t*)0x6d060008)
#define OUTPUT ((uint8_t*)0x6d080000)
extern uint64_t U(init)(void),U(mmio_read)(uint64_t),U(inject)(const uint8_t*,uintptr_t);
extern bool U(mmio_write)(uint64_t,uint64_t);
static uint64_t irq,transitions,barriers;
void cu_irq_level(uint64_t v){assert(v<2);irq=v;transitions++;}
void uw_memory_barrier(void){__sync_synchronize();barriers++;}
static uint64_t word(const void*p){uint64_t v;memcpy(&v,p,8);return v;}
static void putword(void*p,uint64_t v){memcpy(p,&v,8);}
static uint64_t hash(const uint8_t*p,size_t n){uint64_t h=0xcbf29ce484222325;while(n--)h=(h^*p++)*0x100000001b3;return h;}
static void write_(uint64_t reg,uint64_t v){assert(U(mmio_write)(reg,v));}
static void configure(void){
    // Actual Linux PL011 startup/termios operations: no DMA, FIFO+8bit,
    // RX/timeout interrupt masks; its TX-ready level is masked when idle.
    write_(0x30,0);write_(0x38,0);write_(0x44,0x7ff);write_(0x24,13);write_(0x28,1);
    write_(0x2c,0x70);write_(0x34,0x12);write_(0x48,0);write_(0x30,0x301);write_(0x38,0x50);
}
static void unchanged_edges(void){
    const uint8_t *mb=(void*)0x6d060000;
    for(unsigned i=0;i<8;i++)assert(mb[i]==0xa5);
    for(unsigned i=8200;i<12288;i++)assert(mb[i]==0xa5);
    for(unsigned i=65544;i<69632;i++)assert(OUTPUT[i]==0x5a);
}
int main(void){
    assert(mmap((void*)0x6d05f000,0x5000,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0x6d05f000);
    assert(!mprotect((void*)0x6d060000,0x3000,PROT_READ|PROT_WRITE));
    assert(mmap((void*)0x6d07f000,0x13000,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0x6d07f000);
    assert(!mprotect(OUTPUT,0x11000,PROT_READ|PROT_WRITE));
    memset((void*)0x6d060000,0xa5,0x3000);memset(OUTPUT,0x5a,0x11000);
    assert(!U(inject)(MAIL,1)&&!U(mmio_write)(0x30,0x301));
    assert(U(init)()==1&&irq==0&&word(OUTPUT)==0&&barriers==1);
    for(unsigned i=8;i<65544;i++)assert(OUTPUT[i]==0);
    assert(U(mmio_read)(0x18)==0x90&&U(mmio_read)(0x30)==0x300);
    uint64_t ids[]={0x11,0x10,0x14,0,0x0d,0xf0,0x05,0xb1};
    for(unsigned i=0;i<8;i++)assert(U(mmio_read)(0xfe0+i*4)==ids[i]);
    // Whole-message credit/range checks precede ALL byte reads and effects.
    uint64_t before=hash(OUTPUT,65544),calls=transitions;
    assert(!U(inject)((void*)1,1)&&!U(inject)((void*)UINTPTR_MAX,2));
    assert(!U(inject)(MAIL-1,1)&&!U(inject)(MAIL,0)&&!U(inject)(MAIL,8193));
    assert(!U(inject)(MAIL+8191,2)&&!U(inject)(MAIL+8192,1));
    assert(transitions==calls&&before==hash(OUTPUT,65544));
    for(unsigned i=0;i<8192;i++)MAIL[i]=(uint8_t)(i*37);
    assert(U(inject)(MAIL,8192)==1&&irq==0); // Trusted delivery may precede open.
    assert(U(mmio_read)(0)==0&&U(mmio_read)(0x18)==0x90);
    calls=transitions;assert(!U(inject)(MAIL,1)&&transitions==calls);
    configure();assert(irq==1&&U(mmio_read)(0x40)==0x10&&(U(mmio_read)(0x18)&0x40));
    write_(0x44,0x7ff);assert(irq==1&&U(mmio_read)(0x40)==0x10); // RX is level.
    for(unsigned i=0;i<4097;i++)assert(U(mmio_read)(0)==(uint8_t)(i*37));
    for(unsigned i=0;i<4097;i++)MAIL[i]=(uint8_t)(i*19+3);
    assert(U(inject)(MAIL,4097)==1&&U(mmio_read)(0x18)&0x40);
    calls=transitions;assert(!U(inject)(MAIL,1)&&transitions==calls);
    // CR and LCRH changes do not silently discard an accepted control burst.
    write_(0x30,0);assert(irq==0&&U(mmio_read)(0)==0&&U(mmio_read)(0x18)&16);
    write_(0x2c,0);write_(0x2c,0x70);write_(0x30,0x301);assert(irq==1);
    for(unsigned i=4097;i<8192;i++)assert(U(mmio_read)(0)==(uint8_t)(i*37));
    for(unsigned i=0;i<4097;i++)assert(U(mmio_read)(0)==(uint8_t)(i*19+3));
    assert(irq==0&&U(mmio_read)(0x18)==0x90);
    puts("private mailbox range, atomic full/wrapped RX, Linux startup and CR retention: PASS");

    const uint8_t binary[]={0,3,10,13,0x11,0x13,0x7f,0xff};memcpy(MAIL,binary,sizeof(binary));
    assert(U(inject)(MAIL,sizeof(binary))==1&&irq==1);
    write_(0x38,0);assert(irq==0&&U(mmio_read)(0x3c)&0x10);
    write_(0x38,0x50);assert(irq==1);
    for(unsigned i=0;i<sizeof(binary);i++)assert(U(mmio_read)(0)==binary[i]);
    assert(irq==0);
    // Below IFLS threshold: timeout latch carries a short completed burst.
    write_(0x34,4<<3);MAIL[0]=0xff;assert(U(inject)(MAIL,1)==1);
    assert(U(mmio_read)(0x40)==0x40&&irq==1);
    write_(0x44,0x40);assert(!irq&&U(mmio_read)(0x40)==0);
    assert(U(mmio_read)(0)==255);assert(U(mmio_read)(0x18)&16);
    // Continuous TX readiness is not clearable by ICR; Linux masks TXIM.
    write_(0x38,0x20);assert(irq==1&&U(mmio_read)(0x40)==0x20);
    write_(0x44,0x20);assert(irq==1);write_(0x38,0);assert(!irq);
    for(unsigned i=0;i<70000;i++)write_(0,(i*13)|0x100);
    assert(word(OUTPUT)==70000&&barriers==70001);
    for(unsigned i=70000-65536;i<70000;i++)assert(OUTPUT[8+i%65536]==(uint8_t)(i*13));
    before=hash(OUTPUT,65544);write_(0x30,0x200);write_(0,42);assert(hash(OUTPUT,65544)==before);
    write_(0x30,0x301);calls=transitions;
    assert(!U(mmio_write)(0x48,1)&&!U(mmio_write)(0x48,2)&&!U(mmio_write)(0x100,1));
    assert(before==hash(OUTPUT,65544)&&transitions==calls);
    putword(OUTPUT,UINT64_MAX);before=hash(OUTPUT,65544);
    assert(!U(mmio_write)(0,0x22)&&before==hash(OUTPUT,65544));
    unchanged_edges();assert(transitions>12000);
    assert(U(init)()==1&&!irq&&word(OUTPUT)==0&&U(mmio_read)(0x18)==0x90);
    unchanged_edges();puts("binary private TX ring, IRQ masks/levels/ICR, no DMA and output canaries: PASS");
    puts("coordinator UART production tests: PASS");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "production fixture requires Linux x86_64")
class CoordinatorUartTests(unittest.TestCase):
    def test_actual_uart_private_queues_and_interrupts(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="coordinator-native-uart-") as directory:
            out = Path(directory)
            (out / "harness.c").write_text(HARNESS)
            source = str(ROOT / "ocore/runtime/aarch64/coordinator_uart.oc")
            commands = [
                [str(compiler), source, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(out / "arm.mir")],
                [str(compiler), source, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "uart.o")],
                [clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "uart.o"), "-o", str(out / "test")],
                [str(out / "test")],
            ]
            for command in commands:
                result = subprocess.run(command, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("coordinator UART production tests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
