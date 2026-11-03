"""Run production guest virtio-net queue code with bounded host packet stubs."""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOST_STUBS = r'''
module runtime::aarch64::kernel_world_net_host;
extern "ocore" fn test_host_send(data: *const u8, length: usize) -> u64;
extern "ocore" fn test_host_receive(data: *mut u8, maximum: usize) -> usize;
pub unsafe fn send(data: *const u8, length: usize) -> u64 { return test_host_send(data, length); }
pub unsafe fn receive(data: *mut u8, maximum: usize) -> usize { return test_host_receive(data, maximum); }
'''
HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#define NET(name) _O_runtime__aarch64__kernel_world_net__##name
extern uint64_t NET(init)(uint64_t,uint64_t,uint64_t);
extern uint64_t NET(mmio_read)(uint64_t);
extern uint64_t NET(mmio_write)(uint64_t,uint64_t);
extern uint64_t NET(poll)(void);
extern uint64_t NET(healthy)(void);
extern uint64_t NET(denials)(void);
extern uint64_t NET(transmitted)(void);
extern uint64_t NET(received)(void);
static const uint64_t GPA=0x40000000ull;
static uint8_t *memory;
static uint8_t sent[1514], incoming[1514];
static size_t sent_length, incoming_length;
static unsigned send_calls, receive_calls, irq;
static int busy;

uintptr_t kw_guest_address(uint64_t gpa,uint64_t length) {
    if (!length || gpa<GPA || length>65536 || gpa-GPA>65536-length) return 0;
    return (uintptr_t)memory+(gpa-GPA);
}
void kw_memory_barrier(void) { __sync_synchronize(); }
void kw_net_irq_level(uint64_t value) { irq=(unsigned)value; }
uint64_t test_host_send(const uint8_t *data,size_t length) {
    assert((uintptr_t)data<(uintptr_t)memory || (uintptr_t)data>=(uintptr_t)memory+65536);
    assert(length>=14 && length<=1514);
    send_calls++;
    if (busy) return 0;
    memcpy(sent,data,length); sent_length=length; return 1;
}
size_t test_host_receive(uint8_t *data,size_t maximum) {
    assert((uintptr_t)data<(uintptr_t)memory || (uintptr_t)data>=(uintptr_t)memory+65536);
    assert(maximum==1514);
    receive_calls++;
    size_t length=incoming_length; incoming_length=0;
    if (length<=maximum) memcpy(data,incoming,length);
    return length;
}
static void p16(unsigned offset,uint16_t value) { memcpy(memory+offset,&value,2); }
static void p32(unsigned offset,uint32_t value) { memcpy(memory+offset,&value,4); }
static void p64(unsigned offset,uint64_t value) { memcpy(memory+offset,&value,8); }
static uint16_t r16(unsigned offset) { uint16_t value; memcpy(&value,memory+offset,2); return value; }
static uint32_t r32(unsigned offset) { uint32_t value; memcpy(&value,memory+offset,4); return value; }
static void w(uint64_t offset,uint64_t value) { assert(NET(mmio_write)(offset,value)==1); }
static unsigned desc_base(unsigned queue) { return queue ? 0x3000:0; }
static unsigned avail_base(unsigned queue) { return queue ? 0x4000:0x1000; }
static unsigned used_base(unsigned queue) { return queue ? 0x5000:0x2000; }
static void descriptor(unsigned queue,unsigned id,uint64_t address,unsigned length,unsigned flags,unsigned next) {
    unsigned offset=desc_base(queue)+id*16;
    p64(offset,address); p32(offset+8,length); p16(offset+12,flags); p16(offset+14,next);
}
static void registers(unsigned queue,unsigned descriptor_offset,unsigned available,unsigned used) {
    w(48,queue); w(56,8); w(128,GPA+descriptor_offset); w(132,0);
    w(144,GPA+available); w(148,0); w(160,GPA+used); w(164,0);
}
static void negotiate(void) {
    w(112,0); memset(memory,0,65536); sent_length=0; incoming_length=0; busy=0;
    w(112,1); w(112,3); w(36,0); w(32,32); w(36,1); w(32,1); w(112,11);
}
static void setup(void) {
    negotiate();
    registers(0,0,0x1000,0x2000); w(68,1);
    registers(1,0x3000,0x4000,0x5000); w(68,1); w(112,15);
    assert(NET(healthy)()==1);
}
static void submit(unsigned queue,unsigned ordinal,unsigned head) {
    p16(avail_base(queue)+4+(ordinal%8)*2,head);
    p16(avail_base(queue)+2,ordinal+1);
}
static void tx(unsigned length) {
    descriptor(1,0,GPA+0x8000,12,1,1);
    descriptor(1,1,GPA+0x9000,length,0,0);
    for (unsigned i=0;i<length;i++) memory[0x9000+i]=(uint8_t)(i^0x5a);
    submit(1,0,0);
}
static void rx(unsigned length) {
    descriptor(0,0,GPA+0x6000,12,3,1);
    descriptor(0,1,GPA+0x7000,length,2,0);
    memset(memory+0x6000,0xcc,12); memset(memory+0x7000,0xcc,length);
    submit(0,0,0);
    incoming_length=14;
    for (unsigned i=0;i<14;i++) incoming[i]=(uint8_t)(i^0xa5);
}
static void denied(uint64_t before,unsigned calls) {
    assert(NET(poll)()==0); assert(NET(healthy)()==0);
    assert(NET(denials)()==before+1); assert(send_calls==calls);
}
int main(void) {
    memory=mmap((void*)0x48000000ull,65536,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(memory!=MAP_FAILED);
    assert(NET(init)(GPA,65536,1)==1);
    assert(NET(mmio_read)(0)==0x74726976 && NET(mmio_read)(4)==2 && NET(mmio_read)(8)==1);
    assert(NET(mmio_read)(256)==0x12005452 && NET(mmio_read)(260)==0x5634);
    setup(); tx(14);
    assert(NET(poll)()==1 && sent_length==14 && r16(used_base(1)+2)==1);
    assert(r32(used_base(1)+8)==0 && irq==1);
    for (unsigned i=0;i<14;i++) assert(sent[i]==(uint8_t)(i^0x5a));
    w(100,1); assert(irq==0);
    rx(14); assert(NET(poll)()==1 && r16(used_base(0)+2)==1);
    assert(r32(used_base(0)+8)==26 && memory[0x6000+10]==1 && memory[0x6000+11]==0);
    for (unsigned i=0;i<10;i++) assert(memory[0x6000+i]==0);
    for (unsigned i=0;i<14;i++) assert(memory[0x7000+i]==(uint8_t)(i^0xa5));
    assert(NET(transmitted)()==1 && NET(received)()==1);

    // Linux can supply header+frame in one writable receive buffer.
    setup(); rx(14); descriptor(0,0,GPA+0x6000,1536,2,0);
    assert(NET(poll)()==1 && r32(used_base(0)+8)==26);
    for (unsigned i=0;i<14;i++) assert(memory[0x600c+i]==(uint8_t)(i^0xa5));
    // Header fields may straddle scatter/gather descriptors.
    setup(); tx(14);
    memcpy(memory+0x800c,memory+0x9000,14);
    descriptor(1,0,GPA+0x8000,5,1,1);
    descriptor(1,1,GPA+0x8005,21,0,0);
    assert(NET(poll)()==1 && sent_length==14);
    for (unsigned i=0;i<14;i++) assert(sent[i]==(uint8_t)(i^0x5a));
    // Ordinary writev-style inputs may reuse exactly the same readable page.
    setup(); tx(14);
    descriptor(1,1,GPA+0x9000,7,1,2); descriptor(1,2,GPA+0x9000,7,0,0);
    assert(NET(poll)()==1 && NET(healthy)()==1 && sent_length==14);
    assert(r32(used_base(1)+8)==0 && r16(used_base(1)+2)==1);
    for (unsigned i=0;i<14;i++) assert(sent[i]==(uint8_t)((i%7)^0x5a));
    for (unsigned i=0;i<14;i++) assert(memory[0x9000+i]==(uint8_t)(i^0x5a));
    // Partial input aliases concatenate their bytes; they are not deduplicated.
    setup(); tx(14);
    descriptor(1,1,GPA+0x9000,14,1,2); descriptor(1,2,GPA+0x9007,7,0,0);
    assert(NET(poll)()==1 && sent_length==21);
    for (unsigned i=0;i<14;i++) assert(sent[i]==(uint8_t)(i^0x5a));
    for (unsigned i=0;i<7;i++) assert(sent[14+i]==(uint8_t)((7+i)^0x5a));
    // A bad later element still prevents any send, even after valid aliases.
    setup(); tx(14);
    descriptor(1,1,GPA+0x9000,7,1,2); descriptor(1,2,GPA+0x9000,7,1,3);
    descriptor(1,3,GPA+65536,1,0,0); denied(NET(denials)(),send_calls);
    setup(); tx(14); p16(avail_base(1),1);
    assert(NET(poll)()==1 && irq==0 && r16(used_base(1)+2)==1);

    setup(); tx(14); busy=1;
    assert(NET(poll)()==0 && r16(used_base(1)+2)==0 && NET(healthy)()==1);
    busy=0; assert(NET(poll)()==1 && r16(used_base(1)+2)==1);
    setup(); tx(1514); assert(NET(poll)()==1 && sent_length==1514);

    setup(); tx(14); memory[0x8000]=1;
    denied(NET(denials)(),send_calls); // Unnegotiated checksum offload.
    setup(); tx(14); memory[0x8001]=1;
    denied(NET(denials)(),send_calls); // Unnegotiated GSO.
    // VERSION_1 uses a 12-byte header, but Linux 6.12 only initializes its
    // unused TX num_buffers bytes when mergeable RX buffers are negotiated.
    setup(); tx(14); memory[0x800a]=0xa5; memory[0x800b]=0x5a;
    assert(NET(poll)()==1 && NET(healthy)()==1 && sent_length==14);
    for (unsigned i=0;i<14;i++) assert(sent[i]==(uint8_t)(i^0x5a));
    setup(); tx(14); descriptor(1,1,GPA+0x9000,14,1,0);
    denied(NET(denials)(),send_calls); // Cycle.
    setup(); tx(14); descriptor(1,1,GPA+65536,14,0,0);
    denied(NET(denials)(),send_calls); // Outside guest ownership.
    setup(); tx(14); descriptor(1,1,GPA,14,0,0);
    denied(NET(denials)(),send_calls); // Other queue's metadata.
    setup(); tx(14); descriptor(1,1,GPA+0x9000,14,2,0);
    denied(NET(denials)(),send_calls); // Wrong direction.
    setup(); tx(14); descriptor(1,1,GPA+0x9000,14,4,0);
    denied(NET(denials)(),send_calls); // Unnegotiated indirect descriptors.
    setup(); tx(1515); denied(NET(denials)(),send_calls);
    setup(); submit(1,0,32); denied(NET(denials)(),send_calls);
    setup(); p16(avail_base(1)+2,9); denied(NET(denials)(),send_calls);

    setup(); rx(14); descriptor(0,1,GPA+65536,14,2,0);
    denied(NET(denials)(),send_calls);
    for (unsigned i=0;i<12;i++) assert(memory[0x6000+i]==0xcc); // No partial header write.
    setup(); rx(14); descriptor(0,1,GPA+0x6000,14,2,0);
    denied(NET(denials)(),send_calls); // Writable RX aliases remain forbidden.
    for (unsigned i=0;i<12;i++) assert(memory[0x6000+i]==0xcc);
    assert(r16(used_base(0)+2)==0);
    setup(); rx(13); denied(NET(denials)(),send_calls);
    setup(); rx(14); incoming_length=1515; denied(NET(denials)(),send_calls);
    setup(); incoming_length=14; unsigned before=receive_calls;
    assert(NET(poll)()==0 && receive_calls==before); // No receive buffer -> retain outer packet.

    negotiate(); registers(0,0,0x1000,0x2000); w(68,1);
    registers(1,0,0x4000,0x5000); assert(NET(mmio_write)(68,1)==0 && NET(healthy)()==0);
    puts("modern virtio-net mediated frame/queue/negative production tests: PASS");
    return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "host queue execution fixture requires Linux x86_64")
class KernelWorldNetTests(unittest.TestCase):
    def test_real_frontend_queue_and_frame_validation(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-net-frontend-") as directory:
            output = Path(directory)
            (output / "host-stubs.oc").write_text(HOST_STUBS)
            (output / "harness.c").write_text(HARNESS)
            inputs = [str(output / "host-stubs.oc"), str(ROOT / "ocore/runtime/aarch64/kernel_world_net.oc")]
            commands = [
                [str(compiler), *inputs, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), *inputs, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "net.o")],
                [clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "net.o"), "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("negative production tests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
