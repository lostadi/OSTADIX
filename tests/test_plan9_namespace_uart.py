"""Actual production UART framing plus the unchanged native namespace service."""
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
#define U(n) _O_runtime__aarch64__plan9_namespace_uart__##n
#define S(n) _O_runtime__common__namespace_store__##n
extern uint64_t U(init)(uint64_t);
extern uint64_t U(mmio_read)(uint64_t);
extern uint64_t U(mmio_write)(uint64_t,uint64_t);
extern uint64_t U(healthy)(void);
extern uint64_t U(diagnostic)(void);
extern uint64_t U(revoke)(void);
extern uint64_t U(request_count)(void);
extern uint64_t U(request_byte_count)(void);
extern uint64_t U(reply_byte_count)(void);
extern uint64_t S(init)(uintptr_t,uintptr_t,uint64_t);
extern uint64_t S(session_init)(uint64_t,uint64_t);
extern uint64_t S(session_handle)(uint64_t);
extern uintptr_t S(handle)(uint64_t,const uint8_t*,uintptr_t,uint8_t*,uintptr_t);
static uint8_t request[8192],response[65536],peer_response[8192],pattern[8181];
static unsigned position,tag,irq,transitions;
static uint64_t peer;
void p9_namespace_irq_level(uint64_t value) { assert(value<=1); irq=(unsigned)value; transitions++; }
static void put(uint8_t *p,uint64_t value,unsigned count) {
    for(unsigned i=0;i<count;i++) p[i]=(uint8_t)(value>>(8*i));
}
static uint64_t get(const uint8_t *p,unsigned count) {
    uint64_t value=0;for(unsigned i=0;i<count;i++)value|=(uint64_t)p[i]<<(8*i);return value;
}
static void b(unsigned count,uint64_t value) { put(request+position,value,count);position+=count; }
static void string(const char *text) { size_t n=strlen(text);b(2,n);memcpy(request+position,text,n);position+=n; }
static void begin(unsigned kind) {
    memset(request,0,sizeof(request));position=7;request[4]=kind;tag=(tag+1)&65535;
    if(kind==100)tag=65535;put(request+5,tag,2);
}
static void finish(void) { put(request,position,4); }
static void w(unsigned offset,uint64_t value) { assert(U(mmio_write)(offset,value)==1); }
static void transmit(unsigned count) { for(unsigned i=0;i<count;i++)w(0,request[i]); }
static unsigned receive(void) {
    for(unsigned i=0;i<4;i++){assert(!(U(mmio_read)(0x18)&0x10));response[i]=(uint8_t)U(mmio_read)(0);}
    unsigned size=(unsigned)get(response,4);assert(size>=7 && size<=8192);
    for(unsigned i=4;i<size;i++){assert(!(U(mmio_read)(0x18)&0x10));response[i]=(uint8_t)U(mmio_read)(0);}
    return size;
}
static unsigned exchange(unsigned expected) {
    finish();transmit(position);assert(U(healthy)()==1);
    unsigned count=receive();assert(response[4]==expected && get(response+5,2)==tag);return count;
}
static unsigned direct(unsigned expected) {
    finish();unsigned n=(unsigned)S(handle)(peer,request,position,peer_response,sizeof(peer_response));
    assert(n>=7 && peer_response[4]==expected);return n;
}
static void version(void) { begin(100);b(4,8192);string("9P2000"); }
static void attach(unsigned fid) { begin(104);b(4,fid);b(4,0xffffffff);string("root");string(""); }
static void walk(unsigned old,unsigned fresh,const char *first,const char *second) {
    begin(110);b(4,old);b(4,fresh);b(2,second?2:1);string(first);if(second)string(second);
}
static void create(unsigned fid,const char *name) { begin(114);b(4,fid);string(name);b(4,0644);b(1,2); }
static void open_(unsigned fid) { begin(112);b(4,fid);b(1,0); }
static void write_(unsigned fid,unsigned offset,const void *data,unsigned size) {
    begin(118);b(4,fid);b(8,offset);b(4,size);memcpy(request+position,data,size);position+=size;
}
static void read_(unsigned fid,unsigned offset,unsigned count) { begin(116);b(4,fid);b(8,offset);b(4,count); }
static void reset_like_original_driver(void) {
    w(0x38,0);w(0x44,0x7e0);assert(!(U(mmio_read)(0x18)&8));w(0x30,0);
    w(0x2c,U(mmio_read)(0x2c)&~16ull);w(0x38,0x30);w(0x2c,U(mmio_read)(0x2c)|16);w(0x30,0x301);
}
int main(void) {
    assert(U(request_count)()==0 && U(request_byte_count)()==0 && U(reply_byte_count)()==0);
    void *volume=mmap(NULL,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(volume!=MAP_FAILED && S(init)((uintptr_t)volume,16777216,7)==1);
    assert(U(init)(0)==0 && U(healthy)()==0 && U(mmio_write)(0x30,0)==0);
    assert(U(init)(100)==1 && U(healthy)()==1 && U(mmio_read)(0x18)==0x90);
    uint64_t uart_token=S(session_handle)(4);
    assert(uart_token && !(uart_token&1) && uart_token!=100); // trusted init returns an opaque token
    assert(U(mmio_read)(0xfe0)==0x11 && U(mmio_read)(0xffc)==0xb1);
    assert(U(mmio_write)(0x48,1)==0); // No DMA or guest-address mechanism.
    reset_like_original_driver();assert(irq==1 && (U(mmio_read)(0x3c)&0x20));
    w(0x44,0x20);assert(irq==0);
    w(0x38,0x10);version();finish();
    transmit(position-1);assert(U(mmio_read)(0x18)&0x10);assert(irq==0);
    assert(U(request_count)()==0 && U(request_byte_count)()==0 && U(reply_byte_count)()==0);
    w(0,request[position-1]);assert(irq==1 && (U(mmio_read)(0x3c)&0x50)==0x50);
    assert(U(request_count)()==1 && U(request_byte_count)()==position && U(reply_byte_count)()==19);
    w(0x44,0x7ff);assert(irq==1 && U(mmio_read)(0x40)==0x10); // RX stays level asserted.
    assert(receive()==19 && response[4]==101 && irq==0);
    w(0x38,0x40);attach(1);finish();transmit(position);assert(irq==1);
    w(0x44,0x40);assert(irq==0 && (U(mmio_read)(0x3c)&0x10));assert(receive()==20);
    w(0x38,0);walk(1,2,"work",NULL);exchange(111);create(2,"binary");exchange(115);
    uint8_t binary[]={0,0x11,0x13,0xff,10,13,0x80,0};
    write_(2,0,binary,sizeof(binary));exchange(119);
    read_(2,0,sizeof(binary));assert(exchange(117)==19 && !memcmp(response+11,binary,sizeof(binary)));

    peer=S(session_init)(2,500);assert(peer);version();direct(101);attach(50);direct(105);
    walk(50,51,"binary",NULL);direct(111);open_(51);direct(113);
    // A partial UART frame cannot mutate native objects before its final byte.
    uint8_t changed=0x5a;write_(2,1,&changed,1);finish();
    uint8_t saved[8192];unsigned pending=position;memcpy(saved,request,position);
    transmit(position-1);assert(U(mmio_read)(0x18)&0x10);
    read_(51,0,8);direct(117);assert(!memcmp(peer_response+11,binary,8));
    w(0,saved[pending-1]);assert(receive()==11 && response[4]==119);
    read_(51,0,8);direct(117);assert(peer_response[12]==0x5a);

    // Full-size replies fill the64KiB output FIFO. Reserve8192 bytes before
    // accepting another request, so backpressure cannot partially commit a write.
    for(unsigned i=0;i<sizeof(pattern);i++)pattern[i]=(uint8_t)(i^0x11);
    write_(2,0,pattern,4096);exchange(119);write_(2,4096,pattern+4096,4085);exchange(119);
    unsigned tags[8];
    for(unsigned i=0;i<8;i++){read_(2,0,8181);finish();tags[i]=tag;transmit(position);}
    assert((U(mmio_read)(0x18)&0x60)==0x60 && !(U(mmio_read)(0x18)&0x80));
    write_(2,0,&changed,1);finish();unsigned write_tag=tag;memcpy(saved,request,position);pending=position;
    assert(U(mmio_write)(0,request[0])==0 && U(healthy)()==1);
    read_(51,0,1);direct(117);assert(peer_response[11]==pattern[0]);
    w(0x38,0x20);w(0x44,0x20);assert(irq==0);
    assert(receive()==8192 && get(response+5,2)==tags[0] && !memcmp(response+11,pattern,8181));
    assert(!(U(mmio_read)(0x18)&0x20) && irq==1); // Freed credit kicks a blocked transmitter.
    memcpy(request,saved,pending);transmit(pending);
    for(unsigned i=1;i<8;i++){assert(receive()==8192 && get(response+5,2)==tags[i]);assert(!memcmp(response+11,pattern,8181));}
    assert(receive()==11 && response[4]==119 && get(response+5,2)==write_tag);
    assert(U(mmio_read)(0x18)&0x10);read_(51,0,1);direct(117);assert(peer_response[11]==changed);

    // Disable flushes partial I/O and invalidates only this transport's fids.
    read_(2,0,1);finish();transmit(position);assert(!(U(mmio_read)(0x18)&0x10));
    write_(2,0,binary,8);finish();transmit(10);reset_like_original_driver();
    assert(U(mmio_read)(0x18)&0x10);version();exchange(101);read_(2,0,1);exchange(107);
    read_(51,0,1);direct(117);assert(peer_response[11]==changed); // Independent native peer remains valid.
    attach(1);exchange(105);walk(1,3,"work","binary");exchange(111);open_(3);exchange(113);
    read_(3,0,1);exchange(117);assert(response[11]==changed);
    // Trusted withdrawal drops staged I/O, revokes root fids and cannot be
    // undone by guest register resets, protocol versions or attach/create.
    read_(3,0,1);finish();transmit(position);assert(!(U(mmio_read)(0x18)&0x10));
    write_(3,0,binary,8);finish();transmit(10);
    uint64_t requests_before=U(request_count)(), bytes_before=U(request_byte_count)(), replies_before=U(reply_byte_count)();
    assert(U(revoke)()==1 && U(healthy)()==0 && U(diagnostic)()==2 && irq==0);
    assert(U(request_count)()==requests_before && U(request_byte_count)()==bytes_before && U(reply_byte_count)()==replies_before);
    uint8_t *snapshot=malloc(16777216);assert(snapshot);memcpy(snapshot,volume,16777216);
    assert(U(mmio_read)(0x18)==0x90 && U(mmio_read)(0)==0 && U(mmio_read)(0x3c)==0);
    assert(U(mmio_write)(0x30,0)==0 && U(mmio_write)(0x30,0x301)==0 && U(mmio_write)(0x38,0x7ff)==0);
    version();finish();for(unsigned i=0;i<position;i++)assert(U(mmio_write)(0,request[i])==0);
    attach(123);finish();for(unsigned i=0;i<position;i++)assert(U(mmio_write)(0,request[i])==0);
    create(123,"must-not-exist");finish();for(unsigned i=0;i<position;i++)assert(U(mmio_write)(0,request[i])==0);
    assert(!memcmp(snapshot,volume,16777216));free(snapshot);
    read_(51,0,1);direct(117);assert(peer_response[11]==changed); // Peer grant2 was not withdrawn.
    // Only trusted reinitialization can provision the same bounded role again.
    assert(U(init)(100)==1);reset_like_original_driver();
    assert(U(request_count)()==requests_before && U(request_byte_count)()==bytes_before && U(reply_byte_count)()==replies_before);
    version();exchange(101);assert(U(request_count)()==requests_before+1);
    read_(3,0,1);exchange(107);attach(1);exchange(105);walk(1,4,"work",NULL);exchange(111);
    create(4,"trusted-rearmed");exchange(115);write_(4,0,binary,8);exchange(119);
    read_(4,0,8);exchange(117);assert(!memcmp(response+11,binary,8));
    // Component-only reset recovery: the optional production monitor instead
    // fail-stops malformed framing before the guest can execute a reset.
    put(request,8193,4);assert(U(mmio_write)(0,request[0])==1);assert(U(mmio_write)(0,request[1])==1);
    assert(U(mmio_write)(0,request[2])==1 && U(mmio_write)(0,request[3])==0);
    assert(U(healthy)()==0 && U(diagnostic)()==21);reset_like_original_driver();assert(U(healthy)()==1);
    read_(51,0,1);direct(117);assert(peer_response[11]==changed);
    assert(U(init)(UINT64_MAX)==1 && U(mmio_write)(0x30,0)==0 && U(diagnostic)()==10);
    assert(transitions>50);
    puts("native Plan9 UART9P binary/framing/credit/IRQ/revoke production tests: PASS");
    return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "host production fixture requires Linux x86_64")
class Plan9NamespaceUartTests(unittest.TestCase):
    def test_actual_uart_transport_and_native_store(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="plan9-native-uart-") as directory:
            out = Path(directory)
            (out / "harness.c").write_text(HARNESS)
            sources = [str(ROOT / name) for name in ("ocore/runtime/common/namespace_store.oc", "ocore/runtime/aarch64/plan9_namespace_uart.oc")]
            commands = [
                [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(out / "arm.mir")],
                [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "uart.o")],
                [clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "uart.o"), "-o", str(out / "test")],
                [str(out / "test")],
            ]
            for command in commands:
                result = subprocess.run(command, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("production tests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
