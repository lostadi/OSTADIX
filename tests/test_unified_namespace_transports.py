"""Native O-core shared backend: live sessions, serialized dispatch, reset isolation.

This does not boot guests or qualify a merged OS. C supplies guest memory,
wire requests and IRQ hooks; all 9P/device/object behavior is production O-core.
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#define N(name) _O_runtime__aarch64__kernel_world_9p__##name
#define S(name) _O_runtime__common__namespace_store__##name
extern uint64_t N(init)(uint64_t,uint64_t,uint64_t);
extern uint64_t N(mmio_write)(uint64_t,uint64_t);
extern uint64_t N(poll)(void);
extern uint64_t N(healthy)(void);
extern uint64_t N(diagnostic)(void);
extern uint64_t S(init)(uintptr_t,uintptr_t,uint64_t);
extern uint64_t S(session_init)(uint64_t,uint64_t);
extern uint64_t S(revoke)(uint64_t);
extern uintptr_t S(handle)(uint64_t,const uint8_t*,uintptr_t,uint8_t*,uintptr_t);
static uint8_t *memory,*volume;
static const uint64_t GPA=0x40000000ull;
static uint8_t request[8192],native_reply[8192];
static unsigned position,ordinal,tag,input_alias;
uintptr_t kw_guest_address(uint64_t gpa,uint64_t length) {
    if (!length || gpa<GPA || length>65536 || gpa-GPA>65536-length) return 0;
    return (uintptr_t)memory+gpa-GPA;
}
void kw_memory_barrier(void) { __sync_synchronize(); }
void kw_9p_irq_level(uint64_t asserted) { (void)asserted; }
static void put(uint8_t *p,uint64_t value,unsigned bytes) {
    for (unsigned i=0;i<bytes;i++) p[i]=(uint8_t)(value>>(8*i));
}
static uint32_t get32(const uint8_t *p) { return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static void b(unsigned bytes,uint64_t value) { put(request+position,value,bytes); position+=bytes; }
static void data(const void *p,unsigned length) { memcpy(request+position,p,length); position+=length; }
static void string(const char *value) { unsigned n=strlen(value); b(2,n); data(value,n); }
static void begin(unsigned type) {
    memset(request,0,sizeof(request)); position=7; request[4]=type;
    tag=(tag+1)&0xffff; if (type==100) tag=0xffff; put(request+5,tag,2);
}
static void w(uint64_t offset,uint64_t value) { assert(N(mmio_write)(offset,value)==1); }
static void setup(void) {
    w(112,0); memset(memory,0,65536); ordinal=0;
    w(112,1); w(112,3); w(36,0); w(32,1); w(36,1); w(32,1); w(112,11);
    w(48,0); w(56,8); w(128,GPA); w(132,0); w(144,GPA+0x1000); w(148,0);
    w(160,GPA+0x2000); w(164,0); w(68,1); w(112,15);
}
static uint8_t *exchange(unsigned expected,unsigned capacity) {
    put(request,position,4); memcpy(memory+0x3000,request,position);
    memset(memory+0x6000,0xcc,capacity);
    put(memory,GPA+0x3000,8); put(memory+8,position,4); put(memory+12,1,2); put(memory+14,1,2);
    put(memory+16,GPA+0x6000,8); put(memory+24,capacity,4); put(memory+28,2,2); put(memory+30,0,2);
    if (input_alias) {
        // A real Twrite header and data SGs with either an identical readable
        // range or partial overlap. The server receives a private concatenation.
        assert(request[4]==118);
        unsigned first=input_alias==1 ? 2:4, second=input_alias==1 ? 2:3;
        unsigned overlap=input_alias==1 ? 0:1;
        assert(position==23+first+second);
        put(memory+8,23,4);
        put(memory+16,GPA+0x3017,8); put(memory+24,first,4); put(memory+28,1,2); put(memory+30,2,2);
        put(memory+32,GPA+0x3017+overlap,8); put(memory+40,second,4); put(memory+44,1,2); put(memory+46,3,2);
        put(memory+48,GPA+0x6000,8); put(memory+56,capacity,4); put(memory+60,2,2); put(memory+62,0,2);
    }
    put(memory+0x1004+(ordinal%8)*2,0,2); put(memory+0x1002,ordinal+1,2);
    uint64_t count=N(poll)();
    if (count!=1 || N(healthy)()!=1) fprintf(stderr,"transport count=%llu reason=%llu request=%u cap=%u\n",
        (unsigned long long)count,(unsigned long long)N(diagnostic)(),request[4],capacity);
    assert(count==1 && N(healthy)()==1);
    uint8_t *response=memory+0x6000;
    if (response[4]!=expected) fprintf(stderr,"9p expected=%u got=%u error=%.*s\n",expected,response[4],
        response[4]==107 ? response[7]|response[8]<<8:0,response+9);
    assert(response[4]==expected && response[5]==request[5] && response[6]==request[6]);
    assert(get32(memory+0x2008+(ordinal%8)*8)==get32(response));
    ordinal++; input_alias=0; w(100,1); return response;
}
static uint8_t *direct(uint64_t session,unsigned expected) {
    put(request,position,4);
    size_t length=S(handle)(session,request,position,native_reply,sizeof(native_reply));
    if (length<7 || native_reply[4]!=expected) fprintf(stderr,"native expected=%u got=%u length=%zu\n",expected,native_reply[4],length);
    assert(length>=7 && native_reply[4]==expected); return native_reply;
}
static void version(void) { begin(100); b(4,8192); string("9P2000"); }
static void attach(unsigned fid) { begin(104); b(4,fid); b(4,0xffffffffu); string("root"); string(""); }
static void walk(unsigned old,unsigned fresh,const char *first,const char *second) {
    begin(110); b(4,old); b(4,fresh); b(2,second?2:1); string(first); if (second) string(second);
}
static void open_(unsigned fid,unsigned mode) { begin(112); b(4,fid); b(1,mode); }
static void create(unsigned fid,const char *name,unsigned mode) { begin(114); b(4,fid); string(name); b(4,0644); b(1,mode); }
static void write_(unsigned fid,const char *text) { begin(118); b(4,fid); b(8,0); b(4,strlen(text)); data(text,strlen(text)); }
static void read_(unsigned fid,unsigned count) { begin(116); b(4,fid); b(8,0); b(4,count); }
static void clunk(unsigned fid) { begin(120); b(4,fid); }
#define U(name) _O_runtime__aarch64__plan9_namespace_uart__##name
extern uint64_t U(init)(uint64_t);
extern uint64_t U(mmio_read)(uint64_t);
extern uint64_t U(mmio_write)(uint64_t,uint64_t);
extern uint64_t U(healthy)(void);
extern uint64_t U(revoke)(void);
static uint8_t uart_reply[8192];
static unsigned uart_irq;
void p9_namespace_irq_level(uint64_t asserted) { assert(asserted<=1); uart_irq=(unsigned)asserted; }
static void uw(unsigned offset,uint64_t value) { assert(U(mmio_write)(offset,value)==1); }
static void usend(unsigned count) { for(unsigned i=0;i<count;i++)uw(0,request[i]); }
static unsigned ureceive(void) {
    for(unsigned i=0;i<4;i++){assert(!(U(mmio_read)(0x18)&0x10));uart_reply[i]=(uint8_t)U(mmio_read)(0);}
    unsigned length=get32(uart_reply);assert(length>=7 && length<=sizeof(uart_reply));
    for(unsigned i=4;i<length;i++){assert(!(U(mmio_read)(0x18)&0x10));uart_reply[i]=(uint8_t)U(mmio_read)(0);}
    return length;
}
static uint8_t *uexchange(unsigned expected) {
    put(request,position,4);usend(position);assert(U(healthy)()==1);unsigned length=ureceive();
    if(uart_reply[4]!=expected)fprintf(stderr,"UART expected=%u got=%u length=%u\n",expected,uart_reply[4],length);
    assert(uart_reply[4]==expected && uart_reply[5]==request[5] && uart_reply[6]==request[6]);
    return uart_reply;
}
static void ureset(void) {
    uw(0x38,0);uw(0x44,0x7ff);uw(0x30,0);uw(0x2c,0x70);uw(0x30,0x301);uw(0x38,0x50);
}
static void write_bytes(unsigned fid,const uint8_t *bytes,unsigned length) {
    begin(118);b(4,fid);b(8,0);b(4,length);data(bytes,length);
}
static void check_bytes(const uint8_t *reply,const uint8_t *bytes,unsigned length) {
    assert(reply[4]==117 && get32(reply+7)==length && !memcmp(reply+11,bytes,length));
}
static void rename_(unsigned fid,const char *name) {
    begin(126);b(4,fid);unsigned packed=position;b(2,0);unsigned inner=position;b(2,0);
    b(2,UINT16_MAX);b(4,UINT32_MAX);b(1,255);b(4,UINT32_MAX);b(8,UINT64_MAX);
    b(4,UINT32_MAX);b(4,UINT32_MAX);b(4,UINT32_MAX);b(8,UINT64_MAX);
    string(name);string("");string("");string("root");
    put(request+inner,position-inner-2,2);put(request+packed,position-inner,2);
}
int main(void) {
    memory=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    volume=mmap(NULL,0x1000000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(memory!=MAP_FAILED && volume!=MAP_FAILED && S(init)((uintptr_t)volume,0x1000000,7)==1);
    assert(S(session_init)(0,1)==0 && S(session_init)(5,1)==0 && S(session_init)(UINT64_MAX,1)==0);
    assert(S(revoke)(0)==0 && S(revoke)(5)==0 && S(revoke)(UINT64_MAX)==0);
    assert(N(init)(GPA,65536,1)==1);setup();
    version();exchange(101,8192);attach(10);exchange(105,8192);
    walk(10,11,"work",NULL);exchange(111,8192);create(11,"shared",2);exchange(115,8192);
    uint8_t bytes[256];for(unsigned i=0;i<sizeof(bytes);i++)bytes[i]=(uint8_t)i;
    write_bytes(11,bytes,sizeof(bytes));exchange(119,8192);

    // Both live clients deliberately use identical numeric fid values. A new
    // Plan9 transport must not clear Linux's existing fids or authority.
    assert(U(init)(100)==1);ureset();version();uexchange(101);attach(10);uexchange(105);
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    walk(10,11,"work","shared");uexchange(111);open_(11,2);uexchange(113);
    read_(11,sizeof(bytes));check_bytes(uexchange(117),bytes,sizeof(bytes));
    for(unsigned round=0;round<32;round++) {
        bytes[0]=(uint8_t)round;bytes[255]=(uint8_t)(255-round);
        write_bytes(11,bytes,sizeof(bytes));exchange(119,8192);
        read_(11,sizeof(bytes));check_bytes(uexchange(117),bytes,sizeof(bytes));
        bytes[1]=(uint8_t)(round^0xa5);
        write_bytes(11,bytes,sizeof(bytes));uexchange(119);
        read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    }
    puts("native shared backend: interleaved Linux virtio and Plan9 UART sessions PASS");

    // Serializing complete requests is the store contract. An incomplete
    // UART write must not mutate data observed through the live virtqueue.
    uint8_t next[256];memcpy(next,bytes,sizeof(next));next[17]^=0xff;
    write_bytes(11,next,sizeof(next));put(request,position,4);unsigned last=request[position-1];usend(position-1);
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    uw(0,last);assert(ureceive()==11 && uart_reply[4]==119);memcpy(bytes,next,sizeof(bytes));
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    rename_(11,"renamed");uexchange(127);
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes)); // Existing Linux fid follows object.
    walk(10,12,"work","shared");exchange(111,8192); // Partial walk: work exists but shared no longer does.
    assert((memory[0x6007]|memory[0x6008]<<8)==1);clunk(12);exchange(107,8192);
    walk(10,12,"work","renamed");exchange(111,8192);open_(12,0);exchange(113,8192);
    read_(12,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));

    // Plan9 retains its previous full-root RW authority under its distinct
    // trusted role; restricted peer/read-only grant behavior remains unchanged.
    walk(10,20,"pkg",NULL);uexchange(111);create(20,"plan9-created",2);uexchange(115);
    write_bytes(20,bytes,sizeof(bytes));uexchange(119);
    walk(10,20,"pkg","plan9-created");exchange(111,8192);open_(20,0);exchange(113,8192);
    read_(20,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    uint64_t peer=S(session_init)(2,500),readonly=S(session_init)(3,600);assert(peer && readonly);
    version();direct(peer,101);attach(1);direct(peer,105);walk(1,2,"pkg",NULL);direct(peer,107);
    walk(1,2,"renamed",NULL);direct(peer,111);open_(2,0);direct(peer,113);
    version();direct(readonly,101);attach(1);direct(readonly,105);
    walk(1,2,"renamed",NULL);direct(readonly,111);open_(2,1);direct(readonly,107);
    create(1,"forbidden",2);direct(readonly,107);
    puts("native shared backend: common mutations and preserved grant authority PASS");

    // Linux driver reset invalidates only Linux fids, never Plan9's live fids.
    setup();version();exchange(101,8192);read_(11,1);exchange(107,8192);
    read_(11,sizeof(bytes));check_bytes(uexchange(117),bytes,sizeof(bytes));
    attach(10);exchange(105,8192);walk(10,11,"work","renamed");exchange(111,8192);open_(11,2);exchange(113,8192);
    // Plan9 reset invalidates only Plan9 fids, including partial queued input.
    write_bytes(11,next,sizeof(next));put(request,position,4);usend(10);ureset();
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    version();uexchange(101);read_(11,1);uexchange(107);attach(10);uexchange(105);
    walk(10,11,"work","renamed");uexchange(111);open_(11,2);uexchange(113);
    read_(2,sizeof(bytes));check_bytes(direct(peer,117),bytes,sizeof(bytes));
    // Store-level Linux session invalidation is deliberately not claimed as
    // durable device revocation: a later virtio reset can provision it again.
    assert(S(revoke)(1)==1);read_(11,1);exchange(107,8192);
    read_(11,sizeof(bytes));check_bytes(uexchange(117),bytes,sizeof(bytes));
    setup();version();exchange(101,8192);attach(10);exchange(105,8192);
    walk(10,11,"work","renamed");exchange(111,8192);open_(11,2);exchange(113,8192);
    puts("native shared backend: bidirectional reset and Linux session invalidation isolation PASS");

    write_bytes(11,next,sizeof(next));put(request,position,4);usend(10);
    assert(U(revoke)()==1 && U(healthy)()==0 && uart_irq==0);
    assert(U(mmio_write)(0x30,0)==0 && U(mmio_write)(0x30,0x301)==0);
    version();put(request,position,4);for(unsigned i=0;i<position;i++)assert(U(mmio_write)(0,request[i])==0);
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    bytes[18]^=0x7f;write_bytes(11,bytes,sizeof(bytes));exchange(119,8192);
    assert(U(init)(100)==1);ureset();version();uexchange(101);read_(11,1);uexchange(107);
    attach(10);uexchange(105);walk(10,11,"work","renamed");uexchange(111);open_(11,2);uexchange(113);
    read_(11,sizeof(bytes));check_bytes(uexchange(117),bytes,sizeof(bytes));
    read_(2,sizeof(bytes));check_bytes(direct(peer,117),bytes,sizeof(bytes));
    puts("native shared backend: trusted Plan9 withdrawal and rearm preserve Linux and peer PASS");

    // Reopening unchanged stored bytes invalidates ephemeral sessions while
    // preserving exact cross-client objects. No simultaneous volume owners.
    assert(S(init)((uintptr_t)volume,0x1000000,8)==1);
    read_(2,1);direct(peer,107);read_(2,1);direct(readonly,107);
    setup();version();exchange(101,8192);attach(10);exchange(105,8192);
    walk(10,11,"work","renamed");exchange(111,8192);open_(11,2);exchange(113,8192);
    assert(U(init)(1000)==1);ureset();version();uexchange(101);attach(10);uexchange(105);
    walk(10,11,"work","renamed");uexchange(111);open_(11,2);uexchange(113);
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    read_(11,sizeof(bytes));check_bytes(uexchange(117),bytes,sizeof(bytes));
    bytes[19]^=0x55;write_bytes(11,bytes,sizeof(bytes));uexchange(119);
    read_(11,sizeof(bytes));check_bytes(exchange(117,8192),bytes,sizeof(bytes));
    puts("native shared backend: persisted volume reopen with fresh transport sessions PASS");
    puts("native production transports and common store isolation: PASS");
    return 0;
}
'''

@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native production fixture requires Linux x86_64")
class UnifiedNamespaceTransportsTests(unittest.TestCase):
    def test_native_transports_share_objects_without_sharing_session_lifecycle(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-shared-transports-") as directory:
            out = Path(directory)
            (out / "harness.c").write_text(HARNESS)
            sources = [str(ROOT / name) for name in (
                "ocore/runtime/common/namespace_store.oc",
                "ocore/runtime/aarch64/kernel_world_9p.oc",
                "ocore/runtime/aarch64/plan9_namespace_uart.oc")]
            commands = [
                [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(out / "arm.mir")],
                [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "production.o")],
                [clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "production.o"), "-o", str(out / "native-test")],
                [str(out / "native-test")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("native production transports and common store isolation: PASS", result.stdout)

if __name__ == "__main__":
    unittest.main()
