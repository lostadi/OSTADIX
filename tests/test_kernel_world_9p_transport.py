"""Compile and execute the production virtio-9P transport with bounded RPC stubs."""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STUBS = r'''
module runtime::common::namespace_store;
extern "ocore" fn test_session_init(grant: u64, generation: u64) -> u64;
extern "ocore" fn test_session_handle(grant: u64) -> u64;
extern "ocore" fn test_revoke_if_current(grant: u64, expected: u64) -> u64;
pub unsafe fn session_handle(grant: u64) -> u64 { return test_session_handle(grant); }
pub unsafe fn revoke_if_current(grant: u64, expected: u64) -> u64 { return test_revoke_if_current(grant, expected); }
extern "ocore" fn test_handle(session: u64, request: *const u8, length: usize,
    response: *mut u8, maximum: usize) -> usize;
pub unsafe fn session_init(grant: u64, generation: u64) -> u64 {
    return test_session_init(grant, generation);
}
pub unsafe fn handle(session: u64, request: *const u8, length: usize,
    response: *mut u8, maximum: usize) -> usize {
    return test_handle(session, request, length, response, maximum);
}
'''
HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#define N(name) _O_runtime__aarch64__kernel_world_9p__##name
extern uint64_t N(init)(uint64_t,uint64_t,uint64_t);
extern uint64_t N(mmio_read)(uint64_t);
extern uint64_t N(mmio_write)(uint64_t,uint64_t);
extern uint64_t N(poll)(void);
extern uint64_t N(healthy)(void);
extern uint64_t N(diagnostic)(void);
static uint8_t *memory;
static const uint64_t GPA=0x40000000ull;
static unsigned irq,calls,mode;
static uint64_t last_epoch,session;
static size_t last_capacity;
static uint8_t expected_payload[2];
uintptr_t kw_guest_address(uint64_t gpa,uint64_t length) {
    if (!length || gpa<GPA || length>65536 || gpa-GPA>65536-length) return 0;
    return (uintptr_t)memory+gpa-GPA;
}
void kw_memory_barrier(void) { __sync_synchronize(); }
void kw_9p_irq_level(uint64_t asserted) { irq=(unsigned)asserted; }
uint64_t test_session_init(uint64_t grant,uint64_t epoch) {
    assert(grant==1 && epoch>last_epoch); last_epoch=epoch;
    session=0xa0000000ull+epoch; return session;
}
uint64_t test_session_handle(uint64_t grant){assert(grant==1);return session;}
uint64_t test_revoke_if_current(uint64_t grant,uint64_t expected){
 assert(grant==1);if(!expected||session!=expected)return 0;session=0;return 1;
}
static void set32(uint8_t *p,uint32_t value) { memcpy(p,&value,4); }
size_t test_handle(uint64_t handle,const uint8_t *request,size_t length,uint8_t *response,size_t maximum) {
    assert(handle==session);
    assert((uintptr_t)request<(uintptr_t)memory || (uintptr_t)request>=(uintptr_t)memory+65536);
    assert((uintptr_t)response<(uintptr_t)memory || (uintptr_t)response>=(uintptr_t)memory+65536);
    assert(length==9 && request[4]==108 && request[5]==0x34 && request[6]==0x12);
    assert(request[7]==expected_payload[0] && request[8]==expected_payload[1]);
    assert(maximum>=7 && maximum<=8192);
    for (unsigned i=0;i<maximum;i++) assert(response[i]==0);
    calls++; last_capacity=maximum;
    if (mode==4) return 0;
    set32(response,7); response[4]=109; response[5]=0x34; response[6]=0x12;
    if (mode==1) response[5]=0;
    if (mode==2) response[4]=111;
    if (mode==3) response[0]=8;
    return 7;
}
static void p16(unsigned offset,uint16_t value) { memcpy(memory+offset,&value,2); }
static void p32(unsigned offset,uint32_t value) { memcpy(memory+offset,&value,4); }
static void p64(unsigned offset,uint64_t value) { memcpy(memory+offset,&value,8); }
static uint16_t r16(unsigned offset) { uint16_t value; memcpy(&value,memory+offset,2); return value; }
static uint32_t r32(unsigned offset) { uint32_t value; memcpy(&value,memory+offset,4); return value; }
static void w(uint64_t offset,uint64_t value) { assert(N(mmio_write)(offset,value)==1); }
static void descriptor(unsigned id,uint64_t address,unsigned length,unsigned flags,unsigned next) {
    unsigned offset=id*16; p64(offset,address); p32(offset+8,length); p16(offset+12,flags); p16(offset+14,next);
}
static void setup(void) {
    w(112,0); memset(memory,0,65536); mode=0;
    expected_payload[0]=99; expected_payload[1]=0;
    w(112,1); w(112,3); w(36,0); w(32,1); w(36,1); w(32,1); w(112,11);
    w(48,0); w(56,8); w(128,GPA); w(132,0);
    w(144,GPA+0x1000); w(148,0); w(160,GPA+0x2000); w(164,0); w(68,1); w(112,15);
    assert(N(healthy)()==1);
}
static void request(unsigned output_length) {
    p32(0x3000,9); memory[0x3004]=108; memory[0x3005]=0x34; memory[0x3006]=0x12;
    p16(0x3007,99);
    descriptor(0,GPA+0x3000,9,1,1);
    descriptor(1,GPA+0x6000,output_length,2,0);
    memset(memory+0x6000,0xcc,output_length);
    p16(0x1004,0); p16(0x1002,1);
}
static void denied(unsigned before,unsigned expected) {
    assert(N(poll)()==0 && N(healthy)()==0 && N(diagnostic)()==expected);
    assert(calls==before && r16(0x2002)==0 && memory[0x6000]==0xcc);
}
int main(void) {
    memory=mmap((void*)0x48000000ull,65536,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(memory!=MAP_FAILED && N(init)(GPA,65536,1)==1);
    assert(N(mmio_read)(0)==0x74726976 && N(mmio_read)(4)==2 && N(mmio_read)(8)==9);
    uint32_t config[3]={(uint32_t)N(mmio_read)(256),(uint32_t)N(mmio_read)(260),(uint32_t)N(mmio_read)(264)};
    assert(((uint8_t*)config)[0]==7 && ((uint8_t*)config)[1]==0 && !memcmp((uint8_t*)config+2,"okernel",7));
    setup(); request(7); assert(N(poll)()==1 && calls==1 && r16(0x2002)==1 && r32(0x2008)==7 && irq==1);
    assert(r32(0x6000)==7 && memory[0x6004]==109 && memory[0x6005]==0x34 && memory[0x6006]==0x12);
    w(100,1); assert(irq==0);
    setup(); request(64); assert(N(poll)()==1 && memory[0x6007]==0xcc && last_capacity==64);
    setup(); request(32768); assert(N(poll)()==1 && last_capacity==8192);
    setup(); request(7); p16(0x1000,1); assert(N(poll)()==1 && irq==0);

    // Both the 9P header and reply can cross SG boundaries.
    setup(); request(7); memcpy(memory+0x3100,memory+0x3003,6);
    descriptor(0,GPA+0x3000,3,1,1); descriptor(1,GPA+0x3100,6,1,2);
    descriptor(2,GPA+0x6000,3,3,3); descriptor(3,GPA+0x6100,4,2,0);
    assert(N(poll)()==1 && r16(0x2002)==1 && memory[0x6000]==7 && memory[0x6101]==109 && memory[0x6102]==0x34);

    // Two readable request elements may reference the same input byte.
    setup(); request(7); expected_payload[0]=expected_payload[1]=0x63; memory[0x3100]=0x63;
    descriptor(0,GPA+0x3000,7,1,1); descriptor(1,GPA+0x3100,1,1,2);
    descriptor(2,GPA+0x3100,1,1,3); descriptor(3,GPA+0x6000,7,2,0);
    assert(N(poll)()==1 && N(healthy)()==1 && r32(0x2008)==7 && memory[0x3100]==0x63);
    // Partially overlapping input elements preserve SG concatenation order.
    setup(); request(7); p32(0x3000,9); memory[0x3007]=0x12;
    expected_payload[0]=0x12; expected_payload[1]=0x12;
    descriptor(0,GPA+0x3000,8,1,1); descriptor(1,GPA+0x3006,1,1,2);
    descriptor(2,GPA+0x6000,7,2,0);
    assert(N(poll)()==1 && N(healthy)()==1 && r32(0x2008)==7);
    // Valid repeated input does not excuse a later out-of-grant element.
    setup(); request(7);
    descriptor(0,GPA+0x3000,7,1,1); descriptor(1,GPA+0x3100,1,1,2);
    descriptor(2,GPA+0x3100,1,1,3); descriptor(3,GPA+65536,7,2,0);
    denied(calls,42);
    // Readable aliases never permit writable reply aliases or ring access.
    setup(); request(7);
    descriptor(1,GPA+0x6000,3,3,2); descriptor(2,GPA+0x6002,4,2,0); denied(calls,44);
    setup(); request(7);
    descriptor(0,GPA+0x3000,7,1,1); descriptor(1,GPA,2,1,2);
    descriptor(2,GPA+0x6000,7,2,0); denied(calls,44);

    setup(); request(7); descriptor(1,GPA+65536,7,2,0); denied(calls,42);
    setup(); request(7); descriptor(1,GPA+0x3000,7,2,0); denied(calls,44);
    setup(); request(7); descriptor(0,GPA+0x3000,9,1,0); denied(calls,41);
    setup(); request(7); descriptor(0,GPA+0x3000,9,3,1); descriptor(1,GPA+0x6000,7,0,0); denied(calls,43);
    setup(); request(7); descriptor(1,GPA+0x6000,7,0,0); denied(calls,45);
    setup(); request(7); descriptor(1,GPA+0x6000,6,2,0); denied(calls,45);
    setup(); request(7); descriptor(0,GPA+0x3000,8193,1,1); denied(calls,45);
    setup(); request(7); descriptor(0,GPA+0x3000,9,5,1); denied(calls,42);
    setup(); request(7); p32(0x3000,8); denied(calls,46);
    setup(); request(7); p16(0x1002,9); denied(calls,31);
    setup(); request(7); p16(0x1004,32); denied(calls,40);
    for (unsigned failure=1;failure<=4;failure++) {
        setup(); request(7); mode=failure; unsigned before=calls;
        assert(N(poll)()==0 && calls==before+1 && N(healthy)()==0);
        assert(N(diagnostic)()==(failure<=2?51:50));
        assert(r16(0x2002)==0 && memory[0x6000]==0xcc);
    }
    assert(last_epoch>1); // Every driver reset got a fresh trusted session.
    puts("virtio-9P production mixed-SG/session/bounds/response tests: PASS");
    return 0;
}
'''

INTEGRATED_HARNESS = r'''
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
int main(void) {
    memory=mmap((void*)0x48000000ull,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    volume=mmap((void*)0x6c000000ull,0x1000000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(memory!=MAP_FAILED && volume!=MAP_FAILED && S(init)((uintptr_t)volume,0x1000000,1)==1);
    assert(N(init)(GPA,65536,1)==1); setup();
    version(); exchange(101,19); attach(10); exchange(105,20);
    walk(10,11,"work",0); exchange(111,8192); create(11,"shared",2); exchange(115,24);
    write_(11,"hello"); assert(get32(exchange(119,11)+7)==5);
    read_(11,5); uint8_t *response=exchange(117,16); assert(get32(response+7)==5 && !memcmp(response+11,"hello",5));
    write_(11,"abab"); input_alias=1; assert(get32(exchange(119,11)+7)==4);
    read_(11,4); response=exchange(117,15); assert(get32(response+7)==4 && !memcmp(response+11,"abab",4));
    write_(11,"abcdbcd"); input_alias=2; assert(get32(exchange(119,11)+7)==7);
    read_(11,7); response=exchange(117,18); assert(get32(response+7)==7 && !memcmp(response+11,"abcdbcd",7));
    begin(124); b(4,11); exchange(125,8192); clunk(11); exchange(121,7);
    walk(10,12,"work","shared"); exchange(111,8192); open_(12,0x11); exchange(113,24);
    write_(12,"linux-replaced"); exchange(119,11); clunk(12); exchange(121,7);

    uint64_t peer=S(session_init)(2,500); assert(peer!=0);
    version(); direct(peer,101); attach(1); direct(peer,105);
    walk(1,2,"shared",0); direct(peer,111); open_(2,0); direct(peer,113);
    read_(2,128); response=direct(peer,117); assert(get32(response+7)==14 && !memcmp(response+11,"linux-replaced",14));
    clunk(2); direct(peer,121); walk(1,2,"shared",0); direct(peer,111); open_(2,0x12); direct(peer,113);
    write_(2,"native"); direct(peer,119); clunk(2); direct(peer,121);
    walk(1,3,"pkg",0); direct(peer,107); // Scoped grant cannot walk outside /work.

    walk(10,13,"work","shared"); exchange(111,8192); open_(13,0); exchange(113,24);
    read_(13,128); response=exchange(117,139); assert(get32(response+7)==6 && !memcmp(response+11,"native",6));
    clunk(13); exchange(121,7);
    uint64_t readonly=S(session_init)(3,600); assert(readonly!=0);
    version(); direct(readonly,101); attach(1); direct(readonly,105);
    walk(1,2,"shared",0); direct(readonly,111); open_(2,1); direct(readonly,107);
    assert(S(revoke)(2)==1); read_(2,1); direct(peer,107);

    // Persisted namespace bytes reconstruct without preserving live sessions.
    assert(S(init)((uintptr_t)volume,0x1000000,2)==1); setup();
    version(); exchange(101,19); attach(10); exchange(105,20);
    walk(10,11,"work","shared"); exchange(111,8192); open_(11,0); exchange(113,24);
    read_(11,128); response=exchange(117,139); assert(get32(response+7)==6 && !memcmp(response+11,"native",6));
    read_(2,1); direct(readonly,107); // A pre-restart handle cannot select fresh fids.
    puts("native 9P transport/server bidirectional objects/grants/short-replies/restart: PASS");
    return 0;
}
'''


INTEGRATED_DOTU_HARNESS = INTEGRATED_HARNESS.split("int main(void)", 1)[0] + r"""
extern uint64_t S(session_handle)(uint64_t);
int main(void) {
    memory=mmap((void*)0x48000000ull,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    volume=mmap((void*)0x6c000000ull,0x1000000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(memory!=MAP_FAILED&&volume!=MAP_FAILED&&S(init)((uintptr_t)volume,0x1000000,1)==1);
    uint64_t plan9=S(session_init)(4,1);assert(plan9&&!(plan9&1));
    version();direct(plan9,101);attach(1);direct(plan9,105);
    assert(N(init)(GPA,65536,1)==1);setup();
    uint64_t old=S(session_handle)(1);assert(old&&!(old&1));
    begin(100);b(4,8192);string("9P2000.u");exchange(101,21);
    uint64_t current=S(session_handle)(1);assert(current!=old&&(current&1));
    attach(10);b(4,1234567);exchange(105,20);
    walk(10,11,"work",0);exchange(111,8192);
    create(11,"dotu-wire",2);string("");exchange(115,24);
    write_(11,"wire-u");exchange(119,11);
    read_(11,6);uint8_t*response=exchange(117,64);assert(get32(response+7)==6&&!memcmp(response+11,"wire-u",6));
    begin(124);b(4,11);response=exchange(125,8192);
    unsigned size=get32(response);for(unsigned i=0;i<14;i++)assert(response[size-14+i]==0);
    begin(124);b(4,1);direct(plan9,125);assert(get32(native_reply)==74);
    assert(S(revoke)(1)==1);read_(11,1);response=exchange(107,64);
    assert(get32(response+get32(response)-4)==116); // actual.u wire errno
    assert(S(session_handle)(4)==plan9);begin(124);b(4,1);direct(plan9,125);
    puts("production virtio.u adoption, numericESTALE and plain Plan9 survivor: PASS");return 0;
}
"""


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "host queue execution fixture requires Linux x86_64")
class KernelWorld9PTransportTests(unittest.TestCase):
    def compile_and_run(self, source, modules):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-9p-integrated-") as directory:
            output = Path(directory)
            (output / "harness.c").write_text(source)
            inputs = [str(ROOT / module) for module in modules]
            commands = [
                [str(compiler), *inputs, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), *inputs, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "production.o")],
                [clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "production.o"), "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout

    def test_real_transport_and_server_share_authorized_objects(self):
        output = self.compile_and_run(INTEGRATED_HARNESS, [
            "ocore/runtime/common/namespace_store.oc", "ocore/runtime/aarch64/kernel_world_9p.oc"])
        self.assertIn("short-replies/restart: PASS", output)

    def test_real_transport_adopts_dotu_token_and_returns_numeric_estale(self):
        output = self.compile_and_run(INTEGRATED_DOTU_HARNESS, [
            "ocore/runtime/common/namespace_store.oc", "ocore/runtime/aarch64/kernel_world_9p.oc"])
        self.assertIn("numericESTALE and plain Plan9 survivor: PASS", output)

    def test_real_transport_memory_and_protocol_boundary(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-9p-transport-") as directory:
            output = Path(directory)
            (output / "store-stubs.oc").write_text(STUBS)
            (output / "harness.c").write_text(HARNESS)
            inputs = [str(output / "store-stubs.oc"), str(ROOT / "ocore/runtime/aarch64/kernel_world_9p.oc")]
            commands = [
                [str(compiler), *inputs, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), *inputs, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "transport.o")],
                [clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "transport.o"), "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("response tests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
