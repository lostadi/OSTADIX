"""Execute the production store's opaque session-token lifetime rules.

C supplies independent 9P wire clients. objcopy changes only symbol visibility
to expose the native counter for the otherwise impractical exhaustion test;
the executed O-core instructions and initial data remain unmodified.
These are native backend tests, not guest-boot or full-OS qualification.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SYMBOL = "_O_runtime__common__namespace_store__"
HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define S(name) _O_runtime__common__namespace_store__##name
extern uint64_t S(init)(uintptr_t,size_t,uint64_t),S(healthy)(void);
extern uint64_t S(session_init)(uint64_t,uint64_t),S(revoke)(uint64_t);
extern uint64_t S(session_claim)(uint64_t,uint64_t,uint64_t),S(revoke_if_current)(uint64_t,uint64_t);
extern uint64_t S(session_is_current)(uint64_t,uint64_t);
extern size_t S(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
extern uint64_t S(SERIAL),S(SESSION)[5],S(GENERATION)[5],S(F_SESSION)[512];
extern uint8_t S(VERSIONED)[5];
static const size_t BYTES=16777216;
static const uint64_t EPOCH=UINT64_C(0x123456789abcdef1);
static uint8_t *volume,request[8192],response[8192];
static size_t position;
// Private O-core globals are not C globals: do not assume C/SIMD alignment.
static void snapshot(void *to,const volatile void *from,size_t n){
    uint8_t *dst=to;const volatile uint8_t *src=from;for(size_t i=0;i<n;i++)dst[i]=src[i];
}
static int unchanged(const void *before,const volatile void *now,size_t n){
    const uint8_t *a=before;const volatile uint8_t *b=now;for(size_t i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;
}
static void put(uint8_t *p,uint64_t value,unsigned width) {
    for(unsigned i=0;i<width;i++)p[i]=(uint8_t)(value>>(i*8));
}
static uint64_t get(const uint8_t *p,unsigned width) {
    uint64_t value=0;for(unsigned i=0;i<width;i++)value|=(uint64_t)p[i]<<(i*8);return value;
}
static void value(uint64_t n,unsigned width){put(request+position,n,width);position+=width;}
static void string(const char *s){size_t n=strlen(s);value(n,2);memcpy(request+position,s,n);position+=n;}
static void begin(unsigned type){memset(request,0,sizeof request);position=7;request[4]=type;put(request+5,123,2);}
static unsigned call(uint64_t session){
    put(request,position,4);memset(response,0xcc,sizeof response);
    size_t n=S(handle)(session,request,position,response,sizeof response);
    assert(n>=7 && n<=sizeof response && get(response,4)==n && get(response+5,2)==123);
    return response[4];
}
static void handshake(uint64_t session){
    begin(100);value(8192,4);string("9P2000");assert(call(session)==101);
    begin(104);value(1,4);value(UINT32_MAX,4);string("root");string("");assert(call(session)==105);
}
static unsigned stat(uint64_t session,unsigned fid){begin(124);value(fid,4);return call(session);}
static unsigned walk(uint64_t session,unsigned old,unsigned fresh,const char *name){
    begin(110);value(old,4);value(fresh,4);value(1,2);string(name);return call(session);
}
static unsigned create(uint64_t session,unsigned fid,const char *name,uint32_t mode){
    begin(114);value(fid,4);string(name);value(mode,4);value(2,1);return call(session);
}
static unsigned openfid(uint64_t session,unsigned fid,unsigned mode){begin(112);value(fid,4);value(mode,1);return call(session);}
static unsigned writefid(uint64_t session,unsigned fid,const char *s){
    begin(118);value(fid,4);value(0,8);value(strlen(s),4);memcpy(request+position,s,strlen(s));position+=strlen(s);return call(session);
}
static unsigned readfid(uint64_t session,unsigned fid){begin(116);value(fid,4);value(0,8);value(100,4);return call(session);}
static void initialize(void){
    volume=mmap(NULL,BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
    assert(S(init)((uintptr_t)volume,BYTES,EPOCH)==1 && S(healthy)()==1);
}
static uint64_t old_collision_generation(unsigned grant){
    const uint64_t c=UINT64_C(0x9e3779b97f4a7c15);
    uint64_t first=EPOCH^c^(UINT64_C(1)<<56)^1;
    return first^EPOCH^(UINT64_C(2)*c)^((uint64_t)grant<<56);
}
static void separate_rw_roles(void){
    uint64_t left=S(session_init)(1,1),generation=old_collision_generation(4);
    assert(left && generation);handshake(left);
    uint64_t right=S(session_init)(4,generation);assert(right && right!=left);handshake(right);
    assert(stat(left,1)==125 && stat(right,1)==125);
    assert(walk(left,1,2,"work")==111 && create(left,2,"common",0644)==115);
    assert(writefid(left,2,"shared bytes")==119);
    assert(walk(right,1,2,"work")==111 && walk(right,2,3,"common")==111 && openfid(right,3,0)==113);
    assert(readfid(right,3)==117 && get(response+7,4)==12 && !memcmp(response+11,"shared bytes",12));
    assert(S(revoke)(4)==1 && stat(right,1)==107 && stat(left,2)==125);
    uint64_t replacement=S(session_init)(4,generation+1);assert(replacement && replacement!=left && replacement!=right);handshake(replacement);
    assert(S(session_init)(4,generation)==0 && S(session_init)(4,generation+1)==0 && stat(replacement,1)==125);
    uint64_t nextleft=S(session_init)(1,2);assert(nextleft && nextleft!=left && nextleft!=replacement);handshake(nextleft);
    assert(stat(left,2)==107 && stat(replacement,1)==125);
    puts("independent RW roles/reset/revoke: PASS");
}
static void readonly_role(void){
    uint64_t rw=S(session_init)(1,1),generation=old_collision_generation(3);assert(rw && generation);handshake(rw);
    uint64_t ro=S(session_init)(3,generation);assert(ro && ro!=rw);handshake(ro);
    assert(stat(rw,1)==125 && create(ro,1,"forbidden",0644)==107);
    assert(walk(ro,1,2,"..")==111 && walk(ro,2,3,"pkg")==107);
    assert(walk(rw,1,2,"work")==111 && create(rw,2,"readable",0644)==115 && writefid(rw,2,"RW only")==119);
    assert(walk(ro,1,3,"readable")==111 && openfid(ro,3,1)==107 && openfid(ro,3,0)==113);
    assert(readfid(ro,3)==117 && get(response+7,4)==7 && !memcmp(response+11,"RW only",7));
    assert(writefid(ro,3,"bad")==107 && S(revoke)(3)==1 && stat(rw,2)==125 && stat(ro,3)==107);
    puts("crafted RO generation cannot acquire root/RW authority: PASS");
}
static void reinitialization(void){
    uint64_t a=S(session_init)(1,1);assert(a);handshake(a);
    uint64_t serial=S(SERIAL);assert(S(session_init)(1,1)==0 && S(session_init)(1,0)==0 && S(session_init)(0,1)==0 && S(session_init)(5,1)==0);
    assert(S(SERIAL)==serial && stat(a,1)==125);
    assert(S(init)((uintptr_t)volume,BYTES,EPOCH)==1 && stat(a,1)==107);
    uint64_t b=S(session_init)(1,1);assert(b && b!=a);handshake(b);
    assert(stat(a,1)==107 && stat(b,1)==125);
    assert(S(init)((uintptr_t)volume,BYTES,EPOCH+1)==1 && stat(a,1)==107 && stat(b,1)==107);
    uint64_t c=S(session_init)(1,1);assert(c && c!=a && c!=b);handshake(c);
    assert(stat(a,1)==107 && stat(b,1)==107 && stat(c,1)==125);
    puts("same/different epoch init clears sessions without recycling tokens: PASS");
}
static void exhaustion(void){
    uint64_t first=S(session_init)(1,1);assert(first);handshake(first);
    S(SERIAL)=UINT64_MAX-1; // Test-only private counter injection; code is unchanged.
    uint64_t last=S(session_init)(1,2);assert(last==UINT64_MAX);handshake(last);
    uint64_t sessions[5],generations[5],fids[512];uint8_t versions[5];
    snapshot(sessions,S(SESSION),sizeof sessions);snapshot(generations,S(GENERATION),sizeof generations);
    snapshot(fids,S(F_SESSION),sizeof fids);snapshot(versions,S(VERSIONED),sizeof versions);
    uint8_t *before=malloc(BYTES);assert(before);memcpy(before,volume,BYTES);
    assert(S(session_init)(1,3)==0 && S(session_init)(4,1)==0 && S(SERIAL)==UINT64_MAX);
    assert(unchanged(sessions,S(SESSION),sizeof sessions) && unchanged(generations,S(GENERATION),sizeof generations));
    assert(unchanged(fids,S(F_SESSION),sizeof fids) && unchanged(versions,S(VERSIONED),sizeof versions) && !memcmp(before,volume,BYTES));
    assert(stat(last,1)==125);free(before);
    assert(S(init)((uintptr_t)volume,BYTES,EPOCH+1)==1 && S(SERIAL)==UINT64_MAX && S(session_init)(1,1)==0);
    puts("last token is usable; exhaustion fails before mutation and survives init: PASS");
}
static void temporary_files(void){
    uint64_t a=S(session_init)(1,1);assert(a);handshake(a);
    assert(walk(a,1,2,"work")==111 && create(a,2,"object.7",UINT32_C(0x040001b4))==115 && response[7]==4);
    assert(writefid(a,2,"original compiler object")==119);
    assert(S(init)((uintptr_t)volume,BYTES,EPOCH+1)==1);
    uint64_t b=S(session_init)(1,1);assert(b && b!=a);handshake(b);
    assert(walk(b,1,2,"work")==111 && walk(b,2,3,"object.7")==111 && openfid(b,3,0)==113 && response[7]==4);
    assert(readfid(b,3)==117 && get(response+7,4)==24 && !memcmp(response+11,"original compiler object",24));
    puts("DMTMP objects/bytes survive reinitialization: PASS");
}
static void serialized_claims(void){
    uint64_t a=S(session_init)(1,1);assert(a);handshake(a);
    assert(S(session_is_current)(1,a)==1 && S(session_is_current)(1,0)==0 && S(session_is_current)(0,a)==0 && S(session_is_current)(5,a)==0);
    uint64_t serial=S(SERIAL),sessions[5],generations[5],fids[512];uint8_t versions[5];
    snapshot(sessions,S(SESSION),sizeof sessions);snapshot(generations,S(GENERATION),sizeof generations);
    snapshot(fids,S(F_SESSION),sizeof fids);snapshot(versions,S(VERSIONED),sizeof versions);
    assert(S(session_claim)(1,2,0)==0 && S(session_claim)(1,2,a+100)==0 && S(revoke_if_current)(1,a+100)==0);
    assert(S(session_claim)(0,2,0)==0 && S(session_claim)(5,2,0)==0 && S(session_claim)(1,0,a)==0 && S(revoke_if_current)(1,0)==0);
    assert(S(SERIAL)==serial && unchanged(sessions,S(SESSION),sizeof sessions) && unchanged(generations,S(GENERATION),sizeof generations));
    assert(unchanged(fids,S(F_SESSION),sizeof fids) && unchanged(versions,S(VERSIONED),sizeof versions) && stat(a,1)==125);
    uint64_t b=S(session_claim)(1,2,a);assert(b && b!=a);handshake(b);
    assert(S(session_is_current)(1,a)==0 && S(session_is_current)(1,b)==1);
    assert(S(session_claim)(1,3,a)==0 && S(revoke_if_current)(1,a)==0 && stat(b,1)==125 && stat(a,1)==107);
    assert(S(revoke_if_current)(1,b)==1 && stat(b,1)==107 && S(revoke_if_current)(1,b)==0);
    uint64_t c=S(session_claim)(1,3,0);assert(c && c!=a && c!=b);handshake(c);
    assert(S(init)((uintptr_t)volume,BYTES,EPOCH+1)==1 && S(session_claim)(1,4,c)==0);
    assert(S(session_is_current)(1,c)==0);
    uint64_t d=S(session_claim)(1,4,0);assert(d && d!=c);handshake(d);
    puts("serialized claims/revocation reject stale or occupied roles without mutation: PASS");
}
int main(int argc,char **argv){
    assert(argc==2);initialize();unsigned scenario=(unsigned)atoi(argv[1]);
    if(scenario==0)separate_rw_roles();else if(scenario==1)readonly_role();else if(scenario==2)reinitialization();
    else if(scenario==3)exhaustion();else if(scenario==4)temporary_files();else if(scenario==5)serialized_claims();else assert(0);
    return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "native production-code fixture requires Linux x86_64")
class NamespaceSessionTokenTests(unittest.TestCase):
    def test_real_store_tokens_are_unique_until_native_counter_exhaustion(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang, objcopy = shutil.which("clang"), shutil.which("objcopy")
        if not compiler.is_file() or not clang or not objcopy:
            self.skipTest("already-built ocorec, clang and objcopy are required")
        with tempfile.TemporaryDirectory(prefix="namespace-session-tokens-") as directory:
            output = Path(directory)
            (output / "harness.c").write_text(HARNESS)
            source = ROOT / "ocore/runtime/common/namespace_store.oc"
            commands = [
                [str(compiler), str(source), "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), str(source), "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "store.o")],
                [objcopy, *["--globalize-symbol=" + SYMBOL + name for name in ("SERIAL", "SESSION", "GENERATION", "VERSIONED", "F_SESSION")], str(output / "store.o"), str(output / "inspectable.o")],
                [clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "inspectable.o"), "-o", str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=60, cwd=output)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for scenario in range(6):
                with self.subTest(scenario=scenario):
                    result = subprocess.run([str(output / "selftest"), str(scenario)], capture_output=True, text=True, timeout=60, cwd=output)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
