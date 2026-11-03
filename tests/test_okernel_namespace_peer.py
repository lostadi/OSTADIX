"""Execute the production native object store and its real 9P wire peer."""

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
#define STORE(n) _O_runtime__common__namespace_store__##n
#define PEER(n) _O_runtime__common__namespace_peer__##n
extern uint64_t STORE(init)(uintptr_t,size_t,uint64_t);
extern uint64_t STORE(session_init)(uint64_t,uint64_t);
extern uint64_t STORE(revoke)(uint64_t);
extern size_t STORE(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
extern uint64_t PEER(init)(uint64_t);
extern uint64_t PEER(poll)(void);
extern uint64_t PEER(exchanges)(void);
static uint8_t q[8192],r[8192];
static uint16_t tag;
static void p16(size_t o,uint16_t v) { q[o]=v; q[o+1]=v>>8; }
static void p32(size_t o,uint32_t v) { p16(o,v); p16(o+2,v>>16); }
static void p64(size_t o,uint64_t v) { p32(o,v); p32(o+4,v>>32); }
static uint16_t r16(size_t o) { return r[o]|((uint16_t)r[o+1]<<8); }
static uint32_t r32(size_t o) { return r16(o)|((uint32_t)r16(o+2)<<16); }
static size_t call(uint64_t s,unsigned kind,size_t n) {
 p32(0,n);q[4]=kind;p16(5,++tag);
 size_t got=STORE(handle)(s,q,n,r,sizeof r);
 assert(got>=7 && got==r32(0) && r16(5)==tag);return got;
}
static void version(uint64_t s) {
 p32(7,8192);p16(11,6);memcpy(q+13,"9P2000",6);
 assert(call(s,100,19)==19 && r[4]==101 && r16(11)==6 && !memcmp(r+13,"9P2000",6));
}
static void attach(uint64_t s) {
 p32(7,1);p32(11,0xffffffff);p16(15,0);p16(17,0);
 assert(call(s,104,19)==20 && r[4]==105);
}
static unsigned walk(uint64_t s,uint32_t parent,uint32_t fid,const char *name) {
 size_t n=strlen(name);p32(7,parent);p32(11,fid);p16(15,n?1:0);
 if(n){p16(17,n);memcpy(q+19,name,n);}
 call(s,110,n?19+n:17);return r[4];
}
static unsigned openfile(uint64_t s,uint32_t fid,unsigned mode) {
 p32(7,fid);q[11]=mode;call(s,112,12);return r[4];
}
static unsigned create(uint64_t s,uint32_t fid,const char *name) {
 size_t n=strlen(name);p32(7,fid);p16(11,n);memcpy(q+13,name,n);p32(13+n,0644);q[17+n]=1;
 call(s,114,18+n);return r[4];
}
static void clunk(uint64_t s,uint32_t fid) {p32(7,fid);assert(call(s,120,11)==7&&r[4]==121);}
static void writefile(uint64_t s,uint32_t fid,const char *data) {
 size_t n=strlen(data);p32(7,fid);p64(11,0);p32(19,n);memcpy(q+23,data,n);
 assert(call(s,118,23+n)==11&&r[4]==119&&r32(7)==n);
}
static size_t readfile(uint64_t s,uint32_t fid,char *out) {
 p32(7,fid);p64(11,0);p32(19,512);size_t n=call(s,116,23);
 assert(r[4]==117&&n==11+r32(7));memcpy(out,r+11,r32(7));out[r32(7)]=0;return r32(7);
}
static void linux_input(uint64_t s,const char *data,int exists) {
 assert(walk(s,1,2,"work")==111);
 if(exists){assert(walk(s,2,3,"from-linux")==111);clunk(s,2);assert(openfile(s,3,0x11)==113);}
 else {assert(create(s,2,"from-linux")==115);}
 writefile(s,exists?3:2,data);clunk(s,exists?3:2);
}
static void linux_output(uint64_t s,const char *expected) {
 assert(walk(s,1,2,"work")==111);assert(walk(s,2,3,"from-plan9")==111);clunk(s,2);
 assert(openfile(s,3,0)==113);char data[1024];readfile(s,3,data);assert(!strcmp(data,expected));clunk(s,3);
}
int main(void) {
 const size_t bytes=16777216;
 void *volume=mmap(0,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 assert(STORE(init)((uintptr_t)volume,bytes,100)==1);
 uint64_t linux_session=STORE(session_init)(1,1);assert(linux_session);version(linux_session);attach(linux_session);
 assert(PEER(init)(42)==1);assert(PEER(poll)()==0);
 linux_input(linux_session,"linux-one\n",0);
 assert(PEER(poll)()==1&&PEER(exchanges)()==1);assert(PEER(poll)()==0);
 linux_output(linux_session,"native-9p-peer generation=000000000000002a\nlinux=linux-one\n");
 linux_input(linux_session,"linux-two\n",1);
 assert(PEER(poll)()==1&&PEER(exchanges)()==2);
 linux_output(linux_session,"native-9p-peer generation=000000000000002a\nlinux=linux-two\n");
 uint64_t ro=STORE(session_init)(3,1);assert(ro);version(ro);attach(ro);
 assert(walk(ro,1,2,"")==111);assert(create(ro,2,"denied")==107);clunk(ro,2);
 assert(walk(ro,1,3,"from-linux")==111);assert(openfile(ro,3,1)==107);
 assert(openfile(ro,3,0)==113);char data[1024];readfile(ro,3,data);assert(!strcmp(data,"linux-two\n"));clunk(ro,3);
 assert(walk(ro,1,4,"pkg")==107); /* scope is /work, not the native root */
 uint64_t fresh=STORE(session_init)(3,2);assert(fresh&&fresh!=ro);
 p32(7,8192);p16(11,6);memcpy(q+13,"9P2000",6);call(ro,100,19);assert(r[4]==107);
 version(fresh);p32(7,3);q[11]=0;call(fresh,112,12);assert(r[4]==107); /* old fid has no authority */
 assert(STORE(revoke)(3)==1);p32(7,1);call(fresh,120,11);assert(r[4]==107);
 assert(STORE(init)((uintptr_t)volume,bytes,101)==1); /* actual persisted volume, fresh epoch */
 p32(7,8192);p16(11,6);memcpy(q+13,"9P2000",6);call(linux_session,100,19);assert(r[4]==107);
 linux_session=STORE(session_init)(1,1);assert(linux_session);version(linux_session);attach(linux_session);
 assert(PEER(init)(43)==1&&PEER(poll)()==1);
 linux_output(linux_session,"native-9p-peer generation=000000000000002b\nlinux=linux-two\n");
 puts("Native shared namespace/Plan9 wire peer production tests: PASS");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "production execution fixture requires Linux x86_64")
class NativeNamespacePeerTests(unittest.TestCase):
    def test_real_wire_bidirectional_files_scoped_grants_and_restart(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-namespace-peer-") as directory:
            output = Path(directory)
            (output / "harness.c").write_text(HARNESS)
            inputs = [str(ROOT / "ocore/runtime/common" / name) for name in ("namespace_store.oc", "namespace_peer.oc")]
            for command in (
                [str(compiler), *inputs, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(output / "arm.mir")],
                [str(compiler), *inputs, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "native.o")],
                [clang, "-O2", "-no-pie", str(output / "harness.c"), str(output / "native.o"), "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ):
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("production tests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
