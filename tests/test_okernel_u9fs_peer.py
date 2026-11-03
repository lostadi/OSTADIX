"""Run the live native store/peer path with the optional original u9fs codec profile.

OCORE_U9FS_MANIFEST selects a hash-sealed full native source-recipe closure.
Without that optional built profile this integration test is explicitly skipped.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("native_codec", ROOT / "scripts/okernel_native_codec.py")
CODEC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CODEC)
HARNESS = r'''#include <plan9.h>
#include <fcall.h>
#define ABI(field,offset) _Static_assert(offsetof(Fcall,field)==offset,"Fcall field layout: " #field)
_Static_assert(sizeof(void*)==8 && sizeof(ulong)==8,"LP64 u9fs profile");
_Static_assert(sizeof(Fcall)==712 && _Alignof(Fcall)==8 && sizeof(Qid)==24,"u9fs storage layout");
ABI(type,0);ABI(fid,4);ABI(tag,8);ABI(msize,12);ABI(version,16);ABI(afid,680);
ABI(uname,72);ABI(aname,80);ABI(perm,88);ABI(name,96);ABI(mode,104);
ABI(newfid,108);ABI(nwname,112);ABI(wname,120);ABI(nwqid,248);
ABI(offset,640);ABI(count,648);ABI(data,656);

#undef assert

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
extern uint64_t PEER(codec_encodes)(void),PEER(codec_decodes)(void),PEER(codec_request_bytes)(void),PEER(codec_response_bytes)(void);
static int measuring;
static uint64_t copy_calls,copy_bytes,string_calls,string_bytes;
extern void *__real_memmove(void*,const void*,size_t);
extern size_t __real_strlen(const char*);
void *__wrap_memmove(void *to,const void *from,size_t length) {
 if(measuring){copy_calls++;copy_bytes+=length;}return __real_memmove(to,from,length);
}
size_t __wrap_strlen(const char *text) {
 size_t length=__real_strlen(text);if(measuring){string_calls++;string_bytes+=length;}return length;
}
static uint64_t peer_init(uint64_t generation){measuring=1;uint64_t result=PEER(init)(generation);measuring=0;return result;}
static uint64_t peer_poll(void){measuring=1;uint64_t result=PEER(poll)();measuring=0;return result;}
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
 assert(peer_init(42)==1);assert(peer_poll()==0);
 linux_input(linux_session,"linux-one\n",0);
 assert(peer_poll()==1&&PEER(exchanges)()==1);assert(peer_poll()==0);
 linux_output(linux_session,"native-9p-peer generation=000000000000002a\nlinux=linux-one\n");
 linux_input(linux_session,"linux-two\n",1);
 assert(peer_poll()==1&&PEER(exchanges)()==2);
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
 assert(peer_init(43)==1&&peer_poll()==1);
 linux_output(linux_session,"native-9p-peer generation=000000000000002b\nlinux=linux-two\n");
 
 /* Original codec keeps payload bytes binary, including NUL and high bytes. */
 assert(walk(linux_session,1,2,"work")==111 && walk(linux_session,2,3,"from-linux")==111);clunk(linux_session,2);
 assert(openfile(linux_session,3,0x11)==113);
 p32(7,3);p64(11,0);p32(19,128);for(unsigned i=0;i<128;i++)q[23+i]=(uint8_t)(i*17);
 assert(call(linux_session,118,151)==11 && r[4]==119);clunk(linux_session,3);
 assert(peer_poll()==1);
 assert(walk(linux_session,1,2,"work")==111 && walk(linux_session,2,3,"from-plan9")==111);clunk(linux_session,2);
 assert(openfile(linux_session,3,0)==113);
 p32(7,3);p64(11,0);p32(19,512);assert(call(linux_session,116,23)==188 && r[4]==117 && r32(7)==177);
 assert(!memcmp(r+11,"native-9p-peer generation=000000000000002b\nlinux=",49));
 for(unsigned i=0;i<128;i++)assert(r[60+i]==(uint8_t)(i*17));clunk(linux_session,3);
 /* Peer withdrawal does not invalidate Linux's independent root session. */
 assert(STORE(revoke)(2)==1 && peer_poll()==0);
 linux_input(linux_session,"linux-after-peer-revoke\n",1);
 assert(peer_init(44)==1 && peer_poll()==1);
 linux_output(linux_session,"native-9p-peer generation=000000000000002c\nlinux=linux-after-peer-revoke\n");
 assert(PEER(codec_encodes)()>2 && PEER(codec_decodes)()==PEER(codec_encodes()));
 printf("Original u9fs native peer actual calls: encodes=%llu decodes=%llu request_bytes=%llu response_bytes=%llu\n",(unsigned long long)PEER(codec_encodes)(),(unsigned long long)PEER(codec_decodes)(),(unsigned long long)PEER(codec_request_bytes)(),(unsigned long long)PEER(codec_response_bytes)());
 printf("Measured codec closure calls during peer init/poll: memmove_calls=%llu memmove_bytes=%llu strlen_calls=%llu strlen_bytes=%llu\n",(unsigned long long)copy_calls,(unsigned long long)copy_bytes,(unsigned long long)string_calls,(unsigned long long)string_bytes);
 puts("Native shared namespace/original u9fs codec peer production tests: PASS");return 0;
}
'''


def checked_identity(record):
    path = Path(record["path"])
    if not path.is_file() or path.is_symlink():
        raise ValueError("expected regular native codec artifact: " + str(path))
    content = path.read_bytes()
    if len(content) != record["bytes"] or hashlib.sha256(content).hexdigest() != record["sha256"]:
        raise ValueError("native codec artifact identity mismatch: " + str(path))
    return path


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native production fixture requires Linux x86_64")
class OriginalU9fsNativePeerTests(unittest.TestCase):
    def test_original_codec_in_live_native_store_path(self):
        selected = os.environ.get("OCORE_U9FS_MANIFEST")
        if not selected:
            self.skipTest("optional source-recipe native codec profile needs OCORE_U9FS_MANIFEST")
        manifest = json.loads(Path(selected).read_text())
        self.assertEqual(manifest["schema"], "ostadix.native-u9fs-codec/v1")
        self.assertEqual(manifest["isa"], "x86_64")
        self.assertEqual(manifest["unresolved_symbols"], [])
        objects = [checked_identity(item) for item in manifest["objects"]]
        self.assertEqual(len(objects), 7, "four codec and three original libc component objects")
        header_paths = [checked_identity(item) for item in manifest["original_headers"]]
        headers = {path.name: path for path in header_paths}
        self.assertIn("plan9.h", headers); self.assertIn("fcall.h", headers)
        self.assertEqual(headers["plan9.h"].parent, headers["fcall.h"].parent)
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        self.assertTrue(compiler.is_file() and clang, "already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="ocore-u9fs-peer-") as directory:
            out = Path(directory)
            frozen = CODEC.stage(Path(selected), out / "codec", "x86_64")
            objects = [Path(item["path"]) for item in frozen["objects"]]
            (out / "harness.c").write_text(HARNESS)
            inputs = [str(ROOT / "ocore/runtime/common" / name) for name in (
                "namespace_store.oc", "u9fs_codec.oc", "u9fs_namespace_peer.oc")]
            commands = [
                [str(compiler), *inputs, "--target", "aarch64-unknown-none", "--emit", "obj", "-o", str(out / "arm.o")],
                [str(compiler), *inputs, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "native.o")],
                [clang, "-O2", "-no-pie", "-I", str(headers["plan9.h"].parent), str(out / "harness.c"), str(out / "native.o"), *map(str, objects), "-Wl,--wrap=memmove,--wrap=strlen", "-o", str(out / "test")],
                [str(out / "test")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("original u9fs codec peer production tests: PASS", result.stdout)
            self.assertIn("Measured codec closure calls", result.stdout)

if __name__ == "__main__":
    unittest.main()
