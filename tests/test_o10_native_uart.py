"""Compiled per-holder polled UART and baseline read-only namespace authority."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define U(n) _O_runtime__aarch64__native_namespace_uart__##n
#define T(n) _O_runtime__aarch64__domain_table__##n
#define S(n) _O_runtime__common__namespace_store__##n
extern uint64_t U(provision)(uint64_t),U(bind)(uint64_t),U(revoke)(uint64_t),U(retire)(uint64_t);
extern uint64_t U(replace)(uint64_t,uint64_t),U(session)(uint64_t),U(healthy)(uint64_t),U(diagnostic)(uint64_t),U(active_owner)(void);
extern uint64_t U(mmio_write)(uint64_t,uint64_t,uint64_t),U(mmio_read)(uint64_t,uint64_t);
extern uint64_t T(boot)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t T(boot_start)(uint64_t,uint64_t,uint64_t),T(fault)(uint64_t),T(restored)(uint64_t,uint64_t,const unsigned char*);
extern uint64_t S(init)(uintptr_t,size_t,uint64_t),S(session_init)(uint64_t,uint64_t),S(session_handle)(uint64_t),S(session_fid_count)(uint64_t);
extern size_t S(handle)(uint64_t,const unsigned char*,size_t,unsigned char*,size_t);
static uint64_t a=(1ull<<32)|2,b=(1ull<<32)|6,writer,irq_owner,irq_level;
static unsigned transitions;
void native_namespace_irq_level(uint64_t holder,uint64_t asserted){
 assert(holder==a||holder==b||holder==((2ull<<32)|2));assert(asserted<=1);
 irq_owner=holder;irq_level=asserted;transitions++;
}
static unsigned char q[8192],r[8192];static size_t n;static unsigned tag;
static uint64_t rd(const void*p,unsigned bytes){const unsigned char*s=p;uint64_t v=0;for(unsigned i=0;i<bytes;i++)v|=(uint64_t)s[i]<<(8*i);return v;}
static void st(void*p,uint64_t v,unsigned bytes){unsigned char*s=p;for(unsigned i=0;i<bytes;i++)s[i]=(unsigned char)(v>>(8*i));}
static void begin(unsigned type){memset(q,0,sizeof q);q[4]=type;st(q+5,++tag,2);n=7;}
static void put(uint64_t v,unsigned bytes){st(q+n,v,bytes);n+=bytes;}
static void string(const char*s){size_t bytes=strlen(s);put(bytes,2);memcpy(q+n,s,bytes);n+=bytes;}
static void version(void){begin(100);put(8192,4);string("9P2000");}
static void attach(unsigned fid){begin(104);put(fid,4);put(UINT32_MAX,4);string("u");string("");}
static void walk(unsigned fid,unsigned fresh,const char*name){begin(110);put(fid,4);put(fresh,4);put(1,2);string(name);}
static void open_(unsigned fid,unsigned mode){begin(112);put(fid,4);put(mode,1);}
static void read_(unsigned fid){begin(116);put(fid,4);put(0,8);put(128,4);}
static unsigned exchange(uint64_t holder,unsigned type){
 st(q,n,4);for(size_t i=0;i<n;i++)assert(U(mmio_write)(holder,0,q[i]));
 assert(!(U(mmio_read)(holder,0x18)&0x10));
 for(unsigned i=0;i<4;i++)r[i]=U(mmio_read)(holder,0);
 unsigned bytes=rd(r,4);assert(bytes>=7&&bytes<=sizeof r);
 for(unsigned i=4;i<bytes;i++)r[i]=U(mmio_read)(holder,0);
 assert(r[4]==type&&rd(r+5,2)==tag&&(U(mmio_read)(holder,0x18)&0x10));return bytes;
}
static unsigned direct(unsigned type){
 st(q,n,4);unsigned bytes=S(handle)(writer,q,n,r,sizeof r);assert(bytes>=7&&r[4]==type);return bytes;
}
static void enable(uint64_t h){assert(U(mmio_write)(h,0x30,0x301));}
int main(void){
 void*volume=mmap(NULL,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 assert(volume!=MAP_FAILED&&S(init)((uintptr_t)volume,16777216,7));
 writer=S(session_init)(2,1);assert(writer);version();direct(101);attach(50);direct(105);
 begin(114);put(50,4);string("o10-m3-witness");put(0644,4);put(2,1);direct(115);
 begin(118);put(50,4);put(0,8);put(24,4);memcpy(q+n,"O10_M3_NATIVE_NAMESPACE\n",24);n+=24;direct(119);
 assert(T(boot)(2,3,3,0xe2200000,0x200000,5,6)&&T(boot)(6,3,3,0xe2600000,0x200000,5,6));
 assert(U(provision)(a)&&U(provision)(b)&&!U(provision)(a));
 assert(U(bind)(a)==0&&U(healthy)(a)&&U(active_owner)()==a); // PROVISIONED bind deasserts.
 uint64_t session=U(session)(a),writer_session=S(session_handle)(2);
 assert(session&&U(bind)(b)==7&&U(session)(a)==session&&S(session_handle)(2)==writer_session);
 assert(U(bind)((2ull<<32)|2)==5&&!U(revoke)((2ull<<32)|2));
 assert(T(boot_start)(2,0x40000000,0x40100000));enable(a);
 version();exchange(a,101);attach(1);exchange(a,105);walk(1,2,"o10-m3-witness");exchange(a,111);
 open_(2,0);exchange(a,113);read_(2);assert(exchange(a,117)==35&&rd(r+7,4)==24&&!memcmp(r+11,"O10_M3_NATIVE_NAMESPACE\n",24));
 open_(1,1);exchange(a,107); // Parent /work remains read-only.
 begin(114);put(1,4);string("forbidden");put(0644,4);put(2,1);exchange(a,107);
 begin(118);put(2,4);put(0,8);put(1,4);put('x',1);exchange(a,107);
 assert(S(session_handle)(2)==writer_session&&S(session_fid_count)(2)==1);
 // Guest reset changes only the current authorized session; it clears old fids.
 assert(U(mmio_write)(a,0x30,0));assert(U(session)(a)!=session);enable(a);
 version();exchange(a,101);read_(2);exchange(a,107);attach(1);exchange(a,105);
 assert(U(mmio_write)(a,0x38,0x20)&&irq_level==1&&irq_owner==a);
 assert(T(fault)(2)&&U(revoke)(a)&&!U(healthy)(a)&&!irq_level&&S(session_handle)(3)==0);
 assert(!U(mmio_write)(a,0x30,0)&&!U(mmio_write)(a,0x30,0x301)&&!U(healthy)(a));
 assert(S(session_handle)(2)==writer_session&&S(session_fid_count)(2)==1);
 unsigned char instance[16]={0};
 uint64_t fresh=(2ull<<32)|2;assert(U(replace)(a,fresh)&&T(restored)(2,1,instance));
 assert(U(bind)(a)==5&&U(bind)(fresh)==0&&U(active_owner)()==fresh);
 assert(S(session_handle)(2)==writer_session);
 assert(U(retire)(fresh)&&U(bind)(b)==0&&U(active_owner)()==b); // grant3 release/reassignment.
 enable(b);version();exchange(b,101);attach(1);exchange(b,105);walk(1,2,"o10-m3-witness");exchange(b,111);
 open_(2,0);exchange(b,113);read_(2);assert(exchange(b,117)==35&&!memcmp(r+11,"O10_M3_NATIVE_NAMESPACE\n",24));
 unsigned char bad[4]={1,32,0,0}; // 8193 exceeds admitted frame bound.
 for(unsigned i=0;i<3;i++)assert(U(mmio_write)(b,0,bad[i]));
 assert(!U(mmio_write)(b,0,bad[3])&&!U(healthy)(b)&&U(diagnostic)(b)==21);
 assert(!U(mmio_write)(b,0x30,0)); // Framing failure fails closed until Governor rebind.
 assert(U(bind)(b)==0);enable(b);assert(U(mmio_read)(b,0x48)==UINT64_MAX&&U(diagnostic)(b)==24);
 assert(transitions>50);puts("per-holder UART namespace authority/lifecycle/framing PASS");return 0;
}
"""


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "native component fixture requires Linux x86_64")
class NativeNamespaceUartTests(unittest.TestCase):
    def test_real_per_holder_uart_and_namespace_store(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang = shutil.which("clang")
        self.assertTrue(compiler.is_file())
        self.assertIsNotNone(clang)
        with tempfile.TemporaryDirectory(prefix="o10-native-uart-") as directory:
            out = Path(directory)
            sources = [str(ROOT / name) for name in (
                "ocore/runtime/aarch64/domain_table.oc",
                "ocore/runtime/aarch64/native_namespace_uart.oc",
                "ocore/runtime/common/namespace_store.oc")]
            for target, name in [("aarch64-unknown-none", "arm.o"), ("x86_64-unknown-none", "native.o")]:
                p = subprocess.run([str(compiler), *sources, "--target", target, "--emit", "obj",
                                    "-o", str(out / name)], capture_output=True, text=True, timeout=120)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            (out / "harness.c").write_text(HARNESS)
            p = subprocess.run([clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "native.o"),
                                "-o", str(out / "test")], capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            p = subprocess.run([str(out / "test")], capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("PASS", p.stdout)


if __name__ == "__main__":
    unittest.main()
