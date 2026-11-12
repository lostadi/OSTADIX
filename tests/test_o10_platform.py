"""Execute the real O10 mailbox/platform native graph on Linux.

Scope: framing, journal dispatch, domain identity and real namespace fid
revocation. Architecture/device assembly entry points are fail-closed sentinels;
this does not qualify EL2 context reset, QEMU boot, or either guest kernel.
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = r"""
pub unsafe fn o10_platform_test_init() -> u64 {
    LIVE[0] = 1; LIVE[1] = 1;
    return 1;
}
pub unsafe fn o10_platform_test_mailbox() -> u64 {
    native_control();
    return LIVE[0] | (LIVE[1] << 1);
}
"""
HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#define NS(n) _O_runtime__common__namespace_store__##n
#define UW(n) _O_runtime__aarch64__unified_world__##n
extern uint64_t NS(init)(uintptr_t,size_t,uint64_t),NS(session_init)(uint64_t,uint64_t);
extern uint64_t NS(session_handle)(uint64_t),NS(session_fid_count)(uint64_t);
extern size_t NS(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
extern uint64_t UW(o10_platform_test_init)(void),UW(o10_platform_test_mailbox)(void);
static unsigned char *request=(void*)0x6d0a0000,*reply=(void*)0x6d0a0200;
static uint64_t mailbox_seq=0;
static uint64_t rd(const void *q,unsigned n){const unsigned char*p=q;uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void st(void*q,uint64_t v,unsigned n){unsigned char*p=q;for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(v>>(8*i));}
static void frame(unsigned type,size_t len,uint64_t epoch,uint64_t seq){
 memset(request,0,512);st(request,len,4);st(request+4,type,1);st(request+5,77,2);
 if(type!=162){st(request+7,epoch,8);st(request+15,seq,8);}
}
static uint64_t call(void){
 st((void*)0x6d000070,++mailbox_seq,8);st((void*)0x6d000078,10,8);
 uint64_t live=UW(o10_platform_test_mailbox)();
 assert(rd((void*)0x6d000080,8)==mailbox_seq);
 assert(rd((void*)0x6d000088,8)==1);
 return live;
}
static void attach(uint64_t session){
 unsigned char q[64]={0},r[512]={0};
 st(q,19,4);q[4]=100;st(q+7,512,4);st(q+11,6,2);memcpy(q+13,"9P2000",6);
 assert(NS(handle)(session,q,19,r,512)==19&&r[4]==101);
 memset(q,0,sizeof q);st(q,20,4);q[4]=104;st(q+7,1,4);st(q+11,UINT32_MAX,4);
 st(q+15,1,2);q[17]='u';st(q+18,0,2);
 assert(NS(handle)(session,q,20,r,512)==20&&r[4]==105);
}
static unsigned stat_session(uint64_t session){
 unsigned char q[11]={11,0,0,0,124,0,0},r[512];st(q+7,1,4);
 assert(NS(handle)(session,q,11,r,512)!=0);return r[4];
}
// Assembly is deliberately outside this harness's corpus. Reaching a sentinel
// aborts instead of simulating successful device or architectural behavior.
#define SENTINEL(name) uint64_t name(void){fprintf(stderr,"off-corpus assembly: "#name"\n");abort();}
SENTINEL(uw_domain_reset)
SENTINEL(uw_current_domain)
SENTINEL(uw_counter_read)
void uw_memory_barrier(void){__sync_synchronize();}
SENTINEL(uw_serial_putc)
SENTINEL(uw_halt)
SENTINEL(uw_vgic_lr_read)
SENTINEL(uw_vgic_lr_write)
SENTINEL(uw_vgic_hcr_write)
SENTINEL(uw_vgic_vmcr_write)
int main(void){
 void *control=mmap((void*)0x6d000000,0x100000,PROT_READ|PROT_WRITE,
 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);assert(control==(void*)0x6d000000);
 void *volume=mmap(NULL,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 assert(NS(init)((uintptr_t)volume,16777216,1)==1);
 uint64_t linux=NS(session_init)(1,1),plan9=NS(session_init)(4,1);assert(linux&&plan9);
 attach(linux);attach(plan9);assert(NS(session_fid_count)(1)==1&&NS(session_fid_count)(4)==1);
 assert(UW(o10_platform_test_init)()==1);
 frame(164,39,0,1);st(request+23,1,8);call();assert(reply[4]==165);
 frame(178,31,1,0);st(request+23,((uint64_t)1<<32)|1,8);call();
 assert(reply[4]==179&&rd(reply+73,4)==1);
 frame(178,31,1,0);st(request+23,1,8);call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==1);
 frame(172,36,1,2);st(request+23,((uint64_t)1<<32)|1,8);
 unsigned char retry[36],outcome[64];memcpy(retry,request,36);
 assert(call()==1);assert(reply[4]==173&&rd(reply,4)==27);
 assert(rd(reply+15,4)==1&&rd(reply+19,4)==1&&rd(reply+23,4)==1);
 memcpy(outcome,reply,27);
 assert(NS(session_handle)(1)==linux&&NS(session_fid_count)(1)==1);
 assert(NS(session_handle)(4)==0&&NS(session_fid_count)(4)==0);
 assert(stat_session(plan9)==107);assert(stat_session(linux)==125);
 memcpy(request,retry,36);assert(call()==1);assert(!memcmp(reply,outcome,27));
 request[31]=1;call();assert(reply[4]==161&&rd(reply+7,4)==4);
 frame(178,31,1,0);st(request+23,((uint64_t)1<<32)|1,8);call();assert(reply[4]==179&&reply[16]==5);
 frame(184,39,1,3);st(request+23,((uint64_t)1<<32)|4,8);st(request+31,((uint64_t)1<<32),8);
 call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==2);
 frame(174,63,1,4);st(request+23,((uint64_t)1<<32)|1,8);
 call();assert(reply[4]==161&&rd(reply+7,4)==5); // unregistered image, no RAM reset
 frame(178,6,1,0);call();assert(reply[4]==161&&rd(reply+7,4)==1);
 frame(100,7,1,0);call();assert(reply[4]==161&&rd(reply+7,4)==1);
 frame(178,513,1,0);call();assert(reply[4]==161&&rd(reply+7,4)==1);
 assert(NS(session_handle)(1)==linux&&NS(session_fid_count)(1)==1);
 puts("O10 platform mailbox, stale identity, journal replay and fid revocation PASS");
 return 0;
}
"""

class O10PlatformTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                         "native platform harness requires Linux x86_64")
    def test_real_platform_dispatch_and_fid_revocation(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang = shutil.which("clang")
        self.assertTrue(compiler.is_file(), "native O10 qualification requires an existing compiler")
        self.assertIsNotNone(clang, "native O10 qualification requires clang")
        import runpy
        sources = runpy.run_path(str(ROOT / "scripts/build_okernel_unified_world.py"))["SOURCES"]
        with tempfile.TemporaryDirectory(prefix="o10-platform-") as directory:
            output = Path(directory)
            unified = output / "unified_world.oc"
            unified.write_text((ROOT / sources[0]).read_text() + WRAPPER)
            profile = output / "profile.oc"
            profile.write_text("module runtime::aarch64::kernel_world_profile;\n"
                "pub const PERSISTENT: u64 = 1;\npub const BACKING_BASE: usize = 0x7000_0000;\n"
                "pub const BACKING_BYTES: usize = 1_073_741_824;\n"
                "pub const NETWORK: u64 = 1;\npub const NAMESPACE: u64 = 1;\n")
            (output / "harness.c").write_text(HARNESS)
            commands = [
                [str(compiler), str(profile), str(unified), *(str(ROOT / name) for name in sources[1:]),
                 "--target", "x86_64-unknown-none", "--emit", "obj", "--function-sections", "-o", str(output / "native.o")],
                [clang, "-O2", "-no-pie", "-Wl,--gc-sections", "-Ulinux", str(output / "harness.c"),
                 str(output / "native.o"), "-o", str(output / "selftest")],
                [str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, " ".join(command) + "\n" + result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
