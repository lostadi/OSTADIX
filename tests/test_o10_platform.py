"""Execute the real O10 mailbox/platform native graph on Linux.

Scope: framing, journal dispatch, domain identity and real namespace fid
revocation. The lifecycle test additionally runs the real private-RAM zero/copy
loop with explicitly modeled architectural reset return/register IO. Other
architecture/device assembly entry points are fail-closed sentinels;
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
pub unsafe fn o10_platform_test_gic_init() -> u64 { return gic_init(); }
pub unsafe fn o10_platform_test_wire_init() -> u64 { return plan9_wire_init(1); }
pub unsafe fn o10_platform_test_generations(domain: u64, lease: u64) -> void {
    O10_DOMAIN_GENERATION[1] = domain; O10_LEASE_GENERATION = lease;
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


LEGACY_HARNESS = r"""

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

extern uint64_t UW(o10_platform_test_gic_init)(void),UW(o10_platform_test_wire_init)(void);
extern void UW(o10_platform_test_generations)(uint64_t,uint64_t);
static uint64_t lrs[2][4],vmcr[2],hcr[2],reset_calls=0,ticks=0;
uint64_t uw_domain_reset(uint64_t domain,uint64_t pc,uint64_t x0,uint64_t pstate){
 assert(domain==1&&pc==0x40100000&&x0==0x40000000&&pstate==0x3c5);
 reset_calls++;return 1;
}
uint64_t uw_counter_read(void){return ++ticks;}
void uw_memory_barrier(void){__sync_synchronize();}
uint64_t uw_vgic_lr_count(void){return 4;}
uint64_t uw_vgic_lr_read(uint64_t domain,uint64_t index){assert(domain<2&&index<4);return lrs[domain][index];}
void uw_vgic_lr_write(uint64_t domain,uint64_t index,uint64_t value){assert(domain<2&&index<4);lrs[domain][index]=value;}
uint64_t uw_vgic_vmcr_read(uint64_t domain){assert(domain<2);return vmcr[domain];}
void uw_vgic_vmcr_write(uint64_t domain,uint64_t value){assert(domain<2);vmcr[domain]=value;}
uint64_t uw_vgic_hcr_read(uint64_t domain){assert(domain<2);return hcr[domain];}
void uw_vgic_hcr_write(uint64_t domain,uint64_t value){assert(domain<2);hcr[domain]=value;}
uint64_t uw_vgic_running_priority(uint64_t domain){assert(domain<2);return 0xff;}
#define SENTINEL(name) uint64_t name(void){fprintf(stderr,"off-corpus architecture: "#name"\n");abort();}
SENTINEL(uw_current_domain)
SENTINEL(uw_serial_putc)
SENTINEL(uw_halt)
static uint64_t legacy(unsigned operation,uint64_t expected){
 st((void*)0x6d000070,++mailbox_seq,8);st((void*)0x6d000078,operation,8);
 uint64_t live=UW(o10_platform_test_mailbox)();
 assert(rd((void*)0x6d000080,8)==mailbox_seq&&rd((void*)0x6d000088,8)==expected);return live;
}
static void* fixed(uintptr_t address,size_t size){
 void*p=mmap((void*)address,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
 assert(p==(void*)address);return p;
}
static void zeros(const unsigned char*p,size_t n){assert(n%8==0);for(size_t i=0;i<n;i+=8)assert(rd(p+i,8)==0);}
static void images(const unsigned char*ram){
 assert(rd(ram,8)==0x01020304edfe0dd0ULL);assert(rd(ram+0x100000,8)==0x1122334455667788ULL);
 zeros(ram+8,0x100000-8);zeros(ram+0x100008,0x20000000-0x100008);
}

int main(int argc,char**argv){
 assert(argc==2);unsigned scenario=(unsigned)strtoul(argv[1],NULL,10);
 fixed(0x6d000000,0x100000);unsigned char*ram=fixed(0xb0000000,0x20000000);
 unsigned char*kernel=fixed(0xd0000000,0x1000),*dtb=fixed(0xd1000000,0x1000);
 unsigned char*survivor=fixed(0x48000000,4096);memset(survivor,0x5a,4096);
 st(kernel,0x1122334455667788ULL,8);st(dtb,0x01020304edfe0dd0ULL,8);
 assert(mprotect(kernel,0x1000,PROT_READ)==0&&mprotect(dtb,0x1000,PROT_READ)==0);
 st((void*)0x6d000000,1,8);st((void*)0x6d000090,8,8);st((void*)0x6d000098,8,8);
 void*volume=mmap(NULL,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 assert(NS(init)((uintptr_t)volume,16777216,1)==1);uint64_t linux=NS(session_init)(1,1);assert(linux);attach(linux);
 assert(UW(o10_platform_test_init)()==1&&UW(o10_platform_test_gic_init)()==1);
 assert(UW(o10_platform_test_wire_init)()==1);
 uint64_t plan9=NS(session_handle)(4);assert(plan9);attach(plan9);

 // M2 legacy operations are explicit errors both before and after claiming.
 assert(legacy(1,9)==3&&legacy(2,9)==3&&reset_calls==0);
 frame(164,39,0,1);st(request+23,1,8);call();assert(reply[4]==165);
 assert(legacy(1,9)==3&&legacy(2,9)==3&&reset_calls==0);
 if(scenario==1){
  UW(o10_platform_test_generations)(1,UINT32_MAX);st(ram+0x1000,0xaabbccdd,8);
  frame(172,36,1,2);st(request+23,(1ull<<32)|1,8);
  assert(call()==3&&reply[4]==161&&rd(reply+7,4)==8);
  assert(rd(ram+0x1000,8)==0xaabbccdd&&reset_calls==0&&NS(session_handle)(4)==plan9);
 }else if(scenario==2){
  UW(o10_platform_test_generations)(UINT32_MAX,1);st(ram+0x1000,0xaabbccdd,8);
  frame(172,36,1,2);st(request+23,((uint64_t)UINT32_MAX<<32)|1,8);assert(call()==1&&reply[4]==173);
  frame(174,63,1,3);st(request+23,((uint64_t)UINT32_MAX<<32)|1,8);st(request+47,1,8);st(request+55,2,8);
  assert(call()==1&&reply[4]==161&&rd(reply+7,4)==8);
  assert(rd(ram+0x1000,8)==0xaabbccdd&&reset_calls==0);
 }else{
  assert(scenario==0);
  frame(172,36,1,2);st(request+23,(1ull<<32)|1,8);assert(call()==1&&reply[4]==173);
  memset(ram,0x3c,0x20000000);frame(174,63,1,3);st(request+23,(1ull<<32)|1,8);
  st(request+47,1,8);st(request+55,2,8);assert(call()==3&&reply[4]==175&&rd(reply+7,8)==((2ull<<32)|1));
  assert(reset_calls==1);images(ram);assert(stat_session(plan9)==107);
  frame(178,31,1,0);st(request+23,(1ull<<32)|1,8);call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==2);
  frame(184,39,1,4);st(request+23,(1ull<<32)|4,8);st(request+31,2ull<<32,8);
  call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==2);
  frame(184,39,1,5);st(request+23,(2ull<<32)|4,8);st(request+31,1ull<<32,8);
  call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==2);
  frame(184,39,1,6);st(request+23,(2ull<<32)|4,8);st(request+31,2ull<<32,8);
  call();assert(reply[4]==185);
 }
 assert(NS(session_handle)(1)==linux&&NS(session_fid_count)(1)==1&&stat_session(linux)==125);
 for(unsigned i=0;i<4096;i++)assert(survivor[i]==0x5a);
 puts("O10 Plan9 generation/capacity/copy and explicit legacy retirement PASS");return 0;
}

"""

class O10PlatformTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                         "native platform harness requires Linux x86_64")
    def test_real_platform_dispatch_and_fid_revocation(self):
        self.run_native(HARNESS, [None])

    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                         "native platform harness requires Linux x86_64")
    def test_o10_restore_and_capacity_after_legacy_retirement(self):
        # These are host models of reset-result/register IO; real EL2 context
        # clearing remains a QEMU/hardware gate. The RAM zero/copy loop is real.
        self.run_native(LEGACY_HARNESS, ["0", "1", "2"])

    def run_native(self, harness, scenarios):
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
                "pub const NETWORK: u64 = 1;\npub const NAMESPACE: u64 = 1;\n"
                "pub const O10_QUALIFICATION: u64 = 0;\n")
            (output / "harness.c").write_text(harness)
            commands = [
                [str(compiler), str(profile), str(unified), *(str(ROOT / name) for name in sources[1:]),
                 "--target", "x86_64-unknown-none", "--emit", "obj", "--function-sections", "-o", str(output / "native.o")],
                [clang, "-O2", "-no-pie", "-Wl,--gc-sections", "-Ulinux", str(output / "harness.c"),
                 str(output / "native.o"), "-o", str(output / "selftest")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, " ".join(command) + "\n" + result.stdout + result.stderr)
            for scenario in scenarios:
                command = [str(output / "selftest")] + ([scenario] if scenario is not None else [])
                result = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, " ".join(command) + "\n" + result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
