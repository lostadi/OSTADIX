"""Execute isolated Linux reset helpers; no guest-boot/filesystem claim."""
import json
import os
from pathlib import Path
import platform
import runpy
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
#define B(n) _O_runtime__aarch64__kernel_world_virtio__##n
#define N(n) _O_runtime__aarch64__kernel_world_net__##n
#define P(n) _O_runtime__aarch64__kernel_world_9p__##n
#define M(n) _O_runtime__aarch64__kernel_world_monitor__##n
#define S(n) _O_runtime__common__namespace_store__##n
#define I(n) _O_runtime__aarch64__linux_domain_images__##n
extern uint64_t B(init)(uint64_t,uint64_t,uint64_t),B(configure_backing)(uintptr_t,uintptr_t,uint64_t);
extern uint64_t B(mmio_write)(uint64_t,uint64_t),B(mmio_read)(uint64_t),B(poll)(void),B(pending)(void),B(arm_hold_next_read)(uint64_t);
extern uint64_t B(generation)(void),N(generation)(void),P(generation)(void);
extern uint64_t N(init)(uint64_t,uint64_t,uint64_t),P(init)(uint64_t,uint64_t,uint64_t);
extern uint64_t N(mmio_write)(uint64_t,uint64_t),N(poll)(void);
extern uint64_t P(mmio_write)(uint64_t,uint64_t),P(poll)(void),P(bound)(void),P(diagnostic)(void),P(bind_current)(uint64_t,uint64_t,uint64_t);
extern uint64_t M(kw_linux_detach)(uint64_t,uint64_t,uint64_t),M(kw_linux_provision)(uint64_t,uint64_t,uint64_t),M(kw_linux_activate)(void);
extern void M(test_admit)(void);
extern uintptr_t kw_guest_address(uint64_t,uint64_t);
extern uint64_t S(init)(uintptr_t,size_t,uint64_t),S(session_init)(uint64_t,uint64_t),S(session_handle)(uint64_t),S(session_fid_count)(uint64_t);
extern uint64_t S(session_claim)(uint64_t,uint64_t,uint64_t);
extern size_t S(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
extern uint64_t I(register)(uintptr_t,size_t,uintptr_t,size_t,uintptr_t,size_t),I(reload)(void);
static unsigned irq[4];static uint64_t linux_session,plan9_session;
void kw_memory_barrier(void){__sync_synchronize();}
void kw_irq_level(uint64_t n){assert(n<=1);irq[0]=(unsigned)n;}
void kw_net_irq_level(uint64_t n){assert(n<=1);irq[1]=(unsigned)n;}
void kw_9p_irq_level(uint64_t n){assert(n<=1);irq[2]=(unsigned)n;}
void kw_uart_irq_level(uint64_t n){assert(n<=1);irq[3]=(unsigned)n;}
static void *map(uintptr_t base,size_t bytes){
 void*p=mmap((void*)base,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
 assert(p==(void*)base);return p;
}
static void st(void *p,uint64_t v,unsigned n){unsigned char*q=p;for(unsigned i=0;i<n;i++)q[i]=(unsigned char)(v>>(8*i));}
static void attach(uint64_t h){
 unsigned char q[64]={0},a[512]={0};
 st(q,19,4);q[4]=100;st(q+7,512,4);st(q+11,6,2);memcpy(q+13,"9P2000",6);
 assert(S(handle)(h,q,19,a,512)==19&&a[4]==101);
 memset(q,0,sizeof q);st(q,20,4);q[4]=104;st(q+7,1,4);st(q+11,UINT32_MAX,4);st(q+15,1,2);q[17]='u';
 assert(S(handle)(h,q,20,a,512)==20&&a[4]==105);
}
static unsigned statfid(uint64_t h){
 unsigned char q[11]={11,0,0,0,124},a[512];st(q+7,1,4);
 assert(S(handle)(h,q,11,a,512)!=0);return a[4];
}
static void survivors(void){
 assert(S(session_handle)(4)==plan9_session&&S(session_fid_count)(4)==1&&statfid(plan9_session)==125);
 for(unsigned i=0;i<4096;i++){assert(((unsigned char*)0xb0000000)[i]==0xa9);assert(((unsigned char*)0x70000000)[i]==0xdd);}
}
static void w(uint64_t off,uint64_t value){assert(B(mmio_write)(off,value)==1);}
static void held_read(void){
 unsigned char *m=(void*)0x48010000;memset(m,0,65536);
 w(112,1);w(112,3);w(36,0);w(32,B(mmio_read)(16));w(36,1);w(32,1);w(112,11);
 w(48,0);w(56,32);w(128,0x40010000);w(132,0);w(144,0x40011000);w(148,0);w(160,0x40012000);w(164,0);w(68,1);w(112,15);
 st(m,0x40013000,8);st(m+8,16,4);st(m+12,1,2);st(m+14,1,2);
 st(m+16,0x40014000,8);st(m+24,512,4);st(m+28,3,2);st(m+30,2,2);
 st(m+32,0x40015000,8);st(m+40,1,4);st(m+44,2,2);
 m[0x5000]=255;st(m+0x1002,1,2);
 assert(B(poll)()==1&&m[0x5000]==0);w(100,1);
 m[0x5000]=255;st(m+0x1006,0,2);st(m+0x1002,2,2);
 assert(B(arm_hold_next_read)(1)==1&&B(poll)()==2&&B(pending)()==1&&m[0x5000]==255);
}
int main(int argc,char**argv){
 assert(argc==2);unsigned which=(unsigned)strtoul(argv[1],0,10);
 unsigned char *guest=map(0x48000000,0x20000000);
 map(0xb0000000,4096);map(0x70000000,4096);
 unsigned char*k=map(0xd2000000,4096),*d=map(0xe2000000,4096),*a=map(0xda000000,4096);
 memset((void*)0xb0000000,0xa9,4096);memset((void*)0x70000000,0xdd,4096);
 for(unsigned i=0;i<4096;i++){k[i]=(unsigned char)(i^0x31);d[i]=(unsigned char)(i^0x57);a[i]=(unsigned char)(i^0x83);}
 if(which==3){
  assert(I(register)(0xd2000000,0x7e00001,0xe2000000,1,0xda000000,1)==8);
  assert(I(register)(0xd2000000,1,0xe2000000,0x10001,0xda000000,1)==8);
  assert(I(register)(0xd2000000,1,0xe2000000,1,0xda000000,0x8000001)==8);
  assert(I(register)(UINTPTR_MAX,1,0xe2000000,1,0xda000000,1)==6);
  assert(I(register)(0xd2000000,0x7e00000,0xe2000000,0x10000,0xda000000,0x8000000)==0);
  assert(I(register)(0xd2000000,1,0xe2000000,1,0xda000000,1)==12);
  puts("Linux immutable image exact boundaries: PASS");return 0;
 }
 void*volume=mmap(0,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 assert(S(init)((uintptr_t)volume,16777216,1)==1);
 assert(P(init)(0x40000000,0x20000000,1)==1);linux_session=S(session_handle)(1);attach(linux_session);
 plan9_session=S(session_init)(4,1);attach(plan9_session);
 assert(B(configure_backing)(0x70000000,4096,1)==1);
 assert(B(init)(0x40000000,0x20000000,1)==1&&N(init)(0x40000000,0x20000000,1)==1);
 M(test_admit)();assert(kw_guest_address(0x40000000,1)==0x48000000);
 if(which==2){
  uint64_t fresh=S(session_claim)(1,2,linux_session);assert(fresh);attach(fresh);
  assert(M(kw_linux_detach)(1,1,1)==0);assert(kw_guest_address(0x40000000,1)==0x48000000);
  assert(S(session_handle)(1)==fresh&&statfid(fresh)==125);survivors();
  assert(B(generation)()==1&&N(generation)()==1&&P(generation)()==1);
  puts("Stale Linux frontend cannot detach rebound session: PASS");return 0;
 }
 memset(guest,0xcc,0x20000000);
 assert(I(register)(0xd2000000,37,0xe2000000,19,0xda000000,73)==0);
 assert(I(reload)()==12&&guest[0]==0xcc&&guest[0x1fffffff]==0xcc);
 held_read();unsigned char saved[65536];memcpy(saved,(void*)0x48010000,sizeof saved);
 assert(M(kw_linux_detach)(0,1,1)==0&&B(pending)()==1&&kw_guest_address(0x40000000,1)!=0);
 assert(M(kw_linux_detach)(1,1,1)==1&&kw_guest_address(0x40000000,1)==0);
 assert(!memcmp(saved,(void*)0x48010000,sizeof saved));assert(B(pending)()==0);
 assert(S(session_handle)(1)==0&&S(session_fid_count)(1)==0&&statfid(linux_session)==107);survivors();
 assert(B(mmio_write)(112,1)==0&&N(mmio_write)(112,1)==0&&P(mmio_write)(112,1)==0);
 assert(B(poll)()==0&&N(poll)()==0&&P(poll)()==0);
 assert(I(reload)()==0);
 for(size_t i=0;i<0x20000000;i++){
  unsigned char expected=0;
  if(i<37)expected=k[i];
  if(i>=0x7e00000&&i<0x7e00000+19)expected=d[i-0x7e00000];
  if(i>=0x8000000&&i<0x8000000+73)expected=a[i-0x8000000];
  assert(guest[i]==expected);
 }
 survivors();
 assert(M(kw_linux_provision)(1ull<<32,2,2)==0);
 assert(B(generation)()==1&&N(generation)()==1&&P(generation)()==1&&guest[0]==k[0]);
 assert(M(kw_linux_provision)(2,2,2)==1&&S(session_handle)(1)==0&&P(bound)()==0);
 assert(P(mmio_write)(112,15)==0&&P(diagnostic)()==32&&S(session_handle)(1)==0);
 assert(P(mmio_write)(112,0)==1&&S(session_handle)(1)==0);assert(M(kw_linux_activate)()==0);
 assert(P(bind_current)(2,plan9_session,2)==0);survivors();
 uint64_t fresh=S(session_init)(1,2);assert(fresh&&P(bind_current)(1,fresh,2)==0&&P(bind_current)(2,fresh,2)==1);
 attach(fresh);assert(M(kw_linux_activate)()==1&&kw_guest_address(0x40000000,1)==0x48000000);
 assert(statfid(linux_session)==107&&statfid(fresh)==125);survivors();
 assert(B(generation)()==2&&N(generation)()==2&&P(generation)()==2);
 assert(B(poll)()==0&&N(poll)()==0&&P(poll)()==0);
 if(which==1){
  assert(M(kw_linux_detach)(2,2,2)==1);
  assert(M(kw_linux_provision)(0xffffffff,0xffffffff,0xffffffff)==1);
  fresh=S(session_init)(1,3);assert(P(bind_current)(0xffffffff,fresh,3)==1);assert(M(kw_linux_activate)()==1);
  assert(M(kw_linux_detach)(0xffffffff,0xffffffff,0xffffffff)==1);
  assert(M(kw_linux_provision)(1ull<<32,1ull<<32,1ull<<32)==0);
  assert(B(generation)()==0xffffffff&&N(generation)()==0xffffffff&&P(generation)()==0xffffffff);
  survivors();
 }
 puts("Linux-only detach, immutable reload, unbound provisioning and survivor preservation: PASS");return 0;
}
"""


class LinuxResetNativeTests(unittest.TestCase):
    @unittest.skipUnless(platform.system()=="Linux" and platform.machine()=="x86_64",
                         "native mapped-memory fixture requires Linux x86_64")
    def test_real_reset_helpers_and_image_boundaries(self):
        compiler=Path(os.environ.get("OCOREC_BIN",ROOT/"target/debug/ocorec"))
        clang=shutil.which("clang")
        self.assertTrue(compiler.is_file(),"existing compiler required")
        self.assertIsNotNone(clang)
        sources=runpy.run_path(str(ROOT/"scripts/build_okernel_unified_world.py"))["SOURCES"][1:]
        sources=tuple(n for n in sources if n!="ocore/runtime/aarch64/linux_domain_images.oc")
        with tempfile.TemporaryDirectory(prefix="o10-linux-reset-") as directory:
            out=Path(directory)
            monitor_name="ocore/runtime/aarch64/kernel_world_monitor.oc"
            monitor=out/"monitor.oc"
            monitor.write_text((ROOT/monitor_name).read_text()+"\npub unsafe fn test_admit() -> void { RAM_LIVE = 1; }\n")
            profile=out/"profile.oc"
            profile.write_text("module runtime::aarch64::kernel_world_profile;\n"
                "pub const PERSISTENT: u64 = 1;\npub const NETWORK: u64 = 1;\npub const NAMESPACE: u64 = 1;\n"
                "pub const BACKING_BASE: usize = 0x7000_0000;\npub const BACKING_BYTES: usize = 4096;\n")
            inputs=[str(profile),*(str(monitor if n==monitor_name else ROOT/n) for n in sources),
                    str(ROOT/"ocore/runtime/aarch64/linux_domain_images.oc")]
            for target,emit,name in [("aarch64-unknown-none","mir","arm.mir"),("x86_64-unknown-none","obj","native.o")]:
                result=subprocess.run([str(compiler),*inputs,"--target",target,"--emit",emit,"--function-sections","-o",str(out/name)],
                                      capture_output=True,text=True,timeout=120)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            (out/"harness.c").write_text(HARNESS)
            imports=subprocess.run(["nm","-u",str(out/"native.o")],check=True,capture_output=True,text=True).stdout
            modeled={"kw_memory_barrier","kw_irq_level","kw_net_irq_level","kw_9p_irq_level","kw_uart_irq_level"}
            names={line.split()[-1] for line in imports.splitlines() if line.split()}
            (out/"sentinels.c").write_text("#include <stdio.h>\n#include <stdlib.h>\n"+"\n".join(
                'void '+n+'(void){fputs("off-corpus architecture: '+n+'\\n",stderr);abort();}'
                for n in sorted(names) if n.startswith(("kw_","uw_")) and n not in modeled))
            command=[clang,"-O2","-no-pie","-Wl,--gc-sections",str(out/"harness.c"),str(out/"sentinels.c"),
                     str(out/"native.o"),"-o",str(out/"selftest")]
            result=subprocess.run(command,capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            for scenario in range(4):
                result=subprocess.run([str(out/"selftest"),str(scenario)],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,f"scenario={scenario}: "+result.stdout+result.stderr)
                self.assertIn("PASS",result.stdout)


if __name__=="__main__":
    unittest.main()
