"""Execute O10 Linux lifecycle using real native state and RAM-copy helpers.

Architecture reset/register operations are explicit host models. This does
not qualify AArch64 reset, Linux boot or interrupted filesystem recovery.
"""
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
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
extern uint64_t P(can_provision)(uint64_t),P(provision)(uint64_t,uint64_t,uint64_t);
extern uint64_t M(kw_linux_detach)(uint64_t,uint64_t,uint64_t),M(kw_linux_provision)(uint64_t,uint64_t,uint64_t),M(kw_linux_activate)(void);
extern void M(test_admit)(void);
extern uintptr_t kw_guest_address(uint64_t,uint64_t);
extern uint64_t S(init)(uintptr_t,size_t,uint64_t),S(session_init)(uint64_t,uint64_t),S(session_handle)(uint64_t),S(session_fid_count)(uint64_t);
extern uint64_t S(session_claim)(uint64_t,uint64_t,uint64_t);
extern size_t S(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
extern uint64_t I(register)(uintptr_t,size_t,uintptr_t,size_t,uintptr_t,size_t),I(reload)(void);
static unsigned irq[4];static uint64_t linux_session,plan9_session;
void kw_memory_barrier(void){__sync_synchronize();}




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

#define W(n) _O_runtime__aarch64__unified_world__##n
extern uint64_t W(test_init)(void),W(test_mailbox)(void),W(test_plan9_input)(void),W(test_linux_input)(void);
extern void W(test_inputs)(void),W(test_generation)(uint64_t);
static uint64_t ticks,reset_calls,vmcr[2],hcr[2],lrs[2][4];
static unsigned char *request=(void*)0x6d0a0000,*reply=(void*)0x6d0a0200;
static uint64_t sequence,mailbox_seq;
uint64_t uw_domain_reset(uint64_t domain,uint64_t pc,uint64_t x0,uint64_t pstate){
 assert(domain==0&&pc==0x40000000&&x0==0x47e00000&&pstate==0x3c5);reset_calls++;return 1;
}
uint64_t uw_counter_read(void){return ++ticks;}
void uw_memory_barrier(void){__sync_synchronize();}
void uw_serial_putc(uint64_t byte){assert(byte<256);}
uint64_t uw_vgic_lr_count(void){return 4;}
uint64_t uw_vgic_lr_read(uint64_t domain,uint64_t index){assert(domain<2&&index<4);return lrs[domain][index];}
void uw_vgic_lr_write(uint64_t domain,uint64_t index,uint64_t value){assert(domain<2&&index<4);lrs[domain][index]=value;}
uint64_t uw_vgic_vmcr_read(uint64_t domain){assert(domain<2);return vmcr[domain];}
void uw_vgic_vmcr_write(uint64_t domain,uint64_t value){assert(domain<2);vmcr[domain]=value;}
uint64_t uw_vgic_hcr_read(uint64_t domain){assert(domain<2);return hcr[domain];}
void uw_vgic_hcr_write(uint64_t domain,uint64_t value){assert(domain<2);hcr[domain]=value;}
static uint64_t rd(const void*p,unsigned n){const unsigned char*q=p;uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)q[i]<<(8*i);return v;}
static void frame(unsigned type,size_t length,int mutation){
 memset(request,0,512);st(request,length,4);request[4]=(unsigned char)type;st(request+5,91,2);
 st(request+7,sequence?1:0,8);st(request+15,mutation?++sequence:0,8);
}
static uint64_t call(void){
 st((void*)0x6d000070,++mailbox_seq,8);st((void*)0x6d000078,10,8);
 uint64_t live=W(test_mailbox)();assert(rd((void*)0x6d000080,8)==mailbox_seq&&rd((void*)0x6d000088,8)==1);return live;
}
static void state(uint64_t handle,unsigned expected){
 frame(178,31,0);st(request+23,handle,8);call();assert(reply[4]==179&&reply[16]==expected);
}
int main(int argc,char**argv){
 assert(argc==2);unsigned scenario=(unsigned)strtoul(argv[1],0,10);
 unsigned char *guest=map(0x48000000,0x20000000);map(0xb0000000,4096);map(0x70000000,4096);map(0x6d000000,0x100000);
 unsigned char*k=map(0xd2000000,4096),*d=map(0xe2000000,4096),*a=map(0xda000000,4096);
 memset(guest,0xcc,0x20000000);memset((void*)0xb0000000,0xa9,4096);memset((void*)0x70000000,0xdd,4096);
 for(unsigned i=0;i<4096;i++){k[i]=(unsigned char)(i^0x31);d[i]=(unsigned char)(i^0x57);a[i]=(unsigned char)(i^0x83);}
 assert(I(register)(0xd2000000,37,0xe2000000,19,0xda000000,73)==0);
 void*volume=mmap(0,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 assert(S(init)((uintptr_t)volume,16777216,1)==1);
 uint64_t namespace_generation=scenario==3?UINT64_C(0x7bed31e65e6f3ac6):scenario==4?UINT64_MAX-1:scenario==5?UINT64_MAX:scenario==6?UINT32_MAX:1;
 assert(P(init)(0x40000000,0x20000000,namespace_generation)==1);linux_session=S(session_handle)(1);attach(linux_session);
 plan9_session=S(session_init)(4,1);attach(plan9_session);
 assert(B(configure_backing)(0x70000000,4096,1)==1);
 assert(B(init)(0x40000000,0x20000000,1)==1&&N(init)(0x40000000,0x20000000,1)==1);M(test_admit)();
 assert(W(test_init)()==1);W(test_inputs)();
 hcr[1]=0x45;vmcr[1]=0x6789;lrs[1][0]=0xabc;
 for(unsigned op=1;op<=2;op++){
  st((void*)0x6d000070,++mailbox_seq,8);st((void*)0x6d000078,op,8);
  assert(W(test_mailbox)()==3&&rd((void*)0x6d000088,8)==9);
  assert(S(session_handle)(1)==linux_session&&S(session_handle)(4)==plan9_session&&reset_calls==0);
 }
 frame(164,39,1);st(request+23,1,8);call();assert(reply[4]==165);
 uint64_t handle=1ull<<32;
 if(scenario==2){W(test_generation)(0xffffffff);handle=0xffffffffull<<32;}
 if(scenario==1){
  frame(196,33,1);st(request+23,handle,8);st(request+31,1,2);
  assert(call()==2&&reply[4]==197);state(handle,4);survivors();
 }
 frame(172,36,1);st(request+23,handle,8);assert(call()==2&&reply[4]==173);
 assert(rd(reply+19,4)==(scenario==1?0:1)&&rd(reply+23,4)==(scenario==1?0:1));
 state(handle,5);assert(S(session_handle)(1)==0&&statfid(linux_session)==107);survivors();
 assert(W(test_plan9_input)()==1&&W(test_linux_input)()==0&&kw_guest_address(0x40000000,1)==0);
 assert(P(can_provision)(namespace_generation)==0&&P(can_provision)(0)==0);
 assert(P(provision)(0x40000000,0x20000000,namespace_generation)==0&&P(generation)()==namespace_generation);
 frame(174,63,1);st(request+23,handle,8);st(request+47,99,8);st(request+55,4,8);
 call();assert(reply[4]==161&&rd(reply+7,4)==5&&reset_calls==0&&guest[0]==0xcc);
 frame(174,63,1);st(request+23,handle,8);memset(request+31,0x77,16);st(request+47,3,8);st(request+55,4,8);
 if(scenario==2||scenario==5){
  call();assert(reply[4]==161&&rd(reply+7,4)==8&&reset_calls==0&&guest[0]==0xcc);
  assert(P(generation)()==namespace_generation&&B(generation)()==1&&N(generation)()==1);survivors();
  puts("Linux lifecycle generation capacity is nondestructive: PASS");return 0;
 }
 unsigned char retransmit[63],saved[15];memcpy(retransmit,request,63);
 assert(call()==3&&reply[4]==175&&rd(reply+7,8)==(2ull<<32)&&reset_calls==1);memcpy(saved,reply,15);
 assert(P(generation)()==namespace_generation+1&&B(generation)()==2&&N(generation)()==2);
 for(size_t i=0;i<0x20000000;i++){
  unsigned char expected=0;
  if(i<37)expected=k[i];
  if(i>=0x7e00000&&i<0x7e00000+19)expected=d[i-0x7e00000];
  if(i>=0x8000000&&i<0x8000000+73)expected=a[i-0x8000000];
  assert(guest[i]==expected);
 }
 assert(hcr[1]==0x45&&vmcr[1]==0x6789&&lrs[1][0]==0xabc);survivors();state(2ull<<32,3);
 memcpy(request,retransmit,63);call();assert(!memcmp(reply,saved,15)&&reset_calls==1);
 state(2ull<<32,3);assert(kw_guest_address(0x40000000,1)==0);
 frame(178,31,0);st(request+23,handle,8);call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==2);
 frame(184,39,1);st(request+23,(1ull<<32)|1,8);st(request+31,2ull<<32,8);
 call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==2);
 frame(184,39,1);st(request+23,(2ull<<32)|1,8);st(request+31,1ull<<32,8);
 call();assert(reply[4]==161&&rd(reply+7,4)==5&&rd(reply+11,8)==2);
 frame(184,39,1);st(request+23,(2ull<<32)|1,8);st(request+31,2ull<<32,8);
 call();assert(reply[4]==185&&kw_guest_address(0x40000000,1)==0x48000000);state(2ull<<32,2);
 uint64_t fresh=S(session_handle)(1);assert(fresh&&fresh!=linux_session);attach(fresh);
 assert(statfid(fresh)==125&&statfid(linux_session)==107);survivors();assert(W(test_plan9_input)()==1);
 assert(reset_calls==1&&hcr[1]==0x45&&vmcr[1]==0x6789&&lrs[1][0]==0xabc);
 if(scenario==4){
  // The existing full-u64 transport epoch may reach MAX once; a later restore
  // must refuse before zeroing RAM, resetting state or wrapping the transport.
  guest[4096]=0x5a;
  frame(172,36,1);st(request+23,2ull<<32,8);call();assert(reply[4]==173);
  frame(174,63,1);st(request+23,2ull<<32,8);st(request+47,3,8);st(request+55,4,8);
  call();assert(reply[4]==161&&rd(reply+7,4)==8&&reset_calls==1&&guest[4096]==0x5a);
  assert(P(generation)()==UINT64_MAX&&B(generation)()==2&&N(generation)()==2);survivors();
 }
 puts("O10 Linux withdraw/fault/restore/bind exact-once + survivor preservation: PASS");return 0;
}

"""
WRAPPER = r"""

pub unsafe fn test_init() -> u64 { LIVE[0]=1; LIVE[1]=1; return gic_init(); }
pub unsafe fn test_mailbox() -> u64 { native_control(); return LIVE[0] | (LIVE[1]<<1); }
pub unsafe fn test_inputs() -> void { LINUX_INPUT_COUNT=3; LINUX_INPUT[0]=0x55; RX_COUNT=7; RX[0]=0xa7; }
pub unsafe fn test_plan9_input() -> u64 { return (RX_COUNT==7 && RX[0]==0xa7) as u64; }
pub unsafe fn test_linux_input() -> u64 { return LINUX_INPUT_COUNT as u64; }
pub unsafe fn test_generation(value:u64) -> void { O10_DOMAIN_GENERATION[0]=value; }

"""

class LinuxRestartNativeTests(unittest.TestCase):
    @unittest.skipUnless(platform.system()=="Linux" and platform.machine()=="x86_64",
                         "mapped-memory fixture requires Linux x86_64")
    def test_real_linux_o10_lifecycle_and_survivors(self):
        compiler=Path(os.environ.get("OCOREC_BIN",ROOT/"target/debug/ocorec"))
        clang=shutil.which("clang");self.assertTrue(compiler.is_file());self.assertIsNotNone(clang)
        sources=runpy.run_path(str(ROOT/"scripts/build_okernel_unified_world.py"))["SOURCES"]
        with tempfile.TemporaryDirectory(prefix="o10-linux-lifecycle-") as directory:
            out=Path(directory)
            profile=out/"profile.oc";profile.write_text("module runtime::aarch64::kernel_world_profile;\n"
                "pub const PERSISTENT:u64=1;\npub const NETWORK:u64=1;\npub const NAMESPACE:u64=1;\n"
                "pub const BACKING_BASE:usize=0x70000000;\npub const BACKING_BYTES:usize=4096;\n"
                "pub const O10_QUALIFICATION:u64=1;\n")
            world=out/"world.oc";world.write_text((ROOT/sources[0]).read_text()+WRAPPER)
            monitor_name="ocore/runtime/aarch64/kernel_world_monitor.oc"
            monitor=out/"monitor.oc";monitor.write_text((ROOT/monitor_name).read_text()+
                "\npub unsafe fn test_admit() -> void { RAM_LIVE=1; }\n")
            inputs=[str(profile),str(world),*(str(monitor if n==monitor_name else ROOT/n) for n in sources[1:])]
            for target,emit,name in [("aarch64-unknown-none","mir","arm.mir"),("x86_64-unknown-none","obj","native.o")]:
                p=subprocess.run([str(compiler),*inputs,"--target",target,"--emit",emit,"--function-sections","-o",str(out/name)],
                                 capture_output=True,text=True,timeout=120)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            (out/"harness.c").write_text(HARNESS)
            imports=subprocess.run(["nm","-u",str(out/"native.o")],check=True,capture_output=True,text=True).stdout
            modeled={"kw_memory_barrier","uw_domain_reset","uw_counter_read","uw_memory_barrier","uw_serial_putc",
                     "uw_vgic_lr_count","uw_vgic_lr_read","uw_vgic_lr_write","uw_vgic_vmcr_read","uw_vgic_vmcr_write",
                     "uw_vgic_hcr_read","uw_vgic_hcr_write"}
            names={line.split()[-1] for line in imports.splitlines() if line.split()}
            (out/"sentinels.c").write_text("#include <stdio.h>\n#include <stdlib.h>\n"+"\n".join(
                'void '+n+'(void){fputs("off-corpus architecture: '+n+'\\n",stderr);abort();}'
                for n in sorted(names) if n.startswith(("kw_","uw_")) and n not in modeled))
            p=subprocess.run([clang,"-O2","-no-pie","-Wl,--gc-sections",str(out/"harness.c"),str(out/"sentinels.c"),
                              str(out/"native.o"),"-o",str(out/"selftest")],capture_output=True,text=True,timeout=120)
            self.assertEqual(p.returncode,0,p.stdout+p.stderr)
            for scenario in range(7):
                p=subprocess.run([str(out/"selftest"),str(scenario)],capture_output=True,text=True,timeout=30)
                self.assertEqual(p.returncode,0,f"scenario={scenario}: "+p.stdout+p.stderr)
                self.assertIn("PASS",p.stdout)


if __name__=="__main__":
    unittest.main()
