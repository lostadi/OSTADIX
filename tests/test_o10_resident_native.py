"""M1 native control-flow tests with explicit host models for EL2 register IO.

This qualifies the compiled monitor's idle/dispatch/containment decisions.
It does not execute AArch64 assembly, measure a real 60-second idle interval,
or qualify guest boot/reset. Any unmodeled architecture entry aborts.
"""
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = r"""
pub unsafe fn resident_test_init(mask: u64) -> u64 {
    LIVE[0] = mask & 1; LIVE[1] = (mask >> 1) & 1;
    FREQUENCY = 1000; PERIOD = 10; DEADLINE = 10;
    return gic_init();
}
pub unsafe fn resident_test_live() -> u64 { return LIVE[0] | (LIVE[1] << 1); }
pub unsafe fn resident_test_mailbox() -> u64 {
    native_control(); return LIVE[0] | (LIVE[1] << 1);
}
"""
HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define UW(n) _O_runtime__aarch64__unified_world__##n
#define NS(n) _O_runtime__common__namespace_store__##n
extern uint64_t NS(init)(uintptr_t,size_t,uint64_t),NS(session_init)(uint64_t,uint64_t);
extern uint64_t NS(session_handle)(uint64_t),NS(session_fid_count)(uint64_t);
extern size_t NS(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
static uint64_t linux_session,plan9_session;
extern uint64_t UW(resident_test_init)(uint64_t),UW(resident_test_live)(void),UW(resident_test_mailbox)(void);
extern uint64_t uw_handle_exit(uintptr_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t _O_runtime__aarch64__kernel_world_net__init(uint64_t,uint64_t,uint64_t);
extern uint64_t _O_runtime__aarch64__kernel_world_9p__init(uint64_t,uint64_t,uint64_t);
extern uint64_t _O_runtime__aarch64__kernel_world_9p__fault_kind(void);
extern void _O_runtime__aarch64__kernel_world_virtio__resident_test_hold(void);
extern uint64_t _O_runtime__aarch64__kernel_world_virtio__init(uint64_t,uint64_t,uint64_t);
extern uint64_t _O_runtime__aarch64__kernel_world_virtio__mmio_write(uint64_t,uint64_t);
extern void uw_unexpected_exit(uint64_t,uint64_t,uint64_t);
static jmp_buf stop;
static unsigned char serial[8192];static size_t serial_count;
static uint64_t current=0,physical_irq=26,clock_ticks=0,lrs[2][4],vmcr[2],hcr[2];
static unsigned idle_count=0,eoi_count=0,halt_count=0;static uint64_t idle_irq=26;
static unsigned char *request=(void*)0x6d0a0000,*reply=(void*)0x6d0a0200;
static uint64_t mailbox_seq=0;
static uint64_t rd(const void*q,unsigned n){const unsigned char*p=q;uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static void st(void*q,uint64_t v,unsigned n){unsigned char*p=q;for(unsigned i=0;i<n;i++)p[i]=(unsigned char)(v>>(8*i));}
static void attach_session(uint64_t session){
 unsigned char q[64]={0},r[512]={0};
 st(q,19,4);q[4]=100;st(q+7,512,4);st(q+11,6,2);memcpy(q+13,"9P2000",6);
 assert(NS(handle)(session,q,19,r,512)==19&&r[4]==101);
 memset(q,0,sizeof q);st(q,20,4);q[4]=104;st(q+7,1,4);st(q+11,UINT32_MAX,4);
 st(q+15,1,2);q[17]=117;st(q+18,0,2);
 assert(NS(handle)(session,q,20,r,512)==20&&r[4]==105);
}
static unsigned stat_session(uint64_t session){
 unsigned char q[11]={11,0,0,0,124,0,0},r[512];st(q+7,1,4);
 assert(NS(handle)(session,q,11,r,512)!=0);return r[4];
}
static void namespace_sessions(void){
 void*volume=mmap(NULL,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 assert(NS(init)((uintptr_t)volume,16777216,1)==1);
 linux_session=NS(session_init)(1,1);plan9_session=NS(session_init)(4,1);assert(linux_session&&plan9_session);
 attach_session(linux_session);attach_session(plan9_session);
 assert(NS(session_fid_count)(1)==1&&NS(session_fid_count)(4)==1);
}
static void frame(unsigned kind,size_t len,uint64_t epoch,uint64_t seq){
 memset(request,0,512);st(request,len,4);st(request+4,kind,1);st(request+5,88,2);
 st(request+7,epoch,8);st(request+15,seq,8);
}
static uint64_t mailbox(void){
 st((void*)0x6d000070,++mailbox_seq,8);st((void*)0x6d000078,10,8);
 uint64_t live=UW(resident_test_mailbox)();
 assert(rd((void*)0x6d000080,8)==mailbox_seq);assert(rd((void*)0x6d000088,8)==1);return live;
}
// Bounded hardware-register model: reads/writes preserve actual modeled banks.
uint64_t uw_current_domain(void){return current;}
uint64_t uw_counter_read(void){return ++clock_ticks;}
uint64_t kw_counter_read(void){return ++clock_ticks;}
uint64_t kw_counter_frequency(void){return 1000;}
uint64_t uw_irq_ack(void){return physical_irq;}
void uw_irq_eoi(uint64_t irq){assert(irq==physical_irq);eoi_count++;}
void uw_memory_barrier(void){__sync_synchronize();}
void kw_memory_barrier(void){__sync_synchronize();}
void uw_serial_putc(uint64_t byte){assert(serial_count<sizeof serial-1);serial[serial_count++]=(unsigned char)byte;}
uint64_t uw_serial_try_read(void){return UINT64_MAX;}

uint64_t uw_timer_pending(uint64_t domain,uint64_t kind){assert(domain<2&&kind<2);return 0;}
uint64_t uw_timer_deadline(uint64_t domain,uint64_t kind){assert(domain<2&&kind<2);return UINT64_MAX;}
uint64_t uw_vgic_lr_count(void){return 4;}
uint64_t uw_vgic_lr_read(uint64_t domain,uint64_t index){assert(domain<2&&index<4);return lrs[domain][index];}
void uw_vgic_lr_write(uint64_t domain,uint64_t index,uint64_t value){assert(domain<2&&index<4);lrs[domain][index]=value;}
uint64_t uw_vgic_vmcr_read(uint64_t domain){assert(domain<2);return vmcr[domain];}
void uw_vgic_vmcr_write(uint64_t domain,uint64_t value){assert(domain<2);vmcr[domain]=value;}
uint64_t uw_vgic_hcr_read(uint64_t domain){assert(domain<2);return hcr[domain];}
void uw_vgic_hcr_write(uint64_t domain,uint64_t value){assert(domain<2);hcr[domain]=value;}
uint64_t uw_vgic_running_priority(uint64_t domain){assert(domain<2);return 0xff;}
void uw_halt(void){halt_count++;longjmp(stop,2);}
uint64_t uw_idle_until(uint64_t deadline){
 assert(rd((void*)0x6d000008,8)==0);assert(deadline>=clock_ticks);
 if(idle_irq!=26){idle_count++;clock_ticks=deadline;return idle_irq;}
 if(idle_count){assert(rd((void*)0x6d000080,8)==mailbox_seq);assert(reply[4]==179);assert(reply[16]==4);}
 if(++idle_count==6)longjmp(stop,1);
 frame(178,31,0,0);st(request+23,((uint64_t)1<<32)|1,8);
 st((void*)0x6d000070,++mailbox_seq,8);st((void*)0x6d000078,10,8);
 clock_ticks=deadline;return 26;
}
static void diagnostic(uint64_t reason,uint64_t arg0){
 assert(halt_count==1);assert(rd((void*)0x6d0000d0,8)==reason);
 assert(rd((void*)0x6d0000d8,8)==arg0);assert(rd((void*)0x6d000008,8)==0);
 assert(!strncmp((char*)serial,"KW unified internal invariant: ",31));
}
int main(int argc,char**argv){
 assert(argc==2);unsigned scenario=(unsigned)strtoul(argv[1],NULL,10);
 void*control=mmap((void*)0x6d000000,0x100000,PROT_READ|PROT_WRITE,
 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);assert(control==(void*)0x6d000000);
 assert(UW(resident_test_init)(0)==1);
 uint64_t registers[34]={0};registers[31]=0x40100000;
 if(scenario==0){
  int code=setjmp(stop);if(code==0)uw_handle_exit((uintptr_t)registers,1,0,0,0);
  assert(code==1&&idle_count==6&&halt_count==0&&UW(resident_test_live)()==0);
  assert(rd((void*)0x6d000080,8)==5);assert(eoi_count==1);
 }else if(scenario==1){
  current=99;int code=setjmp(stop);if(!code)uw_handle_exit((uintptr_t)registers,1,0,0,0);
  assert(code==2);diagnostic(0x1101,99);
 }else if(scenario==2){
  physical_irq=33;int code=setjmp(stop);if(!code)uw_handle_exit((uintptr_t)registers,1,0,0,0);
  assert(code==2);diagnostic(0x1102,33);
 }else if(scenario==3||scenario==4){
  namespace_sessions();assert(UW(resident_test_init)(3)==1);current=0;
  int code=setjmp(stop);if(!code){
   uint64_t next=uw_handle_exit((uintptr_t)registers,scenario==3?2:0,
                                scenario==3?0x1234:0,scenario==3?0x45:0,scenario==3?0xabc0:0);
   assert(next==1&&UW(resident_test_live)()==2&&halt_count==0);
   assert(NS(session_handle)(1)==0&&NS(session_fid_count)(1)==0&&stat_session(linux_session)==107);
   assert(NS(session_handle)(4)==plan9_session&&NS(session_fid_count)(4)==1&&stat_session(plan9_session)==125);
    if(scenario==3){
     frame(178,31,0,0);st(request+23,((uint64_t)1<<32),8);mailbox();
     assert(reply[4]==179&&rd(reply+49,8)==0x1234&&rd(reply+57,8)==0xabc045);
     assert(rd(reply+65,8)==registers[31]);
    }
  }else assert(!"guest containment halted or entered idle with survivor");
  assert(strstr((char*)serial,"KW unified domain failure: ")!=NULL);
 }else if(scenario==5){
  assert(UW(resident_test_init)(2)==1);current=1;lrs[1][0]=((uint64_t)1<<62)|1023;
  int code=setjmp(stop);if(!code)uw_handle_exit((uintptr_t)registers,1,0,0,0);
  assert(code==2);diagnostic(0x1103,1);assert(UW(resident_test_live)()==2);
 }else if(scenario==6){
  assert(UW(resident_test_init)(3)==1);current=1;st((void*)0x6d040000,UINT64_MAX,8);
  int code=setjmp(stop);if(!code)uw_handle_exit((uintptr_t)registers,2,0,0,0);
  assert(code==2);diagnostic(0x1105,UINT64_MAX);
 }else if(scenario==7){
  int code=setjmp(stop);if(!code)uw_unexpected_exit(11,22,33);
  assert(code==2);diagnostic(0x1100,11);
  assert(rd((void*)0x6d0000e0,8)==22&&rd((void*)0x6d0000e8,8)==33);
 }else if(scenario==8){
  assert(UW(resident_test_init)(3)==1);
  frame(164,39,0,1);st(request+23,1,8);mailbox();assert(reply[4]==165);
  frame(196,33,1,2);st(request+23,((uint64_t)1<<32)|1,8);st(request+31,1,2);uint64_t live=mailbox();
  if(QUALIFICATION){assert(reply[4]==197&&live==1);assert(strstr((char*)serial,"KW unified domain failure: ")!=NULL);}
  else assert(reply[4]==161&&rd(reply+7,4)==9&&live==3&&serial_count==0);
  frame(196,33,1,3);st(request+23,((uint64_t)1<<32),8);st(request+31,2,2);
  mailbox();assert(reply[4]==161&&rd(reply+7,4)==9);
 }else if(scenario==9){
   idle_irq=33;int code=setjmp(stop);
   if(!code)uw_handle_exit((uintptr_t)registers,1,0,0,0);
   assert(code==2&&idle_count==1&&UW(resident_test_live)()==0);
   diagnostic(0x1102,33);
   assert(strstr((char*)serial,"KW unified domain failure: ")==NULL);
  }else if(scenario>=10&&scenario<=16){
   namespace_sessions();assert(UW(resident_test_init)(3)==1);current=0;
   uint64_t esr=((uint64_t)0x24<<26)|(1ull<<24)|(1ull<<25)|(2ull<<22)|64;
   uint64_t ipa=0xdead0000;
   if(scenario==11)ipa=0x09000ffc; // Unhandled UART write.
   if(scenario==12){ipa=0x0a000000;esr|=1ull<<22;} // Unsupported 8-byte width.
   if(scenario==13){assert(_O_runtime__aarch64__kernel_world_virtio__init(0x40000000,65536,1)==1);ipa=0x0a0000fc;} // Invalid block register write.
   if(scenario==14){assert(_O_runtime__aarch64__kernel_world_net__init(0x40000000,65536,1)==1);ipa=0x0a000300;} // Inactive network frontend write.
   if(scenario==15){esr=((uint64_t)0x16<<26)|10;registers[0]=0x84000000;}
   if(scenario==16){esr=(uint64_t)0x16<<26;registers[0]=0x12345678;}
   int code=setjmp(stop);if(!code){
    uint64_t next=uw_handle_exit((uintptr_t)registers,0,esr,ipa&4095,(ipa>>8)&~15ull);
    assert(next==1&&UW(resident_test_live)()==2&&halt_count==0);
    assert(NS(session_handle)(1)==0&&stat_session(linux_session)==107);
    assert(NS(session_handle)(4)==plan9_session&&stat_session(plan9_session)==125);
   }else assert(!"hostile Linux exit halted the monitor");
  }else if(scenario>=17&&scenario<=19){
   assert(!SERVICES);namespace_sessions();assert(UW(resident_test_init)(3)==1);current=0;
   assert(_O_runtime__aarch64__kernel_world_virtio__init(0x40000000,65536,1)==1);
   uint64_t esr=(uint64_t)0x16<<26,ipa=0;
   registers[0]=0x84000008; // SYSTEM_OFF is explicitly denied, never host halt.
   if(scenario==18){esr=((uint64_t)0x24<<26)|(1ull<<24)|(1ull<<25)|(2ull<<22);ipa=0x0a000000;}
   if(scenario==19){assert(_O_runtime__aarch64__kernel_world_virtio__mmio_write(0xff,1)==0);esr=0;}
   int code=setjmp(stop);if(!code){
    uint64_t next=uw_handle_exit((uintptr_t)registers,scenario==19?1:0,esr,ipa&4095,(ipa>>8)&~15ull);
    assert(halt_count==0&&next<2);
    if(scenario==19){assert(UW(resident_test_live)()==2&&next==1&&NS(session_handle)(1)==0);}
    else{
     assert(UW(resident_test_live)()==3&&NS(session_handle)(1)==linux_session);
     assert(registers[0]==(scenario==17?UINT64_MAX-1:0x74726976));
    }
    assert(NS(session_handle)(4)==plan9_session&&stat_session(plan9_session)==125);
   }else assert(!"valid Linux path or queue rejection halted");
  }else if(scenario==20){
   assert(SERVICES);assert(UW(resident_test_init)(3)==1);
   int code=setjmp(stop);if(!code)uw_handle_exit((uintptr_t)registers,1,0,0,0);
   assert(code==2&&UW(resident_test_live)()==3);diagnostic(0x1109,0x1019);
  }else if(scenario>=21&&scenario<=24){
   assert(UW(resident_test_init)(3)==1);current=0;
   uint64_t esr=0,ipa=0,expected=0;
   if(scenario==21){
    assert(SERVICES);namespace_sessions();expected=0x1112;ipa=0x0a000300;
    esr=((uint64_t)0x24<<26)|(1ull<<24)|(1ull<<25)|(2ull<<22)|64;
   }else if(scenario==22){
    assert(SERVICES);
    assert(_O_runtime__aarch64__kernel_world_9p__init(0x40000000,65536,1)==0);
    assert(_O_runtime__aarch64__kernel_world_9p__fault_kind()==3);
    expected=0x1111;ipa=0x0a000470;
    esr=((uint64_t)0x24<<26)|(1ull<<24)|(1ull<<25)|(2ull<<22)|64;
   }else{
    assert(!SERVICES);namespace_sessions();
    if(scenario==23){
     assert(_O_runtime__aarch64__kernel_world_virtio__init(0x40000000,65536,1)==1);
     _O_runtime__aarch64__kernel_world_virtio__resident_test_hold();expected=0x1014;
    }else expected=0x1113;
   }
   int code=setjmp(stop);if(!code)uw_handle_exit((uintptr_t)registers,esr?0:1,esr,ipa&4095,(ipa>>8)&~15ull);
   assert(code==2&&UW(resident_test_live)()==3);diagnostic(0x1109,expected);
   assert(strstr((char*)serial,"KW unified domain failure: ")==NULL);
   if(scenario!=22){assert(NS(session_handle)(1)==linux_session&&NS(session_handle)(4)==plan9_session);}
  }else if(scenario>=25&&scenario<=31){
   namespace_sessions();assert(UW(resident_test_init)(3)==1);current=0;
   uint64_t esr=((uint64_t)0x24<<26)|(1ull<<24)|(1ull<<25)|(2ull<<22)|64;
   uint64_t ipa=0x09000008;registers[0]=1;
   if(scenario==26)esr&=~64ull;
   if(scenario==27)ipa=0x09000048;
   if(scenario==29){ipa=0x09000030;registers[0]=0x80;}
   if(scenario==30){ipa=0x0900002c;registers[0]=0x62;}
   if(scenario==31)ipa=0x09000fe0;
   int code=setjmp(stop);if(!code){
    if(scenario==28){
     assert(!SERVICES);
     assert(_O_runtime__aarch64__kernel_world_virtio__init(0x40000000,65536,1)==1);
     const uint64_t offsets[]={0x30,0x44,0x38,0x48,0x24,0x28,0x2c,0x34,0x30,0x38,0x04};
     const uint64_t values[]={0,0x7ff,0,0,13,1,0x70,0x12,0xf01,0x50,0};
     for(unsigned i=0;i<sizeof offsets/sizeof offsets[0];i++){
      registers[0]=values[i];ipa=0x09000000+offsets[i];
      assert(uw_handle_exit((uintptr_t)registers,0,esr,ipa&4095,(ipa>>8)&~15ull)<2);
      assert(UW(resident_test_live)()==3&&halt_count==0);
     }
     const uint64_t ro[]={0x18,0x3c,0x40,0x48,0xfe0,0xfe4,0xfe8,0xfec,0xff0,0xff4,0xff8,0xffc};
     for(unsigned i=0;i<sizeof ro/sizeof ro[0];i++){
      ipa=0x09000000+ro[i];assert(uw_handle_exit((uintptr_t)registers,0,esr&~64ull,ipa&4095,(ipa>>8)&~15ull)<2);
      assert(UW(resident_test_live)()==3&&halt_count==0);
     }
    }else{
     assert(uw_handle_exit((uintptr_t)registers,0,esr,ipa&4095,(ipa>>8)&~15ull)==1);
     assert(UW(resident_test_live)()==2&&halt_count==0);
     assert(NS(session_handle)(1)==0&&stat_session(linux_session)==107);
    }
    assert(NS(session_handle)(4)==plan9_session&&stat_session(plan9_session)==125);
   }else assert(!"virtual UART corpus halted monitor");
  }else assert(!"unknown scenario");
 puts("resident native scenario PASS");return 0;
}
"""

class O10ResidentNativeTests(unittest.TestCase):
    @unittest.skipUnless(platform.system()=="Linux" and platform.machine()=="x86_64",
                         "native host model requires Linux x86_64")
    def test_resident_paths_and_qualification_boundary(self):
        compiler=Path(os.environ.get("OCOREC_BIN",ROOT/"target/debug/ocorec"))
        clang=shutil.which("clang")
        self.assertTrue(compiler.is_file(),"existing native compiler required")
        self.assertIsNotNone(clang,"clang required")
        sources=runpy.run_path(str(ROOT/"scripts/build_okernel_unified_world.py"))["SOURCES"]
        with tempfile.TemporaryDirectory(prefix="o10-resident-") as directory:
            output=Path(directory)
            world=output/"unified_world.oc";world.write_text((ROOT/sources[0]).read_text()+WRAPPER)
            (output/"harness.c").write_text(HARNESS)
            block_name="ocore/runtime/aarch64/kernel_world_virtio.oc"
            block=output/"block.oc"
            block.write_text((ROOT/block_name).read_text()+
                "\npub unsafe fn resident_test_hold() -> void { PENDING = 1; PENDING_TYPE = 0; }\n")
            for configuration in ((0,1),(1,1),(0,0),(1,0)):
                qualification,services=configuration
                profile=output/"profile.oc"
                profile.write_text("module runtime::aarch64::kernel_world_profile;\n"
                    "pub const PERSISTENT: u64 = 1;\npub const BACKING_BASE: usize = 0x7000_0000;\n"
                    "pub const BACKING_BYTES: usize = 1_073_741_824;\npub const NETWORK: u64 = "+str(services)+";\n"
                    "pub const NAMESPACE: u64 = "+str(services)+";\npub const O10_QUALIFICATION: u64 = "+str(qualification)+";\n")
                command=[str(compiler),str(profile),str(world),*(str(block if name==block_name else ROOT/name) for name in sources[1:]),
                         "--target","x86_64-unknown-none","--emit","obj","--function-sections","-o",str(output/"native.o")]
                result=subprocess.run(command,capture_output=True,text=True,timeout=120)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                # Every unspecified assembly import gets an aborting sentinel.
                imports=subprocess.run(["nm","-u",str(output/"native.o")],check=True,capture_output=True,text=True).stdout
                modeled={"uw_current_domain","uw_counter_read","uw_irq_ack","uw_irq_eoi","uw_memory_barrier",
                         "uw_serial_putc","uw_serial_try_read","uw_timer_pending","uw_timer_deadline",
                         "uw_vgic_lr_count","uw_vgic_lr_read","uw_vgic_lr_write","uw_vgic_vmcr_read",
                         "uw_vgic_vmcr_write","uw_vgic_hcr_read","uw_vgic_hcr_write","uw_vgic_running_priority",
                         "uw_halt","uw_idle_until","kw_memory_barrier","kw_counter_read","kw_counter_frequency",
                         "kw_serial_try_read","kw_serial_putc","kw_uart_irq_level","kw_irq_level"}
                names={line.split()[-1] for line in imports.splitlines() if line.split()}
                unmodeled=sorted(name for name in names if name.startswith(("uw_","kw_")) and name not in modeled)
                (output/"sentinels.c").write_text("#include <stdio.h>\n#include <stdlib.h>\n"+
                    "\n".join('void '+name+'(void){fputs("off-corpus architecture: '+name+'\\n",stderr);abort();}' for name in unmodeled))
                command=[clang,"-O2","-no-pie","-Ulinux","-Wl,--gc-sections","-DQUALIFICATION="+str(qualification),"-DSERVICES="+str(services),
                         str(output/"harness.c"),str(output/"sentinels.c"),str(output/"native.o"),"-o",str(output/"selftest")]
                result=subprocess.run(command,capture_output=True,text=True,timeout=120)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                for scenario in list(range(17))+([20,21,22,25,26,27,29,30,31] if services else [17,18,19,23,24,25,26,27,28,29,30,31]):
                    result=subprocess.run([str(output/"selftest"),str(scenario)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,0,f"qualification={qualification} scenario={scenario}: "+result.stdout+result.stderr)

if __name__=="__main__":
    unittest.main()
