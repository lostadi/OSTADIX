"""Real native store/frontends under an explicit host RAM/register model.
No guest boot, AArch64 assembly, or live milestone qualification.
"""
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
#define S(n) _O_runtime__common__namespace_store__##n
#define N(n) _O_runtime__aarch64__kernel_world_9p__##n
#define U(n) _O_runtime__aarch64__plan9_namespace_uart__##n
#define W(n) _O_runtime__aarch64__linux_restart_witness__##n
extern uint64_t S(init)(uintptr_t,size_t,uint64_t),S(session_handle)(uint64_t),S(session_init)(uint64_t,uint64_t);
extern uint64_t S(qualification_fids)(uint64_t,uint64_t,uint64_t*,size_t);
extern uint64_t N(init)(uint64_t,uint64_t,uint64_t),N(mmio_write)(uint64_t,uint64_t),N(poll)(void),N(detach)(uint64_t),N(qualification_session)(void);
extern uint64_t U(init)(uint64_t),U(mmio_write)(uint64_t,uint64_t),U(mmio_read)(uint64_t),U(qualification_session)(void);
extern uint64_t W(execute)(uint64_t,uint64_t,uint64_t);
static unsigned char *mem,*out=(void*)0x6d0b0000,q[512],reply[512];static unsigned pos,avail;
static uint64_t rd(const void*p,unsigned n){const unsigned char*b=p;uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)b[i]<<(i*8);return v;}
static void st(void*p,uint64_t v,unsigned n){unsigned char*b=p;for(unsigned i=0;i<n;i++)b[i]=(unsigned char)(v>>(i*8));}
static void put(uint64_t v,unsigned n){st(q+pos,v,n);pos+=n;}
static void str(const char*s){unsigned n=strlen(s);put(n,2);memcpy(q+pos,s,n);pos+=n;}
static void begin(unsigned kind){memset(q,0,sizeof q);pos=7;q[4]=kind;st(q+5,55,2);}
static void map_at(uintptr_t base,size_t size){assert(mmap((void*)base,size,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED_NOREPLACE,-1,0)==(void*)base);}
uintptr_t kw_guest_address(uint64_t p,uint64_t n){if(!n||p<0x40000000||n>65536||p-0x40000000>65536-n)return 0;return (uintptr_t)mem+p-0x40000000;}
void kw_memory_barrier(void){__sync_synchronize();}
void kw_9p_irq_level(uint64_t n){assert(n<=1);}
void p9_namespace_irq_level(uint64_t n){assert(n<=1);}
static void nw(unsigned a,uint64_t v){assert(N(mmio_write)(a,v)==1);}
static void exchange(unsigned role,unsigned expected){
 st(q,pos,4);memset(reply,0,sizeof reply);
 if(role==0){
  memcpy(mem+0x3000,q,pos);memset(mem+0x6000,0,512);
  st(mem,0x40003000,8);st(mem+8,pos,4);st(mem+12,1,2);st(mem+14,1,2);
  st(mem+16,0x40006000,8);st(mem+24,512,4);st(mem+28,2,2);st(mem+30,0,2);
  st(mem+0x1004+(avail%8)*2,0,2);st(mem+0x1002,++avail,2);
  assert(N(poll)()==1);memcpy(reply,mem+0x6000,512);nw(100,1);
 }else{
  for(unsigned i=0;i<pos;i++)assert(U(mmio_write)(0,q[i])==1);
  for(unsigned i=0;i<4;i++){assert(!(U(mmio_read)(0x18)&16));reply[i]=U(mmio_read)(0);}
  unsigned n=rd(reply,4);assert(n>=7&&n<=512);
  for(unsigned i=4;i<n;i++){assert(!(U(mmio_read)(0x18)&16));reply[i]=U(mmio_read)(0);}
 }
 assert(reply[4]==expected&&rd(reply+5,2)==55);
}
static void setup(unsigned dotu,unsigned attach){
 void*v=mmap(0,16777216,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_PRIVATE,-1,0);assert(v!=MAP_FAILED);
 assert(S(init)((uintptr_t)v,16777216,1)==1);
 assert(N(init)(0x40000000,65536,1)==1);assert(U(init)(1)==1);assert(U(mmio_write)(0x30,0x301)==1);
 nw(112,0);nw(112,1);nw(112,3);nw(36,0);nw(32,1);nw(36,1);nw(32,1);nw(112,11);
 nw(48,0);nw(56,8);nw(128,0x40000000);nw(132,0);nw(144,0x40001000);nw(148,0);nw(160,0x40002000);nw(164,0);nw(68,1);nw(112,15);
 for(unsigned role=0;role<2;role++){
  begin(100);put(512,4);str(role==0&&dotu?"9P2000.u":"9P2000");exchange(role,101);
  if(!attach)continue;
  begin(104);put(role?30:9,4);put(UINT32_MAX,4);str("root");str("");if(!role&&dotu)put(UINT32_MAX,4);exchange(role,105);
  begin(110);put(role?30:9,4);put(role?2:1,4);put(0,2);exchange(role,111);
  if(role){begin(110);put(30,4);put(17,4);put(0,2);exchange(role,111);}
 }
}
static void cleared(void){for(unsigned i=40;i<0x50000;i++)assert(out[i]==0);}
int main(int argc,char**argv){
 assert(argc==2);unsigned scenario=strtoul(argv[1],0,10);map_at(0x6d0b0000,0x50000);map_at(0x48000000,65536);mem=(void*)0x48000000;
 if(scenario==0){memset(out,0xaa,0x50000);assert(W(execute)(1,1,0)==9);assert(rd(out+12,4)==9);cleared();}
 else if(scenario==1){assert(W(execute)(3,1,1)==1);cleared();assert(W(execute)(1,0,1)==4);assert(W(execute)(2,1,1)==12);assert(W(execute)(1,1,1)==4);}
 else if(scenario==2){
  setup(1,1);uint64_t ls=N(qualification_session)(),ps=U(qualification_session)();assert(ls&&ps&&ls!=ps&&(ls&1));
  assert(W(execute)(1,1,1)==0);assert(rd(out+40,8)==ls&&rd(out+56,8)==ps);assert(rd(out+72,4)==2&&rd(out+76,4)==3);
  const unsigned fids[]={1,9,2,17,30};for(unsigned i=0;i<5;i++){unsigned char*r=out+128+i*576;assert(rd(r+4,4)==fids[i]&&r[52]==125);}
  assert(W(execute)(1,2,1)==7);cleared();assert(W(execute)(2,3,1)==7);cleared();
  assert(N(detach)(1)==1);assert(W(execute)(2,4,1)==0);
  for(unsigned i=0;i<2;i++){unsigned char*r=out+128+i*576;unsigned n=rd(r+28,4);assert(r[52]==107&&rd(r+48+n-4,4)==116);}
  for(unsigned i=2;i<5;i++)assert(out[128+i*576+52]==125);
  assert(W(execute)(2,4,1)==4);cleared();
  begin(120);put(17,4);exchange(1,121);assert(W(execute)(2,5,1)==5);cleared();
 }else if(scenario==3){
  setup(1,1);uint64_t tuples[2048];memset(tuples,0xaa,sizeof tuples);assert(S(qualification_fids)(1,N(qualification_session)(),tuples,1)==UINT64_MAX-1);assert(tuples[0]==0xaaaaaaaaaaaaaaaa);
  assert(S(qualification_fids)(1,99,tuples,512)==UINT64_MAX);
  assert(S(qualification_fids)(1,N(qualification_session)(),tuples,512)==2);assert(tuples[0]==1&&tuples[4]==9);
 }else if(scenario==4){setup(0,1);assert(W(execute)(1,1,1)==12);cleared();}
 else if(scenario==5){setup(1,1);assert(S(session_init)(1,100));assert(N(qualification_session)()==0);assert(W(execute)(1,1,1)==12);cleared();}
 else if(scenario==6){setup(1,0);assert(W(execute)(1,1,1)==12);cleared();}
 else assert(!"unknown scenario");
 puts("native store witness scenario PASS");return 0;
}
'''
class LinuxWitnessNativeTests(unittest.TestCase):
    @unittest.skipUnless(platform.system()=="Linux" and platform.machine()=="x86_64", "native host model requires Linux x86_64")
    def test_real_transport_selected_fids_and_numeric_stale_replies(self):
        compiler=Path(os.environ.get("OCOREC_BIN",ROOT/"target/debug/ocorec"))
        self.assertTrue(compiler.is_file(),"existing compiler required")
        clang=shutil.which("clang");self.assertIsNotNone(clang)
        sources=["ocore/runtime/aarch64/linux_restart_witness.oc","ocore/runtime/aarch64/kernel_world_9p.oc",
                 "ocore/runtime/aarch64/plan9_namespace_uart.oc","ocore/runtime/common/namespace_store.oc",
                 "ocore/runtime/common/o10_codec.oc"]
        with tempfile.TemporaryDirectory(prefix="o10-store-witness-") as d:
            p=Path(d);(p/"harness.c").write_text(HARNESS)
            for target,kind,output in [("x86_64-unknown-none","obj",p/"native.o"),
                                       ("aarch64-unknown-none","mir",p/"native.arm.mir")]:
                command=[str(compiler),*(str(ROOT/x) for x in sources),"--emit",kind,"--target",target,"-o",str(output)]
                result=subprocess.run(command,capture_output=True,text=True,timeout=120)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            result=subprocess.run([clang,"-O2","-no-pie","-Wl,--gc-sections",str(p/"harness.c"),str(p/"native.o"),"-o",str(p/"selftest")],capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            for scenario in range(7):
                result=subprocess.run([str(p/"selftest"),str(scenario)],capture_output=True,text=True,timeout=20)
                self.assertEqual(result.returncode,0,f"scenario={scenario}: "+result.stdout+result.stderr)
                self.assertIn("PASS",result.stdout)
if __name__=="__main__":
    unittest.main()
