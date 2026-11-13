"""Actual O10 executor/world provisioning with explicit EL2 register models.

The image copies, table, UART, namespace store, journal and IRQ ownership are
production code. Host architecture functions model stage2/reset; full EL2 and
three-kernel acceptance have separate gates.
"""
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import tempfile
import unittest

from tests.test_o10_domain_table import extend_world
from tests.test_o10_resident_native import HARNESS as RESIDENT_HARNESS, WRAPPER as RESIDENT_WRAPPER

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = RESIDENT_WRAPPER + r"""
pub unsafe fn provisioning_test_mmio(holder:u64,offset:u64,value:u64,writing:u64) -> u64 {
    let domain:u64=d_lookup(holder);if domain==DOMAINS { return MAX; }
    let mut frame:[u64;34]=[0;34];frame[0]=value;frame[31]=0x4000_1000;
    let esr:u64=(1<<24)|(1<<25)|(2<<22)|(writing<<6);
    if !native_mmio(domain,&mut frame[0],esr,0x0900_1000+offset) { return MAX; }
    if frame[31]!=0x4000_1004 { return MAX; }return frame[0];
}
"""
HARNESS = RESIDENT_HARNESS.split("int main(int argc,char**argv){", 1)[0] + r"""
#define T(n) _O_runtime__aarch64__domain_table__##n
#define I(n) _O_runtime__aarch64__domain_images__##n
#define U(n) _O_runtime__aarch64__native_namespace_uart__##n
extern uint64_t I(register)(size_t,size_t,size_t,size_t,size_t,size_t,size_t);
extern uint64_t T(state)(uint64_t),T(handle)(uint64_t),T(generation)(uint64_t),T(lookup)(uint64_t);
extern uint64_t T(boot)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t T(instance_byte)(uint64_t,uint64_t),T(block)(uint64_t),T(wake)(uint64_t);
extern uint64_t U(session)(uint64_t),U(healthy)(uint64_t);
extern uint64_t UW(provisioning_test_mmio)(uint64_t,uint64_t,uint64_t,uint64_t);
static uint64_t configured[8]={1,1},bases[8]={0x48000000,0xb0000000},sizes[8]={0x20000000,0x20000000};
static uint64_t configure_count,unconfigure_count,init_count,reset_count,seq;
uint64_t uw_domain_configured(uint64_t slot){assert(slot<8);return configured[slot];}
uint64_t uw_domain_configure(uint64_t slot,uint64_t base,uint64_t bytes){
 assert(slot<8&&!configured[slot]&&base>=0xe2200000&&base+bytes<=0xe2400000&&bytes==0x200000);
 configured[slot]=1;bases[slot]=base;sizes[slot]=bytes;configure_count++;return 1;
}
uint64_t uw_domain_unconfigure(uint64_t slot){
 assert(slot<8&&configured[slot]);configured[slot]=0;bases[slot]=sizes[slot]=0;unconfigure_count++;return 1;
}
uint64_t uw_domain_init(uint64_t slot,uint64_t pc,uint64_t x0,uint64_t pstate){
 assert(slot<8&&configured[slot]&&pc==0x40000000&&x0==0x40100000&&pstate==0x3c5);init_count++;return 1;
}
uint64_t uw_domain_reset(uint64_t slot,uint64_t pc,uint64_t x0,uint64_t pstate){
 assert(slot<8&&configured[slot]&&pc==0x40000000&&x0==0x40100000&&pstate==0x3c5);reset_count++;return 1;
}
static void map_(uintptr_t base,size_t bytes){
 assert(mmap((void*)base,bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)base);
}
static uint64_t digest(const void*p,size_t n){const unsigned char*q=p;uint64_t h=1469598103934665603ull;for(size_t i=0;i<n;i++)h=(h^q[i])*1099511628211ull;return h;}
static void aux(void){
 unsigned char*p=(void*)0xe2500000;memset(p,0,128);memcpy(p,"O10M3N1\0",8);
 st(p+8,1,4);st(p+12,128,4);st(p+16,0x401f0000,8);st(p+24,0x09001000,8);
 st(p+32,14,4);st(p+36,24,4);memcpy(p+40,"o10-m3-witness",14);memcpy(p+72,"O10_M3_NATIVE_NAMESPACE\n",24);
}
static void begin(unsigned type,unsigned bytes){frame(type,bytes,1,++seq);}
static void error(unsigned code){mailbox();if(reply[4]!=161||rd(reply+7,4)!=code)fprintf(stderr,"type=%u seq=%llu expected error=%u actual type=%u code=%llu\n",request[4],(unsigned long long)rd(request+15,8),code,reply[4],(unsigned long long)rd(reply+7,4));assert(reply[4]==161&&rd(reply+7,4)==code);}
static void create(unsigned kind,uint64_t kernel,uint64_t auxiliary,uint64_t bytes,unsigned cpus){
 begin(168,50);st(request+23,kind,1);st(request+24,kernel,8);st(request+32,auxiliary,8);st(request+40,bytes,8);st(request+48,cpus,2);
}
static void bind_(uint64_t lease,uint64_t dom){
 begin(184,39);st(request+23,lease,8);st(request+31,(dom&0xffffffff00000000ull),8);
}
static uint64_t create_native(void){create(3,5,6,0x200000,1);mailbox();assert(reply[4]==169);return rd(reply+7,8);}
static void start_(uint64_t holder,unsigned byte){
 begin(170,47);st(request+23,holder,8);memset(request+31,byte,16);mailbox();assert(reply[4]==171&&rd(reply+7,8)==holder);
}
static void destroy_(uint64_t holder){
 begin(176,31);st(request+23,holder,8);mailbox();assert(reply[4]==177&&rd(reply+7,8)==holder);
}
static void survivors(void){
 assert(T(handle)(0)==(1ull<<32)&&T(handle)(1)==((1ull<<32)|1)&&T(state)(0)==2&&T(state)(1)==2);
 assert(G(binding_generation)(0)==1&&G(binding_generation)(1)==1&&configured[0]&&configured[1]);
 assert(NS(session_handle)(1)==linux_session&&NS(session_handle)(4)==plan9_session);
 assert(NS(session_fid_count)(1)==1&&NS(session_fid_count)(4)==1);
 assert(stat_session(linux_session)==125&&stat_session(plan9_session)==125);
 for(unsigned i=0;i<4096;i++){assert(((unsigned char*)0x48000000)[i]==0xa3);assert(((unsigned char*)0xb0000000)[i]==0xb7);}
}
static void revoked_zero(void){
 for(unsigned i=0;i<0x200000;i++)assert(((unsigned char*)0xe2200000)[i]==0);
 assert(!NS(session_handle)(3));
}
static unsigned char q[8192],a[8192];static size_t qn;static unsigned qtag;
static void qbegin(unsigned type){memset(q,0,sizeof q);q[4]=type;st(q+5,++qtag,2);qn=7;}
static void qp(uint64_t v,unsigned n){st(q+qn,v,n);qn+=n;}
static void qs(const char*s){size_t n=strlen(s);qp(n,2);memcpy(q+qn,s,n);qn+=n;}
static void version(void){qbegin(100);qp(512,4);qs("9P2000");}
static void attach_(unsigned fid){qbegin(104);qp(fid,4);qp(UINT32_MAX,4);qs("u");qs("");}
static unsigned direct(uint64_t session,unsigned type){
 st(q,qn,4);unsigned n=NS(handle)(session,q,qn,a,sizeof a);assert(n>=7&&a[4]==type);return n;
}
static uint64_t mmio(uint64_t h,uint64_t off,uint64_t value,unsigned wr){
 return UW(provisioning_test_mmio)(h,off,value,wr);
}
static unsigned uart(uint64_t h,unsigned type){
 st(q,qn,4);for(size_t i=0;i<qn;i++)assert(mmio(h,0,q[i],1)==q[i]);
 assert(!(mmio(h,0x18,0,0)&0x10));
 for(unsigned i=0;i<4;i++)a[i]=mmio(h,0,0,0);
 unsigned n=rd(a,4);assert(n>=7&&n<=sizeof a);for(unsigned i=4;i<n;i++)a[i]=mmio(h,0,0,0);
 assert(a[4]==type&&rd(a+5,2)==qtag);return n;
}
static void read_witness(uint64_t h){
 assert(mmio(h,0x30,0x301,1)==0x301);
 version();uart(h,101);attach_(1);uart(h,105);
 qbegin(110);qp(1,4);qp(2,4);qp(1,2);qs("o10-m3-witness");uart(h,111);
 qbegin(112);qp(2,4);qp(0,1);uart(h,113);
 qbegin(116);qp(2,4);qp(0,8);qp(128,4);
 assert(uart(h,117)==35&&rd(a+7,4)==24&&!memcmp(a+11,"O10_M3_NATIVE_NAMESPACE\n",24));
}
static void setup(void){
 map_(0x6d000000,0x100000);map_(0xe2200000,0x600000);map_(0x48000000,4096);map_(0xb0000000,4096);
 memset((void*)0x48000000,0xa3,4096);memset((void*)0xb0000000,0xb7,4096);
 memset((void*)0xe2200000,0xa5,0x600000);aux();
 for(unsigned i=0;i<123;i++)((unsigned char*)0xe2400000)[i]=(unsigned char)(i+1);
 assert(I(register)(0,0,0,0,0,123,128)==0);
 namespace_sessions();assert(UW(resident_test_init)(3)==1);
 uint64_t writer=NS(session_init)(2,1);assert(writer);version();direct(writer,101);attach_(50);direct(writer,105);
 qbegin(114);qp(50,4);qs("o10-m3-witness");qp(0644,4);qp(2,1);direct(writer,115);
 qbegin(118);qp(50,4);qp(0,8);qp(24,4);memcpy(q+qn,"O10_M3_NATIVE_NAMESPACE\n",24);qn+=24;direct(writer,119);
 frame(164,39,0,++seq);st(request+23,1,8);mailbox();assert(reply[4]==165);
}
int main(int argc,char**argv){
 assert(argc==2);unsigned scenario=strtoul(argv[1],0,10);setup();
 uint64_t immutable=digest((void*)0xe2400000,0x200000),dom,old;
 if(scenario==0){
  create(1,5,6,0x200000,1);error(9);create(3,5,6,0x200000,2);error(9);
  create(2,5,6,0x200000,1);error(6);create(3,5,4,0x200000,1);error(5);
  create(3,5,6,0x400000,1);error(8);assert(!configure_count&&!T(state)(2));
  ((unsigned char*)0xe2500000)[120]=1;create(3,5,6,0x200000,1);error(6);
  assert(configure_count==1&&unconfigure_count==1&&!configured[2]&&!T(state)(2)&&!init_count);
  for(unsigned i=0;i<0x200000;i++)assert(((unsigned char*)0xe2200000)[i]==0xa5);
  ((unsigned char*)0xe2500000)[120]=0;
  dom=create_native();assert(dom==((1ull<<32)|2)&&T(state)(2)==1&&G(binding_generation)(2)==1);
  unsigned char original_q[50],original_r[15];memcpy(original_q,request,50);memcpy(original_r,reply,15);
  mailbox();assert(!memcmp(reply,original_r,15)&&init_count==1); // byte-identical retransmission.
  request[23]=2;error(4);memcpy(request,original_q,50);
  create(3,5,6,0x200000,1);error(7);assert(init_count==1);
  assert(!memcmp((void*)0xe2200000,(void*)0xe2400000,123)&&!memcmp((void*)0xe2300000,(void*)0xe2500000,128));
  bind_((1ull<<32)|3,dom);mailbox();assert(reply[4]==185&&T(state)(2)==1&&U(session)(dom));
  assert(halt_count==0);start_(dom,0x6c);assert(T(state)(2)==2);
  for(unsigned i=0;i<16;i++)assert(T(instance_byte)(2,i)==0x6c);
  read_witness(dom);assert(T(block)(2));read_witness(dom);assert(T(wake)(2)); // BLOCKED holder's polled wire stays live.
  old=dom;begin(196,33);st(request+23,dom,8);st(request+31,1,2);mailbox();assert(reply[4]==197);
  assert(T(state)(2)==4&&!U(healthy)(dom)&&!G(binding_generation)(2)&&!NS(session_handle)(3));
  assert(mmio(dom,0x30,0x301,1)==UINT64_MAX&&!U(healthy)(dom)); // guest reset cannot regrant.
  memset((void*)0xe2200000,0xcc,0x200000);
  begin(174,63);st(request+23,dom,8);memset(request+31,0x7d,16);st(request+47,5,8);st(request+55,6,8);
  mailbox();assert(reply[4]==175);dom=rd(reply+7,8);
  assert(dom==((2ull<<32)|2)&&reset_count==1&&T(state)(2)==3&&G(binding_generation)(2)==2);
  assert(!memcmp((void*)0xe2200000,(void*)0xe2400000,123)&&*((unsigned char*)0xe22f0000)==0);
  frame(178,31,1,0);st(request+23,old,8);error(5);
  bind_((1ull<<32)|3,dom);error(5);bind_((2ull<<32)|3,old);error(5);
  bind_((2ull<<32)|3,dom);mailbox();assert(reply[4]==185&&T(state)(2)==2);read_witness(dom);
  destroy_(dom);assert(!configured[2]&&!G(binding_generation)(2)&&T(lookup)(dom)==8);revoked_zero();
  old=dom;dom=create_native();assert(dom==((3ull<<32)|2));
  bind_((2ull<<32)|3,dom);error(5);bind_((3ull<<32)|3,dom);mailbox();assert(reply[4]==185);
  start_(dom,0x8e);read_witness(dom);begin(176,31);st(request+23,old,8);error(5);
  destroy_(dom);revoked_zero();assert(configure_count==3&&unconfigure_count==3&&init_count==2);
 }else if(scenario==1){
  // A provisioned holder may already have bound fids; destruction revokes them.
  dom=create_native();bind_((1ull<<32)|3,dom);mailbox();assert(reply[4]==185&&T(state)(2)==1);
  uint64_t s=U(session)(dom);version();direct(s,101);attach_(1);direct(s,105);assert(NS(session_fid_count)(3)==1);
  destroy_(dom);revoked_zero();dom=create_native();assert(dom==((2ull<<32)|2));
  bind_((2ull<<32)|3,dom);mailbox();assert(reply[4]==185);start_(dom,0x17);
  read_witness(dom);begin(172,36);st(request+23,dom,8);mailbox();assert(reply[4]==173&&rd(reply+15,4)==1&&rd(reply+23,4)==2);
  assert(T(state)(2)==5&&!G(binding_generation)(2)&&reset_count==1);revoked_zero();
  survivors();destroy_(dom);revoked_zero();
 }else if(scenario==2){
  for(unsigned i=2;i<8;i++)assert(T(boot)(i,3,3,0xe2600000+(i-2)*0x200000,0x200000,5,6));
  create(3,5,6,0x200000,1);error(8);assert(!configure_count);
 }else assert(!"unknown scenario");
 survivors();assert(digest((void*)0xe2400000,0x200000)==immutable&&halt_count==0);
 puts("O10 production provisioning/bind/start/fault/restore/destroy/reuse PASS");return 0;
}
"""


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "native component fixture requires Linux x86_64")
class O10ProvisioningTests(unittest.TestCase):
    def test_real_executor_and_lifecycle(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang = shutil.which("clang")
        self.assertTrue(compiler.is_file())
        self.assertIsNotNone(clang)
        sources = runpy.run_path(str(ROOT / "scripts/build_okernel_unified_world.py"))["SOURCES"]
        with tempfile.TemporaryDirectory(prefix="o10-provisioning-") as directory:
            out = Path(directory)
            from tests.test_o10_domain_table import write_table_fixture
            table = write_table_fixture(out)
            world = out / "world.oc"
            world.write_text(extend_world((ROOT / sources[0]).read_text(), WRAPPER))
            profile = out / "profile.oc"
            profile.write_text("module runtime::aarch64::kernel_world_profile;\n"
                "pub const PERSISTENT:u64=1;\npub const NETWORK:u64=0;\npub const NAMESPACE:u64=0;\n"
                "pub const BACKING_BASE:usize=0x70000000;\npub const BACKING_BYTES:usize=4096;\n"
                "pub const O10_QUALIFICATION:u64=1;\n")
            inputs = [str(profile), str(world), *(str(table if name ==
                "ocore/runtime/aarch64/domain_table.oc" else ROOT / name) for name in sources[1:])]
            for target, name in [("aarch64-unknown-none", "arm.o"), ("x86_64-unknown-none", "native.o")]:
                p = subprocess.run([str(compiler), *inputs, "--target", target, "--emit", "obj",
                                    "--function-sections", "-o", str(out / name)],
                                    capture_output=True, text=True, timeout=120)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            (out / "harness.c").write_text(HARNESS)
            imports = subprocess.run(["nm", "-u", str(out / "native.o")], check=True,
                                      capture_output=True, text=True).stdout
            modeled = {"uw_current_domain", "uw_counter_read", "uw_irq_ack", "uw_irq_eoi", "uw_memory_barrier",
                "uw_serial_putc", "uw_serial_try_read", "uw_timer_pending", "uw_timer_deadline",
                "uw_vgic_lr_count", "uw_vgic_lr_read", "uw_vgic_lr_write", "uw_vgic_vmcr_read",
                "uw_vgic_vmcr_write", "uw_vgic_hcr_read", "uw_vgic_hcr_write", "uw_vgic_running_priority",
                "uw_halt", "uw_idle_until", "kw_memory_barrier", "kw_counter_read", "kw_counter_frequency",
                "uw_domain_configured", "uw_domain_configure", "uw_domain_unconfigure", "uw_domain_init", "uw_domain_reset",
                "kw_serial_try_read", "kw_serial_putc", "kw_uart_irq_level", "kw_irq_level"}
            names = {line.split()[-1] for line in imports.splitlines() if line.split()}
            (out / "sentinels.c").write_text("#include <stdio.h>\n#include <stdlib.h>\n" + "\n".join(
                'void ' + name + '(void){fputs("off-corpus architecture: ' + name + '\\n",stderr);abort();}'
                for name in sorted(names) if name.startswith(("kw_", "uw_")) and name not in modeled))
            p = subprocess.run([clang, "-O2", "-no-pie", "-Ulinux", "-DSERVICES=0", "-Wl,--gc-sections",
                str(out / "harness.c"), str(out / "sentinels.c"), str(out / "native.o"), "-o", str(out / "test")],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            for scenario in range(3):
                p = subprocess.run([str(out / "test"), str(scenario)], capture_output=True, text=True, timeout=30)
                self.assertEqual(p.returncode, 0, f"scenario={scenario}: " + p.stdout + p.stderr)
                self.assertIn("PASS", p.stdout)


if __name__ == "__main__":
    unittest.main()
