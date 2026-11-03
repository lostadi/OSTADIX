"""Run the actual native console mux with physical-serial/EL2 fixture hooks.

Only the Linux provider's boot/poll entrypoints are substituted. The tested
mux, GIC, Plan9 UART9P and native namespace are the production O-core sources.
This component test does not boot either original kernel or replace the real
foreground-PTY acceptance in verify_okernel_unified_console.py.
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = r'''
module runtime::aarch64::kernel_world_monitor;
use runtime::common::namespace_store::init;
use runtime::common::namespace_store::provision_clock;
pub unsafe fn kw_monitor_init() -> u64 {
    if init(0x6c00_0000, 16_777_216, 100) != 1 { return 0; }
    return provision_clock(1_700_000_000);
}
pub unsafe fn kw_handle_exit(frame: usize, esr: u64, far: u64, hpfar: u64) -> u64 { return 0; }
'''
HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#define S(n) _O_runtime__common__namespace_store__##n
#define CU(n) _O_runtime__aarch64__coordinator_uart__##n
#define CONTROL ((uint8_t*)0x6d000000)
#define P9BASE ((uint8_t*)0x6d020000)
#define LINUXBASE ((uint8_t*)0x6d040000)
extern uint64_t uw_init(void),uw_handle_exit(uintptr_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t kw_serial_try_read(void);
extern void kw_serial_putc(uint64_t);
extern uint64_t S(session_init)(uint64_t,uint64_t);
extern uintptr_t S(handle)(uint64_t,const uint8_t*,uintptr_t,uint8_t*,uintptr_t);
extern uint64_t CU(mmio_read)(uint64_t),CU(inject)(const uint8_t*,uintptr_t);
static uint64_t bank[2][16],vmcr[2],hcr[2],current,now=100000;
static uint8_t physical[32768],display[262144];
static size_t physical_head,physical_count,display_count;
static uint64_t frame[34];
static uint64_t word(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static void putword(void *p,uint64_t v){memcpy(p,&v,8);}
uint64_t uw_domain_init(uint64_t d,uint64_t pc,uint64_t x0,uint64_t pstate){assert(d<2&&pstate==0x3c5&&pc==(d?0x40100000:0x40000000)&&x0==(d?0x40000000:0x47e00000));return 1;}
uint64_t uw_domain_reset(uint64_t d,uint64_t pc,uint64_t x0,uint64_t pstate){return uw_domain_init(d,pc,x0,pstate);}
uint64_t uw_current_domain(void){return current;}
uint64_t uw_counter_read(void){return now+=10001;}
uint64_t uw_counter_frequency(void){return 1000000;}
uint64_t uw_irq_ack(void){return 26;}
void uw_irq_eoi(uint64_t irq){assert(irq==26);}
uint64_t uw_timer_pending(uint64_t d,uint64_t kind){assert(d<2&&kind<2);return 0;}
uint64_t uw_timer_read(uint64_t d,uint64_t kind,uint64_t field){assert(d<2&&kind<2&&field<3);return 0;}
uint64_t uw_timer_write(uint64_t d,uint64_t kind,uint64_t field,uint64_t v){(void)v;assert(d<2&&kind<2&&field<3);return 1;}
void uw_serial_putc(uint64_t v){assert(v<256&&display_count<sizeof(display));display[display_count++]=(uint8_t)v;}
uint64_t uw_serial_try_read(void){if(!physical_count)return 0;uint64_t v=physical[physical_head++]|256;physical_count--;return v;}
void uw_memory_barrier(void){__sync_synchronize();}
void uw_halt(void){fputs("unexpected production halt\n",stderr);abort();}
uint64_t uw_vgic_lr_count(void){return 4;}
uint64_t uw_vgic_lr_read(uint64_t d,uint64_t i){assert(d<2&&i<4);return bank[d][i];}
void uw_vgic_lr_write(uint64_t d,uint64_t i,uint64_t v){assert(d<2&&i<4);bank[d][i]=v;}
uint64_t uw_vgic_hcr_read(uint64_t d){assert(d<2);return hcr[d];}
void uw_vgic_hcr_write(uint64_t d,uint64_t v){assert(d<2);hcr[d]=v;}
uint64_t uw_vgic_vmcr_read(uint64_t d){assert(d<2);return vmcr[d];}
void uw_vgic_vmcr_write(uint64_t d,uint64_t v){assert(d<2);vmcr[d]=v;}
static void tick(void){current=0;frame[31]=0x40001000;assert(uw_handle_exit((uintptr_t)frame,0,UINT64_C(1)<<26,0,0)<2);assert(word(CONTROL+8)==0&&word(CONTROL+0x20)==3);}
static void input(const void *p,size_t n){assert(!physical_count&&n<=sizeof(physical));memcpy(physical,p,n);physical_head=0;physical_count=n;while(physical_count)tick();}
static uint64_t mode(void){return word(CONTROL+0x60);}
static uint64_t dropped(void){return word(CONTROL+0x68);}
static void select_(unsigned d){uint8_t bytes[]={30,(uint8_t)('0'+d)};input(bytes,2);assert(mode()==d);}
static uint64_t p9_mmio(unsigned offset,int writing,uint64_t value){
    uint64_t ipa=0x09000000+offset;
    // Actual stage2 data-abort path, Rt0, 32-bit UART access, valid syndrome.
    uint64_t esr=(UINT64_C(0x24)<<26)|(UINT64_C(1)<<25)|(UINT64_C(1)<<24)|(UINT64_C(2)<<22)|(writing?64:0);
    current=1;frame[0]=value;frame[31]=0x40101000;
    assert(uw_handle_exit((uintptr_t)frame,0,esr,ipa,ipa>>8)<2);
    assert(word(CONTROL+0x20)==3);return frame[0];
}
static void p9_output(const uint8_t *bytes,size_t n){for(size_t i=0;i<n;i++)p9_mmio(0,1,bytes[i]);}
static void linux_output(const uint8_t *bytes,size_t n){for(size_t i=0;i<n;i++)kw_serial_putc(bytes[i]);}
static void linux_input(const uint8_t *expected,size_t n){for(size_t i=0;i<n;i++)assert(kw_serial_try_read()==(256|expected[i]));assert(kw_serial_try_read()==0);}
static void p9_input(const uint8_t *expected,size_t n){for(size_t i=0;i<n;i++){assert(!(p9_mmio(0x18,0,0)&16));assert(p9_mmio(0,0,0)==expected[i]);}assert(p9_mmio(0x18,0,0)&16);}
static int contains(const uint8_t *p,size_t n,const char *s){size_t m=strlen(s);for(size_t i=0;i+m<=n;i++)if(!memcmp(p+i,s,m))return 1;return 0;}
static void canary(unsigned start,unsigned end){memset(CONTROL+start,0xa5,end-start);}
static void intact(unsigned start,unsigned end){for(unsigned i=start;i<end;i++)assert(CONTROL[i]==0xa5);}
static uint64_t hash(const uint8_t *p,size_t n){uint64_t h=0xcbf29ce484222325;while(n--)h=(h^*p++)*0x100000001b3;return h;}
static void ring_suffix(uint8_t *base,const uint8_t *bytes,size_t n,uint64_t first){for(size_t i=n>65536?n-65536:0;i<n;i++)assert(base[8+(first+i)%65536]==bytes[i]);}

static uint64_t coordinator_access(unsigned domain,uint64_t ipa,unsigned width,int writing,uint64_t value,unsigned sign,unsigned sf,unsigned rt){
    unsigned sas=width==1?0:width==2?1:width==4?2:3;
    uint64_t esr=(UINT64_C(0x24)<<26)|(UINT64_C(1)<<25)|(UINT64_C(1)<<24)|((uint64_t)sas<<22)|((uint64_t)rt<<16)|((uint64_t)sign<<21)|((uint64_t)sf<<15)|(writing?64:0)|5;
    current=domain;frame[31]=domain?0x40101000:0x40001000;
    if(rt!=31)frame[rt]=value;
    assert(uw_handle_exit((uintptr_t)frame,0,esr,ipa,ipa>>8)<2);
    assert(frame[31]==(domain?0x40101004:0x40001004));
    assert(word(CONTROL+0x20)==3);return rt==31?0:frame[rt];
}
static uint64_t coordinator_read(unsigned offset,unsigned width,unsigned sign,unsigned sf){return coordinator_access(0,0x09001000+offset,width,0,UINT64_MAX,sign,sf,10);}
static void coordinator_write(unsigned offset,unsigned width,uint64_t value){coordinator_access(0,0x09001000+offset,width,1,value,0,0,10);}
static void coordinator_dispatch_widths(void){
    // Actual Linux R7 syndrome934a0045: STRH W10,[UART_IMSC]. Drive the
    // production unified dispatcher rather than calling its device directly.
    current=0;frame[10]=UINT64_C(0xdeadbeef00000555);frame[31]=0x40001000;
    assert(uw_handle_exit((uintptr_t)frame,0,0x934a0045,0x09001038,0x09001038>>8)<2);
    assert(word(CONTROL+0x20)==3&&frame[31]==0x40001004&&coordinator_read(0x38,2,0,0)==0x555);
    coordinator_write(0x38,1,UINT64_C(0xdeadbeef000007ff));assert(coordinator_read(0x38,4,0,0)==0xff);
    coordinator_write(0x38,2,0x555);assert(coordinator_read(0x38,1,0,0)==0x55);
    coordinator_write(0x24,4,UINT64_C(0xdeadbeef000080ff));
    assert(coordinator_read(0x24,2,0,0)==0x80ff&&coordinator_read(0x24,1,0,0)==0xff);
    assert(coordinator_read(0x24,2,1,1)==UINT64_C(0xffffffffffff80ff));
    assert(coordinator_read(0x24,2,1,0)==UINT64_C(0xffff80ff));
    assert(coordinator_read(0x24,1,1,1)==UINT64_MAX&&coordinator_read(0x24,1,1,0)==UINT32_MAX);
    assert(coordinator_read(0x24,4,0,0)==0x80ff); // W destination clears stale high bits.
    coordinator_access(0,0x09001038,2,1,UINT64_MAX,0,0,31);assert(coordinator_read(0x38,2,0,0)==0); // STRH WZR.
    coordinator_access(0,0x09001024,2,0,0,0,0,31); // LDRH WZR still advances PC.
    // The same IPA is the ORIGINAL Plan9's namespace UART, not this device.
    assert(p9_mmio(0x38,0,0)==0);p9_mmio(0x38,1,0x40);
    assert(coordinator_read(0x38,2,0,0)==0&&p9_mmio(0x38,0,0)==0x40);
    coordinator_write(0x38,2,0x55);assert(p9_mmio(0x38,0,0)==0x40);
    p9_mmio(0x38,1,0);
    // Native private TX is separate from BOTH operator console output rings.
    uint64_t lp=word(LINUXBASE),pp=word(P9BASE),private=word((void*)0x6d080000);
    coordinator_write(0x30,2,0x301);coordinator_write(0,1,30);coordinator_write(0,2,'1');
    assert(word((void*)0x6d080000)==private+2&&*(uint8_t*)(0x6d080008+private%65536)==30&&*(uint8_t*)(0x6d080008+(private+1)%65536)=='1');
    assert(mode()==0&&word(LINUXBASE)==lp&&word(P9BASE)==pp);
    // Inject is a trusted fixture hook here, not qualification of native op3.
    uint8_t *mail=(void*)0x6d060008;mail[0]=0x80;mail[1]=0xff;mail[2]=0;
    assert(CU(inject)(mail,3)==1);
    assert(coordinator_read(0,1,1,1)==UINT64_C(0xffffffffffffff80));
    assert(coordinator_read(0,2,1,0)==255&&coordinator_read(0,4,0,0)==0);
    assert(coordinator_read(0x18,2,0,0)&16);
    // Invalid bus widths/alignment contain only the source domain before any
    // device mutation. Fork isolates that intentional fail-stop from the rest
    // of this component fixture; it is not a VM or context-reset test.
    for(unsigned kind=0;kind<3;kind++){
        pid_t child=fork();assert(child>=0);
        if(!child){
            uint64_t before=word((void*)0x6d080000),mask=CU(mmio_read)(0x38);
            uint64_t ipa=kind==0?0x09001039:0x09001038;
            unsigned width=kind==1?8:2,domain=kind==2?1:0,sas=width==8?3:1;
            uint64_t esr=(UINT64_C(0x24)<<26)|(UINT64_C(1)<<25)|(UINT64_C(1)<<24)|((uint64_t)sas<<22)|(UINT64_C(10)<<16)|(kind==0?0:64)|5;
            current=domain;frame[10]=UINT64_MAX;frame[31]=domain?0x40101000:0x40001000;
            assert(uw_handle_exit((uintptr_t)frame,0,esr,ipa,ipa>>8)<2);
            assert(word(CONTROL+0x20)==(domain?1:2));
            assert(frame[31]==(domain?0x40101000:0x40001000));
            assert(word((void*)0x6d080000)==before&&CU(mmio_read)(0x38)==mask);
            _exit(0);
        }
        int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    }
    coordinator_write(0x38,2,0);assert(word(CONTROL+0x20)==3);
    puts("actual unified dispatcher byte/half/word Linux PL011 and domain-private width guards: PASS");
}

static void namespace_text(void){
    // A real native peer writes bytes resembling console commands. Only the
    // physical serial hook feeds route_input; names/file data grant no input.
    uint8_t req[256]={0},rep[8192];uint64_t session=S(session_init)(2,999);assert(session);
    #define PUT(at,v,n) do{uint64_t _v=(v);for(unsigned _i=0;_i<(n);_i++)req[(at)+_i]=(uint8_t)(_v>>(8*_i));}while(0)
    #define RPC(kind,n,expected) do{PUT(0,n,4);req[4]=(kind);assert(S(handle)(session,req,n,rep,sizeof(rep))>=7&&rep[4]==(expected));}while(0)
    PUT(7,8192,4);PUT(11,6,2);memcpy(req+13,"9P2000",6);RPC(100,19,101);
    memset(req,0,sizeof(req));PUT(7,1,4);PUT(11,UINT32_MAX,4);PUT(15,1,2);req[17]='x';PUT(18,0,2);RPC(104,20,105);
    memset(req,0,sizeof(req));PUT(7,1,4);PUT(11,7,2);memcpy(req+13,"control",7);PUT(20,0644,4);req[24]=2;RPC(114,25,115);
    uint8_t text[]={30,'1',30,'0',0,0x11,0x13,0xff};
    memset(req,0,sizeof(req));PUT(7,1,4);PUT(19,sizeof(text),4);memcpy(req+23,text,sizeof(text));RPC(118,23+sizeof(text),119);
    memset(req,0,sizeof(req));PUT(7,1,4);PUT(19,sizeof(text),4);RPC(116,23,117);assert(!memcmp(rep+11,text,sizeof(text)));
    tick();assert(mode()==0&&kw_serial_try_read()==0&&(p9_mmio(0x18,0,0)&16));
    puts("native namespace control-looking bytes confer no operator input authority: PASS");
}

int main(void){
    void *guard=mmap((void*)0x6bfff000,0x1093000,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);assert(guard==(void*)0x6bfff000);
    assert(!mprotect((void*)0x6c000000,0x1091000,PROT_READ|PROT_WRITE));
    assert(mmap((void*)0xb0000000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0xb0000000);
    putword(CONTROL,100);putword(CONTROL+0x10,1700000000);*(uint32_t*)0xb0000000=0xedfe0dd0;
    assert(uw_init()==1&&mode()==0&&word(CONTROL+0x20)==3);
    assert(word(LINUXBASE)==35&&word(P9BASE)==0&&!memcmp(LINUXBASE+8,"KW unified Linux/Plan9 EL2: online\n",35));
    coordinator_dispatch_widths();
    canary(0x100,0x10000);canary(0x11008,0x20000);canary(0x30008,0x40000);canary(0x50008,0x60000);
    namespace_text();uint64_t volume=hash((uint8_t*)0x6c000000,16777216);
    uint8_t binary[]={0,3,0x11,0x13,0x7f,0xff,'L',13,10};input(binary,sizeof(binary));linux_input(binary,sizeof(binary));p9_input(NULL,0);
    select_(1);input(binary,sizeof(binary));assert(kw_serial_try_read()==0);p9_input(binary,sizeof(binary));
    const uint8_t escaped[]={30,'0',30,'1',0,0x11,0x13,0xff};
    uint64_t lp=word(LINUXBASE),pp=word(P9BASE);size_t visible=display_count;
    linux_output(escaped,sizeof(escaped));assert(mode()==1&&display_count==visible&&word(P9BASE)==pp);
    assert(word(LINUXBASE)==lp+sizeof(escaped));ring_suffix(LINUXBASE,escaped,sizeof(escaped),lp);
    p9_output(escaped,sizeof(escaped));assert(mode()==1&&display_count==visible+sizeof(escaped));
    assert(!memcmp(display+visible,escaped,sizeof(escaped))&&word(P9BASE)==pp+sizeof(escaped));ring_suffix(P9BASE,escaped,sizeof(escaped),pp);
    select_(0);visible=display_count;pp=word(P9BASE);lp=word(LINUXBASE);
    p9_output(escaped,sizeof(escaped));assert(mode()==0&&display_count==visible&&word(LINUXBASE)==lp&&word(P9BASE)==pp+sizeof(escaped));
    linux_output(escaped,sizeof(escaped));assert(mode()==0&&display_count==visible+sizeof(escaped));
    assert(contains(LINUXBASE+8,(size_t)word(LINUXBASE),"[O-core console: original Plan 9")&&contains(LINUXBASE+8,(size_t)word(LINUXBASE),"[O-core console: Linux"));
    puts("physical-only selection, independent binary guest input and output rings: PASS");

    const uint8_t literal[]={30,30,'1',30,'x'};const uint8_t decoded[]={30,'1',30,'x'};
    input(literal,sizeof(literal));assert(mode()==0);linux_input(decoded,sizeof(decoded));
    input("\x1e",1);assert(mode()==0&&kw_serial_try_read()==0);input("1",1);assert(mode()==1);p9_input(NULL,0);
    input("\x1e\x1e",2);assert(mode()==1);const uint8_t prefix[]={30};p9_input(prefix,1);select_(0);
    // A full guest input queue never consumes the native operator switch.
    uint8_t many[8192];memset(many,'A',sizeof(many));input(many,4096);assert(dropped()==0);
    memset(many,'B',64);input(many,64);assert(dropped()==64);
    assert(contains(display,display_count,"O-core console input buffer full"));
    select_(1);input("p9",2);p9_input((const uint8_t*)"p9",2);select_(0);
    memset(many,'A',4096);linux_input(many,4096);
    select_(1);memset(many,'P',1024);input(many,1024);memset(many,'X',17);input(many,17);assert(dropped()==81);
    select_(0);input("linux",5);linux_input((const uint8_t*)"linux",5);select_(1);memset(many,'P',1024);p9_input(many,1024);select_(0);
    puts("literal/dangling prefix parsing and observable bounded input overrun: PASS");

    // Ring wrap is observable in each monotonic eight-byte header; only the
    // fixed65536-byte payload is overwritten, never the other guest's ring.
    uint8_t stream[70000];for(size_t i=0;i<sizeof(stream);i++)stream[i]=(uint8_t)(i*17+3);
    lp=word(LINUXBASE);pp=word(P9BASE);linux_output(stream,sizeof(stream));assert(word(LINUXBASE)==lp+sizeof(stream)&&word(P9BASE)==pp);ring_suffix(LINUXBASE,stream,sizeof(stream),lp);
    lp=word(LINUXBASE);p9_output(stream,sizeof(stream));assert(word(P9BASE)==pp+sizeof(stream)&&word(LINUXBASE)==lp);ring_suffix(P9BASE,stream,sizeof(stream),pp);
    intact(0x100,0x10000);intact(0x11008,0x20000);intact(0x30008,0x40000);intact(0x50008,0x60000);
    assert(hash((uint8_t*)0x6c000000,16777216)==volume&&dropped()==81&&mode()==0);
    puts("output ring headers/wrap, disjoint canaries and namespace preservation: PASS");
    puts("unified console mux production tests: PASS");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "production fixture requires Linux x86_64")
class UnifiedConsoleMuxTests(unittest.TestCase):
    def test_actual_mux_and_native_services_with_physical_input_fixture(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="unified-console-mux-") as directory:
            out = Path(directory)
            (out / "provider.oc").write_text(PROVIDER)
            (out / "harness.c").write_text(HARNESS)
            sources = [str(ROOT / name) for name in (
                "ocore/runtime/common/namespace_store.oc", "ocore/runtime/aarch64/plan9_namespace_uart.oc",
                "ocore/runtime/aarch64/coordinator_uart.oc",
                "ocore/runtime/aarch64/unified_gic.oc", "ocore/runtime/aarch64/unified_world.oc")]
            sources.append(str(out / "provider.oc"))
            commands = [
                [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(out / "arm.mir")],
                [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "mux.o")],
                [clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "mux.o"), "-o", str(out / "test")],
                [str(out / "test")],
            ]
            for command in commands:
                result = subprocess.run(command, text=True, capture_output=True, timeout=40)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("unified console mux production tests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
