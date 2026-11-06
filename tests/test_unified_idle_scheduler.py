"""Execute production native WFI admission with explicit hardware/time hooks.

The C fixture supplies saved CPU banks, counter/IRQ inputs and physical idle;
all scheduling, wake decisions, device mediation and domain control are actual
O-core objects. These tests do not qualify original guest boot or host CPU use.
"""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_unified_console_mux as mux

ROOT = Path(__file__).resolve().parents[1]

HOOKS = r'''
#define G(n) _O_runtime__aarch64__unified_gic__##n
extern uint64_t G(mmio_write)(uint64_t,uint64_t,uint64_t,uint64_t),G(mmio_read)(uint64_t,uint64_t,uint64_t);
extern uint64_t G(set_level)(uint64_t,uint64_t,uint64_t),G(wake_pending)(uint64_t);
extern uint64_t uw_next_deadline(void);
extern uint64_t CU(mmio_write)(uint64_t,uint64_t);
extern void kw_uart_irq_level(uint64_t);
static uint64_t timer_ctl[2][2],timer_cval[2][2],running[2]={255,255};
static uint64_t idle_calls,first_idle_deadline,wake_action,inject_during_progress;
uint64_t uw_counter_read(void){return now;}
uint64_t uw_timer_deadline(uint64_t d,uint64_t k){assert(d<2&&k<2);return timer_ctl[d][k]==1?timer_cval[d][k]:UINT64_MAX;}
uint64_t uw_timer_pending(uint64_t d,uint64_t k){
    assert(d<2&&k<2);
    if(inject_during_progress){inject_during_progress=0;assert(G(set_level)(0,33,1));}
    return timer_ctl[d][k]==1&&timer_cval[d][k]<=now;
}
uint64_t uw_vgic_running_priority(uint64_t d){assert(d<2);return running[d];}
uint64_t uw_idle_until(uint64_t deadline){
    assert(deadline>now && deadline-now<=5000 && word(CONTROL+8)==0 && word(CONTROL+0xa0)==((wake_action==5&&idle_calls)?1:3));
    if(!idle_calls)first_idle_deadline=deadline;
    idle_calls++;assert(idle_calls<8);now=deadline;
    if(wake_action==5){
        if(idle_calls==1){putword(CONTROL+0x78,1);putword(CONTROL+0x70,1);}
        else{assert(idle_calls==2&&word(CONTROL+0x20)==1&&word(CONTROL+0x88)==1);putword(CONTROL+0x78,2);putword(CONTROL+0x70,2);}
    }else if(wake_action==1){assert(timer_ctl[0][1]==1&&now==timer_cval[0][1]);}
    else if(idle_calls==3){
        if(wake_action==2){
            // The native mailbox, not a shared text marker, injects a byte.
            putword((void*)0x6d060000,1);*(uint8_t*)0x6d060008='C';
            putword(CONTROL+0x78,3);putword(CONTROL+0x70,1);
        }else if(wake_action==3){assert(G(set_level)(0,33,1));}
        else if(wake_action==4){
            // Physical keyboard input, with Linux's poll callback raising IRQ.
            physical[0]='K';physical_head=0;physical_count=1;
            inject_during_progress=1;
        }else abort();
    }
    return 26;
}
static void ready_irq(unsigned d,unsigned irq,unsigned priority){
    uint64_t base=irq<32?0x080b0000:0x08000000;
    assert(G(mmio_write)(d,0x080a0014,4,0));
    assert(G(mmio_write)(d,0x08000000,4,0x13));
    uint64_t a=base+0x80+(irq/32)*4;
    assert(G(mmio_write)(d,a,4,G(mmio_read)(d,a,4)|(UINT64_C(1)<<(irq%32))));
    assert(G(mmio_write)(d,base+0x100+(irq/32)*4,4,UINT64_C(1)<<(irq%32)));
    assert(G(mmio_write)(d,base+0x400+irq,1,priority));
}
static uint64_t wait_(unsigned d,int wfe){current=d;frame[31]=0x40008000+d*4096;frame[32]=0x3c5;
    uint64_t answer=uw_handle_exit((uintptr_t)frame,0,(UINT64_C(1)<<26)|wfe,0,0);
    assert(frame[31]==0x40008004+d*4096);return answer;}
static void setup(void){
    assert(mmap((void*)0x6c000000,0x1091000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0x6c000000);
    assert(mmap((void*)0xb0000000,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0xb0000000);
    putword(CONTROL,100);putword(CONTROL+0x10,1700000000);*(uint32_t*)0xb0000000=0xedfe0dd0;
    assert(uw_init()==1);
}
'''

MAIN = r'''
int main(int argc,char **argv){
    assert(argc==2);setup();
    if(!strcmp(argv[1],"park-one")){
        assert(wait_(0,0)==1 && word(CONTROL+0xa0)==1 && !idle_calls);
        for(unsigned n=0;n<50;n++){p9_mmio(0x18,0,0);assert(word(CONTROL+0xa0)==1&&!idle_calls);}
        assert(wait_(1,1)==1&&word(CONTROL+0xa0)==1&&!idle_calls);
    }else if(!strcmp(argv[1],"pending-and-race")){
        ready_irq(0,33,0x80);inject_during_progress=1;
        assert(wait_(0,0)==1&&word(CONTROL+0xa0)==0&&!idle_calls);
        assert(G(wake_pending)(0)==1); // PSTATE.I is set in the real frame.
        assert(wait_(1,1)==0&&word(CONTROL+0xa0)==0);
    }else if(!strcmp(argv[1],"timer")){
        ready_irq(0,30,0x80);timer_ctl[0][1]=1;timer_cval[0][1]=now+123;
        assert(uw_next_deadline()==timer_cval[0][1]);
        assert(wait_(0,0)==1);wake_action=1;
        assert(wait_(1,0)==0&&idle_calls==1&&first_idle_deadline==100123);
        assert(word(CONTROL+0xa0)==2&&word(CONTROL+0xa8)==1);
    }else if(!strcmp(argv[1],"masked-timer")){
        ready_irq(0,33,0x80);timer_ctl[0][0]=3;timer_cval[0][0]=now+1;
        timer_ctl[1][1]=0;timer_cval[1][1]=now+2;
        assert(uw_next_deadline()==now+10000);
        assert(wait_(0,0)==1);wake_action=3;
        assert(wait_(1,0)==0&&idle_calls==3&&first_idle_deadline==105000);
        assert(word(CONTROL+0xa0)==2);
    }else if(!strcmp(argv[1],"native-mailbox")){
        ready_irq(0,51,0x80);assert(CU(mmio_write)(0x30,0x301));assert(CU(mmio_write)(0x38,0x50));
        assert(wait_(0,0)==1);wake_action=2;
        assert(wait_(1,0)==0&&idle_calls==3&&word(CONTROL+0x80)==1&&word(CONTROL+0x88)==1);
        assert(CU(mmio_read)(0)=='C'&&word(CONTROL+0xa0)==2);
    }else if(!strcmp(argv[1],"keyboard")){
        ready_irq(0,33,0x80);assert(wait_(0,0)==1);wake_action=4;
        assert(wait_(1,0)==0&&idle_calls==3&&kw_serial_try_read()==('K'|256));
        assert(word(CONTROL+0xa0)==2);
    }else if(!strcmp(argv[1],"withdraw-restart")){
        assert(mmap((void*)0xb0001000,0x21000000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0xb0001000);
        *(uint64_t*)0xd0000000=UINT64_C(0x1122334455667788);*(uint32_t*)0xd1000000=0xedfe0dd0;
        putword(CONTROL+0x90,8);putword(CONTROL+0x98,4);
        assert(wait_(0,0)==1&&word(CONTROL+0xa0)==1);
        // Both guests park. The private host writes pause then restart while
        // native_current still names Plan9; no idle Linux reentry is needed.
        wake_action=5;assert(wait_(1,0)==1);
        assert(idle_calls==2&&word(CONTROL+0x20)==3&&word(CONTROL+0xa0)==1&&word(CONTROL+0x88)==1);
        assert(*(uint64_t*)0xb0100000==UINT64_C(0x1122334455667788));
    }else if(!strcmp(argv[1],"wake-filter")){
        ready_irq(0,33,0x80);assert(G(set_level)(0,33,1));assert(G(wake_pending)(0)==1);
        vmcr[0]=(0x80u<<24)|2;assert(G(wake_pending)(0)==0); // equal PMR masks
        vmcr[0]=(0xffu<<24);assert(G(wake_pending)(0)==0); // group disabled
        vmcr[0]=(0xffu<<24)|2;hcr[0]=0;assert(G(wake_pending)(0)==0);hcr[0]=1;
        running[0]=0x40;assert(G(wake_pending)(0)==0);running[0]=0xc0;assert(G(wake_pending)(0)==1);
        vmcr[0]=(0xffu<<24)|(7u<<18)|2;running[0]=0x88;assert(G(wake_pending)(0)==0); // same group priority
        running[0]=0xff;assert(G(wake_pending)(0)==1);
        for(unsigned i=0;i<4;i++)if(bank[0][i]>>62)bank[0][i]=(bank[0][i]&~(UINT64_C(1)<<62))|(UINT64_C(1)<<63);
        assert(G(wake_pending)(0)==0); // active is not an asserted interrupt
    }else abort();
    printf("production idle scheduler %s: PASS\n",argv[1]);return 0;
}
'''


def harness():
    text = mux.HARNESS.split("int main(void){", 1)[0]
    for needle in (
        "uint64_t uw_counter_read(void)", "uint64_t uw_timer_deadline(uint64_t d,uint64_t kind)",
        "uint64_t uw_idle_until(uint64_t deadline)", "uint64_t uw_timer_pending(uint64_t d,uint64_t kind)",
        "uint64_t uw_vgic_running_priority(uint64_t d)",
    ):
        start = text.index(needle)
        end = text.index("\n", start)
        text = text[:start] + text[end+1:]
    return text + HOOKS + MAIN


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native fixture requires Linux x86_64")
class UnifiedIdleSchedulerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            raise unittest.SkipTest("already-built ocorec and clang are required")
        cls.directory = Path(tempfile.mkdtemp(prefix="unified-native-idle-"))
        out = cls.directory
        (out / "provider.oc").write_text(mux.PROVIDER)
        (out / "harness.c").write_text(harness())
        sources = [str(ROOT / name) for name in (
            "ocore/runtime/common/namespace_store.oc", "ocore/runtime/aarch64/plan9_namespace_uart.oc",
            "ocore/runtime/aarch64/coordinator_uart.oc", "ocore/runtime/aarch64/unified_gic.oc",
            "ocore/runtime/aarch64/unified_world.oc")]+[str(out / "provider.oc")]
        commands = [
            [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(out / "arm.mir")],
            [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "scheduler.o")],
            [clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "scheduler.o"), "-o", str(out / "test")],
        ]
        for i, command in enumerate(commands):
            result = subprocess.run(command, text=True, capture_output=True, timeout=60)
            (out / f"build-{i}.log").write_text(result.stdout+result.stderr)
            if result.returncode:
                raise AssertionError(result.stdout+result.stderr+"\nEvidence: "+str(out))

    def check_scenario(self, scenario):
        result = subprocess.run([str(self.directory / "test"), scenario], text=True, capture_output=True, timeout=15)
        (self.directory / (scenario+".log")).write_text(result.stdout+result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr+"\nEvidence: "+str(self.directory))
        self.assertIn("PASS", result.stdout)

    def test_parked_guest_is_not_selected_by_other_mmio_or_wfe(self): self.check_scenario("park-one")
    def test_pending_irq_and_progress_arrival_wake_despite_pstate_i(self): self.check_scenario("pending-and-race")
    def test_both_parked_sleep_to_earliest_guest_timer(self): self.check_scenario("timer")
    def test_disabled_masked_timers_do_not_busy_loop(self): self.check_scenario("masked-timer")
    def test_native_mailbox_progress_wakes_with_both_guests_parked(self): self.check_scenario("native-mailbox")
    def test_physical_keyboard_progress_wakes_parked_linux(self): self.check_scenario("keyboard")
    def test_withdraw_restart_does_not_require_running_a_parked_linux(self): self.check_scenario("withdraw-restart")
    def test_wake_predicate_respects_priority_group_apr_and_active_state(self): self.check_scenario("wake-filter")


if __name__ == "__main__": unittest.main()
