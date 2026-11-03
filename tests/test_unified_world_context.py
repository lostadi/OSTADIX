"""Actual EL2 timer preemption and two-world architectural state stress test.

These synthetic instruction loops test the scheduler core, not foreign OS
compatibility. Real Linux/9front qualification belongs to the unified runner.
"""
from pathlib import Path
import json
import os
import selectors
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "ocore/kernel/aarch64/unified_world"

C = r'''
#include <stdint.h>
#include <stddef.h>
extern uint64_t uw_domain_init(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t uw_domain_reset(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t uw_current_domain(void),uw_counter_read(void),uw_counter_frequency(void),uw_irq_ack(void);
extern void uw_irq_eoi(uint64_t),uw_serial_putc(uint64_t);
extern void uw_vgic_hcr_write(uint64_t,uint64_t),uw_vgic_vmcr_write(uint64_t,uint64_t);
extern void uw_vgic_lr_write(uint64_t,uint64_t,uint64_t);
extern void uw_timer_write(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t uw_timer_read(uint64_t,uint64_t,uint64_t);
extern uint8_t guest_begin[],guest_end[];
void *memset(void *,int,size_t);
void *memcpy(void *,const void *,size_t);
static uint64_t deadline,period,visits[2],previous[2];
#ifdef RESET_STRESS
static uint64_t recycled,*target_context;
static uint8_t survivor_copy[4096],target_copy[4096];
static int same(const void *a,const void *b,size_t n){const uint8_t*x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static void tables(uint64_t pa) {
    uint64_t *l1=(uint64_t *)(pa+0x1000000),*l2=(uint64_t *)(pa+0x1100000);
    memset(l1,0,4096);memset(l2,0,4096);l1[1]=0x41100003;
    for(unsigned i=0;i<256;i++)l2[i]=(UINT64_C(0x40000000)+(UINT64_C(0x200000)*i))|0xf01;
    l2[256]=0x42000f01;
    *(uint64_t *)(pa+0x2000000)=UINT64_C(0x1111222233334444);
    *(uint64_t *)(pa+0x4000000)=UINT64_C(0xaaaabbbbccccdddd);
}
#endif
void *memset(void *p,int value,size_t n) {uint8_t *d=p;while(n--)*d++=value;return p;}
void *memcpy(void *d,const void *s,size_t n) {uint8_t *a=d;const uint8_t *b=s;while(n--)*a++=*b++;return d;}
static void out(const char *s) {while(*s)uw_serial_putc((uint8_t)*s++);}
static void hex(uint64_t v) {for(int i=60;i>=0;i-=4)uw_serial_putc("0123456789abcdef"[(v>>i)&15]);}
uint64_t uw_next_deadline(void) {return deadline;}
void uw_unexpected_exit(uint64_t esr,uint64_t far,uint64_t pc) {
    out("UNIFIED_CORE_UNEXPECTED ");hex(esr);out(" ");hex(far);out(" ");hex(pc);out("\n");
}
uint64_t uw_init(void) {
    period=uw_counter_frequency()/100;
    memcpy((void *)0x48000000,guest_begin,guest_end-guest_begin);
    memcpy((void *)0xb0000000,guest_begin,guest_end-guest_begin);
#ifdef RESET_STRESS
    tables(0x48000000);tables(0xb0000000);
#endif
    for(unsigned d=0;d<2;d++) {
        if(uw_domain_init(d,0x40000000,d?0x22:0x11,0x3c5)!=1)return 0;
        uw_vgic_hcr_write(d,1);uw_vgic_vmcr_write(d,(UINT64_C(255)<<24)|2);
#ifdef VIRTUAL_IRQ_STRESS
        uw_vgic_lr_write(d,0,(UINT64_C(1)<<62)|(UINT64_C(1)<<60)|(UINT64_C(0x80)<<48)|27);
#endif
        uw_timer_write(d,0,0,uw_counter_read()+1000000000+d*100000);
        uw_timer_write(d,0,1,3);
        uw_timer_write(d,1,0,0x12340000+d);uw_timer_write(d,1,1,0);
    }
    out("UNIFIED_CORE_STRESS_START\n");deadline=uw_counter_read()+period;return 1;
}
uint64_t uw_handle_exit(uint64_t *f,uint64_t reason,uint64_t esr,uint64_t far,uint64_t hpfar) {
    (void)hpfar;
    unsigned d=uw_current_domain();uint64_t marker=d?0x22:0x11;
#ifdef RESET_STRESS
    if(d && recycled)marker=0x33;
#endif
    uint64_t native_fpcr,native_fpsr,native_claim;__asm__ volatile("mrs %0,fpcr" : "=r"(native_fpcr));__asm__ volatile("mrs %0,fpsr" : "=r"(native_fpsr));__asm__ volatile("mrs %0,dbgclaimclr_el1" : "=r"(native_claim));
    if(native_fpcr || native_fpsr) {out("UNIFIED_CORE_NATIVE_FP_ENV_FAIL\n");return 2;}
    if(reason!=1) {
#ifdef VIRTUAL_IRQ_STRESS
        if((esr>>26)==1){f[31]+=4;return 1-d;}
#endif
        uw_unexpected_exit(esr,far,f[31]);return 2;
    }
    uint64_t irq=uw_irq_ack();uw_irq_eoi(irq);
    if(irq!=26) {out("WRONG_PHYSICAL_IRQ ");hex(irq);return 2;}
    deadline=uw_counter_read()+period;
    // Preemption is legal even halfway through first-instruction bootstrap.
    // Count state assertions only after the guest's explicit setup marker.
    if(f[20]!=0xfeed)return 1-d;
    if(f[65]!=((marker&1)<<22) || f[66]!=(marker&31)) {out("UNIFIED_CORE_FP_ENV_FAIL\n");return 2;}
    // Both EL1 programs keep IRQ/FIQ masked and execute no WFI/MMIO/HVC.
    // Physical EL2 timer preemption must still reach each world repeatedly.
    if(f[0]!=marker || !(f[32]&0x80) || f[10]<=previous[d] || f[47]!=marker
       || f[48]!=marker || f[49]!=marker || f[39]!=(marker<<12)
       || f[33]!=(0x40010000+(marker<<12)) || f[34]!=(0x40020000+(marker<<12))) {
        out("UNIFIED_CORE_GPR_SYSREG_FAIL ");hex(d);out(" ");hex(f[31]);out("\n");return 2;
    }
    const uint8_t *fp=(const uint8_t *)f+1024;
    for(unsigned q=0;q<32;q++)for(unsigned n=0;n<16;n++)if(fp[q*16+n]!=(uint8_t)(marker+q)) {
        out("UNIFIED_CORE_FP_FAIL ");hex(d);out(" ");hex(q);out("\n");return 2;
    }
    if(uw_timer_read(d,1,0)!=0x12340000+d || uw_timer_read(d,1,1)!=0) {
        out("UNIFIED_CORE_CNTP_SHADOW_FAIL\n");return 2;
    }
    if(native_claim || f[70]!=marker || ((f[68]>>1)&1)!=(marker&1) || f[69]!=(marker&1) || f[192]!=(marker<<12)
       || f[224]!=(marker<<20) || f[256]!=marker || f[288]!=marker || (f[79]>>32)!=marker) {
        out("UNIFIED_CORE_PMU_DEBUG_LOCK_FAIL ");hex(d);out(" ");hex(f[68]);out(" ");hex(f[69]);out(" ");hex(f[79]);out("\n");return 2;
    }
#ifdef VIRTUAL_IRQ_STRESS
    if(f[11]!=27 || f[13]!=0x80 || !f[94] || (f[100]>>62)!=2) {
        out("UNIFIED_CORE_ACTIVE_IRQ_FAIL ");hex(d);out(" ");hex(f[11]);out(" ");hex(f[13]);out(" ");hex(f[94]);out(" ");hex(f[100]);out("\n");return 2;
    }
#endif
#ifdef RESET_STRESS
    if(!(f[35]&1) || (f[41]>>48)!=0x2a || f[12]!=(d&&recycled?UINT64_C(0xaaaabbbbccccdddd):UINT64_C(0x1111222233334444))) {
        out("UNIFIED_CORE_RESET_TRANSLATION_FAIL ");hex(d);out(" ");hex(f[12]);out(" ");hex(f[41]);out("\n");return 2;
    }
    if(d)target_context=f;
#endif
    previous[d]=f[10];visits[d]++;
#ifdef RESET_STRESS
    if(!d && !recycled && visits[1]>=5) {
        // Target1 is not running. Keep its old ASID and TTBR addresses, but
        // change an already-used non-global translation before recycling it.
        ((uint64_t *)0xb1100000)[256]=0x44000f01;
        __asm__ volatile("dsb sy" ::: "memory");
        memcpy(survivor_copy,f,4096);memcpy(target_copy,target_context,4096);
        if(uw_domain_reset(2,0x40000000,0x33,0x3c5)!=0 || uw_domain_reset(1,0x20000000,0x33,0x3c5)!=0
           || !same(target_copy,target_context,4096) || uw_domain_reset(1,0x40000000,0x33,0x3c5)!=1) {
            out("UNIFIED_CORE_RESET_ADMISSION_FAIL\n");return 2;
        }
        for(unsigned n=0;n<512;n++) {
            uint64_t expected=0;
            if(n==0)expected=0x33;if(n==31)expected=0x40000000;if(n==32)expected=0x3c5;
            if(n==35)expected=0x30d00800;if(n==37)expected=0x300000;if(n==64)expected=1;
            if(target_context[n]!=expected){out("UNIFIED_CORE_RESET_DIRTY_BANK_FAIL ");hex(n);out("\n");return 2;}
        }
        if(!same(survivor_copy,f,4096) || uw_current_domain()!=0){out("UNIFIED_CORE_RESET_SURVIVOR_FAIL\n");return 2;}
        recycled=1;previous[1]=0;visits[1]=0;
        uw_vgic_hcr_write(1,1);uw_vgic_vmcr_write(1,(UINT64_C(255)<<24)|2);
        uw_timer_write(1,0,0,uw_counter_read()+1000000000);uw_timer_write(1,0,1,3);
        uw_timer_write(1,1,0,0x12340001);uw_timer_write(1,1,1,0);
        out("UNIFIED_CORE_RESET_BANK_CLEAR_PASS\n");deadline=uw_counter_read()+period;return 1;
    }
#endif
    if(visits[0]>=15 && visits[1]>=15) {
#ifdef RESET_STRESS
        if(!recycled){out("UNIFIED_CORE_RESET_NOT_EXERCISED_FAIL\n");return 2;}
        out("UNIFIED_CORE_RESET_TRANSLATION_SURVIVOR_PASS\n");
#endif
        out("UNIFIED_CORE_PREEMPTION_PASS\n");return 2;
    }
    return 1-d;
}
'''


def guest_source(virtual_irq=False, reset=False):
    source = ".arch armv8-a\n.section .text.guest,\"ax\"\n.balign 2048\n.global guest_begin,guest_end\nguest_begin:\n"
    source += "msr daifset,#15\nmsr tpidr_el0,x0\nmsr tpidrro_el0,x0\nmsr tpidr_el1,x0\n"
    source += "lsl x3,x0,#12\nmsr contextidr_el1,x3\nmov x4,#0x40010000\nadd x4,x4,x3\nmsr sp_el0,x4\n"
    source += "mov x4,#0x40020000\nadd x4,x4,x3\nmov sp,x4\n"
    source += "and w3,w0,#1\nlsl x3,x3,#22\nmsr fpcr,x3\nand w3,w0,#31\nmsr fpsr,x3\n"
    source += "msr osdlr_el1,xzr\nmsr oslar_el1,xzr\nlsl x3,x0,#12\nmsr dbgbvr0_el1,x3\nmsr dbgbcr0_el1,xzr\nlsl x3,x0,#20\nmsr dbgwvr0_el1,x3\nmsr dbgwcr0_el1,xzr\n"
    source += "mov x3,#255\nmsr dbgclaimclr_el1,x3\nmsr dbgclaimset_el1,x0\n"
    source += "mov x3,#0x47\nmsr pmcr_el0,x3\nmsr pmevcntr0_el0,x0\nmsr pmevtyper0_el0,x0\nlsl x3,x0,#32\nmsr pmccntr_el0,x3\nmov x3,#0x80000000\nmsr pmcntenset_el0,x3\n"
    source += "and x3,x0,#1\nmsr oslar_el1,x3\nmsr osdlr_el1,x3\n"
    for q in range(32):
        source += f"add w3,w0,#{q}\ndup v{q}.16b,w3\n"
    source += "mov x10,#0\n"
    if reset:
        source += "mov x3,#255\nmsr mair_el1,x3\nmovz x3,#0x4100,lsl #16\nmovk x3,#0x2a,lsl #48\nmsr ttbr0_el1,x3\nmovz x3,#0x3519\nmovk x3,#0x80,lsl #16\nmsr tcr_el1,x3\ndsb sy\nisb\nmrs x3,sctlr_el1\norr x3,x3,#1\nmsr sctlr_el1,x3\nisb\nmov x14,#0x60000000\n"
    if virtual_irq:
        source += "adr x4,guest_vectors\nmsr vbar_el1,x4\nisb\nmsr daifclr,#2\n1: wfi\nb 1b\n"
        source += ".balign 2048\nguest_vectors:\n"
        for slot in range(16):
            source += ("b guest_irq\n" if slot==5 else "b guest_fault\n")+".space 124\n"
        source += "guest_irq:\nmsr daifset,#15\nmrs x11,icc_iar1_el1\nmov x20,#0xfeed\n2: mrs x13,icc_rpr_el1\nadd x10,x10,#1\nb 2b\nguest_fault: hvc #0\nb guest_fault\n"
    else:
        source += ("ldr x12,[x14]\nmov x20,#0xfeed\n1: ldr x12,[x14]\nadd x10,x10,#1\nb 1b\n" if reset else "mov x20,#0xfeed\n1: add x10,x10,#1\nb 1b\n")
    source += "guest_end:\n"
    return source


class UnifiedContextTests(unittest.TestCase):
    def test_actual_el2_preempts_two_irq_masked_cpu_bound_worlds(self):
        self.exercise(False)

    def test_preemption_preserves_active_virtual_irq_priority_and_lr_banks(self):
        self.exercise(True)

    def test_reset_clears_target_archstate_reuses_asid_safely_and_preserves_other_world(self):
        # Pair observable MMU reuse with a source guard: QEMU may itself flush
        # some translations on SCTLR writes, so the explicit architectural
        # VMID-scoped invalidation remains a required production instruction.
        reset_code=(CORE / "monitor.S").read_text().split("uw_domain_reset:",1)[1].split("uw_stage2_init:",1)[0]
        self.assertIn("tlbi vmalls12e1is",reset_code)
        self.assertLess(reset_code.index("msr vttbr_el2, x4"),reset_code.index("tlbi vmalls12e1is"))
        self.assertGreater(reset_code.index("msr vttbr_el2, x6"),reset_code.index("tlbi vmalls12e1is"))
        self.exercise(False, reset=True)

    def exercise(self, virtual_irq, reset=False):
        clang, linker, qemu = map(shutil.which, ("clang", "ld.lld", "qemu-system-aarch64"))
        if not all((clang, linker, qemu)):
            self.skipTest("AArch64 clang/lld and QEMU required")
        output = Path(tempfile.mkdtemp(prefix="ostadix-unified-context-"))
        (output / "fixture.c").write_text(C)
        (output / "guest.S").write_text(guest_source(virtual_irq,reset))
        commands = [[clang, "--target=aarch64-none-elf", "-march=armv8-a", "-c", str(CORE / "monitor.S"), "-o", str(output / "core.o")],
                    [clang, "--target=aarch64-none-elf", "-march=armv8-a", "-c", str(output / "guest.S"), "-o", str(output / "guest.o")],
                    [clang, "--target=aarch64-none-elf", "-O2", "-ffreestanding", "-fno-stack-protector", *( ["-DVIRTUAL_IRQ_STRESS"] if virtual_irq else [] ), *( ["-DRESET_STRESS"] if reset else [] ), "-c", str(output / "fixture.c"), "-o", str(output / "fixture.o")],
                    [linker, "-m", "aarch64elf", "-nostdlib", "--build-id=none", "-T", str(CORE / "linker.ld"), "-o", str(output / "test.elf"), str(output / "core.o"), str(output / "guest.o"), str(output / "fixture.o")]]
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr + "\nEvidence: " + str(output))
        command = [qemu, "-machine", "virt,virtualization=on,gic-version=3,its=off", "-cpu", "cortex-a57", "-smp", "1", "-m", "3G", "-accel", "tcg,thread=single", "-nodefaults", "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot", "-kernel", str(output / "test.elf")]
        received = bytearray()
        with (output / "stderr.log").open("wb") as errors:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, stdin=subprocess.DEVNULL)
            selector = selectors.DefaultSelector();selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic()+20
            try:
                while time.monotonic()<deadline and process.poll() is None:
                    for key,_ in selector.select(0.05):
                        received.extend(os.read(key.fileobj.fileno(),65536))
                    if b"UNIFIED_CORE_PREEMPTION_PASS\n" in received or b"FAIL" in received or b"UNEXPECTED" in received:break
            finally:
                process.terminate();process.wait(timeout=3);selector.close();process.stdout.close()
        (output / "console.log").write_bytes(received)
        passed=b"UNIFIED_CORE_PREEMPTION_PASS\n" in received
        if reset:passed=passed and b"UNIFIED_CORE_RESET_BANK_CLEAR_PASS\n" in received and b"UNIFIED_CORE_RESET_TRANSLATION_SURVIVOR_PASS\n" in received
        (output / "result.json").write_text(json.dumps({"passed":passed,"argv":command,"scope":"synthetic actualEL2 context/preemption stress, not foreignOS qualification"},indent=2)+"\n")
        self.assertTrue(passed,received.decode(errors="replace")+"\nEvidence: "+str(output))
        print("Actual EL2 context/preemption evidence:",output)


if __name__ == "__main__":
    unittest.main()
