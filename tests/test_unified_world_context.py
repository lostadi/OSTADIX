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
extern uint64_t uw_probe_domain_reset(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t uw_domain_configure(uint64_t,uint64_t,uint64_t),uw_domain_unconfigure(uint64_t);
extern uint64_t uw_domain_configured(uint64_t),uw_domain_ram_base(uint64_t),uw_domain_ram_bytes(uint64_t);
extern uint64_t uw_domain_root(uint64_t),uw_domain_vmid(uint64_t);
extern uint64_t uw_vgic_hcr_read(uint64_t);
extern uint64_t uw_current_domain(void),uw_counter_read(void),uw_counter_frequency(void),uw_irq_ack(void);
extern void uw_irq_eoi(uint64_t),uw_serial_putc(uint64_t);
extern void uw_vgic_hcr_write(uint64_t,uint64_t),uw_vgic_vmcr_write(uint64_t,uint64_t);
extern void uw_vgic_lr_write(uint64_t,uint64_t,uint64_t);
extern void uw_timer_write(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t uw_timer_read(uint64_t,uint64_t,uint64_t);
extern uint64_t uw_timer_deadline(uint64_t,uint64_t),uw_idle_until(uint64_t),uw_vgic_running_priority(uint64_t);
extern uint8_t guest_begin[],guest_end[];
void *memset(void *,int,size_t);
void *memcpy(void *,const void *,size_t);
#ifndef SECOND_DOMAIN
#define SECOND_DOMAIN 1
#endif
#ifndef RESET_TARGET
#define RESET_TARGET SECOND_DOMAIN
#endif
#define BANKS 8
static uint64_t deadline,period,visits[BANKS],previous[BANKS];
#ifdef RESET_STRESS
static uint64_t recycled,*target_context,*survivor_context;
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

#ifdef BANK_ADMISSION
static uint64_t boot_roots[2][512],boot_leaves[2][512];
static int banks_admission(void) {
    uint64_t root0=uw_domain_root(0),root1=uw_domain_root(1);
    if(!root0 || root1-root0!=4096 || uw_domain_vmid(0)!=1 || uw_domain_vmid(1)!=2
       || uw_domain_ram_base(0)!=0x48000000 || uw_domain_ram_base(1)!=0xb0000000
       || uw_domain_ram_bytes(0)!=0x20000000 || uw_domain_ram_bytes(1)!=0x20000000)return 0;
    for(unsigned d=0;d<2;d++){
        uint64_t *root=(uint64_t *)uw_domain_root(d),*leaf=(uint64_t *)(root[1]&~UINT64_C(4095));
        memcpy(boot_roots[d],root,4096);memcpy(boot_leaves[d],leaf,4096);
    }
    for(unsigned d=2;d<BANKS;d++)
        if(uw_domain_configured(d) || uw_domain_root(d) || uw_domain_vmid(d)
           || uw_domain_ram_base(d) || uw_domain_ram_bytes(d)
           || uw_domain_init(d,0x40000000,0,0x3c5)
           || uw_domain_reset(d,0x40000000,0,0x3c5) || uw_domain_unconfigure(d))return 0;
    if(uw_domain_configure(BANKS,0xe2200000,0x200000)
       || uw_domain_configure(2,0xe2200001,0x200000)
       || uw_domain_configure(2,0xe2200000,0)
       || uw_domain_configure(2,0xe2200000,0x200001)
       || uw_domain_configure(2,0xe2200000,0x20200000)
       || uw_domain_configure(2,UINT64_C(0xffffffffffe00000),0x200000)
       || uw_domain_configure(2,0xffe00000,0x400000)
       || uw_domain_configure(2,0x40000000,0x200000)
       || uw_domain_configure(2,0x6d000000,0x200000)
       || uw_domain_configure(2,0x6e000000,0x200000)
       || uw_domain_configure(2,0x70000000,0x200000)
       || uw_domain_configure(2,0xd2000000,0x200000)
       || uw_domain_configure(2,0xe2000000,0x200000)
       || uw_domain_configure(2,0xe2400000,0x200000)
       || uw_domain_configure(2,0x48000000,0x200000)
       || uw_domain_configure(2,0xcfe00000,0x200000))return 0;
    for(unsigned d=2;d<BANKS;d++) {
        uint64_t pa=UINT64_C(0xe2600000)+(d-2)*UINT64_C(0x200000);
        if(uw_domain_configure(d,pa,0x200000)!=1 || uw_domain_configured(d)!=1
           || uw_domain_ram_base(d)!=pa || uw_domain_ram_bytes(d)!=0x200000
           || uw_domain_vmid(d)!=d+1 || uw_domain_root(d)!=root0+d*4096
           || uw_domain_configure(d,pa,0x200000)
           || uw_domain_init(d,0x40200000,0,0x3c5)
           || uw_domain_init(d,0x40000001,0,0x3c5)
           || uw_domain_init(d,0x40000000,0,0)
           || uw_domain_init(d,0x40000000,d,0x3c5)!=1)return 0;
        uint64_t *root=(uint64_t *)uw_domain_root(d),*leaf=(uint64_t *)(root[1]&~UINT64_C(4095));
        if((root[1]&4095)!=3 || leaf[0]!=(pa|0x7fd))return 0;
        for(unsigned n=0;n<512;n++)if((n!=1 && root[n]) || (n && leaf[n]))return 0;
        uw_vgic_hcr_write(d,0x80+d);
        if(uw_vgic_hcr_read(d)!=0x80+d)return 0;
    }
    for(unsigned d=2;d<BANKS;d++)
        if(uw_domain_unconfigure(d)!=1 || uw_domain_configured(d) || uw_domain_root(d)
           || uw_domain_ram_base(d) || uw_domain_ram_bytes(d) || uw_domain_vmid(d)
           || uw_vgic_hcr_read(d) || uw_domain_unconfigure(d)
           || uw_domain_init(d,0x40000000,0,0x3c5)
           || uw_domain_reset(d,0x40000000,0,0x3c5))return 0;
    if(uw_domain_configure(2,0xe2200000,0x200000)!=1 || uw_domain_unconfigure(2)!=1)return 0;
    for(unsigned d=0;d<2;d++) {
        uint64_t *root=(uint64_t *)uw_domain_root(d),*leaf=(uint64_t *)(root[1]&~UINT64_C(4095));
        const uint8_t *a=(const uint8_t *)root,*b=(const uint8_t *)boot_roots[d];
        for(unsigned n=0;n<4096;n++)if(a[n]!=b[n])return 0;
        a=(const uint8_t *)leaf;b=(const uint8_t *)boot_leaves[d];
        for(unsigned n=0;n<4096;n++)if(a[n]!=b[n])return 0;
    }
    return 1;
}
#endif

static void out(const char *s) {while(*s)uw_serial_putc((uint8_t)*s++);}
static void hex(uint64_t v) {for(int i=60;i>=0;i-=4)uw_serial_putc("0123456789abcdef"[(v>>i)&15]);}
uint64_t uw_next_deadline(void) {return deadline;}
void uw_unexpected_exit(uint64_t esr,uint64_t far,uint64_t pc) {
    out("UNIFIED_CORE_UNEXPECTED ");hex(esr);out(" ");hex(far);out(" ");hex(pc);out("\n");
}
void uw_internal_failure(uint64_t reason,uint64_t a,uint64_t b,uint64_t c) {
    out("UNIFIED_CORE_INTERNAL ");hex(reason);out(" ");hex(a);out(" ");hex(b);out(" ");hex(c);out("\n");
}
uint64_t uw_init(void) {
    period=uw_counter_frequency()/100;
    uint64_t idle_deadline=uw_counter_read()+period;
    if(uw_idle_until(idle_deadline)!=26 || uw_counter_read()<idle_deadline) {
        out("UNIFIED_CORE_BOUNDED_IDLE_FAIL\n");return 0;
    }
    out("UNIFIED_CORE_BOUNDED_IDLE_PASS\n");
#ifdef BANK_ADMISSION
    if(!banks_admission()){out("UNIFIED_CORE_EIGHT_BANK_ADMISSION_FAIL\n");return 0;}
    out("UNIFIED_CORE_EIGHT_BANK_ADMISSION_PASS\n");
#endif
#if SECOND_DOMAIN != 1
    if(uw_domain_unconfigure(1)!=1 || uw_domain_configure(SECOND_DOMAIN,0xb0000000,0x20000000)!=1) {
        out("UNIFIED_CORE_HIGH_BANK_CONFIGURE_FAIL\n");return 0;
    }
#endif
    memcpy((void *)0x48000000,guest_begin,guest_end-guest_begin);
    memcpy((void *)0xb0000000,guest_begin,guest_end-guest_begin);
#ifdef RESET_STRESS
    tables(0x48000000);tables(0xb0000000);
#endif
    for(unsigned i=0;i<2;i++) {
        unsigned d=i?SECOND_DOMAIN:0;
        if(uw_domain_init(d,0x40000000,d?0x22:0x11,0x3c5)!=1)return 0;
        uw_vgic_hcr_write(d,1);uw_vgic_vmcr_write(d,(UINT64_C(255)<<24)|2);
#ifdef VIRTUAL_IRQ_STRESS
        uw_vgic_lr_write(d,0,(UINT64_C(1)<<62)|(UINT64_C(1)<<60)|(UINT64_C(0x80)<<48)|27);
#endif
        uw_timer_write(d,0,0,uw_counter_read()+1000000000+d*100000);
        uw_timer_write(d,0,1,3);
        uw_timer_write(d,1,0,0x12340000+d);uw_timer_write(d,1,1,0);
        if(uw_timer_deadline(d,0)!=UINT64_MAX || uw_timer_deadline(d,1)!=UINT64_MAX) {
            out("UNIFIED_CORE_MASKED_TIMER_DEADLINE_FAIL\n");return 0;
        }
        uw_timer_write(d,1,1,1);
        if(uw_timer_deadline(d,1)!=0x12340000+d) {out("UNIFIED_CORE_CNTP_DEADLINE_FAIL\n");return 0;}
        uw_timer_write(d,1,1,0);
        uw_timer_write(d,0,1,1);
        if(uw_timer_deadline(d,0)!=uw_timer_read(d,0,0)) {out("UNIFIED_CORE_CNTV_DEADLINE_FAIL\n");return 0;}
        uw_timer_write(d,0,1,3);
    }
    out("UNIFIED_CORE_STRESS_START\n");deadline=uw_counter_read()+period;return 1;
}
uint64_t uw_handle_exit(uint64_t *f,uint64_t reason,uint64_t esr,uint64_t far,uint64_t hpfar) {
    (void)hpfar;
    unsigned d=uw_current_domain();uint64_t marker=d?0x22:0x11;
#ifdef RESET_STRESS
    if(d==RESET_TARGET && recycled)marker=0x33;
#endif
    // The saved virtual timer deadline is in its offset counter domain;
    // native idle must convert it back without changing the retained bank.
    uint64_t original_offset=f[61],virtual_cval=uw_timer_read(d,0,0);
    f[61]=1234;uw_timer_write(d,0,1,1);
    if(uw_timer_deadline(d,0)!=virtual_cval+1234){out("UNIFIED_CORE_CNTVOFF_DEADLINE_FAIL\n");return BANKS;}
    f[61]=original_offset;uw_timer_write(d,0,1,3);
    uint64_t native_fpcr,native_fpsr,native_claim;__asm__ volatile("mrs %0,fpcr" : "=r"(native_fpcr));__asm__ volatile("mrs %0,fpsr" : "=r"(native_fpsr));__asm__ volatile("mrs %0,dbgclaimclr_el1" : "=r"(native_claim));
    if(native_fpcr || native_fpsr) {out("UNIFIED_CORE_NATIVE_FP_ENV_FAIL\n");return BANKS;}
    if(reason!=1) {
#ifdef VIRTUAL_IRQ_STRESS
        if((esr>>26)==1){f[31]+=4;return d?0:SECOND_DOMAIN;}
#endif
        uw_unexpected_exit(esr,far,f[31]);return BANKS;
    }
    uint64_t irq=uw_irq_ack();uw_irq_eoi(irq);
    if(irq!=26) {out("WRONG_PHYSICAL_IRQ ");hex(irq);return BANKS;}
    deadline=uw_counter_read()+period;
    // Preemption is legal even halfway through first-instruction bootstrap.
    // Count state assertions only after the guest's explicit setup marker.
    if(f[20]!=0xfeed)return d?0:SECOND_DOMAIN;
    if(f[65]!=((marker&1)<<22) || f[66]!=(marker&31)) {out("UNIFIED_CORE_FP_ENV_FAIL\n");return BANKS;}
    // Both EL1 programs keep IRQ/FIQ masked and execute no WFI/MMIO/HVC.
    // Physical EL2 timer preemption must still reach each world repeatedly.
    if(f[0]!=marker || !(f[32]&0x80) || f[10]<=previous[d] || f[47]!=marker
       || f[48]!=marker || f[49]!=marker || f[39]!=(marker<<12)
       || f[33]!=(0x40010000+(marker<<12)) || f[34]!=(0x40020000+(marker<<12))) {
        out("UNIFIED_CORE_GPR_SYSREG_FAIL ");hex(d);out(" ");hex(f[31]);out("\n");return BANKS;
    }
    const uint8_t *fp=(const uint8_t *)f+1024;
    for(unsigned q=0;q<32;q++)for(unsigned n=0;n<16;n++)if(fp[q*16+n]!=(uint8_t)(marker+q)) {
        out("UNIFIED_CORE_FP_FAIL ");hex(d);out(" ");hex(q);out("\n");return BANKS;
    }
    if(uw_timer_read(d,1,0)!=0x12340000+d || uw_timer_read(d,1,1)!=0) {
        out("UNIFIED_CORE_CNTP_SHADOW_FAIL\n");return BANKS;
    }
    if(native_claim || f[70]!=marker || ((f[68]>>1)&1)!=(marker&1) || f[69]!=(marker&1) || f[192]!=(marker<<12)
       || f[224]!=(marker<<20) || f[256]!=marker || f[288]!=marker || (f[79]>>32)!=marker) {
        out("UNIFIED_CORE_PMU_DEBUG_LOCK_FAIL ");hex(d);out(" ");hex(f[68]);out(" ");hex(f[69]);out(" ");hex(f[79]);out("\n");return BANKS;
    }
#ifdef VIRTUAL_IRQ_STRESS
    if(uw_vgic_running_priority(d)!=0x80 || f[11]!=27 || f[13]!=0x80 || !f[94] || (f[100]>>62)!=2) {
        out("UNIFIED_CORE_ACTIVE_IRQ_FAIL ");hex(d);out(" ");hex(f[11]);out(" ");hex(f[13]);out(" ");hex(f[94]);out(" ");hex(f[100]);out("\n");return BANKS;
    }
#endif
#ifdef RESET_STRESS
    if(!(f[35]&1) || (f[41]>>48)!=0x2a || f[12]!=(d==RESET_TARGET&&recycled?UINT64_C(0xaaaabbbbccccdddd):UINT64_C(0x1111222233334444))) {
        out("UNIFIED_CORE_RESET_TRANSLATION_FAIL ");hex(d);out(" ");hex(f[12]);out(" ");hex(f[41]);out("\n");return BANKS;
    }
    if(d==RESET_TARGET)target_context=f;else survivor_context=f;
#endif
    previous[d]=f[10];visits[d]++;
#ifdef RESET_STRESS
#ifdef SELF_RESET
    if(d==RESET_TARGET && !recycled && visits[0]>=5 && visits[SECOND_DOMAIN]>=5) {
#else
    if(d!=RESET_TARGET && !recycled && visits[RESET_TARGET]>=5) {
#endif
        // The target is stopped at its complete saved EL2 boundary. Keep its
        // old ASID and TTBR addresses, but
        // change an already-used non-global translation before recycling it.
        ((uint64_t *)(RESET_TARGET?0xb1100000:0x49100000))[256]=0x44000f01;
        __asm__ volatile("dsb sy" ::: "memory");
        memcpy(survivor_copy,survivor_context,4096);memcpy(target_copy,target_context,4096);
#if RESET_TARGET == 0
        // Exercise the exact Linux entry/DTB tuple through an ABI canary wrapper
        // before starting the common synthetic guest with its0x33 marker.
        if(uw_probe_domain_reset(0,0x40000000,0x47e00000,0x3c5)!=1) {
            out("UNIFIED_CORE_LINUX_RESET_TUPLE_ABI_FAIL\n");return BANKS;
        }
        for(unsigned n=0;n<512;n++) {
            uint64_t expected=0;
            if(n==0)expected=0x47e00000;if(n==31)expected=0x40000000;if(n==32)expected=0x3c5;
            if(n==35)expected=0x30d00800;if(n==37)expected=0x300000;if(n==64)expected=1;
            if(target_context[n]!=expected){out("UNIFIED_CORE_LINUX_RESET_TUPLE_BANK_FAIL\n");return BANKS;}
        }
        if(!same(survivor_copy,survivor_context,4096) || uw_current_domain()!=d) {
            out("UNIFIED_CORE_LINUX_RESET_TUPLE_SURVIVOR_FAIL\n");return BANKS;
        }
        out("UNIFIED_CORE_LINUX_RESET_TUPLE_ABI_PASS\n");
        memcpy(target_copy,target_context,4096);
#endif
        if(uw_domain_reset(2,0x40000000,0x33,0x3c5)!=0 || uw_domain_reset(RESET_TARGET,0x20000000,0x33,0x3c5)!=0
           || !same(target_copy,target_context,4096) || uw_probe_domain_reset(RESET_TARGET,0x40000000,0x33,0x3c5)!=1) {
            out("UNIFIED_CORE_RESET_ADMISSION_FAIL\n");return BANKS;
        }
        for(unsigned n=0;n<512;n++) {
            uint64_t expected=0;
            if(n==0)expected=0x33;if(n==31)expected=0x40000000;if(n==32)expected=0x3c5;
            if(n==35)expected=0x30d00800;if(n==37)expected=0x300000;if(n==64)expected=1;
            if(target_context[n]!=expected){out("UNIFIED_CORE_RESET_DIRTY_BANK_FAIL ");hex(n);out("\n");return BANKS;}
        }
        if(!same(survivor_copy,survivor_context,4096) || uw_current_domain()!=d){out("UNIFIED_CORE_RESET_SURVIVOR_FAIL\n");return BANKS;}
        recycled=1;previous[RESET_TARGET]=0;visits[RESET_TARGET]=0;
        uw_vgic_hcr_write(RESET_TARGET,1);uw_vgic_vmcr_write(RESET_TARGET,(UINT64_C(255)<<24)|2);
        uw_timer_write(RESET_TARGET,0,0,uw_counter_read()+1000000000);uw_timer_write(RESET_TARGET,0,1,3);
        uw_timer_write(RESET_TARGET,1,0,0x12340000+RESET_TARGET);uw_timer_write(RESET_TARGET,1,1,0);
        out("UNIFIED_CORE_RESET_BANK_CLEAR_PASS\n");deadline=uw_counter_read()+period;return RESET_TARGET;
    }
#endif
    if(visits[0]>=15 && visits[SECOND_DOMAIN]>=15) {
#ifdef RESET_STRESS
        if(!recycled){out("UNIFIED_CORE_RESET_NOT_EXERCISED_FAIL\n");return BANKS;}
        out("UNIFIED_CORE_RESET_TRANSLATION_SURVIVOR_PASS\n");
#endif
        out("UNIFIED_CORE_PREEMPTION_PASS\n");return BANKS;
    }
    return d?0:SECOND_DOMAIN;
}

// Return BANKS(8) makes a callee-saved-register violation an explicit failure.
__asm__(
".text\n"
".global uw_probe_domain_reset\n"
"uw_probe_domain_reset:\n"
"stp x19, x20, [sp, #-96]!\n"
"stp x21, x22, [sp, #16]\n"
"stp x23, x24, [sp, #32]\n"
"stp x25, x26, [sp, #48]\n"
"stp x27, x28, [sp, #64]\n"
"stp x29, x30, [sp, #80]\n"
"mov x19, #0x119\n"
"mov x20, #0x120\n"
"mov x21, #0x121\n"
"mov x22, #0x122\n"
"mov x23, #0x123\n"
"mov x24, #0x124\n"
"mov x25, #0x125\n"
"mov x26, #0x126\n"
"mov x27, #0x127\n"
"mov x28, #0x128\n"
"mov x29, #0x129\n"
"bl uw_domain_reset\n"
"mov x9, x0\n"
"cmp x19, #0x119\n"
"b.ne 9f\n"
"cmp x20, #0x120\n"
"b.ne 9f\n"
"cmp x21, #0x121\n"
"b.ne 9f\n"
"cmp x22, #0x122\n"
"b.ne 9f\n"
"cmp x23, #0x123\n"
"b.ne 9f\n"
"cmp x24, #0x124\n"
"b.ne 9f\n"
"cmp x25, #0x125\n"
"b.ne 9f\n"
"cmp x26, #0x126\n"
"b.ne 9f\n"
"cmp x27, #0x127\n"
"b.ne 9f\n"
"cmp x28, #0x128\n"
"b.ne 9f\n"
"cmp x29, #0x129\n"
"b.ne 9f\n"
"mov x0, x9\n"
"b 8f\n"
"9: mov x0, #8\n"
"8: ldp x21, x22, [sp, #16]\n"
"ldp x23, x24, [sp, #32]\n"
"ldp x25, x26, [sp, #48]\n"
"ldp x27, x28, [sp, #64]\n"
"ldp x29, x30, [sp, #80]\n"
"ldp x19, x20, [sp], #96\n"
"ret\n"
);
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

    def test_reset_of_last_current_domain_reselects_fresh_context_after_saved_el2_boundary(self):
        self.exercise(False, reset=True, self_reset=True)

    def test_all_eight_banks_admit_confined_ram_and_highest_bank_executes(self):
        self.exercise(False, second_domain=7, bank_admission=True)

    def test_highest_bank_reset_preserves_survivor_and_target_vmid_translation(self):
        self.exercise(False, reset=True, second_domain=7)

    def test_linux_slot_reset_preserves_survivor_and_callee_saved_registers(self):
        self.exercise(False, reset=True, reset_target=0)

    def test_reset_of_last_current_linux_slot_reselects_fresh_context(self):
        self.exercise(False, reset=True, self_reset=True, reset_target=0)

    def test_highest_bank_self_reset_reselects_fresh_context_and_preserves_callee_saved_registers(self):
        self.exercise(False, reset=True, self_reset=True, second_domain=7)

    def test_linux_slot_reset_preserves_highest_bank_survivor_and_callee_saved_registers(self):
        self.exercise(False, reset=True, second_domain=7, reset_target=0)

    def test_linux_self_reset_preserves_highest_bank_survivor_and_callee_saved_registers(self):
        self.exercise(False, reset=True, self_reset=True, second_domain=7, reset_target=0)

    def exercise(self, virtual_irq, reset=False, self_reset=False, second_domain=1, bank_admission=False, reset_target=None):
        self.assertIn(second_domain, (1, 7))
        reset_target = second_domain if reset_target is None else reset_target
        self.assertIn(reset_target, (0, second_domain))
        clang, linker, qemu = map(shutil.which, ("clang", "ld.lld", "qemu-system-aarch64"))
        if not all((clang, linker, qemu)):
            self.skipTest("AArch64 clang/lld and QEMU required")
        output = Path(tempfile.mkdtemp(prefix="ostadix-unified-context-"))
        (output / "fixture.c").write_text(C)
        (output / "guest.S").write_text(guest_source(virtual_irq,reset))
        commands = [[clang, "--target=aarch64-none-elf", "-march=armv8-a", "-c", str(CORE / "monitor.S"), "-o", str(output / "core.o")],
                    [clang, "--target=aarch64-none-elf", "-march=armv8-a", "-c", str(output / "guest.S"), "-o", str(output / "guest.o")],
                    [clang, "--target=aarch64-none-elf", "-O2", "-ffreestanding", "-mstrict-align", "-fno-stack-protector", *( ["-DVIRTUAL_IRQ_STRESS"] if virtual_irq else [] ), *( ["-DRESET_STRESS"] if reset else [] ), *( ["-DSELF_RESET"] if self_reset else [] ), f"-DSECOND_DOMAIN={second_domain}", f"-DRESET_TARGET={reset_target}", *( ["-DBANK_ADMISSION"] if bank_admission else [] ), "-c", str(output / "fixture.c"), "-o", str(output / "fixture.o")],
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
        if bank_admission:passed=passed and b"UNIFIED_CORE_EIGHT_BANK_ADMISSION_PASS\n" in received
        if reset and reset_target==0:passed=passed and b"UNIFIED_CORE_LINUX_RESET_TUPLE_ABI_PASS\n" in received
        (output / "result.json").write_text(json.dumps({"passed":passed,"argv":command,"second_domain":second_domain,"reset_target":reset_target,"self_reset":self_reset,"bank_admission":bank_admission,"scope":"synthetic actualEL2 context/preemption stress, not foreignOS qualification"},indent=2)+"\n")
        self.assertTrue(passed,received.decode(errors="replace")+"\nEvidence: "+str(output))
        print("Actual EL2 context/preemption evidence:",output)


if __name__ == "__main__":
    unittest.main()
