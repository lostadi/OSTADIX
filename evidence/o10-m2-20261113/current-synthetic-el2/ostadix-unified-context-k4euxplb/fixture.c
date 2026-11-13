
#include <stdint.h>
#include <stddef.h>
#ifndef RESET_TARGET
#define RESET_TARGET 1
#endif
extern uint64_t uw_domain_init(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t uw_domain_reset(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t uw_probe_domain_reset(uint64_t,uint64_t,uint64_t,uint64_t);
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
static uint64_t deadline,period,visits[2],previous[2];
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
    if(uw_timer_deadline(d,0)!=virtual_cval+1234){out("UNIFIED_CORE_CNTVOFF_DEADLINE_FAIL\n");return 2;}
    f[61]=original_offset;uw_timer_write(d,0,1,3);
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
    if(uw_vgic_running_priority(d)!=0x80 || f[11]!=27 || f[13]!=0x80 || !f[94] || (f[100]>>62)!=2) {
        out("UNIFIED_CORE_ACTIVE_IRQ_FAIL ");hex(d);out(" ");hex(f[11]);out(" ");hex(f[13]);out(" ");hex(f[94]);out(" ");hex(f[100]);out("\n");return 2;
    }
#endif
#ifdef RESET_STRESS
    if(!(f[35]&1) || (f[41]>>48)!=0x2a || f[12]!=(d==RESET_TARGET&&recycled?UINT64_C(0xaaaabbbbccccdddd):UINT64_C(0x1111222233334444))) {
        out("UNIFIED_CORE_RESET_TRANSLATION_FAIL ");hex(d);out(" ");hex(f[12]);out(" ");hex(f[41]);out("\n");return 2;
    }
    if(d==RESET_TARGET)target_context=f;else survivor_context=f;
#endif
    previous[d]=f[10];visits[d]++;
#ifdef RESET_STRESS
#ifdef SELF_RESET
    if(d==RESET_TARGET && !recycled && visits[0]>=5 && visits[1]>=5) {
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
            out("UNIFIED_CORE_LINUX_RESET_TUPLE_ABI_FAIL\n");return 2;
        }
        for(unsigned n=0;n<512;n++) {
            uint64_t expected=0;
            if(n==0)expected=0x47e00000;if(n==31)expected=0x40000000;if(n==32)expected=0x3c5;
            if(n==35)expected=0x30d00800;if(n==37)expected=0x300000;if(n==64)expected=1;
            if(target_context[n]!=expected){out("UNIFIED_CORE_LINUX_RESET_TUPLE_BANK_FAIL\n");return 2;}
        }
        if(!same(survivor_copy,survivor_context,4096) || uw_current_domain()!=d) {
            out("UNIFIED_CORE_LINUX_RESET_TUPLE_SURVIVOR_FAIL\n");return 2;
        }
        out("UNIFIED_CORE_LINUX_RESET_TUPLE_ABI_PASS\n");
        memcpy(target_copy,target_context,4096);
#endif
        if(uw_domain_reset(2,0x40000000,0x33,0x3c5)!=0 || uw_domain_reset(RESET_TARGET,0x20000000,0x33,0x3c5)!=0
           || !same(target_copy,target_context,4096) || uw_probe_domain_reset(RESET_TARGET,0x40000000,0x33,0x3c5)!=1) {
            out("UNIFIED_CORE_RESET_ADMISSION_FAIL\n");return 2;
        }
        for(unsigned n=0;n<512;n++) {
            uint64_t expected=0;
            if(n==0)expected=0x33;if(n==31)expected=0x40000000;if(n==32)expected=0x3c5;
            if(n==35)expected=0x30d00800;if(n==37)expected=0x300000;if(n==64)expected=1;
            if(target_context[n]!=expected){out("UNIFIED_CORE_RESET_DIRTY_BANK_FAIL ");hex(n);out("\n");return 2;}
        }
        if(!same(survivor_copy,survivor_context,4096) || uw_current_domain()!=d){out("UNIFIED_CORE_RESET_SURVIVOR_FAIL\n");return 2;}
        recycled=1;previous[RESET_TARGET]=0;visits[RESET_TARGET]=0;
        uw_vgic_hcr_write(RESET_TARGET,1);uw_vgic_vmcr_write(RESET_TARGET,(UINT64_C(255)<<24)|2);
        uw_timer_write(RESET_TARGET,0,0,uw_counter_read()+1000000000);uw_timer_write(RESET_TARGET,0,1,3);
        uw_timer_write(RESET_TARGET,1,0,0x12340000+RESET_TARGET);uw_timer_write(RESET_TARGET,1,1,0);
        out("UNIFIED_CORE_RESET_BANK_CLEAR_PASS\n");deadline=uw_counter_read()+period;return RESET_TARGET;
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

// Return2 makes any callee-saved-register violation an explicit test failure.
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
"9: mov x0, #2\n"
"8: ldp x21, x22, [sp, #16]\n"
"ldp x23, x24, [sp, #32]\n"
"ldp x25, x26, [sp, #48]\n"
"ldp x27, x28, [sp, #64]\n"
"ldp x29, x30, [sp, #80]\n"
"ldp x19, x20, [sp], #96\n"
"ret\n"
);
