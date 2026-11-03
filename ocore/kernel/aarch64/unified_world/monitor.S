// Two independent EL1 worlds below one EL2 owner. All device accesses trap.
// Frame ABI: x0..x30 @0, PC@248, PSTATE@256, complete private context4KiB.
// Only the EL2 timer (physical PPI26) is enabled in the real GIC.
.arch armv8-a
.equ UW_CTX_BYTES, 4096
.equ UW_PC, 248
.equ UW_PSTATE, 256
.equ UW_SP0, 264
.equ UW_SP1, 272
.equ UW_CNTV_CTL, 456
.equ UW_CNTV_CVAL, 464
.equ UW_CNTP_CTL, 472
.equ UW_CNTP_CVAL, 480
.equ UW_CNTVOFF, 488
.equ UW_ICH_HCR, 704
.equ UW_ICH_VMCR, 712
.equ UW_AP0, 720
.equ UW_AP1, 752
.equ UW_LR, 800
.equ UW_FP, 1024

.section .text.boot, "ax", %progbits
.global _start
_start:
    msr daifset, #0xf
    mrs x0, CurrentEL
    cmp x0, #8
    b.ne uw_halt
    adrp x0, uw_stack_top
    add x0, x0, :lo12:uw_stack_top
    mov sp, x0
    adrp x0, __bss_start
    add x0, x0, :lo12:__bss_start
    adrp x1, __bss_end
    add x1, x1, :lo12:__bss_end
1:  cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:  adrp x0, uw_vectors
    add x0, x0, :lo12:uw_vectors
    msr vbar_el2, x0
    msr cptr_el2, xzr
    // Preserve implemented PMU event counters in MDCR.HPMN.
    mrs x0, pmcr_el0
    ubfx x0, x0, #11, #5
    msr mdcr_el2, x0
    adrp x1, uw_pmu_count
    str x0, [x1, :lo12:uw_pmu_count]
    mrs x0, id_aa64dfr0_el1
    ubfx x1, x0, #12, #4
    add x1, x1, #1
    adrp x2, uw_break_count
    str x1, [x2, :lo12:uw_break_count]
    ubfx x1, x0, #20, #4
    add x1, x1, #1
    adrp x2, uw_watch_count
    str x1, [x2, :lo12:uw_watch_count]
    // Permit counter reads, trap CNTP registers. CNTV cannot be trapped on A57:
    // save its live bank and mask physical PPI27; synthesize each world's IRQ.
    mov x0, #1
    msr cnthctl_el2, x0
    msr cntvoff_el2, xzr
    msr cntp_ctl_el0, xzr
    msr cntv_ctl_el0, xzr
    msr cnthp_ctl_el2, xzr
    mrs x0, midr_el1
    msr vpidr_el2, x0
    mrs x0, mpidr_el1
    msr vmpidr_el2, x0
    bl uw_physical_gic_init
    bl uw_stage2_init
    bl uw_console_init
    bl uw_init
    cmp x0, #1
    b.ne uw_halt
    bl uw_next_deadline
    adrp x1, uw_deadline
    str x0, [x1, :lo12:uw_deadline]
    adrp x0, uw_contexts
    add x0, x0, :lo12:uw_contexts
    mov x19, x0
    bl uw_restore_arch
    bl uw_timer_rearm
    b uw_enter_saved

.section .text, "ax", %progbits
.global uw_current_domain
uw_current_domain:
    adrp x0, uw_current
    ldr x0, [x0, :lo12:uw_current]
    ret

// Trusted initializer only; a guest never chooses an entry or address space.
.global uw_domain_init
uw_domain_init:
    cmp x0, #2
    b.hs 9f
    mov x5, #0x40000000
    cmp x1, x5
    b.lo 9f
    mov x5, #0x60000000
    cmp x1, x5
    b.hs 9f
    tst x1, #3
    b.ne 9f
    cmp x3, #0x3c5
    b.ne 9f
    adrp x4, uw_contexts
    add x4, x4, :lo12:uw_contexts
    add x4, x4, x0, lsl #12
    str x2, [x4]
    str x1, [x4, #UW_PC]
    str x3, [x4, #UW_PSTATE]
    movz x1, #0x0800
    movk x1, #0x30d0, lsl #16
    str x1, [x4, #280] // SCTLR RES1, MMU/caches initially disabled.
    mov x1, #0x300000
    str x1, [x4, #296] // FP/SIMD available to original kernels.
    mov x1, #1
    str x1, [x4, #512] // ICC_SRE_EL1
    mov x0, #1
    ret
9:  mov x0, #0
    ret

// Trusted stopped-domain recycling. All architectural state, including SIMD,
// PMU/debug/locks and active virtual interrupts, is discarded. The caller must
// first withdraw the domain and replace its private RAM while QEMU is stopped.
// Native code cannot use this as an in-place reset of a running guest frame.
.global uw_domain_reset
uw_domain_reset:
    cmp x0, #2
    b.hs 9f
    mov x5, #0x40000000
    cmp x1, x5
    b.lo 9f
    mov x5, #0x60000000
    cmp x1, x5
    b.hs 9f
    tst x1, #3
    b.ne 9f
    cmp x3, #0x3c5
    b.ne 9f
    adrp x4, uw_contexts
    add x4, x4, :lo12:uw_contexts
    add x4, x4, x0, lsl #12
    mov x5, #UW_CTX_BYTES
1:  stp xzr, xzr, [x4], #16
    subs x5, x5, #16
    b.ne 1b
    // Reusing a VMID requires invalidating its previous stage-1 and stage-2
    // translations, without touching the surviving world's context bank.
    mrs x6, vttbr_el2
    adrp x4, uw_root0
    add x4, x4, :lo12:uw_root0
    cbz x0, 2f
    adrp x4, uw_root1
    add x4, x4, :lo12:uw_root1
2:  add x5, x0, #1
    orr x4, x4, x5, lsl #48
    dsb sy
    msr vttbr_el2, x4
    isb
    tlbi vmalls12e1is
    dsb sy
    ic iallu
    dsb sy
    msr vttbr_el2, x6
    isb
    b uw_domain_init
9:  mov x0, #0
    ret

uw_stage2_init:
    adrp x0, uw_root0
    add x0, x0, :lo12:uw_root0
    adrp x1, uw_ram0
    add x1, x1, :lo12:uw_ram0
    orr x2, x1, #3
    str x2, [x0, #8]
    movz x2, #0x07fd
    movk x2, #0x4800, lsl #16
    mov x3, #256
1:  str x2, [x1], #8
    add x2, x2, #0x200, lsl #12
    subs x3, x3, #1
    b.ne 1b
    adrp x0, uw_root1
    add x0, x0, :lo12:uw_root1
    adrp x1, uw_ram1
    add x1, x1, :lo12:uw_ram1
    orr x2, x1, #3
    str x2, [x0, #8]
    movz x2, #0x07fd
    movk x2, #0xb000, lsl #16
    mov x3, #256
2:  str x2, [x1], #8
    add x2, x2, #0x200, lsl #12
    subs x3, x3, #1
    b.ne 2b
    movz x0, #0x3560
    movk x0, #0x8000, lsl #16
    msr vtcr_el2, x0
    dsb sy
    tlbi vmalls12e1is
    dsb sy
    isb
    // RW, VM, IMO, FMO, AMO, TSC, TWI and TWE. IMO/FMO force every
    // EL1 SGI send to EC18, so no guest can send a physical SGI.
    movz x0, #0x6039
    movk x0, #0x8008, lsl #16
    msr hcr_el2, x0
    isb
    ret

uw_physical_gic_init:
    mov x0, #9
    msr icc_sre_el2, x0
    isb
    mov x0, #1
    msr icc_sre_el1, x0
    isb
    mov x0, #0x08000000
    str wzr, [x0]
1:  ldr w1, [x0]
    tbnz w1, #31, 1b
    ldr w1, [x0, #4]
    and x1, x1, #31
    mov w2, #-1
    mov x3, #1
2:  cmp x3, x1
    b.hi 3f
    add x4, x0, x3, lsl #2
    str w2, [x4, #0x180] // all physical SPIs masked
    str w2, [x4, #0x280]
    str w2, [x4, #0x80]  // nonsecure Group1
    add x3, x3, #1
    b 2b
3:  mov w1, #0x12 // affinity routing and nonsecure Group1
    str w1, [x0]
    mov x0, #0x080a0000
    ldr w1, [x0, #0x14]
    bic w1, w1, #2
    str w1, [x0, #0x14]
4:  ldr w1, [x0, #0x14]
    tbnz w1, #2, 4b
    mov x0, #0x080b0000
    str w2, [x0, #0x180]
    str w2, [x0, #0x280]
    str w2, [x0, #0x80]
    mov w1, #0x80
    strb w1, [x0, #0x41a] // EL2 CNTHP PPI26
    mov w1, #0x4000000
    str w1, [x0, #0x100]
    mov x0, #0xff
    msr icc_pmr_el1, x0
    msr icc_bpr1_el1, xzr
    msr icc_ctlr_el1, xzr
    mov x0, #1
    msr icc_igrpen1_el1, x0
    mrs x0, ich_vtr_el2
    and x1, x0, #31
    add x1, x1, #1
    cmp x1, #16
    b.hi uw_halt
    adrp x2, uw_lr_count
    str x1, [x2, :lo12:uw_lr_count]
    ubfx x0, x0, #26, #3 // PREbits minus1: implemented active priorities
    mov x1, #1
    cmp x0, #5
    b.lo 5f
    lsl x1, x1, #1
    cmp x0, #6
    b.lo 5f
    lsl x1, x1, #1
5:  adrp x2, uw_apr_count
    str x1, [x2, :lo12:uw_apr_count]
    mrs x0, cntfrq_el0
    mov x1, #100
    udiv x0, x0, x1
    cbz x0, uw_halt
    adrp x1, uw_tick_period
    str x0, [x1, :lo12:uw_tick_period]
    dsb sy
    isb
    ret

.global uw_irq_ack
uw_irq_ack:
    adrp x0, uw_irq_latched
    ldr x0, [x0, :lo12:uw_irq_latched]
    ret
.global uw_irq_eoi
uw_irq_eoi:
    cmp x0, #1020
    b.hs 1f
    msr icc_eoir1_el1, x0
    isb
1:  ret
.global uw_timer_rearm
uw_timer_rearm:
    adrp x0, uw_deadline
    ldr x0, [x0, :lo12:uw_deadline]
    msr cnthp_cval_el2, x0
    mov x0, #1
    msr cnthp_ctl_el2, x0
    isb
    ret
.global uw_counter_read
.global kw_counter_read
uw_counter_read:
kw_counter_read:
    mrs x0, cntpct_el0
    ret
.global uw_counter_frequency
.global kw_counter_frequency
uw_counter_frequency:
kw_counter_frequency:
    mrs x0, cntfrq_el0
    ret
.global uw_memory_barrier
.global kw_memory_barrier
uw_memory_barrier:
kw_memory_barrier:
    dmb sy
    ret
.global uw_serial_putc
uw_serial_putc:
    mov x1, #0x09000000
1:  ldr w2, [x1, #0x18]
    tbnz w2, #5, 1b
    str w0, [x1]
    ret
.global uw_serial_try_read
uw_serial_try_read:
    mov x1, #0x09000000
    ldr w2, [x1, #0x18]
    tbnz w2, #4, 1f
    ldr w0, [x1]
    and x0, x0, #0xff
    orr x0, x0, #0x100
    ret
1:  mov x0, #0
    ret
.global uw_console_init
.global kw_console_init
.global kw_serial_console_init
uw_console_init:
kw_console_init:
kw_serial_console_init:
    mov x1, #0x09000000
    str wzr, [x1, #0x38]
    mov w2, #0x7ff
    str w2, [x1, #0x44]
    str wzr, [x1, #0x30]
    mov w2, #1
    str w2, [x1, #0x24]
    str wzr, [x1, #0x28]
    mov w2, #0x70
    str w2, [x1, #0x2c]
    mov w2, #0x301
    str w2, [x1, #0x30]
    dsb sy
    ret
.global kw_revoke_guest_ram
kw_revoke_guest_ram:
    // The persistent profile has no recover-and-resume RAM withdrawal route.
    b uw_halt

// Saved-bank hooks; no O-core caller ever touches the currently live ICH bank.
.global uw_vgic_lr_count
uw_vgic_lr_count:
    adrp x0, uw_lr_count
    ldr x0, [x0, :lo12:uw_lr_count]
    ret
.global uw_vgic_lr_read
uw_vgic_lr_read:
    cmp x0, #2
    b.hs uw_halt
    adrp x3, uw_lr_count
    ldr x3, [x3, :lo12:uw_lr_count]
    cmp x1, x3
    b.hs uw_halt
    adrp x3, uw_contexts
    add x3, x3, :lo12:uw_contexts
    add x3, x3, x0, lsl #12
    add x3, x3, #UW_LR
    ldr x0, [x3, x1, lsl #3]
    ret
.global uw_vgic_lr_write
uw_vgic_lr_write:
    cmp x0, #2
    b.hs uw_halt
    adrp x3, uw_lr_count
    ldr x3, [x3, :lo12:uw_lr_count]
    cmp x1, x3
    b.hs uw_halt
    adrp x3, uw_contexts
    add x3, x3, :lo12:uw_contexts
    add x3, x3, x0, lsl #12
    add x3, x3, #UW_LR
    str x2, [x3, x1, lsl #3]
    ret

.global uw_vgic_hcr_read
uw_vgic_hcr_read:
    cmp x0, #2
    b.hs uw_halt
    adrp x2, uw_contexts
    add x2, x2, :lo12:uw_contexts
    add x2, x2, x0, lsl #12
    ldr x0, [x2, #704]
    ret
.global uw_vgic_hcr_write
uw_vgic_hcr_write:
    cmp x0, #2
    b.hs uw_halt
    adrp x2, uw_contexts
    add x2, x2, :lo12:uw_contexts
    add x2, x2, x0, lsl #12
    str x1, [x2, #704]
    ret

.global uw_vgic_vmcr_read
uw_vgic_vmcr_read:
    cmp x0, #2
    b.hs uw_halt
    adrp x2, uw_contexts
    add x2, x2, :lo12:uw_contexts
    add x2, x2, x0, lsl #12
    ldr x0, [x2, #712]
    ret
.global uw_vgic_vmcr_write
uw_vgic_vmcr_write:
    cmp x0, #2
    b.hs uw_halt
    adrp x2, uw_contexts
    add x2, x2, :lo12:uw_contexts
    add x2, x2, x0, lsl #12
    str x1, [x2, #712]
    ret

.global uw_timer_read
uw_timer_read:
    cmp x0, #2
    b.hs uw_halt
    cmp x1, #2
    b.hs uw_halt
    adrp x3, uw_contexts
    add x3, x3, :lo12:uw_contexts
    add x3, x3, x0, lsl #12
    add x3, x3, #UW_CNTV_CTL
    add x3, x3, x1, lsl #4
    cmp x2, #0
    b.eq 1f
    mrs x4, cntpct_el0
    cbnz x1, 2f
    ldr x5, [x3, #32] // CNTVOFF relative to CNTV_CTL
    sub x4, x4, x5
2:  ldr x5, [x3, #8]
    cmp x2, #2
    b.eq 3f
    cmp x2, #1
    b.ne uw_halt
    ldr x0, [x3]
    and x0, x0, #3
    tbz x0, #0, 4f
    cmp x4, x5
    b.lo 4f
    orr x0, x0, #4
4:  ret
1:  ldr x0, [x3, #8]
    ret
3:  sub x0, x5, x4
    and x0, x0, #0xffffffff
    ret
.global uw_timer_write
uw_timer_write:
    cmp x0, #2
    b.hs uw_halt
    cmp x1, #2
    b.hs uw_halt
    adrp x4, uw_contexts
    add x4, x4, :lo12:uw_contexts
    add x4, x4, x0, lsl #12
    add x4, x4, #UW_CNTV_CTL
    add x4, x4, x1, lsl #4
    cmp x2, #1
    b.eq 1f
    cmp x2, #0
    b.eq 2f
    cmp x2, #2
    b.ne uw_halt
    mrs x5, cntpct_el0
    cbnz x1, 3f
    ldr x6, [x4, #32]
    sub x5, x5, x6
3:  sxtw x3, w3
    add x3, x3, x5
2:  str x3, [x4, #8]
    mov x0, #1
    ret
1:  and x3, x3, #3
    str x3, [x4]
    mov x0, #1
    ret
.global uw_timer_pending
uw_timer_pending:
    mov x2, #1
    stp x29, x30, [sp, #-16]!
    bl uw_timer_read
    and x0, x0, #7
    cmp x0, #5
    cset x0, eq
    ldp x29, x30, [sp], #16
    ret

.macro UW_SYS_SAVE reg, offset
    mrs x1, \reg
    str x1, [x0, #\offset]
.endm
.macro UW_SYS_RESTORE reg, offset
    ldr x1, [x0, #\offset]
    msr \reg, x1
.endm
uw_save_arch:
    // QEMU8.2 A57 lock model: EL2 can clear both locks. Save the write-only
    // OSLAR state through OSLSR.OSLK. Real-hardware DoubleLock is not qualified.
    UW_SYS_SAVE oslsr_el1, 544
    UW_SYS_SAVE osdlr_el1, 552
    msr osdlr_el1, xzr
    msr oslar_el1, xzr
    isb
    UW_SYS_SAVE dbgclaimclr_el1, 560
    mov x1, #0xff
    msr dbgclaimclr_el1, x1
    UW_SYS_SAVE sp_el0, 264
    UW_SYS_SAVE sp_el1, 272
    UW_SYS_SAVE sctlr_el1, 280
    UW_SYS_SAVE actlr_el1, 288
    UW_SYS_SAVE cpacr_el1, 296
    UW_SYS_SAVE csselr_el1, 304
    UW_SYS_SAVE contextidr_el1, 312
    UW_SYS_SAVE cntkctl_el1, 320
    UW_SYS_SAVE ttbr0_el1, 328
    UW_SYS_SAVE ttbr1_el1, 336
    UW_SYS_SAVE tcr_el1, 344
    UW_SYS_SAVE mair_el1, 352
    UW_SYS_SAVE amair_el1, 360
    UW_SYS_SAVE vbar_el1, 368
    UW_SYS_SAVE tpidr_el0, 376
    UW_SYS_SAVE tpidrro_el0, 384
    UW_SYS_SAVE tpidr_el1, 392
    UW_SYS_SAVE elr_el1, 400
    UW_SYS_SAVE spsr_el1, 408
    UW_SYS_SAVE esr_el1, 416
    UW_SYS_SAVE far_el1, 424
    UW_SYS_SAVE par_el1, 432
    UW_SYS_SAVE afsr0_el1, 440
    UW_SYS_SAVE afsr1_el1, 448
    UW_SYS_SAVE cntv_ctl_el0, 456
    UW_SYS_SAVE cntv_cval_el0, 464
    UW_SYS_SAVE cntvoff_el2, 488
    UW_SYS_SAVE mdscr_el1, 496
    UW_SYS_SAVE pmuserenr_el0, 504
    UW_SYS_SAVE icc_sre_el1, 512
    UW_SYS_SAVE fpcr, 520
    UW_SYS_SAVE fpsr, 528
    UW_SYS_SAVE mdccint_el1, 536
    UW_SYS_SAVE pmcr_el0, 600
    UW_SYS_SAVE pmcntenset_el0, 608
    UW_SYS_SAVE pmovsclr_el0, 616
    UW_SYS_SAVE pmselr_el0, 624
    UW_SYS_SAVE pmccntr_el0, 632
    UW_SYS_SAVE pmccfiltr_el0, 640
    UW_SYS_SAVE pmintenset_el1, 648
    UW_SYS_SAVE ich_hcr_el2, 704
    UW_SYS_SAVE ich_vmcr_el2, 712
    // Native handlers use their own FP environment, never guest rounding or
    // exception enables. The full guest FP environment is restored on eret.
    msr fpcr, xzr
    msr fpsr, xzr
    // Stop guest timers/PMU/debug while native code runs. CNTP is always
    // emulated: its saved fields are NEVER overwritten from physical hardware.
    msr cntv_ctl_el0, xzr
    msr cntp_ctl_el0, xzr
    msr mdscr_el1, xzr
    mrs x1, pmcr_el0
    bic x1, x1, #1
    msr pmcr_el0, x1
    msr ich_hcr_el2, xzr
    add x3, x0, #UW_FP
    stp q0, q1, [x3, #0]
    stp q2, q3, [x3, #32]
    stp q4, q5, [x3, #64]
    stp q6, q7, [x3, #96]
    stp q8, q9, [x3, #128]
    stp q10, q11, [x3, #160]
    stp q12, q13, [x3, #192]
    stp q14, q15, [x3, #224]
    stp q16, q17, [x3, #256]
    stp q18, q19, [x3, #288]
    stp q20, q21, [x3, #320]
    stp q22, q23, [x3, #352]
    stp q24, q25, [x3, #384]
    stp q26, q27, [x3, #416]
    stp q28, q29, [x3, #448]
    stp q30, q31, [x3, #480]

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #1
    b.lo .Lsave_ap0_0
    mrs x1, ich_ap0r0_el2
    str x1, [x0, #720]
.Lsave_ap0_0:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #2
    b.lo .Lsave_ap0_1
    mrs x1, ich_ap0r1_el2
    str x1, [x0, #728]
.Lsave_ap0_1:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #3
    b.lo .Lsave_ap0_2
    mrs x1, ich_ap0r2_el2
    str x1, [x0, #736]
.Lsave_ap0_2:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #4
    b.lo .Lsave_ap0_3
    mrs x1, ich_ap0r3_el2
    str x1, [x0, #744]
.Lsave_ap0_3:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #1
    b.lo .Lsave_ap1_0
    mrs x1, ich_ap1r0_el2
    str x1, [x0, #752]
.Lsave_ap1_0:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #2
    b.lo .Lsave_ap1_1
    mrs x1, ich_ap1r1_el2
    str x1, [x0, #760]
.Lsave_ap1_1:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #3
    b.lo .Lsave_ap1_2
    mrs x1, ich_ap1r2_el2
    str x1, [x0, #768]
.Lsave_ap1_2:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #4
    b.lo .Lsave_ap1_3
    mrs x1, ich_ap1r3_el2
    str x1, [x0, #776]
.Lsave_ap1_3:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #1
    b.lo .Lsave_lr0
    mrs x1, ich_lr0_el2
    str x1, [x0, #800]
.Lsave_lr0:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #2
    b.lo .Lsave_lr1
    mrs x1, ich_lr1_el2
    str x1, [x0, #808]
.Lsave_lr1:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #3
    b.lo .Lsave_lr2
    mrs x1, ich_lr2_el2
    str x1, [x0, #816]
.Lsave_lr2:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #4
    b.lo .Lsave_lr3
    mrs x1, ich_lr3_el2
    str x1, [x0, #824]
.Lsave_lr3:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #5
    b.lo .Lsave_lr4
    mrs x1, ich_lr4_el2
    str x1, [x0, #832]
.Lsave_lr4:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #6
    b.lo .Lsave_lr5
    mrs x1, ich_lr5_el2
    str x1, [x0, #840]
.Lsave_lr5:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #7
    b.lo .Lsave_lr6
    mrs x1, ich_lr6_el2
    str x1, [x0, #848]
.Lsave_lr6:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #8
    b.lo .Lsave_lr7
    mrs x1, ich_lr7_el2
    str x1, [x0, #856]
.Lsave_lr7:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #9
    b.lo .Lsave_lr8
    mrs x1, ich_lr8_el2
    str x1, [x0, #864]
.Lsave_lr8:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #10
    b.lo .Lsave_lr9
    mrs x1, ich_lr9_el2
    str x1, [x0, #872]
.Lsave_lr9:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #11
    b.lo .Lsave_lr10
    mrs x1, ich_lr10_el2
    str x1, [x0, #880]
.Lsave_lr10:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #12
    b.lo .Lsave_lr11
    mrs x1, ich_lr11_el2
    str x1, [x0, #888]
.Lsave_lr11:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #13
    b.lo .Lsave_lr12
    mrs x1, ich_lr12_el2
    str x1, [x0, #896]
.Lsave_lr12:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #14
    b.lo .Lsave_lr13
    mrs x1, ich_lr13_el2
    str x1, [x0, #904]
.Lsave_lr13:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #15
    b.lo .Lsave_lr14
    mrs x1, ich_lr14_el2
    str x1, [x0, #912]
.Lsave_lr14:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #16
    b.lo .Lsave_lr15
    mrs x1, ich_lr15_el2
    str x1, [x0, #920]
.Lsave_lr15:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #1
    b.lo .Lsave_dbgbvr0
    mrs x1, dbgbvr0_el1
    str x1, [x0, #1536]
.Lsave_dbgbvr0:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #2
    b.lo .Lsave_dbgbvr1
    mrs x1, dbgbvr1_el1
    str x1, [x0, #1544]
.Lsave_dbgbvr1:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #3
    b.lo .Lsave_dbgbvr2
    mrs x1, dbgbvr2_el1
    str x1, [x0, #1552]
.Lsave_dbgbvr2:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #4
    b.lo .Lsave_dbgbvr3
    mrs x1, dbgbvr3_el1
    str x1, [x0, #1560]
.Lsave_dbgbvr3:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #5
    b.lo .Lsave_dbgbvr4
    mrs x1, dbgbvr4_el1
    str x1, [x0, #1568]
.Lsave_dbgbvr4:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #6
    b.lo .Lsave_dbgbvr5
    mrs x1, dbgbvr5_el1
    str x1, [x0, #1576]
.Lsave_dbgbvr5:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #7
    b.lo .Lsave_dbgbvr6
    mrs x1, dbgbvr6_el1
    str x1, [x0, #1584]
.Lsave_dbgbvr6:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #8
    b.lo .Lsave_dbgbvr7
    mrs x1, dbgbvr7_el1
    str x1, [x0, #1592]
.Lsave_dbgbvr7:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #9
    b.lo .Lsave_dbgbvr8
    mrs x1, dbgbvr8_el1
    str x1, [x0, #1600]
.Lsave_dbgbvr8:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #10
    b.lo .Lsave_dbgbvr9
    mrs x1, dbgbvr9_el1
    str x1, [x0, #1608]
.Lsave_dbgbvr9:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #11
    b.lo .Lsave_dbgbvr10
    mrs x1, dbgbvr10_el1
    str x1, [x0, #1616]
.Lsave_dbgbvr10:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #12
    b.lo .Lsave_dbgbvr11
    mrs x1, dbgbvr11_el1
    str x1, [x0, #1624]
.Lsave_dbgbvr11:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #13
    b.lo .Lsave_dbgbvr12
    mrs x1, dbgbvr12_el1
    str x1, [x0, #1632]
.Lsave_dbgbvr12:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #14
    b.lo .Lsave_dbgbvr13
    mrs x1, dbgbvr13_el1
    str x1, [x0, #1640]
.Lsave_dbgbvr13:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #15
    b.lo .Lsave_dbgbvr14
    mrs x1, dbgbvr14_el1
    str x1, [x0, #1648]
.Lsave_dbgbvr14:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #16
    b.lo .Lsave_dbgbvr15
    mrs x1, dbgbvr15_el1
    str x1, [x0, #1656]
.Lsave_dbgbvr15:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #1
    b.lo .Lsave_dbgbcr0
    mrs x1, dbgbcr0_el1
    str x1, [x0, #1664]
.Lsave_dbgbcr0:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #2
    b.lo .Lsave_dbgbcr1
    mrs x1, dbgbcr1_el1
    str x1, [x0, #1672]
.Lsave_dbgbcr1:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #3
    b.lo .Lsave_dbgbcr2
    mrs x1, dbgbcr2_el1
    str x1, [x0, #1680]
.Lsave_dbgbcr2:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #4
    b.lo .Lsave_dbgbcr3
    mrs x1, dbgbcr3_el1
    str x1, [x0, #1688]
.Lsave_dbgbcr3:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #5
    b.lo .Lsave_dbgbcr4
    mrs x1, dbgbcr4_el1
    str x1, [x0, #1696]
.Lsave_dbgbcr4:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #6
    b.lo .Lsave_dbgbcr5
    mrs x1, dbgbcr5_el1
    str x1, [x0, #1704]
.Lsave_dbgbcr5:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #7
    b.lo .Lsave_dbgbcr6
    mrs x1, dbgbcr6_el1
    str x1, [x0, #1712]
.Lsave_dbgbcr6:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #8
    b.lo .Lsave_dbgbcr7
    mrs x1, dbgbcr7_el1
    str x1, [x0, #1720]
.Lsave_dbgbcr7:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #9
    b.lo .Lsave_dbgbcr8
    mrs x1, dbgbcr8_el1
    str x1, [x0, #1728]
.Lsave_dbgbcr8:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #10
    b.lo .Lsave_dbgbcr9
    mrs x1, dbgbcr9_el1
    str x1, [x0, #1736]
.Lsave_dbgbcr9:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #11
    b.lo .Lsave_dbgbcr10
    mrs x1, dbgbcr10_el1
    str x1, [x0, #1744]
.Lsave_dbgbcr10:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #12
    b.lo .Lsave_dbgbcr11
    mrs x1, dbgbcr11_el1
    str x1, [x0, #1752]
.Lsave_dbgbcr11:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #13
    b.lo .Lsave_dbgbcr12
    mrs x1, dbgbcr12_el1
    str x1, [x0, #1760]
.Lsave_dbgbcr12:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #14
    b.lo .Lsave_dbgbcr13
    mrs x1, dbgbcr13_el1
    str x1, [x0, #1768]
.Lsave_dbgbcr13:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #15
    b.lo .Lsave_dbgbcr14
    mrs x1, dbgbcr14_el1
    str x1, [x0, #1776]
.Lsave_dbgbcr14:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #16
    b.lo .Lsave_dbgbcr15
    mrs x1, dbgbcr15_el1
    str x1, [x0, #1784]
.Lsave_dbgbcr15:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #1
    b.lo .Lsave_dbgwvr0
    mrs x1, dbgwvr0_el1
    str x1, [x0, #1792]
.Lsave_dbgwvr0:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #2
    b.lo .Lsave_dbgwvr1
    mrs x1, dbgwvr1_el1
    str x1, [x0, #1800]
.Lsave_dbgwvr1:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #3
    b.lo .Lsave_dbgwvr2
    mrs x1, dbgwvr2_el1
    str x1, [x0, #1808]
.Lsave_dbgwvr2:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #4
    b.lo .Lsave_dbgwvr3
    mrs x1, dbgwvr3_el1
    str x1, [x0, #1816]
.Lsave_dbgwvr3:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #5
    b.lo .Lsave_dbgwvr4
    mrs x1, dbgwvr4_el1
    str x1, [x0, #1824]
.Lsave_dbgwvr4:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #6
    b.lo .Lsave_dbgwvr5
    mrs x1, dbgwvr5_el1
    str x1, [x0, #1832]
.Lsave_dbgwvr5:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #7
    b.lo .Lsave_dbgwvr6
    mrs x1, dbgwvr6_el1
    str x1, [x0, #1840]
.Lsave_dbgwvr6:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #8
    b.lo .Lsave_dbgwvr7
    mrs x1, dbgwvr7_el1
    str x1, [x0, #1848]
.Lsave_dbgwvr7:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #9
    b.lo .Lsave_dbgwvr8
    mrs x1, dbgwvr8_el1
    str x1, [x0, #1856]
.Lsave_dbgwvr8:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #10
    b.lo .Lsave_dbgwvr9
    mrs x1, dbgwvr9_el1
    str x1, [x0, #1864]
.Lsave_dbgwvr9:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #11
    b.lo .Lsave_dbgwvr10
    mrs x1, dbgwvr10_el1
    str x1, [x0, #1872]
.Lsave_dbgwvr10:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #12
    b.lo .Lsave_dbgwvr11
    mrs x1, dbgwvr11_el1
    str x1, [x0, #1880]
.Lsave_dbgwvr11:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #13
    b.lo .Lsave_dbgwvr12
    mrs x1, dbgwvr12_el1
    str x1, [x0, #1888]
.Lsave_dbgwvr12:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #14
    b.lo .Lsave_dbgwvr13
    mrs x1, dbgwvr13_el1
    str x1, [x0, #1896]
.Lsave_dbgwvr13:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #15
    b.lo .Lsave_dbgwvr14
    mrs x1, dbgwvr14_el1
    str x1, [x0, #1904]
.Lsave_dbgwvr14:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #16
    b.lo .Lsave_dbgwvr15
    mrs x1, dbgwvr15_el1
    str x1, [x0, #1912]
.Lsave_dbgwvr15:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #1
    b.lo .Lsave_dbgwcr0
    mrs x1, dbgwcr0_el1
    str x1, [x0, #1920]
.Lsave_dbgwcr0:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #2
    b.lo .Lsave_dbgwcr1
    mrs x1, dbgwcr1_el1
    str x1, [x0, #1928]
.Lsave_dbgwcr1:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #3
    b.lo .Lsave_dbgwcr2
    mrs x1, dbgwcr2_el1
    str x1, [x0, #1936]
.Lsave_dbgwcr2:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #4
    b.lo .Lsave_dbgwcr3
    mrs x1, dbgwcr3_el1
    str x1, [x0, #1944]
.Lsave_dbgwcr3:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #5
    b.lo .Lsave_dbgwcr4
    mrs x1, dbgwcr4_el1
    str x1, [x0, #1952]
.Lsave_dbgwcr4:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #6
    b.lo .Lsave_dbgwcr5
    mrs x1, dbgwcr5_el1
    str x1, [x0, #1960]
.Lsave_dbgwcr5:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #7
    b.lo .Lsave_dbgwcr6
    mrs x1, dbgwcr6_el1
    str x1, [x0, #1968]
.Lsave_dbgwcr6:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #8
    b.lo .Lsave_dbgwcr7
    mrs x1, dbgwcr7_el1
    str x1, [x0, #1976]
.Lsave_dbgwcr7:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #9
    b.lo .Lsave_dbgwcr8
    mrs x1, dbgwcr8_el1
    str x1, [x0, #1984]
.Lsave_dbgwcr8:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #10
    b.lo .Lsave_dbgwcr9
    mrs x1, dbgwcr9_el1
    str x1, [x0, #1992]
.Lsave_dbgwcr9:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #11
    b.lo .Lsave_dbgwcr10
    mrs x1, dbgwcr10_el1
    str x1, [x0, #2000]
.Lsave_dbgwcr10:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #12
    b.lo .Lsave_dbgwcr11
    mrs x1, dbgwcr11_el1
    str x1, [x0, #2008]
.Lsave_dbgwcr11:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #13
    b.lo .Lsave_dbgwcr12
    mrs x1, dbgwcr12_el1
    str x1, [x0, #2016]
.Lsave_dbgwcr12:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #14
    b.lo .Lsave_dbgwcr13
    mrs x1, dbgwcr13_el1
    str x1, [x0, #2024]
.Lsave_dbgwcr13:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #15
    b.lo .Lsave_dbgwcr14
    mrs x1, dbgwcr14_el1
    str x1, [x0, #2032]
.Lsave_dbgwcr14:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #16
    b.lo .Lsave_dbgwcr15
    mrs x1, dbgwcr15_el1
    str x1, [x0, #2040]
.Lsave_dbgwcr15:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #1
    b.lo .Lsave_pmevcntr0
    mrs x1, pmevcntr0_el0
    str x1, [x0, #2048]
.Lsave_pmevcntr0:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #2
    b.lo .Lsave_pmevcntr1
    mrs x1, pmevcntr1_el0
    str x1, [x0, #2056]
.Lsave_pmevcntr1:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #3
    b.lo .Lsave_pmevcntr2
    mrs x1, pmevcntr2_el0
    str x1, [x0, #2064]
.Lsave_pmevcntr2:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #4
    b.lo .Lsave_pmevcntr3
    mrs x1, pmevcntr3_el0
    str x1, [x0, #2072]
.Lsave_pmevcntr3:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #5
    b.lo .Lsave_pmevcntr4
    mrs x1, pmevcntr4_el0
    str x1, [x0, #2080]
.Lsave_pmevcntr4:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #6
    b.lo .Lsave_pmevcntr5
    mrs x1, pmevcntr5_el0
    str x1, [x0, #2088]
.Lsave_pmevcntr5:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #7
    b.lo .Lsave_pmevcntr6
    mrs x1, pmevcntr6_el0
    str x1, [x0, #2096]
.Lsave_pmevcntr6:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #8
    b.lo .Lsave_pmevcntr7
    mrs x1, pmevcntr7_el0
    str x1, [x0, #2104]
.Lsave_pmevcntr7:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #9
    b.lo .Lsave_pmevcntr8
    mrs x1, pmevcntr8_el0
    str x1, [x0, #2112]
.Lsave_pmevcntr8:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #10
    b.lo .Lsave_pmevcntr9
    mrs x1, pmevcntr9_el0
    str x1, [x0, #2120]
.Lsave_pmevcntr9:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #11
    b.lo .Lsave_pmevcntr10
    mrs x1, pmevcntr10_el0
    str x1, [x0, #2128]
.Lsave_pmevcntr10:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #12
    b.lo .Lsave_pmevcntr11
    mrs x1, pmevcntr11_el0
    str x1, [x0, #2136]
.Lsave_pmevcntr11:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #13
    b.lo .Lsave_pmevcntr12
    mrs x1, pmevcntr12_el0
    str x1, [x0, #2144]
.Lsave_pmevcntr12:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #14
    b.lo .Lsave_pmevcntr13
    mrs x1, pmevcntr13_el0
    str x1, [x0, #2152]
.Lsave_pmevcntr13:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #15
    b.lo .Lsave_pmevcntr14
    mrs x1, pmevcntr14_el0
    str x1, [x0, #2160]
.Lsave_pmevcntr14:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #16
    b.lo .Lsave_pmevcntr15
    mrs x1, pmevcntr15_el0
    str x1, [x0, #2168]
.Lsave_pmevcntr15:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #17
    b.lo .Lsave_pmevcntr16
    mrs x1, pmevcntr16_el0
    str x1, [x0, #2176]
.Lsave_pmevcntr16:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #18
    b.lo .Lsave_pmevcntr17
    mrs x1, pmevcntr17_el0
    str x1, [x0, #2184]
.Lsave_pmevcntr17:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #19
    b.lo .Lsave_pmevcntr18
    mrs x1, pmevcntr18_el0
    str x1, [x0, #2192]
.Lsave_pmevcntr18:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #20
    b.lo .Lsave_pmevcntr19
    mrs x1, pmevcntr19_el0
    str x1, [x0, #2200]
.Lsave_pmevcntr19:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #21
    b.lo .Lsave_pmevcntr20
    mrs x1, pmevcntr20_el0
    str x1, [x0, #2208]
.Lsave_pmevcntr20:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #22
    b.lo .Lsave_pmevcntr21
    mrs x1, pmevcntr21_el0
    str x1, [x0, #2216]
.Lsave_pmevcntr21:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #23
    b.lo .Lsave_pmevcntr22
    mrs x1, pmevcntr22_el0
    str x1, [x0, #2224]
.Lsave_pmevcntr22:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #24
    b.lo .Lsave_pmevcntr23
    mrs x1, pmevcntr23_el0
    str x1, [x0, #2232]
.Lsave_pmevcntr23:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #25
    b.lo .Lsave_pmevcntr24
    mrs x1, pmevcntr24_el0
    str x1, [x0, #2240]
.Lsave_pmevcntr24:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #26
    b.lo .Lsave_pmevcntr25
    mrs x1, pmevcntr25_el0
    str x1, [x0, #2248]
.Lsave_pmevcntr25:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #27
    b.lo .Lsave_pmevcntr26
    mrs x1, pmevcntr26_el0
    str x1, [x0, #2256]
.Lsave_pmevcntr26:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #28
    b.lo .Lsave_pmevcntr27
    mrs x1, pmevcntr27_el0
    str x1, [x0, #2264]
.Lsave_pmevcntr27:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #29
    b.lo .Lsave_pmevcntr28
    mrs x1, pmevcntr28_el0
    str x1, [x0, #2272]
.Lsave_pmevcntr28:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #30
    b.lo .Lsave_pmevcntr29
    mrs x1, pmevcntr29_el0
    str x1, [x0, #2280]
.Lsave_pmevcntr29:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #31
    b.lo .Lsave_pmevcntr30
    mrs x1, pmevcntr30_el0
    str x1, [x0, #2288]
.Lsave_pmevcntr30:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #1
    b.lo .Lsave_pmevtyper0
    mrs x1, pmevtyper0_el0
    str x1, [x0, #2304]
.Lsave_pmevtyper0:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #2
    b.lo .Lsave_pmevtyper1
    mrs x1, pmevtyper1_el0
    str x1, [x0, #2312]
.Lsave_pmevtyper1:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #3
    b.lo .Lsave_pmevtyper2
    mrs x1, pmevtyper2_el0
    str x1, [x0, #2320]
.Lsave_pmevtyper2:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #4
    b.lo .Lsave_pmevtyper3
    mrs x1, pmevtyper3_el0
    str x1, [x0, #2328]
.Lsave_pmevtyper3:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #5
    b.lo .Lsave_pmevtyper4
    mrs x1, pmevtyper4_el0
    str x1, [x0, #2336]
.Lsave_pmevtyper4:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #6
    b.lo .Lsave_pmevtyper5
    mrs x1, pmevtyper5_el0
    str x1, [x0, #2344]
.Lsave_pmevtyper5:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #7
    b.lo .Lsave_pmevtyper6
    mrs x1, pmevtyper6_el0
    str x1, [x0, #2352]
.Lsave_pmevtyper6:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #8
    b.lo .Lsave_pmevtyper7
    mrs x1, pmevtyper7_el0
    str x1, [x0, #2360]
.Lsave_pmevtyper7:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #9
    b.lo .Lsave_pmevtyper8
    mrs x1, pmevtyper8_el0
    str x1, [x0, #2368]
.Lsave_pmevtyper8:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #10
    b.lo .Lsave_pmevtyper9
    mrs x1, pmevtyper9_el0
    str x1, [x0, #2376]
.Lsave_pmevtyper9:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #11
    b.lo .Lsave_pmevtyper10
    mrs x1, pmevtyper10_el0
    str x1, [x0, #2384]
.Lsave_pmevtyper10:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #12
    b.lo .Lsave_pmevtyper11
    mrs x1, pmevtyper11_el0
    str x1, [x0, #2392]
.Lsave_pmevtyper11:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #13
    b.lo .Lsave_pmevtyper12
    mrs x1, pmevtyper12_el0
    str x1, [x0, #2400]
.Lsave_pmevtyper12:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #14
    b.lo .Lsave_pmevtyper13
    mrs x1, pmevtyper13_el0
    str x1, [x0, #2408]
.Lsave_pmevtyper13:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #15
    b.lo .Lsave_pmevtyper14
    mrs x1, pmevtyper14_el0
    str x1, [x0, #2416]
.Lsave_pmevtyper14:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #16
    b.lo .Lsave_pmevtyper15
    mrs x1, pmevtyper15_el0
    str x1, [x0, #2424]
.Lsave_pmevtyper15:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #17
    b.lo .Lsave_pmevtyper16
    mrs x1, pmevtyper16_el0
    str x1, [x0, #2432]
.Lsave_pmevtyper16:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #18
    b.lo .Lsave_pmevtyper17
    mrs x1, pmevtyper17_el0
    str x1, [x0, #2440]
.Lsave_pmevtyper17:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #19
    b.lo .Lsave_pmevtyper18
    mrs x1, pmevtyper18_el0
    str x1, [x0, #2448]
.Lsave_pmevtyper18:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #20
    b.lo .Lsave_pmevtyper19
    mrs x1, pmevtyper19_el0
    str x1, [x0, #2456]
.Lsave_pmevtyper19:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #21
    b.lo .Lsave_pmevtyper20
    mrs x1, pmevtyper20_el0
    str x1, [x0, #2464]
.Lsave_pmevtyper20:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #22
    b.lo .Lsave_pmevtyper21
    mrs x1, pmevtyper21_el0
    str x1, [x0, #2472]
.Lsave_pmevtyper21:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #23
    b.lo .Lsave_pmevtyper22
    mrs x1, pmevtyper22_el0
    str x1, [x0, #2480]
.Lsave_pmevtyper22:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #24
    b.lo .Lsave_pmevtyper23
    mrs x1, pmevtyper23_el0
    str x1, [x0, #2488]
.Lsave_pmevtyper23:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #25
    b.lo .Lsave_pmevtyper24
    mrs x1, pmevtyper24_el0
    str x1, [x0, #2496]
.Lsave_pmevtyper24:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #26
    b.lo .Lsave_pmevtyper25
    mrs x1, pmevtyper25_el0
    str x1, [x0, #2504]
.Lsave_pmevtyper25:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #27
    b.lo .Lsave_pmevtyper26
    mrs x1, pmevtyper26_el0
    str x1, [x0, #2512]
.Lsave_pmevtyper26:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #28
    b.lo .Lsave_pmevtyper27
    mrs x1, pmevtyper27_el0
    str x1, [x0, #2520]
.Lsave_pmevtyper27:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #29
    b.lo .Lsave_pmevtyper28
    mrs x1, pmevtyper28_el0
    str x1, [x0, #2528]
.Lsave_pmevtyper28:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #30
    b.lo .Lsave_pmevtyper29
    mrs x1, pmevtyper29_el0
    str x1, [x0, #2536]
.Lsave_pmevtyper29:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #31
    b.lo .Lsave_pmevtyper30
    mrs x1, pmevtyper30_el0
    str x1, [x0, #2544]
.Lsave_pmevtyper30:
    ret

uw_restore_arch:
    // x0 is the private saved context. Choose an independent root/VMID before
    // restoring stage1, and never map monitor/GIC/store/disk as guest RAM.
    adrp x1, uw_contexts
    add x1, x1, :lo12:uw_contexts
    sub x1, x0, x1
    lsr x1, x1, #12
    cbnz x1, 1f
    adrp x2, uw_root0
    add x2, x2, :lo12:uw_root0
    b 2f
1:  adrp x2, uw_root1
    add x2, x2, :lo12:uw_root1
2:  add x1, x1, #1
    orr x2, x2, x1, lsl #48
    dsb sy
    msr vttbr_el2, x2
    isb
    msr ich_hcr_el2, xzr
    msr cntv_ctl_el0, xzr
    msr cntp_ctl_el0, xzr
    msr mdscr_el1, xzr
    msr osdlr_el1, xzr
    msr oslar_el1, xzr
    isb
    mov x1, #-1
    msr pmcntenclr_el0, x1
    msr pmintenclr_el1, x1
    msr pmovsclr_el0, x1
    mov x1, #0xff
    msr dbgclaimclr_el1, x1
    UW_SYS_RESTORE dbgclaimset_el1, 560
    UW_SYS_RESTORE sp_el0, 264
    UW_SYS_RESTORE sp_el1, 272
    UW_SYS_RESTORE sctlr_el1, 280
    UW_SYS_RESTORE actlr_el1, 288
    UW_SYS_RESTORE cpacr_el1, 296
    UW_SYS_RESTORE csselr_el1, 304
    UW_SYS_RESTORE contextidr_el1, 312
    UW_SYS_RESTORE cntkctl_el1, 320
    UW_SYS_RESTORE ttbr0_el1, 328
    UW_SYS_RESTORE ttbr1_el1, 336
    UW_SYS_RESTORE tcr_el1, 344
    UW_SYS_RESTORE mair_el1, 352
    UW_SYS_RESTORE amair_el1, 360
    UW_SYS_RESTORE vbar_el1, 368
    UW_SYS_RESTORE tpidr_el0, 376
    UW_SYS_RESTORE tpidrro_el0, 384
    UW_SYS_RESTORE tpidr_el1, 392
    UW_SYS_RESTORE elr_el1, 400
    UW_SYS_RESTORE spsr_el1, 408
    UW_SYS_RESTORE esr_el1, 416
    UW_SYS_RESTORE far_el1, 424
    UW_SYS_RESTORE par_el1, 432
    UW_SYS_RESTORE afsr0_el1, 440
    UW_SYS_RESTORE afsr1_el1, 448
    UW_SYS_RESTORE cntv_cval_el0, 464
    UW_SYS_RESTORE cntvoff_el2, 488
    UW_SYS_RESTORE pmuserenr_el0, 504
    UW_SYS_RESTORE icc_sre_el1, 512
    UW_SYS_RESTORE mdccint_el1, 536
    UW_SYS_RESTORE pmselr_el0, 624
    UW_SYS_RESTORE pmccntr_el0, 632
    UW_SYS_RESTORE pmccfiltr_el0, 640
    UW_SYS_RESTORE ich_vmcr_el2, 712

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #1
    b.lo .Lrestore_ap0_0
    ldr x1, [x0, #720]
    msr ich_ap0r0_el2, x1
.Lrestore_ap0_0:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #2
    b.lo .Lrestore_ap0_1
    ldr x1, [x0, #728]
    msr ich_ap0r1_el2, x1
.Lrestore_ap0_1:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #3
    b.lo .Lrestore_ap0_2
    ldr x1, [x0, #736]
    msr ich_ap0r2_el2, x1
.Lrestore_ap0_2:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #4
    b.lo .Lrestore_ap0_3
    ldr x1, [x0, #744]
    msr ich_ap0r3_el2, x1
.Lrestore_ap0_3:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #1
    b.lo .Lrestore_ap1_0
    ldr x1, [x0, #752]
    msr ich_ap1r0_el2, x1
.Lrestore_ap1_0:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #2
    b.lo .Lrestore_ap1_1
    ldr x1, [x0, #760]
    msr ich_ap1r1_el2, x1
.Lrestore_ap1_1:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #3
    b.lo .Lrestore_ap1_2
    ldr x1, [x0, #768]
    msr ich_ap1r2_el2, x1
.Lrestore_ap1_2:

    adrp x2, uw_apr_count
    ldr x2, [x2, :lo12:uw_apr_count]
    cmp x2, #4
    b.lo .Lrestore_ap1_3
    ldr x1, [x0, #776]
    msr ich_ap1r3_el2, x1
.Lrestore_ap1_3:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #1
    b.lo .Lrestore_lr0
    ldr x1, [x0, #800]
    msr ich_lr0_el2, x1
.Lrestore_lr0:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #2
    b.lo .Lrestore_lr1
    ldr x1, [x0, #808]
    msr ich_lr1_el2, x1
.Lrestore_lr1:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #3
    b.lo .Lrestore_lr2
    ldr x1, [x0, #816]
    msr ich_lr2_el2, x1
.Lrestore_lr2:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #4
    b.lo .Lrestore_lr3
    ldr x1, [x0, #824]
    msr ich_lr3_el2, x1
.Lrestore_lr3:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #5
    b.lo .Lrestore_lr4
    ldr x1, [x0, #832]
    msr ich_lr4_el2, x1
.Lrestore_lr4:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #6
    b.lo .Lrestore_lr5
    ldr x1, [x0, #840]
    msr ich_lr5_el2, x1
.Lrestore_lr5:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #7
    b.lo .Lrestore_lr6
    ldr x1, [x0, #848]
    msr ich_lr6_el2, x1
.Lrestore_lr6:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #8
    b.lo .Lrestore_lr7
    ldr x1, [x0, #856]
    msr ich_lr7_el2, x1
.Lrestore_lr7:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #9
    b.lo .Lrestore_lr8
    ldr x1, [x0, #864]
    msr ich_lr8_el2, x1
.Lrestore_lr8:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #10
    b.lo .Lrestore_lr9
    ldr x1, [x0, #872]
    msr ich_lr9_el2, x1
.Lrestore_lr9:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #11
    b.lo .Lrestore_lr10
    ldr x1, [x0, #880]
    msr ich_lr10_el2, x1
.Lrestore_lr10:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #12
    b.lo .Lrestore_lr11
    ldr x1, [x0, #888]
    msr ich_lr11_el2, x1
.Lrestore_lr11:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #13
    b.lo .Lrestore_lr12
    ldr x1, [x0, #896]
    msr ich_lr12_el2, x1
.Lrestore_lr12:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #14
    b.lo .Lrestore_lr13
    ldr x1, [x0, #904]
    msr ich_lr13_el2, x1
.Lrestore_lr13:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #15
    b.lo .Lrestore_lr14
    ldr x1, [x0, #912]
    msr ich_lr14_el2, x1
.Lrestore_lr14:

    adrp x2, uw_lr_count
    ldr x2, [x2, :lo12:uw_lr_count]
    cmp x2, #16
    b.lo .Lrestore_lr15
    ldr x1, [x0, #920]
    msr ich_lr15_el2, x1
.Lrestore_lr15:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #1
    b.lo .Lrestore_dbgbvr0
    ldr x1, [x0, #1536]
    msr dbgbvr0_el1, x1
.Lrestore_dbgbvr0:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #2
    b.lo .Lrestore_dbgbvr1
    ldr x1, [x0, #1544]
    msr dbgbvr1_el1, x1
.Lrestore_dbgbvr1:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #3
    b.lo .Lrestore_dbgbvr2
    ldr x1, [x0, #1552]
    msr dbgbvr2_el1, x1
.Lrestore_dbgbvr2:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #4
    b.lo .Lrestore_dbgbvr3
    ldr x1, [x0, #1560]
    msr dbgbvr3_el1, x1
.Lrestore_dbgbvr3:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #5
    b.lo .Lrestore_dbgbvr4
    ldr x1, [x0, #1568]
    msr dbgbvr4_el1, x1
.Lrestore_dbgbvr4:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #6
    b.lo .Lrestore_dbgbvr5
    ldr x1, [x0, #1576]
    msr dbgbvr5_el1, x1
.Lrestore_dbgbvr5:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #7
    b.lo .Lrestore_dbgbvr6
    ldr x1, [x0, #1584]
    msr dbgbvr6_el1, x1
.Lrestore_dbgbvr6:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #8
    b.lo .Lrestore_dbgbvr7
    ldr x1, [x0, #1592]
    msr dbgbvr7_el1, x1
.Lrestore_dbgbvr7:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #9
    b.lo .Lrestore_dbgbvr8
    ldr x1, [x0, #1600]
    msr dbgbvr8_el1, x1
.Lrestore_dbgbvr8:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #10
    b.lo .Lrestore_dbgbvr9
    ldr x1, [x0, #1608]
    msr dbgbvr9_el1, x1
.Lrestore_dbgbvr9:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #11
    b.lo .Lrestore_dbgbvr10
    ldr x1, [x0, #1616]
    msr dbgbvr10_el1, x1
.Lrestore_dbgbvr10:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #12
    b.lo .Lrestore_dbgbvr11
    ldr x1, [x0, #1624]
    msr dbgbvr11_el1, x1
.Lrestore_dbgbvr11:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #13
    b.lo .Lrestore_dbgbvr12
    ldr x1, [x0, #1632]
    msr dbgbvr12_el1, x1
.Lrestore_dbgbvr12:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #14
    b.lo .Lrestore_dbgbvr13
    ldr x1, [x0, #1640]
    msr dbgbvr13_el1, x1
.Lrestore_dbgbvr13:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #15
    b.lo .Lrestore_dbgbvr14
    ldr x1, [x0, #1648]
    msr dbgbvr14_el1, x1
.Lrestore_dbgbvr14:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #16
    b.lo .Lrestore_dbgbvr15
    ldr x1, [x0, #1656]
    msr dbgbvr15_el1, x1
.Lrestore_dbgbvr15:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #1
    b.lo .Lrestore_dbgbcr0
    ldr x1, [x0, #1664]
    msr dbgbcr0_el1, x1
.Lrestore_dbgbcr0:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #2
    b.lo .Lrestore_dbgbcr1
    ldr x1, [x0, #1672]
    msr dbgbcr1_el1, x1
.Lrestore_dbgbcr1:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #3
    b.lo .Lrestore_dbgbcr2
    ldr x1, [x0, #1680]
    msr dbgbcr2_el1, x1
.Lrestore_dbgbcr2:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #4
    b.lo .Lrestore_dbgbcr3
    ldr x1, [x0, #1688]
    msr dbgbcr3_el1, x1
.Lrestore_dbgbcr3:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #5
    b.lo .Lrestore_dbgbcr4
    ldr x1, [x0, #1696]
    msr dbgbcr4_el1, x1
.Lrestore_dbgbcr4:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #6
    b.lo .Lrestore_dbgbcr5
    ldr x1, [x0, #1704]
    msr dbgbcr5_el1, x1
.Lrestore_dbgbcr5:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #7
    b.lo .Lrestore_dbgbcr6
    ldr x1, [x0, #1712]
    msr dbgbcr6_el1, x1
.Lrestore_dbgbcr6:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #8
    b.lo .Lrestore_dbgbcr7
    ldr x1, [x0, #1720]
    msr dbgbcr7_el1, x1
.Lrestore_dbgbcr7:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #9
    b.lo .Lrestore_dbgbcr8
    ldr x1, [x0, #1728]
    msr dbgbcr8_el1, x1
.Lrestore_dbgbcr8:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #10
    b.lo .Lrestore_dbgbcr9
    ldr x1, [x0, #1736]
    msr dbgbcr9_el1, x1
.Lrestore_dbgbcr9:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #11
    b.lo .Lrestore_dbgbcr10
    ldr x1, [x0, #1744]
    msr dbgbcr10_el1, x1
.Lrestore_dbgbcr10:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #12
    b.lo .Lrestore_dbgbcr11
    ldr x1, [x0, #1752]
    msr dbgbcr11_el1, x1
.Lrestore_dbgbcr11:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #13
    b.lo .Lrestore_dbgbcr12
    ldr x1, [x0, #1760]
    msr dbgbcr12_el1, x1
.Lrestore_dbgbcr12:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #14
    b.lo .Lrestore_dbgbcr13
    ldr x1, [x0, #1768]
    msr dbgbcr13_el1, x1
.Lrestore_dbgbcr13:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #15
    b.lo .Lrestore_dbgbcr14
    ldr x1, [x0, #1776]
    msr dbgbcr14_el1, x1
.Lrestore_dbgbcr14:

    adrp x2, uw_break_count
    ldr x2, [x2, :lo12:uw_break_count]
    cmp x2, #16
    b.lo .Lrestore_dbgbcr15
    ldr x1, [x0, #1784]
    msr dbgbcr15_el1, x1
.Lrestore_dbgbcr15:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #1
    b.lo .Lrestore_dbgwvr0
    ldr x1, [x0, #1792]
    msr dbgwvr0_el1, x1
.Lrestore_dbgwvr0:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #2
    b.lo .Lrestore_dbgwvr1
    ldr x1, [x0, #1800]
    msr dbgwvr1_el1, x1
.Lrestore_dbgwvr1:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #3
    b.lo .Lrestore_dbgwvr2
    ldr x1, [x0, #1808]
    msr dbgwvr2_el1, x1
.Lrestore_dbgwvr2:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #4
    b.lo .Lrestore_dbgwvr3
    ldr x1, [x0, #1816]
    msr dbgwvr3_el1, x1
.Lrestore_dbgwvr3:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #5
    b.lo .Lrestore_dbgwvr4
    ldr x1, [x0, #1824]
    msr dbgwvr4_el1, x1
.Lrestore_dbgwvr4:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #6
    b.lo .Lrestore_dbgwvr5
    ldr x1, [x0, #1832]
    msr dbgwvr5_el1, x1
.Lrestore_dbgwvr5:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #7
    b.lo .Lrestore_dbgwvr6
    ldr x1, [x0, #1840]
    msr dbgwvr6_el1, x1
.Lrestore_dbgwvr6:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #8
    b.lo .Lrestore_dbgwvr7
    ldr x1, [x0, #1848]
    msr dbgwvr7_el1, x1
.Lrestore_dbgwvr7:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #9
    b.lo .Lrestore_dbgwvr8
    ldr x1, [x0, #1856]
    msr dbgwvr8_el1, x1
.Lrestore_dbgwvr8:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #10
    b.lo .Lrestore_dbgwvr9
    ldr x1, [x0, #1864]
    msr dbgwvr9_el1, x1
.Lrestore_dbgwvr9:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #11
    b.lo .Lrestore_dbgwvr10
    ldr x1, [x0, #1872]
    msr dbgwvr10_el1, x1
.Lrestore_dbgwvr10:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #12
    b.lo .Lrestore_dbgwvr11
    ldr x1, [x0, #1880]
    msr dbgwvr11_el1, x1
.Lrestore_dbgwvr11:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #13
    b.lo .Lrestore_dbgwvr12
    ldr x1, [x0, #1888]
    msr dbgwvr12_el1, x1
.Lrestore_dbgwvr12:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #14
    b.lo .Lrestore_dbgwvr13
    ldr x1, [x0, #1896]
    msr dbgwvr13_el1, x1
.Lrestore_dbgwvr13:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #15
    b.lo .Lrestore_dbgwvr14
    ldr x1, [x0, #1904]
    msr dbgwvr14_el1, x1
.Lrestore_dbgwvr14:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #16
    b.lo .Lrestore_dbgwvr15
    ldr x1, [x0, #1912]
    msr dbgwvr15_el1, x1
.Lrestore_dbgwvr15:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #1
    b.lo .Lrestore_dbgwcr0
    ldr x1, [x0, #1920]
    msr dbgwcr0_el1, x1
.Lrestore_dbgwcr0:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #2
    b.lo .Lrestore_dbgwcr1
    ldr x1, [x0, #1928]
    msr dbgwcr1_el1, x1
.Lrestore_dbgwcr1:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #3
    b.lo .Lrestore_dbgwcr2
    ldr x1, [x0, #1936]
    msr dbgwcr2_el1, x1
.Lrestore_dbgwcr2:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #4
    b.lo .Lrestore_dbgwcr3
    ldr x1, [x0, #1944]
    msr dbgwcr3_el1, x1
.Lrestore_dbgwcr3:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #5
    b.lo .Lrestore_dbgwcr4
    ldr x1, [x0, #1952]
    msr dbgwcr4_el1, x1
.Lrestore_dbgwcr4:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #6
    b.lo .Lrestore_dbgwcr5
    ldr x1, [x0, #1960]
    msr dbgwcr5_el1, x1
.Lrestore_dbgwcr5:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #7
    b.lo .Lrestore_dbgwcr6
    ldr x1, [x0, #1968]
    msr dbgwcr6_el1, x1
.Lrestore_dbgwcr6:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #8
    b.lo .Lrestore_dbgwcr7
    ldr x1, [x0, #1976]
    msr dbgwcr7_el1, x1
.Lrestore_dbgwcr7:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #9
    b.lo .Lrestore_dbgwcr8
    ldr x1, [x0, #1984]
    msr dbgwcr8_el1, x1
.Lrestore_dbgwcr8:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #10
    b.lo .Lrestore_dbgwcr9
    ldr x1, [x0, #1992]
    msr dbgwcr9_el1, x1
.Lrestore_dbgwcr9:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #11
    b.lo .Lrestore_dbgwcr10
    ldr x1, [x0, #2000]
    msr dbgwcr10_el1, x1
.Lrestore_dbgwcr10:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #12
    b.lo .Lrestore_dbgwcr11
    ldr x1, [x0, #2008]
    msr dbgwcr11_el1, x1
.Lrestore_dbgwcr11:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #13
    b.lo .Lrestore_dbgwcr12
    ldr x1, [x0, #2016]
    msr dbgwcr12_el1, x1
.Lrestore_dbgwcr12:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #14
    b.lo .Lrestore_dbgwcr13
    ldr x1, [x0, #2024]
    msr dbgwcr13_el1, x1
.Lrestore_dbgwcr13:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #15
    b.lo .Lrestore_dbgwcr14
    ldr x1, [x0, #2032]
    msr dbgwcr14_el1, x1
.Lrestore_dbgwcr14:

    adrp x2, uw_watch_count
    ldr x2, [x2, :lo12:uw_watch_count]
    cmp x2, #16
    b.lo .Lrestore_dbgwcr15
    ldr x1, [x0, #2040]
    msr dbgwcr15_el1, x1
.Lrestore_dbgwcr15:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #1
    b.lo .Lrestore_pmevcntr0
    ldr x1, [x0, #2048]
    msr pmevcntr0_el0, x1
.Lrestore_pmevcntr0:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #2
    b.lo .Lrestore_pmevcntr1
    ldr x1, [x0, #2056]
    msr pmevcntr1_el0, x1
.Lrestore_pmevcntr1:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #3
    b.lo .Lrestore_pmevcntr2
    ldr x1, [x0, #2064]
    msr pmevcntr2_el0, x1
.Lrestore_pmevcntr2:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #4
    b.lo .Lrestore_pmevcntr3
    ldr x1, [x0, #2072]
    msr pmevcntr3_el0, x1
.Lrestore_pmevcntr3:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #5
    b.lo .Lrestore_pmevcntr4
    ldr x1, [x0, #2080]
    msr pmevcntr4_el0, x1
.Lrestore_pmevcntr4:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #6
    b.lo .Lrestore_pmevcntr5
    ldr x1, [x0, #2088]
    msr pmevcntr5_el0, x1
.Lrestore_pmevcntr5:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #7
    b.lo .Lrestore_pmevcntr6
    ldr x1, [x0, #2096]
    msr pmevcntr6_el0, x1
.Lrestore_pmevcntr6:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #8
    b.lo .Lrestore_pmevcntr7
    ldr x1, [x0, #2104]
    msr pmevcntr7_el0, x1
.Lrestore_pmevcntr7:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #9
    b.lo .Lrestore_pmevcntr8
    ldr x1, [x0, #2112]
    msr pmevcntr8_el0, x1
.Lrestore_pmevcntr8:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #10
    b.lo .Lrestore_pmevcntr9
    ldr x1, [x0, #2120]
    msr pmevcntr9_el0, x1
.Lrestore_pmevcntr9:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #11
    b.lo .Lrestore_pmevcntr10
    ldr x1, [x0, #2128]
    msr pmevcntr10_el0, x1
.Lrestore_pmevcntr10:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #12
    b.lo .Lrestore_pmevcntr11
    ldr x1, [x0, #2136]
    msr pmevcntr11_el0, x1
.Lrestore_pmevcntr11:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #13
    b.lo .Lrestore_pmevcntr12
    ldr x1, [x0, #2144]
    msr pmevcntr12_el0, x1
.Lrestore_pmevcntr12:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #14
    b.lo .Lrestore_pmevcntr13
    ldr x1, [x0, #2152]
    msr pmevcntr13_el0, x1
.Lrestore_pmevcntr13:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #15
    b.lo .Lrestore_pmevcntr14
    ldr x1, [x0, #2160]
    msr pmevcntr14_el0, x1
.Lrestore_pmevcntr14:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #16
    b.lo .Lrestore_pmevcntr15
    ldr x1, [x0, #2168]
    msr pmevcntr15_el0, x1
.Lrestore_pmevcntr15:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #17
    b.lo .Lrestore_pmevcntr16
    ldr x1, [x0, #2176]
    msr pmevcntr16_el0, x1
.Lrestore_pmevcntr16:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #18
    b.lo .Lrestore_pmevcntr17
    ldr x1, [x0, #2184]
    msr pmevcntr17_el0, x1
.Lrestore_pmevcntr17:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #19
    b.lo .Lrestore_pmevcntr18
    ldr x1, [x0, #2192]
    msr pmevcntr18_el0, x1
.Lrestore_pmevcntr18:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #20
    b.lo .Lrestore_pmevcntr19
    ldr x1, [x0, #2200]
    msr pmevcntr19_el0, x1
.Lrestore_pmevcntr19:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #21
    b.lo .Lrestore_pmevcntr20
    ldr x1, [x0, #2208]
    msr pmevcntr20_el0, x1
.Lrestore_pmevcntr20:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #22
    b.lo .Lrestore_pmevcntr21
    ldr x1, [x0, #2216]
    msr pmevcntr21_el0, x1
.Lrestore_pmevcntr21:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #23
    b.lo .Lrestore_pmevcntr22
    ldr x1, [x0, #2224]
    msr pmevcntr22_el0, x1
.Lrestore_pmevcntr22:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #24
    b.lo .Lrestore_pmevcntr23
    ldr x1, [x0, #2232]
    msr pmevcntr23_el0, x1
.Lrestore_pmevcntr23:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #25
    b.lo .Lrestore_pmevcntr24
    ldr x1, [x0, #2240]
    msr pmevcntr24_el0, x1
.Lrestore_pmevcntr24:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #26
    b.lo .Lrestore_pmevcntr25
    ldr x1, [x0, #2248]
    msr pmevcntr25_el0, x1
.Lrestore_pmevcntr25:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #27
    b.lo .Lrestore_pmevcntr26
    ldr x1, [x0, #2256]
    msr pmevcntr26_el0, x1
.Lrestore_pmevcntr26:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #28
    b.lo .Lrestore_pmevcntr27
    ldr x1, [x0, #2264]
    msr pmevcntr27_el0, x1
.Lrestore_pmevcntr27:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #29
    b.lo .Lrestore_pmevcntr28
    ldr x1, [x0, #2272]
    msr pmevcntr28_el0, x1
.Lrestore_pmevcntr28:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #30
    b.lo .Lrestore_pmevcntr29
    ldr x1, [x0, #2280]
    msr pmevcntr29_el0, x1
.Lrestore_pmevcntr29:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #31
    b.lo .Lrestore_pmevcntr30
    ldr x1, [x0, #2288]
    msr pmevcntr30_el0, x1
.Lrestore_pmevcntr30:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #1
    b.lo .Lrestore_pmevtyper0
    ldr x1, [x0, #2304]
    msr pmevtyper0_el0, x1
.Lrestore_pmevtyper0:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #2
    b.lo .Lrestore_pmevtyper1
    ldr x1, [x0, #2312]
    msr pmevtyper1_el0, x1
.Lrestore_pmevtyper1:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #3
    b.lo .Lrestore_pmevtyper2
    ldr x1, [x0, #2320]
    msr pmevtyper2_el0, x1
.Lrestore_pmevtyper2:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #4
    b.lo .Lrestore_pmevtyper3
    ldr x1, [x0, #2328]
    msr pmevtyper3_el0, x1
.Lrestore_pmevtyper3:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #5
    b.lo .Lrestore_pmevtyper4
    ldr x1, [x0, #2336]
    msr pmevtyper4_el0, x1
.Lrestore_pmevtyper4:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #6
    b.lo .Lrestore_pmevtyper5
    ldr x1, [x0, #2344]
    msr pmevtyper5_el0, x1
.Lrestore_pmevtyper5:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #7
    b.lo .Lrestore_pmevtyper6
    ldr x1, [x0, #2352]
    msr pmevtyper6_el0, x1
.Lrestore_pmevtyper6:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #8
    b.lo .Lrestore_pmevtyper7
    ldr x1, [x0, #2360]
    msr pmevtyper7_el0, x1
.Lrestore_pmevtyper7:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #9
    b.lo .Lrestore_pmevtyper8
    ldr x1, [x0, #2368]
    msr pmevtyper8_el0, x1
.Lrestore_pmevtyper8:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #10
    b.lo .Lrestore_pmevtyper9
    ldr x1, [x0, #2376]
    msr pmevtyper9_el0, x1
.Lrestore_pmevtyper9:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #11
    b.lo .Lrestore_pmevtyper10
    ldr x1, [x0, #2384]
    msr pmevtyper10_el0, x1
.Lrestore_pmevtyper10:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #12
    b.lo .Lrestore_pmevtyper11
    ldr x1, [x0, #2392]
    msr pmevtyper11_el0, x1
.Lrestore_pmevtyper11:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #13
    b.lo .Lrestore_pmevtyper12
    ldr x1, [x0, #2400]
    msr pmevtyper12_el0, x1
.Lrestore_pmevtyper12:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #14
    b.lo .Lrestore_pmevtyper13
    ldr x1, [x0, #2408]
    msr pmevtyper13_el0, x1
.Lrestore_pmevtyper13:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #15
    b.lo .Lrestore_pmevtyper14
    ldr x1, [x0, #2416]
    msr pmevtyper14_el0, x1
.Lrestore_pmevtyper14:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #16
    b.lo .Lrestore_pmevtyper15
    ldr x1, [x0, #2424]
    msr pmevtyper15_el0, x1
.Lrestore_pmevtyper15:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #17
    b.lo .Lrestore_pmevtyper16
    ldr x1, [x0, #2432]
    msr pmevtyper16_el0, x1
.Lrestore_pmevtyper16:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #18
    b.lo .Lrestore_pmevtyper17
    ldr x1, [x0, #2440]
    msr pmevtyper17_el0, x1
.Lrestore_pmevtyper17:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #19
    b.lo .Lrestore_pmevtyper18
    ldr x1, [x0, #2448]
    msr pmevtyper18_el0, x1
.Lrestore_pmevtyper18:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #20
    b.lo .Lrestore_pmevtyper19
    ldr x1, [x0, #2456]
    msr pmevtyper19_el0, x1
.Lrestore_pmevtyper19:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #21
    b.lo .Lrestore_pmevtyper20
    ldr x1, [x0, #2464]
    msr pmevtyper20_el0, x1
.Lrestore_pmevtyper20:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #22
    b.lo .Lrestore_pmevtyper21
    ldr x1, [x0, #2472]
    msr pmevtyper21_el0, x1
.Lrestore_pmevtyper21:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #23
    b.lo .Lrestore_pmevtyper22
    ldr x1, [x0, #2480]
    msr pmevtyper22_el0, x1
.Lrestore_pmevtyper22:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #24
    b.lo .Lrestore_pmevtyper23
    ldr x1, [x0, #2488]
    msr pmevtyper23_el0, x1
.Lrestore_pmevtyper23:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #25
    b.lo .Lrestore_pmevtyper24
    ldr x1, [x0, #2496]
    msr pmevtyper24_el0, x1
.Lrestore_pmevtyper24:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #26
    b.lo .Lrestore_pmevtyper25
    ldr x1, [x0, #2504]
    msr pmevtyper25_el0, x1
.Lrestore_pmevtyper25:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #27
    b.lo .Lrestore_pmevtyper26
    ldr x1, [x0, #2512]
    msr pmevtyper26_el0, x1
.Lrestore_pmevtyper26:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #28
    b.lo .Lrestore_pmevtyper27
    ldr x1, [x0, #2520]
    msr pmevtyper27_el0, x1
.Lrestore_pmevtyper27:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #29
    b.lo .Lrestore_pmevtyper28
    ldr x1, [x0, #2528]
    msr pmevtyper28_el0, x1
.Lrestore_pmevtyper28:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #30
    b.lo .Lrestore_pmevtyper29
    ldr x1, [x0, #2536]
    msr pmevtyper29_el0, x1
.Lrestore_pmevtyper29:

    adrp x2, uw_pmu_count
    ldr x2, [x2, :lo12:uw_pmu_count]
    cmp x2, #31
    b.lo .Lrestore_pmevtyper30
    ldr x1, [x0, #2544]
    msr pmevtyper30_el0, x1
.Lrestore_pmevtyper30:
    UW_SYS_RESTORE pmcntenset_el0, 608
    UW_SYS_RESTORE pmovsset_el0, 616
    UW_SYS_RESTORE pmintenset_el1, 648
    ldr x1, [x0, #600]
    bic x1, x1, #6 // P/C are commands, not persisted state.
    msr pmcr_el0, x1
    UW_SYS_RESTORE cntv_ctl_el0, 456
    UW_SYS_RESTORE mdscr_el1, 496
    ldr x1, [x0, #544]
    ubfx x1, x1, #1, #1
    msr oslar_el1, x1
    UW_SYS_RESTORE osdlr_el1, 552
    UW_SYS_RESTORE ich_hcr_el2, 704
    UW_SYS_RESTORE fpcr, 520
    UW_SYS_RESTORE fpsr, 528
    add x3, x0, #UW_FP
    ldp q0, q1, [x3, #0]
    ldp q2, q3, [x3, #32]
    ldp q4, q5, [x3, #64]
    ldp q6, q7, [x3, #96]
    ldp q8, q9, [x3, #128]
    ldp q10, q11, [x3, #160]
    ldp q12, q13, [x3, #192]
    ldp q14, q15, [x3, #224]
    ldp q16, q17, [x3, #256]
    ldp q18, q19, [x3, #288]
    ldp q20, q21, [x3, #320]
    ldp q22, q23, [x3, #352]
    ldp q24, q25, [x3, #384]
    ldp q26, q27, [x3, #416]
    ldp q28, q29, [x3, #448]
    ldp q30, q31, [x3, #480]
    dsb sy
    isb
    ret

.macro UW_VECTOR target
    b \target
    .space 124
.endm
.section .vectors, "ax", %progbits
.balign 2048
uw_vectors:
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_lower_sync
    UW_VECTOR uw_lower_irq
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected
    UW_VECTOR uw_unexpected

.section .text, "ax", %progbits
uw_lower_sync:
    stp x0, x1, [sp, #-16]!
    mov x0, #0
    b uw_exception
uw_lower_irq:
    stp x0, x1, [sp, #-16]!
    // Claim a level IRQ before deasserting the timer; reversing these two
    // operations can turn a genuine timer exception into spurious IAR1023.
    mrs x0, icc_iar1_el1
    adrp x1, uw_irq_latched
    str x0, [x1, :lo12:uw_irq_latched]
    mov x0, #1
    msr cnthp_ctl_el2, xzr
uw_exception:
    msr daifset, #0xf
    // Preserve reason temporarily in EL2-only TPIDR; all guest GPRs remain
    // available until copied. TPIDR_EL2 is never exposed to either world.
    msr tpidr_el2, x0
    adrp x0, uw_current
    ldr x0, [x0, :lo12:uw_current]
    adrp x1, uw_contexts
    add x1, x1, :lo12:uw_contexts
    add x0, x1, x0, lsl #12
    stp x2, x3, [x0, #16]
    stp x4, x5, [x0, #32]
    stp x6, x7, [x0, #48]
    stp x8, x9, [x0, #64]
    stp x10, x11, [x0, #80]
    stp x12, x13, [x0, #96]
    stp x14, x15, [x0, #112]
    stp x16, x17, [x0, #128]
    stp x18, x19, [x0, #144]
    stp x20, x21, [x0, #160]
    stp x22, x23, [x0, #176]
    stp x24, x25, [x0, #192]
    stp x26, x27, [x0, #208]
    stp x28, x29, [x0, #224]
    str x30, [x0, #240]
    ldp x2, x3, [sp], #16
    stp x2, x3, [x0]
    mrs x1, elr_el2
    str x1, [x0, #UW_PC]
    mrs x1, spsr_el2
    str x1, [x0, #UW_PSTATE]
    mov x19, x0
    mrs x20, tpidr_el2
    bl uw_save_arch
    mov x0, x19
    mov x1, x20
    mrs x2, esr_el2
    mrs x3, far_el2
    mrs x4, hpfar_el2
    bl uw_handle_exit
    cmp x0, #2
    b.hs uw_halt
    adrp x1, uw_current
    str x0, [x1, :lo12:uw_current]
    adrp x19, uw_contexts
    add x19, x19, :lo12:uw_contexts
    add x19, x19, x0, lsl #12
    bl uw_next_deadline
    adrp x1, uw_deadline
    str x0, [x1, :lo12:uw_deadline]
    mov x0, x19
    bl uw_restore_arch
    // The dispatcher owns an ABSOLUTE deadline. Rearming after a sync exit
    // never postpones it, so adversarial MMIO cannot starve the other world.
    bl uw_timer_rearm
uw_enter_saved:
    ldr x0, [x19, #UW_PC]
    msr elr_el2, x0
    ldr x0, [x19, #UW_PSTATE]
    msr spsr_el2, x0
    mov x30, x19
    clrex
    dsb sy
    isb
    ldp x0, x1, [x30, #0]
    ldp x2, x3, [x30, #16]
    ldp x4, x5, [x30, #32]
    ldp x6, x7, [x30, #48]
    ldp x8, x9, [x30, #64]
    ldp x10, x11, [x30, #80]
    ldp x12, x13, [x30, #96]
    ldp x14, x15, [x30, #112]
    ldp x16, x17, [x30, #128]
    ldp x18, x19, [x30, #144]
    ldp x20, x21, [x30, #160]
    ldp x22, x23, [x30, #176]
    ldp x24, x25, [x30, #192]
    ldp x26, x27, [x30, #208]
    ldp x28, x29, [x30, #224]
    ldr x30, [x30, #240]
    eret
uw_unexpected:
    msr daifset, #0xf
    mrs x0, esr_el2
    mrs x1, far_el2
    mrs x2, elr_el2
    bl uw_unexpected_exit
    b uw_halt
.global uw_halt
.global kw_halt
uw_halt:
kw_halt:
    msr daifset, #0xf
    msr cnthp_ctl_el2, xzr
1:  wfe
    b 1b

.section .bss, "aw", %nobits
.balign 4096
uw_contexts: .skip 8192
uw_root0: .skip 4096
uw_root1: .skip 4096
uw_ram0: .skip 4096
uw_ram1: .skip 4096
.balign 16
uw_current: .skip 8
uw_lr_count: .skip 8
uw_apr_count: .skip 8
uw_pmu_count: .skip 8
uw_break_count: .skip 8
uw_watch_count: .skip 8
uw_tick_period: .skip 8
uw_deadline: .skip 8
uw_irq_latched: .skip 8
.balign 16
uw_stack: .skip 524288
uw_stack_top:

