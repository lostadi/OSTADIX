/* Native RV64GC S-mode bootstrap; OpenSBI owns M mode, never a Linux guest.
 * See ABI.md for the versioned trap frame and explicit bootstrap limits. */
.option norvc
.option norelax

.macro save_gprs base
    sd zero, 0(\base)
    .irp n,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        sd x\n, (\n * 8)(\base)
    .endr
.endm
.macro restore_gprs base
    .irp n,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        ld x\n, (\n * 8)(\base)
    .endr
.endm
.macro save_fprs base
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        fsd f\n, (304 + \n * 8)(\base)
    .endr
.endm
.macro restore_fprs base
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        fld f\n, (304 + \n * 8)(\base)
    .endr
.endm

.section .text.boot,"ax",@progbits
.balign 16
.global _start
.type _start,@function
_start:
    /* OpenSBI boot ABI: a0 hart ID, a1 firmware device-tree address. */
    csrw sie, zero
    csrci sstatus, 2
    mv s0, a0
    mv s1, a1
    la t0, __bss_start
    la t1, __bss_end
1:  bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:  la sp, rv_kernel_stack_top
    la gp, __global_pointer$
    la tp, rv_kernel_tls
    la t0, rv_trap_stack_top
    csrw sscratch, t0
    la t0, rv_trap_entry
    csrw stvec, t0
    csrw satp, zero
    sfence.vma zero, zero
    li t0, 0x6000
    csrs sstatus, t0
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        fmv.d.x f\n, zero
    .endr
    fscsr zero
    mv a0, s0
    mv a1, s1
    call rv_boot_main
    j rv_arch_fatal
.size _start,.-_start

.section .text,"ax",@progbits
.balign 16
.global rv_trap_entry
.type rv_trap_entry,@function
rv_trap_entry:
    /* Swap to a private stack without destroying any interrupted GPR. */
    csrrw sp, sscratch, sp
    beqz sp, rv_arch_fatal
    addi sp, sp, -576
    save_gprs sp
    csrr t0, sscratch
    sd t0, 16(sp)
    /* Nested synchronous faults fail closed; no recursive frame overwrite. */
    csrw sscratch, zero
    csrr t0, sepc
    sd t0, 256(sp)
    csrr t0, sstatus
    sd t0, 264(sp)
    csrr t1, scause
    sd t1, 272(sp)
    csrr t1, stval
    sd t1, 280(sp)
    sd zero, 288(sp)
    sd zero, 296(sp)
    sd zero, 560(sp)
    sd zero, 568(sp)
    li t1, 0x6000
    and t0, t0, t1
    beqz t0, .Lrv_no_fp_save
    frcsr t0
    sd t0, 288(sp)
    save_fprs sp
    li t0, 1
    sd t0, 560(sp)
.Lrv_no_fp_save:
    /* Kernel callbacks have a private TLS base; interrupted tp is in x[4]. */
    la gp, __global_pointer$
    la tp, rv_kernel_tls
    mv a0, sp
    call rv_boot_trap

    /* Deliberately clobber every saved GPR and active FP register. The live
     * probe must observe real restoration rather than untouched registers. */
    .irp n,1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        li x\n, 0
    .endr
    ld t0, 560(sp)
    beqz t0, .Lrv_no_fp_restore
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        fmv.d.x f\n, zero
    .endr
    fscsr zero
    restore_fprs sp
    ld t0, 288(sp)
    fscsr t0
.Lrv_no_fp_restore:
    ld t0, 256(sp)
    csrw sepc, t0
    ld t0, 264(sp)
    csrw sstatus, t0
    la t0, rv_trap_stack_top
    csrw sscratch, t0
    restore_gprs sp
    ld sp, 16(sp)
    sret
.size rv_trap_entry,.-rv_trap_entry

/* Probe all registers across an actual S-mode ebreak/sret. All callee-saved
 * state, gp, tp, and prior sstatus are restored before the C ABI return. */
.global rv_arch_state_probe
.type rv_arch_state_probe,@function
rv_arch_state_probe:
    addi sp, sp, -160
    sd ra, 0(sp)
    sd gp, 8(sp)
    sd tp, 16(sp)
    sd s0, 24(sp)
    sd s1, 32(sp)
    .irp n,2,3,4,5,6,7,8,9,10,11
        sd s\n, (40 + (\n - 2) * 8)(sp)
    .endr
    csrr t0, sstatus
    sd t0, 120(sp)
    sd a0, 128(sp)
    la t0, rv_probe_saved_sp
    sd sp, 0(t0)
    la tp, rv_probe_tls
    li t0, 0x6000
    csrc sstatus, t0
    beqz a0, .Lrv_probe_seed_gprs
    csrs sstatus, t0
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        li t0, (0x3ff0000000000000 + \n)
        fmv.d.x f\n, t0
    .endr
    li t0, 0x65
    fscsr t0
.Lrv_probe_seed_gprs:
    .irp n,1,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
        li x\n, (0x5a00000000000000 + \n)
    .endr
.global rv_probe_breakpoint
rv_probe_breakpoint:
    ebreak
    /* sscratch supplies a scratch register without losing original x[31]. */
    csrrw t6, sscratch, t6
    la t6, rv_probe_snapshot
    sd zero, 0(t6)
    .irp n,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
        sd x\n, (\n * 8)(t6)
    .endr
    csrr t0, sscratch
    sd t0, 248(t6)
    la t0, rv_trap_stack_top
    csrw sscratch, t0
    csrr t0, sepc
    sd t0, 256(t6)
    csrr t0, sstatus
    sd t0, 264(t6)
    csrr t0, scause
    sd t0, 272(t6)
    csrr t0, stval
    sd t0, 280(t6)
    sd zero, 288(t6)
    sd zero, 296(t6)
    sd zero, 560(t6)
    sd zero, 568(t6)
    ld t0, 128(sp)
    beqz t0, .Lrv_probe_return
    frcsr t0
    sd t0, 288(t6)
    save_fprs t6
    li t0, 1
    sd t0, 560(t6)
.Lrv_probe_return:
    ld t0, 120(sp)
    csrw sstatus, t0
    ld ra, 0(sp)
    ld gp, 8(sp)
    ld tp, 16(sp)
    ld s0, 24(sp)
    ld s1, 32(sp)
    .irp n,2,3,4,5,6,7,8,9,10,11
        ld s\n, (40 + (\n - 2) * 8)(sp)
    .endr
    mv a0, t6
    addi sp, sp, 160
    ret
.size rv_arch_state_probe,.-rv_arch_state_probe

.global rv_arch_fp_snapshot
.type rv_arch_fp_snapshot,@function
rv_arch_fp_snapshot:
    la a0, rv_probe_snapshot
    frcsr t0
    sd t0, 288(a0)
    save_fprs a0
    li t0, 1
    sd t0, 560(a0)
    ret
.size rv_arch_fp_snapshot,.-rv_arch_fp_snapshot

.global rv_arch_timer_wait
.type rv_arch_timer_wait,@function
rv_arch_timer_wait:
    addi sp, sp, -32
    sd ra, 0(sp)
    sd s0, 8(sp)
    mv s0, a0
    rdtime a0
    li t0, 10000
    add a0, a0, t0
    call rv_arch_set_timer
    bnez a0, .Lrv_timer_return
    li t0, 32
    csrs sie, t0
    csrsi sstatus, 2
.Lrv_timer_wait:
    ld t0, 0(s0)
    bnez t0, .Lrv_timer_done
    wfi
    j .Lrv_timer_wait
.Lrv_timer_done:
    csrci sstatus, 2
    li t0, 32
    csrc sie, t0
    li a0, 0
.Lrv_timer_return:
    ld ra, 0(sp)
    ld s0, 8(sp)
    addi sp, sp, 32
    ret
.size rv_arch_timer_wait,.-rv_arch_timer_wait

.global rv_arch_set_timer
.type rv_arch_set_timer,@function
rv_arch_set_timer:
    li a6, 0
    li a7, 0x54494d45
    ecall
    ret
.size rv_arch_set_timer,.-rv_arch_set_timer

.global rv_arch_putc
.type rv_arch_putc,@function
rv_arch_putc:
    /* Legacy console is firmware output, not a host-language runtime call. */
    li a7, 1
    ecall
    ret
.size rv_arch_putc,.-rv_arch_putc

.global rv_arch_shutdown
.type rv_arch_shutdown,@function
rv_arch_shutdown:
    mv a1, a0
    li a0, 0
    li a6, 0
    li a7, 0x53525354
    ecall
1:  wfi
    j 1b
.size rv_arch_shutdown,.-rv_arch_shutdown

.macro address_accessor name, symbol
    .global \name
    .type \name,@function
\name:
    la a0, \symbol
    ret
    .size \name,.-\name
.endm
address_accessor rv_arch_kernel_tls, rv_kernel_tls
address_accessor rv_arch_probe_tls, rv_probe_tls
address_accessor rv_arch_expected_gp, __global_pointer$
address_accessor rv_arch_probe_pc, rv_probe_breakpoint
address_accessor rv_arch_trap_stack_low, rv_trap_stack_bottom
address_accessor rv_arch_trap_stack_high, rv_trap_stack_top
.global rv_arch_expected_sp
.type rv_arch_expected_sp,@function
rv_arch_expected_sp:
    la a0, rv_probe_saved_sp
    ld a0, 0(a0)
    ret
.size rv_arch_expected_sp,.-rv_arch_expected_sp
.global rv_arch_current_tp
.type rv_arch_current_tp,@function
rv_arch_current_tp:
    mv a0, tp
    ret
.size rv_arch_current_tp,.-rv_arch_current_tp
.global rv_arch_current_sp
.type rv_arch_current_sp,@function
rv_arch_current_sp:
    mv a0, sp
    ret
.size rv_arch_current_sp,.-rv_arch_current_sp
.global rv_arch_satp
.type rv_arch_satp,@function
rv_arch_satp:
    csrr a0, satp
    ret
.size rv_arch_satp,.-rv_arch_satp

rv_arch_fatal:
    /* Nested traps cannot safely enter compiled code or reuse the trap stack. */
    la t0, .Lrv_fatal_text
    li t1, 0x10000000
1:  lbu t2, 0(t0)
    beqz t2, 2f
    sb t2, 0(t1)
    addi t0, t0, 1
    j 1b
2:  li a0, 1
    j rv_arch_shutdown

.section .rodata,"a",@progbits
.Lrv_fatal_text:
    .asciz "RV64 bootstrap architecture FAIL\n"
.section .data,"aw",@progbits
.balign 16
rv_kernel_tls:
    .quad 0x4f434f5245544c53, 0
rv_probe_tls:
    .quad 0x50524f4245544c53, 1
.section .bss,"aw",@nobits
.balign 16
rv_probe_saved_sp:
    .zero 8
.balign 16
rv_probe_snapshot:
    .zero 576
.section .note.GNU-stack,"",@progbits
