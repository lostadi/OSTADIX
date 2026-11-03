.arch armv8-a
.section .text.boot, "ax", %progbits
.global _start
_start:
    msr daifset, #0xf
    mrs x0, CurrentEL
    cmp x0, #8
    b.ne p9_halt
    adrp x0, p9_stack_top
    add x0, x0, :lo12:p9_stack_top
    mov sp, x0
    adrp x0, __bss_start
    add x0, x0, :lo12:__bss_start
    adrp x1, __bss_end
    add x1, x1, :lo12:__bss_end
1:
    cmp x0, x1
    b.hs 2f
    str xzr, [x0], #8
    b 1b
2:
    adrp x0, p9_vectors
    add x0, x0, :lo12:p9_vectors
    msr vbar_el2, x0
    msr cptr_el2, xzr
    msr mdcr_el2, xzr
    mov x0, #3
    msr cnthctl_el2, x0
    msr cntvoff_el2, xzr
    mrs x0, midr_el1
    msr vpidr_el2, x0
    mrs x0, mpidr_el1
    msr vmpidr_el2, x0
    // This isolated lane explicitly assigns one emulated GICv3 controller.
    // Enable its EL1 system-register interface; it is not a multi-domain vGIC.
    mov x0, #9
    msr ICC_SRE_EL2, x0
    isb
    mov x0, #1
    msr ICC_SRE_EL1, x0
    isb
    bl p9_stage2_install
    bl p9_probe_init
    cbz x0, p9_halt
    movz x0, #0x0800
    movk x0, #0x30d0, lsl #16
    msr sctlr_el1, x0
    msr ttbr0_el1, xzr
    msr ttbr1_el1, xzr
    msr tcr_el1, xzr
    msr mair_el1, xzr
    msr vbar_el1, xzr
    msr contextidr_el1, xzr
    mov x0, #0x300000
    msr cpacr_el1, x0
    mov x0, #0x40100000 // Original 9front ARM64 entry; not Linux Image ABI.
    msr elr_el2, x0
    mov x0, #0x3c5
    msr spsr_el2, x0
    mov x0, #0x40000000 // Original kernel also uses this fixed DTB address.
    mov x1, xzr
    mov x2, xzr
    mov x3, xzr
    dsb sy
    isb
    eret

.section .text, "ax", %progbits
p9_stage2_install:
    adrp x0, p9_stage2_root
    add x0, x0, :lo12:p9_stage2_root
    adrp x1, p9_stage2_devices
    add x1, x1, :lo12:p9_stage2_devices
    orr x2, x1, #3
    str x2, [x0]
    adrp x2, p9_stage2_ram
    add x2, x2, :lo12:p9_stage2_ram
    orr x3, x2, #3
    str x3, [x0, #8]
    // Only guest IPA40000000..60000000 -> PA48000000..68000000.
    movz x3, #0x07fd
    movk x3, #0x4800, lsl #16
    mov x4, #256
1:
    str x3, [x2], #8
    add x3, x3, #0x200, lsl #12
    subs x4, x4, #1
    b.ne 1b
    adrp x2, p9_stage2_gic
    add x2, x2, :lo12:p9_stage2_gic
    orr x3, x2, #3
    str x3, [x1, #512]
    // GIC distributor64KiB; no adjacent physical devices are admitted.
    movz x3, #0x06c3
    movk x3, #0x0800, lsl #16
    movk x3, #0x0040, lsl #48
    mov x4, #16
2:
    str x3, [x2], #8
    add x3, x3, #1, lsl #12
    subs x4, x4, #1
    b.ne 2b
    // Assign only the SGI/PPI half of CPU0's redistributor. The complete
    // RD-control half080a0000..080b0000 stays unmapped and is mediated, so
    // guest LPI configuration can never reach a physical table/DMA pointer.
    adrp x2, p9_stage2_gic
    add x2, x2, :lo12:p9_stage2_gic
    add x2, x2, #1408
    movz x3, #0x06c3
    movk x3, #0x080b, lsl #16
    movk x3, #0x0040, lsl #48
    mov x4, #16
3:
    str x3, [x2], #8
    add x3, x3, #1, lsl #12
    subs x4, x4, #1
    b.ne 3b
    movz x1, #0x3560
    movk x1, #0x8000, lsl #16
    msr vtcr_el2, x1
    mov x1, #1
    lsl x1, x1, #48
    orr x0, x0, x1
    msr vttbr_el2, x0
    dsb sy
    tlbi vmalls12e1is
    dsb sy
    isb
    // RW,VM,TSC,TWI,TWE. The guest never owns EL2 or an arbitrary MMIO map.
    movz x0, #0x6001
    movk x0, #0x8008, lsl #16
    msr hcr_el2, x0
    isb
    ret

.global p9_memory_barrier
p9_memory_barrier:
    dmb sy
    ret
.global p9_namespace_enabled
p9_namespace_enabled:
#ifdef P9_NAMESPACE
    mov x0, #1
#else
    mov x0, #0
#endif
    ret
.global p9_counter_read
p9_counter_read:
    mrs x0, cntpct_el0
    ret
.global p9_counter_frequency
p9_counter_frequency:
    mrs x0, cntfrq_el0
    ret
.global p9_serial_putc
p9_serial_putc:
    mov x1, #0x09000000
1:
    ldr w2, [x1, #0x18]
    tbnz w2, #5, 1b
    str w0, [x1]
    ret
.global p9_serial_try_read
p9_serial_try_read:
    mov x1, #0x09000000
    ldr w2, [x1, #0x18]
    tbnz w2, #4, 1f
    ldr w0, [x1]
    and x0, x0, #0xff
    orr x0, x0, #0x100
    ret
1:
    mov x0, #0
    ret
.global p9_serial_init
p9_serial_init:
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
.global p9_halt
p9_halt:
    msr daifset, #0xf
1:
    wfe
    b 1b

.macro P9_VECTOR target
    b \target
    .space 124
.endm
.section .vectors, "ax", %progbits
.balign 2048
p9_vectors:
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_lower_sync
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected
    P9_VECTOR p9_unexpected

.section .text, "ax", %progbits
p9_lower_sync:
    sub sp, sp, #272
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x0, elr_el2
    str x0, [sp, #248]
    mrs x0, spsr_el2
    str x0, [sp, #256]
    mov x0, sp
    mrs x1, esr_el2
    mrs x2, far_el2
    mrs x3, hpfar_el2
    bl p9_probe_exit
    cbnz x0, p9_halt
    ldr x0, [sp, #248]
    msr elr_el2, x0
    ldr x0, [sp, #256]
    msr spsr_el2, x0
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    add sp, sp, #272
    eret
p9_unexpected:
    mrs x0, esr_el2
    mrs x1, far_el2
    mrs x2, elr_el2
    bl p9_probe_unexpected
    b p9_halt

.section .bss, "aw", %nobits
.balign 4096
p9_stage2_root: .skip 4096
p9_stage2_devices: .skip 4096
p9_stage2_ram: .skip 4096
p9_stage2_gic: .skip 4096
.balign 16
p9_stack: .skip 131072
p9_stack_top:
