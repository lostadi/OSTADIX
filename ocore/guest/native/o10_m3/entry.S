.section .text.entry, "ax"
.global _start
.type _start, %function
_start:
    msr daifset, #15
    mov x19, x0
    ldr x1, =0x40200000
    mov sp, x1
    ldr x1, =__bss_start
    ldr x2, =__bss_end
1:  cmp x1, x2
    b.hs 2f
    str xzr, [x1], #8
    b 1b
2:  mov x0, x19
    bl fixture_main
    brk #0x10
.size _start, . - _start
