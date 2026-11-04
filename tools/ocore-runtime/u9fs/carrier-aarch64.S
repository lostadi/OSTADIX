/* Linux test carrier under QEMU user emulation only; no libc or loader. */
.text
.global _start
_start:
    bl main
    mov x8, #93
    svc #0
.global test_write
test_write:
    mov x2, x1
    mov x1, x0
    mov x0, #1
    mov x8, #64
    svc #0
    ret
.section .note.GNU-stack,"",@progbits
