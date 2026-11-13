/* Linux test carrier only; no libc or dynamic loader. */
.section .text
.global _start
_start:
    xor %rbp, %rbp
    and $-16, %rsp
    call main
    mov %eax, %edi
    mov $60, %eax
    syscall
.global test_write
test_write:
    mov %rsi, %rdx
    mov %rdi, %rsi
    mov $1, %edi
    mov $1, %eax
    syscall
    ret
.section .note.GNU-stack,"",@progbits
