.text
.global _start
.type _start,@function
_start:
    mov %rsp,%rdi
    xor %ebp,%ebp
    call probe
    ud2
.section .note.GNU-stack,"",@progbits
