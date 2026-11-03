.text
.global posix_probe_flush
.type posix_probe_flush,@function
posix_probe_flush:
    mov %rdi,%cr3
    ret
.global posix_probe_flags
.type posix_probe_flags,@function
posix_probe_flags:
    pushfq
    pop %rax
    ret
.section .note.GNU-stack,"",@progbits
