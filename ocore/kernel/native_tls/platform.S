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
 .global tls_probe_cpu_fs_base
.type tls_probe_cpu_fs_base,@function
tls_probe_cpu_fs_base:
    mov $0xc0000100,%ecx
    rdmsr
    shl $32,%rdx
    or %rdx,%rax
    ret
.global tls_probe_cpu_fs_selector
.type tls_probe_cpu_fs_selector,@function
tls_probe_cpu_fs_selector:
    xor %eax,%eax
    mov %fs,%ax
    ret
.section .note.GNU-stack,"",@progbits
