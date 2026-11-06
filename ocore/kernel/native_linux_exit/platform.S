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


.global idle_probe_gs_base
.type idle_probe_gs_base,@function
idle_probe_gs_base:
    mov $0xc0000101,%ecx
    rdmsr
    shl $32,%rdx
    or %rdx,%rax
    ret
.global idle_probe_kernel_gs_base
.type idle_probe_kernel_gs_base,@function
idle_probe_kernel_gs_base:
    mov $0xc0000102,%ecx
    rdmsr
    shl $32,%rdx
    or %rdx,%rax
    ret
.global idle_probe_stack_pointer
.type idle_probe_stack_pointer,@function
idle_probe_stack_pointer:
    lea 8(%rsp),%rax
    ret
.section .note.GNU-stack,"",@progbits
.text
.global idle_probe_set_gs
.type idle_probe_set_gs,@function
idle_probe_set_gs:
    mov %rdi,%rax
    mov %rdi,%rdx
    shr $32,%rdx
    mov $0xc0000101,%ecx
    wrmsr
    ret
.global idle_probe_set_fs
.type idle_probe_set_fs,@function
idle_probe_set_fs:
    mov %rdi,%rax
    mov %rdi,%rdx
    shr $32,%rdx
    mov $0xc0000100,%ecx
    wrmsr
    ret
.global idle_probe_bad_stack_enable
.type idle_probe_bad_stack_enable,@function
idle_probe_bad_stack_enable:
    mov %rsp,%rax
    mov %rdi,%rsp
    and $-16,%rsp
    push %rax
    sub $8,%rsp
    mov %rsp,idle_probe_bad_stack_seen(%rip)
    call _O_runtime__scheduler__enable_personality_idle
    add $8,%rsp
    pop %r11
    mov %r11,%rsp
    ret
.bss
.balign 8
.global idle_probe_bad_stack_seen
idle_probe_bad_stack_seen:
    .skip 8
.section .note.GNU-stack,"",@progbits
