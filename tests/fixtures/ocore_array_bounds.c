typedef unsigned long u64;
extern u64 bounds_case(u64);

static long write_byte(char *value) {
#if defined(__x86_64__)
    register long result __asm__("rax") = 1;
    __asm__ volatile("syscall" : "+a"(result) : "D"(1L), "S"(value), "d"(1L) : "rcx", "r11", "memory");
    return result;
#elif defined(__aarch64__)
    register long x0 __asm__("x0") = 1;
    register char *x1 __asm__("x1") = value;
    register long x2 __asm__("x2") = 1;
    register long x8 __asm__("x8") = 64;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
#elif defined(__riscv) && __riscv_xlen == 64
    register long a0 __asm__("a0") = 1;
    register char *a1 __asm__("a1") = value;
    register long a2 __asm__("a2") = 1;
    register long a7 __asm__("a7") = 64;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    return a0;
#else
#error Unsupported bounds carrier ISA
#endif
}

__attribute__((noreturn)) void bounds_exit(u64 code) {
#if defined(__x86_64__)
    __asm__ volatile("syscall" : : "a"(60L), "D"(code) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
    register u64 x0 __asm__("x0") = code;
    register long x8 __asm__("x8") = 93;
    __asm__ volatile("svc #0" : : "r"(x0), "r"(x8) : "memory");
#else
    register u64 a0 __asm__("a0") = code;
    register long a7 __asm__("a7") = 93;
    __asm__ volatile("ecall" : : "r"(a0), "r"(a7) : "memory");
#endif
    __builtin_unreachable();
}

void bounds_event(u64 code) {
    char value = (char)code;
    if (write_byte(&value) != 1) bounds_exit(98);
}

int bounds_main(void) {
    u64 result = bounds_case(BOUNDS_CASE);
    if (result != (u64)BOUNDS_EXPECTED) {
        bounds_event('!');
        bounds_exit(99);
    }
    bounds_event('P');
    bounds_event('\n');
    return 0;
}

#if defined(__x86_64__)
__asm__(".text\n.globl _start\n_start:\n  xor %ebp,%ebp\n  and $-16,%rsp\n  call bounds_main\n  mov %eax,%edi\n  mov $60,%eax\n  syscall\n  ud2\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n_start:\n  bl bounds_main\n  mov x8,#93\n  svc #0\n  brk #0\n");
#else
__asm__(".text\n.globl _start\n_start:\n  call bounds_main\n  li a7,93\n  ecall\n  unimp\n");
#endif
