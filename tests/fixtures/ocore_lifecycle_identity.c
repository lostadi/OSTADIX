#include <stdint.h>
#include <stddef.h>

extern uint64_t lifecycle_identity_probe(uint64_t, uint64_t, uint64_t, uint64_t *);
extern uint64_t lifecycle_identity_layout(void);

static long system_call(long number, long first, long second, long third) {
#if defined(__x86_64__)
    register long rax __asm__("rax") = number;
    __asm__ volatile("syscall" : "+a"(rax) : "D"(first), "S"(second), "d"(third) : "rcx", "r11", "memory");
    return rax;
#elif defined(__aarch64__)
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = first;
    register long x1 __asm__("x1") = second;
    register long x2 __asm__("x2") = third;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
#elif defined(__riscv) && __riscv_xlen == 64
    register long a7 __asm__("a7") = number;
    register long a0 __asm__("a0") = first;
    register long a1 __asm__("a1") = second;
    register long a2 __asm__("a2") = third;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7), "r"(a1), "r"(a2) : "memory");
    return a0;
#else
#error Missing lifecycle carrier ISA
#endif
}

__attribute__((noreturn)) static void finish(long code) {
#if defined(__x86_64__)
    system_call(60, code, 0, 0);
#else
    system_call(93, code, 0, 0);
#endif
    __builtin_trap();
}

__attribute__((used,noreturn)) void lifecycle_carrier_main(void) {
    const uint64_t values[] = {0, 1, 2, UINT32_MAX-1ULL, UINT32_MAX,
        UINT64_C(0x100000000), UINT64_C(0x7bed31e65e6f3ac6),
        UINT64_C(0xe3c89e5e834b8c17), UINT64_MAX-1, UINT64_MAX};
    for (uint64_t kind=0; kind<3; ++kind) {
        uint64_t limit=kind==0 ? UINT32_MAX : UINT64_MAX;
        for (unsigned i=0; i<sizeof(values)/sizeof(values[0]); ++i) {
            uint64_t raw=values[i];
            for (uint64_t operation=0; operation<2; ++operation) {
                uint64_t output=UINT64_C(0x123456789);
                uint64_t status=lifecycle_identity_probe(kind,raw,operation,&output);
                uint64_t valid=raw!=0 && (operation==0 ? raw<=limit : raw<limit);
                uint64_t expected=valid ? raw+operation : 29;
                if (status!=valid || output!=expected) finish(10+(long)kind);
            }
        }
        uint64_t output=0;
        if (lifecycle_identity_probe(kind,1,2,&output)!=0 || output!=29) finish(20+(long)kind);
    }
    if (lifecycle_identity_layout()!=UINT64_C(0x118100808)) finish(30);
    static const char message[]="OCORE-LIFECYCLE-IDENTITY cases=64\n";
#if defined(__x86_64__)
    const long write_number=1;
#else
    const long write_number=64;
#endif
    if (system_call(write_number,1,(long)message,sizeof(message)-1)!=(long)sizeof(message)-1) finish(31);
    finish(0);
}

#if defined(__x86_64__)
__asm__(".global _start\n_start:\nxor %rbp,%rbp\nand $-16,%rsp\ncall lifecycle_carrier_main\nud2\n");
#elif defined(__aarch64__)
__asm__(".global _start\n_start:\nbl lifecycle_carrier_main\nbrk #0\n");
#else
__asm__(".global _start\n_start:\nandi sp,sp,-16\ncall lifecycle_carrier_main\nunimp\n");
#endif
