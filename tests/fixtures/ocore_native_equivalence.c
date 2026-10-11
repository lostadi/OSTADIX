/* Independent reference and freestanding Linux test entry point. No libc. */
typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef signed char i8;
typedef short i16;

/* Clang may lower even a constant stack initializer to a freestanding call. */
void *memcpy(void *destination, const void *source, unsigned long length) {
    u8 *dst = destination;
    const u8 *src = source;
    for (unsigned long index = 0; index < length; ++index) dst[index] = src[index];
    return destination;
}

extern u64 unsigned_mix(u64, u64, u32);
extern u64 signed_mix(i64, i64, u32);
extern u64 narrow_mix(u8, u16, i8, i16);
extern u32 unsigned32_identity(u32);
extern u64 many_args(u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64);
extern u64 ocore_selftest(void);
extern i64 fault_div(i64, i64);
extern i64 fault_rem(i64, i64);
extern u64 fault_volatile(const u64 *);
extern u64 fault_atomic(const u64 *);
extern u64 diverging_repeat(void);
extern u64 diverging_argument(void);

u64 foreign_sum(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,
                u64 g,u64 h,u64 i,u64 j,u64 k,u64 l) {
    return a+2*b+3*c+4*d+5*e+6*f+7*g+8*h+9*i+10*j+11*k+12*l;
}
u32 foreign_u32(u32 value) { return value; }
u64 foreign_callback(u64 value) { return 3*value+1; }

static u64 native_syscall(u64 number, u64 first, u64 second, u64 third) {
#if defined(__x86_64__)
    register u64 rax __asm__("rax") = number;
    __asm__ volatile("syscall" : "+a"(rax) : "D"(first), "S"(second), "d"(third) : "rcx", "r11", "memory");
    return rax;
#elif defined(__aarch64__)
    register u64 x0 __asm__("x0") = first;
    register u64 x1 __asm__("x1") = second;
    register u64 x2 __asm__("x2") = third;
    register u64 x8 __asm__("x8") = number;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
#elif defined(__riscv) && __riscv_xlen == 64
    register u64 a0 __asm__("a0") = first;
    register u64 a1 __asm__("a1") = second;
    register u64 a2 __asm__("a2") = third;
    register u64 a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    return a0;
#else
#error Unsupported test architecture
#endif
}

static void finish(u64 status) {
#if defined(__x86_64__)
    native_syscall(60, status, 0, 0);
#else
    native_syscall(93, status, 0, 0);
#endif
    __builtin_trap();
}
__attribute__((noreturn)) void runtime_exit(u64 status) { finish(status); __builtin_unreachable(); }
static void write_all(const char *data, u64 length) {
    while (length) {
#if defined(__x86_64__)
        u64 written = native_syscall(1, 1, (u64)data, length);
#else
        u64 written = native_syscall(64, 1, (u64)data, length);
#endif
        if (!written || written > length) finish(99);
        data += written;
        length -= written;
    }
}

int conformance_main(void) {
#if NEVER_CASE == 1
    diverging_repeat(); return 107;
#elif NEVER_CASE == 2
    diverging_argument(); return 108;
#elif FAULT_CASE == 1
    fault_div(9, 0); return 101;
#elif FAULT_CASE == 2
    fault_div((i64)(1ULL << 63), -1); return 102;
#elif FAULT_CASE == 3
    fault_rem(9, 0); return 103;
#elif FAULT_CASE == 4
    fault_rem((i64)(1ULL << 63), -1); return 104;
#elif FAULT_CASE == 5
    fault_volatile((const u64 *)1); return 105;
#elif FAULT_CASE == 6
    fault_atomic((const u64 *)1); return 106;
#else
    u64 selftest = ocore_selftest();
    if (selftest) return (int)selftest;
    if (many_args(1,2,3,4,5,6,7,8,9,10,11,12) != 650) return 31;
    if (unsigned32_identity(0xf1234567U) != 0xf1234567U) return 32;
    u64 state = 0x9e3779b97f4a7c15ULL;
    u64 digest = 0xcbf29ce484222325ULL;
    for (u32 index=0; index<4096; ++index) {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        u64 a=state, b=(state ^ (state >> 31)) | 1;
        u32 shift=index; /* Exercise the common modulo-64 count contract. */
        u64 expected=((a+b)^(a-b)^(a*b))+(a/b)+(a%b)+(a<<(shift&63))+(a>>(shift&63));
        u64 result=unsigned_mix(a,b,shift);
        if (result != expected) return 33;
        digest = (digest ^ result) * 0x100000001b3ULL;
        i64 sa=(i64)a, sb=(i64)(b & 0x7fffffffffffffffULL);
        if (!sb) sb=1; /* No signed division UB in the reference. */
        expected=(u64)(sa/sb)+(u64)(sa%sb)+(u64)(sa>>(shift&63))+(a<<(shift&63));
        result=signed_mix(sa,sb,shift);
        if (result != expected) return 34;
        digest = (digest ^ result) * 0x100000001b3ULL;
        u8 na=(u8)a; u16 nb=(u16)(a>>8); i8 nc=(i8)(a>>24); i16 nd=(i16)(a>>32);
        expected=(u8)((u8)~na/3)+(u8)((u8)-na/5)+(u16)((u16)~nb/7)
            +(u16)((u16)-nb/11)+(u64)(i8)((i8)-nc/3)+(u64)(i16)((i16)~nd/7);
        result=narrow_mix(na,nb,nc,nd);
        if (result != expected) return 35;
        digest = (digest ^ result) * 0x100000001b3ULL;
    }
    /* Fixed hexadecimal encoding makes results byte-comparable across ISAs. */
    char output[]="OCORE-NATIVE-EQUIVALENCE digest=0000000000000000 cases=12288\n";
    const char hex[]="0123456789abcdef";
    for (u32 i=0; i<16; ++i) output[sizeof("OCORE-NATIVE-EQUIVALENCE digest=")-1+i]=hex[(digest >> (60-4*i)) & 15];
    write_all(output, sizeof(output)-1);
    return 0;
#endif
}

/* The Linux entry stack is not a normal C function call on AMD64. */
#if defined(__x86_64__)
__asm__(".text\n.globl _start\n_start:\n  xor %ebp,%ebp\n  and $-16,%rsp\n  call conformance_main\n  mov %eax,%edi\n  mov $60,%eax\n  syscall\n  ud2\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n_start:\n  bl conformance_main\n  mov x8,#93\n  svc #0\n  brk #0\n");
#else
__asm__(".text\n.globl _start\n_start:\n  call conformance_main\n  li a7,93\n  ecall\n  ebreak\n");
#endif
