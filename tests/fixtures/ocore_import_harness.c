/* Independent Clang implementation versus the imported O-core implementation. */
typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;
typedef unsigned char u8;
#define DECL(P) \
extern u64 P##unsigned_mix(u64,u64,u32); \
extern u64 P##signed_mix(i64,i64,u32); \
extern u64 P##narrow(u8,signed char,unsigned short,short); \
extern u64 P##loop(u64); \
extern u64 P##many(u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64); \
extern u64 P##call(u64); \
extern u64 P##indirect(u64 (*)(u64),u64); \
extern u64 P##table_call(u64); \
extern u64 P##global(u64); \
extern u64 P##packed(void *,u64); \
extern u64 P##memory(u8 *,u64); \
extern u64 P##stack(u64);
DECL(imported_)
DECL(reference_)
u64 foreign_scalar_callback(u64 a) { return a*3+1; }
u64 foreign_scalar_sum(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u64 i,u64 j,u64 k,u64 l) { return a+2*b+3*c+4*d+5*e+6*f+7*g+8*h+9*i+10*j+11*k+12*l; }

static u64 syscall3(u64 number,u64 a,u64 b,u64 c) {
#if defined(__x86_64__)
    register u64 result __asm__("rax")=number;
    __asm__ volatile("syscall":"+a"(result):"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return result;
#elif defined(__aarch64__)
    register u64 result __asm__("x0")=a; register u64 x1 __asm__("x1")=b; register u64 x2 __asm__("x2")=c; register u64 x8 __asm__("x8")=number;
    __asm__ volatile("svc #0":"+r"(result):"r"(x1),"r"(x2),"r"(x8):"memory"); return result;
#else
    register u64 result __asm__("a0")=a; register u64 a1 __asm__("a1")=b; register u64 a2 __asm__("a2")=c; register u64 a7 __asm__("a7")=number;
    __asm__ volatile("ecall":"+r"(result):"r"(a1),"r"(a2),"r"(a7):"memory"); return result;
#endif
}
int import_main(void) {
    u64 state=0x9e3779b97f4a7c15ULL,digest=0xcbf29ce484222325ULL;
    u8 left[80],right[80];
#define CHECK(n,a,b) do { u64 actual=(a),expected=(b); if (actual!=expected) return n; digest=(digest^actual)*0x100000001b3ULL; } while(0)
    for (u32 i=0;i<2048;i++) {
        state^=state<<13; state^=state>>7; state^=state<<17;
        u64 a=state,b=(state^(state>>31))|1; i64 sb=(i64)(b>>1); if(!sb) sb=1;
        CHECK(1,imported_unsigned_mix(a,b,i),reference_unsigned_mix(a,b,i));
        CHECK(2,imported_signed_mix((i64)a,sb,i),reference_signed_mix((i64)a,sb,i));
        CHECK(3,imported_narrow((u8)a,(signed char)(a>>8),(unsigned short)(a>>16),(short)(a>>32)),reference_narrow((u8)a,(signed char)(a>>8),(unsigned short)(a>>16),(short)(a>>32)));
        CHECK(4,imported_loop(a),reference_loop(a));
        CHECK(5,imported_many(a,2,3,4,5,6,7,8,9,10,11,12),reference_many(a,2,3,4,5,6,7,8,9,10,11,12));
        CHECK(6,imported_call(a),reference_call(a));
        CHECK(7,imported_indirect(foreign_scalar_callback,a),reference_indirect(foreign_scalar_callback,a));
        CHECK(8,imported_table_call(a),reference_table_call(a));
        CHECK(9,imported_global(a),reference_global(a));
        CHECK(10,imported_packed(left+1,a),reference_packed(right+1,a));
        CHECK(11,imported_memory(left,a),reference_memory(right,a));
        for(u32 j=0;j<64;j++) if(left[j]!=right[j]) return 13;
        CHECK(12,imported_stack(a),reference_stack(a));
    }
    char output[]="OCORE-IMPORT digest=0000000000000000 cases=24576\n";
    const char *hex="0123456789abcdef";
    for(u32 i=0;i<16;i++) output[sizeof("OCORE-IMPORT digest=")-1+i]=hex[(digest>>(60-4*i))&15];
#if defined(__x86_64__)
    if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1) return 99;
#else
    if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1) return 99;
#endif
    return 0;
}
#if defined(__x86_64__)
__asm__(".text\n.globl _start\n_start:\n xor %ebp,%ebp\n and $-16,%rsp\n call import_main\n mov %eax,%edi\n mov $60,%eax\n syscall\n ud2\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n_start:\n bl import_main\n mov x8,#93\n svc #0\n brk #0\n");
#else
__asm__(".text\n.globl _start\n_start:\n call import_main\n li a7,93\n ecall\n ebreak\n");
#endif
