/* Whole upstream Parser/token.c versus its original captured Clang object.
 * This Linux test carrier is not a CPython runtime or OSTADIX platform port. */
typedef unsigned long long u64;
_Static_assert(sizeof(int) == 4 && sizeof(u64) == 8 && sizeof(void *) == 8, "LP64 scalar test ABI");
#ifndef TOKEN_NAME_COUNT
#error TOKEN_NAME_COUNT must come from the actual module and original ELF symbol
#endif
#define DECL(P) \
extern int P##_PyToken_OneChar(int); \
extern int P##_PyToken_TwoChars(int,int); \
extern int P##_PyToken_ThreeChars(int,int,int); \
extern const char * const P##_PyParser_TokenNames[TOKEN_NAME_COUNT];
DECL()
DECL(oracle_)

static u64 syscall3(u64 n,u64 a,u64 b,u64 c) {
#if defined(__x86_64__)
    register u64 r __asm__("rax")=n;
    __asm__ volatile("syscall":"+a"(r):"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;
#elif defined(__aarch64__)
    register u64 r __asm__("x0")=a; register u64 x1 __asm__("x1")=b; register u64 x2 __asm__("x2")=c; register u64 x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(r):"r"(x1),"r"(x2),"r"(x8):"memory"); return r;
#else
    register u64 r __asm__("a0")=a; register u64 a1 __asm__("a1")=b; register u64 a2 __asm__("a2")=c; register u64 a7 __asm__("a7")=n;
    __asm__ volatile("ecall":"+r"(r):"r"(a1),"r"(a2),"r"(a7):"memory"); return r;
#endif
}
static void output(const char *s,u64 n) {
#if defined(__x86_64__)
    syscall3(1,1,(u64)s,n);
#else
    syscall3(64,1,(u64)s,n);
#endif
}
static void hex(char *dst,u64 value,unsigned width) {
    const char *digits="0123456789abcdef";
    for(unsigned i=0;i<width;i++) dst[i]=digits[(value>>(4*(width-i-1)))&15];
}
static int mismatch(int kind,int a,int b,int c,int actual,int expected) {
    char line[]="TOKEN-MISMATCH kind=00 args=00000000,00000000,00000000 actual=00000000 expected=00000000\n";
    hex(line+sizeof("TOKEN-MISMATCH kind=")-1,(unsigned)kind,2);
    unsigned p=sizeof("TOKEN-MISMATCH kind=00 args=")-1;
    hex(line+p,(unsigned)a,8); hex(line+p+9,(unsigned)b,8); hex(line+p+18,(unsigned)c,8);
    hex(line+sizeof("TOKEN-MISMATCH kind=00 args=00000000,00000000,00000000 actual=")-1,(unsigned)actual,8);
    hex(line+sizeof("TOKEN-MISMATCH kind=00 args=00000000,00000000,00000000 actual=00000000 expected=")-1,(unsigned)expected,8);
    output(line,sizeof(line)-1);
    return kind;
}
int token_main(void) {
    u64 digest=0xcbf29ce484222325ULL;
#define CHECK(K,A,B,C,ACTUAL,EXPECTED) do { int actual=(ACTUAL),expected=(EXPECTED); \
    if(actual!=expected) return mismatch(K,A,B,C,actual,expected); \
    digest=(digest^(unsigned)actual)*0x100000001b3ULL; } while(0)
    /* Strings and all 67 pointer relocations must survive whole-module emission. */
    for(unsigned i=0;i<TOKEN_NAME_COUNT;i++) {
        const char *left=_PyParser_TokenNames[i],*right=oracle__PyParser_TokenNames[i];
        if(!left || !right) return mismatch(20,(int)i,0,0,!left,!right);
        unsigned j;
        for(j=0;j<256;j++) {
            CHECK(20,(int)i,(int)j,0,(unsigned char)left[j],(unsigned char)right[j]);
            if(!left[j]) break;
        }
        if(j==256) return mismatch(21,(int)i,0,0,256,0);
    }
    for(int a=0;a<256;a++) CHECK(11,a,0,0,_PyToken_OneChar(a),oracle__PyToken_OneChar(a));
    for(int a=0;a<256;a++) for(int b=0;b<256;b++)
        CHECK(12,a,b,0,_PyToken_TwoChars(a,b),oracle__PyToken_TwoChars(a,b));
    for(int a=0;a<256;a++) for(int b=0;b<256;b++) for(int c=0;c<256;c++)
        CHECK(13,a,b,c,_PyToken_ThreeChars(a,b,c),oracle__PyToken_ThreeChars(a,b,c));
    /* Defined int32 boundaries are separate from exhaustive byte coverage. */
    const int edges[]={(-2147483647-1),-2147483606,-65536,-257,-256,-128,-1,
                       0,'!','*','.','/','<','=','>',255,256,257,298,317,65578,1114111,2147483647};
    _Static_assert(sizeof(edges)/sizeof(edges[0]) == 23, "boundary case output must match the actual domain");
    unsigned count=sizeof(edges)/sizeof(edges[0]);
    for(unsigned a=0;a<count;a++) {
        CHECK(14,edges[a],0,0,_PyToken_OneChar(edges[a]),oracle__PyToken_OneChar(edges[a]));
        for(unsigned b=0;b<count;b++) {
            CHECK(15,edges[a],edges[b],0,_PyToken_TwoChars(edges[a],edges[b]),oracle__PyToken_TwoChars(edges[a],edges[b]));
            for(unsigned c=0;c<count;c++)
                CHECK(16,edges[a],edges[b],edges[c],_PyToken_ThreeChars(edges[a],edges[b],edges[c]),oracle__PyToken_ThreeChars(edges[a],edges[b],edges[c]));
        }
    }
    char line[]="OCORE-CPYTHON-TOKEN digest=0000000000000000 byte_cases=16843008 edge_cases=12719\n";
    hex(line+sizeof("OCORE-CPYTHON-TOKEN digest=")-1,digest,16);
    output(line,sizeof(line)-1);
    return 0;
}
#if defined(__x86_64__)
__asm__(".text\n.globl _start\n_start:\n xor %ebp,%ebp\n and $-16,%rsp\n call token_main\n mov %eax,%edi\n mov $60,%eax\n syscall\n ud2\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n_start:\n bl token_main\n mov x8,#93\n svc #0\n brk #0\n");
#else
__asm__(".text\n.globl _start\n_start:\n call token_main\n li a7,93\n ecall\n ebreak\n");
#endif
