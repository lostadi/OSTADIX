/* Existing C frontend semantics, not a hand-written O-core translation. */
typedef unsigned long long u64;
typedef long long i64;
typedef unsigned int u32;
typedef unsigned char u8;
#ifndef PREFIX
#define PREFIX imported_
#endif
#define JOIN2(a,b) a##b
#define JOIN(a,b) JOIN2(a,b)
#define NAME(n) JOIN(PREFIX,n)

extern u64 foreign_scalar_sum(u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64,u64);
extern u64 foreign_scalar_callback(u64);

u64 NAME(unsigned_mix)(u64 a, u64 b, u32 shift) {
    return ((a+b)^(a-b)^(a*b))+(a/b)+(a%b)+(a<<(shift&63))+(a>>(shift&63));
}
u64 NAME(signed_mix)(i64 a, i64 b, u32 shift) {
    return (u64)(a/b)+(u64)(a%b)+(u64)(a>>(shift&63))+((u64)a<<(shift&63));
}
u64 NAME(narrow)(u8 a, signed char b, unsigned short c, short d) {
    return (u64)(u8)(a*17)+(u64)(i64)b+(u64)(unsigned short)(c*31)+(u64)(i64)d;
}
u64 NAME(loop)(u64 a) {
    u64 b=3;
    for (u32 i=0;i<19;i++) { u64 old=a; a=b; b=old+b+(u64)i; }
    return a^b;
}
u64 NAME(many)(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u64 i,u64 j,u64 k,u64 l) {
    return a+2*b+3*c+4*d+5*e+6*f+7*g+8*h+9*i+10*j+11*k+12*l;
}
u64 NAME(call)(u64 a) {
    return foreign_scalar_sum(a,2,3,4,5,6,7,8,9,10,11,12);
}
u64 NAME(indirect)(u64 (*callback)(u64), u64 a) { return callback(a)+1; }
static u64 (*NAME(table))(u64)=foreign_scalar_callback;
u64 NAME(table_call)(u64 a) { return NAME(table)(a)+3; }
static volatile u64 NAME(total)=7;
u64 NAME(global)(u64 a) { NAME(total)=a; return NAME(total)+5; }
struct __attribute__((packed)) Packed { u8 tag; u64 value; };
u64 NAME(packed)(void *buffer,u64 a) {
    struct Packed *p=buffer; p->tag=11; p->value=a; return p->value+p->tag;
}
u64 NAME(memory)(u8 *bytes, u64 a) {
    for (u32 i=0;i<64;i++) bytes[i]=(u8)(a+i);
    u64 sum=0; for (u32 i=0;i<64;i++) sum+=bytes[i]; return sum;
}
u64 NAME(stack)(u64 a) { volatile u64 local[3]; local[0]=a; local[1]=a+1; local[2]=a+2; return local[0]^local[1]^local[2]; }
