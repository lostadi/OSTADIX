/* Authored invocation/control bootstrap, not original musl CRT or startup.
   The linked getuid and _Exit implementations are unchanged original sources.
   Native private control and host telemetry are separate test interfaces. */
typedef unsigned long U; typedef long S;
extern unsigned getuid(void);
extern _Noreturn void _Exit(int);
#ifndef NATIVE_USER_PROVIDER
#define NATIVE_USER_PROVIDER 1
#endif
#ifndef STATUS_GROUP
#define STATUS_GROUP 0
#endif
#ifndef HOST_UID
#define HOST_UID 1000
#endif
#ifndef HOST_EUID
#define HOST_EUID 1000
#endif
#ifndef HOST_GID
#define HOST_GID 1000
#endif
#ifndef HOST_EGID
#define HOST_EGID 1000
#endif
#define CONTROL 0x7fff0000UL
static unsigned role;
static unsigned char byte;
static S sc(U n,U a,U b,U c){
 U r;
#if defined(__x86_64__)
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory","cc");
#elif defined(__aarch64__)
 register U x8 __asm__("x8")=n,x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
 __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2):"memory","cc");r=x0;
#elif defined(__riscv) && __riscv_xlen==64
 register U a7 __asm__("a7")=n,a0 __asm__("a0")=a,a1 __asm__("a1")=b,a2 __asm__("a2")=c;
 __asm__ volatile("ecall":"+r"(a0):"r"(a7),"r"(a1),"r"(a2):"memory");r=a0;
#else
#error no owned bootstrap for this actual ISA
#endif
 return (S)r;
}
static _Noreturn void die(U line){
#if NATIVE_USER_PROVIDER
 sc(CONTROL,99,line,role);
#endif
 for(;;){
#if defined(__x86_64__)
 __asm__ volatile("ud2");
#elif defined(__aarch64__)
 __asm__ volatile("brk #1");
#else
 __asm__ volatile("unimp");
#endif
 }
}
#define CHECK(x) do{if(!(x))die(__LINE__);}while(0)
static int code(void){
 if(STATUS_GROUP==0){static const int c[4]={0,1,42,255};return c[role];}
 static const int c[4]={256,-1,2147483647,(-2147483647-1)};return c[role];
}
static void report_uid(unsigned ordinal,unsigned value){
 CHECK(value==HOST_UID);
#if NATIVE_USER_PROVIDER
 CHECK(!sc(CONTROL,8,value,ordinal));
#else
 U record[4]={0x4f50524f43554944UL,role,ordinal,value};
 CHECK(sc(
#if defined(__x86_64__)
 1,
#else
 64,
#endif
 1,(U)record,sizeof(record))==(S)sizeof(record));
#endif
}
void probe(U *sp){
 CHECK(sp[0]==2&&sp[3]==0);char *arg=(char*)sp[2];CHECK(arg[0]>='0'&&arg[0]<='3'&&!arg[1]);role=arg[0]-'0';
 U *env=sp+4;while(*env)env++;U *aux=env+1;U seen=0;
 while(aux[0]){U type=aux[0],value=aux[1];if(type==11){CHECK(value==HOST_UID);seen|=1;}if(type==12){CHECK(value==HOST_EUID);seen|=2;}if(type==13){CHECK(value==HOST_GID);seen|=4;}if(type==14){CHECK(value==HOST_EGID);seen|=8;}aux+=2;}CHECK(seen==15);
#if NATIVE_USER_PROVIDER
 CHECK(sc(CONTROL,11,(U)"/work/input",0)==3);CHECK(sc(CONTROL,12,(U)&byte,0)==1&&byte==0);
 CHECK(!sc(CONTROL,0,0,0));while(!sc(CONTROL,1,0,0))CHECK(!sc(CONTROL,24,0,0));
 CHECK(!sc(CONTROL,2,0,0));CHECK(sc(CONTROL,12,(U)&byte,0)==1&&byte==73);
 CHECK(!sc(CONTROL,3,0,0));while(!sc(CONTROL,4,0,0))CHECK(!sc(CONTROL,24,0,0));
#endif
 report_uid(0,getuid());
 if(role>=2){
#if NATIVE_USER_PROVIDER
  while(!sc(CONTROL,role==2?6:7,0,0))CHECK(!sc(CONTROL,24,0,0));
  CHECK(sc(CONTROL,12,(U)&byte,0)==1&&byte==146);
#endif
  report_uid(1,getuid());
 }
 _Exit(code()); /* Original implementation alone owns group->exit fallback. */
}
