/* Owned architecture fixture, not an upstream program or Linux exit ABI. */
typedef unsigned long U;
typedef long S;
#define CONTROL 0x7fff0000UL
#ifndef OCORE_NEGATIVE_CASE
#define OCORE_NEGATIVE_CASE 0
#endif
static unsigned role;
static U tls[4][8] __attribute__((aligned(64)));
static unsigned char byte;
static S sc(U n,U a,U b,U c,U d){register U r10 __asm__("r10")=d;U r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory");return(S)r;}
static void die(U line){sc(CONTROL,99,line,role,0);for(;;)__asm__ volatile("ud2");}
#define CHECK(x) do{if(!(x))die(__LINE__);}while(0)
static U fs8(void){U r;__asm__ volatile("mov %%fs:8,%0":"=r"(r)::"memory");return r;}
void probe(U *sp){
 CHECK(sp[0]==2&&sp[3]==0);char *arg=(char*)sp[2];CHECK(arg[0]>='0'&&arg[0]<='3'&&!arg[1]);role=arg[0]-'0';
 U *area=tls[role];area[0]=(U)area;area[1]=0xabcd123400000000UL+role;
 CHECK(!sc(158,0x1002,(U)area,0,0));CHECK(fs8()==area[1]);
#if OCORE_NEGATIVE_CASE == 16
 if(role==0){__asm__ volatile("mov $1,%%rsp; mov $0x7fff0000,%%eax; mov $23,%%edi; syscall; ud2":::"rax","rdi","rcx","r11","memory");__builtin_unreachable();}
#endif
#if OCORE_NEGATIVE_CASE == 17
 if(role==0){unsigned short selector=0x1b;__asm__ volatile("mov %0,%%gs"::"r"(selector):"memory");}
#endif
 CHECK(sc(CONTROL,20,0,0,0)==-31);CHECK(sc(CONTROL,21,0,0,0)==-32);
 CHECK(!sc(CONTROL,22,0,0,0));CHECK(fs8()==area[1]);
 S fd=-1;if(role!=1){fd=sc(257,-100,(U)"/work/input",0,0);CHECK(fd==3);CHECK(sc(0,fd,(U)&byte,1,0)==1&&byte==0);}
 CHECK(!sc(CONTROL,0,0,0,0));while(!sc(CONTROL,1,0,0,0))CHECK(!sc(24,0,0,0,0));
 CHECK(!sc(CONTROL,2,0,0,0));CHECK(fs8()==area[1]);
 if(role!=1)CHECK(sc(0,fd,(U)&byte,1,0)==1&&byte==73);
 CHECK(!sc(CONTROL,3,0,0,0));while(!sc(CONTROL,4,0,0,0))CHECK(!sc(24,0,0,0,0));
 if(role==3)while(!sc(CONTROL,6,0,0,0))CHECK(!sc(24,0,0,0,0));
 sc(CONTROL,5,0,0,0);die(__LINE__); /* Retirement must never resume this frame. */
}
