/* Authored ABI/lifecycle carrier; this is not upstream libc or a shell. */
typedef unsigned long U; typedef long S;
#define CONTROL 0x7fff0000UL
#ifndef OCORE_NEGATIVE_CASE
#define OCORE_NEGATIVE_CASE 0
#endif
#ifndef OCORE_STATUS_GROUP
#define OCORE_STATUS_GROUP 0
#endif
static unsigned role;
static U tls[4][8] __attribute__((aligned(64)));
static U child_sentinel[4] __attribute__((aligned(64)));
static unsigned char byte;
static S sc(U n,U a,U b,U c,U d){register U r10 __asm__("r10")=d;U r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory");return(S)r;}
static void die(U line){sc(CONTROL,99,line,role,0);for(;;)__asm__ volatile("ud2");}
#define CHECK(x) do{if(!(x))die(__LINE__);}while(0)
static U fs8(void){U r;__asm__ volatile("mov %%fs:8,%0":"=r"(r)::"memory");return r;}
static U raw(void){
 if(OCORE_STATUS_GROUP==0)return role<2?0:1;
 if(OCORE_STATUS_GROUP==1)return role<2?42:255;
 if(OCORE_STATUS_GROUP==2)return role<2?256:~0UL;
 if(OCORE_STATUS_GROUP==3)return role<2?0x8123456789abcdefUL:(U)-31;
 return role<2?(U)-32:0x100000001UL;
}
void probe(U *sp){
 CHECK(sp[0]==2&&sp[3]==0);char *arg=(char*)sp[2];CHECK(arg[0]>='0'&&arg[0]<='3'&&!arg[1]);role=arg[0]-'0';
 U *area=tls[role];area[0]=(U)area;area[1]=0xabcd123400000000UL+role;
 CHECK(!sc(158,0x1002,(U)area,0,0));CHECK(fs8()==area[1]);
 U registered=role==0?~0UL:role==1?~1UL:(U)&child_sentinel[role];
 child_sentinel[role]=0x9876543200000000UL+role;
 if(!(OCORE_NEGATIVE_CASE==2&&role==0)){
  CHECK(sc(186,0,0,0,0)==4101+role);
  CHECK(sc(218,registered,0,0,0)==4101+role);
 }else{CHECK(sc(186,0,0,0,0)==-3);CHECK(sc(218,registered,0,0,0)==-3);}
 CHECK(!sc(CONTROL,10,(U)&child_sentinel[role],child_sentinel[role],0));
 S fd=-1;if(role!=1){fd=sc(257,-100,(U)"/work/input",0,0);CHECK(fd==3);CHECK(sc(0,fd,(U)&byte,1,0)==1&&byte==0);}
 CHECK(!sc(CONTROL,0,0,0,0));while(!sc(CONTROL,1,0,0,0))CHECK(!sc(24,0,0,0,0));
 CHECK(!sc(CONTROL,2,0,0,0));CHECK(fs8()==area[1]);
 if(role!=1)CHECK(sc(0,fd,(U)&byte,1,0)==1&&byte==73);
 CHECK(!sc(CONTROL,3,0,0,0));while(!sc(CONTROL,4,0,0,0))CHECK(!sc(24,0,0,0,0));
 if(OCORE_NEGATIVE_CASE==1||OCORE_NEGATIVE_CASE==2||OCORE_NEGATIVE_CASE==17){
  if(OCORE_NEGATIVE_CASE==1||role==0){CHECK(sc(60,raw(),0,0,0)==-38);CHECK(sc(231,raw(),0,0,0)==-38);}
  CHECK(fs8()==area[1]);if(role!=1)CHECK(sc(0,fd,(U)&byte,1,0)==1&&byte==146);
  for(;;)CHECK(!sc(CONTROL,9,0,0,0));
 }
 if(role==2){while(!sc(CONTROL,6,0,0,0))CHECK(!sc(24,0,0,0,0));CHECK(fs8()==area[1]);CHECK(sc(0,fd,(U)&byte,1,0)==1&&byte==146);CHECK(!sc(CONTROL,8,0,0,0));}
 if(role==3)while(!sc(CONTROL,7,0,0,0))CHECK(!sc(24,0,0,0,0));
 if(((OCORE_NEGATIVE_CASE>=6&&OCORE_NEGATIVE_CASE<=14)||OCORE_NEGATIVE_CASE==18)&&role!=0)for(;;)CHECK(!sc(24,0,0,0,0));
 U n=role&1?231:60;
 if(role==0&&OCORE_NEGATIVE_CASE==3){CHECK(sc(n,raw(),0,0,0)==-38);CHECK(fs8()==area[1]);}
 if(role==0&&OCORE_NEGATIVE_CASE==4){CHECK(!sc(n,raw(),0,0,0));CHECK(fs8()==area[1]);}
 if(role<2&&OCORE_NEGATIVE_CASE==15){
  __asm__ volatile("mov $1,%%rsp; syscall; ud2"::"a"(n),"D"(raw()):"rcx","r11","memory");__builtin_unreachable();
 }
 sc(n,raw(),0,0,0);die(__LINE__); /* Neither terminal syscall may resume. */
}
