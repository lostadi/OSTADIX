/* Controlled kernel-boundary fixture, not an upstream application. */
typedef unsigned long U;
typedef long S;
#define CONTROL 0x7fff0000UL
static unsigned role;
static unsigned char buffer[12288] __attribute__((aligned(4096)));
static const char input[]="/work/input";
extern void _start(void);
static S sc(U nr,U a,U b,U c,U d) {
 register U r10 __asm__("r10")=d;
 U result;
 __asm__ volatile("syscall" : "=a"(result) : "a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10) : "rcx","r11","memory");
 return (S)result;
}
static int equal(const char *a,const char *b) { while(*a&&*a==*b){a++;b++;}return *a==*b; }
static void error(U line) { sc(CONTROL,99,line,role,0);for(;;)__asm__ volatile("ud2"); }
#define CHECK(c) do { if(!(c))error(__LINE__); }while(0)
static void pattern(U offset,U n) { for(U i=0;i<n;i++)CHECK(buffer[i]==(unsigned char)(((offset+i)*73)^((offset+i)>>8))); }
static void done(void) { CHECK(sc(CONTROL,0,role,0,0)==0);for(;;)sc(24,0,0,0,0); }
void probe(U *sp) {
 CHECK(!((U)sp&15)&&sp[0]==2&&sp[3]==0&&sp[5]==0);
 CHECK(equal((char*)sp[1],"native-posix-files")&&equal((char*)sp[4],"LANG=C"));
 const char *which=(const char*)sp[2];CHECK(which[0]>='0'&&which[0]<='3'&&!which[1]);role=which[0]-'0';
 U seen=0;
 for(U *a=sp+6;a[0];a+=2){
  if(a[0]==3){CHECK(a[1]>=0x02000000&&a[1]<0x02100000);seen|=1;}
  if(a[0]==4){CHECK(a[1]==56);seen|=2;}
  if(a[0]==5){CHECK(a[1]==4);seen|=4;}
  if(a[0]==6){CHECK(a[1]==4096);seen|=8;}
  if(a[0]==9){CHECK(a[1]==(U)_start);seen|=16;}
  if(a[0]==11||a[0]==12||a[0]==13||a[0]==14){CHECK(a[1]==1000);seen|=32UL<<(a[0]-11);}
  if(a[0]==23){CHECK(!a[1]);seen|=512;}
  if(a[0]==25){for(U i=0;i<16;i++)CHECK(((unsigned char*)a[1])[i]==0x80+i);seen|=1024;}
  if(a[0]==31){CHECK(equal((char*)a[1],"/bin/probe.elf"));seen|=2048;}
 }
 CHECK(seen==4095);
 if(role==1){
  CHECK(sc(257,-100,(U)input,0,0)==-13&&sc(0,3,(U)buffer,1,0)==-13);
  CHECK(sc(CONTROL,0,role,0,0)==0);__asm__ volatile("ud2");for(;;){}
 }
 CHECK(sc(0,3,(U)buffer,1,0)==-9&&sc(0,999,0,1,0)==-9);
 S fd=sc(257,-100,(U)input,0,0);CHECK(fd==3);
 CHECK(sc(0,fd,(U)buffer,12288,0)==12288);pattern(0,12288);
 CHECK(sc(0,fd,(U)buffer,1,0)==0&&sc(8,fd,0,0,0)==0);
 CHECK(sc(0,fd,0,4,0)==-14&&sc(8,fd,0,1,0)==0);
 CHECK(sc(0,fd,(U)input,4,0)==-14&&sc(8,fd,0,1,0)==0);
 CHECK(sc(0,fd,0x04000000,4,0)==-14&&sc(8,fd,0,1,0)==0);
 CHECK(sc(257,-100,0x04000000,0,0)==-14);
 CHECK(sc(0,fd,~0UL-3,4,0)==-14&&sc(8,fd,0,1,0)==0);
 CHECK(sc(0,fd,0,0,0)==0&&sc(1,1,(U)input,4,0)==-9&&sc(5,fd,(U)buffer,0,0)==-38);
 CHECK(sc(8,fd,1UL<<63,0,0)==-22&&sc(8,fd,0,1,0)==0);
 if(role==0){
  for(U i=0;i<12288;i++)buffer[i]=0xa5;
  CHECK(sc(CONTROL,3,0,0,0)==0);
  CHECK(sc(0,fd,(U)buffer,8192,0)==4096);pattern(0,4096);
  for(U i=4096;i<8192;i++)CHECK(buffer[i]==0xa5);
  CHECK(sc(8,fd,0,1,0)==4096&&sc(0,fd,(U)buffer,8192,0)==8192);pattern(4096,8192);
 }
 if(role==3){
  CHECK(sc(CONTROL,1,0,0,0)==0&&sc(0,fd,(U)buffer,1,0)==-13);
  CHECK(sc(CONTROL,2,0,0,0)==0&&sc(0,fd,(U)buffer,1,0)==-9);
  CHECK(sc(257,-100,(U)input,0,0)==3&&sc(0,3,(U)buffer,4,0)==4);pattern(0,4);
 }
 CHECK(sc(3,fd,0,0,0)==0&&sc(3,fd,0,0,0)==-9);
 if(role==2){for(U i=0;i<4;i++){
  CHECK(sc(2,(U)input,0,0,0)==3&&sc(0,3,(U)buffer,17,0)==17);pattern(0,17);
  CHECK(sc(3,3,0,0,0)==0);sc(24,0,0,0,0);
 }}
 if(role==2){
  static const char output[]="/work/output";
  CHECK(sc(257,-100,(U)output,2|64|128,0600)==3);
  for(U i=0;i<12288;i++)buffer[i]=(unsigned char)((i*73)^(i>>8));
  CHECK(sc(1,3,(U)buffer,12288,0)==12288&&sc(32,3,0,0,0)==4);
  CHECK(sc(8,4,0,0,0)==0&&sc(0,3,(U)buffer,12288,0)==12288);pattern(0,12288);
  CHECK(sc(3,3,0,0,0)==0&&sc(1,4,(U)input,4,0)==4&&sc(8,4,0,1,0)==12292);
  CHECK(sc(33,4,10,0,0)==10&&sc(3,4,0,0,0)==0&&sc(33,10,10,0,0)==10);
  CHECK(sc(1,10,0,4,0)==-14&&sc(1,10,0x04000000,4,0)==-14&&sc(8,10,0,1,0)==12292);
  CHECK(sc(8,10,12288,0,0)==12288&&sc(0,10,(U)buffer,4,0)==4);
  for(U i=0;i<4;i++)CHECK(buffer[i]==input[i]);
  CHECK(sc(3,10,0,0,0)==0&&sc(257,-100,(U)output,2|64|128,0600)==-17);
  CHECK(sc(257,-100,(U)output,1|512,0)==3&&sc(0,3,(U)buffer,1,0)==-9);
  CHECK(sc(1,3,(U)input,4,0)==4&&sc(3,3,0,0,0)==0);
  CHECK(sc(257,-100,(U)output,0,0)==3&&sc(0,3,(U)buffer,12,0)==4);
  for(U i=0;i<4;i++)CHECK(buffer[i]==input[i]);
  CHECK(sc(3,3,0,0,0)==0);
 }

 done();
}
