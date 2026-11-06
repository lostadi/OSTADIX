/* Native-component regression. Hardware LR/APR effects below are a fixture,
 * not actual CPU emulation/boot evidence. The two O-core modules are exact R8
 * baseline and current production, plus read-only test introspection. No
 * kernel/VM or saved-state operation is performed. */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define B(n) _O_runtime__aarch64__unified_gic_baseline__##n
#define V(n) _O_runtime__aarch64__unified_gic__##n
#define D UINT64_C(0x08000000)
#define R UINT64_C(0x080a0000)
#define P UINT64_C(0x080b0000)
#define PENDING (UINT64_C(1)<<62)
#define ACTIVE (UINT64_C(1)<<63)
#define GROUP1 (UINT64_C(1)<<60)
#define HW (UINT64_C(1)<<61)
#define DECLARE(N) \
 extern uint64_t N(init)(void); \
 extern uint64_t N(reset)(uint64_t); \
 extern uint64_t N(mmio_read)(uint64_t,uint64_t,uint64_t); \
 extern uint64_t N(mmio_write)(uint64_t,uint64_t,uint64_t,uint64_t); \
 extern uint64_t N(set_level)(uint64_t,uint64_t,uint64_t); \
 extern uint64_t N(send_sgi)(uint64_t,uint64_t,uint64_t); \
 extern uint64_t N(poll)(uint64_t); \
 extern uint64_t N(healthy)(uint64_t); \
 extern uint64_t N(diagnostic)(uint64_t); \
 extern uint64_t N(test_inspect)(uint64_t,uint64_t,uint64_t);
DECLARE(B)
DECLARE(V)
struct api {
 uint64_t (*init)(void),(*reset)(uint64_t);
 uint64_t (*read)(uint64_t,uint64_t,uint64_t),(*write)(uint64_t,uint64_t,uint64_t,uint64_t);
 uint64_t (*level)(uint64_t,uint64_t,uint64_t),(*sgi)(uint64_t,uint64_t,uint64_t);
 uint64_t (*poll)(uint64_t),(*healthy)(uint64_t),(*diagnostic)(uint64_t);
 uint64_t (*inspect)(uint64_t,uint64_t,uint64_t);
};
static struct api apis[2]={
 {B(init),B(reset),B(mmio_read),B(mmio_write),B(set_level),B(send_sgi),B(poll),B(healthy),B(diagnostic),B(test_inspect)},
 {V(init),V(reset),V(mmio_read),V(mmio_write),V(set_level),V(send_sgi),V(poll),V(healthy),V(diagnostic),V(test_inspect)}
};
static unsigned which,count=4,seed,step,operation;
static uint64_t banks[2][2][16],vmcr[2][2],hcr[2][2],apr[2][2][4],reads[2],writes[2];
static uint64_t comparisons,transitions,ack_count,eoi_count,corruption_count;
uint64_t uw_vgic_lr_count(void){return count;}
uint64_t uw_vgic_lr_read(uint64_t d,uint64_t i){assert(d<2&&i<count);reads[which]++;return banks[which][d][i];}
void uw_vgic_lr_write(uint64_t d,uint64_t i,uint64_t v){assert(d<2&&i<count);writes[which]++;banks[which][d][i]=v;}
uint64_t uw_vgic_vmcr_read(uint64_t d){assert(d<2);return vmcr[which][d];}
void uw_vgic_vmcr_write(uint64_t d,uint64_t v){assert(d<2);vmcr[which][d]=v;}
uint64_t uw_vgic_running_priority(uint64_t d){assert(d<2);return 255;}
uint64_t uw_vgic_hcr_read(uint64_t d){assert(d<2);return hcr[which][d];}
void uw_vgic_hcr_write(uint64_t d,uint64_t v){assert(d<2);hcr[which][d]=v;}
static void equal(uint64_t a,uint64_t b,const char *kind,unsigned d,unsigned index){
 comparisons++;
 if(a!=b){fprintf(stderr,"DIFF seed=%u step=%u op=%u %s d=%u i=%u base=%llx candidate=%llx\n",seed,step,operation,kind,d,index,(unsigned long long)a,(unsigned long long)b);abort();}
}
static uint64_t base(unsigned irq){return irq<32?P:D;}
static uint64_t mutate(unsigned type,unsigned d,uint64_t a,uint64_t b,uint64_t c){
 uint64_t result[2];uint64_t before_apr[2][2][4];memcpy(before_apr,apr,sizeof(apr));
 for(which=0;which<2;which++){
  struct api *g=&apis[which];
  switch(type){
   case 0:result[which]=g->level(d,a,b);break;
   case 1:result[which]=g->write(d,a,b,c);break;
   case 2:result[which]=g->read(d,a,b);break;
   case 3:result[which]=g->sgi(d,a,b);break;
   case 4:result[which]=g->reset(d);break;
   default:abort();
  }
 }
 assert(!memcmp(before_apr,apr,sizeof(apr))); /* Modules never alter APRs. */
 equal(result[0],result[1],"return",d,type);return result[0];
}
static void canonical(void){
 for(unsigned d=0;d<2;d++){
  uint64_t result[2];
  for(which=0;which<2;which++)result[which]=apis[which].poll(d);
  equal(result[0],result[1],"poll",d,0);
 }
 equal(memcmp(banks[0],banks[1],sizeof(banks[0])),0,"LRs",0,0);
 equal(memcmp(vmcr[0],vmcr[1],sizeof(vmcr[0])),0,"VMCR",0,0);
 equal(memcmp(hcr[0],hcr[1],sizeof(hcr[0])),0,"HCR",0,0);
 equal(memcmp(apr[0],apr[1],sizeof(apr[0])),0,"APR",0,0);
 for(unsigned d=0;d<2;d++){
  equal(apis[0].healthy(d),apis[1].healthy(d),"healthy",d,0);
  equal(apis[0].diagnostic(d),apis[1].diagnostic(d),"diagnostic",d,0);
  for(unsigned kind=0;kind<=22;kind++){
   unsigned n=0;
   if(kind==0)n=2;
   if(kind>=1&&kind<=4)n=1;
   if((kind>=10&&kind<=18)||kind==20)n=64;
   if(kind==21||kind==22)n=16;
   for(unsigned i=0;i<n;i++)equal(apis[0].inspect(d,kind,i),apis[1].inspect(d,kind,i),"state",d,kind*100+i);
  }
 }
}
static void provision(unsigned d){
  assert(mutate(1,d,R+0x14,4,0));assert(mutate(1,d,D,4,0x13));
  assert(mutate(1,d,P+0x80,4,UINT32_MAX));assert(mutate(1,d,D+0x84,4,UINT32_MAX));
  assert(mutate(1,d,P+0x100,4,UINT32_MAX));assert(mutate(1,d,D+0x104,4,UINT32_MAX));
}
static void initialize(void){
 for(which=0;which<2;which++){memset(apr[which],0,sizeof(apr[which]));assert(apis[which].init()==1);}
 for(unsigned d=0;d<2;d++)provision(d);
 canonical();
}
static unsigned random_(uint64_t *state){*state^=*state<<13;*state^=*state>>7;*state^=*state<<17;return (unsigned)*state;}
static void hardware_ack(unsigned d,unsigned choice){
 int selected=-1;unsigned running=256,best=256;
 /* Minimal IAR effect: accept eligible highest-priority pending Group1 IRQ
  * below both PMR and active running priority, then update private APR bit. */
 for(unsigned i=0;i<count;i++)if(banks[0][d][i]&ACTIVE){unsigned p=(banks[0][d][i]>>48)&255;if(p<running)running=p;}
 for(unsigned i=0;i<count;i++)if((banks[0][d][i]>>62)==1){
  unsigned p=(banks[0][d][i]>>48)&255,pmr=(vmcr[0][d]>>24)&255;
  if((vmcr[0][d]&2)&&p<running&&p<pmr&&p<best){best=p;selected=(int)i;}
 }
 (void)choice;
 if(selected<0)return;
 for(unsigned v=0;v<2;v++){
  banks[v][d][selected]=(banks[v][d][selected]&~PENDING)|ACTIVE;
  apr[v][d][0]|=UINT64_C(1)<<(best>>3);
 }
 ack_count++;
}
static void hardware_eoi(unsigned d,unsigned choice){
 unsigned slots[16],n=0;for(unsigned i=0;i<count;i++)if(banks[0][d][i]&ACTIVE)slots[n++]=i;
 if(!n)return;
 unsigned selected=slots[choice%n],p=(banks[0][d][selected]>>48)&255;
 for(unsigned v=0;v<2;v++){
  banks[v][d][selected]&=~ACTIVE;
  unsigned same=0;for(unsigned i=0;i<count;i++)if((banks[v][d][i]&ACTIVE)&&(((banks[v][d][i]>>48)&255)==p))same++;
  if(!same)apr[v][d][0]&=~(UINT64_C(1)<<(p>>3));
 }
 eoi_count++;
}
static unsigned assigned_irq(unsigned d,unsigned number){
 static const unsigned linux_irqs[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,27,30,33,48,49,50,51};
 static const unsigned plan9[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,27,30,33,50};
 return d?plan9[number%(sizeof(plan9)/sizeof(*plan9))]:linux_irqs[number%(sizeof(linux_irqs)/sizeof(*linux_irqs))];
}
static void random_traces(void){
 const unsigned counts[]={1,4,16};
 for(unsigned size=0;size<3;size++)for(seed=1;seed<=12;seed++){
  count=counts[size];initialize();uint64_t random=UINT64_C(0x1234f00d56780000)+seed*19+count;
  for(step=0;step<700;step++){
   unsigned a=random_(&random),b=random_(&random),c=random_(&random),d=a&1;
   unsigned irq=assigned_irq(d,b),registers[]={0x80,0x100,0x180,0x200,0x280,0x300,0x380};
   operation=(a>>2)%18;
   switch(operation){
    case 0:case 1:case 2:
     if(irq>=16)mutate(0,d,irq,operation==0?apis[0].inspect(d,14,irq):(c&1),0);
     break;
    case 3:{
     uint64_t value=UINT64_C(1)<<(irq%32);
     if(c%7==0){
      value=0;for(unsigned bit=0;bit<32;bit++)if(apis[0].inspect(d,11,(irq/32)*32+bit))value|=UINT64_C(1)<<bit;
      value^=UINT64_C(1)<<(irq%32);
     }
     mutate(1,d,base(irq)+registers[c%7]+(irq/32)*4,4,value);break;
    }
    case 4:mutate(1,d,base(irq)+0x400+irq,1,c);break;
    case 5:mutate(1,d,R+0x14,4,(c&1)*2);break;
    case 6:mutate(1,d,D,4,c&3);break;
    case 7:mutate(3,d,((uint64_t)(b&15)<<24)|1,1,0);break;
    case 8:hardware_ack(d,c);break;
    case 9:hardware_eoi(d,c);break;
    case 10:
     if(irq>=32)mutate(1,d,D+0x6000+irq*8,8,(c&1)?0x80000000:0);
     break;
    case 11:mutate(1,d,base(irq)+0xc00+(irq/16)*4,4,c&0xaaaaaaaa);break;
    case 12:mutate(2,d,base(irq)+registers[c%7]+(irq/32)*4,4,0);break;
    case 13: /* Native banked CPU interface/APR edits are not O-core config. */
     for(unsigned v=0;v<2;v++){vmcr[v][d]=((uint64_t)(c&0xf8)<<24)|2;hcr[v][d]=1;apr[v][d][1]=b;}
     break;
    case 14:
     for(unsigned v=0;v<2;v++)memset(apr[v][d],0,sizeof(apr[v][d]));
     mutate(4,d,0,0,0);canonical();provision(d);break;
    case 15: /* All these authorities remain denied, including invalid domain. */
     switch(c%7){
      case 0:mutate(0,d,26,1,0);break;
      case 1:mutate(0,1,48,1,0);break;
      case 2:mutate(0,d,33,2,0);break;
      case 3:mutate(1,d,R+0x70,8,0x60000000);break;
      case 4:mutate(1,d,D+1,4,0);break;
      case 5:mutate(3,d,((uint64_t)(b&15)<<24)|1,0,0);break;
      case 6:mutate(4,2,0,0,0);break;
     }break;
    case 16: /* Multi-width routing and MMIO lanes. */
     if(irq>=32)mutate(1,d,D+0x6000+irq*8+3,1,(c&1)?0x80:0);
     else mutate(2,d,P+0x400+(irq&~1),2,0);
     break;
    case 17: /* Multiple unchanged polls must preserve all LR/APR state. */
     canonical();canonical();break;
   }
   canonical();
   if(step%8==0){hardware_ack(d,c);canonical();}
   if(step%11==0){hardware_eoi(d,c);canonical();}
   transitions++;
  }
 }
}
static void corruption(void){
 count=4;
 for(unsigned kind=0;kind<5;kind++){
  seed=999;step=kind;operation=100;initialize();
  assert(mutate(0,0,48,1,0));assert(mutate(0,0,49,1,0));canonical();
  int left=-1,right=-1;for(unsigned i=0;i<count;i++)if(banks[0][0][i]>>62){if((uint32_t)banks[0][0][i]==48)left=i;if((uint32_t)banks[0][0][i]==49)right=i;}
  assert(left>=0&&right>=0);
  for(unsigned v=0;v<2;v++){
   if(kind==0)banks[v][0][left]=(banks[v][0][left]&~UINT64_C(0xffffffff))|26;
   if(kind==1)banks[v][0][left]|=HW;
   if(kind==2)banks[v][0][left]&=~GROUP1;
   if(kind==3)banks[v][0][right]=(banks[v][0][right]&~UINT64_C(0xffffffff))|48;
   if(kind==4)banks[v][0][left]=(banks[v][0][left]&~UINT64_C(0xffffffff))|50;
  }
  uint64_t before[2][2][16],oldwrites[2];memcpy(before,banks,sizeof(banks));memcpy(oldwrites,writes,sizeof(writes));
  for(which=0;which<2;which++)assert(apis[which].poll(0)==0);
  assert(!memcmp(before,banks,sizeof(banks))&&!memcmp(oldwrites,writes,sizeof(writes)));
  canonical();
  assert(!apis[0].healthy(0)&&!apis[1].healthy(0)&&apis[0].healthy(1)&&apis[1].healthy(1));
  corruption_count++;
 }
 /* Same-level callback intentionally defers hardware-bank validation until
  * mandatory poll. Prove that no saved slot can be restored unchecked. */
 initialize();assert(mutate(0,0,48,1,0));canonical();
 int slot=-1;for(unsigned i=0;i<count;i++)if((uint32_t)banks[0][0][i]==48&&(banks[0][0][i]>>62))slot=i;
 assert(slot>=0);for(unsigned v=0;v<2;v++)banks[v][0][slot]|=HW;
 which=1;uint64_t before[16];memcpy(before,banks[1][0],sizeof(before));uint64_t oldwrites=writes[1];
 assert(apis[1].level(0,48,1)==1&&apis[1].healthy(0)==1);
 assert(apis[1].poll(0)==0&&!apis[1].healthy(0));
 assert(!memcmp(before,banks[1][0],sizeof(before))&&oldwrites==writes[1]);
 corruption_count++;
}
static uint64_t cpu_ns(void){
 struct timespec value;assert(!clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&value));
 return (uint64_t)value.tv_sec*1000000000+value.tv_nsec;
}
static void hotpath(void){
 count=4;initialize();const unsigned iterations=100000;
 for(unsigned v=0;v<2;v++){
  which=v;reads[v]=writes[v]=0;uint64_t start=cpu_ns();
  for(unsigned i=0;i<iterations;i++)assert(apis[v].poll(0));
  uint64_t elapsed=cpu_ns()-start;
  assert(reads[v]==4*iterations&&writes[v]==(v?0:4*iterations));
  printf("{\"mode\":\"unchanged-poll\",\"variant\":%u,\"iterations\":%u,\"cpu_ns\":%llu,\"reads\":%llu,\"writes\":%llu}\n",v,iterations,(unsigned long long)elapsed,(unsigned long long)reads[v],(unsigned long long)writes[v]);
  reads[v]=writes[v]=0;start=cpu_ns();
  for(unsigned i=0;i<iterations;i++)assert(apis[v].level(0,48,0));
  elapsed=cpu_ns()-start;
  assert(reads[v]==(v?0:4*iterations)&&writes[v]==(v?0:4*iterations));
  printf("{\"mode\":\"unchanged-level\",\"variant\":%u,\"iterations\":%u,\"cpu_ns\":%llu,\"reads\":%llu,\"writes\":%llu}\n",v,iterations,(unsigned long long)elapsed,(unsigned long long)reads[v],(unsigned long long)writes[v]);
  assert(apis[v].poll(0));
  reads[v]=writes[v]=0;start=cpu_ns();
  for(unsigned i=0;i<iterations;i++){
   assert(apis[v].level(0,27,0)&&apis[v].level(0,30,0)&&apis[v].level(0,33,0)&&apis[v].level(0,48,0)&&apis[v].level(0,49,0)&&apis[v].level(0,50,0)&&apis[v].level(0,51,0));
   assert(apis[v].level(1,27,0)&&apis[v].level(1,30,0)&&apis[v].level(1,33,0)&&apis[v].level(1,50,0));
   assert(apis[v].poll(0)&&apis[v].poll(1));
  }
  elapsed=cpu_ns()-start;
  assert(reads[v]==(v?8:52)*iterations&&writes[v]==(v?0:52)*iterations);
  printf("{\"mode\":\"idle-exit-bundle\",\"variant\":%u,\"iterations\":%u,\"cpu_ns\":%llu,\"reads\":%llu,\"writes\":%llu}\n",v,iterations,(unsigned long long)elapsed,(unsigned long long)reads[v],(unsigned long long)writes[v]);
 }
 canonical();
 /* Every actual slot is checked, even if a late slot changes. Hardware IAR
  * and EOI must invalidate the idle path and keep active priorities/APRs. */
 assert(mutate(0,0,48,1,0));canonical();hardware_ack(0,0);canonical();
 int active=-1;for(unsigned i=0;i<count;i++)if((banks[0][0][i]&ACTIVE)&&(uint32_t)banks[0][0][i]==48)active=i;
 assert(active>=0);uint64_t active_apr[2][2][4];memcpy(active_apr,apr,sizeof(apr));
 which=1;reads[1]=writes[1]=0;
 for(unsigned i=0;i<iterations;i++)assert(apis[1].poll(0));
 assert(reads[1]==4*iterations&&writes[1]==0&&!memcmp(active_apr,apr,sizeof(apr)));
 hardware_eoi(0,0);canonical();
 unsigned pending=0;for(unsigned i=0;i<count;i++)if((banks[1][0][i]&PENDING)&&(uint32_t)banks[1][0][i]==48)pending++;
 assert(pending==1);
 /* ROUTE is the state-changing MMIO path which does not fold itself. */
 which=1;assert(apis[1].write(0,D+0x6000+48*8,8,0x80000000));
 reads[1]=writes[1]=0;assert(apis[1].poll(0));assert(reads[1]==4&&writes[1]>=4);
 reads[1]=writes[1]=0;assert(apis[1].poll(0));assert(reads[1]==4&&writes[1]==0);
 /* A reset of domain0 must not invalidate domain1's clean saved-bank cache. */
 assert(apis[1].poll(1));assert(apis[1].reset(0));reads[1]=writes[1]=0;
 assert(apis[1].poll(1));assert(reads[1]==4&&writes[1]==0);
 /* Unassigned IRQ/value/domain checks remain ahead of the same-level path. */
 reads[1]=writes[1]=0;
 assert(!apis[1].level(0,26,0)&&!apis[1].level(1,48,0)&&!apis[1].level(2,33,0)&&!apis[1].level(0,33,2));
 assert(reads[1]==0&&writes[1]==0);
 assert(apis[1].poll(0)); /* Complete the selected domain's fresh reset. */
 banks[1][0][3]=PENDING|GROUP1|33; /* Late slot has no trusted software owner. */
 uint64_t forged[16];memcpy(forged,banks[1][0],sizeof(forged));reads[1]=writes[1]=0;
 assert(!apis[1].poll(0)&&!apis[1].healthy(0));
 assert(reads[1]>=4&&writes[1]==0&&!memcmp(forged,banks[1][0],sizeof(forged)));
 puts("unified GIC unchanged-bank hotpath, dirty invalidation and hardware transitions: PASS");
}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--hotpath")){hotpath();return 0;}
 assert(argc==1);
 random_traces();corruption();
 printf("{\"transitions\":%llu,\"comparisons\":%llu,\"hardware_acks\":%llu,\"hardware_eois\":%llu,\"corruption_scenarios\":%llu,\"lr_counts\":[1,4,16],\"ok\":true}\n",(unsigned long long)transitions,(unsigned long long)comparisons,(unsigned long long)ack_count,(unsigned long long)eoi_count,(unsigned long long)corruption_count);
 return 0;
}
