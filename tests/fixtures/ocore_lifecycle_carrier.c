/* Primitive Linux carrier for current O-core policy. No libc or policy oracle.
 * Privileged architecture hooks below are explicit effect-recording models.
 * RAM replacement, namespace operations and O10 policy remain production code.
 */
typedef unsigned long long u64;
typedef unsigned long usize;
typedef unsigned int u32;
typedef unsigned char u8;
#define S(n) _O_runtime__common__namespace_store__##n
#define E(n) _O_runtime__common__o10_executor__##n
#define P(n) _O_runtime__aarch64__kernel_world_9p__##n
#define U(n) _O_runtime__aarch64__plan9_namespace_uart__##n
#define B(n) _O_runtime__aarch64__kernel_world_virtio__##n
#define N(n) _O_runtime__aarch64__kernel_world_net__##n
#define M(n) _O_runtime__aarch64__kernel_world_monitor__##n
#define W(n) _O_runtime__aarch64__unified_world__##n
#define I(n) _O_runtime__aarch64__linux_domain_images__##n

extern u64 S(init)(usize,usize,u64),S(session_init)(u64,u64),S(session_handle)(u64);
extern u64 S(revoke)(u64),S(session_claim)(u64,u64,u64),S(revoke_if_current)(u64,u64);
extern usize S(handle)(u64,const u8*,usize,u8*,usize);
extern u64 E(epoch)(void),E(last_seq)(void),E(pending)(void),E(commit)(const u8*,usize);
extern usize E(prepare)(const u8*,usize,u8*,usize);
extern u64 P(init)(u64,u64,u64),P(detach)(u64),P(provision)(u64,u64,u64);
extern u64 P(bind_current)(u64,u64,u64),P(generation)(void),P(bound)(void),P(mmio_write)(u64,u64);
extern u64 U(init)(u64),U(revoke)(void),U(qualification_generation)(void);
extern u64 B(init)(u64,u64,u64),B(configure_backing)(usize,usize,u64);
extern u64 B(generation)(void),N(generation)(void),N(init)(u64,u64,u64);
extern u64 I(register)(usize,usize,usize,usize,usize,usize);
extern void M(lifecycle_test_admit)(void);
extern u64 W(lifecycle_test_init)(void),W(lifecycle_test_request)(void);

/* These names are made observable only in a fresh test object by objcopy.
 * C does not define their storage or replace the production allocation code.
 */
extern u64 S(SERIAL),S(GENERATION)[5];
extern u64 P(SESSION_EPOCH),P(ACTIVE),U(ACTIVE);
extern u64 W(O10_DOMAIN_GENERATION)[2],W(LINUX_LEASE_GENERATION),W(O10_LEASE_GENERATION);
extern u64 W(LINUX_SESSION_GENERATION),W(O10_SESSION_GENERATION),W(LIVE)[2],W(BLOCKED)[2];
extern u64 W(LINUX_WAIT_BIND),W(O10_WAIT_BIND),W(LINUX_DETACHED),W(LINUX_WITHDRAWN),W(PLAN9_WITHDRAWN);
extern u64 E(LAST),E(EPOCH);

typedef struct { u64 op,a,b,c,d; usize length; u8 bytes[512]; } LCStep;
typedef struct { u64 transport,plan9_epoch,serial,domain,lease,session_epoch,last,epoch;
                 usize count; } LCCase;

void *memcpy(void *d,const void *s,usize n) { u8 *a=d;const u8*b=s;for(usize i=0;i<n;i++)a[i]=b[i];return d; }
void *memset(void *d,int value,usize n) { u8*a=d;for(usize i=0;i<n;i++)a[i]=(u8)value;return d; }
static u64 syscall6(u64 number,u64 a,u64 b,u64 c,u64 d,u64 e,u64 f) {
#if defined(__x86_64__)
 register u64 rax __asm__("rax")=number,r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
 __asm__ volatile("syscall":"+a"(rax):"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return rax;
#elif defined(__aarch64__)
 register u64 x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=number;
 __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory");return x0;
#elif defined(__riscv) && __riscv_xlen == 64
 register u64 a0 __asm__("a0")=a,a1 __asm__("a1")=b,a2 __asm__("a2")=c,a3 __asm__("a3")=d,a4 __asm__("a4")=e,a5 __asm__("a5")=f,a7 __asm__("a7")=number;
 __asm__ volatile("ecall":"+r"(a0):"r"(a1),"r"(a2),"r"(a3),"r"(a4),"r"(a5),"r"(a7):"memory");return a0;
#else
#error Missing lifecycle test ISA
#endif
}
static void flush_output(void);
__attribute__((noreturn)) static void finish(u64 code) {
 flush_output();
#if defined(__x86_64__)
 syscall6(60,code,0,0,0,0,0);
#else
 syscall6(93,code,0,0,0,0,0);
#endif
 __builtin_trap();
}
static void require(int condition);
static void read_all(u64 fd,void*out,usize n) {
 u8*p=out;while(n){
#if defined(__x86_64__)
  u64 got=syscall6(0,fd,(u64)p,n,0,0,0);
#else
  u64 got=syscall6(63,fd,(u64)p,n,0,0,0);
#endif
  require(got&&got<=n);p+=got;n-=got;}
}
static u64 input_word(u64 fd) {u8 bytes[8];read_all(fd,bytes,8);u64 value=0;for(usize i=0;i<8;i++)value|=(u64)bytes[i]<<(8*i);return value;}
static void raw_emit(const char*s,usize n) { while(n) {
#if defined(__x86_64__)
 u64 wrote=syscall6(1,1,(u64)s,n,0,0,0);
#else
 u64 wrote=syscall6(64,1,(u64)s,n,0,0,0);
#endif
 if(!wrote||wrote>n)__builtin_trap();s+=wrote;n-=wrote; } }
static char output[65536];static usize output_used;
static void flush_output(void) { if(output_used){raw_emit(output,output_used);output_used=0;} }
static void emit(const char*s,usize n) { while(n){usize room=sizeof(output)-output_used;
 if(!room){flush_output();room=sizeof(output);}usize take=n<room?n:room;
 memcpy(output+output_used,s,take);output_used+=take;s+=take;n-=take;} }
static void text(const char*s) { usize n=0;while(s[n])n++;emit(s,n); }
static void number(u64 n) { char digits[21];usize at=21;do{digits[--at]=(char)('0'+n%10);n/=10;}while(n);emit(digits+at,21-at); }
static void hexbytes(const u8*p,usize n) { const char*h="0123456789abcdef";for(usize i=0;i<n;i++){char x[2]={h[p[i]>>4],h[p[i]&15]};emit(x,2);} }
static void array(const u64*a,usize n) { text("[");for(usize i=0;i<n;i++){if(i)text(",");number(a[i]);}text("]"); }
static void require(int yes) { if(!yes){text("{\"unexpected_adapter\":true}\n");finish(97);} }
static void map(u64 base,u64 bytes) {
#if defined(__x86_64__)
 const u64 call=9;
#else
 const u64 call=222;
#endif
 require(syscall6(call,base,bytes,3,0x100022,(u64)-1,0)==base);
}
static void readonly(u64 base,u64 bytes) {
#if defined(__x86_64__)
 const u64 call=10;
#else
 const u64 call=226;
#endif
 require(syscall6(call,base,bytes,1,0,0,0)==0);
}
static u64 load(const void*p,usize n) { const u8*b=p;u64 v=0;for(usize i=0;i<n;i++)v|=(u64)b[i]<<(8*i);return v; }
static void store(void*p,u64 v,usize n) { u8*b=p;for(usize i=0;i<n;i++)b[i]=(u8)(v>>(8*i)); }
static u64 tokens[256],reset_count[2],ram_digest[2],vmcr[2],hcr[2],lrs[2][4],ticks,current_step,value;
static u64 effects[4096][4],effect_count,reset_failure,batch_mode,batch_index,prefix_mode,group_index;
static u8 volume[16777216] __attribute__((aligned(4096))),response[8192];
static usize response_length;
static void effect(u64 kind,u64 domain,u64 first,u64 second) {
 require(effect_count<4096);
 effects[effect_count][0]=kind;effects[effect_count][1]=domain;
 effects[effect_count][2]=first;effects[effect_count][3]=second;effect_count++;
}
/* Hash bytes actually written by the production replacement loops. Zero words
 * are folded eight bytes at a time, after reading them, without assuming that
 * any region was cleared. The carrier contains no lifecycle transition oracle.
 */
static u64 ram_hash(u64 base) {
 const u64 prime=0x100000001b3ull;
 u64 power=1;for(usize i=0;i<8;i++)power*=prime;
 u64 hash=0xcbf29ce484222325ull;
 const volatile u64*words=(const volatile u64*)base;
 for(usize i=0;i<0x20000000/8;i++) {
  u64 word=words[i];
  if(word==0)hash*=power;
  else for(usize j=0;j<8;j++){hash^=(u8)(word>>(j*8));hash*=prime;}
 }
 return hash;
}
static void record(void) {
 if(batch_mode){text(prefix_mode?"{\"prefix\":":"{\"case\":");number(prefix_mode?group_index:batch_index);text(",\"record\":");}
 u64 sessions[4],generations[4];for(usize i=0;i<4;i++){sessions[i]=S(session_handle)(i+1);generations[i]=S(GENERATION)[i+1];}
 u64 dg[2]={W(O10_DOMAIN_GENERATION)[0],W(O10_DOMAIN_GENERATION)[1]};
 u64 leases[2]={W(LINUX_LEASE_GENERATION),W(O10_LEASE_GENERATION)};
 u64 session_gen[2]={W(LINUX_SESSION_GENERATION),W(O10_SESSION_GENERATION)};
 u64 states[2]={W(LIVE)[0]?((W(BLOCKED)[0]||W(LINUX_WAIT_BIND))?3:2):(W(LINUX_WITHDRAWN)?5:4),
                W(LIVE)[1]?((W(BLOCKED)[1]||W(O10_WAIT_BIND))?3:2):(W(PLAN9_WITHDRAWN)?5:4)};
 u64 transport[6]={B(generation)(),N(generation)(),P(generation)(),P(SESSION_EPOCH),P(ACTIVE),P(bound)()};
 u64 plan9_transport[2]={U(qualification_generation)(),U(ACTIVE)};
 u64 journal[3]={E(epoch)(),E(last_seq)(),E(pending)()};
 u64 terminal[4]={load((void*)0x6d0000d0,8),load((void*)0x6d0000d8,8),load((void*)0x6d0000e0,8),load((void*)0x6d0000e8,8)};
 text("{\"step\":");number(current_step);text(",\"value\":");number(value);text(",\"reply\":\"");hexbytes(response,response_length);
 text("\",\"sessions\":");array(sessions,4);text(",\"namespace_generations\":");array(generations,4);
 text(",\"domain_generations\":");array(dg,2);text(",\"leases\":");array(leases,2);text(",\"session_generations\":");array(session_gen,2);
 text(",\"states\":");array(states,2);text(",\"transport\":");array(transport,6);text(",\"plan9_transport\":");array(plan9_transport,2);text(",\"journal\":");array(journal,3);
 text(",\"reset_count\":");array(reset_count,2);text(",\"ram_digest\":");array(ram_digest,2);
 text(",\"effects\":[");for(usize i=0;i<effect_count;i++){if(i)text(",");array(effects[i],4);}text("]");
 text(",\"terminal\":");array(terminal,4);text("}");if(batch_mode)text("}");text("\n");flush_output();
}
void lifecycle_unexpected(void) { require(0); }
void kw_memory_barrier(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
void uw_memory_barrier(void) { __atomic_thread_fence(__ATOMIC_SEQ_CST); }
u64 uw_domain_reset(u64 domain,u64 pc,u64 x0,u64 pstate) {
 require(domain<2&&pstate==0x3c5);
 require((domain==0&&pc==0x40000000&&x0==0x47e00000)||(domain==1&&pc==0x40100000&&x0==0x40000000));
 ram_digest[domain]=ram_hash(domain==0?0x48000000:0xb0000000);
 effect(1,domain,ram_digest[domain],0);effect(2,domain,pc,x0);
 reset_count[domain]++;
 if(reset_failure){reset_failure=0;return 0;}return 1;
}
u64 uw_counter_read(void) { return ++ticks; }
void uw_serial_putc(u64 byte) { require(byte<256); }
u64 uw_vgic_lr_count(void) { return 4; }
u64 uw_vgic_lr_read(u64 d,u64 i) { require(d<2&&i<4);return lrs[d][i]; }
void uw_vgic_lr_write(u64 d,u64 i,u64 v) { require(d<2&&i<4);lrs[d][i]=v;effect(5,d,i,v); }
u64 uw_vgic_vmcr_read(u64 d) { require(d<2);return vmcr[d]; }
void uw_vgic_vmcr_write(u64 d,u64 v) { require(d<2);vmcr[d]=v;effect(3,d,v,0); }
u64 uw_vgic_hcr_read(u64 d) { require(d<2);return hcr[d]; }
void uw_vgic_hcr_write(u64 d,u64 v) { require(d<2);hcr[d]=v;effect(4,d,v,0); }
__attribute__((noreturn)) void uw_halt(void) { response_length=0;record();finish(86); }

static void initialize(const LCCase*c) {
 /* Reduced-policy carriers share the framing, but do not initialize unrelated
  * frontends or lifetime identities. Limits remain in isolated source copies. */
 map(0x6d000000,0x100000);
 if(c->transport==0) {
  require(c->plan9_epoch<=1);
  if(c->plan9_epoch==1)require(S(init)((usize)volume,sizeof(volume),1)==1);
  return;
 }
 map(0x48000000,0x20000000);map(0xb0000000,0x20000000);map(0x70000000,4096);
 map(0xd0000000,4096);map(0xd1000000,4096);map(0xd2000000,4096);map(0xda000000,4096);map(0xe2000000,4096);
 for(usize i=0;i<4096;i++){((u8*)0x48000000)[i]=0xcc;((u8*)0xb0000000)[i]=0xa9;((u8*)0x70000000)[i]=0xdd;
   ((u8*)0xd2000000)[i]=(u8)(i^0x31);((u8*)0xe2000000)[i]=(u8)(i^0x57);((u8*)0xda000000)[i]=(u8)(i^0x83);
   ((u8*)0xd0000000)[i]=(u8)(i^0xa1);((u8*)0xd1000000)[i]=(u8)(i^0xb3);}
 store((void*)0x6d000000,c->plan9_epoch,8);store((void*)0xd1000000,0xedfe0dd0,4);
 readonly(0xd0000000,4096);readonly(0xd1000000,4096);readonly(0xd2000000,4096);readonly(0xda000000,4096);readonly(0xe2000000,4096);
 store((void*)0x6d000090,32,8);store((void*)0x6d000098,32,8);
 require(I(register)(0xd2000000,37,0xe2000000,19,0xda000000,73)==0);
 require(S(init)((usize)volume,sizeof(volume),1)==1);
 require(P(init)(0x40000000,0x20000000,c->transport)==1);require(U(init)(c->plan9_epoch)==1);
 require(B(configure_backing)(0x70000000,4096,1)==1);
 require(B(init)(0x40000000,0x20000000,1)==1&&N(init)(0x40000000,0x20000000,1)==1);
 M(lifecycle_test_admit)();require(W(lifecycle_test_init)()==1);
 tokens[1]=S(session_handle)(1);tokens[2]=S(session_handle)(4);
 if(c->serial)S(SERIAL)=c->serial;if(c->domain)W(O10_DOMAIN_GENERATION)[0]=c->domain;
 if(c->lease)W(LINUX_LEASE_GENERATION)=c->lease;if(c->session_epoch)P(SESSION_EPOCH)=c->session_epoch;
 if(c->last)E(LAST)=c->last;if(c->epoch)E(EPOCH)=c->epoch;
}
static void step(const LCStep*s) {
 response_length=0;value=0;effect_count=0;reset_failure=(s->op==17&&s->a==1);
 if(s->op==1){value=S(session_init)(s->a,s->b);require(s->c<256);tokens[s->c]=value;}
 else if(s->op==2)value=S(revoke)(s->a);
 else if(s->op==3){require(s->c<256&&s->d<256);value=S(session_claim)(s->a,s->b,tokens[s->c]);tokens[s->d]=value;}
 else if(s->op==4){require(s->b<256);value=S(revoke_if_current)(s->a,tokens[s->b]);}
 else if(s->op==5)value=S(init)((usize)volume,sizeof(volume),s->a);
 else if(s->op==6){require(s->a<256&&s->length<=512);u64 session=tokens[s->a];if(s->d==1)session^=1;response_length=S(handle)(session,s->bytes,s->length,response,sizeof(response));value=response_length;if(s->b){require(s->b<256);tokens[s->b]=S(session_handle)(s->c);}}
 else if(s->op==7){require(s->b<256);value=S(session_handle)(s->a);tokens[s->b]=value;}
 else if(s->op==8)value=P(init)(0x40000000,0x20000000,s->a);
 else if(s->op==9)value=P(detach)(s->a);
 else if(s->op==10)value=P(provision)(0x40000000,0x20000000,s->a);
 else if(s->op==11){require(s->b<256);value=P(bind_current)(s->a,tokens[s->b],s->c);}
 else if(s->op==12)value=P(mmio_write)(s->a?s->a:112,s->b);
 else if(s->op==13)value=U(init)(s->a);
 else if(s->op==14)value=U(revoke)();
 else if(s->op==15){response_length=E(prepare)(s->bytes,s->length,response,512);value=response_length;}
 else if(s->op==16)value=E(commit)(s->bytes,s->length);
 else if(s->op==17){require(s->length<=512);memcpy((void*)0x6d0a0000,s->bytes,s->length);store((void*)0x6d000070,current_step+1,8);store((void*)0x6d000078,10,8);value=W(lifecycle_test_request)();response_length=(usize)load((void*)0x6d0a0200,4);require(response_length<=512);memcpy(response,(void*)0x6d0a0200,response_length);}
 else require(0);
 require(response_length<=sizeof(response));record();
}
static void read_step(u64 fd,LCStep*s) {
 s->op=input_word(fd);s->a=input_word(fd);s->b=input_word(fd);s->c=input_word(fd);s->d=input_word(fd);s->length=input_word(fd);
 require(s->length<=512);read_all(fd,s->bytes,s->length);
}
static LCStep batch_steps[10000],prefix_steps[10000];
static u64 fork_process(void) {
#if defined(__x86_64__)
 return syscall6(57,0,0,0,0,0,0);
#else
 return syscall6(220,17,0,0,0,0,0);
#endif
}
static u64 wait_process(u64 pid) {
#if defined(__x86_64__)
 const u64 call=61;
#else
 const u64 call=260;
#endif
 u64 status=0;require(syscall6(call,pid,(u64)&status,0,0,0,0)==pid);
 return(status&127)?128+(status&127):(status>>8)&255;
}
static void completed(u64 code) {
 text("{\"case\":");number(batch_index);text(",\"exit\":");number(code);text("}\n");flush_output();
}
static void run_groups(u64 fd,LCCase*c) {
 initialize(c);usize base=0;
 for(group_index=0;group_index<c->count;group_index++){
  usize prefix_count=input_word(fd);require(prefix_count<=10000);
  for(usize i=0;i<prefix_count;i++)read_step(fd,&prefix_steps[i]);
  usize actions=input_word(fd);require(actions&&actions<=10000);
  for(usize i=0;i<actions;i++)read_step(fd,&batch_steps[i]);
  flush_output();u64 group=fork_process();require(group<0x7fffffff);
  if(group==0){
   prefix_mode=1;current_step=(u64)-1;record();
   for(current_step=0;current_step<prefix_count;current_step++)step(&prefix_steps[current_step]);
   prefix_mode=0;
   for(usize i=0;i<actions;i++){
    batch_index=base+i;flush_output();u64 child=fork_process();require(child<0x7fffffff);
    if(child==0){current_step=prefix_count;step(&batch_steps[i]);finish(0);}
    completed(wait_process(child));
   }
   finish(0);
  }
  require(wait_process(group)==0);base+=actions;
 }
}
static void run_batch(u64 fd,LCCase*c) {
 usize cases=c->count;initialize(c);
 for(batch_index=0;batch_index<cases;batch_index++){
  usize count=input_word(fd);require(count&&count<=10000);
  for(usize i=0;i<count;i++)read_step(fd,&batch_steps[i]);
  flush_output();
  u64 pid=fork_process();
  require(pid<0x7fffffff);
  if(pid==0){current_step=(u64)-1;record();for(current_step=0;current_step<count;current_step++)step(&batch_steps[current_step]);finish(0);}
  completed(wait_process(pid));
 }
}
int conformance_main(u64 *stack) {
 require(stack[0]==2);const char*arg=(const char*)stack[2];
#if defined(__x86_64__)
 u64 fd=syscall6(257,(u64)-100,(u64)arg,0,0,0,0);
#else
 u64 fd=syscall6(56,(u64)-100,(u64)arg,0,0,0,0);
#endif
 require(fd<0x7fffffff);u64 magic=input_word(fd);require(magic==0x31434c4f434f||magic==0x32434c4f434f||magic==0x33434c4f434f);batch_mode=magic!=0x31434c4f434f;
 LCCase c;c.transport=input_word(fd);c.plan9_epoch=input_word(fd);c.serial=input_word(fd);c.domain=input_word(fd);
 c.lease=input_word(fd);c.session_epoch=input_word(fd);c.last=input_word(fd);c.epoch=input_word(fd);c.count=input_word(fd);
 require(c.count<=10000&&(!batch_mode||c.count));if(magic==0x33434c4f434f){run_groups(fd,&c);return 0;}if(batch_mode){run_batch(fd,&c);return 0;}initialize(&c);current_step=(u64)-1;record();
 for(current_step=0;current_step<c.count;current_step++){
  LCStep s;read_step(fd,&s);step(&s);
 }
 flush_output();return 0;
}

#if defined(__x86_64__)
__asm__(".text\n.globl _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall conformance_main\nmov %eax,%edi\nmov $60,%eax\nsyscall\nud2\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n_start:\nmov x0,sp\nbl conformance_main\nmov x8,#93\nsvc #0\nbrk #0\n");
#else
__asm__(".text\n.globl _start\n_start:\nmv a0,sp\ncall conformance_main\nli a7,93\necall\nebreak\n");
#endif
