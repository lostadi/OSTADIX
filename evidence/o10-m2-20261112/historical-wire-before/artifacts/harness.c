
#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#undef linux

#define REF(n) _O_runtime__common__namespace_store_baseline__##n
#define NEW(n) _O_runtime__common__namespace_store__##n
#define DECLARE(P) \
 extern uint64_t P(init)(uintptr_t,size_t,uint64_t),P(healthy)(void); \
 extern uint64_t P(session_init)(uint64_t,uint64_t),P(revoke)(uint64_t),P(provision_clock)(uint64_t); \
 extern uint64_t P(session_claim)(uint64_t,uint64_t,uint64_t),P(session_is_current)(uint64_t,uint64_t),P(revoke_if_current)(uint64_t,uint64_t); \
 extern size_t P(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t); \
 extern uint64_t P(READY),P(EPOCH),P(SERIAL),P(CLOCK); \
 extern uint8_t P(USED)[3999],P(VERSIONED)[5]; \
 extern size_t P(FREE_BLOCKS),P(MSIZE)[5],P(F_OBJECT)[512]; \
 extern uint64_t P(SESSION)[5],P(GENERATION)[5],P(F_SESSION)[512],P(F_NUMBER)[512],P(F_GENERATION)[512],P(F_MODE)[512];
DECLARE(REF)
DECLARE(NEW)
static uint8_t *pair_original,*pair_candidate;
static uint64_t pair_operations,pair_states;
#define SAME(n) do { if(memcmp(&NEW(n),&REF(n),sizeof NEW(n))){fprintf(stderr,"state differs: %s at operation %llu\n",#n,(unsigned long long)pair_operations);abort();} }while(0)
static void pair_state(void){
 SAME(READY);SAME(EPOCH);SAME(SERIAL);SAME(CLOCK);SAME(USED);SAME(FREE_BLOCKS);
 SAME(SESSION);SAME(GENERATION);SAME(VERSIONED);SAME(MSIZE);SAME(F_SESSION);
 SAME(F_NUMBER);SAME(F_OBJECT);SAME(F_GENERATION);SAME(F_MODE);
 if(pair_original)assert(!memcmp(pair_original,pair_candidate,16777216));
 pair_states++;
}
uint64_t PAIR_init(uintptr_t address,size_t length,uint64_t epoch){
 assert(length==16777216);
 if(!pair_candidate){pair_candidate=mmap(NULL,length,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(pair_candidate!=MAP_FAILED);}
 pair_original=(uint8_t*)address;
 // The historical fixtures deliberately corrupt/migrate backing bytes before
 // init. Apply the identical external input to both stores; prior operation
 // effects have already been compared byte-for-byte, never copied over here.
 memcpy(pair_candidate,pair_original,length);
 uint64_t a=REF(init)(address,length,epoch),b=NEW(init)((uintptr_t)pair_candidate,length,epoch);
 pair_operations++;assert(a==b);pair_state();return a;
}
uint64_t PAIR_healthy(void){uint64_t a=REF(healthy)(),b=NEW(healthy)();assert(a==b);pair_state();return a;}
uint64_t PAIR_provision_clock(uint64_t x){uint64_t a=REF(provision_clock)(x),b=NEW(provision_clock)(x);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_session_init(uint64_t g,uint64_t e){uint64_t a=REF(session_init)(g,e),b=NEW(session_init)(g,e);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_revoke(uint64_t g){uint64_t a=REF(revoke)(g),b=NEW(revoke)(g);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_session_claim(uint64_t g,uint64_t e,uint64_t old){uint64_t a=REF(session_claim)(g,e,old),b=NEW(session_claim)(g,e,old);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_session_is_current(uint64_t g,uint64_t old){uint64_t a=REF(session_is_current)(g,old),b=NEW(session_is_current)(g,old);pair_operations++;assert(a==b);pair_state();return a;}
uint64_t PAIR_revoke_if_current(uint64_t g,uint64_t old){uint64_t a=REF(revoke_if_current)(g,old),b=NEW(revoke_if_current)(g,old);pair_operations++;assert(a==b);pair_state();return a;}
size_t PAIR_handle(uint64_t session,const uint8_t *request,size_t length,uint8_t *response,size_t capacity){
 uint8_t input[8192],output[8192];
 if(request)memcpy(input,request,length<sizeof input?length:sizeof input);
 if(response)memcpy(output,response,sizeof output);
 const uint8_t *candidate_request=request?input:NULL;
 if(request==response&&request){memcpy(output,response,sizeof output);candidate_request=output;}
 size_t a=REF(handle)(session,request,length,response,capacity);
 size_t b=NEW(handle)(session,candidate_request,length,response?output:NULL,capacity);
 pair_operations++;
 if(a!=b||(response&&memcmp(response,output,sizeof output))){fprintf(stderr,"wire differs: operation %llu kind %u cap %zu lengths %zu/%zu\n",(unsigned long long)pair_operations,request?request[4]:0,capacity,a,b);abort();}
 pair_state();return a;
}
#define NS(name) PAIR_##name

extern uint64_t NS(init)(uintptr_t,size_t,uint64_t),NS(healthy)(void);
extern uint64_t NS(session_init)(uint64_t,uint64_t),NS(revoke)(uint64_t);
extern uint64_t NS(provision_clock)(uint64_t);
extern size_t NS(handle)(uint64_t,const uint8_t *,size_t,uint8_t *,size_t);
static uint8_t request[8192],response[8192];
static size_t pos,received;
static uint64_t serial=1;
static void *volume;
static uint64_t rd(const uint8_t *p,unsigned n) {
    uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(i*8);return v;
}
static void st(uint8_t *p,uint64_t v,unsigned n) {
    for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(i*8));
}
static void put(uint64_t v,unsigned n) { st(request+pos,v,n);pos+=n; }
static void str(const char *s) { size_t n=strlen(s);put(n,2);memcpy(request+pos,s,n);pos+=n; }
static void begin(unsigned type) { memset(request,0,sizeof request);pos=7;request[4]=type;st(request+5,0x1234,2); }
static unsigned callcap(uint64_t session,size_t cap) {
    st(request,pos,4);memset(response,0x55,sizeof response);
    received=NS(handle)(session,request,pos,response,cap);
    if(!received)return 0;
    assert(received>=7 && received<=cap && rd(response,4)==received && rd(response+5,2)==rd(request+5,2));
    if(response[4]==107)assert(rd(response+7,2)+9==received);
    return response[4];
}
static unsigned call(uint64_t session) { return callcap(session,sizeof response); }
static void handshake(uint64_t session,uint32_t fid,const char *aname) {
    begin(100);put(8192,4);str("9P2000");assert(call(session)==101 && rd(response+7,4)==8192);
    begin(104);put(fid,4);put(UINT32_MAX,4);str("root");str(aname);assert(call(session)==105);
}
static uint64_t session(unsigned grant) { uint64_t s=NS(session_init)(grant,serial++);assert(s);handshake(s,1,"");return s; }
static unsigned walk(uint64_t s,uint32_t from,uint32_t to,const char *name) {
    begin(110);put(from,4);put(to,4);put(name?1:0,2);if(name)str(name);return call(s);
}
static unsigned openfid(uint64_t s,uint32_t fid,unsigned mode) {
    begin(112);put(fid,4);put(mode,1);return call(s);
}
static unsigned create(uint64_t s,uint32_t fid,const char *name,unsigned mode,unsigned access) {
    begin(114);put(fid,4);str(name);put(mode,4);put(access,1);return call(s);
}
static unsigned clunk(uint64_t s,uint32_t fid) { begin(120);put(fid,4);return callcap(s,7); }
static unsigned removefid(uint64_t s,uint32_t fid) { begin(122);put(fid,4);return call(s); }
static unsigned writefid(uint64_t s,uint32_t fid,uint64_t offset,const void *data,size_t length,size_t cap) {
    begin(118);put(fid,4);put(offset,8);put(length,4);memcpy(request+pos,data,length);pos+=length;return callcap(s,cap);
}
static unsigned readfid(uint64_t s,uint32_t fid,uint64_t offset,uint32_t length) {
    begin(116);put(fid,4);put(offset,8);put(length,4);return call(s);
}
static unsigned statfid(uint64_t s,uint32_t fid) { begin(124);put(fid,4);return call(s); }
static uint64_t qidpath(void) { return rd(response+12,8); }
static unsigned wstatfields(uint64_t s,uint32_t fid,const char *name,uint64_t length,uint32_t mode,size_t capacity) {
    begin(126);put(fid,4);size_t packed=pos;put(0,2);size_t inner=pos;put(0,2);
    put(UINT16_MAX,2);put(UINT32_MAX,4);put(255,1);put(UINT32_MAX,4);put(UINT64_MAX,8);
    put(mode,4);put(UINT32_MAX,4);put(UINT32_MAX,4);put(length,8);str(name);str("");str("");str("root");
    st(request+inner,pos-inner-2,2);st(request+packed,pos-inner,2);return callcap(s,capacity);
}
static unsigned wstat(uint64_t s,uint32_t fid,const char *name,uint64_t length) { return wstatfields(s,fid,name,length,UINT32_MAX,8192); }
static unsigned wstatmode(uint64_t s,uint32_t fid,uint32_t mode) { return wstatfields(s,fid,"",UINT64_MAX,mode,8192); }
static void initvolume(void) {
    volume=mmap(NULL,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
    assert(NS(init)((uintptr_t)volume,16777216,0x123456789abcdef1)==1 && NS(healthy)()==1);
    assert(NS(provision_clock)(1700000000)==1);
}
static void directory_records(void) {
    uint64_t s=session(1);assert(openfid(s,1,0)==113);assert(readfid(s,1,0,8192)==117);
    size_t length=(size_t)rd(response+7,4),at=11;unsigned names=0;
    while(at<11+length) {
        size_t size=(size_t)rd(response+at,2)+2;assert(size>=64 && at+size<=11+length);
        size_t n=(size_t)rd(response+at+41,2);assert(size==64+n);
        if(n==4 && !memcmp(response+at+43,"work",4))names|=1;
        if(n==3 && !memcmp(response+at+43,"pkg",3))names|=2;
        if(n==5 && !memcmp(response+at+43,"build",5))names|=4;
        if(n==8 && !memcmp(response+at+43,"services",8))names|=8;
        if(n==12 && !memcmp(response+at+43,"nativeREADME",12))names|=16;
        at+=size;
    }
    assert(at==11+length && names==31);
    assert(readfid(s,1,1,8192)==107);assert(clunk(s,1)==121);
}
static void sharing_and_persistence(void) {
    uint64_t linux=session(1),peer=session(2),ro=session(3);
    assert(walk(linux,1,2,"work")==111 && walk(linux,2,3,NULL)==111);
    assert(create(linux,3,"from-linux",0644,2)==115);
    uint64_t identity=qidpath();uint8_t data[8000];for(unsigned i=0;i<sizeof data;i++)data[i]=(uint8_t)(i^0xab);
    for(unsigned i=0;i<9;i++)assert(writefid(linux,3,i*sizeof data,data,sizeof data,11)==119 && rd(response+7,4)==sizeof data);
    assert(walk(peer,1,2,"from-linux")==111 && openfid(peer,2,0)==113 && qidpath()==identity);
    for(unsigned i=0;i<9;i++)assert(readfid(peer,2,i*sizeof data,sizeof data)==117 && rd(response+7,4)==sizeof data && !memcmp(response+11,data,sizeof data));
    assert(walk(ro,1,2,"from-linux")==111 && openfid(ro,2,1)==107);
    assert(openfid(ro,2,0)==113 && readfid(ro,2,0,10)==117);
    assert(writefid(ro,2,0,"bad",3,8192)==107);
    assert(walk(ro,1,3,NULL)==111 && create(ro,3,"denied",0644,1)==107);
    assert(wstat(ro,2,"renamed",UINT64_MAX)==107 && removefid(ro,2)==107);
    // Attach names and users cannot select another grant or escape /work.
    uint64_t scoped=NS(session_init)(2,serial++);assert(scoped);handshake(scoped,1,"/pkg");
    assert(walk(scoped,1,2,"..")==111);assert(walk(scoped,2,3,"nativeREADME")==107);
    assert(walk(scoped,1,3,NULL)==111 && create(scoped,3,"from-plan9",0644,2)==115);
    assert(writefid(scoped,3,5,"native",6,11)==119);
    assert(walk(linux,2,4,"from-plan9")==111 && openfid(linux,4,0)==113);
    assert(readfid(linux,4,0,20)==117 && rd(response+7,4)==11);
    for(unsigned i=0;i<5;i++)assert(response[11+i]==0);
    assert(!memcmp(response+16,"native",6));
    // Capacity preflight must leave file and directory metadata unchanged.
    assert(writefid(linux,3,0,"corrupt",7,10)==0);
    assert(readfid(linux,3,0,8)==117 && !memcmp(response+11,data,8));
    assert(wstat(linux,3,"renamed",17)==127);
    assert(walk(linux,2,5,"from-linux")==107 && walk(linux,2,5,"renamed")==111);
    assert(openfid(linux,5,0)==113 && qidpath()==identity);
    assert(readfid(linux,5,0,32)==117 && rd(response+7,4)==17 && !memcmp(response+11,data,17));
    assert(statfid(linux,5)==125 && rd(response+7,2)+9==received && rd(response+9,2)+2==rd(response+7,2));
    assert(walk(linux,2,6,NULL)==111 && create(linux,6,"temporary",0644,2)==115);
    assert(removefid(linux,6)==123 && statfid(linux,6)==107);
    assert(NS(revoke)(1)==1 && readfid(linux,3,0,1)==107);
    uint64_t old=scoped;
    assert(NS(init)((uintptr_t)volume,16777216,0x223456789abcdef1)==1);
    assert(readfid(old,3,0,1)==107);
    linux=session(1);assert(walk(linux,1,2,"work")==111 && walk(linux,2,3,"renamed")==111);
    assert(openfid(linux,3,0)==113 && qidpath()==identity);
    assert(readfid(linux,3,0,32)==117 && rd(response+7,4)==17 && !memcmp(response+11,data,17));
    // Ordinary Linux redirection truncates an existing file on OWRITE|OTRUNC.
    assert(walk(linux,2,4,"renamed")==111 && openfid(linux,4,0x11)==113);
    assert(readfid(linux,3,0,32)==117 && rd(response+7,4)==0);
    assert(writefid(linux,4,4,"z",1,11)==119);
    assert(readfid(linux,3,0,32)==117 && rd(response+7,4)==5 && response[15]=='z');
    for(unsigned i=0;i<4;i++)assert(response[11+i]==0);
}
static void fid_lifecycle(void) {
    uint64_t s=session(1);assert(walk(s,1,2,"work")==111);
    assert(walk(s,2,3,NULL)==111 && create(s,3,"old",0644,2)==115);uint64_t identity=qidpath();
    assert(walk(s,2,4,"old")==111);assert(removefid(s,3)==123);
    assert(walk(s,2,3,NULL)==111 && create(s,3,"new",0644,2)==115 && qidpath()!=identity);
    assert(openfid(s,4,0)==107); // Same slot reused, old object generation rejected.
    assert(clunk(s,4)==121); // Deleted objects must not leak known fid slots.
    assert(walk(s,2,4,"new")==111 && clunk(s,4)==121); // Linux immediately recycles that fid integer.
    assert(clunk(s,3)==121 && clunk(s,3)==0); // Seven-byte cap cannot fit Rerror.
    uint64_t fresh=NS(session_init)(1,serial++);assert(fresh && fresh!=s);
    assert(statfid(s,1)==107);assert(NS(session_init)(1,1)==0);
    handshake(fresh,1,"");
    // A partial Twalk must not bind its destination fid.
    begin(110);put(1,4);put(2,4);put(2,2);str("work");str("missing");assert(call(fresh)==111 && rd(response+7,2)==1);
    assert(statfid(fresh,2)==107);
    // Successful remove accepts the minimal response buffer.
    assert(walk(fresh,1,2,"work")==111 && walk(fresh,2,3,"new")==111);
    begin(122);put(3,4);assert(callcap(fresh,7)==123);
}
static void malformed(void) {
    uint64_t s=session(1);
    for(unsigned n=0;n<7;n++)assert(NS(handle)(s,request,n,response,sizeof response)==0);
    begin(104);put(20,4);put(UINT32_MAX,4);put(8190,2);assert(call(s)==107);
    begin(118);put(1,4);put(0,8);put(2000,4);assert(call(s)==107);
    begin(110);put(1,4);put(2,4);put(65535,2);assert(call(s)==107);
    begin(108);put(55,2);assert(callcap(s,7)==109);
    begin(104);put(1,4);put(UINT32_MAX,4);str("root");str("");assert(call(s)==107);
    // Every request truncation is rejected without creating a file.
    assert(walk(s,1,2,"work")==111);
    begin(114);put(2,4);str("truncated");put(0644,4);put(1,1);size_t full=pos;
    uint8_t saved[128];memcpy(saved,request,full);
    for(size_t n=7;n<full;n++) {memcpy(request,saved,full);pos=n;assert(call(s)==107);}
    assert(walk(s,2,3,"truncated")==107);
    assert(walk(s,2,3,NULL)==111);
    begin(114);put(3,4);str("small-reply");put(0644,4);put(1,1);assert(callcap(s,23)==0);
    assert(walk(s,2,4,"small-reply")==107);
}
static void capacities(void) {
    uint64_t s=session(1);assert(walk(s,1,2,"work")==111);
    char name[32];unsigned created=0;
    for(unsigned i=0;i<1100;i++) {
        assert(walk(s,2,3,NULL)==111);snprintf(name,sizeof name,"n%04u",i);
        unsigned result=create(s,3,name,0644,2);
        if(result==107) {assert(rd(response+7,2)==23 && !memcmp(response+9,"No space left on device",23));assert(clunk(s,3)==121);break;}
        assert(result==115 && clunk(s,3)==121);created++;
    }
    assert(created==1018 && NS(healthy)()==1);
    assert(walk(s,2,3,"n0000")==111 && removefid(s,3)==123);
    assert(walk(s,2,3,NULL)==111 && create(s,3,"after-free",0644,2)==115);
    assert(NS(init)((uintptr_t)volume,16777216,0x323456789abcdef1)==1);
}
static void block_capacity(void) {
    uint64_t s=session(1);assert(walk(s,1,2,"work")==111 && create(s,2,"large",0644,2)==115);
    uint8_t data[8000];memset(data,0x6c,sizeof data);uint64_t offset=0;
    for(;;) {
        unsigned result=writefid(s,2,offset,data,sizeof data,8192);
        if(result==107)break;
        assert(result==119);offset+=sizeof data;assert(offset<16777216);
    }
    assert(offset>16000000 && NS(healthy)()==1);
    assert(readfid(s,2,offset-8000,8000)==117 && rd(response+7,4)==8000 && !memcmp(response+11,data,8000));
    assert(wstat(s,2,"",10)==127);
    assert(writefid(s,2,10,data,8000,11)==119);
    assert(NS(init)((uintptr_t)volume,16777216,0x423456789abcdef1)==1);
}
static uint64_t mtime(uint64_t session,uint32_t fid) {
    assert(statfid(session,fid)==125);return rd(response+38,4);
}
static void clocks(void) {
    uint64_t s=session(1);assert(walk(s,1,2,"work")==111);
    assert(walk(s,2,3,NULL)==111 && create(s,3,"old-target",0644,2)==115);
    for(unsigned i=0;i<20;i++)assert(writefid(s,3,0,"target",6,11)==119);
    uint64_t target_time=mtime(s,3);assert(target_time>1700000000);
    assert(walk(s,2,4,NULL)==111 && create(s,4,"new-source",0644,2)==115);
    assert(mtime(s,4)>target_time);
    assert(writefid(s,3,0,"rebuilt",7,11)==119);target_time=mtime(s,3);
    assert(writefid(s,4,0,"changed",7,11)==119 && mtime(s,4)>target_time);
    // Original make/mk compares different objects, not their QID versions.
    assert(removefid(s,4)==123);
    uint64_t before=rd((uint8_t *)volume+56,8);
    assert(NS(init)((uintptr_t)volume,16777216,0x623456789abcdef1)==1);
    assert(NS(provision_clock)(1600000000)==1 && rd((uint8_t *)volume+56,8)>=before);
    s=session(1);assert(walk(s,1,2,"work")==111 && create(s,2,"after-restart",0644,2)==115);
    assert(mtime(s,2)>before);
    // An explicit user timestamp remains metadata, not the persisted clock.
    begin(126);put(2,4);size_t packed=pos;put(0,2);size_t inner=pos;put(0,2);
    put(UINT16_MAX,2);put(UINT32_MAX,4);put(255,1);put(UINT32_MAX,4);put(UINT64_MAX,8);
    put(UINT32_MAX,4);put(UINT32_MAX,4);put(0,4);put(UINT64_MAX,8);str("");str("");str("");str("root");
    st(request+inner,pos-inner-2,2);st(request+packed,pos-inner,2);assert(call(s)==127 && mtime(s,2)==0);
    before=rd((uint8_t *)volume+56,8);
    assert(NS(init)((uintptr_t)volume,16777216,0x723456789abcdef1)==1);
    assert(rd((uint8_t *)volume+56,8)>=before);
    // Previously valid v1 images with unused zero header words migrate safely.
    memset((uint8_t *)volume+56,0,16);
    assert(NS(init)((uintptr_t)volume,16777216,0x823456789abcdef1)==1);
    assert(rd((uint8_t *)volume+56,8)>=target_time);
}
static void clock_exhaustion(void) {
    assert(NS(provision_clock)(0)==0 && NS(provision_clock)(UINT32_MAX)==0);
    assert(NS(provision_clock)(UINT32_MAX-3)==1);
    uint64_t s=session(1);assert(walk(s,1,2,"work")==111 && create(s,2,"last",0644,2)==115);
    assert(rd((uint8_t *)volume+56,8)==UINT32_MAX-1);
    assert(writefid(s,2,0,"x",1,8192)==107 && NS(healthy)()==1);
    assert(readfid(s,2,0,1)==117 && rd(response+7,4)==0);
}
static void temporary_mode(void) {
    const uint32_t TMP=0x04000000,DIR=0x80000000;
    uint64_t linux=session(1),peer=session(2),ro=session(3);
    assert(walk(linux,1,2,"work")==111 && walk(linux,2,3,NULL)==111);
    // The unchanged original compiler creates its .7 files with0664|DMTMP.
    assert(create(linux,3,"object.7",0664|TMP,2)==115 && response[7]==4);
    uint64_t identity=qidpath();uint8_t binary[6000],tail[]={0,0x11,0x13,0xff};
    for(unsigned i=0;i<sizeof(binary);i++)binary[i]=(uint8_t)(i*17+3);
    assert(writefid(linux,3,0,binary,sizeof(binary),11)==119 && writefid(linux,3,9000,tail,4,11)==119);
    assert(clunk(linux,3)==121); // DMTMP never means remove-on-close.
    assert(walk(linux,2,4,"object.7")==111 && response[9]==4);
    assert(openfid(linux,4,2)==113 && response[7]==4 && qidpath()==identity);
    assert(readfid(linux,4,0,8000)==117 && rd(response+7,4)==8000 && !memcmp(response+11,binary,6000));
    for(unsigned i=6000;i<8000;i++)assert(response[11+i]==0);
    assert(readfid(linux,4,8000,2000)==117 && rd(response+7,4)==1004);
    for(unsigned i=0;i<1000;i++)assert(response[11+i]==0);
    assert(!memcmp(response+1011,tail,4));
    assert(statfid(linux,4)==125 && response[17]==4 && rd(response+30,4)==(0664|TMP));
    assert(walk(ro,1,2,"object.7")==111 && openfid(ro,2,1)==107 && openfid(ro,2,0)==113);
    assert(writefid(ro,2,0,"bad",3,8192)==107 && wstatmode(ro,2,0664)==107);
    assert(walk(ro,1,3,NULL)==111 && create(ro,3,"denied-temp",0664|TMP,2)==107);
    assert(walk(peer,1,2,"object.7")==111 && openfid(peer,2,0)==113 && response[7]==4);
    assert(NS(revoke)(1)==1 && readfid(linux,4,0,1)==107);
    assert(readfid(peer,2,0,4)==117 && !memcmp(response+11,binary,4));
    assert(NS(init)((uintptr_t)volume,16777216,0x923456789abcdef1)==1 && readfid(peer,2,0,1)==107);
    linux=session(1);assert(walk(linux,1,2,"work")==111 && walk(linux,2,4,"object.7")==111);
    assert(openfid(linux,4,2)==113 && response[7]==4 && qidpath()==identity);
    assert(statfid(linux,4)==125 && response[17]==4 && rd(response+30,4)==(0664|TMP));
    uint64_t version=rd(response+18,4),clock=rd((uint8_t*)volume+56,8);
    assert(wstatfields(linux,4,"",UINT64_MAX,0664,6)==0);
    assert(statfid(linux,4)==125 && rd(response+18,4)==version && response[17]==4 && rd((uint8_t*)volume+56,8)==clock);
    assert(wstatmode(linux,4,0664)==127 && statfid(linux,4)==125 && response[17]==0 && rd(response+30,4)==0664);
    assert(wstatmode(linux,4,0664|TMP)==127 && statfid(linux,4)==125 && response[17]==4);
    // Directory listings carry the same mode/qid flag as stat/open/walk.
    assert(walk(linux,2,8,NULL)==111 && openfid(linux,8,0)==113 && readfid(linux,8,0,8192)==117);
    size_t end=11+rd(response+7,4),at=11;unsigned found=0;
    while(at<end){size_t size=rd(response+at,2)+2,n=rd(response+at+41,2);assert(at+size<=end);
        if(n==8 && !memcmp(response+at+43,"object.7",8)){assert(response[at+8]==4 && rd(response+at+21,4)==(0664|TMP));found++;}at+=size;}
    assert(found==1);
    assert(walk(linux,2,6,NULL)==111 && create(linux,6,"temporary-dir",DIR|TMP|0755,0)==115 && response[7]==0x84);
    assert(wstatmode(linux,6,TMP|0755)==107 && statfid(linux,6)==125 && response[17]==0x84);
    assert(wstatmode(linux,6,DIR|0755)==127 && statfid(linux,6)==125 && response[17]==0x80);
    for(unsigned bit=9;bit<31;bit++)if(bit!=26){
        assert(walk(linux,2,20,NULL)==111);
        assert(create(linux,20,"unsupported",0664|TMP|(1u<<bit),2)==107 && clunk(linux,20)==121);
        assert(wstatmode(linux,4,0664|TMP|(1u<<bit))==107);
    }
    assert(walk(linux,2,20,NULL)==111 && create(linux,20,"orclose",0664|TMP,2|0x40)==107 && clunk(linux,20)==121);
    assert(readfid(linux,4,9000,4)==117 && !memcmp(response+11,tail,4));
    assert(NS(init)((uintptr_t)volume,16777216,0xa23456789abcdef1)==1);
}
static void corruption(unsigned scenario) {
    uint8_t *v=volume;
    if(scenario==6)v[4096+72]^=1; // Metadata checksum mismatch.
    if(scenario==7)v[48]^=1; // Header checksum mismatch.
    if(scenario==8) { // Validly checksummed chain alias is still rejected.
        uint64_t s=session(1);assert(walk(s,1,2,"work")==111 && create(s,2,"alias",0644,2)==115);
        assert(writefid(s,2,0,"x",1,11)==119);
        uint8_t *n=v+4096+6*384;st(n+48,1,8);
        uint64_t h=UINT64_C(0xcbf29ce484222325);for(unsigned i=0;i<376;i++)h=(h^n[i])*UINT64_C(0x100000001b3);st(n+376,h,8);
    }
    if(scenario==9) {memset(v,0,16777216);v[16777215]=1;} // Never format nonzero unknown storage.
    if(scenario==10)v[56]^=1; // Counter seal rejects torn/corrupted clock metadata.
    assert(NS(init)((uintptr_t)volume,16777216,0x523456789abcdef1)==0 && NS(healthy)()==0);
}

static void barriers(void){
 uint64_t s=session(1);assert(walk(s,1,2,"work")==111);
 const uint8_t bytes[]={0,0xff,'a',0x11,0x13,'z'};
 // Every response capacity around success and Rerror sizes. Failed create
 // leaves the fid unopened; retrying it must create exactly one object.
 for(size_t cap=0;cap<=40;cap++){
  char name[32];snprintf(name,sizeof name,"cap-%02zu",cap);
  assert(walk(s,2,3,NULL)==111);unsigned kind;
  if(cap<24){assert(create(s,3,name,0644,2)==115);assert(removefid(s,3)==123);assert(walk(s,2,3,NULL)==111);}
  begin(114);put(3,4);str(name);put(0644,4);put(2,1);kind=callcap(s,cap);
  if(cap<24){assert(kind==0);assert(create(s,3,name,0644,2)==115);}else assert(kind==115);
  assert(writefid(s,3,9,bytes,sizeof bytes,10)==0);
  assert(readfid(s,3,0,100)==117&&rd(response+7,4)==0);
  assert(writefid(s,3,9,bytes,sizeof bytes,11)==119);
  // Exact regular-read clamp by both MSIZE and response capacity, then EOF.
  begin(116);put(3,4);put(9,8);put(UINT32_MAX,4);kind=callcap(s,cap);
  if(cap<11)assert(kind==0);else{size_t n=cap-11;if(n>sizeof bytes)n=sizeof bytes;assert(kind==117&&rd(response+7,4)==n&&!memcmp(response+11,bytes,n));}
  assert(clunk(s,3)==121);
  assert(walk(s,2,3,name)==111);
  begin(112);put(3,4);put(0x12,1);kind=callcap(s,cap);
  if(cap<24){assert(kind==0);assert(openfid(s,3,0)==113);assert(readfid(s,3,9,sizeof bytes)==117&&rd(response+7,4)==sizeof bytes);}else{assert(kind==113&&readfid(s,3,0,1)==117&&rd(response+7,4)==0);}
  assert(clunk(s,3)==121);
 }
 // Multiwalk parses later components even after a miss; incomplete input
 // returns protocol error without binding or replacing either destination.
 begin(110);put(1,4);put(20,4);put(3,2);str("work");str("absent");put(4,2);put('x',1);assert(call(s)==107);
 assert(statfid(s,20)==107);
 begin(110);put(1,4);put(1,4);put(2,2);str("work");str("absent");assert(call(s)==111&&rd(response+7,2)==1);
 assert(walk(s,1,20,"work")==111&&clunk(s,20)==121); // original root fid survives partial same-fid walk
 uint64_t peer=session(2),ro=session(3),uart=session(4);
 assert(walk(peer,1,2,"..")==111&&walk(peer,2,3,"pkg")==107);
 assert(walk(ro,1,2,NULL)==111&&create(ro,2,"denied",0644,1)==107);
 assert(walk(uart,1,2,"work")==111&&walk(uart,2,3,"cap-00")==111&&openfid(uart,3,0)==113);
 assert(NS(revoke_if_current)(4,uart+1)==0&&readfid(uart,3,9,sizeof bytes)==117);
 assert(NS(session_claim)(4,100,uart+1)==0&&readfid(uart,3,9,sizeof bytes)==117);
 uint64_t replacement=NS(session_claim)(4,100,uart);assert(replacement&&replacement!=uart&&readfid(uart,3,0,1)==107);
 handshake(replacement,1,"");assert(NS(revoke_if_current)(4,uart)==0&&NS(session_is_current)(4,replacement)==1);
 assert(NS(revoke_if_current)(4,replacement)==1&&NS(session_is_current)(4,replacement)==0);
}
static void frame_matrix(void){
 uint64_t s=session(1);assert(walk(s,1,2,"work")==111&&create(s,2,"frames",0644,2)==115);
 uint8_t data[8169];for(size_t n=0;n<sizeof data;n++)data[n]=(uint8_t)(n^0x93);
 // msize8192 permits only8169 payload bytes, and read replies only8181.
 assert(writefid(s,2,0,data,sizeof data,8192)==119);
 assert(readfid(s,2,0,UINT32_MAX)==117&&rd(response+7,4)==sizeof data&&!memcmp(response+11,data,sizeof data));
 assert(writefid(s,2,UINT64_MAX,data,1,8192)==107);
 begin(100);put(256,4);str("9P2000");assert(call(s)==101&&rd(response+7,4)==256);
 begin(104);put(1,4);put(UINT32_MAX,4);str("root");str("");assert(call(s)==105);
 assert(walk(s,1,2,"work")==111&&walk(s,2,3,"frames")==111&&openfid(s,3,2)==113);
 assert(readfid(s,3,0,UINT32_MAX)==117&&rd(response+7,4)==245&&!memcmp(response+11,data,245));
 assert(writefid(s,3,0,data,233,11)==119);
 assert(writefid(s,3,0,data,234,8192)==107); // MSIZE request cap, no partial mutation
 begin(118);put(3,4);put(0,8);put(232,4);memcpy(request+pos,data,233);pos+=233;assert(call(s)==107);
 // All truncations and output-capacity boundaries of a valid Twrite.
 begin(118);put(3,4);put(7,8);put(17,4);memcpy(request+pos,data,17);pos+=17;
 uint8_t frame[128];size_t full=pos;memcpy(frame,request,full);
 for(size_t n=0;n<=full;n++)for(size_t cap=0;cap<=36;cap++){
  memcpy(request,frame,full);pos=n;callcap(s,cap);
 }
 // A declared-length mismatch is rejected before session lookup; unsupported
 // types, invalid sessions and every one-bit payload mutation use both stores.
 uint64_t rng=0x13579bdf;
 for(unsigned trial=0;trial<2048;trial++){
  memcpy(request,frame,full);pos=full;rng=rng*6364136223846793005ULL+1;
  size_t at=(rng>>32)%full;request[at]^=(uint8_t)(1u<<(trial%8));
  callcap(trial%5?s:UINT64_MAX,trial%41);
 }
 memcpy(request,frame,full);st(request,full+1,4);
 assert(NS(handle)(s,request,full,response,sizeof response)>0&&response[4]==107);
 // Renegotiation with insufficient output capacity must retain open fids.
 begin(100);put(8192,4);str("9P2000");assert(callcap(s,18)==0);
 assert(readfid(s,3,0,1)==117);
 assert(NS(provision_clock)(UINT32_MAX-1)==1);
 assert(writefid(s,3,0,data,0,8192)==107); // zero Twrite still checks clock exhaustion
 assert(walk(s,2,4,"frames")==111);
 begin(112);put(4,4);put(0x12,1);assert(callcap(s,23)==0); // capacity precedes truncation clock error
 assert(openfid(s,4,0x12)==107);
}

int main(int argc,char **argv) {
    assert(argc==2);unsigned scenario=(unsigned)atoi(argv[1]);initvolume();
    if(scenario==0)directory_records();
    if(scenario==1)sharing_and_persistence();
    if(scenario==2)fid_lifecycle();
    if(scenario==3)malformed();
    if(scenario==4)capacities();
    if(scenario==5)block_capacity();
    if(scenario>=6 && scenario<=10)corruption(scenario);
    if(scenario==11)clocks();
    if(scenario==12)clock_exhaustion();
    if(scenario==13)temporary_mode();
    if(scenario==14)barriers();
    if(scenario==15)frame_matrix();
    printf("paired operations=%llu whole-volume/state comparisons=%llu\n",(unsigned long long)pair_operations,(unsigned long long)pair_states);
    printf("native namespace scenario %u: PASS\n",scenario);return 0;
}
