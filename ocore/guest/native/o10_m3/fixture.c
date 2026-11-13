/* Minimal native EL1 M3 guest. Authority is the bound read-only transport.
 * The immutable aux record supplies labels and expected corpus bytes.
 * Errors publish a numeric diagnostic then BRK #0x10, containing this domain.
 */
#include <stdint.h>
#include <stddef.h>

#define AUX_IPA UINT64_C(0x40100000)
#define HEARTBEAT_IPA UINT64_C(0x401f0000)
#define UART_IPA UINT64_C(0x09001000)
#define FRAME 512u
#define POLLS 4096u
enum { BAD_AUX=1, TX_TIMEOUT=2, RX_TIMEOUT=3, BAD_REPLY=4,
       STORE_ERROR=5, CORPUS_MISMATCH=6, LOCAL_OVERFLOW=7,
       COUNTER_EXHAUSTED=8 };

static uint64_t little(const uint8_t *p, unsigned n) {
    uint64_t value=0;
    for(unsigned i=0;i<n;i++) value|=(uint64_t)p[i]<<(8*i);
    return value;
}
static int equal(const uint8_t *a,const uint8_t *b,unsigned n) {
    for(unsigned i=0;i<n;i++) if(a[i]!=b[i]) return 0;
    return 1;
}
static int aux_valid(const uint8_t *a) {
    static const uint8_t magic[8]={'O','1','0','M','3','N','1',0};
    if(!equal(a,magic,8) || little(a+8,4)!=1 || little(a+12,4)!=128
       || little(a+16,8)!=HEARTBEAT_IPA || little(a+24,8)!=UART_IPA) return 0;
    unsigned name=(unsigned)little(a+32,4),data=(unsigned)little(a+36,4);
    if(name==0 || name>32 || data==0 || data>48) return 0;
    for(unsigned i=0;i<name;i++) {
        uint8_t c=a[40+i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')
             ||c=='_'||c=='-'||c=='.')) return 0;
    }
    if((name==1&&a[40]=='.') || (name==2&&a[40]=='.'&&a[41]=='.')) return 0;
    for(unsigned i=name;i<32;i++) if(a[40+i]) return 0;
    for(unsigned i=data;i<48;i++) if(a[72+i]) return 0;
    for(unsigned i=120;i<128;i++) if(a[i]) return 0;
    return 1;
}
static int reply_valid(const uint8_t *p,unsigned n,uint8_t type,uint16_t tag) {
    return n>=7 && n<=FRAME && little(p,4)==n && p[4]==type
        && little(p+5,2)==tag;
}

#ifdef O10_FIXTURE_TEST
int o10_fixture_aux_valid(const uint8_t *a) { return aux_valid(a); }
int o10_fixture_reply_valid(const uint8_t *p,unsigned n,uint8_t type,uint16_t tag) {
    return reply_valid(p,n,type,tag);
}
#else

struct heartbeat {
    uint64_t magic,seq,reads,error,last_reply,last_bytes,stage,last_tag;
};
static volatile struct heartbeat *const hb=(void *)HEARTBEAT_IPA;
static volatile uint32_t *const uart=(void *)UART_IPA;
static uint8_t request[FRAME],response[FRAME];
static unsigned used;
static uint16_t tag;

static _Noreturn void fail(uint64_t error) {
    hb->error=error;
    hb->last_reply=response[4];
    hb->last_tag=tag;
    hb->stage=4;
    __asm__ volatile("dsb sy" ::: "memory");
    __asm__ volatile("brk #0x10");
    __builtin_unreachable();
}
static void emit(uint64_t value,unsigned count) {
    if(count>8 || used>FRAME-count) fail(LOCAL_OVERFLOW);
    for(unsigned i=0;i<count;i++) request[used++]=(uint8_t)(value>>(8*i));
}
static void string(const uint8_t *text,unsigned count) {
    if(count>FRAME-2) fail(LOCAL_OVERFLOW);
    emit(count,2);
    for(unsigned i=0;i<count;i++) emit(text[i],1);
}
static void begin(uint8_t type) {
    if(tag==65534) tag=0;
    tag++;
    used=7;
    request[4]=type;
    request[5]=(uint8_t)tag;
    request[6]=(uint8_t)(tag>>8);
}
static void send_byte(uint8_t value) {
    unsigned polls=0;
    while(uart[0x18/4]&(1u<<5)) if(++polls==POLLS) fail(TX_TIMEOUT);
    uart[0]=value;
}
static uint8_t receive_byte(void) {
    unsigned polls=0;
    while(uart[0x18/4]&(1u<<4)) if(++polls==POLLS) fail(RX_TIMEOUT);
    return (uint8_t)uart[0];
}
static unsigned exchange(uint8_t expected) {
    unsigned n=used;
    for(unsigned i=0;i<4;i++) request[i]=(uint8_t)(n>>(8*i));
    for(unsigned i=0;i<n;i++) send_byte(request[i]);
    for(unsigned i=0;i<7;i++) response[i]=receive_byte();
    unsigned reply=(unsigned)little(response,4);
    if(reply<7 || reply>FRAME || little(response+5,2)!=tag) fail(BAD_REPLY);
    for(unsigned i=7;i<reply;i++) response[i]=receive_byte();
    if(response[4]==107) fail(STORE_ERROR);
    if(!reply_valid(response,reply,expected,tag)) fail(BAD_REPLY);
    return reply;
}
static void handshake(const uint8_t *aux) {
    static const uint8_t version[6]={'9','P','2','0','0','0'};
    begin(100);emit(FRAME,4);string(version,6);
    if(exchange(101)!=19 || little(response+7,4)!=FRAME
       || little(response+11,2)!=6 || !equal(response+13,version,6)) fail(BAD_REPLY);
    begin(104);emit(1,4);emit(UINT32_MAX,4);emit(0,2);emit(0,2);
    if(exchange(105)!=20) fail(BAD_REPLY);
    begin(110);emit(1,4);emit(2,4);emit(1,2);
    string(aux+40,(unsigned)little(aux+32,4));
    if(exchange(111)!=22 || little(response+7,2)!=1) fail(BAD_REPLY);
    begin(112);emit(2,4);emit(0,1);
    if(exchange(113)!=24) fail(BAD_REPLY);
    hb->stage=2;
}
_Noreturn void fixture_main(uint64_t aux_ipa) {
    hb->magic=0;
    hb->seq=0;hb->reads=0;hb->error=0;hb->last_reply=0;
    hb->last_bytes=0;hb->stage=1;hb->last_tag=0;
    __asm__ volatile("dsb sy" ::: "memory");
    hb->magic=UINT64_C(0x314248334d30314f); /* O10M3HB1 */
    const uint8_t *aux=(const uint8_t *)aux_ipa;
    if(aux_ipa!=AUX_IPA || !aux_valid(aux)) fail(BAD_AUX);
    uart[0x38/4]=0;
    uart[0x30/4]=0x301;
    handshake(aux);
    unsigned count=(unsigned)little(aux+36,4);
    for(;;) {
        begin(116);emit(2,4);emit(0,8);emit(count+1,4);
        unsigned n=exchange(117);
        if(n!=11+count || little(response+7,4)!=count
           || !equal(response+11,aux+72,count)) fail(CORPUS_MISMATCH);
        if(hb->seq>UINT64_MAX-2 || hb->reads==UINT64_MAX) fail(COUNTER_EXHAUSTED);
        hb->seq++;
        __asm__ volatile("dmb ishst" ::: "memory");
        hb->reads++;hb->last_reply=117;hb->last_bytes=count;
        hb->last_tag=tag;hb->stage=3;
        __asm__ volatile("dmb ishst" ::: "memory");
        hb->seq++;
        /* Pure compute between requests; EL2's quantum remains in charge. */
        for(unsigned i=0;i<65536;i++) __asm__ volatile("yield");
    }
}
#endif
