"""Execute the original two boot profiles against saved hardware-LR banks.

This fixture models only the assembly register-bank hooks. The distributor,
redistributor, authority checks, pending state and LR scheduling are compiled
from the actual O-core implementation, also typechecked for AArch64.
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define G(n) _O_runtime__aarch64__unified_gic__##n
#define D UINT64_C(0x08000000)
#define R UINT64_C(0x080a0000)
#define P UINT64_C(0x080b0000)
#define PENDING (UINT64_C(1)<<62)
#define ACTIVE (UINT64_C(1)<<63)
#define GROUP1 (UINT64_C(1)<<60)
#define HW (UINT64_C(1)<<61)
extern uint64_t G(init)(void);
extern uint64_t G(configure)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t G(reset)(uint64_t);
extern uint64_t G(mmio_read)(uint64_t,uint64_t,uint64_t);
extern uint64_t G(mmio_write)(uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t G(set_level)(uint64_t,uint64_t,uint64_t);
extern uint64_t G(send_sgi)(uint64_t,uint64_t,uint64_t);
extern uint64_t G(poll)(uint64_t);
extern uint64_t G(healthy)(uint64_t);
extern uint64_t G(diagnostic)(uint64_t);
static uint64_t banks[2][16],vmcr[2],hcr[2],count=4,writes,forbidden_domain=2;
uint64_t uw_vgic_lr_count(void){return count;}
uint64_t uw_vgic_lr_read(uint64_t d,uint64_t i){assert(d<2&&i<count);return banks[d][i];}
void uw_vgic_lr_write(uint64_t d,uint64_t i,uint64_t v){assert(d<2&&i<count&&d!=forbidden_domain);banks[d][i]=v;writes++;}
uint64_t uw_vgic_vmcr_read(uint64_t d){assert(d<2);return vmcr[d];}
void uw_vgic_vmcr_write(uint64_t d,uint64_t v){assert(d<2&&d!=forbidden_domain);vmcr[d]=v;}
uint64_t uw_vgic_running_priority(uint64_t d){assert(d<2);return 255;}
uint64_t uw_vgic_hcr_read(uint64_t d){assert(d<2);return hcr[d];}
void uw_vgic_hcr_write(uint64_t d,uint64_t v){assert(d<2&&d!=forbidden_domain);hcr[d]=v;}
static uint64_t read_(unsigned d,uint64_t a,unsigned width){return G(mmio_read)(d,a,width);}
static void write_(unsigned d,uint64_t a,unsigned width,uint64_t v){assert(G(mmio_write)(d,a,width,v)==1);}
static void poll_(unsigned d){assert(G(poll)(d)==1);}
static unsigned entries(unsigned d){unsigned n=0;for(unsigned i=0;i<count;i++)if(banks[d][i]>>62)n++;return n;}
static int lr(unsigned d,unsigned irq){for(unsigned i=0;i<count;i++)if((banks[d][i]>>62)&&(uint32_t)banks[d][i]==irq)return (int)i;return -1;}
static uint64_t state(unsigned d,unsigned irq){int i=lr(d,irq);assert(i>=0);return banks[d][i]>>62;}
static void ack(unsigned d,unsigned irq){int i=lr(d,irq);assert(i>=0&&banks[d][i]&PENDING);banks[d][i]=(banks[d][i]&~PENDING)|ACTIVE;}
static void eoi(unsigned d,unsigned irq){int i=lr(d,irq);assert(i>=0&&banks[d][i]&ACTIVE);banks[d][i]&=~ACTIVE;}
static uint64_t base(unsigned irq){return irq<32?P:D;}
static void bit(unsigned d,unsigned irq,unsigned reg){write_(d,base(irq)+reg+(irq/32)*4,4,UINT64_C(1)<<(irq%32));}
static void group(unsigned d,unsigned irq){uint64_t a=base(irq)+0x80+(irq/32)*4;write_(d,a,4,read_(d,a,4)|(UINT64_C(1)<<(irq%32)));}
static void enable(unsigned d,unsigned irq){group(d,irq);bit(d,irq,0x100);}
static void priority(unsigned d,unsigned irq,unsigned v){write_(d,base(irq)+0x400+irq,1,v);}
static void ready(unsigned d){write_(d,R+0x14,4,0);write_(d,D,4,0x13);}
static void reset(void){assert(G(init)()==1);assert(!G(healthy)(0)&&!G(healthy)(1));assert(G(configure)(0,1,1ull<<50,1ull<<48,1ull<<49,(1ull<<33)|(1ull<<51)));assert(G(configure)(1,1,1ull<<50,1ull<<33,0,0));assert(G(healthy)(0)&&G(healthy)(1));assert(hcr[0]==1&&hcr[1]==1&&vmcr[0]==0xff000002&&vmcr[1]==0xff000002);}

static void driver_registers(void){
    reset();
    assert(read_(0,D+4,4)==(1|(5u<<19))&&read_(1,D+4,4)==read_(0,D+4,4));
    assert(read_(0,D+0xffe8,4)==0x30&&read_(0,R+0xffe8,1)==0x30);
    assert(read_(0,R+8,8)==16&&read_(0,R+8,4)==16&&read_(0,R+12,4)==0);
    assert(read_(0,R+0x14,4)==6);
    // Original Linux irq-gic-v3.c/gic-common.c initialization transactions.
    for(unsigned d=0;d<2;d++){
        write_(d,D,4,0);
        write_(d,D+0x84,4,UINT32_MAX);
        write_(d,D+0xc08,4,0);write_(d,D+0xc0c,4,0);
        for(unsigned i=32;i<64;i+=4)write_(d,D+0x400+i,4,0xa0a0a0a0);
        write_(d,D+0x384,4,UINT32_MAX);write_(d,D+0x184,4,UINT32_MAX);
        for(unsigned i=32;i<64;i++)write_(d,D+0x6000+8*i,8,0);
        write_(d,P+0x80,4,UINT32_MAX);write_(d,P+0x380,4,UINT32_MAX);write_(d,P+0x180,4,UINT32_MAX);
        for(unsigned i=0;i<32;i+=4)write_(d,P+0x400+i,4,0xa0a0a0a0);
        ready(d);
        assert(read_(d,D,4)==0x53&&read_(d,R+0x14,4)==0);
        assert(read_(d,P+0x80,4)==0x4800ffff); // SGIs and timer PPIs27/30 only.
        assert(read_(d,D+0x84,4)==(d?0x40002:0xf0002));
    }
    // Original9front3502661 intrinit also clears legacy ITARGETSR with ARE=1.
    // These registers are RAZ/WI; even all-one target bytes grant no route.
    for(unsigned i=0;i<64;i+=4){write_(1,D+0x400+i,4,0);write_(1,D+0x800+i,4,0);}
    write_(1,D+0x800,8,UINT64_MAX);assert(read_(1,D+0x800,8)==0);
    assert(read_(1,D+0x6000+50*8,8)==0);
    // Byte/half/word/dword register lanes, priority implementation discovery.
    write_(0,P+0x400,8,UINT64_MAX);assert(read_(0,P+0x400,8)==UINT64_C(0xf8f8f8f8f8f8f8f8));
    write_(0,D+0x400+48,2,0x1828);assert(read_(0,D+0x430,2)==0x1828);
    write_(0,D+0x430,1,0xff);assert(read_(0,D+0x430,1)==0xf8&&read_(0,D+0x431,1)==0x18);
    write_(0,D+0x6000+48*8+3,1,0x80);assert(read_(0,D+0x6000+48*8,8)==0x80000000);
    write_(0,D+0x6000+48*8,4,0);assert(read_(0,D+0x6000+48*8,8)==0);
    assert(read_(1,D+0x430,2)==0&&read_(1,D+0x6000+48*8,8)==0);
    // Bulk unassigned bank bits can never create an injectable authority.
    write_(0,D+0x104,4,UINT32_MAX);assert(read_(0,D+0x104,4)==0xf0002);
    write_(1,D+0x204,4,UINT32_MAX);poll_(1);assert(entries(1)==0);
    assert(!G(set_level)(0,26,1)&&!G(set_level)(1,48,1)&&!G(set_level)(1,49,1));
    assert(!G(set_level)(2,33,1)&&!G(set_level)(0,33,2)&&!G(set_level)(0,1,1));
    assert(G(healthy)(0)&&G(healthy)(1));
    puts("original driver register sequence and byte/word/dword isolation: PASS");
}

static void original_plan9_driver(void){
    reset();
    // Original9front leaves WAKER to firmware. The trusted monitor provisions
    // the already-awake boot PE; this is not an extra guest driver operation.
    write_(1,R+0x14,4,0);
    write_(1,D,4,0);assert(!(read_(1,D,4)&(1u<<31)));
    unsigned n=32*((read_(1,D+4,4)&31)+1);assert(n==64);
    for(unsigned i=32;i<n;i+=32){
        write_(1,D+0x80+i/8,4,UINT32_MAX);
        write_(1,D+0x100+i/8,4,UINT32_MAX);
        write_(1,D+0x180+i/8,4,UINT32_MAX);
        write_(1,D+0x380+i/8,4,UINT32_MAX);
    }
    for(unsigned i=0;i<n;i+=4){write_(1,D+0x400+i,4,0);write_(1,D+0x800+i,4,0);}
    for(unsigned i=32;i<n;i+=16)write_(1,D+0xc00+i/4,4,0);
    write_(1,D,4,0x13);assert(!(read_(1,D,4)&(1u<<31)));
    assert((read_(1,R+8,8)>>32)==0&&(read_(1,R+8,8)&16));
    write_(1,P+0x80,4,UINT32_MAX);write_(1,P+0x100,4,UINT32_MAX);
    write_(1,P+0x180,4,UINT32_MAX);write_(1,P+0x380,4,UINT32_MAX);
    for(unsigned i=0;i<32;i+=4)write_(1,P+0x400+i,4,0);
    assert(!(read_(1,R,4)&8));
    // Original intrenable reads/ORs priority and legacy target, then enables.
    for(unsigned i=0;i<2;i++){
        unsigned irq=i?50:27;uint64_t b=base(irq);
        write_(1,b+0x400+irq,1,read_(1,b+0x400+irq,1)|0x80);
        if(irq>=32)write_(1,D+0x800+irq,1,read_(1,D+0x800+irq,1)|1);
        bit(1,irq,0x100);assert(G(set_level)(1,irq,1));
    }
    poll_(1);assert(state(1,27)==1&&state(1,50)==1&&entries(0)==0);
    puts("original9front initialization and firmware-wake IRQ delivery: PASS");
}

static void level_lifecycle(void){
    reset();ready(0);ready(1);enable(0,48);enable(1,50);priority(0,48,0x90);
    vmcr[0]=0x780002;hcr[0]=1;
    assert(G(set_level)(0,48,1));poll_(0);assert(state(0,48)==1&&entries(0)==1&&entries(1)==0);
    for(unsigned i=0;i<5;i++){poll_(0);assert(entries(0)==1&&state(0,48)==1);}
    assert(vmcr[0]==0x780002&&hcr[0]==1); // Guest CPU-interface state survives poll.
    ack(0,48);poll_(0);assert(state(0,48)==2); // Held level cannot create P+A duplicates.
    assert(read_(0,D+0x304,4)==0x10000);poll_(0);assert(state(0,48)==2);
    // Changes while active do not destroy its saved running-priority state.
    bit(0,48,0x180);priority(0,48,0x20);poll_(0);
    assert(state(0,48)==2&&((banks[0][lr(0,48)]>>48)&255)==0x90);
    eoi(0,48);poll_(0);assert(entries(0)==0);
    bit(0,48,0x100);poll_(0);assert(state(0,48)==1&&((banks[0][lr(0,48)]>>48)&255)==0x20);
    ack(0,48);assert(G(set_level)(0,48,0));poll_(0);assert(state(0,48)==2);
    eoi(0,48);poll_(0);assert(entries(0)==0);
    // Both kernels have private copies of identically numbered IRQ50.
    assert(G(set_level)(1,50,1));poll_(1);assert(state(1,50)==1&&entries(0)==0);
    write_(1,R+0x14,4,2);poll_(1);assert(entries(1)==0);
    write_(1,R+0x14,4,0);poll_(1);assert(state(1,50)==1);
    write_(1,D,4,0);poll_(1);assert(entries(1)==0);
    write_(1,D,4,1);poll_(1);assert(entries(1)==0); // DS=1 Group0 alone cannot deliver Group1.
    ready(1);poll_(1);assert(state(1,50)==1);
    reset();poll_(0);poll_(1);assert(entries(0)==0&&entries(1)==0);
    puts("saved LR ACK/EOI, level reassertion, active priority and resets: PASS");
}

static void linux_private_coordinator_irq(void){
    reset();ready(0);ready(1);enable(0,51);enable(1,51);
    assert(G(set_level)(0,51,1)&&!G(set_level)(1,51,1));
    assert(!(read_(1,D+0x104,4)&(1u<<19))); // Plan9 writes grant no new IRQ.
    poll_(0);poll_(1);assert(entries(0)==1&&state(0,51)==1&&entries(1)==0);
    ack(0,51);poll_(0);assert(state(0,51)==2);
    eoi(0,51);poll_(0);assert(state(0,51)==1); // Held private level reasserts.
    ack(0,51);assert(G(set_level)(0,51,0));poll_(0);eoi(0,51);poll_(0);
    assert(entries(0)==0&&entries(1)==0&&G(healthy)(0)&&G(healthy)(1));
    puts("Linux-private coordinator IRQ51 delivery, EOI and domain isolation: PASS");
}

static void edges_and_sgi(void){
    reset();ready(0);ready(1);enable(0,33);enable(0,3);enable(1,3);
    // Only bit1 of each ICFGR pair is implemented; configure UART edge.
    write_(0,D+0xc08,4,8);assert(read_(0,D+0xc08,4)==8);
    assert(G(set_level)(0,33,1));poll_(0);assert(state(0,33)==1);
    ack(0,33);assert(G(set_level)(0,33,0)&&G(set_level)(0,33,1));poll_(0);assert(state(0,33)==3);
    // Hardware EOI of Active+Pending leaves Pending, then next ACK consumes it.
    eoi(0,33);poll_(0);assert(state(0,33)==1);ack(0,33);poll_(0);eoi(0,33);poll_(0);assert(entries(0)==0);
    assert(G(send_sgi)(0,(UINT64_C(3)<<24)|1,1));poll_(0);assert(state(0,3)==1&&entries(1)==0);
    ack(0,3);poll_(0);eoi(0,3);poll_(0);assert(entries(0)==0);
    assert(G(send_sgi)(1,(UINT64_C(3)<<24)|1,1));poll_(1);assert(state(1,3)==1&&entries(0)==0);
    ack(1,3);poll_(1);eoi(1,3);poll_(1);
    assert(G(send_sgi)(0,(UINT64_C(3)<<24)|(UINT64_C(1)<<40),1));
    assert(G(send_sgi)(0,(UINT64_C(3)<<24)|(UINT64_C(1)<<16)|1,1));
    assert(G(send_sgi)(0,(UINT64_C(3)<<24)|2,1));poll_(0);assert(entries(0)==0);
    assert(!G(send_sgi)(0,(UINT64_C(3)<<24)|1,0)&&!G(send_sgi)(0,(UINT64_C(1)<<44)|1,1));
    // Software pending survives no LR credit, but can be explicitly cleared.
    bit(0,33,0x200);bit(0,33,0x280);poll_(0);assert(entries(0)==0);
    bit(0,33,0x200);poll_(0);assert(state(0,33)==1);
    puts("edge events, software pending and strictly private group1 SGIs: PASS");
}

static void capacity_and_priority(void){
    reset();ready(0);for(unsigned i=0;i<6;i++){enable(0,i);priority(0,i,0x80-i*8);bit(0,i,0x200);}
    poll_(0);assert(entries(0)==4&&lr(0,5)>=0&&lr(0,4)>=0&&lr(0,3)>=0&&lr(0,2)>=0&&lr(0,1)<0);
    // Outstanding active IRQ cannot be evicted by more urgent pending IRQ.
    ack(0,2);poll_(0);priority(0,0,0);poll_(0);assert(state(0,2)==2&&lr(0,0)>=0);
    for(unsigned round=0;round<8;round++){
        for(unsigned i=0;i<count;i++)if(banks[0][i]>>62)banks[0][i]=(banks[0][i]&~PENDING)|ACTIVE;
        poll_(0);for(unsigned i=0;i<count;i++)banks[0][i]&=~ACTIVE;
        poll_(0);
    }
    assert(entries(0)==0&&read_(0,P+0x200,4)==0);poll_(0);
    puts("finite LR credit, priority selection and deferred event preservation: PASS");
}

static unsigned snapshot_registers(unsigned d,uint64_t *out){
    unsigned n=0;out[n++]=read_(d,D,4);out[n++]=read_(d,R+0x14,4);
    const unsigned offsets[]={0x80,0x100,0x200,0x300};
    for(unsigned i=0;i<4;i++){out[n++]=read_(d,P+offsets[i],4);out[n++]=read_(d,D+offsets[i]+4,4);}
    for(unsigned i=0;i<64;i+=8)out[n++]=read_(d,base(i)+0x400+i,8);
    out[n++]=read_(d,P+0xc00,4);out[n++]=read_(d,P+0xc04,4);
    out[n++]=read_(d,D+0xc08,4);out[n++]=read_(d,D+0xc0c,4);
    out[n++]=read_(d,D+0x6000+50*8,8);out[n++]=G(diagnostic)(d);
    poll_(d);return n;
}
static void isolated_trusted_reset(void){
    for(unsigned target=0;target<2;target++){
        reset();unsigned other=1-target;ready(target);ready(other);
        // One active level, one pending edge, an SGI, and a disabled software
        // pending IRQ exercise four independent kinds of retained state.
        for(unsigned d=0;d<2;d++){
            enable(d,50);enable(d,33);enable(d,3);group(d,2);
            priority(d,50,0x98);priority(d,33,0x40);priority(d,3,0xa8);
            write_(d,D+0xc08,4,8);write_(d,D+0x6000+50*8,8,0x80000000);
            assert(G(set_level)(d,50,1));poll_(d);ack(d,50);poll_(d);
            assert(G(set_level)(d,33,1)&&G(send_sgi)(d,(UINT64_C(3)<<24)|1,1));
            bit(d,2,0x200);poll_(d);assert(state(d,50)==2&&state(d,33)==1&&state(d,3)==1);
        }
        assert(!G(mmio_write)(other,R+0x70,8,1)); // Preserve its own diagnostic too.
        uint64_t before[64]={0},after[64]={0};unsigned n=snapshot_registers(other,before);
        vmcr[other]=0x7f100202;hcr[other]=9;
        uint64_t saved[16],saved_vmcr=vmcr[other],saved_hcr=hcr[other];memcpy(saved,banks[other],sizeof(saved));
        // Trusted reset must also recover this target's fail-stopped GIC.
        banks[target][lr(target,33)]|=HW;assert(!G(poll)(target)&&!G(healthy)(target)&&G(diagnostic)(target)==100);
        uint64_t both[2][16];memcpy(both,banks,sizeof(both));uint64_t old_writes=writes;
        assert(!G(reset)(2)&&!G(reset)(UINT64_MAX));
        assert(!memcmp(both,banks,sizeof(both))&&writes==old_writes&&!G(healthy)(target));
        assert(vmcr[other]==saved_vmcr&&hcr[other]==saved_hcr);
        // Assembly is responsible for first clearing ONLY the target's entire
        // architectural context, including APRs. This fixture models the saved
        // LR/VMCR/HCR hooks only and does not claim to test assembly APR reset.
        forbidden_domain=other;assert(G(reset)(target)==1);forbidden_domain=2;
        assert(writes==old_writes+count&&!memcmp(saved,banks[other],sizeof(saved)));
        assert(vmcr[other]==saved_vmcr&&hcr[other]==saved_hcr&&G(healthy)(other));
        assert(G(healthy)(target)&&G(diagnostic)(target)==0&&entries(target)==0);
        assert(vmcr[target]==0xff000002&&hcr[target]==1);
        assert(read_(target,D,4)==0x50&&read_(target,R+0x14,4)==6);
        for(unsigned i=0;i<4;i++){
            unsigned reg=(unsigned[]){0x80,0x100,0x200,0x300}[i];
            assert(read_(target,P+reg,4)==0&&read_(target,D+reg+4,4)==0);
        }
        for(unsigned i=0;i<64;i+=8)assert(read_(target,base(i)+0x400+i,8)==0);
        assert(read_(target,P+0xc00,4)==0xaaaaaaaa&&read_(target,P+0xc04,4)==0);
        assert(read_(target,D+0xc08,4)==0&&read_(target,D+0xc0c,4)==0&&read_(target,D+0x6000+50*8,8)==0);
        assert(snapshot_registers(other,after)==n&&!memcmp(before,after,n*sizeof(uint64_t)));
        assert(!memcmp(saved,banks[other],sizeof(saved))&&vmcr[other]==saved_vmcr&&hcr[other]==saved_hcr);
        // Re-enabling old sources cannot resurrect withdrawn level/SW state.
        ready(target);enable(target,50);enable(target,33);enable(target,3);enable(target,2);poll_(target);assert(entries(target)==0);
        // The other active level still reasserts after EOI; its deferred SW
        // event, SGI and edge event remain available without duplication.
        eoi(other,50);poll_(other);assert(state(other,50)==1&&state(other,33)==1&&state(other,3)==1);
        bit(other,2,0x100);poll_(other);assert(state(other,2)==1);
        assert(G(set_level)(target,33,1));poll_(target);assert(state(target,33)==1);
    }
    puts("trusted single-domain GIC reset preserves other active/pending/config/banks: PASS");
}

static void denied_and_corruption(void){
    reset();ready(0);enable(0,48);assert(G(set_level)(0,48,1));poll_(0);
    uint64_t before[2][16];memcpy(before,banks,sizeof(banks));uint64_t old_writes=writes;
    uint64_t addresses[]={R+0x70,R+0x78,R+0x80,R+0x88,D+0x40,D+0x8000,D+0x6000+48*8};
    uint64_t values[]={0x60000000,0x60000000,0x60000000,0x60000000,1,1,1};
    for(unsigned i=0;i<sizeof(addresses)/sizeof(*addresses);i++)assert(!G(mmio_write)(0,addresses[i],8,values[i]));
    assert(!G(mmio_write)(0,R,4,1)); // EnableLPIs never accepted.
    assert(!G(mmio_write)(0,D+0xc08,4,1)); // Reserved ICFGR pair bit.
    assert(!G(mmio_write)(0,D,4,0x80000000)&&!G(mmio_write)(0,D+0xd00,4,1));
    assert(!G(mmio_write)(0,D+1,4,0)&&!G(mmio_write)(0,UINT64_MAX-3,4,0));
    assert(read_(0,R+0x70,8)==UINT64_MAX&&read_(0,D+1,4)==UINT64_MAX&&read_(2,D,4)==UINT64_MAX);
    assert(!memcmp(before,banks,sizeof(banks))&&writes==old_writes&&G(healthy)(0));
    // Forged/duplicate/HW LRs must be rejected before ANY slot is changed.
    for(unsigned kind=0;kind<3;kind++){
        reset();ready(0);enable(0,48);enable(0,49);assert(G(set_level)(0,48,1)&&G(set_level)(0,49,1));poll_(0);
        int i=lr(0,48),j=lr(0,49);assert(i>=0&&j>=0);
        if(kind==0)banks[0][i]=(banks[0][i]&~UINT64_C(0xffffffff))|26;
        if(kind==1)banks[0][i]|=HW;
        if(kind==2)banks[0][j]=(banks[0][j]&~UINT64_C(0xffffffff))|48;
        memcpy(before,banks,sizeof(banks));old_writes=writes;
        assert(!G(poll)(0)&&!G(healthy)(0)&&G(diagnostic)(0)>=100);
        assert(!memcmp(before,banks,sizeof(banks))&&writes==old_writes&&G(healthy)(1));
        poll_(1);assert(entries(1)==0);
    }
    count=0;assert(!G(init)()&&!G(healthy)(0));count=17;assert(!G(init)());count=16;reset();
    count=4;reset();
    puts("LPI/routing denial and preflighted corrupt saved-bank fail-stop: PASS");
}
int main(void){
    driver_registers();original_plan9_driver();level_lifecycle();linux_private_coordinator_irq();edges_and_sgi();capacity_and_priority();isolated_trusted_reset();denied_and_corruption();
    puts("unified GIC production tests: PASS");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "production fixture requires Linux x86_64")
class UnifiedGicTests(unittest.TestCase):
    def test_actual_distributor_redistributor_and_saved_lr_banks(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="unified-native-gic-") as directory:
            out = Path(directory)
            (out / "harness.c").write_text(HARNESS)
            source = str(ROOT / "ocore/runtime/aarch64/unified_gic.oc")
            commands = [
                [str(compiler), source, "--target", "aarch64-unknown-none", "--emit", "mir", "-o", str(out / "arm.mir")],
                [str(compiler), source, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "gic.o")],
                [clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "gic.o"), "-o", str(out / "test")],
                [str(out / "test")],
            ]
            for command in commands:
                result = subprocess.run(command, text=True, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("unified GIC production tests: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
