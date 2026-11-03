"""Execute the production ELF loader's trusted-native startup configuration.

The immutable retained-object fixture replaces only image delivery. The real
O-core ELF validation, segment/stack materialization and plan lifetime code is
executed natively. A freestanding fixture ELF checks its actual entry stack
after a host child transfers control to it; this is not upstream-app or EL0
kernel admission. No VM or installed launcher is modified.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROVIDER = r'''
module runtime::image_vfs;
extern "C" fn fixture_object_length(object: u64) -> usize;
extern "C" fn fixture_read(object: u64, offset: usize, result: *mut u8) -> u64;
extern "C" fn fixture_release(object: u64) -> u64;
pub unsafe fn object_length(object: u64) -> usize { return fixture_object_length(object); }
pub unsafe fn read_retained_byte(object: u64, offset: usize, result: *mut u8) -> u64 { return fixture_read(object, offset, result); }
pub unsafe fn release_object(object: u64) -> u64 { return fixture_release(object); }
'''

ENTRY = r'''
.text
.global _start
_start:
    mov %rsp, %rdi
    call probe
    mov %eax, %edi
    mov $60, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
'''

PROBE = r'''
typedef unsigned long U;
static int equal(const char *a,const char *b) {
    while(*a && *a==*b) { a++; b++; } return *a==*b;
}
int probe(U *sp) {
    if(((U)sp&15) || sp[0]!=3) return 11;
    if(!equal((char*)sp[1],"probe") || !equal((char*)sp[2],"payload") || !equal((char*)sp[3],"") || sp[4]) return 12;
    if(!equal((char*)sp[5],"LANG=C") || !equal((char*)sp[6],"PATH=/bin") || sp[7]) return 13;
    U seen=0;
    for(U *p=sp+8;p[0];p+=2) {
        switch(p[0]) {
        case 3: if(*(unsigned*)p[1]!=1) return 21; seen|=1; break;
        case 4: if(p[1]!=56) return 22; seen|=2; break;
        case 5: if(!p[1] || p[1]>16) return 23; seen|=4; break;
        case 6: if(p[1]!=4096) return 24; seen|=8; break;
        case 9: if(p[1]!=0x02001000) return 25; seen|=16; break;
        case 11: if(p[1]!=1000) return 26; seen|=32; break;
        case 12: if(p[1]!=1001) return 27; seen|=64; break;
        case 13: if(p[1]!=1002) return 28; seen|=128; break;
        case 14: if(p[1]!=1003) return 29; seen|=256; break;
        case 23: if(p[1]!=1) return 30; seen|=512; break;
        case 25: for(unsigned i=0;i<16;i++) if(((unsigned char*)p[1])[i]!=(unsigned char)(0x80+i)) return 31; seen|=1024; break;
        case 31: if(!equal((char*)p[1],"/usr/bin/probe")) return 32; seen|=2048; break;
        default: return 33;
        }
    }
    return seen==4095?0:34;
}
'''

HARNESS = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <elf.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#define L(name) _O_runtime__elf_loader__##name
extern uint64_t L(init)(void),L(validate)(uint64_t),L(configure_startup)(uint64_t,const uint64_t*,size_t);
extern uint64_t L(materialize_stack_range)(uint64_t,size_t,uint8_t*,size_t);
extern uint64_t L(materialize_segment_range)(uint64_t,size_t,size_t,uint8_t*,size_t);
extern uint64_t L(commit_for_process_start)(uint64_t,uintptr_t*,uintptr_t*),L(abort)(uint64_t),L(release_plan)(uint64_t);
extern uint64_t L(is_validated)(uint64_t),L(invariants_hold)(void),L(last_error)(void);
extern uintptr_t L(stack_pointer)(uint64_t),L(entry)(uint64_t),L(stack_base)(uint64_t);
extern size_t L(segment_count)(uint64_t),L(segment_vaddr)(uint64_t,size_t),L(segment_memsz)(uint64_t,size_t);
extern size_t L(segment_page_start)(uint64_t,size_t),L(segment_page_end)(uint64_t,size_t);
extern uint64_t L(segment_flags)(uint64_t,size_t);
static unsigned char *image;
static size_t image_size;
static unsigned refs;
size_t fixture_object_length(uint64_t object) { return object==1 && refs ? image_size:0; }
uint64_t fixture_read(uint64_t object,size_t offset,unsigned char *result) {
    if(object!=1 || !refs || offset>=image_size || !result) return 0;
    *result=image[offset]; return 1;
}
uint64_t fixture_release(uint64_t object) { if(object!=1 || !refs) return 0; refs--; return 1; }
static uint64_t plan(void) { refs++; uint64_t p=L(validate)(1); assert(p && L(invariants_hold)()); return p; }
static unsigned char stack[16384],prior[16384],chunks[16384];
static char args[]="probe\0payload\0"; // C adds the third, empty argument.
static char environment[]="LANG=C\0PATH=/bin";
static char execfn[]="/usr/bin/probe";
static unsigned char random_bytes[16]; // Explicit deterministic fixture input, not entropy provision.
static uint64_t config[15];
static void descriptor(void) {
    uint64_t d[]={ (uintptr_t)args,sizeof args,3,(uintptr_t)environment,sizeof environment,2,
        (uintptr_t)execfn,sizeof execfn,(uintptr_t)random_bytes,16,1000,1001,1002,1003,1};
    memcpy(config,d,sizeof d);
}
static uint64_t word(const unsigned char *p) { uint64_t v;memcpy(&v,p,8);return v; }
static void capture(uint64_t p,unsigned char *to) { assert(L(materialize_stack_range)(p,0,to,16384)==1); }
static size_t configured_offset(uint64_t p) { return L(stack_pointer)(p)-L(stack_base)(p); }
static const char *string(uint64_t pointer) {
    assert(pointer>=0x013fc000 && pointer<0x01400000);return (const char*)stack+(pointer-0x013fc000);
}
static uint64_t aux(uint64_t p,unsigned kind) {
    size_t at=configured_offset(p)+8;
    while(word(stack+at)) at+=8;at+=8;
    while(word(stack+at)) at+=8;at+=8;
    for(;word(stack+at);at+=16) if(word(stack+at)==kind) return word(stack+at+8);
    return 0;
}
static void unchanged(uint64_t p,const uint64_t *d,size_t words) {
    uintptr_t sp=L(stack_pointer)(p);capture(p,prior);
    assert(L(configure_startup)(p,d,words)==0 && L(stack_pointer)(p)==sp && L(invariants_hold)());
    capture(p,stack);assert(!memcmp(prior,stack,sizeof stack));
}
static void defaults(uint64_t p) {
    capture(p,stack);assert(L(stack_pointer)(p)==0x01400000-80);
    for(unsigned i=0;i<16384-80;i++)assert(stack[i]==0);
    uint64_t expected[]={0,0,0,6,4096,9,L(entry)(p),0,0,0};
    assert(!memcmp(stack+16384-80,expected,sizeof expected));
}
static void configuration(void) {
    uint64_t p=plan();defaults(p);descriptor();assert(L(configure_startup)(p,config,15)==1);capture(p,stack);
    size_t offset=configured_offset(p);assert(!(L(stack_pointer)(p)&15));assert(word(stack+offset)==3);
    assert(!strcmp(string(word(stack+offset+8)),"probe") && !strcmp(string(word(stack+offset+16)),"payload"));
    assert(!strcmp(string(word(stack+offset+24)),"") && !word(stack+offset+32));
    assert(!strcmp(string(word(stack+offset+40)),"LANG=C") && !strcmp(string(word(stack+offset+48)),"PATH=/bin"));
    assert(aux(p,6)==4096 && aux(p,9)==L(entry)(p) && aux(p,4)==56 && aux(p,5)>0);
    assert(aux(p,11)==1000 && aux(p,12)==1001 && aux(p,13)==1002 && aux(p,14)==1003 && aux(p,23)==1);
    assert(!strcmp(string(aux(p,31)),execfn) && !memcmp(string(aux(p,25)),random_bytes,16));
    const Elf64_Ehdr *eh=(const Elf64_Ehdr*)image;
    assert(aux(p,3)==0x02000000+eh->e_phoff && aux(p,5)==eh->e_phnum);
    for(unsigned i=0;i<offset;i++)assert(!stack[i]);
    // Caller storage is not retained, and partial materialization is exact.
    char saved=args[0];args[0]='X';capture(p,prior);args[0]=saved;assert(!memcmp(prior,stack,sizeof stack));
    memset(chunks,0xcc,sizeof chunks);
    for(size_t at=0;at<sizeof chunks;) { size_t n=37;if(n>sizeof chunks-at)n=sizeof chunks-at;assert(L(materialize_stack_range)(p,at,chunks+at,n));at+=n; }
    assert(!memcmp(chunks,stack,sizeof chunks));
    assert(!L(materialize_stack_range)(p,16384,chunks,1) && !L(materialize_stack_range)(p,0,(void*)(UINTPTR_MAX-3),4));
    // Failed configuration never replaces the valid stack.
    uint64_t bad[15];memcpy(bad,config,sizeof bad);
    unchanged(p,config,14);unchanged(p,NULL,15);unchanged(p,(uint64_t*)((uintptr_t)config+1),15);
    for(unsigned field=0;field<15;field++) {
        memcpy(bad,config,sizeof bad);
        if(field==0 || field==3 || field==6 || field==8)bad[field]=0;
        else if(field==1 || field==4 || field==7)bad[field]=UINT64_MAX;
        else if(field==2 || field==5)bad[field]++;
        else if(field==9)bad[field]=15;
        else if(field<14)bad[field]=UINT64_C(1)<<32;
        else bad[field]=2;
        unchanged(p,bad,15);
    }
    char malformed[]={'a',0,'b'};memcpy(bad,config,sizeof bad);bad[0]=(uintptr_t)malformed;bad[1]=sizeof malformed;bad[2]=1;unchanged(p,bad,15);
    char tail[]={'a',0,0};bad[0]=(uintptr_t)tail;bad[1]=sizeof tail;bad[2]=1;unchanged(p,bad,15);
    memcpy(bad,config,sizeof bad);bad[0]=UINTPTR_MAX-3;bad[1]=4;unchanged(p,bad,15);
    unsigned char huge[16384];memset(huge,'a',sizeof huge);huge[sizeof huge-1]=0;
    memcpy(bad,config,sizeof bad);bad[0]=(uintptr_t)huge;bad[1]=sizeof huge;bad[2]=1;unchanged(p,bad,15);
    unsigned char many[2000]={0};memcpy(bad,config,sizeof bad);bad[0]=(uintptr_t)many;bad[1]=sizeof many;bad[2]=sizeof many;unchanged(p,bad,15);
    assert(L(abort)(p)==1 && !refs && !L(is_validated)(p) && !L(stack_pointer)(p));
    assert(!L(configure_startup)(p,config,15) && !L(materialize_stack_range)(p,0,stack,16384));
    uint64_t next=plan();assert(next!=p);defaults(next);assert(L(abort)(next)==1);
    puts("startup vectors/auxv/copies/alignment/atomic rejection/stale plan/default compatibility: PASS");
}
static void unmapped_headers(void) {
    Elf64_Ehdr *eh=(Elf64_Ehdr*)image;Elf64_Phdr *ph=(Elf64_Phdr*)(image+eh->e_phoff);
    Elf64_Phdr old=ph[0];assert(ph[0].p_type==PT_LOAD && ph[0].p_offset==0);
    // Removing the file header mapping must omit all PHDR aux entries.
    ph[0].p_type=PT_NOTE;uint64_t p=plan();descriptor();assert(L(configure_startup)(p,config,15));capture(p,stack);
    assert(!aux(p,3) && !aux(p,4) && !aux(p,5) && aux(p,6)==4096);assert(L(abort)(p)==1);ph[0]=old;
    puts("PHDR aux entries require validated mapped table, not kernel pointers: PASS");
}
static void rejected(uint64_t error) {
    unsigned before=refs;refs++;assert(!L(validate)(1) && refs==before && L(last_error)()==error && L(invariants_hold)());
}
static void legacy_rejections(void) {
    Elf64_Ehdr *eh=(Elf64_Ehdr*)image;Elf64_Phdr *ph=(Elf64_Phdr*)(image+eh->e_phoff);
    unsigned char magic=image[0];image[0]=0;rejected(1);image[0]=magic;
    unsigned short type=eh->e_type;eh->e_type=ET_DYN;rejected(1);eh->e_type=type;
    unsigned short machine=eh->e_machine;eh->e_machine=EM_AARCH64;rejected(1);eh->e_machine=machine;
    assert(ph[0].p_type==PT_LOAD && ph[1].p_type==PT_LOAD);
    unsigned flags=ph[1].p_flags;ph[1].p_flags=PF_R|PF_W|PF_X;rejected(3);ph[1].p_flags=flags;
    uintptr_t address=ph[1].p_vaddr;ph[1].p_vaddr=ph[0].p_vaddr;rejected(2);ph[1].p_vaddr=address;
    address=ph[0].p_vaddr;ph[0].p_vaddr=0x01000000;rejected(4);ph[0].p_vaddr=address;
    puts("legacy ELF malformed/dynamic/wrongISA/WX/overlap/range rejections: PASS");
}
static void varied_vectors(void) {
    unsigned char arguments[2048],variables[2048];
    uint64_t p=plan();
    for(unsigned count=0;count<65;count++) {
        size_t ab=0,eb=0;unsigned env_count=(count*7)%32;
        for(unsigned i=0;i<count;i++) { unsigned n=(i*11+count)%17;for(unsigned j=0;j<n;j++)arguments[ab++]=(unsigned char)('a'+i%26);arguments[ab++]=0; }
        for(unsigned i=0;i<env_count;i++) { unsigned n=(i*13+count)%19;for(unsigned j=0;j<n;j++)variables[eb++]=(unsigned char)('A'+i%26);variables[eb++]=0; }
        descriptor();config[0]=(uintptr_t)arguments;config[1]=ab;config[2]=count;
        config[3]=(uintptr_t)variables;config[4]=eb;config[5]=env_count;
        assert(L(configure_startup)(p,config,15) && L(invariants_hold)());capture(p,stack);
        size_t at=configured_offset(p);assert(!(at&15) && word(stack+at)==count);at+=8;
        size_t pos=0;
        for(unsigned i=0;i<count;i++) {const char *s=string(word(stack+at));assert(!strcmp(s,(char*)arguments+pos));pos+=strlen(s)+1;at+=8;}
        assert(pos==ab && !word(stack+at));at+=8;pos=0;
        for(unsigned i=0;i<env_count;i++) {const char *s=string(word(stack+at));assert(!strcmp(s,(char*)variables+pos));pos+=strlen(s)+1;at+=8;}
        assert(pos==eb && !word(stack+at) && aux(p,6)==4096 && !memcmp(string(aux(p,25)),random_bytes,16));
        for(size_t i=0;i<configured_offset(p);i++)assert(stack[i]==0);
    }
    assert(L(abort)(p));puts("65 varying argv/env layouts including empty vectors and arguments: PASS");
}
static void execute_entry(void) {
    uint64_t p=plan();descriptor();assert(L(configure_startup)(p,config,15));
    pid_t child=fork();assert(child>=0);
    if(!child) {
        for(size_t i=0;i<L(segment_count)(p);i++) {
            uintptr_t begin=L(segment_page_start)(p,i),end=L(segment_page_end)(p,i);
            assert(mmap((void*)begin,end-begin,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)begin);
            assert(L(materialize_segment_range)(p,i,0,(void*)L(segment_vaddr)(p,i),L(segment_memsz)(p,i)));
            unsigned flags=L(segment_flags)(p,i);int prot=PROT_READ;if(flags&2)prot|=PROT_WRITE;if(flags&1)prot|=PROT_EXEC;
            assert(!mprotect((void*)begin,end-begin,prot));
        }
        assert(mmap((void*)0x013fc000,16384,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0x013fc000);
        assert(L(materialize_stack_range)(p,0,(void*)0x013fc000,16384));
        uintptr_t entry=0,sp=0;assert(L(commit_for_process_start)(p,&entry,&sp));
        __asm__ volatile("mov %0, %%rsp\n\tjmp *%1"::"r"(sp),"r"(entry):"memory");__builtin_unreachable();
    }
    int status=0;assert(waitpid(child,&status,0)==child);if(!WIFEXITED(status)||WEXITSTATUS(status))fprintf(stderr,"entry probe wait status: %d\n",status);
    assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(L(abort)(p)==1);
    puts("actual static ELF entry observes configured Linux stack: PASS");
}
static void lifetime(void) {
    uint64_t plans[4];for(unsigned i=0;i<4;i++) { plans[i]=plan();descriptor();assert(L(configure_startup)(plans[i],config,15)); }
    refs++;assert(!L(validate)(1) && refs==4 && L(last_error)()==5);
    for(unsigned i=0;i<4;i++) {
        uintptr_t entry=0,sp=0;assert(L(commit_for_process_start)(plans[i],&entry,&sp) && entry==0x02001000 && !(sp&15));
        assert(L(is_validated)(plans[i]) && !L(configure_startup)(plans[i],config,15));
        assert(!L(materialize_stack_range)(plans[i],0,stack,16384));assert(L(release_plan)(plans[i]));
        assert(!L(release_plan)(plans[i]) && !L(stack_pointer)(plans[i]));
    }
    assert(!refs && L(invariants_hold)());
    for(unsigned i=0;i<4;i++) {uint64_t p=plan();defaults(p);assert(L(abort)(p));}
    puts("four plans, capacity, commit/release/slot reuse clear configured data: PASS");
}
int main(int argc,char **argv) {
    assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);assert(!fseek(f,0,SEEK_END));image_size=ftell(f);rewind(f);
    image=malloc(image_size);assert(image && fread(image,1,image_size,f)==image_size);fclose(f);
    for(unsigned i=0;i<16;i++)random_bytes[i]=(unsigned char)(0x80+i);
    assert(L(init)()==1 && L(init)()==0);configuration();unmapped_headers();legacy_rejections();varied_vectors();execute_entry();lifetime();
    puts("Native ELF Linux startup configuration: PASS");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native x86-64 Linux fixture")
class LinuxInitialStackTests(unittest.TestCase):
    def test_production_loader_startup_and_actual_entry(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="okernel-linux-startup-") as directory:
            out = Path(directory)
            for name, contents in {"provider.oc": PROVIDER, "entry.S": ENTRY, "probe.c": PROBE, "harness.c": HARNESS}.items():
                (out / name).write_text(contents)
            def run(argv):
                result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout
            run([str(compiler), str(out / "provider.oc"), str(ROOT / "ocore/runtime/x86_64/elf_loader.oc"),
                 "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "loader.o")])
            run([clang, "-O2", "-fno-stack-protector", "-fno-builtin", "-nostdlib", "-static", "-no-pie",
                 "-Wl,-Ttext-segment=0x02000000", str(out / "entry.S"), str(out / "probe.c"), "-o", str(out / "probe")])
            run([clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "loader.o"), "-o", str(out / "selftest")])
            output = run([str(out / "selftest"), str(out / "probe")])
            self.assertIn("actual static ELF entry observes configured Linux stack: PASS", output)
            self.assertIn("Native ELF Linux startup configuration: PASS", output)


if __name__ == "__main__":
    unittest.main()
