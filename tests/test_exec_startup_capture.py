"""Run production process/mapping/ELF/startup-copy code in a native carrier.

Only immutable image delivery and five privileged architectural hooks are
replaced. This does not claim a kernel execve trap, original libc admission,
hardware copy-fault recovery, or a complete process-replacement transaction.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_linux_initial_stack as BASE

ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    "native_abi", "personality", "domain", "capability", "pages",
    "memory_object", "mapping", "elf_loader", "address_space", "process",
    "user_memory", "exec_startup_capture",
]

HARNESS = BASE.HARNESS.split("int main(int argc,char **argv)", 1)[0] + r'''
#define X(n) _O_runtime__exec_startup_capture__##n
#define P(n) _O_runtime__process__##n
#define A(n) _O_runtime__address_space__##n
#define CAP(n) _O_runtime__capability__##n
#define M(n) _O_runtime__memory_object__##n
#define D(n) _O_runtime__domain__##n
#define FR(n) _O_runtime__pages__##n
#define MAP(n) _O_runtime__mapping__##n
extern int64_t X(configure_current)(uint64_t,uintptr_t,uintptr_t,uintptr_t,const uint64_t*,size_t);
extern uint64_t P(init)(void),P(current_process_handle)(void),P(exit_current)(uint64_t);
extern uint64_t P(install_for_owner)(size_t,uint64_t,uint64_t,uint64_t,uint64_t,uintptr_t,uintptr_t,uintptr_t);
extern uint64_t P(scheduler_switch_to)(uint64_t),P(scheduler_deschedule_current)(void);
extern uint64_t A(install_bootstrap)(uintptr_t),A(create_native_for_owner)(uint64_t);
extern uint64_t CAP(init)(void),CAP(cspace_handle_for_slot)(size_t);
extern uint64_t D(init)(void),M(init)(void),M(set_quota_for_owner)(uint64_t,size_t);
extern uint64_t FR(init)(uintptr_t,uintptr_t),MAP(init)(void);
static uint64_t kernel_tables[1024] __attribute__((aligned(4096)));
static uint64_t root_table[512] __attribute__((aligned(4096)));
uintptr_t ocore_current_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_management_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_kernel_p1_address(void){return (uintptr_t)kernel_tables;}
static size_t from_calls,fail_from;
static int reenter;
static uint64_t active_plan;
static uint64_t policy[7];
static uintptr_t filename=0x01011000,argument_table=0x01012000,environment_table=0x01013000;
static unsigned char *argument_data=(void*)0x01014000,*environment_data=(void*)0x01016000;
uint64_t ocore_copy_from_user(void *dst,const void *src,size_t n){
 from_calls++;
 if(reenter){reenter=0;assert(X(configure_current)(active_plan,filename,argument_table,environment_table,policy,7)==-16);}
 if(fail_from==from_calls){if(n)memset(dst,0x5a,1);return 1;}
 memcpy(dst,src,n);return 0;
}
uint64_t ocore_copy_to_user(void *dst,const void *src,size_t n){memcpy(dst,src,n);return 0;}
static void inputs(void){
 strcpy((char*)filename,"/usr/bin/probe");
 memcpy(argument_data,args,sizeof args);memcpy(environment_data,environment,sizeof environment);
 uint64_t av[]={(uintptr_t)argument_data,(uintptr_t)argument_data+6,(uintptr_t)argument_data+14,0};
 uint64_t ev[]={(uintptr_t)environment_data,(uintptr_t)environment_data+7,0};
 memcpy((void*)argument_table,av,sizeof av);memcpy((void*)environment_table,ev,sizeof ev);
 uint64_t p[]={(uintptr_t)random_bytes,16,1000,1001,1002,1003,1};memcpy(policy,p,sizeof p);
}
static int64_t prepare(uint64_t p){return X(configure_current)(p,filename,argument_table,environment_table,policy,7);}
static void expect_failure(uint64_t p,int64_t expected,uintptr_t path,uintptr_t av,uintptr_t ev,const uint64_t *pol,size_t words){
 uintptr_t sp=L(stack_pointer)(p);capture(p,prior);
 assert(X(configure_current)(p,path,av,ev,pol,words)==expected);
 capture(p,stack);assert(sp==L(stack_pointer)(p)&&!memcmp(stack,prior,sizeof stack)&&L(invariants_hold)());
}
static void copy_and_faults(uint64_t p){
 inputs();size_t start=from_calls;assert(!prepare(p));size_t operations=from_calls-start;assert(operations>32);
 capture(p,stack);size_t off=configured_offset(p);
 assert(word(stack+off)==3&&!strcmp(string(word(stack+off+8)),"probe"));
 assert(!strcmp(string(word(stack+off+16)),"payload")&&!strcmp(string(word(stack+off+24)),""));
 assert(!strcmp(string(aux(p,31)),"/usr/bin/probe")&&aux(p,11)==1000&&aux(p,23)==1);
 assert(!memcmp(string(aux(p,25)),random_bytes,16));
 memcpy(prior,stack,sizeof prior);memset(argument_data,0xcc,sizeof args);memset(environment_data,0xdd,sizeof environment);
 memset((void*)filename,'X',14);capture(p,stack);assert(!memcmp(prior,stack,sizeof stack));inputs();
 // Every architectural copy position, including vector words and strings,
 // fails independently without changing an already configured stack.
 for(size_t call=1;call<=operations;call++){
  fail_from=from_calls+call;expect_failure(p,-14,filename,argument_table,environment_table,policy,7);fail_from=0;
  assert(!prepare(p));
 }
 active_plan=p;reenter=1;assert(!prepare(p)&&!reenter);
 puts("exact current-user vectors/empty argument/immutable capture/all copy faults/atomic rollback/reentry: PASS");
}
static void rejected_inputs(uint64_t p){
 inputs();assert(!prepare(p));
 expect_failure(p,-14,0,argument_table,environment_table,policy,7);
 expect_failure(p,-14,UINTPTR_MAX,argument_table,environment_table,policy,7);
 expect_failure(p,-14,filename,UINTPTR_MAX-3,environment_table,policy,7);
 expect_failure(p,-14,filename,argument_table,0x01200000,policy,7);
 ((uint64_t*)argument_table)[0]=UINTPTR_MAX;expect_failure(p,-14,filename,argument_table,environment_table,policy,7);inputs();
 memset((void*)0x011ffffc,'a',4);((uint64_t*)argument_table)[0]=0x011ffffc;
 expect_failure(p,-14,filename,argument_table,environment_table,policy,7);inputs();
 *(char*)filename=0;expect_failure(p,-2,filename,argument_table,environment_table,policy,7);inputs();
 memset((void*)filename,'a',4096);expect_failure(p,-36,filename,argument_table,environment_table,policy,7);inputs();
 expect_failure(p,-22,filename,argument_table,environment_table,NULL,7);
 expect_failure(p,-22,filename,argument_table,environment_table,policy,6);
 expect_failure(p,-22,filename,argument_table,environment_table,(const uint64_t*)((uintptr_t)policy+1),7);
 for(unsigned i=1;i<7;i++){
  uint64_t old=policy[i];policy[i]=i==1?15:(i==6?2:UINT64_C(1)<<32);
  expect_failure(p,-22,filename,argument_table,environment_table,policy,7);policy[i]=old;
 }
 // Raw non-UTF8 argument bytes are neither decoded nor normalized.
 argument_data[0]=0xff;assert(!prepare(p));capture(p,stack);
 assert(*(const unsigned char*)string(word(stack+configured_offset(p)+8))==0xff);inputs();
 assert(!X(configure_current)(p,filename,0,0,policy,7));capture(p,stack);
 assert(word(stack+configured_offset(p))==0&&!word(stack+configured_offset(p)+8));
 puts("invalid/overflow/unmapped pointers, limits, trusted policy, raw bytes and null vectors: PASS");
}
static void limits(uint64_t p){
 inputs();assert(!prepare(p));unsigned char *large=(void*)0x01020000;
 memset(large,'q',16384);((uint64_t*)argument_table)[0]=(uintptr_t)large;((uint64_t*)argument_table)[1]=0;
 expect_failure(p,-7,filename,argument_table,environment_table,policy,7);
 large[16383]=0;expect_failure(p,-7,filename,argument_table,environment_table,policy,7);
 inputs();uint64_t *many=(void*)0x01030000;unsigned char *empty=(void*)0x01035000;*empty=0;
 for(unsigned i=0;i<2049;i++)many[i]=(uintptr_t)empty;
 expect_failure(p,-7,filename,(uintptr_t)many,environment_table,policy,7);
 // Individually valid packed bytes can still exceed combined stack/auxv.
 memset(large,'q',10000);large[9999]=0;memset(large+10000,'e',10000);large[19999]=0;
 ((uint64_t*)argument_table)[0]=(uintptr_t)large;((uint64_t*)argument_table)[1]=0;
 ((uint64_t*)environment_table)[0]=(uintptr_t)large+10000;((uint64_t*)environment_table)[1]=0;
 expect_failure(p,-7,filename,argument_table,environment_table,policy,7);inputs();assert(!prepare(p));
 puts("per-string/vector and combined loader stack capacity preserve previous image: PASS");
}
static void execute_captured_entry(uint64_t p){
 inputs();assert(!prepare(p));pid_t child=fork();assert(child>=0);
 if(!child){
  for(size_t i=0;i<L(segment_count)(p);i++){
   uintptr_t begin=L(segment_page_start)(p,i),end=L(segment_page_end)(p,i);
   assert(mmap((void*)begin,end-begin,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)begin);
   assert(L(materialize_segment_range)(p,i,0,(void*)L(segment_vaddr)(p,i),L(segment_memsz)(p,i)));
   unsigned flags=L(segment_flags)(p,i);int prot=PROT_READ;if(flags&2)prot|=PROT_WRITE;if(flags&1)prot|=PROT_EXEC;
   assert(!mprotect((void*)begin,end-begin,prot));
  }
  assert(L(materialize_stack_range)(p,0,(void*)0x013fc000,16384));
  uintptr_t entry=0,sp=0;assert(L(commit_for_process_start)(p,&entry,&sp));
  __asm__ volatile("mov %0, %%rsp\n\tjmp *%1"::"r"(sp),"r"(entry):"memory");__builtin_unreachable();
 }
 int status=0;assert(waitpid(child,&status,0)==child);
 assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
 puts("actual ELF entry consumes user-captured argv/env/auxv stack: PASS");
}
int main(int argc,char **argv){
 assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);assert(!fseek(f,0,SEEK_END));image_size=ftell(f);rewind(f);
 image=malloc(image_size);assert(image&&fread(image,1,image_size,f)==image_size);fclose(f);
 for(unsigned i=0;i<16;i++)random_bytes[i]=(unsigned char)(0x80+i);
 assert(L(init)()==1);uint64_t p=plan();
 expect_failure(p,-3,filename,argument_table,environment_table,policy,7); // No current process, no copies.
 assert(mmap((void*)0x01000000,0x00400000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0x01000000);
 assert(!mprotect((void*)0x01200000,4096,PROT_NONE));
 void *frames=NULL;assert(!posix_memalign(&frames,4096,1048576));
 assert(FR(init)((uintptr_t)frames,(uintptr_t)frames+1048576)&&CAP(init)()&&M(init)()&&MAP(init)());
 uint64_t domain=D(init)();assert(domain&&P(init)()&&A(install_bootstrap)((uintptr_t)root_table));
 uint64_t c0=CAP(cspace_handle_for_slot)(0),c1=CAP(cspace_handle_for_slot)(1);
 assert(c0&&c1&&M(set_quota_for_owner)(c1,8));uint64_t a1=A(create_native_for_owner)(c1);assert(a1);
 uint64_t p0=P(install_for_owner)(0,101,domain,1,c0,0x7000,0x01000000,0x01400000);
 uint64_t p1=P(install_for_owner)(1,102,domain,a1,c1,0x8000,0x01000000,0x01400000);assert(p0&&p1);
 assert(P(scheduler_switch_to)(p0)==101);copy_and_faults(p);rejected_inputs(p);limits(p);execute_captured_entry(p);
 assert(P(scheduler_switch_to)(p1)==102);expect_failure(p,-14,filename,argument_table,environment_table,policy,7);
 assert(P(scheduler_switch_to)(p0)==101);inputs();assert(!prepare(p));
 assert(P(scheduler_deschedule_current)()==p0);expect_failure(p,-3,filename,argument_table,environment_table,policy,7);
 assert(P(scheduler_switch_to)(p0)==101&&P(exit_current)(0)==101);
 expect_failure(p,-3,filename,argument_table,environment_table,policy,7);
 assert(L(abort)(p));assert(X(configure_current)(p,filename,argument_table,environment_table,policy,7)==-22);
 assert(!refs&&L(invariants_hold)());puts("real current process/address-space authority and stale loader plan: PASS");
 puts("Native exec startup capture: PASS");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native x86-64 carrier")
class ExecStartupCaptureTests(unittest.TestCase):
    def test_real_registries_and_fault_atomic_user_capture(self):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            self.skipTest("already-built ocorec and clang are required")
        with tempfile.TemporaryDirectory(prefix="okernel-exec-startup-") as directory:
            out = Path(directory)
            for name, contents in {"provider.oc": BASE.PROVIDER, "entry.S": BASE.ENTRY,
                                   "probe.c": BASE.PROBE, "harness.c": HARNESS}.items():
                (out / name).write_text(contents)
            def run(argv):
                result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout
            run([str(compiler), str(out / "provider.oc"),
                 *[str(ROOT / f"ocore/runtime/x86_64/{name}.oc") for name in MODULES],
                 "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "runtime.o")])
            run([clang, "-O2", "-fno-stack-protector", "-fno-builtin", "-nostdlib", "-static", "-no-pie",
                 "-Wl,-Ttext-segment=0x02000000", str(out / "entry.S"), str(out / "probe.c"), "-o", str(out / "probe")])
            run([clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "runtime.o"), "-o", str(out / "selftest")])
            output = run([str(out / "selftest"), str(out / "probe")])
            self.assertIn("actual ELF entry consumes user-captured argv/env/auxv stack: PASS", output)
            self.assertIn("Native exec startup capture: PASS", output)


if __name__ == "__main__":
    unittest.main()
