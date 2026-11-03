"""Execute the opt-in file syscall component with real native kernel registries.

The carrier replaces only the five architectural CR3/user-copy entry points.
It does not enter EL0, switch hardware page tables, or prove trap integration.
Process, address-space, capability, frame, mapping, file and codec behavior is
the production O-core implementation. Fault-copy failures are injected at the
architecture boundary because the kernel assembly uses privileged GS state.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_posix_namespace_files as BASE

ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    "native_abi", "personality", "domain", "capability", "pages",
    "memory_object", "mapping", "domain_namespace", "image_vfs_storage_m7",
    "image_vfs", "elf_loader", "address_space", "process", "user_memory",
    "posix_file_syscalls",
]
ARCH_SYMBOLS = {
    "ocore_copy_from_user", "ocore_copy_to_user", "ocore_current_cr3",
    "ocore_kernel_p1_address", "ocore_management_cr3",
}
HARNESS = BASE.HARNESS.split("int main(void){", 1)[0] + r'''
#define K(n) _O_runtime__posix_file_syscalls__##n
#define P(n) _O_runtime__process__##n
#define A(n) _O_runtime__address_space__##n
#define CAP(n) _O_runtime__capability__##n
#define M(n) _O_runtime__memory_object__##n
#define D(n) _O_runtime__domain__##n
#define FR(n) _O_runtime__pages__##n
#define MAP(n) _O_runtime__mapping__##n
extern int64_t K(init)(uint64_t),K(provision)(uint64_t,uint64_t,uint64_t),K(revoke_process)(uint64_t);
extern int64_t K(openat)(int64_t,uintptr_t,uint64_t,uint64_t),K(read)(int64_t,uintptr_t,size_t);
extern int64_t K(lseek)(int64_t,int64_t,uint64_t),K(close)(int64_t),K(native_metadata)(int64_t,uintptr_t);
extern int64_t K(dispatch)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern uint64_t P(init)(void),P(current_process_handle)(void),P(exit_current)(uint64_t);
extern uint64_t P(install_for_owner)(size_t,uint64_t,uint64_t,uint64_t,uint64_t,uintptr_t,uintptr_t,uintptr_t);
extern uint64_t P(scheduler_switch_to)(uint64_t),P(scheduler_deschedule_current)(void);
extern uint64_t P(stop_process)(uint64_t,uint64_t),P(begin_reap)(uint64_t),P(finalize_reap)(uint64_t);
extern uint64_t A(install_bootstrap)(uintptr_t),A(create_native_for_owner)(uint64_t),A(destroy)(uint64_t);
extern uint64_t CAP(init)(void),CAP(create_cspace)(size_t),CAP(cspace_handle_for_slot)(size_t);
extern uint64_t D(init)(void),M(init)(void),M(set_quota_for_owner)(uint64_t,size_t),M(drain_and_destroy_cspace)(uint64_t);
extern uint64_t FR(init)(uintptr_t,uintptr_t),MAP(init)(void);

static uint64_t kernel_tables[1024] __attribute__((aligned(4096)));
static uint64_t root_table[512] __attribute__((aligned(4096)));
uintptr_t ocore_current_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_management_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_kernel_p1_address(void){return (uintptr_t)kernel_tables;}
static size_t from_calls,to_calls,fail_from,fail_to,partial_fault;
uint64_t ocore_copy_from_user(void *dst,const void *src,size_t size){
 from_calls++;if(fail_from==from_calls)return 1;
 memcpy(dst,src,size);return 0;
}
uint64_t ocore_copy_to_user(void *dst,const void *src,size_t size){
 to_calls++;if(fail_to==to_calls){if(partial_fault&&size>=partial_fault)memcpy(dst,src,partial_fault);return 1;}
 memcpy(dst,src,size);return 0;
}
static uint8_t *path=(uint8_t*)0x01011000,*dest=(uint8_t*)0x01210000;
static int64_t open_path(const char *s){strcpy((char*)path,s);return K(dispatch)(257,(uint64_t)-100,(uintptr_t)path,0,0);}
static void select_process(uint64_t owner,uint64_t id){assert(P(scheduler_switch_to)(owner)==id&&P(current_process_handle)()==owner);}
int main(void){
 const size_t max=1048576,volume_size=16777216;
 void *fixed=mmap((void*)0x01000000,0x00400000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
 assert(fixed==(void*)0x01000000);assert(mprotect((void*)0x01200000,4096,PROT_NONE)==0);
 void *frames=0;assert(posix_memalign(&frames,4096,1048576)==0);
 assert(FR(init)((uintptr_t)frames,(uintptr_t)frames+1048576)==1);
 assert(CAP(init)()==1&&M(init)()==1&&MAP(init)()==1);
 uint64_t domain=D(init)();assert(domain&&P(init)()==1);
 assert(A(install_bootstrap)((uintptr_t)root_table)==1);
 uint64_t c0=CAP(cspace_handle_for_slot)(0),c1=CAP(cspace_handle_for_slot)(1),c2=CAP(cspace_handle_for_slot)(2);
 assert(c0&&c1&&c2&&M(set_quota_for_owner)(c1,8)==1&&M(set_quota_for_owner)(c2,8)==1);
 uint64_t a1=A(create_native_for_owner)(c1),a2=A(create_native_for_owner)(c2);assert(a1&&a2&&a1!=a2);
 uint64_t p0=P(install_for_owner)(0,101,domain,1,c0,0x7000,0x01000000,0x01400000);
 uint64_t p1=P(install_for_owner)(1,102,domain,a1,c1,0x8000,0x01000000,0x01400000);
 uint64_t p2=P(install_for_owner)(2,103,domain,a2,c2,0x9000,0x01000000,0x01400000);assert(p0&&p1&&p2);
 volume=mmap(0,volume_size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 payload=malloc(max);assert(payload);for(size_t i=0;i<max;i++)payload[i]=(uint8_t)((i*73)^(i>>8));
 assert(S(init)((uintptr_t)volume,volume_size,1)==1&&S(provision_clock)(1700000000)==1);
 peer=S(session_init)(4,1);assert(peer);handshake();
 create_file("empty",payload,0);create_file("small",payload,4096);create_file("large",payload,max);
 assert(K(init)(1)==0&&K(provision)(p0,201,1)==0&&K(provision)(p1,202,1)==0);
 assert(K(provision)(UINT64_C(0xdeadbeef),201,1)==-3&&K(provision)(p0,999,2)==-22);
 assert(K(read)(3,(uintptr_t)dest,1)==-13);select_process(p0,101);
 const char *names[]={"/work/empty","/work/small","/work/large"};const size_t sizes[]={0,4096,max};
 for(unsigned i=0;i<3;i++){
  int64_t fd=open_path(names[i]);assert(fd==3);memset(dest,0xa5,max+32);
  assert(K(dispatch)(0,fd,(uintptr_t)dest,sizes[i]+17,0)==(int64_t)sizes[i]);
  assert(!memcmp(dest,payload,sizes[i]));for(unsigned j=0;j<17;j++)assert(dest[sizes[i]+j]==0xa5);
  assert(K(dispatch)(3,fd,0,0,0)==0&&K(close)(fd)==-9);
 }
 puts("production registries and shared original-codec service: binary empty/4K/1MiB reads PASS");
 strcpy((char*)path,"/work/small");
 assert(K(dispatch)(2,(uintptr_t)path,0,0,0)==3&&K(read)(3,(uintptr_t)dest,4)==4&&!memcmp(dest,payload,4));
 assert(K(close)(3)==0&&K(dispatch)(2,(uintptr_t)path,1,0,0)==-22);
 assert(K(dispatch)(2,0,0,0,0)==-14); // SYS_open uses the same checked user-copy path.
 int64_t fd=open_path("/work/large");assert(fd==3&&K(lseek)(fd,0,1)==0);
 assert(K(read)(999,0,1)==-9); // Invalid fd wins over an invalid destination.
 size_t copied=to_calls;assert(K(read)(fd,0,12)==-14&&to_calls==copied&&K(lseek)(fd,0,1)==0);
 assert(K(read)(fd,UINTPTR_MAX-3,4)==-14&&K(lseek)(fd,0,1)==0);
 assert(K(read)(fd,0x01100000,1)==-14&&K(read)(fd,0x011ffff0,64)==-14&&to_calls==copied);
 assert(K(read)(fd,0,0)==0&&K(lseek)(fd,0,1)==0);
 assert(K(read)(fd,(uintptr_t)dest,(size_t)INT64_MAX+1)==-22);
 memset(dest,0xa5,8192);fail_to=to_calls+1;assert(K(read)(fd,(uintptr_t)dest,8192)==-14&&K(lseek)(fd,0,1)==0);fail_to=0;
 for(unsigned i=0;i<8192;i++)assert(dest[i]==0xa5);
 fail_to=to_calls+2;partial_fault=13;assert(K(read)(fd,(uintptr_t)dest,8192)==4096&&K(lseek)(fd,0,1)==4096);
 assert(!memcmp(dest,payload,4096+13));for(unsigned i=4096+13;i<8192;i++)assert(dest[i]==0xa5);
 fail_to=0;partial_fault=0;assert(K(read)(fd,(uintptr_t)dest,4096)==4096&&!memcmp(dest,payload+4096,4096));
 assert(K(lseek)(fd,0,1)==8192&&K(lseek)(fd,INT64_MIN,0)==-22&&K(lseek)(fd,0,1)==8192);
 assert(K(native_metadata)(fd,(uintptr_t)dest+1)==0);assert(get(dest+1,8)==max&&get(dest+9,8)==(0100000|0664));
 assert(K(native_metadata)(fd,0x01100000)==-14&&K(dispatch)(5,fd,(uintptr_t)dest,0,0)==-38);
 assert(K(dispatch)(262,0,0,0,0)==-38&&K(dispatch)(1,fd,(uintptr_t)dest,1,0)==-38);
 assert(K(close)(fd)==0);puts("mapped ranges, output permissions, fault rollback/partial progress and honest unsupported ABI PASS");
 strcpy((char*)path,"/work/small");assert(K(openat)(999,(uintptr_t)path,0x8000,0)==3&&K(close)(3)==0);
 assert(K(openat)(-100,(uintptr_t)path,1,0)==-22&&K(openat)(-100,(uintptr_t)path,0x80000,0)==-22);
 strcpy((char*)path,"relative");assert(K(openat)(-100,(uintptr_t)path,0,0)==-38);
 path[0]=0;assert(K(openat)(-100,(uintptr_t)path,0,0)==-2);
 memset(path,'x',4096);assert(K(openat)(-100,(uintptr_t)path,0,0)==-36);
 memset((void*)0x011ffffc,'x',4);assert(K(openat)(-100,0x011ffffc,0,0)==-14);
 assert(K(openat)(-100,0,0,0)==-14&&K(openat)(-100,UINTPTR_MAX,0,0)==-14);
 strcpy((char*)path,"/work/small");fail_from=from_calls+3;assert(K(openat)(-100,(uintptr_t)path,0,0)==-14);fail_from=0;
 assert(open_path("/work/small")==3&&K(close)(3)==0);puts("bounded NUL pathname copies and independent host fault injection PASS");
 fd=open_path("/work/small");assert(fd==3&&K(read)(fd,(uintptr_t)dest,37)==37);
 select_process(p2,103);assert(K(read)(3,(uintptr_t)dest,1)==-13&&K(dispatch)(0,p0,(uintptr_t)dest,1,0)==-13);
 select_process(p1,102);assert(K(read)(3,0x01201000,1)==-9);
 uint8_t *p1path=(uint8_t*)0x01000100;strcpy((char*)p1path,"/work/small");
 assert(K(openat)(-100,(uintptr_t)p1path,0,0)==3&&K(read)(3,0x01201000,16)==16);
 assert(!memcmp((void*)0x01201000,payload,16)&&K(lseek)(3,0,1)==16);
 copied=to_calls;assert(K(read)(3,0x01201ff8,16)==-14&&to_calls==copied&&K(lseek)(3,0,1)==16);
 select_process(p0,101);assert(K(lseek)(3,0,1)==37&&K(revoke_process)(p0)==0&&K(read)(3,(uintptr_t)dest,1)==-13);
 select_process(p1,102);assert(K(read)(3,0x01201000,8)==8&&!memcmp((void*)0x01201000,payload+16,8));peer_valid();
 assert(K(provision)(p0,201,1)==-116&&K(provision)(p0,201,2)==0);
 select_process(p0,101);assert(K(read)(3,(uintptr_t)dest,1)==-9&&open_path("/work/small")==3);
 assert(S(revoke)(1)==1&&K(read)(3,0,0)==-116&&K(read)(3,0,1)==-116&&K(lseek)(3,0,1)==-116);peer_valid();
 assert(K(init)(2)==0&&K(read)(3,(uintptr_t)dest,1)==-13);
 assert(K(provision)(p0,201,2)==-116&&K(provision)(p0,201,3)==0&&open_path("/work/small")==3&&K(close)(3)==0);
 puts("real current-process authority, distinct address spaces, scoped withdrawal and service restart PASS");
 // Reap/recreate an actual dynamic PCB/CSpace/AS so stale handles cannot be
 // converted into the new process's file authority by slot reuse.
 assert(K(revoke_process)(p1)==0||K(revoke_process)(p1)==-9);
 select_process(p1,102);assert(P(scheduler_deschedule_current)()==p1&&P(stop_process)(p1,0)==1);
 assert(K(provision)(p1,202,2)==-3&&P(begin_reap)(p1)==1);
 assert(A(destroy)(a1)==1&&M(drain_and_destroy_cspace)(c1)==1&&P(finalize_reap)(p1)==1);
 uint64_t new_c1=CAP(create_cspace)(1);assert(new_c1&&new_c1!=c1&&M(set_quota_for_owner)(new_c1,8)==1);
 uint64_t new_a1=A(create_native_for_owner)(new_c1);assert(new_a1&&new_a1!=a1);
 uint64_t new_p1=P(install_for_owner)(1,104,domain,new_a1,new_c1,0xa000,0x01000000,0x01400000);assert(new_p1&&new_p1!=p1);
 select_process(new_p1,104);assert(K(read)(3,0x01201000,1)==-13&&K(provision)(p1,202,3)==-3);
 assert(K(provision)(new_p1,203,1)==0&&K(openat)(-100,(uintptr_t)p1path,0,0)==3&&K(read)(3,0x01201000,4)==4);
 assert(K(revoke_process)(p1)==-9&&K(read)(3,0x01201000,4)==4&&K(close)(3)==0);peer_valid();
 assert(P(exit_current)(0)==104&&K(read)(3,0x01201000,1)==-13&&K(provision)(new_p1,203,2)==-3);
 assert(K(revoke_process)(new_p1)==0);select_process(p0,101);assert(open_path("/work/small")==3&&K(read)(3,(uintptr_t)dest,4)==4&&K(close)(3)==0);
 puts("actual PCB/AS/CSpace generation reuse and exited-process denial PASS");
 printf("native file syscall component: PASS; codec exchanges=%llu; from-copies=%zu; to-copies=%zu; hosted kernel state only\n",(unsigned long long)C(encodes)(),from_calls,to_calls);
 return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native carrier requires Linux x86_64")
class PosixFileSyscallsTests(unittest.TestCase):
    def test_kernel_mediated_file_calls_use_real_registries_and_user_copy_checks(self):
        selected = os.environ.get("OCORE_U9FS_MANIFEST")
        if not selected:
            self.skipTest("complete original codec closure requires OCORE_U9FS_MANIFEST")
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang, linker, nm = shutil.which("clang"), shutil.which("ld.lld"), shutil.which("nm")
        self.assertTrue(compiler.is_file() and clang and linker and nm, "built compiler and native link tools are required")
        with tempfile.TemporaryDirectory(prefix="posix-file-syscalls-") as directory:
            out = Path(directory)
            frozen = BASE.CODEC.stage(Path(selected), out / "codec", "x86_64")
            manifest = json.loads(Path(selected).read_text())
            BASE.checked_headers(manifest, out / "headers")
            (out / "harness.c").write_text(HARNESS)
            sources = [ROOT / "ocore/runtime/x86_64" / (name + ".oc") for name in MODULES]
            sources += [ROOT / "ocore/runtime/common" / (name + ".oc") for name in ("namespace_store", "u9fs_codec", "posix_namespace_files")]
            commands = [
                [str(compiler), *map(str, sources), "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "kernel.o")],
                [linker, "-r", "-o", str(out / "component.o"), str(out / "kernel.o"), *[item["path"] for item in frozen["objects"]]],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=90, cwd=out)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            undefined = subprocess.run([nm, "-u", str(out / "component.o")], capture_output=True, text=True, check=True).stdout
            self.assertEqual({line.split()[-1] for line in undefined.splitlines()}, ARCH_SYMBOLS, "production closure may import only declared architecture primitives")
            command = [clang, "-O2", "-no-pie", "-I", str(out / "headers"), str(out / "harness.c"), str(out / "component.o"), "-o", str(out / "test")]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60, cwd=out)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(out / "test")], capture_output=True, text=True, timeout=90, cwd=out)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("native file syscall component: PASS", result.stdout)
            self.assertIn("actual PCB/AS/CSpace generation reuse", result.stdout)


if __name__ == "__main__":
    unittest.main()
