"""Production thread-owned FS metadata and checked arch_prctl copies.

This hosted carrier supplies only the same five architecture functions as the
file boundary fixture. Hardware FS capture/restore is qualified separately by
the native_tls QEMU profile; these tests exercise real registry lifetimes.
"""
import os
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_posix_file_syscalls as BASE

ROOT = Path(__file__).resolve().parents[1]
HARNESS = BASE.HARNESS.split("int main(void){", 1)[0] + r'''
#define TH(n) _O_runtime__thread__##n
#define TLS(n) _O_runtime__linux_tls_syscalls__##n
extern uint64_t TH(init)(void),TH(prepare_next)(void),TH(commit_next)(uint64_t);
extern uint64_t TH(install)(size_t,uint64_t,uint64_t,uintptr_t,size_t,uintptr_t,uint64_t,uint64_t,uint64_t);
extern uint64_t TH(current_handle)(void),TH(preempt_current)(void),TH(terminate_current)(void);
extern uint64_t TH(cancel)(uint64_t),TH(terminate_process)(uint64_t),TH(reap)(uint64_t),TH(queue_invariants_hold)(void);
extern uint64_t TH(user_fs_base_for)(uint64_t),TH(user_fs_selector_for)(uint64_t);
extern uint64_t TH(valid_user_fs_selector)(uint64_t);
extern uint64_t kernel_thread_capture_user_fs(uint64_t,uint64_t);
extern uint64_t kernel_thread_current_user_fs_base(void),kernel_thread_current_user_fs_selector(void);
extern int64_t TLS(arch_prctl)(uint64_t,uint64_t),TLS(dispatch)(uint64_t,uint64_t,uint64_t);
static uint64_t activate(uint64_t expected,uint64_t owner,uint64_t id){
 uint64_t next=TH(prepare_next)();assert(next==expected);
 assert(P(scheduler_switch_to)(owner)==id&&TH(commit_next)(next)==next);
 assert(TH(current_handle)()==next&&TH(queue_invariants_hold)());return next;
}
static void yield_current(uint64_t owner){
 assert(TH(preempt_current)()!=0&&P(scheduler_deschedule_current)()==owner);
}
int main(void){
 void *fixed=mmap((void*)0x01000000,0x00400000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
 assert(fixed==(void*)0x01000000);
 void *frames=0;assert(!posix_memalign(&frames,4096,1048576));
 assert(FR(init)((uintptr_t)frames,(uintptr_t)frames+1048576)==1);
 assert(CAP(init)()==1&&M(init)()==1&&MAP(init)()==1);
 uint64_t domain=D(init)();assert(domain&&P(init)()==1&&TH(init)()==1);
 assert(A(install_bootstrap)((uintptr_t)root_table)==1);
 uint64_t c0=CAP(cspace_handle_for_slot)(0),c1=CAP(cspace_handle_for_slot)(1);
 assert(M(set_quota_for_owner)(c1,8)==1);
 uint64_t a1=A(create_native_for_owner)(c1);assert(a1);
 uint64_t p0=P(install_for_owner)(0,101,domain,1,c0,0x7000,0x01000000,0x01400000);
 uint64_t p1=P(install_for_owner)(1,102,domain,a1,c1,0x8000,0x01000000,0x01400000);assert(p0&&p1);
 uint64_t t0=TH(install)(0,201,p0,0x01000000,0,0x7000,0,1,1);
 uint64_t t1=TH(install)(1,202,p1,0x01000000,0,0x8000,0,1,1);assert(t0&&t1);
 assert(TLS(arch_prctl)(0x1002,0x02000000)==-3);
 assert(kernel_thread_capture_user_fs(0,0)==1); // Unscheduled bootstrap.
 activate(t0,p0,101);
 assert(!TH(user_fs_base_for)(t0)&&!TH(user_fs_selector_for)(t0));
 assert(TLS(dispatch)(218,0,0)==-38);
 assert(TLS(dispatch)(158,0x1002,0x03000000)==0);
 assert(TH(user_fs_base_for)(t0)==0x03000000&&!TH(user_fs_selector_for)(t0));
 uint64_t *out=(uint64_t*)0x01201000;*out=UINT64_MAX;
 assert(TLS(arch_prctl)(0x1003,(uintptr_t)out)==0&&*out==0x03000000);
 assert(TLS(arch_prctl)(0x1003,0)==-14&&TLS(arch_prctl)(0x1003,0x01000000)==-14);
 assert(TLS(arch_prctl)(0x1003,UINT64_MAX-3)==-14);
 assert(TLS(arch_prctl)(0x1002,UINT64_C(0x7ffffffff000))==-1);
 assert(TLS(arch_prctl)(0x1002,UINT64_C(0xffff800000000000))==-1);
 assert(TH(user_fs_base_for)(t0)==0x03000000);
 assert(TLS(arch_prctl)(0x1001,0)==-22&&TLS(arch_prctl)(0x9999,0)==-22);
 for(uint64_t i=0;i<8;i++){
  uint64_t selector=(i<4?0x18:0x1c)+i;
  assert(TH(valid_user_fs_selector)(selector));
  assert(kernel_thread_capture_user_fs(0,selector)==1);
  assert(!kernel_thread_current_user_fs_base()&&kernel_thread_current_user_fs_selector()==selector);
  assert(TLS(arch_prctl)(0x1003,(uintptr_t)out)==0&&!*out&&TH(user_fs_selector_for)(t0)==selector);
  assert(TH(queue_invariants_hold)());
 }
 for(uint64_t i=0;i<4;i++)assert(TH(valid_user_fs_selector)(i));
 uint64_t rejected[]={4,7,0x10,0x17,0x1c,0x1f,0x24,0xffff,0x10018,UINT64_MAX};
 for(size_t i=0;i<sizeof(rejected)/sizeof(rejected[0]);i++){
  assert(!TH(valid_user_fs_selector)(rejected[i]));
  assert(!kernel_thread_capture_user_fs(0,rejected[i])&&TH(user_fs_selector_for)(t0)==0x23);
 }
 assert(kernel_thread_capture_user_fs(0,0x1b)==1);
 assert(!TH(user_fs_base_for)(t0)&&TH(user_fs_selector_for)(t0)==0x1b);
 assert(TLS(arch_prctl)(0x1002,0x03000001)==0&&!TH(user_fs_selector_for)(t0));
 assert(kernel_thread_capture_user_fs(0x03000002,0x10)==0&&TH(user_fs_base_for)(t0)==0x03000001);
 assert(kernel_thread_capture_user_fs(UINT64_C(0x800000000000),0)==0);
 assert(P(scheduler_deschedule_current)()==p0&&P(scheduler_switch_to)(p1)==102);
 assert(TLS(arch_prctl)(0x1002,0x04000000)==-3&&kernel_thread_capture_user_fs(0,0)==0);
 assert(TH(user_fs_base_for)(t0)==0x03000001);
 assert(P(scheduler_deschedule_current)()==p1&&P(scheduler_switch_to)(p0)==101);
 yield_current(p0);activate(t1,p1,102);
 assert(!TH(user_fs_base_for)(t1)&&!TH(user_fs_selector_for)(t1));
 assert(TLS(arch_prctl)(0x1002,0x04000000)==0&&TH(user_fs_base_for)(t0)==0x03000001);
 assert(TLS(arch_prctl)(0x1003,(uintptr_t)out)==0&&*out==0x04000000);
 assert(TH(terminate_current)()==t1&&P(scheduler_deschedule_current)()==p1);
 assert(!TH(user_fs_base_for)(t1)&&!TH(user_fs_selector_for)(t1)&&TH(reap)(t1)==1);
 uint64_t fresh=TH(install)(1,203,p1,0x01000000,0,0x8000,0,1,1);assert(fresh&&fresh!=t1);
 assert(!TH(user_fs_base_for)(fresh)&&!TH(user_fs_selector_for)(fresh)&&!TH(user_fs_base_for)(t1));
 activate(t0,p0,101);assert(kernel_thread_current_user_fs_base()==0x03000001);
 assert(kernel_thread_capture_user_fs(0,0x23)==1&&kernel_thread_current_user_fs_selector()==0x23);
 yield_current(p0);activate(fresh,p1,102);assert(!kernel_thread_current_user_fs_base());
 assert(TLS(arch_prctl)(0x1002,0)==0&&TH(cancel)(t0)==1&&!TH(user_fs_base_for)(t0));
 assert(TH(terminate_process)(p1)==1&&P(scheduler_deschedule_current)()==p1);
 assert(!TH(user_fs_base_for)(fresh)&&TH(reap)(fresh)==1&&TH(reap)(t0)==1&&TH(queue_invariants_hold)());
 puts("Native FS metadata/syscall policy: PASS; current-thread authority, checked copies, selector capture, stale TCB reuse and teardown");
 return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native carrier requires Linux x86_64")
class LinuxTlsTests(unittest.TestCase):
    def test_real_thread_registry_fs_lifetime_and_arch_prctl(self):
        manifest = os.environ.get("OCORE_U9FS_MANIFEST")
        if not manifest:
            self.skipTest("original source closure requires OCORE_U9FS_MANIFEST")
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang, linker, nm = shutil.which("clang"), shutil.which("ld.lld"), shutil.which("nm")
        self.assertTrue(compiler.is_file() and clang and linker and nm)
        with tempfile.TemporaryDirectory(prefix="native-tls-registry-") as directory:
            output = Path(directory)
            frozen = BASE.BASE.CODEC.stage(Path(manifest), output / "codec", "x86_64")
            BASE.BASE.checked_headers(json.loads(Path(manifest).read_text()), output / "headers")
            (output / "harness.c").write_text(HARNESS)
            modules = BASE.MODULES + ["thread", "linux_tls_syscalls"]
            sources = [ROOT / "ocore/runtime/x86_64" / (name + ".oc") for name in modules]
            sources += [ROOT / "ocore/runtime/common" / (name + ".oc") for name in ["namespace_store", "u9fs_codec", "posix_namespace_files"]]
            commands = [
                [str(compiler), *map(str, sources), "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(output / "kernel.o")],
                [linker, "-r", "-o", str(output / "component.o"), str(output / "kernel.o"), *[item["path"] for item in frozen["objects"]]],
            ]
            for command in commands:
                result = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            undefined = subprocess.check_output([nm, "-u", str(output / "component.o")], text=True)
            self.assertEqual({line.split()[-1] for line in undefined.splitlines()}, BASE.ARCH_SYMBOLS)
            result = subprocess.run([clang, "-O2", "-no-pie", "-I", str(output / "headers"), str(output / "harness.c"), str(output / "component.o"), "-o", str(output / "test")], cwd=output, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(output / "test")], cwd=output, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Native FS metadata/syscall policy: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
