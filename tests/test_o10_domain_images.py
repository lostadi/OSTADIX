"""Real image registration, confinement, clean reload and immutable-source tests."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define I(n) _O_runtime__aarch64__domain_images__##n
extern uint64_t I(register)(size_t,size_t,size_t,size_t,size_t,size_t,size_t);
extern uint64_t I(backend)(uint64_t,uint64_t),I(kind)(uint64_t,uint64_t),I(bytes)(uint64_t,uint64_t);
extern uint64_t I(entry_pc)(uint64_t,uint64_t),I(entry_x0)(uint64_t,uint64_t);
extern uint64_t I(load)(uint64_t,uint64_t,uint64_t,uint64_t),I(zero)(uint64_t,uint64_t);
uintptr_t kw_guest_address(uint64_t gpa,uint64_t bytes){assert(gpa==0x40000000&&bytes==1);return 0;}
void kw_memory_barrier(void){__sync_synchronize();}
static void st(void*p,uint64_t v,unsigned bytes){unsigned char*q=p;for(unsigned i=0;i<bytes;i++)q[i]=(unsigned char)(v>>(i*8));}
static uint64_t checksum(void*p,size_t bytes){uint64_t h=1469598103934665603ull;unsigned char*q=p;for(size_t i=0;i<bytes;i++)h=(h^q[i])*1099511628211ull;return h;}
static void aux(void){
 unsigned char*p=(void*)0xe2500000;memset(p,0,128);memcpy(p,"O10M3N1\0",8);
 st(p+8,1,4);st(p+12,128,4);st(p+16,0x401f0000,8);st(p+24,0x09001000,8);
 st(p+32,14,4);st(p+36,24,4);memcpy(p+40,"o10-m3-witness",14);memcpy(p+72,"O10_M3_NATIVE_NAMESPACE\n",24);
}
int main(int argc,char**argv){
 assert(argc==2);unsigned scenario=strtoul(argv[1],0,10);
 assert(mmap((void*)0xe2200000,0x600000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void*)0xe2200000);
 memset((void*)0xe2200000,0xa5,0x600000);aux();
 unsigned char*image=(void*)0xe2400000;for(unsigned i=0;i<123;i++)image[i]=(unsigned char)(i+1);
 uint64_t original=checksum((void*)0xe2400000,0x200000);
 assert(!I(backend)(5,6)&&I(load)(5,6,0xe2200000,0x200000)==5);
 if(scenario==0){
  assert(I(register)(0,0,0,0,0,123,128)==0);
  assert(I(register)(0,0,0,0,0,123,128)==12);
  assert(I(backend)(5,6)==3&&I(kind)(5,6)==3&&I(bytes)(5,6)==0x200000);
  assert(I(entry_pc)(5,6)==0x40000000&&I(entry_x0)(5,6)==0x40100000);
  assert(!I(backend)(5,4)&&!I(backend)(1,2)&&!I(backend)(3,4));
  uint64_t before=checksum((void*)0xe2200000,0x200000);
  assert(I(load)(5,6,0xe2400000,0x200000)==6);
  assert(I(load)(5,6,0xe2200001,0x200000)==6&&I(load)(5,6,0xe2200000,0x400000)==6);
  assert(I(load)(5,7,0xe2200000,0x200000)==5&&checksum((void*)0xe2200000,0x200000)==before);
  assert(!I(load)(5,6,0xe2200000,0x200000));
  assert(!memcmp((void*)0xe2200000,image,123)&&!memcmp((void*)0xe2300000,(void*)0xe2500000,128));
  for(unsigned i=123;i<0x100000;i++)assert(((unsigned char*)0xe2200000)[i]==0);
  for(unsigned i=128;i<0x100000;i++)assert(((unsigned char*)0xe2300000)[i]==0);
  assert(checksum((void*)0xe2400000,0x200000)==original);
  for(unsigned i=0;i<0x200000;i++)assert(((unsigned char*)0xe2600000)[i]==0xa5);
  assert(!I(zero)(0xe2200000,0x200000));
  for(unsigned i=0;i<0x200000;i++)assert(((unsigned char*)0xe2200000)[i]==0);
 }else if(scenario==1){
  unsigned offsets[]={0,8,12,16,24,32,36,40,54,72,96,120};
  for(unsigned i=0;i<sizeof offsets/sizeof *offsets;i++){
   unsigned char*at=(void*)(uintptr_t)(0xe2500000+offsets[i]);*at^=1;
   assert(I(register)(0,0,0,0,0,123,128)==6&&!I(backend)(5,6));*at^=1;
  }
  assert(I(register)(0,0,0,0,0,123,128)==0);
  ((unsigned char*)0xe2500000)[120]=1;
  assert(I(load)(5,6,0xe2200000,0x200000)==6);
  for(unsigned i=0;i<0x200000;i++)assert(((unsigned char*)0xe2200000)[i]==0xa5);
 }else if(scenario==2){
  assert(I(register)(1,0,0,0,0,0,0)==8&&I(register)(0,0,1,0,1,0,0)==8);
  assert(I(register)(0,0,0,0,0,0x100001,128)==8&&I(register)(0,0,0,0,0,123,127)==8);
  assert(I(register)(0,0,0,0,0,0,128)==8&&!I(backend)(5,6));
  assert(I(register)(0,0,0,0,0,0,0)==0&&!I(backend)(5,6));
 }else assert(!"unknown scenario");
 uint64_t bases[]={0,0x40000000,0x6d000000,0xd2000000,0xe2000000,0xe2400000,0xe2500000,0xe2600001,UINT64_MAX-0x1fffff};
 for(unsigned i=0;i<sizeof bases/sizeof *bases;i++)assert(I(zero)(bases[i],0x200000)==6);
 assert(I(zero)(0xe2200000,0)==6&&I(zero)(0xe2200000,0x200001)==6);
 puts("immutable image registry/range/reload PASS");return 0;
}
"""


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "native component fixture requires Linux x86_64")
class DomainImageTests(unittest.TestCase):
    def test_registration_and_clean_confined_reload(self):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang = shutil.which("clang")
        self.assertTrue(compiler.is_file())
        self.assertIsNotNone(clang)
        with tempfile.TemporaryDirectory(prefix="o10-domain-images-") as directory:
            out = Path(directory)
            sources = [str(ROOT / name) for name in (
                "ocore/runtime/aarch64/domain_images.oc",
                "ocore/runtime/aarch64/linux_domain_images.oc")]
            for target, name in [("aarch64-unknown-none", "arm.o"), ("x86_64-unknown-none", "native.o")]:
                p = subprocess.run([str(compiler), *sources, "--target", target, "--emit", "obj",
                                    "-o", str(out / name)], capture_output=True, text=True, timeout=120)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            (out / "harness.c").write_text(HARNESS)
            p = subprocess.run([clang, "-O2", "-no-pie", str(out / "harness.c"), str(out / "native.o"),
                                "-o", str(out / "test")], capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            for scenario in range(3):
                p = subprocess.run([str(out / "test"), str(scenario)], capture_output=True, text=True, timeout=30)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertIn("PASS", p.stdout)


if __name__ == "__main__":
    unittest.main()
