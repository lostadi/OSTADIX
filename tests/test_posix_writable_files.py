"""Native writable OFDs over the shared store and original source-built codec.

One fixture exercises the freestanding common service on x86-64 and closes
its AArch64 dependency graph. A second uses the production process/AS/usercopy
registries; only its privileged copy/CR3 hooks are an explicit host fixture.
Actual CPL3 qualification remains the separate native_posix_files profile.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import unittest

from tests import test_posix_namespace_files as NS
from tests import test_posix_file_syscalls as SYS

ROOT = Path(__file__).resolve().parents[1]

COMMON = NS.HARNESS.split("int main(void){", 1)[0]+r'''
extern int64_t F(open_file)(uint64_t,uint64_t,uint64_t,const uint8_t*,size_t,uint64_t,uint64_t);
extern int64_t F(write)(uint64_t,uint64_t,uint64_t,int64_t,const uint8_t*,size_t);
extern int64_t F(duplicate)(uint64_t,uint64_t,uint64_t,int64_t);
extern int64_t F(duplicate_to)(uint64_t,uint64_t,uint64_t,int64_t,int64_t);
static int64_t open_(const char *s,uint64_t flags,uint64_t mode){return F(open_file)(11,21,1,(const uint8_t*)s,strlen(s),flags,mode);}
static int64_t write_(int64_t fd,const void *p,size_t n){return F(write)(11,21,1,fd,p,n);}
static int64_t read_(int64_t fd,void *p,size_t n){return F(read)(11,21,1,fd,p,n);}
static int64_t seek_(int64_t fd,int64_t off,uint64_t whence){return F(lseek)(11,21,1,fd,off,whence);}
static int64_t close_(int64_t fd){return F(close)(11,21,1,fd);}
static void verify_peer(const char *name,const void *expected,size_t n){
 walk(1,50,"work");walk(50,51,name);clunk(50);peer_open(51,0);
 size_t done=0;while(done<n){size_t wanted=n-done;if(wanted>8000)wanted=8000;
  begin(116);value(51,4);value(done,8);value(wanted,4);assert(call()==117&&get(reply+7,4)==wanted&&!memcmp(reply+11,(const uint8_t*)expected+done,wanted));done+=wanted;
 }clunk(51);
}
int main(int argc,char**argv){
 assert(argc==2);const size_t max=!strcmp(argv[1],"space-partial")?18*1048576:1048576;
 volume=mmap(0,16777216,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 payload=malloc(max+32);output=malloc(max+32);assert(payload&&output);
 for(size_t i=0;i<max+32;i++)payload[i]=(uint8_t)((i*73)^(i>>8));
 assert(S(init)((uintptr_t)volume,16777216,42)&&S(provision_clock)(1700000000));peer=S(session_init)(4,1);assert(peer);handshake();
 create_file("existing",payload,65536);create_file("other",payload+11,4096);
 assert(F(init)(1)==0&&F(provision)(11,21,1)==0);
 if(!strcmp(argv[1],"create-alias")){
  int64_t a=open_("/work/new",2|64|128,0600);assert(a==3&&write_(a,payload,20001)==20001&&seek_(a,0,1)==20001);
  uint64_t meta[6];assert(F(fstat)(11,21,1,a,meta,6)==0&&meta[0]==20001&&meta[1]==(0100000|0600));
  uint64_t calls=C(encodes)();int64_t b=F(duplicate)(11,21,1,a);assert(b==4&&C(encodes)()==calls);
  assert(seek_(b,17,0)==17&&seek_(a,0,1)==17&&read_(b,output,32)==32&&!memcmp(output,payload+17,32));
  assert(seek_(a,0,1)==49&&close_(a)==0&&C(encodes)()==calls+1); // one Tread, no alias clunk
  assert(write_(b,payload+49,111)==111&&F(duplicate_to)(11,21,1,b,10)==10);
  calls=C(encodes)();assert(close_(b)==0&&C(encodes)()==calls&&close_(10)==0&&C(encodes)()==calls+1);
  verify_peer("new",payload,20001);
 }else if(!strcmp(argv[1],"append-truncate")){
  int64_t a=open_("/work/existing",1|1024,0);assert(a==3&&seek_(a,0,1)==0);
  walk(1,20,"work");walk(20,21,"existing");clunk(20);peer_open(21,1);write_bytes(21,65536,"peer",4);clunk(21);
  assert(seek_(a,0,0)==0&&write_(a,"!",1)==1&&seek_(a,0,1)==65541);
  assert(seek_(a,5,0)==5&&write_(a,0,0)==0&&seek_(a,0,1)==5&&read_(a,0,1)==-9);
  assert(close_(a)==0);a=open_("/work/existing",0,0);assert(a==3&&write_(a,0,1)==-9);
  int64_t b=open_("/work/existing",2|512,0);assert(b==4);
  assert(read_(a,output,20)==0&&write_(b,"truncate",8)==8&&read_(a,output,20)==8&&!memcmp(output,"truncate",8));
  assert(close_(a)==0&&close_(b)==0);verify_peer("existing","truncate",8);
 }else if(!strcmp(argv[1],"dup-replace-revoke")){
  int64_t a=open_("/work/existing",2,0),b=open_("/work/other",2,0);assert(a==3&&b==4);
  assert(F(duplicate)(11,21,1,a)==5&&seek_(5,37,0)==37&&seek_(3,0,1)==37);
  assert(F(duplicate_to)(11,21,1,3,4)==4&&read_(4,output,7)==7&&!memcmp(output,payload+37,7));
  uint64_t calls=C(encodes)();assert(F(duplicate_to)(11,21,1,3,3)==3&&F(duplicate_to)(11,21,1,3,5)==5&&C(encodes)()==calls);
  assert(F(duplicate_to)(11,21,1,999,3)==-9&&F(duplicate_to)(11,21,1,3,1)==-9&&seek_(3,0,1)==44);
  for(int fd=6;fd<=10;fd++)assert(F(duplicate)(11,21,1,a)==fd);
  assert(F(duplicate)(11,21,1,a)==-24);
  calls=C(encodes)();assert(F(revoke)(11,21,1)==0&&C(encodes)()==calls+1);
  for(unsigned generation=2;generation<90;generation++){
   assert(F(provision)(11,21,generation)==0);
   assert(F(open_read)(11,21,generation,(const uint8_t*)"/work/other",11)==3);
   for(unsigned fd=4;fd<=10;fd++)assert(F(duplicate)(11,21,generation,3)==fd);
   assert(F(revoke)(11,21,generation)==0);
  }
  peer_valid(); // 89 contexts of aliases must not exhaust native512fid slots.
 }else if(!strcmp(argv[1],"errors")){
  uint8_t *snapshot=malloc(16777216);assert(snapshot);memcpy(snapshot,volume,16777216);
  assert(open_("/work/existing",2|64|128,0600)==-17&&open_("/work/existing",3,0)==-22);
  assert(open_("/work/existing",512,0)==-22&&open_("/work/existing",128,0)==-22&&open_("/work/existing",0x80000,0)==-22);
  assert(open_("/work/badmode",2|64,0x8000)==-22&&open_("/missing/child",2|64,0600)==-2);
  assert(open_("/work/missing/",2|64,0600)==-2&&open_("relative",2|64,0600)==-38);
  for(unsigned n=0;n<600;n++)assert(open_("/missing/child",2|64,0600)==-2);
  assert(!memcmp(snapshot,volume,16777216)); // errors only allocate/clunk transientfids
  int64_t a=open_("/work/existing",2,0);assert(a==3);
  assert(write_(a,0,1)==-14&&write_(a,(const void*)(UINTPTR_MAX-2),3)==-14&&seek_(a,0,1)==0);
  assert(write_(a,payload,(size_t)INT64_MAX+1)==-22&&seek_(a,INT64_MAX,0)==INT64_MAX&&write_(a,payload,1)==-75);
  assert(close_(a)==0);peer_valid();
 }else if(!strcmp(argv[1],"space-partial")){
  int64_t a=open_("/work/full",2|64|128,0600);assert(a==3);
  int64_t written=write_(a,payload,max);assert(written>0&&written<(int64_t)max&&written%8168==0&&seek_(a,0,1)==written);
  uint64_t meta[6];assert(F(fstat)(11,21,1,a,meta,6)==0&&meta[0]==(uint64_t)written);
  assert(write_(a,payload,8168)==-28&&seek_(a,0,1)==written&&write_(a,0,0)==0);
  assert(close_(a)==0);verify_peer("full",payload,(size_t)written);
  a=open_("/work/full",1|1024,0);assert(a==3&&seek_(a,5,0)==5);
  assert(write_(a,payload,8168)==-28&&seek_(a,0,1)==5&&close_(a)==0);
 }else if(!strcmp(argv[1],"stale-alias")){
  int64_t a=open_("/work/existing",2,0),b=open_("/work/other",0,0);assert(a==3&&b==4&&F(duplicate)(11,21,1,a)==5);
  remove_file("existing");assert(write_(a,"X",1)==-116);uint64_t calls=C(encodes)();assert(read_(5,output,1)==-116&&C(encodes)()==calls);
  assert(close_(a)==0&&C(encodes)()==calls&&close_(5)==0&&C(encodes)()==calls+1&&read_(b,output,4)==4&&!memcmp(output,payload+11,4));
  assert(close_(b)==0);peer_valid();
 }else abort();
 printf("native writable common %s: PASS; original codec exchanges=%llu\n",argv[1],(unsigned long long)C(encodes)());return 0;
}
'''

SETUP = SYS.HARNESS.split("int main(void){", 1)[1].split(" const char *names[]", 1)[0]
KERNEL = SYS.HARNESS.split("int main(void){", 1)[0] + "int main(void){" + SETUP + r'''
 strcpy((char*)path,"/work/kernel-output");
 int64_t fd=K(dispatch)(257,(uint64_t)-100,(uintptr_t)path,2|64|128,0600);assert(fd==3);
 memcpy(dest,payload,12288);assert(K(dispatch)(1,fd,(uintptr_t)dest,8192,0)==8192&&K(lseek)(fd,0,1)==8192);
 assert(K(dispatch)(32,fd,0,0,0)==4&&K(lseek)(4,0,0)==0&&K(lseek)(fd,0,1)==0);
 assert(K(dispatch)(33,fd,10,0,0)==10&&K(close)(fd)==0&&K(close)(4)==0);
 size_t before=from_calls;fail_from=from_calls+1;
 assert(K(dispatch)(1,10,(uintptr_t)dest,8192,0)==-14&&K(lseek)(10,0,1)==0);fail_from=0;
 assert(from_calls==before+1&&K(native_metadata)(10,(uintptr_t)dest)==0&&get(dest,8)==8192);
 memcpy(dest,payload+17,12288);fail_from=from_calls+2;
 assert(K(dispatch)(1,10,(uintptr_t)dest,8192,0)==4096&&K(lseek)(10,0,1)==4096);fail_from=0;
 assert(K(lseek)(10,0,0)==0&&K(read)(10,(uintptr_t)dest,8192)==8192&&!memcmp(dest,payload+17,4096)&&!memcmp(dest+4096,payload+4096,4096));
 assert(K(dispatch)(1,999,0,1,0)==-9&&K(dispatch)(1,10,0,0,0)==0&&K(dispatch)(1,10,UINTPTR_MAX-3,4,0)==-14);
 // A readable but non-writable mapping is a valid write SOURCE.
 *(uint8_t*)0x01100000=0xa7;before=from_calls;
 assert(K(dispatch)(1,10,0x01100000,1,0)==1&&from_calls==before+1);
 before=from_calls;assert(K(dispatch)(1,10,0x04000000,1,0)==-14&&K(dispatch)(1,10,0x011ffff0,64,0)==-14&&from_calls==before);
 assert(K(close)(10)==0);select_process(p2,103);assert(K(dispatch)(1,3,(uintptr_t)dest,1,0)==-13&&K(dispatch)(32,3,0,0,0)==-13);
 select_process(p0,101);strcpy((char*)path,"/work/kernel-output");assert(K(openat)(-100,(uintptr_t)path,0,0)==3);
 before=from_calls;assert(K(dispatch)(1,3,0,1,0)==-9&&K(dispatch)(1,3,0,0,0)==-9&&from_calls==before&&K(close)(3)==0);
 assert(K(openat)(-100,(uintptr_t)path,1,0)==3);before=to_calls;
 assert(K(read)(3,0,1)==-9&&K(read)(3,0,0)==-9&&to_calls==before&&K(close)(3)==0);
 puts("native kernel writable calls: PASS; currentprocess/usercopy/chunkfault/sharedOFD checks");return 0;
}
'''


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native fixture requires Linux x86_64")
class PosixWritableFilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get("OCORE_U9FS_MANIFEST")
        if not selected: raise unittest.SkipTest("source-built originalcodec closure requires OCORE_U9FS_MANIFEST")
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        clang, linker, nm = shutil.which("clang"), shutil.which("ld.lld"), shutil.which("nm")
        if not compiler.is_file() or not all([clang,linker,nm]): raise unittest.SkipTest("built ocorec and link tools required")
        cls.directory = Path(tempfile.mkdtemp(prefix="posix-writable-native-"));out=cls.directory
        manifest = Path(selected);arm_manifest=Path(os.environ.get("OCORE_U9FS_ARM_MANIFEST", str(manifest.parent.parent / "aarch64-O1-final/native-codec.json")))
        frozen=NS.CODEC.stage(manifest,out/"codec","x86_64");arm=NS.CODEC.stage(arm_manifest,out/"arm-codec","aarch64")
        NS.checked_headers(json.loads(manifest.read_text()),out/"headers")
        common=[ROOT/"ocore/runtime/common"/(n+".oc") for n in ["namespace_store","u9fs_codec","posix_namespace_files"]]
        commands=[]
        for isa,closure in [("aarch64",arm),("x86_64",frozen)]:
            commands += [[str(compiler),*map(str,common),"--target",isa+"-unknown-none","--emit","obj","-o",str(out/(isa+".o"))],
                [linker,"-r","-o",str(out/(isa+"-closed.o")),str(out/(isa+".o")),*[x["path"] for x in closure["objects"]]]]
        (out/"common.c").write_text(COMMON);(out/"kernel.c").write_text(KERNEL)
        sources=[ROOT/"ocore/runtime/x86_64"/(name+".oc") for name in SYS.MODULES]+common
        commands += [[str(compiler),*map(str,sources),"--target","x86_64-unknown-none","--emit","obj","-o",str(out/"kernel.o")],
            [linker,"-r","-o",str(out/"kernel-closed.o"),str(out/"kernel.o"),*[x["path"] for x in frozen["objects"]]],
            [clang,"-O2","-no-pie","-I",str(out/"headers"),str(out/"common.c"),str(out/"x86_64-closed.o"),"-o",str(out/"common")],
            [clang,"-O2","-no-pie","-I",str(out/"headers"),str(out/"kernel.c"),str(out/"kernel-closed.o"),"-o",str(out/"kernel")]]
        for i,c in enumerate(commands):
            p=subprocess.run(c,capture_output=True,text=True,timeout=90,cwd=out);(out/("build-"+str(i)+".log")).write_text(p.stdout+p.stderr)
            if p.returncode:raise AssertionError(p.stdout+p.stderr+"\nEvidence: "+str(out))
        for name,expected in [("aarch64-closed.o",set()),("x86_64-closed.o",set()),("kernel-closed.o",SYS.ARCH_SYMBOLS)]:
            p=subprocess.run([nm,"-u",str(out/name)],capture_output=True,text=True,check=True)
            if {line.split()[-1] for line in p.stdout.splitlines()}!=expected:raise AssertionError("undeclared native closure "+name+" "+p.stdout)

    def run_case(self, case):
        command=[str(self.directory/("kernel" if case=="kernel" else "common"))]+([] if case=="kernel" else [case])
        p=subprocess.run(command,capture_output=True,text=True,timeout=45,cwd=self.directory)
        (self.directory/(case+".log")).write_text(p.stdout+p.stderr)
        self.assertEqual(p.returncode,0,p.stdout+p.stderr+"\nEvidence: "+str(self.directory));self.assertIn("PASS",p.stdout)
    def test_create_binary_write_and_last_alias_close(self): self.run_case("create-alias")
    def test_append_rechecks_shared_eof_and_truncate_is_visible(self): self.run_case("append-truncate")
    def test_dup2_replacement_shared_offsets_exhaustion_and_revoke(self): self.run_case("dup-replace-revoke")
    def test_failed_open_flags_and_overflow_do_not_mutate_volume(self): self.run_case("errors")
    def test_real_backend_capacity_yields_exact_partial_writes(self): self.run_case("space-partial")
    def test_stale_object_aliases_fail_without_poisoning_other_files(self): self.run_case("stale-alias")
    def test_kernel_current_identity_and_chunk_copy_failure_accounting(self): self.run_case("kernel")

if __name__ == "__main__": unittest.main()
