"""Native regular-file service over the real store and original u9fs codecs.

The C fixture independently creates/mutates files through ordinary 9P wire
messages. It is not a replacement application, VFS, codec or POSIX kernel.
OCORE_U9FS_MANIFEST selects the completed seven-object x86-64 source closure;
the sibling AArch64 manifest supplies matching original-header ABI evidence.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("posix_native_codec", ROOT / "scripts/okernel_native_codec.py")
CODEC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CODEC)
ABI = r'''
#include <plan9.h>
#include <fcall.h>
#define ABI(T,field,n) _Static_assert(offsetof(T,field)==n,#T "." #field)
_Static_assert(sizeof(void*)==8 && sizeof(ulong)==8,"LP64 original codec");
_Static_assert(sizeof(Fcall)==712 && _Alignof(Fcall)==8 && sizeof(Qid)==24,"Fcall/Qid layout");
_Static_assert(sizeof(Dir)==96 && _Alignof(Dir)==8,"Dir layout");
ABI(Fcall,type,0);ABI(Fcall,tag,8);ABI(Fcall,msize,12);ABI(Fcall,version,16);
ABI(Fcall,ename,32);ABI(Fcall,qid,40);ABI(Fcall,iounit,64);ABI(Fcall,nstat,664);ABI(Fcall,stat,672);
ABI(Fcall,fid,4);ABI(Fcall,afid,680);ABI(Fcall,uname,72);ABI(Fcall,aname,80);
ABI(Fcall,mode,104);ABI(Fcall,newfid,108);ABI(Fcall,nwname,112);ABI(Fcall,wname,120);ABI(Fcall,nwqid,248);ABI(Fcall,wqid,256);
ABI(Fcall,offset,640);ABI(Fcall,count,648);ABI(Fcall,data,656);
ABI(Qid,path,0);ABI(Qid,vers,8);ABI(Qid,type,16);
ABI(Dir,qid,8);ABI(Dir,mode,32);ABI(Dir,atime,40);ABI(Dir,mtime,48);ABI(Dir,length,56);
'''
HARNESS = ABI + r'''
#undef assert
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define S(n) _O_runtime__common__namespace_store__##n
#define F(n) _O_runtime__common__posix_namespace_files__##n
#define C(n) _O_runtime__common__u9fs_codec__##n
extern uint64_t S(init)(uintptr_t,size_t,uint64_t),S(provision_clock)(uint64_t);
extern uint64_t S(session_init)(uint64_t,uint64_t),S(revoke)(uint64_t);
extern uint64_t S(revoke_if_current)(uint64_t,uint64_t);
extern size_t S(handle)(uint64_t,const uint8_t*,size_t,uint8_t*,size_t);
extern int64_t F(init)(uint64_t),F(provision)(uint64_t,uint64_t,uint64_t),F(revoke)(uint64_t,uint64_t,uint64_t);
extern int64_t F(open_read)(uint64_t,uint64_t,uint64_t,const uint8_t*,size_t);
extern int64_t F(read)(uint64_t,uint64_t,uint64_t,int64_t,uint8_t*,size_t);
extern int64_t F(lseek)(uint64_t,uint64_t,uint64_t,int64_t,int64_t,uint64_t);
extern int64_t F(fstat)(uint64_t,uint64_t,uint64_t,int64_t,uint64_t*,size_t);
extern int64_t F(close)(uint64_t,uint64_t,uint64_t,int64_t);
extern uint64_t C(encodes)(void),C(decodes)(void);
static uint8_t request[8192],reply[8192],*volume,*payload,*output;
static size_t position;
static uint64_t peer;
static void put(uint8_t *p,uint64_t value,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(value>>(i*8));}
static uint64_t get(const uint8_t *p,unsigned n){uint64_t value=0;for(unsigned i=0;i<n;i++)value|=(uint64_t)p[i]<<(i*8);return value;}
static void value(uint64_t n,unsigned width){put(request+position,n,width);position+=width;}
static void string(const char *s){size_t n=strlen(s);value(n,2);memcpy(request+position,s,n);position+=n;}
static void begin(unsigned type){memset(request,0,sizeof request);position=7;request[4]=type;put(request+5,123,2);}
static unsigned call(void){
 put(request,position,4);size_t n=S(handle)(peer,request,position,reply,sizeof reply);
 assert(n>=7 && get(reply,4)==n && get(reply+5,2)==123);return reply[4];
}
static void handshake(void){
 begin(100);value(8192,4);string("9P2000");assert(call()==101);
 begin(104);value(1,4);value(UINT32_MAX,4);string("root");string("");assert(call()==105);
}
static void walk(unsigned from,unsigned to,const char *name){begin(110);value(from,4);value(to,4);value(1,2);string(name);assert(call()==111);}
static void clunk(unsigned fid){begin(120);value(fid,4);assert(call()==121);}
static void peer_open(unsigned fid,unsigned mode){begin(112);value(fid,4);value(mode,1);assert(call()==113);}
static void write_bytes(unsigned fid,size_t offset,const void *bytes,size_t n){
 begin(118);value(fid,4);value(offset,8);value(n,4);memcpy(request+position,bytes,n);position+=n;
 assert(call()==119 && get(reply+7,4)==n);
}
static uint64_t create_file(const char *name,const void *bytes,size_t n){
 walk(1,20,"work");begin(114);value(20,4);string(name);value(0664|0x04000000,4);value(2,1);assert(call()==115);
 uint64_t inode=get(reply+12,8);
 for(size_t done=0;done<n;){size_t chunk=n-done;if(chunk>8000)chunk=8000;write_bytes(20,done,(const uint8_t*)bytes+done,chunk);done+=chunk;}
 clunk(20);return inode;
}
static void peer_valid(void){begin(124);value(1,4);assert(call()==125);}
static void remove_file(const char *name){walk(1,20,"work");walk(20,21,name);clunk(20);begin(122);value(21,4);assert(call()==123);}
static int64_t open_name(uint64_t owner,uint64_t ns,uint64_t gen,const char *name){return F(open_read)(owner,ns,gen,(const uint8_t*)name,strlen(name));}
static void unchanged_on_error(int64_t expected,int64_t actual){assert(expected==actual);for(unsigned i=0;i<32;i++)assert(output[i]==0xa5);}
int main(void){
 const size_t volume_bytes=16777216,max=1048576;
 volume=mmap(0,volume_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);assert(volume!=MAP_FAILED);
 payload=malloc(max);output=malloc(max+32);assert(payload&&output);
 for(size_t i=0;i<max;i++)payload[i]=(uint8_t)((i*73)^(i>>8));
 assert(S(init)((uintptr_t)volume,volume_bytes,42)==1 && S(provision_clock)(1700000000)==1);
 peer=S(session_init)(4,1);assert(peer);handshake();
 create_file("empty",payload,0);create_file("small",payload,4096);create_file("medium",payload,65536);
 uint64_t large_inode=create_file("large",payload,max);
 uint8_t *snapshot=malloc(volume_bytes);assert(snapshot);memcpy(snapshot,volume,volume_bytes);
 uint64_t independent_peer=peer,occupied=S(session_init)(1,1);assert(occupied);peer=occupied;handshake();
 uint64_t calls_before=C(encodes)();assert(F(init)(2)==-116 && C(encodes)()==calls_before);peer_valid();
 assert(S(revoke_if_current)(1,occupied)==1);peer=independent_peer;
 assert(F(init)(2)==0 && F(init)(2)==-116 && F(provision)(11,21,1)==0);peer_valid();
 const char *names[]={"/work/empty","/work/small","/work/medium","/work/large"};
 const size_t sizes[]={0,4096,65536,max};
 for(unsigned scenario=0;scenario<4;scenario++){
  int64_t fd=open_name(11,21,1,names[scenario]);assert(fd==3);memset(output,0xa5,max+32);
  assert(F(read)(11,21,1,fd,output,sizes[scenario]+17)==(int64_t)sizes[scenario]);
  assert(!memcmp(output,payload,sizes[scenario]));for(unsigned i=0;i<17;i++)assert(output[sizes[scenario]+i]==0xa5);
  assert(F(read)(11,21,1,fd,output,100)==0 && F(close)(11,21,1,fd)==0 && F(close)(11,21,1,fd)==-9);
 }
 assert(!memcmp(snapshot,volume,volume_bytes));puts("binary 0/4K/64K/1MiB reads use unchanged shared volume: PASS");
 int64_t a=open_name(11,21,1,"//work/./large");assert(a==3);int64_t b=open_name(11,21,1,"/work/large");assert(b==4);
 assert(F(read)(11,21,1,a,output,37)==37 && F(lseek)(11,21,1,a,0,1)==37 && F(lseek)(11,21,1,b,0,1)==0);
 assert(F(lseek)(11,21,1,a,-3,2)==(int64_t)max-3 && F(read)(11,21,1,a,output,10)==3 && !memcmp(output,payload+max-3,3));
 assert(F(lseek)(11,21,1,a,INT64_MIN,0)==-22 && F(lseek)(11,21,1,a,INT64_MIN,1)==-22);
 assert(F(lseek)(11,21,1,a,INT64_MAX,0)==INT64_MAX && F(lseek)(11,21,1,a,1,1)==-75 && F(lseek)(11,21,1,a,0,1)==INT64_MAX);
 assert(F(read)(11,21,1,a,output,1)==0 && F(lseek)(11,21,1,a,INT64_MAX,2)==-75 && F(lseek)(11,21,1,a,0,3)==-22);
 assert(F(lseek)(11,21,1,a,10,0)==10 && F(lseek)(11,21,1,a,-10,1)==0);
 uint64_t meta[8];for(unsigned i=0;i<8;i++)meta[i]=UINT64_C(0xfeedfacefeedface);
 assert(F(fstat)(11,21,1,a,meta+1,6)==0 && meta[0]==UINT64_C(0xfeedfacefeedface) && meta[7]==UINT64_C(0xfeedfacefeedface));
 assert(meta[1]==max && meta[2]==(0100000|0664) && meta[3]==large_inode && meta[4]>0 && meta[5]>0 && meta[6]>0);
 assert(F(fstat)(11,21,1,a,meta,5)==-22 && F(fstat)(11,21,1,a,(uint64_t*)((uint8_t*)meta+1),6)==-14);
 assert(F(read)(11,21,1,a,0,0)==0 && F(read)(11,21,1,a,0,1)==-14);
 assert(F(read)(11,21,1,a,(uint8_t*)(UINTPTR_MAX-3),4)==-14 && F(read)(11,21,1,a,output,(size_t)INT64_MAX+1)==-22);
 memset(output,0xa5,32);unchanged_on_error(-9,F(read)(12,21,1,a,output,32));unchanged_on_error(-9,F(read)(11,22,1,a,output,32));
 unchanged_on_error(-9,F(read)(11,21,2,a,output,32));unchanged_on_error(-9,F(read)(11,21,1,1000,output,32));
 assert(F(provision)(12,21,1)==0 && F(provision)(11,22,1)==0);
 int64_t other=open_name(12,21,1,"/work/small");assert(other==3 && F(read)(12,21,1,other,output,4)==4);
 assert(F(lseek)(11,21,1,a,0,1)==0 && F(lseek)(12,21,1,other,0,1)==4);
 assert(F(close)(11,21,1,a)==0 && F(close)(11,21,1,b)==0 && F(close)(12,21,1,other)==0);
 puts("owner/ns/generation keyed descriptions, independent offsets, seek/stat/buffer bounds: PASS");
 for(unsigned i=0;i<700;i++)assert(open_name(11,21,1,"/work/no-such-file")==-2);
 assert(open_name(11,21,1,"/work")==-21 && open_name(11,21,1,"/work/large/")==-20 && open_name(11,21,1,"")==-2);
 assert(open_name(11,21,1,"/work/large/child")==-20 && open_name(11,21,1,"/work/large/.")==-20 && open_name(11,21,1,"/work/large/../small")==-20);
 assert(F(open_read)(11,21,1,(const uint8_t*)"bad\0path",8)==-22 && F(open_read)(11,21,1,(const uint8_t*)1,4097)==-36);
 uint8_t long_name[262];memset(long_name,'x',sizeof long_name);memcpy(long_name,"/work/",6);assert(F(open_read)(11,21,1,long_name,sizeof long_name)==-36);
 a=open_name(11,21,1,"/work/large");assert(a==3);uint64_t prior_version=meta[4];
 walk(1,20,"work");walk(20,21,"large");clunk(20);peer_open(21,0x11);const uint8_t changed[]={0,0xff,13};write_bytes(21,0,changed,sizeof changed);clunk(21);
 assert(F(fstat)(11,21,1,a,meta,6)==0 && meta[0]==3 && meta[2]==large_inode && meta[3]>prior_version);
 assert(F(lseek)(11,21,1,a,0,2)==3 && F(lseek)(11,21,1,a,0,0)==0 && F(read)(11,21,1,a,output,32)==3 && !memcmp(output,changed,3));
 assert(F(close)(11,21,1,a)==0);puts("independent 9P frontend mutations immediately visible; failed opens clunk fids: PASS");
 create_file("victim",payload,32);a=open_name(11,21,1,"/work/victim");b=open_name(11,21,1,"/work/small");assert(a==3&&b==4);
 remove_file("victim");assert(F(read)(11,21,1,a,output,1)==-116 && F(fstat)(11,21,1,a,meta,6)==-116);
 calls_before=C(encodes)();assert(F(lseek)(11,21,1,a,0,0)==-116 && F(read)(11,21,1,a,output,0)==-116 && C(encodes)()==calls_before);
 assert(F(fstat)(11,21,1,b,meta,6)==0 && meta[0]==4096 && F(read)(11,21,1,b,output,32)==32 && !memcmp(output,payload,32));
 assert(F(close)(11,21,1,a)==0 && F(close)(11,21,1,b)==0);peer_valid();
 puts("removed object reports ESTALE without poisoning unrelated open files: PASS");
 for(unsigned i=3;i<8;i++)assert(F(provision)(100+i,200+i,1)==0);
 assert(F(provision)(999,999,1)==-28);
 uint64_t owners[8]={11,12,11,103,104,105,106,107},namespaces[8]={21,21,22,203,204,205,206,207};
 for(unsigned owner=0;owner<8;owner++){
  for(unsigned fd=0;fd<8;fd++)assert(open_name(owners[owner],namespaces[owner],1,"/work/small")==3+(int64_t)fd);
  assert(open_name(owners[owner],namespaces[owner],1,"/work/small")==-24);
 }
 assert(F(revoke)(11,21,1)==0 && F(read)(11,21,1,3,output,1)==-9 && F(read)(12,21,1,3,output,1)==1);peer_valid();
 assert(F(provision)(11,21,1)==-116 && F(provision)(11,21,2)==0 && open_name(11,21,2,"/work/small")==3);
 assert(F(provision)(11,21,3)==0 && F(read)(11,21,2,3,output,1)==-9 && open_name(11,21,3,"/work/small")==3);
 assert(F(init)(3)==0);peer_valid();
 assert(F(read)(11,21,3,3,output,1)==-9 && F(provision)(11,21,3)==-116 && F(provision)(11,21,4)==0);
 a=open_name(11,21,4,"/work/small");assert(a==3);
 assert(S(revoke)(1)==1);calls_before=C(encodes)();
 assert(F(read)(11,21,4,a,output,0)==-116 && F(lseek)(11,21,4,a,0,0)==-116 && F(lseek)(11,21,4,a,0,1)==-116);
 assert(F(close)(11,21,4,a)==-116 && F(revoke)(11,21,4)==-116 && F(provision)(11,21,5)==-116 && C(encodes)()==calls_before);peer_valid();
 assert(F(init)(4)==0 && F(provision)(11,21,4)==-116 && F(provision)(11,21,5)==0);
 a=open_name(11,21,5,"/work/small");assert(a==3 && F(read)(11,21,5,a,output,4)==4 && F(close)(11,21,5,a)==0);peer_valid();
 a=open_name(11,21,5,"/work/small");assert(a==3);independent_peer=peer;occupied=S(session_init)(1,100);assert(occupied);peer=occupied;handshake();
 calls_before=C(encodes)();assert(F(init)(101)==-116 && F(lseek)(11,21,5,a,0,0)==-116 && F(read)(11,21,5,a,output,0)==-116 && C(encodes)()==calls_before);peer_valid();
 assert(S(revoke_if_current)(1,occupied)==1);peer=independent_peer;
 assert(F(init)(101)==0 && F(provision)(11,21,5)==-116 && F(provision)(11,21,6)==0);peer_valid();
 a=open_name(11,21,6,"/work/small");assert(a==3);assert(S(init)((uintptr_t)volume,volume_bytes,43)==1);
 peer=S(session_init)(4,1);assert(peer);handshake();
 calls_before=C(encodes)();assert(F(lseek)(11,21,6,a,0,0)==-116 && F(read)(11,21,6,a,output,0)==-116 && C(encodes)()==calls_before);peer_valid();
 assert(F(init)(102)==0 && F(provision)(11,21,6)==-116 && F(provision)(11,21,7)==0);peer_valid();
 a=open_name(11,21,7,"/work/small");assert(a==3 && F(read)(11,21,7,a,output,4)==4 && F(close)(11,21,7,a)==0);
 a=open_name(11,21,7,"/work/small");assert(a==3 && S(revoke)(1)==1);calls_before=C(encodes)();
 assert(F(lseek)(11,21,7,a,0,1)==-116 && C(encodes)()==calls_before);peer_valid();
 assert(F(init)(103)==0 && F(provision)(11,21,8)==0);
 a=open_name(11,21,8,"/work/small");assert(a==3 && F(read)(11,21,8,a,output,4)==4 && F(close)(11,21,8,a)==0);
 puts("every local/file operation detects withdrawn session without wire roundtrip: PASS");
 assert(C(encodes)()>1000 && C(decodes)()==C(encodes()));
 printf("Original u9fs codec actual exchanges: %llu\n",(unsigned long long)C(encodes)());
 puts("native read-only POSIX regular-file component: PASS; no EL0/app/kernel qualification");
 return 0;
}
'''


def checked_headers(manifest, output):
    output.mkdir()
    for item in manifest["original_headers"]:
        path = Path(item["path"])
        raw = path.read_bytes()
        if path.is_symlink() or len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("original codec header changed: " + str(path))
        (output / path.name).write_bytes(raw)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native fixture requires Linux x86_64")
class PosixNamespaceFilesTests(unittest.TestCase):
    def test_readonly_regular_files_use_original_codec_and_shared_store(self):
        selected = os.environ.get("OCORE_U9FS_MANIFEST")
        if not selected:
            self.skipTest("verified original codec closure requires OCORE_U9FS_MANIFEST")
        manifest = Path(selected)
        arm_manifest = Path(os.environ.get("OCORE_U9FS_ARM_MANIFEST", str(manifest.parent.parent / "aarch64-O1-final/native-codec.json")))
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang, linker, nm = shutil.which("clang"), shutil.which("ld.lld"), shutil.which("nm")
        self.assertTrue(compiler.is_file() and clang and linker and nm, "already-built ocorec, clang, ld.lld and nm are required")
        with tempfile.TemporaryDirectory(prefix="posix-namespace-files-") as directory:
            out = Path(directory)
            frozen = CODEC.stage(manifest, out / "codec", "x86_64")
            frozen_arm = CODEC.stage(arm_manifest, out / "arm-codec", "aarch64")
            arm = json.loads(arm_manifest.read_text())
            native = json.loads(manifest.read_text())
            for isa, original in (("x86_64", native), ("aarch64", arm)):
                checked_headers(original, out / (isa + "-headers"))
                (out / "abi.c").write_text(ABI)
                includes = [str(out / (isa + "-headers")), *original["include_roots"][1:]]
                result = subprocess.run([clang, "--target=" + isa + "-unknown-linux-musl", "-ffreestanding", "-nostdinc",
                                         *[value for path in includes for value in ("-I", path)], "-fsyntax-only", str(out / "abi.c")],
                                        capture_output=True, text=True, timeout=60, cwd=out)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            (out / "harness.c").write_text(HARNESS)
            sources = [str(ROOT / "ocore/runtime/common" / name) for name in ("namespace_store.oc", "u9fs_codec.oc", "posix_namespace_files.oc")]
            commands = [
                [str(compiler), *sources, "--target", "aarch64-unknown-none", "--emit", "obj", "-o", str(out / "arm.o")],
                [str(compiler), *sources, "--target", "x86_64-unknown-none", "--emit", "obj", "-o", str(out / "native.o")],
                [linker, "-r", "-o", str(out / "arm-closed.o"), str(out / "arm.o"), *[item["path"] for item in frozen_arm["objects"]]],
                [linker, "-r", "-o", str(out / "native-closed.o"), str(out / "native.o"), *[item["path"] for item in frozen["objects"]]],
                [clang, "-O2", "-no-pie", "-I", str(out / "x86_64-headers"), str(out / "harness.c"), str(out / "native-closed.o"), "-o", str(out / "test")],
                [str(out / "test")],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, text=True, timeout=90, cwd=out)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("native read-only POSIX regular-file component: PASS", result.stdout)
            for artifact in ("arm-closed.o", "native-closed.o"):
                result = subprocess.run([nm, "--undefined-only", str(out / artifact)], capture_output=True, text=True, timeout=60, cwd=out)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "", "native service closure must not import host libc/syscalls")


if __name__ == "__main__":
    unittest.main()
