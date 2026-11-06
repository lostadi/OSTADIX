"""Actual original-codec wire versus opt-in native-local common OFD service.

Both sides execute complete production O-core objects. Historical fixtures bind
exact reviewed8fa/ad8 source, never a C policy model. Compare the full volume,
15 authoritative store arrays/words and common OFD/context state after every
public operation and independent wire-peer operation. Local codec counters
must stay unchanged. Actual CPL3 remains a separate private hardware gate.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from tests import test_namespace_local_backend as CORE
from tests import test_posix_namespace_files as NS
from tests import test_posix_writable_files as WR
from tests import test_posix_file_syscalls as SYS

ROOT = Path(__file__).resolve().parents[1]
COMMON_STATE = ('SESSION','SERVICE_GENERATION','ACTIVE','NEXT_FID','OWNER','NAMESPACE','GENERATION','ENABLED','FD_DESCRIPTION','DESCRIPTION_OWNER','FID','POSITION','IO_UNIT','STALE_DESCRIPTION','REFERENCES','FILE_FLAGS')
REF_STORE = 'runtime::common::namespace_store_reference'
REF_FILES = 'runtime::common::posix_namespace_files_reference'
STORE_PREFIX = '_O_runtime__common__namespace_store'
FILES_PREFIX = '_O_runtime__common__posix_namespace_files'
BASELINES = {'namespace_store_before_direct.oc.txt':'db6d91df7e2055e17d00f773c7c86fb5019090b969e401d7f820d44dae5b92b1','posix_namespace_files_before_direct.oc.txt':'27d633fbeb2a6e6e9c634788c56262a8c00840da157e5fdc9565907c7858bb6e'}

# Signatures are declarations of the production ABI, not reimplementations.
SIGNATURES = [
 ('provision','uint64_t owner,uint64_t ns,uint64_t gen','owner,ns,gen'),
 ('revoke','uint64_t owner,uint64_t ns,uint64_t gen','owner,ns,gen'),
 ('retire','uint64_t owner,uint64_t ns,uint64_t gen','owner,ns,gen'),
 ('open_file','uint64_t owner,uint64_t ns,uint64_t gen,const uint8_t *path,size_t length,uint64_t flags,uint64_t mode','owner,ns,gen,path,length,flags,mode'),
 ('open_read','uint64_t owner,uint64_t ns,uint64_t gen,const uint8_t *path,size_t length','owner,ns,gen,path,length'),
 ('write','uint64_t owner,uint64_t ns,uint64_t gen,int64_t fd,const uint8_t *input,size_t length','owner,ns,gen,fd,input,length'),
 ('lseek','uint64_t owner,uint64_t ns,uint64_t gen,int64_t fd,int64_t offset,uint64_t whence','owner,ns,gen,fd,offset,whence'),
 ('close','uint64_t owner,uint64_t ns,uint64_t gen,int64_t fd','owner,ns,gen,fd'),
 ('duplicate','uint64_t owner,uint64_t ns,uint64_t gen,int64_t fd','owner,ns,gen,fd'),
 ('duplicate_to','uint64_t owner,uint64_t ns,uint64_t gen,int64_t fd,int64_t target','owner,ns,gen,fd,target'),
]

def paired_abi():
    state = r'''
#define FR(n) _O_runtime__common__posix_namespace_files_reference__##n
#define FN(n) _O_runtime__common__posix_namespace_files__##n
extern uint64_t _O_runtime__common__u9fs_codec__encodes(void),_O_runtime__common__u9fs_codec__decodes(void);
extern int64_t FR(init)(uint64_t),FN(init_backend)(uint64_t,uint64_t);
#define FSTATE(P) \
 extern uint64_t P(SESSION),P(SERVICE_GENERATION),P(ACTIVE),P(NEXT_FID); \
 extern uint64_t P(OWNER)[8],P(NAMESPACE)[8],P(GENERATION)[8],P(ENABLED)[8]; \
 extern uint64_t P(FD_DESCRIPTION)[64],P(DESCRIPTION_OWNER)[64],P(FID)[64],P(POSITION)[64],P(IO_UNIT)[64],P(STALE_DESCRIPTION)[64],P(REFERENCES)[64],P(FILE_FLAGS)[64];
FSTATE(FR)
FSTATE(FN)
static uint64_t local_operations;
#define FSAME(n) do { if(memcmp(&FR(n),&FN(n),sizeof FR(n))){fprintf(stderr,"OFD state differs: %s\n",#n);abort();} }while(0)
static void file_state(void){
'''+''.join(' FSAME('+x+');\n' for x in COMMON_STATE)+'''}
static uint64_t codec_count(void){return _O_runtime__common__u9fs_codec__encodes()+_O_runtime__common__u9fs_codec__decodes();}
'''
    pair = CORE.PAIR.replace('#define REF(n) _O_runtime__common__namespace_store_baseline__##n', '#define REF(n) _O_runtime__common__namespace_store_reference__##n')
    pair = pair.replace(' pair_states++;',' file_state();pair_states++;')
    pair = pair.replace('#define NS(name) PAIR_##name','')
    wrappers = r'''
int64_t FPAIR_init(uint64_t gen){int64_t a=FR(init)(gen);uint64_t c=codec_count();int64_t b=FN(init_backend)(gen,1);assert(codec_count()==c);assert(a==b);local_operations++;pair_state();return a;}
'''
    for name,params,args in SIGNATURES:
        wrappers += f'extern int64_t FR({name})({params}),FN({name})({params});\n'
        wrappers += f'int64_t FPAIR_{name}({params}){{int64_t a=FR({name})({args});uint64_t c=codec_count();int64_t b=FN({name})({args});assert(codec_count()==c);if(a!=b){{fprintf(stderr,"{name} differs: %lld/%lld\\n",(long long)a,(long long)b);abort();}}local_operations++;pair_state();return a;}}\n'
    wrappers += r'''
extern int64_t FR(read)(uint64_t,uint64_t,uint64_t,int64_t,uint8_t*,size_t),FN(read)(uint64_t,uint64_t,uint64_t,int64_t,uint8_t*,size_t);
int64_t FPAIR_read(uint64_t owner,uint64_t ns,uint64_t gen,int64_t fd,uint8_t *output,size_t length){
 uint8_t *copy=output;int separate=output&&(uintptr_t)output>4096&&length<=19*1048576&&(uintptr_t)output<=UINTPTR_MAX-length;
 if(separate){copy=malloc(length?length:1);assert(copy);memcpy(copy,output,length);}
 int64_t a=FR(read)(owner,ns,gen,fd,output,length);uint64_t c=codec_count();int64_t b=FN(read)(owner,ns,gen,fd,copy,length);
 assert(codec_count()==c);assert(a==b);if(separate){assert(!memcmp(output,copy,length));free(copy);}local_operations++;pair_state();return a;
}
extern int64_t FR(fstat)(uint64_t,uint64_t,uint64_t,int64_t,uint64_t*,size_t),FN(fstat)(uint64_t,uint64_t,uint64_t,int64_t,uint64_t*,size_t);
int64_t FPAIR_fstat(uint64_t owner,uint64_t ns,uint64_t gen,int64_t fd,uint64_t *out,size_t words){
 uint64_t record[8];int separate=out&&(uintptr_t)out%8==0&&words>=6&&words<=8;
 if(separate)memcpy(record,out,words*8);
 int64_t a=FR(fstat)(owner,ns,gen,fd,out,words);uint64_t c=codec_count();int64_t b=FN(fstat)(owner,ns,gen,fd,separate?record:out,words);
 assert(codec_count()==c);assert(a==b);if(separate)assert(!memcmp(record,out,words*8));local_operations++;pair_state();return a;
}
'''
    return state+pair+wrappers+'\n#define S(n) PAIR_##n\n'

EXTRA = r'''
extern uint64_t NEW(local_version)(uint64_t,size_t,uint64_t*,size_t),NEW(local_attach)(uint64_t,uint64_t,uint64_t*,size_t);
extern uint64_t NEW(local_clone)(uint64_t,uint64_t,uint64_t,uint64_t*,size_t),NEW(local_walk_one)(uint64_t,uint64_t,uint64_t,const uint8_t*,size_t,uint64_t*,size_t);
extern uint64_t NEW(local_open)(uint64_t,uint64_t,uint64_t,uint64_t*,size_t),NEW(local_create)(uint64_t,uint64_t,const uint8_t*,size_t,uint64_t,uint64_t,uint64_t*,size_t);
extern uint64_t NEW(local_read)(uint64_t,uint64_t,uint64_t,uint8_t*,size_t,uint64_t*,size_t),NEW(local_write)(uint64_t,uint64_t,uint64_t,const uint8_t*,size_t,uint64_t*,size_t);
extern uint64_t NEW(local_stat)(uint64_t,uint64_t,uint64_t*,size_t),NEW(local_clunk)(uint64_t,uint64_t,uint64_t*,size_t);
static uint64_t raw_s,raw_result[8];static uint8_t raw_bytes[8192];
static uint64_t wire_code(size_t n){
 if(!n)return 11;if(reply[4]!=107)return 0;
 const char *errors[]={"","Protocol error","permission denied","file does not exist","fid unknown or out of range","No space left on device","file already exists","not a directory","directory is not empty","Operation not supported"};
 for(unsigned i=1;i<=9;i++)if(get(reply+7,2)==strlen(errors[i])&&!memcmp(reply+9,errors[i],strlen(errors[i])))return i;
 abort();
}
static size_t raw_wire(size_t cap){put(request,position,4);return REF(handle)(raw_s,request,position,reply,cap);}
#define RAW(expression,capacity) do {size_t wire_n=raw_wire(capacity);uint64_t before=codec_count(),saved_result[8];memcpy(saved_result,raw_result,sizeof saved_result);uint64_t actual=(expression);assert(codec_count()==before);if(actual)assert(!memcmp(saved_result,raw_result,sizeof saved_result));uint64_t expected=wire_code(wire_n);if(actual!=expected){fprintf(stderr,"typed/wire code differs kind%u cap%zu: %llu/%llu\n",request[4],(size_t)(capacity),(unsigned long long)actual,(unsigned long long)expected);abort();}pair_operations++;pair_state();}while(0)
static void raw_version(size_t size,size_t cap,size_t words){begin(100);value(size,4);string("9P2000");RAW(NEW(local_version)(raw_s,size,raw_result,words),cap);}
static void raw_attach(unsigned fid,size_t cap,size_t words){begin(104);value(fid,4);value(UINT32_MAX,4);string("");string("");RAW(NEW(local_attach)(raw_s,fid,raw_result,words),cap);}
static void raw_clone(unsigned from,unsigned to,size_t cap,size_t words){begin(110);value(from,4);value(to,4);value(0,2);RAW(NEW(local_clone)(raw_s,from,to,raw_result,words),cap);}
static void raw_walk(unsigned from,unsigned to,const char *name,size_t cap,size_t words){begin(110);value(from,4);value(to,4);value(1,2);string(name);RAW(NEW(local_walk_one)(raw_s,from,to,(const uint8_t*)name,strlen(name),raw_result,words),cap);}
static void raw_create(unsigned fid,const char*name,unsigned mode,unsigned access,size_t cap,size_t words){begin(114);value(fid,4);string(name);value(mode,4);value(access,1);RAW(NEW(local_create)(raw_s,fid,(const uint8_t*)name,strlen(name),mode,access,raw_result,words),cap);}
static void raw_open(unsigned fid,unsigned mode,size_t cap,size_t words){begin(112);value(fid,4);value(mode,1);RAW(NEW(local_open)(raw_s,fid,mode,raw_result,words),cap);}
static void raw_read(unsigned fid,uint64_t offset,unsigned count_,size_t cap,size_t words){
 memset(raw_bytes,0xa5,sizeof raw_bytes);begin(116);value(fid,4);value(offset,8);value(count_,4);
 RAW(NEW(local_read)(raw_s,fid,offset,raw_bytes,count_,raw_result,words),cap);
 if(reply[4]==117&&cap>=11){size_t n=get(reply+7,4);assert(raw_result[0]==n&&!memcmp(raw_bytes,reply+11,n));for(size_t i=n;i<sizeof raw_bytes;i++)assert(raw_bytes[i]==0xa5);}
}
static void raw_write(unsigned fid,uint64_t offset,size_t count_,size_t cap,size_t words){begin(118);value(fid,4);value(offset,8);value(count_,4);memcpy(request+position,payload,count_);position+=count_;RAW(NEW(local_write)(raw_s,fid,offset,payload,count_,raw_result,words),cap);}
static void raw_stat(unsigned fid,size_t cap,size_t words){
 begin(124);value(fid,4);RAW(NEW(local_stat)(raw_s,fid,raw_result,words),cap);
 if(reply[4]==125&&cap>=9+get(reply+7,2)){
  assert(raw_result[0]==reply[17]&&raw_result[1]==get(reply+18,4)&&raw_result[2]==get(reply+22,8));
  assert(raw_result[4]==get(reply+30,4)&&raw_result[5]==get(reply+34,4)&&raw_result[6]==get(reply+38,4)&&raw_result[7]==get(reply+42,8));
 }
}
static void raw_clunk(unsigned fid,size_t cap,size_t words){begin(120);value(fid,4);RAW(NEW(local_clunk)(raw_s,fid,raw_result,words),cap);}
static void typed_boundaries(void){
 raw_s=PAIR_session_init(2,1);assert(raw_s);raw_attach(1,8192,8);assert(wire_code(get(reply,4))==1);
 raw_version(8192,18,0);raw_version(255,8192,8);raw_version(8192,8192,8);assert(raw_result[0]==8192);
 raw_attach(1,19,2);raw_attach(1,8192,8);raw_clone(1,2,8,0);raw_clone(1,2,8192,8);
 uint64_t before=codec_count();assert(NEW(local_stat)(raw_s,1,raw_result,8)==10&&NEW(local_open)(raw_s,1,0,raw_result,8)==10&&codec_count()==before);pair_state();
 raw_walk(2,2,"..",8192,8);raw_walk(2,3,"pkg",8192,8);assert(wire_code(get(reply,4))==3);
 raw_create(2,"typed",0644|0x04000000,2,23,3);raw_create(2,"typed",0644|0x04000000,2,8192,8);
 assert(raw_result[0]==4&&raw_result[3]==8168);raw_write(2,0,8169,10,0);raw_write(2,0,8169,8192,8);assert(raw_result[0]==8169);
 raw_read(2,0,UINT32_MAX,10,0);raw_read(2,0,UINT32_MAX,8192,8);assert(raw_result[0]==8169);
 raw_stat(2,8,7);raw_stat(2,8192,8);assert(raw_result[7]==8169);
 raw_clunk(2,6,0);raw_clunk(2,8192,8);
 raw_walk(1,2,"typed",8192,8);raw_open(2,0,23,3);raw_open(2,0,8192,8);raw_write(2,0,1,8192,8);assert(wire_code(get(reply,4))==2);raw_clunk(2,8192,8);
 raw_walk(1,2,"typed",8192,8);raw_open(2,1,8192,8);raw_read(2,0,1,8192,8);assert(wire_code(get(reply,4))==2);raw_clunk(2,8192,8);
 raw_version(256,8192,8);raw_attach(1,8192,8);raw_walk(1,2,"typed",8192,8);raw_open(2,2,8192,8);
 raw_read(2,0,UINT32_MAX,8192,8);assert(raw_result[0]==245);raw_write(2,0,233,8192,8);raw_write(2,0,234,8192,8);assert(wire_code(get(reply,4))==1);
 raw_read(2,UINT64_MAX,1,8192,8);assert(raw_result[0]==0);raw_write(2,UINT64_MAX,1,8192,8);assert(wire_code(get(reply,4))==5);
 assert(PAIR_provision_clock(UINT32_MAX-1)==1);raw_write(2,0,0,8192,8);assert(wire_code(get(reply,4))==5);
 raw_clone(1,3,8192,8);raw_walk(3,3,"typed",8192,8);raw_open(3,0x12,23,3);raw_open(3,0x12,8192,8);assert(wire_code(get(reply,4))==5);
}
static void typed_grants(void){
 raw_s=PAIR_session_init(3,1);assert(raw_s);raw_version(8192,8192,8);raw_attach(1,8192,8);
 raw_clone(1,2,8192,8);raw_create(2,"denied",0644,1,8192,8);assert(wire_code(get(reply,4))==2);
 raw_open(1,1,8192,8);assert(wire_code(get(reply,4))==2);raw_clunk(2,8192,8);raw_walk(1,2,"..",8192,8);raw_walk(2,3,"pkg",8192,8);assert(wire_code(get(reply,4))==3);
 uint64_t old=raw_s;assert(PAIR_session_claim(3,2,old+1)==0);uint64_t fresh=PAIR_session_claim(3,2,old);assert(fresh&&fresh!=old);
 raw_attach(50,8192,8);assert(wire_code(get(reply,4))==4);raw_version(256,8192,8);assert(wire_code(get(reply,4))==4);raw_s=fresh;raw_attach(50,8192,8);assert(wire_code(get(reply,4))==1);
 raw_version(8192,8192,8);raw_attach(1,8192,8);
 unsigned exhausted=0;for(unsigned i=2;i<700;i++){raw_clone(1,i,8192,8);if(wire_code(get(reply,4))==5){exhausted=i;break;}assert(wire_code(get(reply,4))==0);}
 assert(exhausted>500&&exhausted<513);raw_clone(1,700,8192,8);assert(wire_code(get(reply,4))==5);
 for(unsigned i=2;i<exhausted;i++)raw_clunk(i,8192,8);
 assert(PAIR_revoke_if_current(3,old)==0&&PAIR_revoke_if_current(3,fresh)==1);raw_clunk(1,8192,8);assert(wire_code(get(reply,4))==4);
}

#include <time.h>
static uint64_t nanoseconds(void){struct timespec ts;assert(!clock_gettime(CLOCK_MONOTONIC_RAW,&ts));return (uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec;}
static void benchmark(int argc,char **argv){
 assert(argc==6);int local=!strcmp(argv[2],"local"),writing=!strcmp(argv[3],"write");size_t bytes=strtoull(argv[4],0,10),iterations=strtoull(argv[5],0,10);assert(bytes<=1048576&&iterations);
 create_file("benchmark",payload,bytes);int64_t fd=open_("/work/benchmark",2,0);assert(fd==3);
 int64_t (*seek_fn)(uint64_t,uint64_t,uint64_t,int64_t,int64_t,uint64_t)=local?FN(lseek):FR(lseek);
 int64_t (*read_fn)(uint64_t,uint64_t,uint64_t,int64_t,uint8_t*,size_t)=local?FN(read):FR(read);
 int64_t (*write_fn)(uint64_t,uint64_t,uint64_t,int64_t,const uint8_t*,size_t)=local?FN(write):FR(write);
 // Identical trusted-buffer common-service carrier, backing state and warmup.
 // No host file syscall, usercopy aperture, privilege change or Linuxmemfd is
 // inside this measurement. Both profiles retain8168B store transactions.
 for(unsigned i=0;i<3;i++){assert(seek_fn(11,21,1,fd,0,0)==0);assert((writing?write_fn(11,21,1,fd,payload,bytes):read_fn(11,21,1,fd,output,bytes))==(int64_t)bytes);}
 uint64_t enc0=_O_runtime__common__u9fs_codec__encodes(),dec0=_O_runtime__common__u9fs_codec__decodes(),started=nanoseconds();
 for(size_t i=0;i<iterations;i++){
  assert(seek_fn(11,21,1,fd,0,0)==0);
  if(writing)assert(write_fn(11,21,1,fd,payload,bytes)==(int64_t)bytes);
  else assert(read_fn(11,21,1,fd,output,bytes)==(int64_t)bytes&&!memcmp(output,payload,bytes));
 }
 uint64_t elapsed=nanoseconds()-started,enc=_O_runtime__common__u9fs_codec__encodes()-enc0,dec=_O_runtime__common__u9fs_codec__decodes()-dec0;
 if(local)assert(enc==0&&dec==0);
 printf("{\"backend\":\"%s\",\"operation\":\"%s\",\"bytes\":%zu,\"iterations\":%zu,\"elapsed_ns\":%llu,\"codec_encodes\":%llu,\"codec_decodes\":%llu,\"user_copy_calls\":0}\n",local?"local":"wire",writing?"write":"read",bytes,iterations,(unsigned long long)elapsed,(unsigned long long)enc,(unsigned long long)dec);
}

static void binary_sizes(void){
 const size_t sizes[]={0,4096,65536,1048576};
 for(unsigned i=0;i<4;i++){
  char path[64];snprintf(path,sizeof path,"/work/binary-%zu",sizes[i]);
  int64_t fd=open_(path,2|64|128,0600);assert(fd==3&&write_(fd,payload,sizes[i])==(int64_t)sizes[i]);
  assert(seek_(fd,0,0)==0);memset(output,0xa5,1048576+32);
  assert(read_(fd,output,sizes[i]+17)==(int64_t)sizes[i]&&!memcmp(output,payload,sizes[i]));
  for(unsigned n=0;n<17;n++)assert(output[sizes[i]+n]==0xa5);
  assert(read_(fd,output,1)==0&&close_(fd)==0);verify_peer(path+6,payload,sizes[i]);
 }
}
'''

def common_harness():
    source = WR.COMMON.replace('#define S(n) _O_runtime__common__namespace_store__##n',paired_abi()).replace('#define F(n) _O_runtime__common__posix_namespace_files__##n','#define F(n) FPAIR_##n')
    source = source.replace('int main(int argc,char**argv){',EXTRA+'\nint main(int argc,char**argv){').replace('assert(argc==2);','assert(argc>=2);')
    source = source.replace(' }else abort();',' }else if(!strcmp(argv[1],"binary-sizes")){binary_sizes();}else if(!strcmp(argv[1],"typed-boundaries")){typed_boundaries();}else if(!strcmp(argv[1],"typed-grants")){typed_grants();}else if(!strcmp(argv[1],"bench")){benchmark(argc,argv);return 0;}else abort();')
    source = source.replace(' printf("native writable common', ' uint64_t prior=codec_count();assert(FN(init_backend)(99,99)==-22&&codec_count()==prior);pair_state();\n printf("paired public operations=%llu complete states=%llu local codec calls=0\\n",(unsigned long long)local_operations,(unsigned long long)pair_states);\n printf("native writable common')
    return source

@unittest.skipUnless(platform.system()=='Linux' and platform.machine()=='x86_64','actual native host profile requires Linux x86_64')
class NativeLocalNamespaceFilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler=Path(os.environ.get('OCOREC_BIN',ROOT/'target/debug/ocorec'))
        selected=os.environ.get('OCORE_U9FS_MANIFEST'); arm_selected=os.environ.get('OCORE_U9FS_ARM_MANIFEST')
        clang,linker,objcopy,nm=shutil.which('clang'),shutil.which('ld.lld'),shutil.which('objcopy'),shutil.which('nm')
        if not cls.compiler.is_file() or not selected or not arm_selected or not all([clang,linker,objcopy,nm]): raise unittest.SkipTest('pinned compiler + actual original source codec manifests/link tools required')
        cls.output=Path(tempfile.mkdtemp(prefix='native-local-files-'));out=cls.output
        cls.commands=[]
        frozen=NS.CODEC.stage(Path(selected),out/'codec','x86_64'); arm=NS.CODEC.stage(Path(arm_selected),out/'arm-codec','aarch64')
        NS.checked_headers(json.loads(Path(selected).read_text()),out/'headers')
        for name,want in BASELINES.items():
            raw=(ROOT/'tests/fixtures'/name).read_bytes()
            if hashlib.sha256(raw).hexdigest()!=want:raise AssertionError('historical source fixture identity changed')
            if name.startswith('namespace_store'):raw=raw.replace(b'module runtime::common::namespace_store;',b'module runtime::common::namespace_store_reference;',1);target=out/'store-reference.oc'
            else:raw=raw.replace(b'runtime::common::namespace_store::',b'runtime::common::namespace_store_reference::').replace(b'module runtime::common::posix_namespace_files;',b'module runtime::common::posix_namespace_files_reference;',1);target=out/'files-reference.oc'
            target.write_bytes(raw)
        common=[ROOT/'ocore/runtime/common'/(x+'.oc') for x in ['namespace_store','u9fs_codec','posix_namespace_files']]
        sources=[out/'store-reference.oc',out/'files-reference.oc',*common]
        for isa,closure in [('aarch64',arm),('x86_64',frozen)]:
            cls.run_build([str(cls.compiler),*map(str,sources),'--target',isa+'-unknown-none','--emit','obj','-o',str(out/(isa+'.o'))])
            cls.run_build([linker,'-r','-o',str(out/(isa+'-closed.o')),str(out/(isa+'.o')),*[x['path'] for x in closure['objects']]])
            if cls.run_build([nm,'-u',str(out/(isa+'-closed.o'))]).strip():raise AssertionError('undeclared native dependency closure')
        globalize=[]
        for suffix in ['','_reference']:
            globalize += ['--globalize-symbol='+STORE_PREFIX+suffix+'__'+x for x in CORE.STATE]
            globalize += ['--globalize-symbol='+FILES_PREFIX+suffix+'__'+x for x in COMMON_STATE]
        cls.run_build([objcopy,*globalize,str(out/'x86_64-closed.o'),str(out/'inspectable.o')])
        (out/'common.c').write_text(common_harness())
        cls.run_build([clang,'-O2','-no-pie','-I',str(out/'headers'),str(out/'common.c'),str(out/'inspectable.o'),'-o',str(out/'common')])
        # Same production current-process/usercopy adapter, selected only by
        # trusted native initialization. C supplies privileged hooks and input.
        kernel_sources=[ROOT/'ocore/runtime/x86_64'/(name+'.oc') for name in SYS.MODULES]+common
        cls.run_build([str(cls.compiler),*map(str,kernel_sources),'--target','x86_64-unknown-none','--emit','obj','-o',str(out/'kernel.o')])
        cls.run_build([linker,'-r','-o',str(out/'kernel-closed.o'),str(out/'kernel.o'),*[x['path'] for x in frozen['objects']]])
        undefined=cls.run_build([nm,'-u',str(out/'kernel-closed.o')])
        if {line.split()[-1] for line in undefined.splitlines()}!=SYS.ARCH_SYMBOLS:raise AssertionError('undeclared kernel architecture dependency')
        prefix,body=WR.KERNEL.split('int main(void){',1)
        body=re.sub(r'K\(init\)\((\d+)\)',r'K(init_backend)(\1,1)',body)
        if 'K(init_backend)' not in body:raise AssertionError('no actual trusted initialization selected')
        body=body.replace('puts("native kernel writable calls:', 'assert(C(encodes)()==0);printf("local usercopy from=%zu to=%zu codec=0\\n",from_calls,to_calls);puts("native kernel writable calls:')
        (out/'kernel.c').write_text(prefix+'extern int64_t K(init_backend)(uint64_t,uint64_t);\nint main(void){'+body)
        cls.run_build([clang,'-O2','-no-pie','-I',str(out/'headers'),str(out/'kernel.c'),str(out/'kernel-closed.o'),'-o',str(out/'kernel')])
        (out/'build.json').write_text(json.dumps(cls.commands,indent=2)+'\n')
    @classmethod
    def run_build(cls,args):
        result=subprocess.run(args,capture_output=True,text=True,timeout=120,cwd=cls.output)
        (cls.output/('build-'+str(len(cls.commands))+'.log')).write_text(result.stdout+result.stderr)
        cls.commands.append({'argv':args,'exit_code':result.returncode})
        if result.returncode:raise AssertionError(result.stdout+result.stderr+'\nEvidence: '+str(cls.output))
        return result.stdout
    def run_case(self,name):
        result=subprocess.run([str(self.output/'common'),name],capture_output=True,text=True,timeout=120)
        (self.output/(name+'.log')).write_text(result.stdout+result.stderr)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr+'\nEvidence: '+str(self.output))
        self.assertIn('local codec calls=0',result.stdout)
    def test_binary_0_4k_64k_1m_full_volume_and_state(self):self.run_case('binary-sizes')
    def test_create_alias_and_independent_wire_reads(self):self.run_case('create-alias')
    def test_append_independent_wire_write_and_truncate(self):self.run_case('append-truncate')
    def test_dup_close_exhaustion_and_revoke(self):self.run_case('dup-replace-revoke')
    def test_errors_and_lifetime_preflights(self):self.run_case('errors')
    def test_real_enospc_transaction_prefix_state(self):self.run_case('space-partial')
    def test_removed_object_and_alias_staleness(self):self.run_case('stale-alias')
    def test_typed_result_capacity_modes_and_transaction_boundaries(self):self.run_case('typed-boundaries')
    def test_typed_root_grant_session_and_fid_exhaustion(self):self.run_case('typed-grants')
    def test_kernel_checked_usercopies_keep_the_local_backend(self):
        result=subprocess.run([str(self.output/'kernel')],capture_output=True,text=True,timeout=90)
        (self.output/'kernel.log').write_text(result.stdout+result.stderr)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr+'\nEvidence: '+str(self.output))
        self.assertIn('codec=0',result.stdout)

if __name__=='__main__':unittest.main()
