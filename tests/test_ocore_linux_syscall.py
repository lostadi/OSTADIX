"""Typed original Linux syscall ABI, not Linux kernel/runtime closure.

Original musl getuid is a complete unchanged component. The seven arity
functions and freestanding Clang driver/bootstrap are separately authored tests.
All effects execute only in bounded owned child processes using a supplied
Linux kernel or guarded QEMU-user provider. No compiler operation executes them.
"""
import copy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import struct
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SDK_DEFAULT = Path.home()/'.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin'
LIB_DEFAULT = Path.home()/'.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/lib/libLLVM.so.22.1-rust-1.97.1-stable'
LIB_SHA = 'ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09'
UNITS = {'x86_64':'6babdc530582466cae1342c00017e577', 'aarch64':'52cb2b1a46814a96a5338a44b7ebb9a6', 'riscv64':'1a69ac1eb63b4a98b8b7ec5c12648136'}
RAW = {
 'x86_64': ('syscall', ['={ax}','{ax}'], ['{di}','{si}','{dx}','{r10}','{r8}','{r9}'], ['~{rcx}','~{r11}','~{memory}','~{dirflag}','~{fpsr}','~{flags}']),
 'aarch64': ('svc 0', ['={x0}','{x8}'], ['{x0}','{x1}','{x2}','{x3}','{x4}','{x5}'], ['~{memory}','~{cc}']),
 'riscv64': ('ecall\\0A\\09', ['={x10}','{x17}'], ['{x10}','{x11}','{x12}','{x13}','{x14}','{x15}'], ['~{memory}']),
}


def identity(path):
    path=Path(path)
    return {'path':str(path.resolve()),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


def source_module(isa, original):
    template, fixed, inputs, clobbers=RAW[isa]
    header='\n'.join(line for line in original.splitlines() if line.startswith(('target datalayout','target triple')))
    lines=[header]
    for arity in range(7):
        params=', '.join('i64 %'+name for name in ['nr']+['a'+str(i) for i in range(arity)])
        arguments=', '.join('i64 %'+name for name in ['nr']+['a'+str(i) for i in range(arity)])
        constraint=','.join(fixed+inputs[:arity]+clobbers)
        lines.append(f'define i64 @raw{arity}({params}) strictfp {{\n %r = call i64 asm sideeffect "{template}", "{constraint}"({arguments}) nounwind strictfp, !srcloc !0\n ret i64 %r\n}}')
    # Matching LP64D source module flag is retained, rather than changing the
    # original source target to the emitter's freestanding catalog spelling.
    if isa=='riscv64':
        lines += ['!llvm.module.flags = !{!1}', '!1 = !{i32 1, !"target-abi", !"lp64d"}']
    lines.append('!0 = !{i64 0, i64 18446744073709551615}')
    return '\n'.join(lines)+'\n'


def executable_elf(path,isa):
    data=Path(path).read_bytes()
    assert data[:7]==b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from('<HH',data,16)==(2,{'x86_64':62,'aarch64':183,'riscv64':243}[isa])
    flags=struct.unpack_from('<I',data,48)[0]
    assert flags&~1==4 if isa=='riscv64' else flags==0
    offset=struct.unpack_from('<Q',data,32)[0]
    stride,count=struct.unpack_from('<HH',data,54)
    assert stride==56 and offset+stride*count<=len(data)
    for i in range(count):
        kind,permissions=struct.unpack_from('<II',data,offset+stride*i)
        assert kind!=3, 'test carrier must not hide a dynamic PT_INTERP runtime'
        assert kind!=1 or permissions&3!=3, 'writable executable LOAD is outside this carrier profile'


def platform_note(path):
    data=Path(path).read_bytes()
    assert data[:7]==b'\x7fELF\x02\x01\x01'
    shoff=struct.unpack_from('<Q',data,40)[0]
    count=struct.unpack_from('<H',data,60)[0]
    found=[]
    for i in range(count):
        fields=struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i)
        if fields[1]!=7: continue
        chunk=data[fields[4]:fields[4]+fields[5]]
        if len(chunk)>=20 and chunk[12:18]==b'Ocore\0':
            namesz,descsz,kind=struct.unpack_from('<III',chunk)
            assert namesz==6 and kind==1 and fields[2]==2 and fields[8]==4
            assert chunk[18:20]==b'\0\0' and len(chunk)==(20+descsz+3)//4*4
            found.append(json.loads(chunk[20:20+descsz]))
    assert len(found)==1,found
    return found[0]


# This test-only carrier is never imported as musl implementation or native
# platform provider. Every syscall below is confined to the owned child, files,
# descriptors and mappings. Addresses are recorded, compared by declared
# semantic relationships, and never rewritten to disguise a failing oracle.
CARRIER = r'''
#ifndef FENV_ROUND
#define FENV_ROUND 1
#endif
typedef unsigned long U; typedef long S;
extern unsigned getuid(void);
extern S ordered_write(S,unsigned char*);
extern S raw0(S),raw1(S,S),raw2(S,S,S),raw3(S,S,S,S),raw4(S,S,S,S,S),raw5(S,S,S,S,S,S),raw6(S,S,S,S,S,S,S);
_Static_assert(sizeof(U)==8 && sizeof(S)==8 && sizeof(unsigned)==4,"declared Linux LP64 carrier ABI");
#if defined(__x86_64__)
#define NR_UID 102
#define NR_CLOSE 3
#define NR_TRUNC 77
#define NR_WRITE 1
#define NR_READ 0
#define NR_OPENAT 257
#define NR_MEMFD 319
#define NR_PIPE2 293
#define NR_LSEEK 8
#define NR_MMAP 9
#define NR_REMAP 25
#define NR_PWRITE 18
#define NR_PREAD 17
#define NR_UMASK 95
static S setup(U nr,U a,U b,U c,U d,U e,U f){register U r10 __asm__("r10")=d;register U r8 __asm__("r8")=e;register U r9 __asm__("r9")=f;S r;__asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory","cc");return r;}
static void fenv_set(void){unsigned x=0x1f80|(FENV_ROUND<<13)|0x3f;unsigned env[7]={0x037f|(FENV_ROUND<<10),0x3f,0xffff,0,0,0,0};__asm__ volatile("ldmxcsr %0;fldenv %1"::"m"(x),"m"(env):"memory");}
static int fenv_expected(U *v){return v[0]==(0x1f80U|(FENV_ROUND<<13)|0x3fU)&&v[1]==(0x037fU|(FENV_ROUND<<10))&&v[2]==0x3f;}
static void fenv_get(U *v){unsigned x;unsigned short c,s;__asm__ volatile("stmxcsr %0;fnstcw %1;fnstsw %2":"=m"(x),"=m"(c),"=m"(s)::"memory");v[0]=x;v[1]=c;v[2]=s;}
#elif defined(__aarch64__)
#define NR_UID 174
#define NR_CLOSE 57
#define NR_TRUNC 46
#define NR_WRITE 64
#define NR_READ 63
#define NR_OPENAT 56
#define NR_MEMFD 279
#define NR_PIPE2 59
#define NR_LSEEK 62
#define NR_MMAP 222
#define NR_REMAP 216
#define NR_PWRITE 68
#define NR_PREAD 67
#define NR_UMASK 166
static S setup(U nr,U a,U b,U c,U d,U e,U f){register U x8 __asm__("x8")=nr;register U x0 __asm__("x0")=a;register U x1 __asm__("x1")=b;register U x2 __asm__("x2")=c;register U x3 __asm__("x3")=d;register U x4 __asm__("x4")=e;register U x5 __asm__("x5")=f;__asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");return (S)x0;}
static void fenv_set(void){U c=(U)FENV_ROUND<<22,s=0x0800009f;__asm__ volatile("msr fpcr,%0;msr fpsr,%1"::"r"(c),"r"(s):"memory");}
static int fenv_expected(U *v){return v[0]==((U)FENV_ROUND<<22)&&v[1]==0x0800009f&&v[2]==0;}
static void fenv_get(U *v){__asm__ volatile("mrs %0,fpcr;mrs %1,fpsr":"=r"(v[0]),"=r"(v[1])::"memory");v[2]=0;}
#elif defined(__riscv) && __riscv_xlen==64
#define NR_UID 174
#define NR_CLOSE 57
#define NR_TRUNC 46
#define NR_WRITE 64
#define NR_READ 63
#define NR_OPENAT 56
#define NR_MEMFD 279
#define NR_PIPE2 59
#define NR_LSEEK 62
#define NR_MMAP 222
#define NR_REMAP 216
#define NR_PWRITE 68
#define NR_PREAD 67
#define NR_UMASK 166
static S setup(U nr,U a,U b,U c,U d,U e,U f){register U a7 __asm__("a7")=nr;register U a0 __asm__("a0")=a;register U a1 __asm__("a1")=b;register U a2 __asm__("a2")=c;register U a3 __asm__("a3")=d;register U a4 __asm__("a4")=e;register U a5 __asm__("a5")=f;__asm__ volatile("ecall":"+r"(a0):"r"(a7),"r"(a1),"r"(a2),"r"(a3),"r"(a4),"r"(a5):"memory");return (S)a0;}
static void fenv_set(void){U c=((U)FENV_ROUND<<5)|31;__asm__ volatile("fscsr %0"::"r"(c):"memory");}
static int fenv_expected(U *v){return v[0]==(((U)FENV_ROUND<<5)|31)&&v[1]==0&&v[2]==0;}
static void fenv_get(U *v){__asm__ volatile("frcsr %0":"=r"(v[0])::"memory");v[1]=v[2]=0;}
#else
#error no qualified Linux carrier for this target
#endif
static U observed[80],checks,env_count;
static U before[3],after[3];
static int captured(U raw){
 fenv_get(after);U record[9]={env_count,raw,before[0],before[1],before[2],after[0],after[1],after[2],env_count==0?32:64};
 for(U i=0;i<3;i++){observed[20+env_count*6+i]=before[i];observed[23+env_count*6+i]=after[i];}
 env_count++;checks++;
 if(setup(NR_WRITE,2,(U)record,sizeof(record),0,0,0)!=sizeof(record))return 0;
 return before[0]==after[0]&&before[1]==after[1]&&before[2]==after[2];
}
#define CHECK(x) do{checks++;if(!(x))return __LINE__%180+40;}while(0)
#define PREP() do{fenv_set();fenv_get(before);CHECK(fenv_expected(before));}while(0)
#define SETUP(n,a,b,c,d,e,f) setup(n,(U)(a),(U)(b),(U)(c),(U)(d),(U)(e),(U)(f))
int conformance_main(void){
 static const unsigned char payload[20]={0,255,17,38,9,10,128,1,2,3,4,5,6,7,8,9,10,11,12,13};
 unsigned char buf[20]; int pipe[2]; S r;
 PREP();observed[0]=getuid();CHECK(captured(observed[0]));
 PREP();r=raw0(NR_UID);CHECK(captured((U)r));CHECK((U)r==observed[0]);observed[1]=(U)r;
 CHECK(SETUP(NR_PIPE2,pipe,2048,0,0,0,0)==0);
 PREP();r=raw1(NR_CLOSE,pipe[1]);observed[14]=r;CHECK(captured((U)r));CHECK(r==0);
 CHECK(SETUP(NR_WRITE,pipe[1],payload,20,0,0,0)==-9);SETUP(NR_CLOSE,pipe[0],0,0,0,0,0);
 PREP();r=raw1(NR_CLOSE,-1UL);CHECK(captured((U)r));CHECK(r==-9);observed[2]=(U)r;
 S fd=SETUP(NR_MEMFD,"ocore-raw-owned",0,0,0,0,0);CHECK(fd>=0);
 PREP();r=raw2(NR_TRUNC,fd,8192);observed[15]=r;CHECK(captured((U)r));CHECK(r==0);CHECK(SETUP(NR_LSEEK,fd,0,2,0,0,0)==8192);
 CHECK(SETUP(NR_PIPE2,pipe,2048,0,0,0,0)==0);
 PREP();r=raw3(NR_WRITE,pipe[1],(U)payload,20);observed[16]=r;CHECK(captured((U)r));CHECK(r==20);
 CHECK(SETUP(NR_READ,pipe[0],buf,20,0,0,0)==20);for(U i=0;i<20;i++)CHECK(buf[i]==payload[i]);
 unsigned char ordered[1]={0};PREP();r=ordered_write(pipe[1],ordered);observed[17]=r;CHECK(captured((U)r));CHECK(r==1);CHECK(ordered[0]==66);
 CHECK(SETUP(NR_READ,pipe[0],buf,1,0,0,0)==1);CHECK(buf[0]==65);
 SETUP(NR_CLOSE,pipe[0],0,0,0,0,0);SETUP(NR_CLOSE,pipe[1],0,0,0,0,0);
 CHECK(SETUP(NR_UMASK,0,0,0,0,0,0)>=0);
 PREP();r=raw4(NR_OPENAT,-100UL,(U)"raw4-created",0200|0100|2,0421);observed[18]=r;CHECK(captured((U)r));CHECK(r>=0);S created=r;
 CHECK(SETUP(NR_WRITE,created,payload,20,0,0,0)==20);SETUP(NR_CLOSE,created,0,0,0,0,0);
 S old=SETUP(NR_MMAP,0,4096,3,0x22,-1,0),dest=SETUP(NR_MMAP,0,8192,3,0x22,-1,0);
 CHECK((U)old<(U)-4095 && (U)dest<(U)-4095 && old && dest && ((U)old+4096<=(U)dest || (U)dest+8192<=(U)old));
 for(U i=0;i<4096;i++)((volatile unsigned char*)old)[i]=(unsigned char)(i*37+19);
 PREP();r=raw5(NR_REMAP,old,4096,8192,3,dest);CHECK(captured((U)r));CHECK(r==dest);
 for(U i=0;i<4096;i++)CHECK(((volatile unsigned char*)dest)[i]==(unsigned char)(i*37+19));
 for(U i=4096;i<8192;i++)CHECK(((volatile unsigned char*)dest)[i]==0);
 observed[3]=old;observed[4]=dest;observed[5]=r;
 CHECK(SETUP(NR_PWRITE,fd,payload,20,4096,0,0)==20);
 PREP();r=raw6(NR_MMAP,0,4096,3,1,fd,4096);CHECK(captured((U)r));CHECK((U)r<(U)-4095 && r);
 volatile unsigned char *mapped=(volatile unsigned char*)r;
 for(U i=0;i<20;i++)CHECK(mapped[i]==payload[i]);
#ifdef CORRUPT_ORACLE
 if(mapped[0]==payload[0])return 31;
#endif
 mapped[0]=91;
 CHECK(SETUP(NR_PREAD,fd,buf,20,4096,0,0)==20);CHECK(buf[0]==91);
 CHECK(SETUP(NR_PREAD,fd,buf,20,0,0,0)==20);for(U i=0;i<20;i++)CHECK(buf[i]==0);
 observed[6]=r;observed[7]=checks;observed[8]=before[0];observed[9]=before[1];observed[10]=before[2];observed[11]=after[0];observed[12]=after[1];observed[13]=after[2];
 observed[19]=env_count;CHECK(env_count==10);
 CHECK(SETUP(NR_WRITE,1,observed,sizeof(observed),0,0,0)==sizeof(observed));return 0;
}
#if defined(__x86_64__)
__asm__(".globl _start\n_start:\n and $-16,%rsp\n call conformance_main\n mov %eax,%edi\n mov $60,%eax\n syscall\n ud2\n");
#elif defined(__aarch64__)
__asm__(".globl _start\n_start:\n bl conformance_main\n mov x8,#93\n svc #0\n brk #1\n");
#else
__asm__(".globl _start\n_start:\n call conformance_main\n li a7,93\n ecall\n unimp\n");
#endif
'''


class LinuxSyscallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get('OCOREC_BIN'):
            raise unittest.SkipTest('set OCOREC_BIN to a separately built compiler; no implicit tool build')
        cls.compiler=Path(os.environ['OCOREC_BIN']).resolve()
        cls.olangc=Path(os.environ['OLANGC_BIN']).resolve() if os.environ.get('OLANGC_BIN') else None
        cls.sdk=Path(os.environ.get('OCORE_TEST_LLVM_BIN',str(SDK_DEFAULT))).resolve()
        cls.library=Path(os.environ.get('OCORE_LLVM_LIBRARY',str(LIB_DEFAULT))).resolve()
        assert identity(cls.library)['sha256']==LIB_SHA
        selected=os.environ.get('OCORE_TEST_LINUX_SYSCALL_OUTPUT_DIR')
        root=Path(selected) if selected else Path(tempfile.mkdtemp(prefix='ocore-linux-syscall-'))
        root.mkdir(parents=True,exist_ok=True);cls.root=root
        cls.source_root=Path.home()/'.cache/okernel-consolidated-native-20261106-6_socz5l/libc-original-inventories'
        spec=importlib.util.spec_from_file_location('independent_syscall_inventory',ROOT/'src/bin/olangc/native_runtime/source_inventory.py')
        cls.inventory=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.inventory)
        cls.tools_before=[identity(p) for p in (cls.compiler,cls.library,cls.sdk/'clang',ROOT/'scripts/ocore_llvm_import.py',ROOT/'src/bin/olangc/native_runtime/source_inventory.py')]
        (root/'tools-before.json').write_text(json.dumps(cls.tools_before,indent=2)+'\n')
        assert os.uname().sysname=='Linux', 'these execution tests require an actual Linux-compatible user provider'
        catalog=subprocess.run([str(cls.compiler),'--list-targets'],capture_output=True,check=True)
        (root/'canonical-targets.stdout').write_bytes(catalog.stdout)
        (root/'canonical-targets.stderr').write_bytes(catalog.stderr)
        (root/'canonical-targets.command.json').write_text(json.dumps({'argv':[str(cls.compiler),'--list-targets'],'exit':catalog.returncode})+'\n')
        table=json.loads(catalog.stdout)
        rows=table['targets'] if isinstance(table,dict) else table
        architectures={row['architecture'] for row in rows}
        assert architectures==set(UNITS), 'all canonical implemented ISAs require explicit syscall execution profiles'
        cls.recipe_products={}
        (root/'external-linux-provider.json').write_text(json.dumps({'uname':list(os.uname()),'uid':os.getuid(),'gid':os.getgid(),
            'scope':'actual test-only external Linux kernel/process; static Clang driver/bootstrap and guarded QEMU-user are not lowered implementation closure'},indent=2)+'\n')

    @classmethod
    def tearDownClass(cls):
        now=[identity(record['path']) for record in cls.tools_before]
        (cls.root/'tools-after.json').write_text(json.dumps(now,indent=2)+'\n')
        assert now==cls.tools_before,'compiler/library/source changed during qualification'
        for pair in cls.recipe_products.values():
            assert identity(pair['owned'])==pair['owned_identity']
            assert identity(pair['reference'])==pair['reference_identity']
            assert identity(pair['packet_path'])==pair['source_group']

    def setUp(self):
        self.directory=self.root/self._testMethodName
        self.directory.mkdir(exist_ok=False);self.records=[]

    def tearDown(self):
        (self.directory/'commands.json').write_text(json.dumps(self.records,indent=2)+'\n')

    def command(self,argv,success=True,cwd=None,timeout=120):
        argv=list(map(str,argv));index=len(self.records)
        record={'argv':argv,'cwd':str(cwd or self.directory),'timeout_seconds':timeout}
        self.records.append(record)
        p=subprocess.run(argv,cwd=cwd or self.directory,capture_output=True,timeout=timeout)
        record.update(exit=p.returncode,stdout=identity_bytes(self.directory/f'{index:03}.stdout',p.stdout),stderr=identity_bytes(self.directory/f'{index:03}.stderr',p.stderr))
        if success:self.assertEqual(p.returncode,0,p.stderr.decode(errors='replace'))
        else:self.assertNotEqual(p.returncode,0,'required fail-closed control unexpectedly succeeded')
        return p

    def original(self,isa):
        p=self.source_root/isa/'capture/units'/UNITS[isa]/'unit-0.ll'
        self.assertTrue(p.is_file(),'retained whole original input is required; no substitute')
        return p

    def import_(self,source,isa,output,profile=True):
        return self.command([self.compiler,source,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir','--llvm-library',self.library,'--llvm-sha256',LIB_SHA,*(['--linux-syscall-profile','linux-user-raw-v1'] if profile else []),'-o',output],success=profile)

    def ensure_recipe_pair(self,isa):
        cached=self.__class__.recipe_products.get(isa)
        if cached is not None:return cached
        self.assertIsNotNone(self.olangc,'OLANGC_BIN is mandatory for this component route')
        rust=Path.home()/'.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin'
        def pin(path):
            record=identity(path);return {'path':str(Path(path).absolute()),'sha256':record['sha256']}
        tools={'python':pin(Path(sys.executable).resolve()),'llvm_library':pin(self.library),
               **{key:pin(self.sdk/name) for key,name in [('cc','clang'),('cxx','clang++'),('llvm_nm','llvm-nm'),('llvm_dis','llvm-dis')]},
               'rustc':pin(rust/'rustc'),'cargo':pin(rust/'cargo'),'compiler_sha256':identity(self.compiler)['sha256']}
        musl=Path.home()/'.cache/okernel-u9fs-native-recipe/sources/musl'
        case=self.root/'source-products'/isa;case.mkdir(parents=True)
        recipe=ROOT/'tools/ocore-runtime/linux-syscall'/(isa+'.getuid.recipe.json')
        name=json.loads(recipe.read_text())['name']
        plan=case/'provider-plan.json';plan.write_text(json.dumps({'schema':'ocore-native-provider-plan-v1','root':name,'tools':tools,
            'components':[{'id':name,'recipe':pin(recipe),'source':str(musl),'dependencies':{}}]},indent=2)+'\n')
        def arguments(input_,output):
            return [self.olangc,input_,'--native-runtime','--native-runtime-provider-plan',plan,'--native-isa',isa+'-unknown-none',
                '--native-runtime-output','obj','--llvm-library',self.library,'--llvm-sha256',LIB_SHA,'-o',output]
        product=case/'product'
        self.command([*arguments(recipe,product),'--native-runtime-source',musl,'--native-runtime-jobs','2','--linux-syscall-profile','linux-user-raw-v1'],timeout=300)
        packet_path=product/'source-group.native-ir.json';packet=json.loads(packet_path.read_text())
        interfaces=packet['module_set']['symbol_inventory']['required_platform_interfaces']
        self.assertEqual(len(interfaces),1);interface=interfaces[0]['interface']
        self.assertEqual(interface['privilege'],'user_mode_only')
        self.assertEqual(interface['execution_environment'],'linux_compatible_user_process_v1')
        self.assertFalse(packet['module_set']['symbol_inventory']['platform_resource_closure_complete'])
        reopened=case/'reopened';self.command(arguments(packet_path,reopened),timeout=300)
        readmission=json.loads((reopened/'source-readmission.json').read_text())
        self.assertTrue(readmission['included_original_ir_body_consistency'])
        self.assertTrue(readmission['required_platform_interfaces'])
        owned=reopened/'lowered/unit-000000/module.o'
        reference=product/'component-000000/build/obj/src/unistd/getuid.o'
        self.assertTrue(owned.is_file() and reference.is_file())
        result={'owned':owned,'reference':reference,'source_group':identity(packet_path),'packet_path':packet_path,'plan_path':plan,
                'owned_identity':identity(owned),'reference_identity':identity(reference)}
        self.__class__.recipe_products[isa]=result
        return result

    def test_compiler_owned_original_recipe_provider_and_strict_source_readmission(self):
        # Prepare real positive products first; each test also works alone via
        # the same lazy fixture. No replay or prior test success is presumed.
        for isa in UNITS:self.ensure_recipe_pair(isa)
        for isa in UNITS:
            pair=self.ensure_recipe_pair(isa);case=self.directory/isa;case.mkdir()
            packet=json.loads(pair['packet_path'].read_text())
            def arguments(input_,output):
                return [self.olangc,input_,'--native-runtime','--native-runtime-provider-plan',pair['plan_path'],'--native-isa',isa+'-unknown-none',
                    '--native-runtime-output','obj','--llvm-library',self.library,'--llvm-sha256',LIB_SHA,'-o',output]
            # Neither the legacy upgrade nor declaration closure may invent a
            # Linux provider when the mandatory interface was removed/changed.
            for field in ['required_platform_interfaces','platform_resource_closure_complete']:
                wrong=copy.deepcopy(packet['module_set']);wrong['symbol_inventory'].pop(field)
                path=case/('drop-'+field+'.json');path.write_text(json.dumps(wrong))
                self.command([self.olangc,path,'--native-runtime','--native-isa',isa+'-unknown-none','--native-runtime-output','obj','-o',case/('reject-'+field)],success=False)
            for kind in ['cookie','return-body']:
                forged=copy.deepcopy(packet);embedded=forged['module_set']['modules'][0]
                module=json.loads(embedded['native_ir'])
                if kind=='cookie':
                    operation=module['functions'][0]['blocks'][0]['instructions'][0]['operation']
                    cookie=operation['source']['srcloc']['operands'][0]
                    cookie['bits']=str((int(cookie['bits'])+1)%(1<<cookie['width']))
                else:
                    function=module['functions'][0]
                    function['blocks'][0]['terminator']['value']={'kind':'int','ty':function['signature']['result'],'bits':'0'}
                encoded=json.dumps(module);native_path=case/(kind+'-coherent-forger.native.json');native_path.write_text(encoded)
                self.command([self.compiler,native_path,'--input-kind','native-ir','--verify-native'])
                source_path=case/(kind+'-original-source.ll')
                source_path.write_bytes(bytes.fromhex(packet['components'][0]['units'][0]['original_ir_hex']))
                if kind=='cookie':
                    with self.assertRaises(self.inventory.InventoryMismatch):
                        self.inventory.audit_native_module(source_path,module,self.library,LIB_SHA)
                else:
                    self.inventory.audit_native_module(source_path,module,self.library,LIB_SHA)
                embedded['native_ir']=encoded;embedded['sha256']=hashlib.sha256(encoded.encode()).hexdigest()
                forged_path=case/(kind+'-coherent-forger.group.json');forged_path.write_text(json.dumps(forged))
                rejected=case/('reject-source-forger-'+kind);self.command(arguments(forged_path,rejected),success=False,timeout=300)
                failure=(rejected/'source-readmission.json').read_text()
                if kind=='cookie':
                    self.assertIn('independent source inventory failed',failure)
                    exact=(rejected/'source-000000-000000/inventory/stderr.log').read_text()
                    self.assertIn('Linux syscall original operands/signature/constraints/effects/attributes/srcloc/site changed',exact)
                else:
                    self.assertIn('fresh original LLVM import does not match embedded typed NativeModule',failure)

    def test_original_complete_getuid_three_isa_source_and_required_linux_provider(self):
        for isa in UNITS:
            directory=self.directory/isa;directory.mkdir()
            source=self.original(isa);output=directory/'getuid.native.json';self.import_(source,isa,output)
            module=json.loads(output.read_text());self.assertEqual(len(module['functions']),1)
            self.assertEqual(module['provenance']['source_function_count'],1)
            self.assertEqual(module['target']['strict_fp_profile'],'integer_linux_syscall_v1')
            self.assertEqual(module['provenance']['input_sha256'],identity(source)['sha256'])
            proof=self.inventory.audit_native_module(source,module,self.library,LIB_SHA)
            (directory/'independent-source-inventory.json').write_text(json.dumps(proof,indent=2)+'\n')
            receipt=directory/'verify.json';self.command([self.compiler,output,'--input-kind','native-ir','--verify-native','--receipt',receipt])
            verified=json.loads(receipt.read_text());self.assertFalse(verified['platform_resource_closure_complete'])
            requirement=verified['required_platform_interfaces'][0];self.assertEqual(requirement['architecture'],isa);self.assertEqual(len(requirement['sites']),1)
            obj=directory/'getuid.o';self.command([self.compiler,output,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',obj])
            self.assertEqual(platform_note(obj),requirement)
            spec=importlib.util.spec_from_file_location('kernel_user_placement_guard',ROOT/'scripts/okernel_native_codec.py')
            guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
            with self.assertRaisesRegex(ValueError,'userspace platform object'):
                guard.require_kernel_platform_object(obj.read_bytes())
            raw=bytearray(obj.read_bytes());count=struct.unpack_from('<H',raw,60)[0];table=struct.unpack_from('<Q',raw,40)[0]
            struct.pack_into('<H',raw,60,0);struct.pack_into('<Q',raw,table+32,count)
            extended=directory/'getuid.extended-numbering.o';extended.write_bytes(raw)
            self.command([self.sdk/'llvm-readobj','--sections',extended])
            with self.assertRaisesRegex(ValueError,'userspace platform object'):
                guard.require_kernel_platform_object(extended.read_bytes())
            symbols=self.command([self.sdk/'llvm-nm','--undefined-only',obj]);self.assertEqual(symbols.stdout,b'','zero ELF UND is distinct from Linux dependency')
            # Default admission remains a real whole-unit failure.
            self.import_(source,isa,directory/'default-must-not-exist.json',profile=False)
            self.assertFalse((directory/'default-must-not-exist.json').exists())

    def test_owned_child_all_twenty_one_register_forms_and_fenv_against_original(self):
        results=[]
        for isa in UNITS:
            directory=self.directory/isa;directory.mkdir()
            original=self.original(isa);text=original.read_text();source=directory/'arity.ll'
            header=Path.home()/'.cache/okernel-u9fs-native-recipe/sources/musl/arch'/isa/'syscall_arch.h'
            self.assertTrue(header.is_file())
            wrappers=directory/'arity-original-headers.c'
            wrappers.write_text('#include "syscall_arch.h"\n'+'\n'.join(
                'long raw'+str(n)+'('+','.join('long '+v for v in ['n']+['a'+str(i) for i in range(n)])+') { return __syscall'+str(n)+'('+','.join(['n']+['a'+str(i) for i in range(n)])+'); }'
                for n in range(7))+'\n'+f'long ordered_write(long fd,unsigned char *p) {{ *p=65; long r=__syscall3({1 if isa=="x86_64" else 64},fd,(long)p,1); *p=66; return r; }}\n')
            triple=re.search(r'target triple = "([^"]+)"',text)[1]
            flags=['-march=rv64gc','-mabi=lp64d'] if isa=='riscv64' else []
            self.command([self.sdk/'clang','--target='+triple,*flags,'-O2','-ffreestanding','-fno-builtin','-frounding-math','-fno-stack-protector','-I',header.parent,'-S','-emit-llvm',wrappers,'-o',source])
            (directory/'original-header.json').write_text(json.dumps(identity(header),indent=2)+'\n')
            modulepath=directory/'arity.native.json';self.import_(source,isa,modulepath)
            module=json.loads(modulepath.read_text());self.assertEqual(len(module['functions']),8)
            ordered=next(f for f in module['functions'] if f['name']=='ordered_write')
            operations=[item['operation']['op'] for b in ordered['blocks'] for item in b['instructions']]
            syscall=operations.index('linux_syscall');self.assertIn('store',operations[:syscall]);self.assertIn('store',operations[syscall+1:])
            self.inventory.audit_native_module(source,module,self.library,LIB_SHA)
            originalmodule=directory/'getuid.native.json';self.import_(original,isa,originalmodule)
            own=directory/'arity.own.o';uidown=directory/'getuid.own.o'
            self.command([self.compiler,modulepath,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',own])
            self.command([self.compiler,originalmodule,'--input-kind','native-ir','--target',isa+'-unknown-none','-o',uidown])
            triple=json.loads(originalmodule.read_text())['target']['triple'];flags=['-march=rv64gc','-mabi=lp64d'] if isa=='riscv64' else []
            reference=directory/'arity.clang.o';uidref=directory/'getuid.clang.o'
            for src,obj in [(source,reference),(original,uidref)]:
                self.command([self.sdk/'clang','--target='+triple,*flags,'-O0','-c',src,'-o',obj])
            recipe_pair=self.ensure_recipe_pair(isa)
            self.assertIsNotNone(recipe_pair,"execution must use this run's actual original source-recipe reference/O-core pair")
            uidown=recipe_pair['owned'];uidref=recipe_pair['reference']
            carrier=directory/'carrier.c';carrier.write_text(CARRIER)
            if isa==os.uname().machine:prefix=[]
            else:
                runner=Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/{'x86_64':'qemu-x86_64','aarch64':'qemu-aarch64','riscv64':'qemu-riscv64'}[isa]
                self.assertTrue(runner.is_file(),'guarded foreign ISA runner is mandatory')
                prefix=[str(runner)]
                version=self.command([runner,'--version']);(directory/'runner.json').write_text(json.dumps({'identity':identity(runner),'version':version.stdout.decode(errors='replace'),'scope':'test-only external emulator, not lowered implementation'},indent=2)+'\n')
            observations=[]
            for mode in range(5 if isa=='riscv64' else 4):
                for implementation,objects in [('reference',[reference,uidref]),('owned',[own,uidown])]:
                    cwd=directory/(implementation+'-round-'+str(mode));cwd.mkdir();executable=cwd/'run'
                    self.command([self.sdk/'clang','--target='+triple,*flags,'--ld-path='+str(self.sdk/'ld.lld'),'-O1','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize','-fno-pic','-fno-pie','-nostdlib','-static','-Wl,--no-relax','-Wl,-e,_start','-DFENV_ROUND='+str(mode),carrier,*objects,'-o',executable])
                    executable_elf(executable,isa)
                    p=self.command([*prefix,executable],cwd=cwd,timeout=30)
                    self.assertEqual(len(p.stdout),640)
                    values=list(struct.unpack('<80Q',p.stdout))
                    self.assertEqual(len(p.stderr),720)
                    records=[list(struct.unpack_from('<9Q',p.stderr,i*72)) for i in range(10)]
                    self.assertEqual([record[0] for record in records],list(range(10)))
                    self.assertEqual([record[8] for record in records],[32]+[64]*9)
                    self.assertEqual([record[1] for record in records],[values[i] for i in [0,1,14,2,15,16,17,18,5,6]])
                    expected_env=([0x1f80|(mode<<13)|63,0x037f|(mode<<10),63] if isa=='x86_64' else [mode<<22,0x0800009f,0] if isa=='aarch64' else [(mode<<5)|31,0,0])
                    for record in records:
                        self.assertEqual(record[2:5],expected_env);self.assertEqual(record[5:8],expected_env)
                    self.assertEqual(values[19],10)
                    self.assertEqual(values[0],os.getuid());self.assertEqual(values[1],os.getuid());self.assertEqual(values[2],2**64-9)
                    self.assertEqual(values[4],values[5]);self.assertEqual(values[8:11],values[11:14])
                    self.assertEqual((cwd/'raw4-created').stat().st_mode&0o777,0o421)
                    self.assertEqual((cwd/'raw4-created').read_bytes(),bytes([0,255,17,38,9,10,128,1,2,3,4,5,6,7,8,9,10,11,12,13]))
                    if implementation == "reference" and mode == 0:
                        corrupt=cwd/"corrupt-oracle"
                        self.command([self.sdk/"clang","--target="+triple,*flags,"--ld-path="+str(self.sdk/"ld.lld"),"-O1","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-vectorize","-fno-slp-vectorize","-fno-pic","-fno-pie","-nostdlib","-static","-Wl,--no-relax","-Wl,-e,_start","-DCORRUPT_ORACLE","-DFENV_ROUND=0",carrier,*objects,"-o",corrupt])
                        corruptcwd=directory/"corrupt";corruptcwd.mkdir()
                        rejected=self.command([*prefix,corrupt],cwd=corruptcwd,timeout=30,success=False)
                    self.assertEqual(rejected.returncode,31,'corrupt oracle must fail at its deliberate check, not an unrelated fault')
                    self.assertEqual(rejected.stdout,b'')
                    observations.append({'implementation':implementation,'rounding_mode':mode,'executable':identity(executable),'raw_values':values,'per_call_raw_and_fenv_records':records,'file':identity(cwd/'raw4-created')})
            # Predeclared ASLR/allocation fields remain in raw evidence; compare
            # only fixed semantic values plus proven own-mapping relationships.
            excluded={3,4,5,6}
            for reference_run,owned_run in zip(observations[::2],observations[1::2]):
                self.assertEqual(reference_run['rounding_mode'],owned_run['rounding_mode'])
                self.assertEqual([v for i,v in enumerate(reference_run['raw_values']) if i not in excluded],[v for i,v in enumerate(owned_run['raw_values']) if i not in excluded])
                for ref_record,own_record in zip(reference_run['per_call_raw_and_fenv_records'],owned_run['per_call_raw_and_fenv_records']):
                    self.assertEqual(ref_record[:1]+ref_record[2:],own_record[:1]+own_record[2:])
                    if ref_record[0] not in [8,9]:self.assertEqual(ref_record[1],own_record[1])
            results.append({'architecture':isa,'arity_forms':7,'observations':observations,'source_recipe_pair':{key:(identity(value) if isinstance(value,Path) else value) for key,value in recipe_pair.items()},'externals':['Clang test driver/bootstrap','Linux syscall provider',*prefix],'runtime_closure_complete':False})
        (self.directory/'execution.json').write_text(json.dumps({'scope':'authored register-form and unchanged getuid component execution','results':results,'nondeterministic_fields_predeclared':[3,4,5,6],'whole_runtime_lowered':False},indent=2)+'\n')

    def test_original_call_contracts_do_not_become_generic_assembly_or_metadata_waivers(self):
        for isa in UNITS:
            original=self.original(isa).read_text()
            template='"'+RAW[isa][0]+'"'
            cases={
                'other-instructions':original.replace(template,'"'+RAW[isa][0]+'; nop"',1),
                'no-sideeffect':original.replace('asm sideeffect','asm',1),
                'missing-memory-clobber':original.replace(',~{memory}','',1),
                'other-attachment-name':original.replace('!srcloc','!not.srcloc'),
                'opaque-cookie':re.sub(r'(![0-9]+ = )!\{i64 [^}]+\}',r'\1!{!"opaque-cookie"}',original),
                'unrelated-strict-fp-body':original+'\ndefine double @unused_fp(double %x) strictfp { %r = fadd double %x, 1.0\n ret double %r }\n',
            }
            for name,text in cases.items():
                path=self.directory/(isa+'-'+name+'.ll');path.write_text(text);output=path.with_suffix('.native.json')
                p=self.command([self.compiler,path,'--input-kind','llvm-ir','--target',isa+'-unknown-none','--emit','mir',
                    '--llvm-library',self.library,'--llvm-sha256',LIB_SHA,'--linux-syscall-profile','linux-user-raw-v1','-o',output],success=False)
                self.assertFalse(output.exists(),'unsupported complete units cannot become partial IR')

    def test_source_witness_and_profile_negative_controls_fail_closed(self):
        isa='x86_64';source=self.original(isa);path=self.directory/'valid.json';self.import_(source,isa,path);valid=json.loads(path.read_text())
        mutations={
          'profile-absent':lambda m:m['target'].pop('linux_syscall_profile'),
          'old-strict':lambda m:m['target'].__setitem__('strict_fp_profile','integer_only_v1'),
          'foreign-os':lambda m:m['target'].__setitem__('triple','x86_64-unknown-none'),
          'missing-clobber':lambda m:m['functions'][0]['blocks'][0]['instructions'][0]['operation']['source'].__setitem__('constraints',list(b'={ax},{ax}')),
          'no-sideeffect':lambda m:m['functions'][0]['blocks'][0]['instructions'][0]['operation']['source'].__setitem__('side_effects',False),
          'wrong-site':lambda m:m['functions'][0]['blocks'][0]['instructions'][0]['operation']['source']['site'].__setitem__('function','other'),
          'bad-cookie-width':lambda m:m['functions'][0]['blocks'][0]['instructions'][0]['operation']['source']['srcloc']['operands'][0].__setitem__('width',0),
        }
        for name,mutate in mutations.items():
            module=copy.deepcopy(valid);mutate(module);candidate=self.directory/(name+'.json');candidate.write_text(json.dumps(module))
            self.command([self.compiler,candidate,'--input-kind','native-ir','--verify-native'],success=False)
        # A coherent source cookie forgery is structurally valid. Only genuine
        # fresh source comparison can authenticate its claimed original source.
        forged=copy.deepcopy(valid);forged['functions'][0]['blocks'][0]['instructions'][0]['operation']['source']['srcloc']['operands'][0]['bits']='81220'
        forgedpath=self.directory/'coherent-forger.json';forgedpath.write_text(json.dumps(forged))
        self.command([self.compiler,forgedpath,'--input-kind','native-ir','--verify-native'])
        with self.assertRaisesRegex(self.inventory.InventoryMismatch,'Linux syscall original.*changed'):
            self.inventory.audit_native_module(source,forged,self.library,LIB_SHA)


def identity_bytes(path,data):
    Path(path).write_bytes(data)
    return identity(path)


if __name__=='__main__': unittest.main()
