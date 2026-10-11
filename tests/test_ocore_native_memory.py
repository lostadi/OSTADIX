"""Actual memory objects on three ISAs with byte snapshots and protected pages.

Linux mappings/syscalls are development carriers, not OSTADIX kernel or whole
runtime admission. The independent oracle describes final byte slices; it does
not select the emitter's traversal direction or reproduce its instructions.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts.check_ocore_native_equivalence import TARGETS, elf
from scripts.check_ocore_foreign_frontends import HARNESS as LINUX_CARRIER
from tests.test_ocore_native_import_backend import (
    ROOT, I64, I8, I32, PTR, function, instruction, module, value,
)

MASK = (1 << 64)-1
LENGTHS = (0,1,2,3,7,8,9,15,16,17,31,32,33,63)
VARIANTS = [(kind,width,volatile) for kind in ("set","copy","move")
            for width in (32,64) for volatile in (False,True)]
NAMES = [f"memory_{kind}{width}{'v' if volatile else ''}"
         for kind,width,volatile in VARIANTS]
SDK = Path.home()/".cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin"


def artifact(path):
    path=Path(path).resolve();digest=hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda:source.read(1024*1024),b""):digest.update(block)
    return {"path":str(path),"sha256":digest.hexdigest(),"bytes":path.stat().st_size}


def corpus(isa):
    functions=[]
    for name,(kind,width,volatile) in zip(NAMES,VARIANTS):
        params=[PTR,I64,I64] if kind=="set" else [PTR,PTR,I64]
        ops=[]
        length=value(2)
        if width==32:
            ops.append(instruction(3,I32,{"op":"cast","kind":"trunc","value":length}))
            length=value(3)
        if kind=="set":
            ops.append(instruction(4,I8,{"op":"cast","kind":"trunc","value":value(1)}))
            operation={"op":"memory_set","destination":value(0),"value":value(4),
                       "length":length,"alignment":1,"volatile":volatile}
        else:
            operation={"op":"memory_copy","destination":value(0),"source":value(1),
                       "length":length,"destination_alignment":1,"source_alignment":1,
                       "volatile":volatile,"allow_overlap":kind=="move"}
        ops.append({"result":None,"operation":operation})
        functions.append(function(name,ops,params=params))
    native=module(isa,functions)
    native["name"]="generic-memory-byte-conformance"
    return native


def cases():
    result=[]
    fills=(0,1,127,128,255,256,0xFEDCBA98765432AB)
    for variant,(kind,width,_) in enumerate(VARIANTS):
        for length in LENGTHS:
            encoded=length | ((1<<32) if width==32 else 0)
            if kind=="set":
                for destination in (0,1,3,17,65):
                    for fill in fills:
                        result.append((variant,destination,0,encoded,fill,0))
            else:
                for destination,source,same in ((1,3,0),(3,1,1),(1,3,1),
                                               (7,7,1),(1,65,1),(65,1,1)):
                    if kind=="copy" and same and destination!=source and length>abs(destination-source):
                        continue  # LLVM memcpy allows equal or disjoint ranges.
                    result.append((variant,destination,source,encoded,0,same))
    return result


def pattern(multiplier,addend):
    return bytearray((index*multiplier+addend)&255 for index in range(128))


def expected_output():
    digest=0xCBF29CE484222325
    def add(data):
        nonlocal digest
        for byte in data:digest=((digest^byte)*0x100000001B3)&MASK
    for variant,destination,source,encoded,fill,same in cases():
        kind,width,_=VARIANTS[variant]
        length=encoded & ((1<<width)-1)
        dest,other=pattern(37,11),pattern(53,7)
        if kind=="set":dest[destination:destination+length]=bytes([fill&255])*length
        else:
            snapshot=bytes((dest if same else other)[source:source+length])
            dest[destination:destination+length]=snapshot
        add(dest);add(other)
    # Guarded exact lengths test both the beginning and end of a writable page.
    # Only the tested slice enters the digest; surrounding bytes are sentinels.
    for variant,(kind,_,_) in enumerate(VARIANTS):
        for length in (0,1,3,7,31,63):
            for end in (False,True):
                destination=128-length if end else 0
                dest,other=pattern(37,11),pattern(53,7)
                if kind=="set":dest[destination:destination+length]=bytes([0xAB])*length
                else:dest[destination:destination+length]=bytes(other[destination:destination+length])
                add(dest);add(other)
    return f"OCORE-MEMORY digest={digest:016x} cases={len(cases())+12*6*2}\n".encode()


def harness(frontend=False):
    syscall=LINUX_CARRIER.split("static u64 syscall3",1)[1].split("static u64 signed_bits",1)[0]
    startup=LINUX_CARRIER.split("#if defined(__x86_64__)\n__asm__",1)[1]
    text="typedef unsigned long long u64; typedef unsigned int u32; typedef unsigned char byte;\nstatic u64 syscall3"+syscall
    text+=r'''
static u64 syscall6(u64 number,u64 first,u64 second,u64 third,u64 fourth,u64 fifth,u64 sixth) {
#if defined(__x86_64__)
    register u64 rax __asm__("rax")=number,r10 __asm__("r10")=fourth,r8 __asm__("r8")=fifth,r9 __asm__("r9")=sixth;
    __asm__ volatile("syscall":"+a"(rax):"D"(first),"S"(second),"d"(third),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return rax;
#elif defined(__aarch64__)
    register u64 x0 __asm__("x0")=first,x1 __asm__("x1")=second,x2 __asm__("x2")=third;
    register u64 x3 __asm__("x3")=fourth,x4 __asm__("x4")=fifth,x5 __asm__("x5")=sixth,x8 __asm__("x8")=number;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory");return x0;
#else
    register u64 a0 __asm__("a0")=first,a1 __asm__("a1")=second,a2 __asm__("a2")=third;
    register u64 a3 __asm__("a3")=fourth,a4 __asm__("a4")=fifth,a5 __asm__("a5")=sixth,a7 __asm__("a7")=number;
    __asm__ volatile("ecall":"+r"(a0):"r"(a1),"r"(a2),"r"(a3),"r"(a4),"r"(a5),"r"(a7):"memory");return a0;
#endif
}
static byte* guarded(void) {
#if defined(__x86_64__)
    u64 address=syscall6(9,0,12288,0,34,~0ULL,0);u64 protect_number=10;
#else
    u64 address=syscall6(222,0,12288,0,34,~0ULL,0);u64 protect_number=226;
#endif
    if(address>=(u64)-4095)return (byte*)0;
    byte* middle=(byte*)(address+4096);
    if(syscall3(protect_number,(u64)middle,4096,3))return (byte*)0;
    return middle;
}
static byte destination[128],other[128],expected[128],snapshot[128];
static u64 digest=0xcbf29ce484222325ULL;
static u32 count=0;
static void initialize(byte* a,byte* b) {
    for(u32 i=0;i<128;++i){a[i]=(byte)(37*i+11);b[i]=(byte)(53*i+7);}
}
static void oracle(u32 kind,byte* out,const byte* src,u64 n,u64 fill) {
    if(kind==0)for(u64 i=0;i<n;++i)out[i]=(byte)fill;
    else {for(u64 i=0;i<n;++i)snapshot[i]=src[i];for(u64 i=0;i<n;++i)out[i]=snapshot[i];}
}
static void add(const byte* data) {for(u32 i=0;i<128;++i)digest=(digest^data[i])*0x100000001b3ULL;}
'''
    for name,(kind,_,_) in zip(NAMES,VARIANTS):
        text+=f"extern u64 {name}(byte*,{'u64' if kind=='set' else 'const byte*'},u64);\n"
    if frontend:
        text+='''extern void frontend_copy(byte*,const byte*,u64),frontend_move(byte*,const byte*,u64),frontend_set(byte*,int,u64);
extern u64 frontend_lifetime(u64);
void opaque_escape(byte* data,u64 length){data[0]^=0x5a;data[length-1]^=0xa5;}
'''
    text+="static void dispatch(u32 variant,byte* d,const byte* s,u64 n,u64 fill) {\n"
    if frontend:
        # The original C functions accept size_t. NativeJSON separately covers
        # i32 lengths; truncate the shared encoded test input in this carrier.
        text+="u64 length=variant%4<2?(u32)n:n;\n"
        # Keep higher fill bits through the original int parameter, while
        # avoiding implementation-defined unsigned-to-signed C conversions.
        text+="if(variant<4)frontend_set(d,(int)(fill&0x7fffffffULL),length);else if(variant<8)frontend_copy(d,s,length);else frontend_move(d,s,length);\n"
    else:
        text+="#ifdef REFERENCE_ONLY\n oracle(variant/4,d,s,(variant%4<2)?(u32)n:n,fill);\n#else\n"
        for index,(name,(kind,_,_)) in enumerate(zip(NAMES,VARIANTS)):
            text+=f"if(variant=={index}){{{name}(d,{'fill' if kind=='set' else 's'},n);return;}}\n"
        text+="#endif\n"
    text+="}\nstruct Test{u32 variant,destination,source;u64 length,fill;u32 same;};\nstatic const struct Test tests[]={\n"
    text+=",\n".join("{"+f"{v},{d},{s},{n}ULL,{f}ULL,{same}"+"}" for v,d,s,n,f,same in cases())+"\n};\n"
    text+=r'''
int conformance_main(void) {
    for(u32 k=0;k<sizeof(tests)/sizeof(tests[0]);++k) {
        const struct Test* t=&tests[k];u32 kind=t->variant/4;
        u64 length=t->variant%4<2?(u32)t->length:t->length;
        initialize(destination,other);for(u32 i=0;i<128;++i)expected[i]=destination[i];
        oracle(kind,expected+t->destination,(t->same?expected:other)+t->source,length,t->fill);
        dispatch(t->variant,destination+t->destination,(t->same?destination:other)+t->source,t->length,t->fill);
#ifdef CORRUPT_REFERENCE
        expected[0]^=1;
#endif
        for(u32 i=0;i<128;++i){if(destination[i]!=expected[i])return 31;if(other[i]!=(byte)(53*i+7))return 32;}
        add(destination);add(other);++count;
    }
    for(u32 variant=0;variant<12;++variant) {
        /* Zero-length raw native ops must not touch these invalid pointers.
         * The C-source witness instead receives valid pointers even at zero,
         * retaining upstream C builtin argument preconditions. */
'''
    if not frontend:
        text+="dispatch(variant,(byte*)1,(byte*)~0ULL,(variant%4<2)?(1ULL<<32):0,0xff);\n"
    text+=r'''
        byte* a=guarded();byte* b=guarded();if(!a||!b)return 80;
        const u32 lengths[]={0,1,3,7,31,63};
        for(u32 k=0;k<6;++k)for(u32 end=0;end<2;++end) {
            u64 n=lengths[k];u32 start=end?128-n:0;
            byte* dest=end?a+4096-128:a;byte* src=end?b+4096-128:b;
            initialize(dest,src);for(u32 i=0;i<128;++i)expected[i]=dest[i];
            oracle(variant/4,expected+start,src+start,n,0xab);
            dispatch(variant,dest+start,src+start,n,0xab);
            for(u32 i=0;i<128;++i)if(dest[i]!=expected[i]||src[i]!=(byte)(53*i+7))return 81;
            add(dest);add(src);++count;
        }
    }
'''
    if frontend:
        # This is an additional assertion, excluded from the shared byte digest.
        text+="for(u32 fill=0;fill<512;++fill)if(frontend_lifetime(fill)!=(((fill^0x5a)&255)|(((fill^0xa5)&255)<<8)))return 82;\n"
    text+=f"if(count!={len(cases())+len(VARIANTS)*6*2})return 83;\n"
    output=expected_output().decode()
    text+=f'char output[]="{output.rstrip().replace(output[output.index("digest=")+7:output.index(" cases=")],"0"*16)}\\n";\n'
    text+=r'''
    for(u32 i=0;i<16;++i){u32 nibble=(u32)(digest>>(60-4*i))&15;output[sizeof("OCORE-MEMORY digest=")-1+i]=(char)(nibble<10?'0'+nibble:'a'+nibble-10);}
    const char* data=output;u64 left=sizeof(output)-1;
    while(left) {
#if defined(__x86_64__)
        u64 written=syscall3(1,1,(u64)data,left);
#else
        u64 written=syscall3(64,1,(u64)data,left);
#endif
        if(!written||written>left)return 99;data+=written;left-=written;
    }
    return 0;
}
#if defined(__x86_64__)
__asm__'''+startup
    return text


class NativeMemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler=Path(os.environ.get("OCOREC",str(ROOT/"target/debug/ocorec"))).resolve()
        if not cls.compiler.is_file():
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":raise RuntimeError("required current ocorec is absent")
            raise unittest.SkipTest("actual built ocorec required; this suite does not run Cargo")

    def setUp(self):
        retained=os.environ.get("OCORE_TEST_NATIVE_MEMORY_OUTPUT_DIR")
        if retained:
            root=Path(retained).expanduser().resolve();root.mkdir(parents=True,exist_ok=True)
            self.directory=Path(tempfile.mkdtemp(prefix="run-",dir=root))
        else:
            temporary=tempfile.TemporaryDirectory(prefix="ocore-native-memory-")
            self.addCleanup(temporary.cleanup);self.directory=Path(temporary.name)

    def tools(self):
        result={name:shutil.which(os.environ.get(variable,default)) for name,variable,default in (
            ("clang","CLANG","clang"),("linker","LD_LLD","ld.lld"),
            ("aarch64","OCORE_TEST_QEMU_AARCH64","qemu-aarch64"),
            ("riscv64","OCORE_TEST_QEMU_RISCV64","qemu-riscv64"))}
        missing=[name for name,path in result.items() if path is None]
        if platform.machine() not in {"x86_64","AMD64"}:missing.append("native x86-64 host")
        if missing:
            reason="all three real memory executions require: "+", ".join(missing)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":self.fail(reason)
            self.skipTest(reason)
        return result

    def command(self,argv,success=True):
        result=subprocess.run([str(item) for item in argv],cwd=ROOT,capture_output=True,timeout=120)
        sequence=len(list(self.directory.glob("command-*.json")))
        (self.directory/f"command-{sequence:03}.json").write_text(json.dumps({"argv":[str(item) for item in argv],
            "exit_code":result.returncode,"stdout":result.stdout.decode(errors="replace"),"stderr":result.stderr.decode(errors="replace")},indent=2))
        if success:self.assertEqual(result.returncode,0,result.stdout.decode(errors="replace")+result.stderr.decode(errors="replace"))
        return result

    def verify(self,path):
        receipt=path.with_suffix(".verified.json")
        self.command([self.compiler,path,"--verify-native","--receipt",receipt])
        record=json.loads(receipt.read_text())
        self.assertTrue(record["verified"]);self.assertEqual(record["scope"],"structural_ir_verification")
        self.assertEqual(record["module_sha256"],hashlib.sha256(path.read_bytes()).hexdigest())

    def execute(self,tools,isa,obj,frontend=False):
        native,hosted,machine,flags=TARGETS[isa]
        carrier=self.directory/(isa+("-frontend" if frontend else "")+"-carrier.c")
        carrier.write_text(harness(frontend))
        link=[tools["clang"],"--target="+hosted,*flags,"-O2","-ffreestanding","-fno-builtin",
              "-fno-stack-protector","-fno-pic","-fno-pie","-nostdlib","-static","-fuse-ld=lld",
              "--ld-path="+tools["linker"],"-Wl,-e,_start","-Wl,--build-id=none",carrier]
        emulator=[] if isa=="x86_64" else [tools[isa]]
        executable=obj.with_suffix(".elf")
        self.command([*link,obj,"-o",executable]);elf(executable,machine,2)
        actual=self.command([*emulator,executable]).stdout
        self.assertEqual(actual,expected_output())
        broken=obj.with_suffix(".broken.elf")
        self.command([*link,obj,"-DCORRUPT_REFERENCE","-o",broken])
        negative=self.command([*emulator,broken],success=False)
        self.assertEqual(negative.returncode,31);self.assertEqual(negative.stdout,b"")
        return {"output":actual.decode(),"negative_control_exit":31,
                "object_sha256":hashlib.sha256(obj.read_bytes()).hexdigest(),
                "executable_sha256":hashlib.sha256(executable.read_bytes()).hexdigest()}

    def test_all_three_own_memory_objects_match_byte_snapshots_and_guarded_pages(self):
        tools=self.tools();report={"scope":"memory compiler conformance on Linux development carriers",
            "runtime_complete":False,"kernel_execution_verified":False,
            "tools":{name:artifact(path) for name,path in {"ocorec":self.compiler,**tools}.items()},"targets":{}}
        for isa,(native,_,machine,_) in TARGETS.items():
            with self.subTest(isa=isa):
                path=self.directory/(isa+".native.json");path.write_text(json.dumps(corpus(isa)))
                self.verify(path);obj=path.with_suffix(".o")
                self.command([self.compiler,path,"--input-kind","native-ir","--target",native,"--emit","obj","-o",obj])
                elf(obj,machine,1)
                report["targets"][isa]=self.execute(tools,isa,obj)
        self.assertEqual(len(report["targets"]),3)
        report["all_three_executions_passed"]=True
        (self.directory/"memory-conformance.json").write_text(json.dumps(report,indent=2))
        print("All three own memory objects: "+expected_output().decode().strip(),flush=True)

    def test_actual_unchanged_clang22_ll_and_bitcode_memory_lifetime_on_all_three(self):
        sdk=Path(os.environ.get("OCORE_TEST_LLVM22_BIN",str(SDK)))
        clang=sdk/"clang"
        if not clang.is_file():self.skipTest("optional source frontend test needs installed exact LLVM22.1.6 SDK; no download")
        version=self.command([clang,"--version"]).stdout.decode()
        self.assertRegex(version,r"\bclang version 22\.1\.6(?:\s|$)")
        tools=self.tools();source=ROOT/"tests/fixtures/ocore_import_memory.c"
        report={"scope":"original C memory/lifetime frontend through own objects on Linux development carriers",
            "runtime_complete":False,"kernel_execution_verified":False,"source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
            "frontend_profile":{"length":"64-bit size_t","fill":"32-bit int","volatile":False,
                                "lifetime_carrier_dependency":"opaque_escape"},
            "tools":{name:artifact(path) for name,path in {"ocorec":self.compiler,"frontend-clang":clang,**tools}.items()},"targets":{}}
        flags=["-O1","-ffreestanding","-fno-builtin","-fno-vectorize","-fno-slp-vectorize",
               "-fno-pic","-fno-pie","-fno-unwind-tables","-fno-asynchronous-unwind-tables","-fno-stack-protector"]
        for isa,(native,hosted,machine,target_flags) in TARGETS.items():
            with self.subTest(isa=isa):
                llvm=self.directory/(isa+".ll");bitcode=self.directory/(isa+".bc")
                frontend=[clang,"--target="+hosted,*target_flags,*flags,"-emit-llvm",source]
                self.command([*frontend,"-S","-o",llvm]);self.command([*frontend,"-c","-o",bitcode])
                original=llvm.read_text()
                for intrinsic in ("llvm.memcpy","llvm.memmove","llvm.memset","llvm.lifetime.start","llvm.lifetime.end"):
                    self.assertIn(intrinsic,original)
                target_report=[];objects=[]
                for path,kind in ((llvm,"llvm-ir"),(bitcode,"llvm-bc")):
                    imported=self.directory/(isa+"-"+kind+".native.json")
                    # llvm-ir admits both text and binary inputs by their bytes.
                    self.command([self.compiler,path,"--input-kind","llvm-ir","--target",native,"--emit","mir","-o",imported])
                    normalized=json.loads(imported.read_text());self.verify(imported)
                    bodies={fn["name"] for fn in normalized["functions"] if fn["entry"] is not None}
                    self.assertEqual(bodies,{"frontend_copy","frontend_move","frontend_set","frontend_lifetime"})
                    self.assertEqual(normalized["provenance"]["input_sha256"],hashlib.sha256(path.read_bytes()).hexdigest())
                    memory_ops=[item["operation"] for fn in normalized["functions"]
                                for block in fn["blocks"] for item in block["instructions"]
                                if item["operation"]["op"] in {"memory_set","memory_copy","lifetime"}]
                    self.assertEqual({op["end"] for op in memory_ops if op["op"]=="lifetime"},{False,True})
                    self.assertEqual({op["allow_overlap"] for op in memory_ops if op["op"]=="memory_copy"},{False,True})
                    self.assertEqual(sum(op["op"]=="memory_set" for op in memory_ops),2)
                    obj=self.directory/(isa+"-"+kind+".o")
                    self.command([self.compiler,imported,"--input-kind","native-ir","--target",native,"--emit","obj","-o",obj])
                    elf(obj,machine,1);objects.append(obj.read_bytes())
                    target_report.append(self.execute(tools,isa,obj,frontend=True))
                self.assertEqual(objects[0],objects[1],"unchanged .ll and .bc frontends must yield reproducible own bytes")
                report["targets"][isa]=target_report
        self.assertEqual(len(report["targets"]),3)
        report["all_three_executions_passed"]=True
        (self.directory/"frontend-memory-conformance.json").write_text(json.dumps(report,indent=2))


if __name__=="__main__":
    unittest.main()
