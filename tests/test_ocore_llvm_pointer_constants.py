"""Exact initializer-only pointer bits and original LLVM native references.

The Linux startup carrier checks data representations, never dereferences a
literal-created pointer. Complete runtime closure and mapping validity remain
outside this compiler conformance test. LLVM input bytes are never rewritten.
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

from scripts.check_ocore_foreign_frontends import HARNESS as LINUX_CARRIER
from scripts.check_ocore_native_equivalence import TARGETS, elf


ROOT = Path(__file__).resolve().parents[1]
SDK = Path.home()/".cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin"
MASK = (1 << 64)-1
LAYOUT = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"
EXTRA = [(1,0),(8,-128),(16,-32768),(32,-2147483648),
         (63,-(1 << 62)),(64,-(1 << 63)),(64,-1),(64,0x0123456789ABCDEF)]
LITERALS = [(width,-1) for width in range(1,65)] + EXTRA
WORDS = [number & ((1 << width)-1) for width,number in LITERALS]
RELOCATIONS = [(9,0),(17,5),(34,11)]
EXPORTS = {"anchors","words","nested","get_word","get_nested","get_nested_byte"}


def artifact(path):
    path=Path(path).resolve();digest=hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda:source.read(1024*1024),b""):digest.update(block)
    return {"path":str(path),"sha256":digest.hexdigest(),"bytes":path.stat().st_size}


def packed_bytes():
    data=bytearray(44)
    data[0]=0xA5
    data[1:9]=(255).to_bytes(8,"little")
    data[25]=0xC2
    data[26:34]=MASK.to_bytes(8,"little")
    data[42:44]=(0x1234).to_bytes(2,"little")
    return data


def original_module(triple, body=None, layout=None):
    layout=layout or LAYOUT+("-Fn32" if triple.startswith("aarch64-") else "")
    header=f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n'
    if body is not None:return header+body
    pointers=", ".join(f"ptr inttoptr (i{width} {number} to ptr)" for width,number in LITERALS)
    return header+f"""
@anchors = constant [16 x i8] [{", ".join("i8 "+str(i) for i in range(1,17))}], align 1
@words = constant [{len(LITERALS)} x ptr] [{pointers}], align 8
@nested = constant <{{i8, [3 x ptr], <{{i8, ptr, ptr}}>, i16}}> <{{
  i8 -91,
  [3 x ptr] [ptr inttoptr (i8 -1 to ptr), ptr @anchors,
             ptr getelementptr ([16 x i8], ptr @anchors, i64 0, i64 5)],
  <{{i8, ptr, ptr}}> <{{i8 -62, ptr inttoptr (i64 -1 to ptr),
                       ptr getelementptr ([16 x i8], ptr @anchors, i64 0, i64 11)}}>,
  i16 4660
}}>, align 1
define i64 @get_word(i64 %index) {{
  %slot = getelementptr [{len(LITERALS)} x ptr], ptr @words, i64 0, i64 %index
  %pointer = load ptr, ptr %slot, align 8
  %bits = ptrtoint ptr %pointer to i64
  ret i64 %bits
}}
define i64 @get_nested(i64 %offset) {{
  %slot = getelementptr i8, ptr @nested, i64 %offset
  %pointer = load ptr, ptr %slot, align 1
  %bits = ptrtoint ptr %pointer to i64
  ret i64 %bits
}}
define i64 @get_nested_byte(i64 %offset) {{
  %slot = getelementptr i8, ptr @nested, i64 %offset
  %byte = load i8, ptr %slot, align 1
  %wide = zext i8 %byte to i64
  ret i64 %wide
}}
"""


def expected_output():
    digest=0xCBF29CE484222325
    data=b"".join(number.to_bytes(8,"little") for number in WORDS)+packed_bytes()
    for byte in data:digest=((digest^byte)*0x100000001B3)&MASK
    return f"OCORE-POINTER-INITIALIZERS digest={digest:016x} checks={len(WORDS)+44+3}\n".encode()


def carrier():
    syscall=LINUX_CARRIER.split("static u64 syscall3",1)[1].split("static u64 signed_bits",1)[0]
    startup=LINUX_CARRIER.split("#if defined(__x86_64__)\n__asm__",1)[1]
    text="typedef unsigned long long u64;typedef unsigned char byte;\nstatic u64 syscall3"+syscall
    text+="\nextern const byte anchors[16],oracle_anchors[16],nested[44],oracle_nested[44];\n"
    text+="extern u64 get_word(u64),oracle_get_word(u64),get_nested(u64),oracle_get_nested(u64),get_nested_byte(u64),oracle_get_nested_byte(u64);\n"
    text+="static const u64 expected_words[]={"+",".join(str(n)+"ULL" for n in WORDS)+"};\n"
    text+="static const byte expected_packed[]={"+",".join(str(n) for n in packed_bytes())+"};\n"
    text+=r"""
static u64 digest=0xcbf29ce484222325ULL;
static void add(byte value){digest=(digest^value)*0x100000001b3ULL;}
int conformance_main(void) {
    u64 checks=0;
    for(u64 i=0;i<sizeof(expected_words)/sizeof(expected_words[0]);++i){
        u64 expected=expected_words[i];
#ifdef CORRUPT_EXPECTED
        if(i==0)expected^=1;
#endif
        u64 own=get_word(i),oracle=oracle_get_word(i);
        if(own!=expected||oracle!=expected||own!=oracle)return 31;
        for(u64 byte_index=0;byte_index<8;++byte_index)add((byte)(own>>(8*byte_index)));
        ++checks;
    }
    static const u64 offsets[]={9,17,34},addends[]={0,5,11};
    for(u64 j=0;j<3;++j){
        if(get_nested(offsets[j])!=(u64)anchors+addends[j])return 32;
        if(oracle_get_nested(offsets[j])!=(u64)oracle_anchors+addends[j])return 33;
        ++checks;
    }
    if(get_nested(1)!=255||oracle_get_nested(1)!=255)return 34;
    if(get_nested(26)!=~0ULL||oracle_get_nested(26)!=~0ULL)return 35;
    for(u64 i=0;i<44;++i){
        byte expected=expected_packed[i],oracle_expected=expected;
        for(u64 j=0;j<3;++j)if(i>=offsets[j]&&i<offsets[j]+8){
            expected=(byte)(((u64)anchors+addends[j])>>(8*(i-offsets[j])));
            oracle_expected=(byte)(((u64)oracle_anchors+addends[j])>>(8*(i-offsets[j])));
        }
        if(get_nested_byte(i)!=expected||nested[i]!=expected)return 36;
        if(oracle_get_nested_byte(i)!=oracle_expected||oracle_nested[i]!=oracle_expected)return 37;
        add(expected_packed[i]);++checks;
    }
    for(u64 i=0;i<16;++i)if(anchors[i]!=i+1||oracle_anchors[i]!=i+1)return 38;
"""
    text+=f"if(checks!={len(WORDS)+44+3})return 39;\n"
    output=expected_output().decode().rstrip()
    digest=output.split("digest=",1)[1].split(" ",1)[0]
    text+='static char output[]="'+output.replace(digest,"0"*16)+'\\n";\n'
    text+=r"""
    for(u64 i=0;i<16;++i){u64 nibble=(digest>>(60-4*i))&15;output[sizeof("OCORE-POINTER-INITIALIZERS digest=")-1+i]=(char)(nibble<10?'0'+nibble:'a'+nibble-10);}
#if defined(__x86_64__)
    if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
    if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
    return 0;
}
#if defined(__x86_64__)
__asm__"""+startup
    return text


class LlvmPointerInitializerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler=Path(os.environ.get("OCOREC",str(ROOT/"target/debug/ocorec"))).resolve()
        if not cls.compiler.is_file():raise unittest.SkipTest("actual built ocorec required; this suite does not run Cargo")
        cls.sdk=Path(os.environ.get("OCORE_TEST_LLVM22_BIN",str(SDK))).resolve()
        for name in ("clang","llvm-as","llvm-objcopy","llvm-nm"):
            tool=cls.sdk/name
            if not tool.is_file():
                reason="original reference needs installed exact LLVM22.1.6 SDK; no download: "+str(tool)
                if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":raise RuntimeError(reason)
                raise unittest.SkipTest(reason)
            result=subprocess.run([str(tool),"--version"],capture_output=True,text=True,timeout=15)
            if result.returncode or not re.search(r"\b(?:clang version|LLVM version) 22\.1\.6(?:\s|$)",result.stdout):
                raise RuntimeError("reference tool must be exact LLVM22.1.6: "+str(tool))

    def setUp(self):
        retained=os.environ.get("OCORE_TEST_POINTER_CONSTANTS_OUTPUT_DIR")
        if retained:
            root=Path(retained).expanduser().resolve();root.mkdir(parents=True,exist_ok=True)
            self.directory=Path(tempfile.mkdtemp(prefix="run-",dir=root))
        else:
            temporary=tempfile.TemporaryDirectory(prefix="ocore-pointer-constants-")
            self.addCleanup(temporary.cleanup);self.directory=Path(temporary.name)
        self.compiler_sha256=hashlib.sha256(self.compiler.read_bytes()).hexdigest()
        self.sequence=0

    def command(self,argv,success=True):
        result=subprocess.run([str(arg) for arg in argv],cwd=ROOT,capture_output=True,timeout=120)
        path=self.directory/f"command-{self.sequence:03}.json";self.sequence+=1
        path.write_text(json.dumps({"argv":[str(arg) for arg in argv],"exit_code":result.returncode,
            "stdout":result.stdout.decode(errors="replace"),"stderr":result.stderr.decode(errors="replace")},indent=2))
        if success:self.assertEqual(result.returncode,0,result.stderr.decode(errors="replace")+result.stdout.decode(errors="replace"))
        return result

    def inputs(self,name,triple,body=None,layout=None):
        source=self.directory/(name+".ll");source.write_text(original_module(triple,body,layout))
        binary=source.with_suffix(".bc")
        self.command([self.sdk/"llvm-as",source,"-o",binary])
        self.assertTrue(binary.read_bytes().startswith(b"BC\xc0\xde"))
        return source,binary

    def imported(self,path,native_target):
        result=path.with_name(path.stem+"-"+path.suffix[1:]+".native.json")
        original=path.read_bytes()
        self.command([self.compiler,path,"--input-kind","llvm-ir","--target",native_target,"--emit","mir","-o",result])
        native=json.loads(result.read_text())
        self.assertEqual(path.read_bytes(),original)
        self.assertEqual(native["provenance"]["input_sha256"],hashlib.sha256(original).hexdigest())
        receipt=result.with_suffix(".verified.json")
        self.command([self.compiler,result,"--input-kind","native-ir","--verify-native","--receipt",receipt])
        verified=json.loads(receipt.read_text())
        self.assertTrue(verified["verified"])
        self.assertEqual(verified["scope"],"structural_ir_verification")
        self.assertEqual(verified["module_sha256"],hashlib.sha256(result.read_bytes()).hexdigest())
        return result,native

    def assert_data(self,native):
        self.assertEqual({fn["name"] for fn in native["functions"]},{"get_word","get_nested","get_nested_byte"})
        globals_by_name={glob["name"]:glob for glob in native["globals"]}
        self.assertEqual(set(globals_by_name),{"anchors","words","nested"})
        words=globals_by_name["words"]["initializer"]
        self.assertEqual(words,{"bytes":list(b"".join(n.to_bytes(8,"little") for n in WORDS)),"relocations":[]})
        nested=globals_by_name["nested"]
        self.assertEqual(nested["alignment"],1)
        self.assertEqual(nested["initializer"],{"bytes":list(packed_bytes()),"relocations":[
            {"offset":offset,"width":64,"symbol":"anchors","addend":addend} for offset,addend in RELOCATIONS]})
        self.assertEqual(globals_by_name["anchors"]["initializer"],{"bytes":list(range(1,17)),"relocations":[]})
        # Compile-time integer widths must not become unsupported executable
        # integer types; no i2/i3/... operation is being admitted by this test.
        self.assertTrue(all(ty["kind"]!="int" or ty["bits"] in {1,8,16,32,64} for ty in native["types"]))

    def test_all_literal_integer_widths_and_nested_relocations_preserve_exact_ll_and_bc_bytes(self):
        for isa,(target,triple,_,_) in TARGETS.items():
            with self.subTest(isa=isa):
                for path in self.inputs(isa,triple):
                    _,native=self.imported(path,target)
                    self.assert_data(native)
                # LLVM canonicalizes this wide zero expression into an AS0
                # null pointer before import. Rejecting surviving wide literal
                # operands must not reject the supported normalized contract.
                for path in self.inputs(isa+"-normalized-wide-zero",triple,
                                        "@normalized = constant ptr inttoptr (i128 0 to ptr), align 8\n"):
                    _,native=self.imported(path,target)
                    self.assertEqual(native["globals"][0]["initializer"],{"bytes":[0]*8,"relocations":[]})
                    self.assertFalse(any(ty["kind"]=="int" and ty["bits"]>64 for ty in native["types"]))
        self.assertEqual(hashlib.sha256(self.compiler.read_bytes()).hexdigest(),self.compiler_sha256)

    def test_unsupported_whole_units_cannot_emit_partial_initializer_artifacts(self):
        cases=[
            ("wide65","@bad = global ptr inttoptr (i65 -1 to ptr)\n",None),
            ("wide128","@bad = global ptr inttoptr (i128 -1 to ptr)\n",None),
            ("address_space","@bad = global ptr addrspace(1) inttoptr (i64 7 to ptr addrspace(1))\n",LAYOUT+"-p1:64:64"),
            ("nonintegral","@bad = global ptr addrspace(1) inttoptr (i64 7 to ptr addrspace(1))\n",LAYOUT+"-p1:64:64-ni:1"),
            ("pointer32","@bad = global ptr inttoptr (i8 -1 to ptr)\n","e-p:32:32-i64:64-n8:16:32:64-S128"),
            ("bigendian","@bad = global ptr inttoptr (i8 -1 to ptr)\n",LAYOUT.replace("e-","E-",1)),
            ("symbol_xor","@bad = global ptr inttoptr (i64 xor (i64 ptrtoint (ptr @good to i64), i64 7) to ptr)\n",None),
        ]
        good="@good = global i64 7\ndefine i64 @otherwise_valid_cold() { ret i64 9 }\n"
        for isa,(target,triple,_,_) in TARGETS.items():
            for name,bad,layout in cases:
                with self.subTest(isa=isa,case=name):
                    for path in self.inputs(isa+"-"+name,triple,good+bad,layout):
                        output=path.with_name(path.name+".rejected.json")
                        result=self.command([self.compiler,path,"--input-kind","llvm-ir","--target",target,"--emit","mir","-o",output],success=False)
                        self.assertNotEqual(result.returncode,0)
                        self.assertTrue(result.stderr.strip(),"whole-unit rejection needs a real diagnostic")
                        self.assertFalse(output.exists(),"cold unsupported globals cannot create a partial module")

    def test_actual_own_objects_and_unmodified_clang22_reference_match_all_three_isas(self):
        linker=shutil.which(os.environ.get("LD_LLD","ld.lld"))
        emulators={isa:shutil.which(os.environ.get("OCORE_TEST_QEMU_"+isa.upper(),"qemu-"+isa)) for isa in ("aarch64","riscv64")}
        if not linker or not all(emulators.values()) or platform.machine() not in {"x86_64","AMD64"}:
            reason="original pointer reference execution requires x86 host, ld.lld and both real QEMU user emulators"
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":self.fail(reason)
            self.skipTest(reason)
        harness=self.directory/"carrier.c";harness.write_text(carrier())
        report={"scope":"initializer bit representation on Linux development carriers",
                "compiler_sha256":self.compiler_sha256,"runtime_complete":False,
                "kernel_execution_verified":False,"literal_pointer_mapping_validity_verified":False,
                "tools":{name:artifact(path) for name,path in {
                    "ocorec":self.compiler,"clang":self.sdk/"clang","llvm-as":self.sdk/"llvm-as",
                    "llvm-objcopy":self.sdk/"llvm-objcopy","llvm-nm":self.sdk/"llvm-nm",
                    "ld.lld":linker,**emulators}.items()},"targets":{}}
        for isa,(target,triple,machine,flags) in TARGETS.items():
            target_report=[]
            for source in self.inputs(isa,triple):
                with self.subTest(isa=isa,input=source.suffix):
                    imported,native=self.imported(source,target);self.assert_data(native)
                    own=source.with_name(isa+"-"+source.suffix[1:]+"-own.o")
                    self.command([self.compiler,imported,"--input-kind","native-ir","--target",target,"--emit","obj","-o",own]);elf(own,machine,1)
                    original=own.with_name(own.stem+"-original.o")
                    self.command([self.sdk/"clang","--target="+triple,*flags,"-O0","-fno-pic","-fno-pie","-fno-unwind-tables","-fno-asynchronous-unwind-tables","-c",source,"-o",original]);elf(original,machine,1)
                    symbols=self.command([self.sdk/"llvm-nm","--defined-only","--format=posix",original]).stdout.decode()
                    self.assertEqual({line.split()[0] for line in symbols.splitlines() if line.split()[1].isupper()},EXPORTS)
                    oracle=own.with_name(own.stem+"-oracle.o")
                    renames=[argument for symbol in sorted(EXPORTS) for argument in ["--redefine-sym",symbol+"=oracle_"+symbol]]
                    self.command([self.sdk/"llvm-objcopy",*renames,original,oracle])
                    link=[self.sdk/"clang","--target="+triple,*flags,"-O2","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-pic","-fno-pie","-nostdlib","-static","-fuse-ld=lld","--ld-path="+linker,"-Wl,-e,_start","-Wl,--build-id=none",harness,own,oracle]
                    executable=own.with_suffix(".elf");self.command([*link,"-o",executable]);elf(executable,machine,2)
                    emulator=[] if isa=="x86_64" else [emulators[isa]]
                    actual=self.command([*emulator,executable]).stdout;self.assertEqual(actual,expected_output())
                    broken=own.with_suffix(".broken.elf");self.command([*link,"-DCORRUPT_EXPECTED","-o",broken])
                    negative=self.command([*emulator,broken],success=False)
                    self.assertEqual(negative.returncode,31);self.assertEqual(negative.stdout,b"")
                    target_report.append({"source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
                        "own_object_sha256":hashlib.sha256(own.read_bytes()).hexdigest(),
                        "original_reference_object_sha256":hashlib.sha256(original.read_bytes()).hexdigest(),
                        "output":actual.decode(),"corrupted_expected_exit":31})
            self.assertEqual(len(target_report),2);report["targets"][isa]=target_report
        self.assertEqual(len(report["targets"]),3)
        self.assertEqual(hashlib.sha256(self.compiler.read_bytes()).hexdigest(),self.compiler_sha256)
        report["all_three_executions_passed"]=True
        (self.directory/"pointer-initializer-conformance.json").write_text(json.dumps(report,indent=2))
        print("All three own pointer initializers: "+expected_output().decode().strip(),flush=True)


if __name__=="__main__":
    unittest.main()
