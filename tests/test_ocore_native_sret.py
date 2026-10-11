"""Typed indirect results against original Clang objects on every native ISA.

Unchanged LLVM and genuine C++ frontend units retain their result pointer
positions and RV64 LP64D profile. All four caller/callee compiler combinations
exercise the ABI. Linux startup and QEMU are test carriers, not runtime closure.
"""

import copy
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

from scripts.check_ocore_native_equivalence import TARGETS as SCALAR_TARGETS
from tests import test_ocore_native_alias as alias_qa
from tests import test_ocore_native_integer_widths as integer_qa
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
TARGETS = {isa:(native,triple,machine,["-march=rv64gc","-mabi=lp64d"] if isa=="riscv64" else flags)
           for isa,(native,triple,machine,flags) in SCALAR_TARGETS.items()}
RESULT_TYPE = "%Result = type {i64, i64, i64, i64}\n%Receiver = type {i64, i64}\n%Empty = type {}\n"
SEED_WORDS = (0x1020304050607080,0x8877665544332211,37,0xFFFFFFFFFFFFFFFE)
RECEIVER = (0x1122334455667788,0xFEDCBA9876543210)
OFFSET = 0x9E3779B97F4A7C15
PATHS = ("direct","alias","indirect","method","method_alias","method_indirect","no_access","empty")


def module_text(triple, body):
    text=weak.promises.module_text(triple,body)
    if triple.startswith("riscv64-"):
        text += '\n!llvm.module.flags = !{!0}\n!0 = !{i32 1, !"target-abi", !"lp64d"}\n'
    return text


def arguments(seed):
    return [(seed+OFFSET*(index+1))&MASK for index in range(9)]


def result_words(seed, method=False):
    values=arguments(seed)
    result=[(values[0]+values[8]+SEED_WORDS[0])&MASK,
            values[1]^values[6]^integer_qa.hash_values(values),
            (values[2]+values[3]+values[4])&MASK,
            values[5]^values[7]^values[8]]
    if method:
        result[0]=(result[0]+RECEIVER[0])&MASK
        result[3]^=RECEIVER[1]
    return result


def llvm_callee():
    plain=", ".join(["i64"]*9)
    parameters=", ".join(f"i64 %a{index}" for index in range(9))
    arguments_text=", ".join(f"i64 %a{index}" for index in range(9))
    reversed_arguments=", ".join(f"i64 %a{index}" for index in reversed(range(9)))
    lines=[RESULT_TYPE,
        "@source_seed = constant %Result {"+", ".join(f"i64 {word}" for word in SEED_WORDS)+"}, align 8",
        "@seed_alias = alias %Result, ptr @source_seed",
        f"declare i64 @clobber({plain})",
        f"define void @engine(ptr sret(%Result) align 8 %out, {parameters}) {{",
        f"  %nested = call i64 @clobber({arguments_text})",
        "  %seed = load i64, ptr @source_seed, align 8",
        "  %first = add i64 %a0, %a8", "  %word0 = add i64 %first, %seed",
        "  %mixed = xor i64 %a1, %a6", "  %word1 = xor i64 %mixed, %nested",
        "  %second = add i64 %a2, %a3", "  %word2 = add i64 %second, %a4",
        "  %third = xor i64 %a5, %a7", "  %word3 = xor i64 %third, %a8"]
    for index in range(4):
        lines += [f"  %p{index} = getelementptr %Result, ptr %out, i64 0, i32 {index}",
                  f"  store i64 %word{index}, ptr %p{index}, align 8"]
    lines += ["  %bit = and i64 %a0, 1", "  %condition = icmp eq i64 %bit, 0",
              "  br i1 %condition, label %even, label %odd", "even:",
              f"  %clobbered_even = call i64 @clobber({reversed_arguments})", "  ret void", "odd:",
              f"  %clobbered_odd = call i64 @clobber({arguments_text})", "  ret void", "}",
              f"@engine_alias = alias void (ptr, {plain}), ptr @engine",
              "@engine_pointer = constant ptr @engine_alias, align 8",
              f"define void @method(ptr %receiver, ptr sret(%Result) align 8 %out, {parameters}) {{",
              f"  call void @engine(ptr sret(%Result) align 8 %out, {arguments_text})",
              "  %bias = load i64, ptr %receiver, align 8",
              "  %mask_pointer = getelementptr %Receiver, ptr %receiver, i64 0, i32 1",
              "  %mask = load i64, ptr %mask_pointer, align 8",
              "  %word0_pointer = getelementptr %Result, ptr %out, i64 0, i32 0",
              "  %word3_pointer = getelementptr %Result, ptr %out, i64 0, i32 3",
              "  %word0 = load i64, ptr %word0_pointer, align 8",
              "  %word3 = load i64, ptr %word3_pointer, align 8",
              "  %adjusted0 = add i64 %word0, %bias", "  %adjusted3 = xor i64 %word3, %mask",
              "  store i64 %adjusted0, ptr %word0_pointer, align 8",
              "  store i64 %adjusted3, ptr %word3_pointer, align 8",
              f"  %clobbered = call i64 @clobber({reversed_arguments})", "  ret void", "}",
              f"@method_alias = alias void (ptr, ptr, {plain}), ptr @method",
              "@method_pointer = constant ptr @method_alias, align 8",
              "define void @no_access(ptr sret(%Result) align 8 %out) { ret void }",
              "define void @empty(ptr sret(%Empty) %out) { ret void }"]
    return "\n".join(lines)+"\n"


def llvm_caller():
    plain=", ".join(["i64"]*9)
    lines=[RESULT_TYPE,
        "@receiver = constant %Receiver {"+", ".join(f"i64 {word}" for word in RECEIVER)+"}, align 8",
        "@engine_pointer = external constant ptr", "@method_pointer = external constant ptr"]
    for name in ("engine","engine_alias"):
        lines.append(f"declare void @{name}(ptr sret(%Result) align 8, {plain})")
    for name in ("method","method_alias"):
        lines.append(f"declare void @{name}(ptr, ptr sret(%Result) align 8, {plain})")
    lines += ["declare void @no_access(ptr sret(%Result) align 8)","declare void @empty(ptr sret(%Empty))"]
    for path in PATHS:
        lines.append(f"define void @run_{path}(ptr %out, i64 %seed) {{")
        if path in {"no_access","empty"}:
            storage="%Empty" if path=="empty" else "%Result"
            lines += [f"  call void @{path}(ptr sret({storage}) align 8 %out)","  ret void","}"]
            continue
        for index in range(9):
            lines.append(f"  %a{index} = add i64 %seed, {(OFFSET*(index+1))&MASK}")
        method=path.startswith("method")
        indirect=path.endswith("indirect")
        if indirect:
            lines.append(f"  %pointer = load ptr, ptr @{'method' if method else 'engine'}_pointer, align 8")
            callee="%pointer"
        else:
            callee="@"+{"direct":"engine","alias":"engine_alias"}.get(path,path)
        result_arguments="ptr @receiver, ptr sret(%Result) align 8 %out" if method else "ptr sret(%Result) align 8 %out"
        args=", ".join(f"i64 %a{index}" for index in range(9))
        lines += [f"  call void {callee}({result_arguments}, {args})", "  ret void", "}"]
    return "\n".join(lines)+"\n"


def observed_values(words):
    yield from words
    for word in words:
        yield from word.to_bytes(8,"little")
    yield 0xA5A5A5A5A5A5A5A5
    yield 0xA5A5A5A5A5A5A5A5


def golden():
    values=[*SEED_WORDS,*SEED_WORDS,1]
    for seed in weak.inputs():
        for path in PATHS:
            words=[0xA5A5A5A5A5A5A5A5]*4 if path in {"no_access","empty"} else result_words(seed,path.startswith("method"))
            values.extend(observed_values(words))
    return f"OCORE-SRET digest={integer_qa.hash_values(values):016x} checks={len(values)}\n".encode()


def output_c(text, expected):
    output=expected.decode().rstrip();start=output.index("digest=")+len("digest=")
    text += f"if(checks!={int(output.split('checks=')[1])})return 37;\n"
    text += 'static char output[]="'+output[:start]+"0"*16+output[start+16:]+'\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{start}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
    text += r"""
#if defined(__x86_64__)
 if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
 if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
 return 0;
}
"""
    return text


def x86_return_observers():
    lines=[".text"]
    for path in PATHS:
        name="observe_"+path;method=path.startswith("method")
        stack=0 if path in {"no_access","empty"} else 48 if method else 32
        lines += [f".global {name}",f".type {name},@function",f"{name}:","pushq %rbx","movq %rdi,%rbx",f"subq ${stack},%rsp"]
        if path in {"no_access","empty"}:
            values=[]
        elif method:
            lines += ["movq %rbx,%rsi","leaq receiver(%rip),%rdi","movq $1,%rdx","movq $2,%rcx","movq $3,%r8","movq $4,%r9"]
            values=range(5,10)
        else:
            lines += ["movq $1,%rsi","movq $2,%rdx","movq $3,%rcx","movq $4,%r8","movq $5,%r9"]
            values=range(6,10)
        lines += [f"movq ${value},{index*8}(%rsp)" for index,value in enumerate(values)]
        if path.endswith("indirect"):
            lines += [f"movq {'method' if method else 'engine'}_pointer(%rip),%r11","call *%r11"]
        else:
            callee={"direct":"engine","alias":"engine_alias"}.get(path,path)
            lines.append("call "+callee)
        lines += ["cmpq %rbx,%rax","sete %al","movzbl %al,%eax",f"addq ${stack},%rsp","popq %rbx","ret",f".size {name},.-{name}"]
    return '__asm__('+json.dumps("\n".join(lines)+"\n")+');\n'


def carrier():
    reusable=weak.carrier(11)
    text=reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern u64 source_seed[4],seed_alias[4];\n"
    for path in PATHS:
        text += f"extern void run_{path}(void*,u64);\n"
    text += f"static void(*const runners[{len(PATHS)}])(void*,u64)={{"+",".join("run_"+path for path in PATHS)+"};\n"
    for label,method in (("plain",False),("method",True)):
        rows=["{"+",".join(f"{word}ULL" for word in result_words(seed,method))+"}" for seed in weak.inputs()]
        text += f"static const u64 {label}_expected[80][4]={{"+",\n".join(rows)+"};\n"
    text += r"""
static u64 clobber_count;
__attribute__((noinline)) u64 clobber(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u64 i){
 u64 values[9]={a,b,c,d,e,f,g,h,i},result=0xcbf29ce484222325ULL;
 ++clobber_count;for(u64 at=0;at<9;++at)result=(result^values[at])*0x100000001b3ULL;
 return result;
}
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
#if defined(__x86_64__)
"""+x86_return_observers()
    for path in PATHS:
        text += f"extern u64 observe_{path}(void*);\n"
    text += "#endif\nint conformance_main(void){\n"
    for name in ("source_seed","seed_alias"):
        for index,word in enumerate(SEED_WORDS):
            text += f"if(add({name}[{index}],{word}ULL))return 31;\n"
    text += r"""
 u64 volatile addresses[2]={(u64)source_seed,(u64)seed_alias};if(add(addresses[0]==addresses[1],1))return 31;
 for(u64 index=0;index<80;++index)for(u64 path=0;path<8;++path){
  u64 storage[6];for(u64 at=0;at<6;++at)storage[at]=0xa5a5a5a5a5a5a5a5ULL;
  static const u64 unchanged[4]={0xa5a5a5a5a5a5a5a5ULL,0xa5a5a5a5a5a5a5a5ULL,0xa5a5a5a5a5a5a5a5ULL,0xa5a5a5a5a5a5a5a5ULL};
  runners[path](storage+1,values[index]);const u64* expected=path>=6?unchanged:path>=3?method_expected[index]:plain_expected[index];
  for(u64 at=0;at<4;++at)if(add(storage[at+1],expected[at]))return 31;
  const unsigned char* bytes=(const unsigned char*)(storage+1);
  for(u64 at=0;at<32;++at)if(add(bytes[at],(expected[at/8]>>(8*(at%8)))&255))return 31;
  if(add(storage[0],0xa5a5a5a5a5a5a5a5ULL)||add(storage[5],0xa5a5a5a5a5a5a5a5ULL))return 31;
 }
 if(clobber_count!=1200)return 38;
#if defined(__x86_64__)
 u64 scratch[4];
"""
    for path in PATHS:
        text += f"if(observe_{path}(scratch)!=\n#ifdef CORRUPT_HIDDEN_RETURN\n0\n#else\n1\n#endif\n)return 32;\n"
    text += "if(clobber_count!=1215)return 38;\n#endif\n"
    text=output_c(text,golden())
    text += '#if defined(__x86_64__)\n__asm__'+reusable.split('#if defined(__x86_64__)\n__asm__',1)[1]
    return text


CPP_TYPES="using u64=unsigned long long; struct Result { u64 a,b,c,d; };\n"
CPP_CALLEE=CPP_TYPES+r"""
extern "C" { u64 cpp_bias=0x1122334455667788ULL; }
struct Maker { u64 bias; Result build(u64,u64,u64,u64,u64,u64,u64,u64,u64) const; };
Result Maker::build(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u64 i) const {
 return {a+i+bias+cpp_bias,b^g,c+d+e,f^h^i};
}
extern "C" Result cpp_engine(u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,u64 g,u64 h,u64 i){
 Maker maker{37};return maker.build(a,b,c,d,e,f,g,h,i);
}
extern "C" u64 unused_cpp_body(u64 value){return value^0x8877665544332211ULL;}
"""
CPP_CALLER=CPP_TYPES+r"""
extern "C" Result cpp_engine(u64,u64,u64,u64,u64,u64,u64,u64,u64);
extern "C" { Result(*cpp_pointer)(u64,u64,u64,u64,u64,u64,u64,u64,u64)=cpp_engine; }
"""
for _style in ("direct","indirect"):
    _callee="cpp_engine" if _style=="direct" else "cpp_pointer"
    _args=",".join(f"seed+{(OFFSET*(index+1))&MASK}ULL" for index in range(9))
    CPP_CALLER += f'extern "C" u64 cpp_{_style}(u64 seed,u64* output){{ Result value={_callee}({_args});output[0]=value.a;output[1]=value.b;output[2]=value.c;output[3]=value.d;return value.a+value.b+value.c+value.d;}}\n'


def cpp_words(seed):
    a=arguments(seed)
    return [(a[0]+a[8]+37+RECEIVER[0])&MASK,a[1]^a[6],(a[2]+a[3]+a[4])&MASK,a[5]^a[7]^a[8]]


def cpp_golden():
    values=[RECEIVER[0]]
    for seed in weak.inputs():
        for _ in range(2):
            words=cpp_words(seed)
            values += [sum(words)&MASK,*observed_values(words)]
    return f"OCORE-CPP-SRET digest={integer_qa.hash_values(values):016x} checks={len(values)}\n".encode()


def cpp_carrier():
    reusable=weak.carrier(11)
    text=reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern u64 cpp_bias,cpp_direct(u64,u64*),cpp_indirect(u64,u64*);\n"
    rows=["{"+",".join(f"{word}ULL" for word in cpp_words(seed))+"}" for seed in weak.inputs()]
    text += "static const u64 expected[80][4]={"+",\n".join(rows)+"};\n"
    text += r"""
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
int conformance_main(void){
 if(add(cpp_bias,0x1122334455667788ULL))return 31;
 for(u64 index=0;index<80;++index)for(u64 path=0;path<2;++path){
  u64 storage[6];for(u64 at=0;at<6;++at)storage[at]=0xa5a5a5a5a5a5a5a5ULL;
  u64 result=path?cpp_indirect(values[index],storage+1):cpp_direct(values[index],storage+1);
  const u64* words=expected[index];if(add(result,words[0]+words[1]+words[2]+words[3]))return 31;
  for(u64 at=0;at<4;++at)if(add(storage[at+1],words[at]))return 31;
  const unsigned char* bytes=(const unsigned char*)(storage+1);
  for(u64 at=0;at<32;++at)if(add(bytes[at],(words[at/8]>>(8*(at%8)))&255))return 31;
  if(add(storage[0],0xa5a5a5a5a5a5a5a5ULL)||add(storage[5],0xa5a5a5a5a5a5a5a5ULL))return 31;
 }
"""
    text=output_c(text,cpp_golden())
    return text+'#if defined(__x86_64__)\n__asm__'+reusable.split('#if defined(__x86_64__)\n__asm__',1)[1]


def elf(path,machine,kind):
    data=Path(path).read_bytes()
    if data[:6]!=b"\x7fELF\x02\x01" or int.from_bytes(data[16:18],"little")!=kind or int.from_bytes(data[18:20],"little")!=machine:
        raise AssertionError("incorrect little-endian ELF64 kind/ISA: "+str(path))
    if machine==243 and int.from_bytes(data[48:52],"little")&6!=4:
        raise AssertionError("the unchanged RV64 LP64D input must produce a genuine double-float ABI object")


class SretNativeTests(alias_qa.AliasNativeTests):
    test_actual_alias_identity_and_independent_strong_overrides_match_original_clang_all_three = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        frontend=cls.sdk/"clang++"
        if not frontend.is_file():
            reason="actual C++ frontend requires installed exact Clang++22.1.6: "+str(frontend)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
        result=subprocess.run([str(frontend),"--version"],capture_output=True,text=True,timeout=15)
        if result.returncode or not re.search(r"\bclang version 22\.1\.6\b",result.stdout):
            raise RuntimeError("exact C++ frontend Clang22.1.6 required")

    def setUp(self):
        retained=os.environ.get("OCORE_TEST_NATIVE_SRET_OUTPUT_DIR")
        if retained:
            root=Path(retained).expanduser().resolve();root.mkdir(parents=True,exist_ok=True)
            self.directory=Path(tempfile.mkdtemp(prefix="run-",dir=root))
        else:
            temporary=tempfile.TemporaryDirectory(prefix="ocore-native-sret-")
            self.addCleanup(temporary.cleanup);self.directory=Path(temporary.name)
        self.compiler_sha=weak.artifact(self.compiler)["sha256"];self.sequence=0

    def emulators(self):
        emulators={isa:shutil.which(os.environ.get("OCORE_TEST_QEMU_"+isa.upper(),"qemu-"+isa)) for isa in ("aarch64","riscv64")}
        if platform.machine() not in {"x86_64","AMD64"} or not all(emulators.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":self.fail("all-three execution tools required")
            self.skipTest("all-three execution tools unavailable")
        return emulators

    def inputs(self,stem,triple,body):
        source=self.directory/(stem+".ll");source.write_text(module_text(triple,body))
        binary=source.with_suffix(".bc");self.command([self.sdk/"llvm-as",source,"-o",binary])
        return source,binary

    def cpp_inputs(self,isa,triple,flags,role,body):
        source=self.directory/(isa+"-"+role+".cpp");source.write_text(body)
        paths=[]
        # This declared QA source profile has no exceptions, RTTI or library
        # calls. It is not a reduced build of any original compiler/runtime.
        for suffix in (".ll",".bc"):
            output=source.with_suffix(suffix)
            self.command([self.sdk/"clang++","--target="+triple,*flags,"-O0","-ffreestanding",
                "-fno-exceptions","-fno-rtti","-fno-pic","-fno-pie","-fno-stack-protector",
                "-emit-llvm","-S" if suffix==".ll" else "-c",source,"-o",output])
            paths.append(output)
        return paths

    def link(self,triple,flags,harness,objects,output,corrupt=None):
        argv=[self.sdk/"clang","--target="+triple,*flags,"--ld-path="+self.linker,"-O1","-ffreestanding",
            "-fno-builtin","-fno-stack-protector","-fno-pic","-fno-pie","-nostdlib","-static",
            "-Wl,--no-relax","-Wl,-e,_start",harness,*objects]
        if corrupt:argv.append("-D"+corrupt)
        self.command([*argv,"-o",output])

    def differential(self,cpp=False):
        emulators=self.emulators()
        report={"scope":"typed sret original LLVM/C++ compiler conformance on Linux carriers",
            "runtime_complete":False,"kernel_execution_verified":False,"dependency_closure_complete":False,
            "floating_point_computation_verified":False,"compiler_sha256":self.compiler_sha,
            "test_source":weak.artifact(__file__),"tools":{name:weak.artifact(path) for name,path in {
                "ocorec":self.compiler,"reference_clang":self.sdk/"clang","frontend_clang++":self.sdk/"clang++",
                "own_assembler":self.assembler,"llvm-as":self.sdk/"llvm-as","linker":self.linker,**emulators}.items()},"targets":{}}
        for isa,(target,triple,machine,flags) in TARGETS.items():
            harness=self.directory/(isa+"-carrier.c");harness.write_text(cpp_carrier() if cpp else carrier())
            objects,units,executions={},{},[]
            for role,body in (("caller",CPP_CALLER if cpp else llvm_caller()),("callee",CPP_CALLEE if cpp else llvm_callee())):
                paths=self.cpp_inputs(isa,triple,flags,role,body) if cpp else self.inputs(isa+"-"+role,triple,body)
                for source in paths:
                    original=source.read_bytes();normalized=source.with_name(source.name+".native.json")
                    receipt=source.with_name(source.name+".verification.json")
                    own,reference=source.with_name(source.name+".own.o"),source.with_name(source.name+".clang.o")
                    self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"--emit","mir","-o",normalized])
                    self.command([self.compiler,normalized,"--input-kind","native-ir","--verify-native","--receipt",receipt])
                    self.assertEqual(json.loads(receipt.read_text())["module_sha256"],weak.artifact(normalized)["sha256"])
                    self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"-o",own])
                    self.command([self.sdk/"clang","--target="+triple,*flags,"-fno-pic","-fno-pie","-O0","-c",source,"-o",reference])
                    self.assertEqual(source.read_bytes(),original)
                    module=json.loads(normalized.read_text())
                    self.assertEqual(len(module["functions"]),module["provenance"]["source_function_count"])
                    self.assertEqual(len(module["globals"]),module["provenance"]["source_global_count"])
                    if isa=="riscv64":self.assertEqual(module["target"]["abi"],"lp64d")
                    functions={item["name"]:item for item in module["functions"]}
                    if cpp:
                        if role=="callee":
                            self.assertEqual(functions["cpp_engine"]["signature"]["return_storage"]["param"],0)
                            self.assertTrue(any(name.startswith("_ZNK5Maker5build") for name in functions))
                            self.assertIsNotNone(functions["unused_cpp_body"]["entry"])
                    else:
                        self.assertEqual(len(module["functions"]),14 if role=="caller" else 5)
                        self.assertEqual(len(module["globals"]),3)
                        self.assertEqual(len(module["aliases"]),0 if role=="caller" else 3)
                        for name,function in functions.items():
                            if name in {"engine","engine_alias","method","method_alias"}:
                                self.assertEqual(function["signature"]["return_storage"]["param"],int(name.startswith("method")))
                    for obj in (own,reference):
                        elf(obj,machine,1)
                        symbols=weak.elf_symbols(obj)
                        for name,function in functions.items():
                            if function["entry"] is not None:
                                self.assertGreater(symbols[name]["size"],0,"every original definition has real emitted bytes")
                    objects[role,source.suffix,"own"],objects[role,source.suffix,"original_clang"]=own,reference
                    units[role,source.suffix]={"role":role,"input":weak.artifact(source),"module":weak.artifact(normalized),
                        "verification":weak.artifact(receipt),"own_object":weak.artifact(own),"original_clang_object":weak.artifact(reference)}
                    if cpp:units[role,source.suffix]["cpp_source"]=weak.artifact(source.with_suffix(".cpp"))
            for suffix in (".ll",".bc"):
                for caller in ("own","original_clang"):
                    for callee in ("own","original_clang"):
                        output=self.directory/(isa+suffix+"-"+caller+"-"+callee)
                        selected=[objects["caller",suffix,caller],objects["callee",suffix,callee]]
                        self.link(triple,flags,harness,selected,output);elf(output,machine,2)
                        result=self.command([output] if isa=="x86_64" else [emulators[isa],output])
                        self.assertEqual(result.stdout,cpp_golden() if cpp else golden())
                        executions.append({"input_kind":suffix,"caller":caller,"callee":callee,
                            "executable":weak.artifact(output),"stdout":result.stdout.decode(),"exit_code":0,
                            "x86_hidden_pointer_return_checks":len(PATHS) if isa=="x86_64" and not cpp else 0})
                        if caller==callee=="own":
                            corrupt=output.with_name(output.name+".corrupt")
                            self.link(triple,flags,harness,selected,corrupt,"CORRUPT_ORACLE")
                            failed=self.command([corrupt] if isa=="x86_64" else [emulators[isa],corrupt],success=False)
                            self.assertEqual(failed.returncode,31);self.assertEqual(failed.stdout,b"")
                            executions.append({"input_kind":suffix,"corrupt_oracle":True,"executable":weak.artifact(corrupt),"exit_code":31})
                            if isa=="x86_64" and not cpp:
                                hidden=output.with_name(output.name+".hidden-corrupt")
                                self.link(triple,flags,harness,selected,hidden,"CORRUPT_HIDDEN_RETURN")
                                failed=self.command([hidden],success=False)
                                self.assertEqual(failed.returncode,32);self.assertEqual(failed.stdout,b"")
                                executions.append({"input_kind":suffix,"corrupt_hidden_pointer_oracle":True,"executable":weak.artifact(hidden),"exit_code":32})
            report["targets"][isa]={"profile":{"triple":triple,"flags":flags},"modules":list(units.values()),"executions":executions}
        self.assertEqual(weak.artifact(self.compiler)["sha256"],self.compiler_sha)
        name="cpp-sret-conformance.json" if cpp else "sret-conformance.json"
        (self.directory/name).write_text(json.dumps(report,indent=2)+"\n")

    def test_original_llvm_sret_exact_abi_aliases_multiple_returns_nested_calls_all_three(self):
        self.differential()

    def test_genuine_cpp_aggregate_returns_keep_original_parameter_order_and_lp64d_all_three(self):
        self.differential(cpp=True)

    def test_malformed_return_storage_contracts_reject_whole_modules_and_receipts(self):
        source,_=self.inputs("contracts",TARGETS["x86_64"][1],llvm_callee())
        normalized=source.with_name(source.name+".native.json")
        self.command([self.compiler,source,"--input-kind","llvm-ir","--emit","mir","-o",normalized])
        original=json.loads(normalized.read_text());functions={item["name"]:item for item in original["functions"]}
        self.assertEqual(functions["engine"]["signature"]["return_storage"]["param"],0)
        void=next(index for index,ty in enumerate(original["types"]) if ty["kind"]=="void")
        int64=next(index for index,ty in enumerate(original["types"]) if ty=={"kind":"int","bits":64})
        pointer=next(index for index,ty in enumerate(original["types"]) if ty=={"kind":"pointer","address_space":0})
        storage=functions["engine"]["signature"]["return_storage"]["ty"]
        def late_storage(module,_signature):
            declaration=copy.deepcopy(functions["clobber"])
            declaration["name"]="late_storage"
            declaration["signature"]={"params":[pointer,int64,pointer],"result":void,"abi":"c","variadic":False,
                "param_attributes":[[],[],[]],"result_attributes":[],"return_storage":{"param":2,"ty":storage}}
            declaration["params"]=[{"id":index,"ty":ty} for index,ty in enumerate((pointer,int64,pointer))]
            module["functions"].append(declaration)
            module["provenance"]["source_function_count"]+=1
        def unsized_function(module,signature):
            ty=len(module["types"])
            module["types"].append({"kind":"function","signature":{"params":[],"result":void,"abi":"c","variadic":False,
                "param_attributes":[],"result_attributes":[]}})
            signature["return_storage"]["ty"]=ty
        def callsite_storage_mismatch(module,_signature):
            method=next(item for item in module["functions"] if item["name"]=="method")
            operation=next(instruction["operation"] for block in method["blocks"] for instruction in block["instructions"]
                           if instruction["operation"]["op"]=="call" and instruction["operation"]["callee"].get("name")=="engine")
            operation["signature"]["return_storage"]["ty"]=int64
        def non_void_result(module,_signature):
            # An unused declaration isolates this signature guard without
            # changing the original engine's aliases, calls or return bodies.
            declaration=copy.deepcopy(functions["clobber"])
            declaration["name"]="non_void_storage"
            declaration["signature"]={"params":[pointer],"result":int64,"abi":"c","variadic":False,
                "param_attributes":[[]],"result_attributes":[],"return_storage":{"param":0,"ty":storage}}
            declaration["params"]=[{"id":0,"ty":pointer}]
            module["functions"].append(declaration)
            module["provenance"]["source_function_count"]+=1
        changes=[("param_out_of_range",lambda module,signature:signature["return_storage"].update(param=100)),
            ("non_pointer_parameter",lambda module,signature:signature["return_storage"].update(param=1)),
            ("unsized_void_storage",lambda module,signature:signature["return_storage"].update(ty=void)),
            ("missing_type",lambda module,signature:signature["return_storage"].update(ty=len(module["types"])+100)),
            ("non_void_result",non_void_result),
            ("unknown_storage_field",lambda module,signature:signature["return_storage"].update(untrusted=True)),
            ("negative_parameter",lambda module,signature:signature["return_storage"].update(param=-1)),
            ("third_parameter_outside_llvm_profile",late_storage),
            ("unsized_function_storage",unsized_function),
            ("callsite_storage_mismatch",callsite_storage_mismatch)]
        diagnostics={
            "param_out_of_range":"return storage must annotate the first or second parameter",
            "non_pointer_parameter":"return storage requires an address-space-zero pointer parameter",
            "unsized_void_storage":f"type {void} is unsized",
            "missing_type":"is out of bounds",
            "non_void_result":"return storage requires a void result",
            "unknown_storage_field":"unknown field `untrusted`",
            "negative_parameter":"invalid value: integer `-1`, expected usize",
            "third_parameter_outside_llvm_profile":"return storage must annotate the first or second parameter",
            "unsized_function_storage":f"type {len(original['types'])} is unsized",
            "callsite_storage_mismatch":"direct callee symbol/signature mismatch",
        }
        records=[]
        for name,change in changes:
            module=copy.deepcopy(original);signature=next(item for item in module["functions"] if item["name"]=="engine")["signature"]
            change(module,signature)
            mutant=self.directory/(name+".json");mutant.write_text(json.dumps(module)+"\n")
            receipt=mutant.with_suffix(".receipt.json");receipt.write_text("stale success must be removed")
            result=self.command([self.compiler,mutant,"--input-kind","native-ir","--verify-native","--receipt",receipt],success=False)
            self.assertNotEqual(result.returncode,0);self.assertFalse(receipt.exists())
            self.assertIn(diagnostics[name],result.stderr.decode(errors="replace"))
            output=mutant.with_suffix(".o")
            emitted=self.command([self.compiler,mutant,"--input-kind","native-ir","-o",output],success=False)
            self.assertNotEqual(emitted.returncode,0);self.assertFalse(output.exists())
            self.assertIn(diagnostics[name],emitted.stderr.decode(errors="replace"))
            records.append({"case":name,"input":weak.artifact(mutant),"verify_exit_code":result.returncode,
                            "emit_exit_code":emitted.returncode,"expected_diagnostic":diagnostics[name],"stderr":result.stderr.decode(errors="replace")})
        (self.directory/"sret-contract-negatives.json").write_text(json.dumps({"runtime_complete":False,
            "compiler":weak.artifact(self.compiler),"test_source":weak.artifact(Path(__file__)),"cases":records},indent=2)+"\n")


if __name__=="__main__":
    unittest.main()
