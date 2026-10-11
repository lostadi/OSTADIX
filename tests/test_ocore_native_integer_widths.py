"""Every LLVM integer width against original objects and an independent oracle.

The C carrier calls only i64 exports. Unusual integer parameter/return types
cross exact LLVM callers and callees in all four own/reference combinations.
Memory checks follow same-type stores and ignore unspecified padding bits.
These Linux carrier tests do not qualify a complete compiler or native kernel.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_native_alias as alias_qa
from tests import test_ocore_native_memory as memory_qa
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
MIXED_WIDTHS = (1, 3, 7, 9, 13, 21, 25, 33, 37, 41, 45, 49, 53, 57, 61, 63)
OFFSET = 0x9E3779B97F4A7C15
FNV_OFFSET, FNV_PRIME = 0xCBF29CE484222325, 0x100000001B3


def mask(width):
    return (1 << width) - 1


def signed(value, width):
    value &= mask(width)
    return value - (1 << width) if value & (1 << (width - 1)) else value


def hash_values(values):
    result = FNV_OFFSET
    for value in values:
        result = ((result ^ (value & MASK)) * FNV_PRIME) & MASK
    return result


def samples(width):
    edge = 1 << (width - 1)
    return [*weak.inputs(), mask(width), edge, edge - 1, edge + 1, mask(width) - 1]


def arguments(width, index):
    values = samples(width)
    # 67 is coprime to every supported width, so 85 cases cover all legal
    # shift counts 0..width-1, including non-power-of-two widths such as i37.
    return values[index], (values[(index + 17) % len(values)] ^ OFFSET) & MASK, index * 67 + 11


def arithmetic(width, value, other, count):
    limit = mask(width)
    a, b, shift = value & limit, other & limit, count % width
    sa, sb = signed(a, width), signed(b, width)
    divisor = b | 1
    results = [(a + b) & limit, (a - b) & limit, (a * b) & limit,
               a & b, a | b, a ^ b, (a << shift) & limit, a >> shift,
               (sa >> shift) & limit, a // divisor, a % divisor]
    if width != 1:
        signed_divisor = (b & ((1 << (width - 2)) - 1)) | 1
        quotient = abs(sa) // signed_divisor
        quotient = -quotient if sa < 0 else quotient
        results += [quotient & limit, (sa - quotient * signed_divisor) & limit]
    results += [int(a == b), int(a < b), int(sa < sb), a if sa < sb else b, sa & MASK]
    return hash_values(results)


def return_value(width, a, b):
    return (((a & mask(width)) - (b & mask(width))) ^ (OFFSET & mask(width))) & mask(width)


def returned(width, a, b):
    return hash_values((return_value(width, a, b), return_value(width, b, a)))


def mixed(seed):
    return hash_values(((seed + OFFSET * (index + 1)) & mask(width))
                       for index, width in enumerate(MIXED_WIDTHS))


def hash_ir(names, widths, stem="hash"):
    lines, previous = [], str(FNV_OFFSET)
    for index, (name, width) in enumerate(zip(names, widths)):
        wide = name
        if width < 64:
            wide = f"%{stem}_wide{index}"
            lines.append(f"  {wide} = zext i{width} {name} to i64")
        xor, result = f"%{stem}_xor{index}", f"%{stem}_{index}"
        lines += [f"  {xor} = xor i64 {previous}, {wide}",
                  f"  {result} = mul i64 {xor}, {FNV_PRIME}"]
        previous = result
    return lines, previous


def caller_body():
    lines = []
    for width in range(1, 65):
        ty = f"i{width}"
        lines += [f"declare {ty} @returned_{width}({ty}, {ty})",
                  f"@returned_pointer_{width} = constant ptr @returned_{width}, align 8",
                  f"define i64 @arithmetic_{width}(i64 %value, i64 %other, i64 %count) {{"]
        lines += (["  %a = or i64 %value, 0", "  %b = or i64 %other, 0"] if width == 64 else
                  [f"  %a = trunc i64 %value to {ty}", f"  %b = trunc i64 %other to {ty}"])
        lines.append(f"  %bounded = urem i64 %count, {width}")
        lines.append("  %shift = or i64 %bounded, 0" if width == 64 else f"  %shift = trunc i64 %bounded to {ty}")
        names, widths = [], []
        for operation in ("add", "sub", "mul", "and", "or", "xor", "shl", "lshr", "ashr"):
            name = "%" + operation
            rhs = "%shift" if operation in {"shl", "lshr", "ashr"} else "%b"
            lines.append(f"  {name} = {operation} {ty} %a, {rhs}")
            names.append(name); widths.append(width)
        lines += [f"  %unsigned_divisor = or {ty} %b, 1",
                  f"  %udiv = udiv {ty} %a, %unsigned_divisor",
                  f"  %urem = urem {ty} %a, %unsigned_divisor"]
        names += ["%udiv", "%urem"]; widths += [width, width]
        if width != 1:
            lines += [f"  %signed_small = and {ty} %b, {(1 << (width - 2)) - 1}",
                      f"  %signed_divisor = or {ty} %signed_small, 1",
                      f"  %sdiv = sdiv {ty} %a, %signed_divisor",
                      f"  %srem = srem {ty} %a, %signed_divisor"]
            names += ["%sdiv", "%srem"]; widths += [width, width]
        for predicate in ("eq", "ult", "slt"):
            name = "%" + predicate
            lines.append(f"  {name} = icmp {predicate} {ty} %a, %b")
            names.append(name); widths.append(1)
        lines.append(f"  %selected = select i1 %slt, {ty} %a, {ty} %b")
        names.append("%selected"); widths.append(width)
        lines.append("  %signed = or i64 %a, 0" if width == 64 else f"  %signed = sext {ty} %a to i64")
        names.append("%signed"); widths.append(64)
        operations, result = hash_ir(names, widths)
        lines += operations + [f"  ret i64 {result}", "}",
                  f"define i64 @memory_{width}(i64 %value, ptr %memory) {{"]
        lines.append("  %a = or i64 %value, 0" if width == 64 else f"  %a = trunc i64 %value to {ty}")
        lines += [f"  store {ty} %a, ptr %memory, align 1", f"  %loaded = load {ty}, ptr %memory, align 1"]
        if width < 64:
            lines += [f"  %wide = zext {ty} %loaded to i64", "  ret i64 %wide"]
        else:
            lines += ["  ret i64 %loaded"]
        lines += ["}", f"define i64 @return_probe_{width}(i64 %value, i64 %other) {{"]
        lines += (["  %a = or i64 %value, 0", "  %b = or i64 %other, 0"] if width == 64 else
                  [f"  %a = trunc i64 %value to {ty}", f"  %b = trunc i64 %other to {ty}"])
        lines += [f"  %direct = call {ty} @returned_{width}({ty} %a, {ty} %b)",
                  f"  %pointer = load ptr, ptr @returned_pointer_{width}, align 8",
                  f"  %indirect = call {ty} %pointer({ty} %b, {ty} %a)"]
        operations, result = hash_ir(("%direct", "%indirect"), (width, width))
        lines += operations + [f"  ret i64 {result}", "}"]
    signature = ", ".join(f"i{width}" for width in MIXED_WIDTHS)
    lines += [f"declare i64 @mixed_sink({signature})", "@mixed_pointer = constant ptr @mixed_sink, align 8"]
    for name, indirect in (("mixed_direct", False), ("mixed_indirect", True)):
        lines.append(f"define i64 @{name}(i64 %seed) {{")
        for index, width in enumerate(MIXED_WIDTHS):
            lines += [f"  %wide{index} = add i64 %seed, {(OFFSET * (index + 1)) & MASK}",
                      f"  %arg{index} = trunc i64 %wide{index} to i{width}"]
        if indirect:
            lines.append("  %pointer = load ptr, ptr @mixed_pointer, align 8")
        args = ", ".join(f"i{width} %arg{index}" for index, width in enumerate(MIXED_WIDTHS))
        lines += [f"  %result = call i64 {'%pointer' if indirect else '@mixed_sink'}({args})", "  ret i64 %result", "}"]
    return "\n".join(lines) + "\n"


def callee_body():
    lines = []
    for width in range(1, 65):
        lines += [f"define i{width} @returned_{width}(i{width} %a, i{width} %b) {{",
                  f"  %difference = sub i{width} %a, %b",
                  f"  %result = xor i{width} %difference, {OFFSET & mask(width)}",
                  f"  ret i{width} %result", "}"]
    signature = ", ".join(f"i{width} %a{index}" for index, width in enumerate(MIXED_WIDTHS))
    lines.append(f"define i64 @mixed_sink({signature}) {{")
    operations, result = hash_ir([f"%a{index}" for index in range(len(MIXED_WIDTHS))], MIXED_WIDTHS)
    lines += operations + [f"  ret i64 {result}", "}"]
    return "\n".join(lines) + "\n"


def golden_values():
    for width in range(1, 65):
        for index in range(len(samples(width))):
            value, other, count = arguments(width, index)
            yield arithmetic(width, value, other, count)
            yield value & mask(width)
            size = (width + 7) // 8
            for byte in range(16):
                if 2 <= byte < 2 + size:
                    shift = (byte - 2) * 8
                    byte_mask = min(255, mask(width) >> shift)
                    yield (value >> shift) & byte_mask
                else:
                    yield 0xA5
            yield returned(width, value, other)
        value=(OFFSET ^ (width * FNV_PRIME)) & MASK
        for _ in range(2):
            yield value & mask(width)
            for byte in range((width+7)//8):
                yield (value >> (byte*8)) & min(255,mask(width) >> (byte*8))
            yield 0xA5
    for seed in weak.inputs():
        yield mixed(seed)
        yield mixed(seed)


def golden():
    values = list(golden_values())
    return f"OCORE-INTEGER-WIDTHS digest={hash_values(values):016x} checks={len(values)}\n".encode()


def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    for width in range(1, 65):
        text += f"extern u64 arithmetic_{width}(u64,u64,u64),memory_{width}(u64,void*),return_probe_{width}(u64,u64);\n"
    for kind, signature in (("arithmetic", "u64,u64,u64"), ("memory", "u64,void*"), ("return_probe", "u64,u64")):
        text += f"static u64 (*const {kind}[64])({signature})={{" + ",".join(f"{kind}_{width}" for width in range(1,65)) + "};\n"
    text += "extern u64 mixed_direct(u64),mixed_indirect(u64);\n"
    # Reuse only the established Linux mmap/mprotect carrier, never its byte
    # oracle or any implementation-specific native memory instruction model.
    guards=memory_qa.harness().split("static u64 syscall6",1)[1].split("static byte destination",1)[0]
    text += "typedef unsigned char byte;\nstatic u64 syscall6"+guards
    for label, oracle in (("arithmetic_expected", arithmetic), ("return_expected", lambda w,a,b,c: returned(w,a,b))):
        rows = ["{" + ",".join(f"{oracle(width,*arguments(width,index))}ULL" for index in range(len(samples(width)))) + "}" for width in range(1,65)]
        text += f"static const u64 {label}[64][85]={{" + ",\n".join(rows) + "};\n"
    text += r"""
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
static u64 sample(u64 width,u64 index){
 if(index<80)return values[index];
 u64 limit=width==64?~0ULL:((1ULL<<width)-1),edge=1ULL<<(width-1);
 switch(index){case 80:return limit;case 81:return edge;case 82:return edge-1;case 83:return edge+1;default:return limit-1;}
}
int conformance_main(void){
 byte* page=guarded();if(!page)return 80;
 for(u64 width=1;width<=64;++width){
  u64 limit=width==64?~0ULL:((1ULL<<width)-1),size=(width+7)/8;
  for(u64 index=0;index<85;++index){
   u64 value=sample(width,index),other=sample(width,(index+17)%85)^0x9e3779b97f4a7c15ULL,count=index*67+11;
   if(add(arithmetic[width-1](value,other,count),arithmetic_expected[width-1][index]))return 31;
   unsigned char bytes[16];for(u64 at=0;at<16;++at)bytes[at]=0xa5;
   if(add(memory[width-1](value,bytes+2),value&limit))return 31;
   for(u64 at=0;at<16;++at){
    u64 got=bytes[at],expected=0xa5;
    if(at>=2&&at<2+size){u64 shift=(at-2)*8,byte_mask=(limit>>shift)&255;
     got&=byte_mask;expected=(value>>shift)&byte_mask;
    }
    if(add(got,expected))return 31;
   }
   if(add(return_probe[width-1](value,other),return_expected[width-1][index]))return 31;
  }
  u64 guarded_value=0x9e3779b97f4a7c15ULL^(width*0x100000001b3ULL);
  for(u64 edge=0;edge<2;++edge){
   byte* pointer=edge?page+4096-size:page;
   byte* sentinel=edge?pointer-1:pointer+size;*sentinel=0xa5;
   if(add(memory[width-1](guarded_value,pointer),guarded_value&limit))return 31;
   for(u64 at=0;at<size;++at){u64 shift=at*8,byte_mask=(limit>>shift)&255;
    if(add(pointer[at]&byte_mask,(guarded_value>>shift)&byte_mask))return 31;
   }
   if(add(*sentinel,0xa5))return 31;
  }
 }
"""
    for seed in weak.inputs():
        text += f"if(add(mixed_direct({seed}ULL),{mixed(seed)}ULL)||add(mixed_indirect({seed}ULL),{mixed(seed)}ULL))return 31;\n"
    output = golden().decode().rstrip()
    count = int(output.split("checks=")[1])
    start = output.index("digest=") + len("digest=")
    text += f"if(checks!={count})return 37;\n"
    text += 'static char output[]="' + output[:start] + "0" * 16 + output[start+16:] + '\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{start}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
    text += r"""
#if defined(__x86_64__)
 if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
 if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
 return 0;
}
#if defined(__x86_64__)
__asm__""" + reusable.split('#if defined(__x86_64__)\n__asm__', 1)[1]
    return text


def rv_abi_body():
    lines=[]
    for attribute in ("zeroext","signext"):
        lines += [f"define {attribute} i32 @rv_{attribute}_return(i64 %value) {{",
                  "  %narrow = trunc i64 %value to i32", "  ret i32 %narrow", "}"]
        signature=f"i32 {attribute}, ptr, i64, i64, i64, i64, i64, i64, i32 {attribute}"
        lines += [f"declare void @raw_{attribute}({signature})",
                  f"@raw_{attribute}_pointer = constant ptr @raw_{attribute}, align 8"]
        for style in ("direct","indirect"):
            lines += [f"define void @rv_{attribute}_{style}(i64 %value, ptr %output) {{",
                      "  %first = trunc i64 %value to i32",
                      "  %wide = add i64 %value, 2147483649",
                      "  %ninth = trunc i64 %wide to i32"]
            if style=="indirect":
                lines.append(f"  %pointer = load ptr, ptr @raw_{attribute}_pointer, align 8")
            callee=f"@raw_{attribute}" if style=="direct" else "%pointer"
            lines += [f"  call void {callee}(i32 {attribute} %first, ptr %output, i64 2, i64 3, i64 4, i64 5, i64 6, i64 7, i32 {attribute} %ninth)",
                      "  ret void", "}"]
    return "\n".join(lines)+"\n"


def rv_abi_golden():
    values=[]
    for seed in weak.inputs():
        zero,second=seed&0xFFFFFFFF,(seed+0x80000001)&0xFFFFFFFF
        sign,sign_second=signed(zero,32)&MASK,signed(second,32)&MASK
        values += [zero,sign,zero,sign,zero,second,zero,second,sign,sign_second,sign,sign_second]
    return f"OCORE-RV-I32-ABI digest={hash_values(values):016x} checks={len(values)}\n".encode()


def rv_abi_carrier():
    reusable=weak.carrier(11)
    text=reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern void observe_returns(u64*,u64),rv_zeroext_direct(u64,u64*),rv_zeroext_indirect(u64,u64*),rv_signext_direct(u64,u64*),rv_signext_indirect(u64,u64*);\n"
    text += r"""
/* These ABI observers are compiled independently of either LLVM module. Their
   external declarations exactly match zeroext/signext i32 parameter contracts.
   They observe raw XLEN argument/return bits, including the ninth stack slot. */
__asm__(".text\n.option push\n.option norelax\n"
".global raw_zeroext\n.type raw_zeroext,@function\nraw_zeroext:\n"
"sd a0,0(a1)\nld t0,0(sp)\nsd t0,8(a1)\nret\n.size raw_zeroext,.-raw_zeroext\n"
".global raw_signext\n.type raw_signext,@function\nraw_signext:\n"
"sd a0,0(a1)\nld t0,0(sp)\nsd t0,8(a1)\nret\n.size raw_signext,.-raw_signext\n"
".global observe_returns\n.type observe_returns,@function\nobserve_returns:\n"
"addi sp,sp,-32\nsd ra,24(sp)\nsd s0,16(sp)\nsd s1,8(sp)\nmv s0,a0\nmv s1,a1\n"
"mv a0,s1\ncall rv_zeroext_return\nsd a0,0(s0)\n"
"mv a0,s1\ncall rv_signext_return\nsd a0,8(s0)\n"
"mv a0,s1\nla t0,rv_zeroext_return\njalr ra,t0,0\nsd a0,16(s0)\n"
"mv a0,s1\nla t0,rv_signext_return\njalr ra,t0,0\nsd a0,24(s0)\n"
"ld ra,24(sp)\nld s0,16(sp)\nld s1,8(sp)\naddi sp,sp,32\nret\n"
".size observe_returns,.-observe_returns\n.option pop\n");
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
int conformance_main(void){
 for(u64 index=0;index<80;++index){
  u64 seed=values[index],zero=seed&0xffffffffULL,second=(seed+0x80000001ULL)&0xffffffffULL;
  u64 sign=zero&(1ULL<<31)?zero|0xffffffff00000000ULL:zero;
  u64 sign_second=second&(1ULL<<31)?second|0xffffffff00000000ULL:second;
  u64 actual[12];for(u64 at=0;at<12;++at)actual[at]=0xdeadc0deULL;
  observe_returns(actual,seed);
  rv_zeroext_direct(seed,actual+4);rv_zeroext_indirect(seed,actual+6);
  rv_signext_direct(seed,actual+8);rv_signext_indirect(seed,actual+10);
  u64 expected[12]={zero,sign,zero,sign,zero,second,zero,second,sign,sign_second,sign,sign_second};
  for(u64 at=0;at<12;++at)if(add(actual[at],expected[at]))return 31;
 }
"""
    output=rv_abi_golden().decode().rstrip()
    count=int(output.split("checks=")[1]);start=output.index("digest=")+len("digest=")
    text += f"if(checks!={count})return 37;\n"
    text += 'static char output[]="'+output[:start]+"0"*16+output[start+16:]+'\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{start}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
    text += r"""
 if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
 return 0;
}
#if defined(__x86_64__)
__asm__"""+reusable.split('#if defined(__x86_64__)\n__asm__',1)[1]
    return text


class IntegerWidthNativeTests(alias_qa.AliasNativeTests):
    test_actual_alias_identity_and_independent_strong_overrides_match_original_clang_all_three = None

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_INTEGER_WIDTHS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-integer-widths-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.sequence = 0

    def emulators(self):
        emulators = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_"+isa.upper(), "qemu-"+isa))
                     for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(emulators.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three execution requires x86 host and both QEMU user emulators")
            self.skipTest("all-three execution tools unavailable")
        return emulators

    def link(self, isa, triple, flags, harness, objects, output, corrupt=False):
        argv = [self.sdk/"clang", "--target="+triple, *flags, "--ld-path="+self.linker, "-O1",
                "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", harness, *objects]
        if corrupt:
            argv.append("-DCORRUPT_ORACLE")
        self.command([*argv, "-o", output])

    def test_every_width_arithmetic_memory_and_cross_compiler_exact_llvm_abi_all_three(self):
        emulators = self.emulators()
        shifts = {str(width):sorted({arguments(width,index)[2] % width for index in range(85)})
                  for width in range(1,65)}
        for width in range(1,65):
            self.assertEqual(shifts[str(width)],list(range(width)))
        report = {"scope":"all i1..i64 compiler conformance on Linux carriers with independent integer oracle",
                  "runtime_complete":False, "kernel_execution_verified":False, "dependency_closure_complete":False,
                  "compiler_sha256":self.compiler_sha, "test_source":weak.artifact(__file__),
                  "memory_contract":"same-type prior store; ceil(width/8) footprint with canaries and protected 4096-byte page edges; unspecified high padding bits masked",
                  "legal_shift_counts":shifts,
                  "tools":{name:weak.artifact(path) for name,path in {"ocorec":self.compiler,
                    "reference_clang":self.sdk/"clang", "own_assembler":self.assembler, "llvm-as":self.sdk/"llvm-as",
                    "linker":self.linker, **emulators}.items()}, "targets":{}}
        for isa,(target,triple,machine,flags) in TARGETS.items():
            harness = self.directory/(isa+"-carrier.c"); harness.write_text(carrier())
            objects, units, executions = {}, [], []
            for role,body in (("caller",caller_body()),("callee",callee_body())):
                for source in self.inputs(isa+"-"+role,triple,body):
                    original = source.read_bytes()
                    normalized = source.with_name(source.name+".native.json")
                    receipt = source.with_name(source.name+".verification.json")
                    own,reference = source.with_name(source.name+".own.o"),source.with_name(source.name+".clang.o")
                    self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"--emit","mir","-o",normalized])
                    self.command([self.compiler,normalized,"--input-kind","native-ir","--verify-native","--receipt",receipt])
                    self.assertEqual(json.loads(receipt.read_text())["module_sha256"],weak.artifact(normalized)["sha256"])
                    self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"-o",own])
                    self.command([self.sdk/"clang","--target="+triple,*flags,"-fno-pic","-fno-pie","-O0","-c",source,"-o",reference])
                    self.assertEqual(source.read_bytes(),original)
                    module=json.loads(normalized.read_text())
                    self.assertEqual(module["provenance"]["source_function_count"],259 if role=="caller" else 65)
                    self.assertEqual(len(module["functions"]),259 if role=="caller" else 65)
                    self.assertEqual(len(module["globals"]),65 if role=="caller" else 0)
                    for obj in (own,reference):
                        elf(obj,machine,1)
                    objects[role,source.suffix,"own"],objects[role,source.suffix,"original_clang"] = own,reference
                    units.append({"role":role,"input":weak.artifact(source),"module":weak.artifact(normalized),
                                  "verification":weak.artifact(receipt),"own_object":weak.artifact(own),
                                  "original_clang_object":weak.artifact(reference)})
            for suffix in (".ll",".bc"):
                for caller in ("own","original_clang"):
                    for callee in ("own","original_clang"):
                        output=self.directory/(isa+suffix+"-"+caller+"-"+callee)
                        selected=[objects["caller",suffix,caller],objects["callee",suffix,callee]]
                        self.link(isa,triple,flags,harness,selected,output)
                        command=[output] if isa=="x86_64" else [emulators[isa],output]
                        result=self.command(command)
                        self.assertEqual(result.stdout,golden(),(isa,suffix,caller,callee))
                        executions.append({"input_kind":suffix,"caller":caller,"callee":callee,
                                           "executable":weak.artifact(output),"stdout":result.stdout.decode(),"exit_code":0})
                        if caller==callee=="own":
                            corrupt=output.with_name(output.name+".corrupt")
                            self.link(isa,triple,flags,harness,selected,corrupt,corrupt=True)
                            failed=self.command([corrupt] if isa=="x86_64" else [emulators[isa],corrupt],success=False)
                            self.assertEqual(failed.returncode,31);self.assertEqual(failed.stdout,b"")
                            executions.append({"input_kind":suffix,"corrupt_oracle":True,
                                               "executable":weak.artifact(corrupt),"exit_code":31})
            report["targets"][isa]={"modules":units,"executions":executions}
        self.assertEqual(weak.artifact(self.compiler)["sha256"],self.compiler_sha)
        (self.directory/"integer-width-conformance.json").write_text(json.dumps(report,indent=2)+"\n")

    def test_odd_byte_volatile_operations_reject_complete_units_without_artifacts(self):
        report=[]
        for isa,(target,triple,_machine,_flags) in TARGETS.items():
            for width in (17,24,33,40,41,48,49,56):
                for operation in ("load","store"):
                    effect=(f"  %loaded = load volatile i{width}, ptr %memory, align 1\n  %wide = zext i{width} %loaded to i64\n  ret i64 %wide\n" if operation=="load" else
                            f"  %narrow = trunc i64 %value to i{width}\n  store volatile i{width} %narrow, ptr %memory, align 1\n  ret i64 7\n")
                    body="define i64 @retained_anchor() { ret i64 9 }\n"+f"define i64 @unsupported(ptr %memory, i64 %value) {{\n"+effect+"}\n"
                    for source in self.inputs(f"{isa}-{operation}-i{width}",triple,body):
                        output=source.with_name(source.name+".o")
                        result=self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"-o",output],success=False)
                        self.assertNotEqual(result.returncode,0)
                        self.assertIn("volatile",result.stderr.decode(errors="replace").lower())
                        self.assertFalse(output.exists(),"a cold unsupported effect must fail the entire unit")
                        report.append({"target":isa,"width":width,"operation":operation,
                                       "input":weak.artifact(source),"exit_code":result.returncode,
                                       "stderr":result.stderr.decode(errors="replace")})
        (self.directory/"volatile-width-negatives.json").write_text(json.dumps({"runtime_complete":False,"cases":report},indent=2)+"\n")

    def test_rv_explicit_i32_extensions_in_raw_register_returns_arguments_and_stack(self):
        emulators=self.emulators()
        target,triple,machine,flags=TARGETS["riscv64"]
        harness=self.directory/"rv-i32-abi-carrier.c";harness.write_text(rv_abi_carrier())
        report={"scope":"RV64 LP64 explicit LLVM zeroext/signext i32 physical ABI on Linux carrier",
                "runtime_complete":False,"kernel_execution_verified":False,"dependency_closure_complete":False,
                "compiler_sha256":self.compiler_sha,"test_source":weak.artifact(__file__),
                "target_profile":{"triple":triple,"flags":flags},
                "tools":{name:weak.artifact(path) for name,path in {"ocorec":self.compiler,
                    "reference_clang":self.sdk/"clang","own_assembler":self.assembler,
                    "llvm-as":self.sdk/"llvm-as","linker":self.linker,"qemu-riscv64":emulators["riscv64"]}.items()},
                "executions":[],"modules":[]}
        for source in self.inputs("rv-i32-abi",triple,rv_abi_body()):
            original=source.read_bytes()
            normalized=source.with_name(source.name+".native.json");receipt=source.with_name(source.name+".verification.json")
            own,reference=source.with_name(source.name+".own.o"),source.with_name(source.name+".clang.o")
            self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"--emit","mir","-o",normalized])
            self.command([self.compiler,normalized,"--input-kind","native-ir","--verify-native","--receipt",receipt])
            self.assertEqual(json.loads(receipt.read_text())["module_sha256"],weak.artifact(normalized)["sha256"])
            self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"-o",own])
            self.command([self.sdk/"clang","--target="+triple,*flags,"-fno-pic","-fno-pie","-O0","-c",source,"-o",reference])
            self.assertEqual(source.read_bytes(),original)
            module=json.loads(normalized.read_text())
            self.assertEqual(len(module["functions"]),8)
            self.assertEqual(len(module["globals"]),2)
            functions={item["name"]:item for item in module["functions"]}
            for attribute in ("zeroext","signext"):
                self.assertEqual(functions[f"rv_{attribute}_return"]["signature"]["result_attributes"],[attribute])
                signature=functions[f"raw_{attribute}"]["signature"]
                self.assertEqual(signature["param_attributes"][0],[attribute])
                self.assertEqual(signature["param_attributes"][8],[attribute])
            report["modules"].append({"input":weak.artifact(source),"module":weak.artifact(normalized),"verification":weak.artifact(receipt),
                                      "own_object":weak.artifact(own),"original_clang_object":weak.artifact(reference)})
            for label,obj in (("own",own),("original_clang",reference)):
                elf(obj,machine,1)
                output=source.with_name(source.name+"."+label)
                self.link("riscv64",triple,flags,harness,[obj],output)
                result=self.command([emulators["riscv64"],output])
                self.assertEqual(result.stdout,rv_abi_golden())
                report["executions"].append({"input_kind":source.suffix,"implementation":label,
                                             "executable":weak.artifact(output),"stdout":result.stdout.decode(),"exit_code":0})
                if label=="own":
                    corrupt=output.with_name(output.name+".corrupt")
                    self.link("riscv64",triple,flags,harness,[obj],corrupt,corrupt=True)
                    failed=self.command([emulators["riscv64"],corrupt],success=False)
                    self.assertEqual(failed.returncode,31);self.assertEqual(failed.stdout,b"")
                    report["executions"].append({"input_kind":source.suffix,"corrupt_oracle":True,
                                                 "executable":weak.artifact(corrupt),"exit_code":31})
        self.assertEqual(weak.artifact(self.compiler)["sha256"],self.compiler_sha)
        (self.directory/"rv-i32-abi-conformance.json").write_text(json.dumps(report,indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
