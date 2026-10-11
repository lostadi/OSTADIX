"""Unchanged LLVM symbolic GEP addresses through all three own ISA objects.

The pinned Clang reference and Linux/QEMU carrier qualify compiler address,
memory and call semantics. They do not establish full engine lowering,
dependency closure, native OSTADIX execution or validity of opaque addresses.
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
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
OFFSETS = (-1, 0, 1, 24, 63, 127, -(1 << 63), (1 << 63) - 1)
ARG_OFFSETS = (1, 63, -1, 24, 31, 125, -(1 << 63), (1 << 63) - 1)
BYTES = tuple((17 * index + 3) & 255 for index in range(128))
PACKED_WORD = 0x8877665544332211
PACKED_BYTES = (165, *PACKED_WORD.to_bytes(8, "little"), 9, 17, 45)


def argument_integers(seed):
    return (seed, seed ^ 1, (seed + 17) & MASK, 0xDEADBEEF,
            (seed << 1) & MASK, seed ^ MASK, 1 << 63, seed)


def argument_digest(seed):
    digest = 0xCBF29CE484222325
    for offset, value in zip(ARG_OFFSETS, argument_integers(seed)):
        digest = ((digest ^ (offset & MASK)) * 0x100000001B3) & MASK
        digest = ((digest ^ value) * 0x100000001B3) & MASK
    return digest


def golden():
    values = [offset & MASK for offset in OFFSETS]
    values += [(-3) & MASK, 25, 30, 125, 1]
    values += [BYTES[31], BYTES[24], PACKED_WORD]
    values += list(BYTES) + list(PACKED_BYTES)
    values += [(-1) & MASK, (-1) & MASK, 24, 24, 0, 0, 0]
    for seed in weak.inputs():
        values += [127 if seed & 1 else 11, 24 if seed & 1 else 63,
                   argument_digest(seed), argument_digest(seed), int((seed & 127) == 63), 0]
    digest = 0xCBF29CE484222325
    for value in values:
        digest = ((digest ^ value) * 0x100000001B3) & MASK
    return f"OCORE-SYMBOL-OFFSETS digest={digest:016x} checks={len(values)}\n".encode()


def gep(offset, name="arena_alias"):
    return f"getelementptr (i8, ptr @{name}, i64 {offset})"


def module_body():
    body = "@arena = global [128 x i8] [" + ", ".join(f"i8 {value}" for value in BYTES) + "], align 16\n"
    body += "@arena_alias = alias [128 x i8], ptr @arena\n"
    body += f"@packed = global <{{ i8, i64, [3 x i8] }}> <{{ i8 165, i64 {PACKED_WORD}, [3 x i8] [i8 9, i8 17, i8 45] }}>, align 1\n"
    body += "@packed_alias = alias <{ i8, i64, [3 x i8] }>, ptr @packed\n"
    body += "@slots = global [4 x ptr] zeroinitializer, align 16\n"
    body += "declare i64 @observe(" + ", ".join(["ptr", "i64"] * 8) + ")\n"
    for index, offset in enumerate(OFFSETS):
        body += f"define ptr @return_offset_{index}() {{ ret ptr {gep(offset)} }}\n"
    body += f"define ptr @return_alias() {{ ret ptr {gep(-3)} }}\n"
    body += """
define ptr @return_nested() {
  ret ptr getelementptr (i8, ptr getelementptr ([128 x i8], ptr @arena, i64 0, i64 104), i64 -79)
}
define ptr @return_narrow_index() {
  ret ptr getelementptr (i8, ptr getelementptr ([128 x i8], ptr @arena_alias, i64 0, i64 31), i8 -1)
}
define ptr @return_negative() {
  ret ptr getelementptr (i8, ptr getelementptr ([128 x i8], ptr @arena_alias, i64 0, i64 128), i64 -3)
}
define ptr @return_packed() {
  ret ptr getelementptr (<{ i8, i64, [3 x i8] }>, ptr @packed_alias, i64 0, i32 1)
}
define i64 @load_byte() {
  %byte = load i8, ptr getelementptr ([128 x i8], ptr @arena_alias, i64 0, i64 31), align 1
  %result = zext i8 %byte to i64
  ret i64 %result
}
define i64 @load_negative() {
  %byte = load i8, ptr getelementptr (i8, ptr getelementptr ([128 x i8], ptr @arena_alias, i64 0, i64 31), i64 -7), align 1
  %result = zext i8 %byte to i64
  ret i64 %result
}
define i64 @load_packed() {
  %value = load i64, ptr getelementptr (<{ i8, i64, [3 x i8] }>, ptr @packed_alias, i64 0, i32 1), align 1
  ret i64 %value
}
define ptr @store_global() {
  store ptr getelementptr (i8, ptr @arena_alias, i64 -1), ptr getelementptr ([4 x ptr], ptr @slots, i64 0, i64 2), align 8
  %result = load ptr, ptr getelementptr ([4 x ptr], ptr @slots, i64 0, i64 2), align 8
  ret ptr %result
}
define ptr @store_local(ptr %destination) {
  store ptr getelementptr (i8, ptr @arena_alias, i64 24), ptr %destination, align 8
  ret ptr getelementptr (i8, ptr @arena_alias, i64 24)
}
define ptr @select_address(i64 %seed) {
  %bit = and i64 %seed, 1
  %condition = icmp ne i64 %bit, 0
  %result = select i1 %condition, ptr getelementptr (i8, ptr @arena, i64 127), ptr getelementptr (i8, ptr @packed_alias, i64 11)
  ret ptr %result
}
define ptr @phi_address(i64 %seed) {
entry:
  %bit = and i64 %seed, 1
  %condition = icmp ne i64 %bit, 0
  br i1 %condition, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %result = phi ptr [ getelementptr (i8, ptr @arena_alias, i64 24), %left ], [ getelementptr (i8, ptr @arena, i64 63), %right ]
  ret ptr %result
}
define i64 @compare_address(ptr %pointer) {
  %equal = icmp eq ptr %pointer, getelementptr (i8, ptr @arena_alias, i64 63)
  %result = zext i1 %equal to i64
  ret i64 %result
}
define i64 @compare_opaque(ptr %pointer) {
  %equal = icmp eq ptr %pointer, getelementptr (i8, ptr @arena_alias, i64 9223372036854775807)
  %higher = icmp ugt ptr %pointer, getelementptr (i8, ptr @arena_alias, i64 9223372036854775807)
  %lower = icmp ult ptr %pointer, getelementptr (i8, ptr @arena_alias, i64 -9223372036854775808)
  %a = zext i1 %equal to i64
  %b = zext i1 %higher to i64
  %c = zext i1 %lower to i64
  %bb = shl i64 %b, 1
  %cc = shl i64 %c, 2
  %ab = or i64 %a, %bb
  %result = or i64 %ab, %cc
  ret i64 %result
}
"""
    for kind in ("direct", "indirect"):
        params = "i64 %seed" if kind == "direct" else "ptr %callee, i64 %seed"
        callee = "@observe" if kind == "direct" else "%callee"
        body += f"define i64 @call_{kind}({params}) {{\n"
        body += "  %xor = xor i64 %seed, 1\n  %added = add i64 %seed, 17\n  %shift = shl i64 %seed, 1\n  %inverse = xor i64 %seed, -1\n"
        integers = ("%seed", "%xor", "%added", "3735928559", "%shift", "%inverse", "-9223372036854775808", "%seed")
        args = ", ".join(f"ptr {gep(offset)}, i64 {integer}" for offset, integer in zip(ARG_OFFSETS, integers))
        body += f"  %result = call i64 {callee}({args})\n  ret i64 %result\n}}\n"
    body += "define i64 @cold_unused() { ret i64 1234567 }\n"
    return body


def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern unsigned char arena[],arena_alias[],packed[],packed_alias[];extern void *slots[4];\n"
    for index in range(len(OFFSETS)):
        text += f"extern void *return_offset_{index}(void);\n"
    text += "extern void *return_alias(void),*return_nested(void),*return_narrow_index(void),*return_negative(void),*return_packed(void),*store_global(void),*store_local(void*),*select_address(u64),*phi_address(u64);\n"
    text += "extern u64 load_byte(void),load_negative(void),load_packed(void),call_direct(u64),call_indirect(void*,u64),compare_address(void*),compare_opaque(void*);\n"
    text += "static const u64 offsets[]={" + ",".join(str(offset & MASK) + "ULL" for offset in OFFSETS) + "};\n"
    text += "static const u64 arg_offsets[]={" + ",".join(str(offset & MASK) + "ULL" for offset in ARG_OFFSETS) + "};\n"
    text += "static const unsigned char packed_bytes[]={" + ",".join(str(value) for value in PACKED_BYTES) + "};\n"
    text += r"""
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
__attribute__((noinline)) u64 observe(void *p0,u64 v0,void *p1,u64 v1,void *p2,u64 v2,void *p3,u64 v3,
                                     void *p4,u64 v4,void *p5,u64 v5,void *p6,u64 v6,void *p7,u64 v7){
 void *received_p[]={p0,p1,p2,p3,p4,p5,p6,p7};u64 received_v[]={v0,v1,v2,v3,v4,v5,v6,v7};
 u64 expected_v[]={v0,v0^1,v0+17,0xdeadbeefULL,v0<<1,~v0,0x8000000000000000ULL,v0};
 u64 result=0xcbf29ce484222325ULL,base=(u64)arena;
 for(u64 i=0;i<8;++i){
  u64 relative=(u64)received_p[i]-base;
  if(relative!=arg_offsets[i] || received_v[i]!=expected_v[i])return 0xbad00000ULL+i;
  result=(result^relative)*0x100000001b3ULL;result=(result^received_v[i])*0x100000001b3ULL;
 }
 return result;
}
static u64 expected_arguments(u64 seed){
 u64 integers[]={seed,seed^1,seed+17,0xdeadbeefULL,seed<<1,~seed,0x8000000000000000ULL,seed};
 u64 result=0xcbf29ce484222325ULL;
 for(u64 i=0;i<8;++i){result=(result^arg_offsets[i])*0x100000001b3ULL;result=(result^integers[i])*0x100000001b3ULL;}
 return result;
}
int conformance_main(void){
 u64 base=(u64)arena,packed_base=(u64)packed;
"""
    for index, offset in enumerate(OFFSETS):
        text += f"if(add((u64)return_offset_{index}()-base,{offset & MASK}ULL))return 31;\n"
    text += f"if(add((u64)return_alias()-base,{MASK-2}ULL)||add((u64)return_nested()-base,25)||add((u64)return_narrow_index()-base,30)||add((u64)return_negative()-base,125)||add((u64)return_packed()-packed_base,1))return 31;\n"
    text += f"if(add(load_byte(),{BYTES[31]})||add(load_negative(),{BYTES[24]})||add(load_packed(),{PACKED_WORD}ULL))return 31;\n"
    text += "for(u64 i=0;i<128;++i)if(add(arena[i],(17*i+3)&255))return 31;\n"
    text += "for(u64 i=0;i<sizeof(packed_bytes);++i)if(add(packed[i],packed_bytes[i]))return 31;\n"
    text += f"if(add((u64)store_global()-base,{MASK}ULL)||add((u64)slots[2]-base,{MASK}ULL))return 31;\n"
    text += r"""
 void *slot=(void*)1;
 if(add((u64)store_local(&slot)-base,24)||add((u64)slot-base,24)||add((u64)slots[0],0)||add((u64)slots[1],0)||add((u64)slots[3],0))return 31;
 for(u64 i=0;i<sizeof(values)/sizeof(values[0]);++i){u64 seed=values[i];
  u64 selected_base=(seed&1)?base:packed_base;
  if(add((u64)select_address(seed)-selected_base,(seed&1)?127:11)||add((u64)phi_address(seed)-base,(seed&1)?24:63))return 31;
  if(add(call_direct(seed),expected_arguments(seed))||add(call_indirect((void*)observe,seed),expected_arguments(seed)))return 31;
  if(add(compare_address((void*)(base+(seed&127))),(seed&127)==63))return 31;
  u64 address=base+offsets[i%8],maximum=base+0x7fffffffffffffffULL,minimum=base+0x8000000000000000ULL;
  u64 expected=(address==maximum)|((address>maximum)<<1)|((address<minimum)<<2);
  /* Compare actual unsigned address bits independently; XOR zero keeps the
     digest independent of unrelated executable image placements. */
  if(add(compare_opaque((void*)address)^expected,0))return 31;
 }
"""
    count = int(golden().decode().split("checks=")[1])
    text += f"if(checks!={count})return 37;\n"
    output = golden().decode().rstrip()
    start = output.index("digest=") + len("digest=")
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


class SymbolOffsetNativeTests(alias_qa.AliasNativeTests):
    test_actual_alias_identity_and_independent_strong_overrides_match_original_clang_all_three = None

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_SYMBOL_OFFSETS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-symbol-offsets-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.sequence = 0

    def test_unchanged_symbolic_gep_addresses_match_original_clang_all_three(self):
        emulators = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                     for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(emulators.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three execution requires x86 host and both QEMU user emulators")
            self.skipTest("all-three execution tools unavailable")
        report = {"scope": "symbolic AS0 GEP address compiler conformance on static Linux carriers",
                  "runtime_complete": False, "kernel_execution_verified": False, "dependency_closure_complete": False,
                  "opaque_address_dereference_qualified": False, "compiler_sha256": self.compiler_sha,
                  "test_source": weak.artifact(__file__), "reference_profile": ["-fno-pic", "-fno-pie", "-mcmodel=large"],
                  "tools": {name: weak.artifact(path) for name, path in {"ocorec": self.compiler, "reference_clang": self.sdk / "clang",
                      "own_assembler": self.assembler, "llvm-as": self.sdk / "llvm-as", "linker": self.linker, **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            units, executions = [], []
            harness = self.directory / (isa + "-carrier.c")
            harness.write_text(carrier())
            for source in self.inputs(isa, triple, module_body()):
                original = source.read_bytes()
                normalized = source.with_name(source.name + ".native.json")
                receipt = source.with_name(source.name + ".verification.json")
                own, reference = source.with_name(source.name + ".own.o"), source.with_name(source.name + ".clang.o")
                self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "--emit", "mir", "-o", normalized])
                self.command([self.compiler, normalized, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                self.assertEqual(json.loads(receipt.read_text())["module_sha256"], weak.artifact(normalized)["sha256"])
                self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own])
                self.command([self.sdk / "clang", "--target=" + triple, *flags, *report["reference_profile"], "-O0", "-c", source, "-o", reference])
                self.assertEqual(source.read_bytes(), original)
                module = json.loads(normalized.read_text())
                self.assertEqual(module["provenance"]["source_function_count"], 26)
                self.assertEqual(len(module["functions"]), 26)
                self.assertEqual(len(module["globals"]), 3)
                self.assertEqual({item["name"] for item in module["aliases"]}, {"arena_alias", "packed_alias"})
                for obj in (own, reference):
                    elf(obj, machine, 1)
                    symbols = weak.elf_symbols(obj)
                    self.assertGreater(symbols["cold_unused"]["size"], 0, "unused source definition is retained")
                    self.assertEqual(symbols["arena"]["size"], 128)
                    self.assertEqual(symbols["packed"]["size"], 12)
                    for alias, root in (("arena_alias", "arena"), ("packed_alias", "packed")):
                        for field in ("section", "value", "type", "size"):
                            self.assertEqual(symbols[alias][field], symbols[root][field])
                units.append({"input": weak.artifact(source), "module": weak.artifact(normalized), "verification": weak.artifact(receipt),
                              "own_object": weak.artifact(own), "original_clang_object": weak.artifact(reference)})
                for implementation, obj in (("own", own), ("original_clang", reference)):
                    output = source.with_name(source.name + "." + implementation)
                    argv = [self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker, "-O1",
                            "-ffreestanding", "-fno-builtin", "-fno-stack-protector", *report["reference_profile"],
                            "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", harness, obj, "-o", output]
                    self.command(argv)
                    result = self.command([output] if isa == "x86_64" else [emulators[isa], output])
                    self.assertEqual(result.stdout, golden())
                    executions.append({"input_kind": source.suffix, "implementation": implementation,
                                       "executable": weak.artifact(output), "stdout": result.stdout.decode(), "exit_code": 0})
                    if implementation == "own":
                        corrupt = output.with_name(output.name + ".corrupt")
                        self.command([*argv[:-2], "-DCORRUPT_ORACLE", "-o", corrupt])
                        failed = self.command([corrupt] if isa == "x86_64" else [emulators[isa], corrupt], success=False)
                        self.assertEqual(failed.returncode, 31)
                        self.assertEqual(failed.stdout, b"")
                        executions.append({"input_kind": source.suffix, "corrupt_oracle": True,
                                           "executable": weak.artifact(corrupt), "exit_code": 31})
            report["targets"][isa] = {"modules": units, "executions": executions}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "symbol-offset-conformance.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
