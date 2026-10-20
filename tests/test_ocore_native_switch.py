"""Actual three-ISA switch objects against independent C and Python results.

Linux startup/syscalls carry these development tests. They do not qualify an
OSTADIX kernel, complete runtime dependencies, or full compiler implementations.
Set OCORE_TEST_REQUIRE_ALL_ISAS=1 to make absent execution tools fail the suite.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.check_ocore_native_equivalence import TARGETS, RunEvidence, elf, execution_prefix, file_identity
from scripts.check_ocore_foreign_frontends import HARNESS as EXISTING_LINUX_CARRIER
from tests.test_ocore_native_import_backend import (
    ROOT, I64, I1, I8, I32, function, integer, instruction, module, value,
)

I16 = 6
MASK = (1 << 64) - 1
DEFAULT = 0xDEC0DE1234567890
EMPTY = 0xFEDCBA9876543210
PHI_XOR = 0x9E3779B97F4A7C15
CASE_FACTOR = 0xD6E8FEB86659FD93
LARGE_COUNT = 1922
WIDTH_TYPES = {1: I1, 8: I8, 16: I16, 32: I32, 64: I64}


def binary(kind, lhs, rhs):
    return {"op": "binary", "kind": kind, "lhs": lhs, "rhs": rhs, "flags": []}


def switch(condition, default, cases):
    return {"op": "switch", "condition": condition, "default": default,
            "cases": [{"value": constant, "target": target} for constant, target in cases]}


def returning(identifier, constant):
    return {"id": identifier, "instructions": [],
            "terminator": {"op": "return", "value": integer(I64, constant)}}


def width_function(width):
    ty = WIDTH_TYPES[width]
    case_values = [0, 1] if width == 1 else [0, (1 << (width-1))-1,
                                           1 << (width-1), (1 << width)-1]
    fn = function(f"switch_i{width}", params=[I64])
    ops = [] if width == 64 else [instruction(1, ty, {
        "op": "cast", "kind": "trunc", "value": value(0)})]
    fn["blocks"] = [{"id": 0, "instructions": ops,
                     "terminator": switch(value(0 if width == 64 else 1), 1,
                                          [(integer(ty, bits), index+2)
                                           for index, bits in enumerate(case_values)])},
                    returning(1, DEFAULT+width)]
    fn["blocks"].extend(returning(index+2, (CASE_FACTOR*(index+1)+width) & MASK)
                        for index in range(len(case_values)))
    return fn


def phi_function():
    def phi(identifier, incoming):
        return instruction(identifier, I64, {"op": "phi", "incoming": [
            {"block": block, "value": operand} for block, operand in incoming]})
    fn = function("switch_parallel_phi", params=[I64, I64])
    fn["blocks"] = [
        {"id": 0, "instructions": [
            instruction(2, I64, binary("xor", value(0), integer(I64, PHI_XOR))),
            instruction(3, I64, binary("and", value(1), integer(I64, 31)))],
         "terminator": {"op": "jump", "target": 1}},
        {"id": 1, "instructions": [
            phi(4, [(0, value(0)), (2, value(8))]),
            phi(5, [(0, value(2)), (2, value(7))]),
            phi(6, [(0, value(3)), (2, value(9))])],
         # Default and two cases reach block 2. Its PHIs have one incoming
         # predecessor, and the loop transfer must snapshot both swapped PHIs.
         "terminator": switch(value(6), 2, [(integer(I64, 0), 3),
                                            (integer(I64, 1), 2),
                                            (integer(I64, 2), 2)])},
        {"id": 2, "instructions": [
            phi(7, [(1, value(4))]), phi(8, [(1, value(5))]),
            instruction(9, I64, binary("sub", value(6), integer(I64, 1)))],
         "terminator": {"op": "jump", "target": 1}},
        {"id": 3, "instructions": [
            instruction(10, I64, binary("mul", value(4), integer(I64, 3))),
            instruction(11, I64, binary("mul", value(5), integer(I64, 5))),
            instruction(12, I64, binary("add", value(10), value(11)))],
         "terminator": {"op": "return", "value": value(12)}},
    ]
    return fn


def large_function():
    fn = function("switch_1922", params=[I64])
    fn["blocks"] = [{"id": 0, "instructions": [instruction(1, I32, {
        "op": "cast", "kind": "trunc", "value": value(0)})],
        "terminator": switch(value(1), 1, [
            (integer(I32, 0x80000000+17*index), index+2)
            for index in range(LARGE_COUNT)])}, returning(1, DEFAULT)]
    fn["blocks"].extend(returning(index+2, (CASE_FACTOR*(index+1)) & MASK)
                        for index in range(LARGE_COUNT))
    return fn


def corpus(isa):
    empty = function("switch_empty", params=[I64])
    empty["blocks"] = [{"id": 0, "instructions": [],
                        "terminator": switch(value(0), 1, [])}, returning(1, EMPTY)]
    native = module(isa, [width_function(width) for width in WIDTH_TYPES] +
                    [phi_function(), large_function(), empty])
    native["name"] = "switch-defined-behavior-conformance"
    native["types"].append({"kind": "int", "bits": 16})
    return native


def width_reference(operand, width):
    bits = operand & ((1 << width)-1)
    cases = [0, 1] if width == 1 else [0, (1 << (width-1))-1,
                                     1 << (width-1), (1 << width)-1]
    return ((CASE_FACTOR*(cases.index(bits)+1)+width) & MASK
            if bits in cases else DEFAULT+width)


def edge_values(width):
    half, mask = 1 << (width-1), (1 << width)-1
    return [0, 1, 2, 3, half-1, half, mask, mask-1,
            65536, 1 << 32, 1 << 63, MASK]


def golden():
    state, digest, count = PHI_XOR, 0xCBF29CE484222325, 0
    def add(output):
        nonlocal digest, count
        digest = ((digest ^ output)*0x100000001B3) & MASK
        count += 1
    for index in range(2048):
        state ^= (state << 13) & MASK
        state ^= state >> 7
        state ^= (state << 17) & MASK
        for width in WIDTH_TYPES:
            add(width_reference(state, width))
        first, second = state, state ^ PHI_XOR
        if index & 1:
            first, second = second, first
        add((3*first+5*second) & MASK)
        add(EMPTY)
    for width in WIDTH_TYPES:
        for operand in edge_values(width):
            add(width_reference(operand, width))
    for index in range(LARGE_COUNT):
        add((CASE_FACTOR*(index+1)) & MASK)
    for _ in range(8):
        add(DEFAULT)
    return f"OCORE-SWITCH digest={digest:016x} cases={count}\n".encode()


def harness():
    # Share the existing, already exercised syscall and entry carrier without
    # altering it. References here use mathematical masks/parity/formulas;
    # they do not implement switch dispatch or PHI copies.
    syscall = EXISTING_LINUX_CARRIER.split("static u64 syscall3",1)[1].split("static u64 signed_bits",1)[0]
    startup = EXISTING_LINUX_CARRIER.split("#if defined(__x86_64__)\n__asm__",1)[1]
    source = "typedef unsigned long long u64; typedef unsigned int u32;\nstatic u64 syscall3"+syscall
    source += "\n".join(f"extern u64 switch_i{width}(u64);" for width in WIDTH_TYPES)
    source += r'''
extern u64 switch_parallel_phi(u64,u64),switch_1922(u64),switch_empty(u64);
#define DEFAULT 0xdec0de1234567890ULL
#define EMPTY 0xfedcba9876543210ULL
#define FACTOR 0xd6e8feb86659fd93ULL
static u64 ref_width(u64 x,u32 width) {
    u64 mask=width==64?~0ULL:(1ULL<<width)-1;
    u64 half=1ULL<<(width-1);x&=mask;
    if(x==0) return FACTOR+width;
    if(width==1) return 2*FACTOR+width;
    if(x==half-1) return 2*FACTOR+width;
    if(x==half) return 3*FACTOR+width;
    if(x==mask) return 4*FACTOR+width;
    return DEFAULT+width;
}
static u64 ref_phi(u64 x,u64 steps) {
    u64 other=x^0x9e3779b97f4a7c15ULL;
    return steps&1?3*other+5*x:3*x+5*other;
}
static u64 ref_large(u64 value) {
    u64 key=(u32)value;
    if(key<0x80000000ULL) return DEFAULT;
    u64 offset=key-0x80000000ULL;
    if(offset%17 || offset/17>=1922) return DEFAULT;
    return FACTOR*(offset/17+1);
}
static u64 selected_width(u64 value,u32 width) {
#ifdef REFERENCE_ONLY
    return ref_width(value,width);
#else
'''
    source += "\n".join(f"if(width=={width}) return switch_i{width}(value);" for width in WIDTH_TYPES)
    source += r'''
    return 0;
#endif
}
#ifdef REFERENCE_ONLY
#define PHI ref_phi
#define LARGE ref_large
#define EMPTY_CALL(value) EMPTY
#else
#define PHI switch_parallel_phi
#define LARGE switch_1922
#define EMPTY_CALL(value) switch_empty(value)
#endif
#ifdef CORRUPT_REFERENCE
#define EXPECT(value) ((value)^1ULL)
#else
#define EXPECT(value) (value)
#endif
static u64 digest=0xcbf29ce484222325ULL;
static u32 cases=0;
static void add(u64 value) {digest=(digest^value)*0x100000001b3ULL;++cases;}
int conformance_main(void) {
    const u32 widths[]={1,8,16,32,64};
    u64 state=0x9e3779b97f4a7c15ULL;
    for(u32 index=0;index<2048;++index) {
        state^=state<<13;state^=state>>7;state^=state<<17;
        for(u32 w=0;w<5;++w) {
            u64 got=selected_width(state,widths[w]);
            if(got!=EXPECT(ref_width(state,widths[w]))) return 31;
            add(got);
        }
        u64 got=PHI(state,index);if(got!=ref_phi(state,index)) return 41;add(got);
        got=EMPTY_CALL(state);if(got!=EMPTY) return 43;add(got);
    }
    for(u32 w=0;w<5;++w) {
        u32 width=widths[w];u64 half=1ULL<<(width-1);
        u64 mask=width==64?~0ULL:(1ULL<<width)-1;
        u64 values[]={0,1,2,3,half-1,half,mask,mask-1,65536,1ULL<<32,1ULL<<63,~0ULL};
        for(u32 i=0;i<12;++i) {
            u64 got=selected_width(values[i],width);
            if(got!=ref_width(values[i],width)) return 32;
            add(got);
        }
    }
    for(u32 i=0;i<1922;++i) {
        u64 operand=0xfedcba9800000000ULL|(0x80000000ULL+17*i);
        u64 got=LARGE(operand);if(got!=ref_large(operand)) return 42;add(got);
    }
    u64 misses[]={0,1,17,0x7fffffff,0x80000001,0x80000000ULL+1922*17,0xffffffff,0x12345678};
    for(u32 i=0;i<8;++i) {u64 got=LARGE(misses[i]);if(got!=DEFAULT)return 44;add(got);}
    char output[]="OCORE-SWITCH digest=0000000000000000 cases=16326\n";
    if(cases!=16326) return 45;
    for(u32 i=0;i<16;++i) {
        u32 nibble=(u32)(digest>>(60-4*i))&15;
        output[sizeof("OCORE-SWITCH digest=")-1+i]=(char)(nibble<10?'0'+nibble:'a'+nibble-10);
    }
    const char *data=output;u64 left=sizeof(output)-1;
    while(left) {
#if defined(__x86_64__)
        u64 written=syscall3(1,1,(u64)data,left);
#else
        u64 written=syscall3(64,1,(u64)data,left);
#endif
        if(!written || written>left)return 99;
        data+=written;left-=written;
    }
    return 0;
}
#if defined(__x86_64__)
__asm__'''+startup
    return source


class NativeSwitchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=Path(os.environ.get("OCOREC",str(ROOT/"target/debug/ocorec")))
        if not compiler.is_file():
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":
                raise RuntimeError("required switch gate needs the actual built ocorec")
            raise unittest.SkipTest("actual ocorec required; no Cargo builds in this suite")
        cls.compiler=str(compiler.resolve())

    def setUp(self):
        retained=os.environ.get("OCORE_TEST_NATIVE_SWITCH_OUTPUT_DIR")
        if retained:
            directory=Path(retained).expanduser().resolve();directory.mkdir(parents=True,exist_ok=True)
            self.directory=Path(tempfile.mkdtemp(prefix="run-",dir=directory))
        else:
            temporary=tempfile.TemporaryDirectory(prefix="ocore-native-switch-")
            self.addCleanup(temporary.cleanup);self.directory=Path(temporary.name)
        self.evidence=RunEvidence([__file__],{"ocorec":self.compiler})
        self.addCleanup(self.evidence.verify_unchanged)

    def command(self,argv,success=True):
        result=self.evidence.run(argv)
        (self.directory/f"command-{len(list(self.directory.glob('command-*.json'))):03}.json").write_text(json.dumps({
            **self.evidence.commands[-1],"exit_code":result.returncode,
            "stdout":result.stdout.decode(errors="replace"),"stderr":result.stderr.decode(errors="replace")},indent=2))
        if success:
            self.assertEqual(result.returncode,0,result.stdout.decode(errors="replace")+result.stderr.decode(errors="replace"))
        return result

    def verify(self,native,name):
        path=self.directory/(name+".json");path.write_text(json.dumps(native))
        self.evidence.watch_source(path)
        receipt=path.with_suffix(".verification.json")
        self.command([self.compiler,path,"--verify-native","--receipt",receipt])
        record=json.loads(receipt.read_text())
        self.assertTrue(record["verified"])
        self.assertEqual(record["module_sha256"],hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(record["scope"],"structural_ir_verification")
        return path

    def test_actual_all_three_objects_match_independent_references_and_exact_bytes(self):
        tools={name:shutil.which(os.environ.get(variable,default)) for name,variable,default in (
            ("clang","CLANG","clang"),("linker","LD_LLD","ld.lld"))}
        missing=[name for name,path in tools.items() if path is None]
        runners={}
        for isa in TARGETS:
            try:
                runners[isa]=execution_prefix(isa,os.environ.get("OCORE_TEST_QEMU_"+isa.upper()))
            except RuntimeError as error:
                missing.append(str(error))
        if missing:
            reason="All three actual switch executions require: "+", ".join(missing)
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS")=="1":self.fail(reason)
            self.skipTest(reason)
        tools["assembler_clang"]=shutil.which(self.evidence.environment.get("OCORE_CLANG","clang"),
                                               path=self.evidence.environment.get("PATH"))
        self.assertIsNotNone(tools["assembler_clang"],"O-core assembler must resolve")
        for name,path in {**tools,**{isa:runner[0] for isa,runner in runners.items() if runner}}.items():
            self.evidence.watch_tool(name,path)
        carrier=self.directory/"reference.c";carrier.write_text(harness())
        self.evidence.watch_source(carrier)
        expected=golden();outputs=[];report={"scope":"switch compiler conformance on Linux development carriers",
            "runtime_complete":False,"kernel_execution_verified":False,
            "expected_output":expected.decode(),"large_switch_cases":LARGE_COUNT,"targets":{}}
        for isa,(native,hosted,machine,flags) in TARGETS.items():
            with self.subTest(isa=isa):
                path=self.verify(corpus(isa),isa)
                obj=self.directory/(isa+".o")
                self.command([self.compiler,path,"--input-kind","native-ir","--target",native,"--emit","obj","-o",obj])
                elf(obj,machine,1)
                link=[tools["clang"],"--target="+hosted,*flags,"-O2","-ffreestanding","-fno-builtin",
                      "-fno-stack-protector","-fno-pic","-fno-pie","-nostdlib","-static","--ld-path="+tools["linker"],
                      "-Wl,-e,_start","-Wl,--build-id=none",carrier]
                emulator=runners[isa]
                reference=self.directory/(isa+".reference.elf")
                self.command([*link,"-DREFERENCE_ONLY","-o",reference]);elf(reference,machine,2)
                self.assertEqual(self.command([*emulator,reference]).stdout,expected)
                exe=self.directory/(isa+".elf")
                self.command([*link,obj,"-o",exe]);elf(exe,machine,2)
                actual=self.command([*emulator,exe]).stdout
                self.assertEqual(actual,expected);outputs.append(actual)
                broken=self.directory/(isa+".broken.elf")
                self.command([*link,obj,"-DCORRUPT_REFERENCE","-o",broken])
                negative=self.command([*emulator,broken],success=False)
                self.assertEqual(negative.returncode,31);self.assertEqual(negative.stdout,b"")
                report["targets"][isa]={"output":actual.decode(),"negative_control_exit":31,
                    "execution_argv_prefix":emulator,
                    "profile":{"native_target":native,"hosted_target":hosted,"flags":flags},
                    "artifacts":{name:file_identity(artifact) for name,artifact in
                                 {"module":path,"verification":path.with_suffix(".verification.json"),
                                  "object":obj,"reference":reference,"executable":exe,"corrupt_oracle":broken}.items()},
                    "module_sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                    "object_sha256":hashlib.sha256(obj.read_bytes()).hexdigest(),
                    "executable_sha256":hashlib.sha256(exe.read_bytes()).hexdigest()}
        self.assertEqual(len(outputs),3);self.assertEqual(len(set(outputs)),1)
        report["all_three_executions_passed"]=True
        report["provenance"]=self.evidence.finish()
        (self.directory/"switch-conformance.json").write_text(json.dumps(report,indent=2))
        print("All three own switch objects: "+expected.decode().strip(),flush=True)

    def test_provenance_rejects_changed_source_and_executed_tool(self):
        source=self.directory/"watched-source.c";source.write_text("original source\n")
        evidence=RunEvidence([source])
        source.write_text("changed source\n")
        with self.assertRaisesRegex(RuntimeError,"run input changed"):
            evidence.finish()
        executable=self.directory/"copied-true"
        shutil.copy2(shutil.which("true"),executable)
        evidence=RunEvidence()
        self.assertEqual(evidence.run([executable]).returncode,0)
        executable.write_bytes(executable.read_bytes()+b"changed after execution")
        with self.assertRaisesRegex(RuntimeError,"run input changed"):
            evidence.finish()

    def test_duplicate_case_decimal_aliases_reject_without_fresh_receipts(self):
        for width in WIDTH_TYPES:
            with self.subTest(width=width):
                native=corpus("x86_64")
                fn=next(fn for fn in native["functions"] if fn["name"]==f"switch_i{width}")
                cases=fn["blocks"][0]["terminator"]["cases"]
                duplicate=copy.deepcopy(cases[0]);duplicate["value"]["bits"]="000";cases.append(duplicate)
                path=self.directory/f"duplicate-{width}.json";path.write_text(json.dumps(native))
                receipt=path.with_suffix(".receipt.json");receipt.write_text('{"verified":true}')
                result=self.command([self.compiler,path,"--verify-native","--receipt",receipt],success=False)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b"duplicate",result.stderr.lower())
                self.assertFalse(receipt.exists())

    def test_case_width_and_missing_destination_reject(self):
        for mode in ("width","destination"):
            with self.subTest(mode=mode):
                native=corpus("x86_64")
                terminator=native["functions"][1]["blocks"][0]["terminator"]
                if mode=="width":terminator["cases"][0]["value"]["ty"]=I64
                else:terminator["default"]=999999
                path=self.directory/(mode+".json");path.write_text(json.dumps(native))
                receipt=path.with_suffix(".receipt.json")
                result=self.command([self.compiler,path,"--verify-native","--receipt",receipt],success=False)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse(receipt.exists())


if __name__=="__main__":
    unittest.main()
