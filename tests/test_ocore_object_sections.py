"""Ordinary O-core object sections: real ELF GC and matched three-ISA execution.

Section granularity changes placement, not object identity or source semantics.
The independent C fixture/harness checks defined pointer identity, array bytes,
mutable state and indirect ABI calls. No numeric address is assumed invariant
across the independently laid out objects. Imported NativeIR is a separate path.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "x86_64-unknown-none": ("x86_64-linux-gnu", "elf_x86_64", None, 62),
    "aarch64-unknown-none": ("aarch64-linux-gnu", "aarch64elf", "qemu-aarch64", 183),
    "riscv64-unknown-none": ("riscv64-linux-gnu", "elf64lriscv", "qemu-riscv64", 243),
}
SOURCE = r'''module object_sections;
@align(64) @export @no_mangle static READ_A: [u8; 5] = [0, 17, 128, 255, 3];
@align(64) @export @no_mangle static READ_B: [u8; 5] = [0, 17, 128, 255, 3];
@align(64) @export @no_mangle static mut WORDS_A: [u64; 3] = [3, 5, 7];
@align(64) @export @no_mangle static mut WORDS_B: [u64; 3] = [9, 11, 13];
@export @no_mangle static mut CALLBACK: fn(u64) -> u64 = callback;
@export @no_mangle fn callback(value: u64) -> u64 { return value + 23; }
@export @no_mangle unsafe fn call_callback(value: u64) -> u64 { return CALLBACK(value); }
@export @no_mangle unsafe fn read_word(index: u64) -> u64 { return WORDS_A[index as usize]; }
@export @no_mangle unsafe fn write_word(index: u64, value: u64) { WORDS_A[index as usize] = value; }
@export @no_mangle static mut UNREACHED_PUBLIC: [u8; 17] = [0; 17];
static UNREACHED_PRIVATE: [u8; 19] = [0; 19];
@export @no_mangle fn unused_function() -> u64 { return 53; }
@link_section(".data.pinned") @align(128) @export @no_mangle static mut PINNED_MUTABLE: u64 = 0x1122334455667788;
@link_section(".rodata.pinned") @align(128) @export @no_mangle static PINNED_READONLY: u64 = 0x8877665544332211;
@link_section(".text.pinned") @export @no_mangle fn pinned_function() -> u64 { return 71; }
'''
REFERENCE = r'''
typedef unsigned long long u64;
__attribute__((aligned(64))) const unsigned char READ_A[5] = {0,17,128,255,3};
__attribute__((aligned(64))) const unsigned char READ_B[5] = {0,17,128,255,3};
__attribute__((aligned(64))) u64 WORDS_A[3] = {3,5,7};
__attribute__((aligned(64))) u64 WORDS_B[3] = {9,11,13};
u64 callback(u64 value) { return value+23; }
u64 (*CALLBACK)(u64) = callback;
u64 call_callback(u64 value) { return CALLBACK(value); }
u64 read_word(u64 index) { return WORDS_A[index]; }
void write_word(u64 index,u64 value) { WORDS_A[index] = value; }
'''
HARNESS = r'''
typedef unsigned long long u64;
extern const unsigned char READ_A[5],READ_B[5];
extern u64 WORDS_A[3],WORDS_B[3];
extern u64 callback(u64),call_callback(u64),read_word(u64);
extern void write_word(u64,u64);
extern u64 (*CALLBACK)(u64);
u64 RESULTS[12];
u64 replacement_callback(u64 x) { return x+100; }
void run_harness(void) {
 u64 packed=0;for(unsigned i=0;i<5;i++)packed |= ((u64)READ_A[i])<<(8*i);
 RESULTS[0]=packed;
 packed=0;for(unsigned i=0;i<5;i++)packed |= ((u64)READ_B[i])<<(8*i);
 RESULTS[1]=packed;
 RESULTS[2]=(&READ_A[0]!=&READ_B[0]) && (&WORDS_A[0]!=&WORDS_B[0]);
 RESULTS[3]=(((u64)READ_A| (u64)READ_B| (u64)WORDS_A| (u64)WORDS_B)&63)==0;
 RESULTS[4]=WORDS_A[0]+WORDS_A[1]+WORDS_A[2];
 WORDS_A[1]=0xfedcba9876543210ULL;RESULTS[5]=read_word(1);
 RESULTS[6]=WORDS_B[1];write_word(2,0x123456789abcdef0ULL);RESULTS[7]=WORDS_A[2];
 RESULTS[8]=call_callback(19);RESULTS[9]=CALLBACK==callback;
 CALLBACK=replacement_callback;RESULTS[10]=call_callback(5);RESULTS[11]=WORDS_B[0]+WORDS_B[2];
}
'''
ENTRY = {
    "x86_64-unknown-none": r'''.intel_syntax noprefix
.section .text.entry,"ax",@progbits
.globl _start
_start:
 and rsp,-16
 call run_harness
 lea rsi,[rip+RESULTS]
 mov edi,1
 mov edx,96
 mov eax,1
 syscall
 xor edi,edi
 mov eax,60
 syscall
''',
    "aarch64-unknown-none": r'''.section .text.entry,"ax",@progbits
.globl _start
_start:
 bl run_harness
 adrp x1,RESULTS
 add x1,x1,:lo12:RESULTS
 mov x0,1
 mov x2,96
 mov x8,64
 svc 0
 mov x0,0
 mov x8,93
 svc 0
''',
    "riscv64-unknown-none": r'''.option norelax
.section .text.entry,"ax",@progbits
.globl _start
_start:
 call run_harness
 la a1,RESULTS
 li a0,1
 li a2,96
 li a7,64
 ecall
 li a0,0
 li a7,93
 ecall
''',
}
LINKER = '''ENTRY(_start)
SECTIONS {
 . = 0x400000;
 .text : { KEEP(*(.text.entry)) KEEP(*(.text.pinned)) *(.text .text.*) }
 . = ALIGN(0x1000);
 .rodata : { KEEP(*(.rodata.pinned)) *(.rodata .rodata.*) }
 . = ALIGN(0x1000);
 .data : { KEEP(*(.data.pinned)) *(.data .data.*) }
 .bss : { *(.bss .bss.*) *(COMMON) }
 /DISCARD/ : { *(.comment) *(.eh_frame) *(.note*) }
}
'''
EXPECTED = struct.pack("<12Q", 0x03FF801100, 0x03FF801100, 1, 1, 15,
                       0xFEDCBA9876543210, 11, 0x123456789ABCDEF0, 42, 1, 105, 22)


class Elf64:
    """Independent ELF64-LE section/symbol/RELA reader (no compiler helpers)."""
    def __init__(self, path):
        self.raw = Path(path).read_bytes()
        h = struct.unpack_from("<16sHHIQQQIHHHHHH", self.raw)
        assert h[0][:6] == b"\x7fELF\x02\x01"
        self.machine = h[2]
        self.loads = []
        for i in range(h[10]):
            ph = struct.unpack_from("<IIQQQQQQ", self.raw, h[5]+i*h[9])
            if ph[0] == 1:
                self.loads.append(dict(flags=ph[1], address=ph[3], bytes=ph[6]))
        records = [struct.unpack_from("<IIQQQQIIQQ", self.raw, h[6]+i*h[11]) for i in range(h[12])]
        names = records[h[13]]
        strings = self.raw[names[4]:names[4]+names[5]]
        name = lambda data, n: data[n:data.index(0, n)].decode()
        self.sections = []
        for x in records:
            self.sections.append(dict(name=name(strings, x[0]), type=x[1], flags=x[2], address=x[3],
                                      offset=x[4], size=x[5], link=x[6], info=x[7], align=x[8], stride=x[9]))
        self.symbols = {}
        self.tables = {}
        for section in self.sections:
            if section["type"] != 2:
                continue
            st = self.sections[section["link"]]
            ss = self.raw[st["offset"]:st["offset"]+st["size"]]
            entries = []
            for pos in range(section["offset"], section["offset"]+section["size"], section["stride"]):
                x = struct.unpack_from("<IBBHQQ", self.raw, pos)
                sym = dict(name=name(ss, x[0]), bind=x[1]>>4, type=x[1]&15, visibility=x[2]&3,
                           section=x[3], value=x[4], size=x[5])
                entries.append(sym)
                if sym["name"]: self.symbols[sym["name"]] = sym
            self.tables[self.sections.index(section)] = entries
        self.relocations = []
        for section in self.sections:
            if section["type"] != 4:
                continue
            syms = self.tables[section["link"]]
            for pos in range(section["offset"], section["offset"]+section["size"], section["stride"]):
                offset, info, addend = struct.unpack_from("<QQq", self.raw, pos)
                self.relocations.append(dict(source=self.sections[section["info"]]["name"], offset=offset,
                                             symbol=syms[info>>32]["name"], type=info&0xffffffff, addend=addend))

    def symbol_bytes(self, symbol):
        s = self.symbols[symbol]
        section = self.sections[s["section"]]
        start = section["offset"]+s["value"]-section["address"]
        return self.raw[start:start+s["size"]]


class ObjectSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = os.environ.get("OCOREC_BIN", str(ROOT/"target/debug/ocorec"))
        cls.clang = os.environ.get("OCORE_SECTIONS_CLANG", shutil.which("clang") or "")
        cls.linker = os.environ.get("OCORE_SECTIONS_LLD", shutil.which("ld.lld") or "")
        for tool in (cls.compiler, cls.clang, cls.linker):
            if not tool or not Path(tool).is_file(): raise unittest.SkipTest(f"required object-section tool missing: {tool}")
        selected = os.environ.get("OCORE_TEST_OBJECT_SECTIONS_OUTPUT_DIR")
        cls.temporary = None
        if selected:
            cls.base = Path(selected);cls.base.mkdir(parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="ocore-object-sections-")
            cls.base = Path(cls.temporary.name)
        cls.commands = []
        cls.catalog = json.loads(cls.command([cls.compiler, "--list-targets"]).stdout)
        actual = {x["target"] for x in cls.catalog["targets"]}
        if actual != set(PROFILES):
            raise AssertionError(f"object-section execution profiles missing/mismatched: {actual ^ set(PROFILES)}")

    @classmethod
    def tearDownClass(cls):
        (cls.base/"commands.json").write_text(json.dumps(cls.commands, indent=2)+"\n")
        files = []
        for path in sorted(cls.base.rglob("*")):
            if path.is_file():
                data = path.read_bytes();files.append(dict(path=str(path.relative_to(cls.base)), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        (cls.base/"inventory.json").write_text(json.dumps(files, indent=2)+"\n")
        if cls.temporary: cls.temporary.cleanup()

    @classmethod
    def command(cls, argv, *, success=True):
        p = subprocess.run([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.commands.append(dict(argv=[str(x) for x in argv], exit=p.returncode,
                                 stdout_hex=p.stdout.hex(), stderr_hex=p.stderr.hex()))
        if success and p.returncode:
            raise AssertionError(f"command failed {p.returncode}: {argv}\n{p.stderr.decode(errors='replace')}")
        return p

    def test_three_isa_native_reference_abi_and_reachability(self):
        results = {}
        for target, (triple, emulation, runner, machine) in PROFILES.items():
            with self.subTest(target=target):
                out = self.base/target;out.mkdir()
                source = out/"fixture.oc";source.write_text(SOURCE)
                reference = out/"reference.c";reference.write_text(REFERENCE)
                harness = out/"harness.c";harness.write_text(HARNESS)
                entry = out/"entry.s";entry.write_text(ENTRY[target])
                linker = out/"linker.ld";linker.write_text(LINKER)
                extras = ["-march=rv64gc", "-mabi=lp64", "-mno-relax"] if target.startswith("riscv") else []
                for source_file in (reference, harness, entry):
                    self.command([self.clang, "--target="+triple, *extras, "-O0", "-ffreestanding", "-fno-pie", "-fno-stack-protector", "-c", source_file, "-o", source_file.with_suffix(".o")])
                executables = []
                for label, flags in (("default", []), ("functions", ["--function-sections"]),
                                     ("data", ["--data-sections"]), ("both", ["--function-sections", "--data-sections"])):
                    obj = out/(label+".o")
                    self.command([self.compiler, source, "--target", target, "--keep-asm", *flags, "-o", obj])
                    elf = Elf64(obj)
                    self.assertEqual(elf.machine, machine)
                    for name, writable in (("READ_A", False), ("READ_B", False), ("WORDS_A", True), ("WORDS_B", True)):
                        sym = elf.symbols[name];section = elf.sections[sym["section"]]
                        self.assertEqual(sym["bind"], 1);self.assertEqual(sym["type"], 1)
                        self.assertEqual(section["flags"]&7, 3 if writable else 2)
                        self.assertGreaterEqual(section["align"], 64)
                        self.assertEqual(sym["value"]%64, 0)
                        if "--data-sections" in flags:
                            self.assertEqual(section["name"], (".data" if writable else ".rodata")+".ocore_static."+name)
                        else:
                            self.assertEqual(section["name"], ".data" if writable else ".rodata")
                    self.assertEqual(elf.symbol_bytes("READ_A"), bytes([0,17,128,255,3]))
                    self.assertEqual(elf.symbol_bytes("WORDS_A"), struct.pack("<3Q",3,5,7))
                    self.assertEqual(elf.symbols["_O_object_sections__UNREACHED_PRIVATE"]["bind"], 0)
                    for name, section_name, value in (("PINNED_MUTABLE", ".data.pinned", 0x1122334455667788), ("PINNED_READONLY", ".rodata.pinned", 0x8877665544332211)):
                        sym = elf.symbols[name];section = elf.sections[sym["section"]]
                        self.assertEqual(section["name"], section_name);self.assertEqual(section["align"], 128)
                        self.assertEqual(elf.symbol_bytes(name), struct.pack("<Q",value))
                    self.assertEqual(elf.sections[elf.symbols["pinned_function"]["section"]]["name"], ".text.pinned")
                    self.assertTrue(any(x["symbol"] == "callback" for x in elf.relocations))
                    exe = out/(label+".elf")
                    cmd = [self.linker, "-m", emulation, "-static", "--gc-sections", "--print-gc-sections", "--Map="+str(out/(label+".map")), "-T", linker, "-o", exe, entry.with_suffix(".o"), harness.with_suffix(".o"), obj]
                    self.command(cmd)
                    linked = Elf64(exe)
                    for name in ("PINNED_MUTABLE", "PINNED_READONLY", "pinned_function", "callback", "CALLBACK"):
                        self.assertIn(name, linked.symbols)
                    for name, writable in (("READ_A", False), ("READ_B", False), ("WORDS_A", True), ("WORDS_B", True), ("PINNED_MUTABLE", True), ("PINNED_READONLY", False)):
                        sym = linked.symbols[name];section = linked.sections[sym["section"]]
                        self.assertEqual(section["flags"]&7, 3 if writable else 2)
                        self.assertEqual(sym["value"]%(128 if name.startswith("PINNED") else 64), 0)
                        mappings = [load for load in linked.loads if load["address"] <= sym["value"] and sym["value"]+sym["size"] <= load["address"]+load["bytes"]]
                        self.assertEqual(len(mappings), 1)
                        self.assertEqual(mappings[0]["flags"]&7, 6 if writable else 4)
                    if label == "both":
                        for name in ("UNREACHED_PUBLIC", "_O_object_sections__UNREACHED_PRIVATE", "unused_function"):
                            self.assertNotIn(name, linked.symbols)
                    executables.append((label, exe))
                original = out/"reference.elf"
                self.command([self.linker, "-m", emulation, "-static", "--gc-sections", "-T", linker, "-o", original, entry.with_suffix(".o"), harness.with_suffix(".o"), reference.with_suffix(".o")])
                executables.append(("reference",original))
                observed = {}
                for label, exe in executables:
                    selected_runner = os.environ.get("OCORE_TEST_QEMU_"+target.split("-")[0].upper(), shutil.which(runner) or runner) if runner else None
                    command = [exe] if selected_runner is None else [selected_runner, exe]
                    observed[label] = self.command(command).stdout
                    self.assertEqual(observed[label], EXPECTED)
                self.assertEqual(len(set(observed.values())), 1)
                results[target] = {label: value.hex() for label,value in observed.items()}
        (self.base/"execution.json").write_text(json.dumps(results,indent=2)+"\n")

    def test_default_and_old_function_api_artifacts_are_byte_compatible(self):
        baseline = os.environ.get("OCORE_SECTIONS_BASELINE_OCOREC")
        if not baseline: self.skipTest("optional retained pre-change compiler not selected")
        source = self.base/"default-compat.oc";source.write_text(SOURCE)
        for target in PROFILES:
            for label, flags in (("default",[]),("functions",["--function-sections"])):
                old = self.base/(target+"-"+label+"-old.o")
                new = self.base/(target+"-"+label+"-new.o")
                self.command([baseline,source,"--target",target,*flags,"-o",old])
                self.command([self.compiler,source,"--target",target,*flags,"-o",new])
                self.assertEqual(old.read_bytes(),new.read_bytes())

    def test_cli_rejects_unrealized_or_irrelevant_section_modes(self):
        invalid = self.base/"invalid.native.json";invalid.write_text("not JSON or LLVM")
        source = self.base/"cli.oc";source.write_text(SOURCE)
        cases = [
            ["--list-targets","--data-sections"],
            [str(source),"--check","--data-sections"],
            [str(invalid),"--input-kind","native-ir","--data-sections"],
            [str(invalid),"--input-kind","llvm-ir","--data-sections"],
            [str(invalid),"--input-kind","native-ir","--verify-native","--data-sections"],
            [str(invalid),"--input-kind","native-ir","--verify-native-map","missing","--map-assembly","missing","--map-artifact","missing","--data-sections"],
        ]
        cases += [[str(source),"--emit",kind,"--data-sections"] for kind in ("ast","hir","mir")]
        for i,argv in enumerate(cases):
            with self.subTest(argv=argv):
                output=self.base/f"rejected-{i}.o"
                if "--list-targets" not in argv and "--check" not in argv and "--verify-native-map" not in argv:
                    argv += ["-o",str(output)]
                p=self.command([self.compiler,*argv],success=False)
                self.assertEqual(p.returncode,2,p.stderr)
                self.assertFalse(output.exists())
                self.assertEqual(p.stdout,b"")


if __name__ == "__main__":
    unittest.main()
