"""Weak definitions through original LLVM, own ELF objects and typed closure.

The synthetic units are backend regression tests, not a Rust compiler substitute.
An optional hash-bound original LLVM Use.cpp check follows the actual compiler
implementation input. Linux startup and QEMU carry the ELF selection comparison;
complete compiler/runtime dependency closure and OSTADIX execution remain separate.
No Cargo build, tool download or original LLVM input rewriting occurs here.
OCORE_TEST_REQUIRE_ALL_ISAS requires the execution matrix; independently set
OCORE_TEST_REQUIRE_CAPTURE_CLOSURE=1 to fail when capture prerequisites are absent.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_foreign_frontends import HARNESS as LINUX_CARRIER
from scripts.check_ocore_native_equivalence import TARGETS, RunEvidence, elf, execution_prefix, host_isa
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_llvm_optimizer_promises as promises
from tests import test_ocore_native_import_backend as native
from tests import test_ocore_native_runtime as capture_qa

ROOT, SDK = baseline.ROOT, promises.SDK
MARKERS = {"a": 11, "b": 53, "strong": 211}
SCENARIOS = (("a", "b"), ("b", "a"), ("a", "strong"), ("strong", "a"))
MASK = (1 << 64) - 1


def artifact(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size}


def provider(tag):
    marker = MARKERS[tag]
    linkage = "" if tag == "strong" else "weak "
    lines = [f"@chosen_global = {linkage}global i64 {marker}, align 8",
             f"@hidden_global = {linkage}hidden global i64 {marker+2}, align 8",
             f"@protected_global = {linkage}protected global i64 {marker+3}, align 8",
             f"@weak_address = {linkage}constant ptr @chosen_global, align 8"]
    for name, visibility, offset in (("chosen", "", 5), ("hidden_function", "hidden ", 7),
                                     ("protected_function", "protected ", 11)):
        lines.append(f"define {linkage}{visibility}i64 @{name}(i64 %x) {{\n"
                     f"  %v = add i64 %x, {marker+offset}\n  ret i64 %v\n}}")
    lines.append(f"define {linkage}i64 @cold_{tag}() {{ ret i64 {marker+97} }}")
    return "\n".join(lines) + "\n"


CONSUMER = """
@chosen_global = external global i64
@hidden_global = external hidden global i64
@protected_global = external protected global i64
@weak_address = external constant ptr
declare i64 @chosen(i64)
declare hidden i64 @hidden_function(i64)
declare protected i64 @protected_function(i64)
define i64 @probe(i64 %x) {
  %a = load i64, ptr @chosen_global, align 8
  %b = load i64, ptr @hidden_global, align 8
  %c = load i64, ptr @protected_global, align 8
  %d = call i64 @chosen(i64 %x)
  %e = call i64 @hidden_function(i64 %x)
  %f = call i64 @protected_function(i64 %x)
  %p = load ptr, ptr @weak_address, align 8
  %equal = icmp eq ptr %p, @chosen_global
  %bit = zext i1 %equal to i64
  %ab = add i64 %a, %b
  %abc = add i64 %ab, %c
  %de = add i64 %d, %e
  %def = add i64 %de, %f
  %sum = add i64 %abc, %def
  %result = add i64 %sum, %bit
  ret i64 %result
}
"""


def inputs():
    state = 0x9E3779B97F4A7C15
    result = [0, 1, (1 << 31)-1, 1 << 31, (1 << 32)-1, 1 << 32,
              (1 << 63)-1, 1 << 63, MASK, MASK-1, 7, 15, 255, 65535, 4097, 97]
    for _ in range(64):
        state ^= (state << 13) & MASK
        state ^= state >> 7
        state ^= (state << 17) & MASK
        result.append(state)
    return result


def golden(marker):
    digest, count = 0xCBF29CE484222325, 0
    for item in [marker, marker+2, marker+3, 1]:
        digest = ((digest ^ item) * 0x100000001B3) & MASK
        count += 1
    for x in inputs():
        for item in ((3*x+6*marker+29) & MASK, (x+marker+5) & MASK,
                     (x+marker+7) & MASK, (x+marker+11) & MASK):
            digest = ((digest ^ item) * 0x100000001B3) & MASK
            count += 1
    return f"OCORE-WEAK selected={marker} digest={digest:016x} checks={count}\n".encode()


def carrier(marker):
    syscall = LINUX_CARRIER.split("static u64 syscall3", 1)[1].split("static u64 signed_bits", 1)[0]
    startup = LINUX_CARRIER.split("#if defined(__x86_64__)\n__asm__", 1)[1]
    values = ",".join(f"0x{x:016x}ULL" for x in inputs())
    text = "typedef unsigned long long u64;\nstatic u64 syscall3" + syscall
    text += f"\n#define MARKER {marker}ULL\nstatic const u64 values[]={{ {values} }};\n"
    text += r"""
extern u64 chosen_global, hidden_global, protected_global;
extern u64 *weak_address;
extern u64 chosen(u64),hidden_function(u64),protected_function(u64),probe(u64);
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected) {
#ifdef CORRUPT_ORACLE
    expected^=1;
#endif
    if(got!=expected)return 31;
    digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
int conformance_main(void) {
    if(add(chosen_global,MARKER)||add(hidden_global,MARKER+2)||
       add(protected_global,MARKER+3)||add(weak_address==&chosen_global,1))return 31;
    for(u64 i=0;i<sizeof(values)/sizeof(values[0]);++i){
        u64 x=values[i];
        if(add(probe(x),3*x+6*MARKER+29)||add(chosen(x),x+MARKER+5)||
           add(hidden_function(x),x+MARKER+7)||add(protected_function(x),x+MARKER+11))return 31;
    }
    if(checks!=324)return 37;
"""
    output = golden(marker).decode().rstrip()
    old = output.split("digest=", 1)[1].split(" ", 1)[0]
    text += 'static char output[]="' + output.replace(old, "0"*16) + '\\n";\n'
    text += r"""
    for(u64 i=0;i<16;++i){u64 n=(digest>>(60-4*i))&15;output[sizeof("OCORE-WEAK selected=")-1+sizeof("MARKER_DIGITS")-1+i]=(char)(n<10?'0'+n:'a'+n-10);}
#if defined(__x86_64__)
    if(syscall3(1,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#else
    if(syscall3(64,1,(u64)output,sizeof(output)-1)!=sizeof(output)-1)return 99;
#endif
    return 0;
}
#if defined(__x86_64__)
__asm__""" + startup
    # The prefix length is independent of executable code or ELF layout.
    prefix = output.index("digest=") + len("digest=")
    return text.replace('sizeof("OCORE-WEAK selected=")-1+sizeof("MARKER_DIGITS")-1+i', str(prefix)+"+i")


def elf_symbols(path):
    """Read actual ELF64 symbol bits, independently of assembler directives."""
    data = Path(path).read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise AssertionError("expected little-endian ELF64")
    offset, entry_size, count = struct.unpack_from("<Q", data, 40)[0], *struct.unpack_from("<HH", data, 58)
    if entry_size != 64 or offset+entry_size*count > len(data):
        raise AssertionError("invalid section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset+i*entry_size) for i in range(count)]
    result = {}
    for section in sections:
        if section[1] != 2:
            continue
        if section[9] != 24:
            raise AssertionError("invalid symtab entry size")
        strings = sections[section[6]]
        table = data[strings[4]:strings[4]+strings[5]]
        for at in range(section[4], section[4]+section[5], 24):
            name, info, other, index, value, size = struct.unpack_from("<IBBHQQ", data, at)
            end = table.find(b"\0", name)
            if end < 0:
                raise AssertionError("unterminated symbol name")
            symbol = table[name:end].decode()
            if symbol:
                result[symbol] = {"binding": info >> 4, "type": info & 15,
                                  "visibility": other & 3, "section": index,
                                  "value": value, "size": size}
    return result


class WeakSourceApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_sha256 = os.environ.get("OCORE_TEST_LLVM_SHA256", importer.PINNED_SHA256)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ocore-weak-source-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def roundtrip(self, body, triple):
        source = self.directory / "original.ll"
        source.write_text(promises.module_text(triple, body))
        original = source.read_bytes()
        bitcode = memory.LlvmMemoryImportTests.bitcode(self, source)
        normalized = [importer.import_module(path, library_path=self.library,
                                            expected_sha256=self.library_sha256) for path in (source, bitcode)]
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual({k:v for k,v in normalized[0].items() if k not in {"name", "provenance"}},
                         {k:v for k,v in normalized[1].items() if k not in {"name", "provenance"}})
        for path, module in zip((source, bitcode), normalized):
            self.assertEqual(module["provenance"]["input_sha256"], artifact(path)["sha256"])
        return normalized

    def test_whole_original_weak_definitions_keep_bodies_globals_visibility_and_relocations_ll_bc_all_three(self):
        for triple in baseline.TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(provider("a"), triple):
                    self.assertEqual(module["provenance"]["source_function_count"], 4)
                    self.assertEqual(module["provenance"]["source_global_count"], 4)
                    self.assertEqual({fn["name"] for fn in module["functions"]},
                                     {"chosen", "hidden_function", "protected_function", "cold_a"})
                    for definition in [*module["functions"], *module["globals"]]:
                        self.assertEqual(definition["linkage"], "weak")
                        name = definition["name"]
                        expected = "hidden" if name.startswith("hidden_") else "protected" if name.startswith("protected_") else "default"
                        self.assertEqual(definition["visibility"], expected)
                    self.assertTrue(all(fn["entry"] is not None and fn["blocks"] for fn in module["functions"]))
                    address = next(g for g in module["globals"] if g["name"] == "weak_address")
                    self.assertEqual(address["initializer"]["relocations"],
                                     [{"offset":0,"width":64,"symbol":"chosen_global","addend":0}])

    def test_ordinary_referenced_declarations_remain_strong_and_typed(self):
        for triple in baseline.TRIPLES:
            for module in self.roundtrip(CONSUMER, triple):
                declarations = [fn for fn in module["functions"] if fn["entry"] is None]
                self.assertEqual(len(declarations), 3)
                self.assertTrue(all(fn["linkage"] == "external" for fn in declarations))
                self.assertTrue(all(g["linkage"] == "external" and g["initializer"] is None for g in module["globals"]))

    def test_external_weak_common_available_externally_and_unsupported_group_policy_reject_whole_units(self):
        cases = ["@unsupported = extern_weak global i64\n",
                 "declare extern_weak i64 @unsupported(i64)\n",
                 "@unsupported = common global i64 0\n",
                 "define available_externally i64 @unsupported() { ret i64 7 }\n",
                 "$unsupported = comdat largest\n@unsupported = weak global i64 7, comdat\n"]
        for triple in baseline.TRIPLES:
            for body in cases:
                with self.subTest(triple=triple, body=body):
                    source = self.directory / "unsupported.ll"
                    source.write_text(promises.module_text(triple, provider("a")+body))
                    bitcode = memory.LlvmMemoryImportTests.bitcode(self,source)
                    for path in (source,bitcode):
                        with self.assertRaises(importer.ImportFailure) as failure:
                            importer.import_module(path, library_path=self.library,
                                                   expected_sha256=self.library_sha256)
                        self.assertIn(failure.exception.stage, ("import", "bitcode-audit"))
                        self.assertRegex(str(failure.exception), "unsupported.*(?:linkage|COMDAT)")


class WeakNativeTests(unittest.TestCase):
    capture_closure_gate = False

    @classmethod
    def setUpClass(cls):
        cls.compiler = Path(os.environ.get("OCOREC", str(ROOT/"target/debug/ocorec"))).resolve()
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(SDK))).resolve()
        cls.linker = shutil.which(os.environ.get("LD_LLD", "ld.lld"))
        cls.assembler = shutil.which("clang")
        library = os.environ.get("OCORE_TEST_LLVM_LIBRARY")
        library_sha = os.environ.get("OCORE_TEST_LLVM_SHA256")
        if library_sha and not library:
            raise RuntimeError("OCORE_TEST_LLVM_SHA256 requires OCORE_TEST_LLVM_LIBRARY")
        cls.llvm_flags = []
        if library:
            library_sha = library_sha or importer.PINNED_SHA256
            if artifact(library)["sha256"] != library_sha:
                raise RuntimeError("explicit LLVM parser digest differs from OCORE_TEST_LLVM_SHA256")
            cls.llvm_flags = ["--llvm-library", library, "--llvm-sha256", library_sha]
        required = [cls.compiler, *(cls.sdk/name for name in ("clang", "llvm-as", "llvm-nm", "llvm-readobj"))]
        missing = [str(path) for path in required if not path.is_file()]
        if cls.linker is None:
            missing.append("LD_LLD/ld.lld")
        if cls.assembler is None:
            missing.append("clang assembler from PATH")
        if missing:
            reason = "actual O-core and installed exact LLVM22 SDK required: " + ", ".join(missing)
            if (os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1"
                    or cls.capture_closure_gate and os.environ.get("OCORE_TEST_REQUIRE_CAPTURE_CLOSURE") == "1"):
                raise RuntimeError(reason)
            raise unittest.SkipTest(reason)
        for path in required[1:]:
            result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=15)
            if result.returncode or not re.search(r"\b(?:clang version|LLVM version|LLD) 22\.1\.6\b", result.stdout):
                raise RuntimeError("exact LLVM22.1.6 required: " + str(path))

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_WEAK_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-weak-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.compiler_sha = artifact(self.compiler)["sha256"]
        self.sequence = 0
        tools={"ocorec":self.compiler,"clang":self.sdk/"clang","own_assembler":self.assembler,
               "llvm-as":self.sdk/"llvm-as","llvm-nm":self.sdk/"llvm-nm",
               "llvm-readobj":self.sdk/"llvm-readobj","linker":self.linker}
        if self.llvm_flags:
            tools["explicit_llvm_parser"]=self.llvm_flags[1]
        self.evidence=RunEvidence([__file__],tools)
        self.addCleanup(self.evidence.verify_unchanged)

    def command(self, argv, success=True, cwd=ROOT):
        argv = [str(item) for item in argv]
        result = self.evidence.run(argv,cwd=cwd)
        (self.directory/f"command-{self.sequence:03}.json").write_text(json.dumps({
            **self.evidence.commands[-1],"exit_code":result.returncode,
            "stdout":result.stdout.decode(errors="replace"),"stderr":result.stderr.decode(errors="replace")}, indent=2))
        self.sequence += 1
        if success:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def inputs(self, stem, triple, body):
        source = self.directory/(stem+".ll"); source.write_text(promises.module_text(triple, body))
        self.evidence.watch_source(source)
        binary = source.with_suffix(".bc"); self.command([self.sdk/"llvm-as",source,"-o",binary])
        self.evidence.watch_source(binary)
        return source, binary

    def test_actual_weak_elf_bindings_and_selection_match_original_clang_all_three_isas(self):
        try:
            runners = {isa:execution_prefix(isa, os.environ.get("OCORE_TEST_QEMU_"+isa.upper()))
                       for isa in TARGETS}
        except RuntimeError as error:
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail(str(error))
            self.skipTest(str(error))
        emulators = {isa:runner[0] for isa,runner in runners.items() if runner}
        for isa,path in emulators.items():
            self.evidence.watch_tool(isa,path)
        report = {"scope":"weak-definition compiler conformance on Linux carriers", "runtime_complete":False,
                  "kernel_execution_verified":False,"dependency_closure_complete":False,"compiler_sha256":self.compiler_sha,
                  "test_source":artifact(__file__),
                  "tools":{name:artifact(path) for name,path in {"ocorec":self.compiler, "clang":self.sdk/"clang",
                      "own_assembler":self.assembler,"llvm-as":self.sdk/"llvm-as","llvm-readobj":self.sdk/"llvm-readobj", "ld.lld":self.linker,
                      **emulators}.items()},"targets":{}}
        for isa,(target,triple,machine,flags) in TARGETS.items():
            objects = {}
            records = []
            for tag,body in [(tag,provider(tag)) for tag in MARKERS]+[("consumer",CONSUMER)]:
                for source in self.inputs(isa+"-"+tag,triple,body):
                    original = source.read_bytes()
                    own = source.with_name(source.name+".own.o")
                    reference = source.with_name(source.name+".clang.o")
                    normalized = source.with_name(source.name+".native.json")
                    self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"--emit","mir","-o",normalized,*self.llvm_flags])
                    receipt = source.with_name(source.name+".verification.json")
                    self.command([self.compiler,normalized,"--input-kind","native-ir","--verify-native","--receipt",receipt])
                    self.assertEqual(json.loads(receipt.read_text())["module_sha256"],artifact(normalized)["sha256"])
                    self.command([self.compiler,source,"--input-kind","llvm-ir","--target",target,"-o",own,*self.llvm_flags])
                    self.command([self.sdk/"clang","--target="+triple,*flags,"-O0","-c",source,"-o",reference])
                    self.assertEqual(source.read_bytes(),original)
                    elf(own,machine,1); elf(reference,machine,1)
                    symbols = elf_symbols(own)
                    self.command([self.sdk/"llvm-readobj","--symbols",own])
                    if tag == "consumer":
                        for name in ("chosen","hidden_function","protected_function","chosen_global",
                                     "hidden_global","protected_global","weak_address"):
                            self.assertEqual(symbols[name]["section"],0,name)
                            self.assertEqual(symbols[name]["binding"],1,name)
                            self.assertEqual(symbols[name]["visibility"],2 if name.startswith("hidden_") else 3 if name.startswith("protected_") else 0,name)
                    else:
                        for name in ("chosen","hidden_function","protected_function","cold_"+tag,
                                     "chosen_global","hidden_global","protected_global","weak_address"):
                            symbol = symbols[name]
                            self.assertNotEqual(symbol["section"],0,name)
                            self.assertEqual(symbol["binding"],1 if tag=="strong" else 2,name)
                            self.assertEqual(symbol["visibility"],2 if name.startswith("hidden_") else 3 if name.startswith("protected_") else 0,name)
                            self.assertEqual(symbol["type"],1 if name.endswith("global") or name=="weak_address" else 2,name)
                            self.assertGreater(symbol["size"],0,name)
                            if symbol["type"]==1:self.assertEqual(symbol["size"],8,name)
                    objects[tag,source.suffix] = own,reference
                    records.append({"unit":tag,"input":artifact(source),"module":artifact(normalized),"verification":artifact(receipt),
                                    "own_object":artifact(own),"original_clang_object":artifact(reference),"elf_symbols":symbols})
            executions = []
            for suffix in (".ll",".bc"):
                for order in SCENARIOS:
                    marker = MARKERS["strong" if "strong" in order else order[0]]
                    harness = self.directory/(isa+"-"+"-".join(order)+suffix+".c")
                    harness.write_text(carrier(marker))
                    self.evidence.watch_source(harness)
                    for kind,index in (("own",0),("clang",1)):
                        output = harness.with_name(harness.name+"."+kind)
                        argv = [self.sdk/"clang","--target="+triple,*flags,"--ld-path="+self.linker,
                                "-O1","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-pic","-fno-pie",
                                "-nostdlib","-static","-Wl,--no-relax","-Wl,-e,_start",harness,
                                objects["consumer",suffix][index],*[objects[tag,suffix][index] for tag in order],"-o",output]
                        self.command(argv)
                        command = [*runners[isa],output]
                        result = self.command(command)
                        self.assertEqual(result.stdout,golden(marker))
                        executions.append({"input_kind":suffix,"order":list(order),"implementation":kind,
                                           "executable":artifact(output),"stdout":result.stdout.decode(),"exit_code":0})
                        if kind=="own" and order==SCENARIOS[0]:
                            corrupt = output.with_name(output.name+".corrupt")
                            self.command([*argv[:-2],"-DCORRUPT_ORACLE","-o",corrupt])
                            failed = self.command([*runners[isa],corrupt],success=False)
                            self.assertEqual(failed.returncode,31); self.assertEqual(failed.stdout,b"")
                            executions.append({"input_kind":suffix,"order":list(order),"corrupt_oracle":True,
                                               "executable":artifact(corrupt),"exit_code":31})
            report["targets"][isa] = {"modules":records,"executions":executions,
                                      "execution_argv_prefix":runners[isa],
                                      "profile":{"native_target":target,"hosted_target":triple,"flags":flags}}
        self.assertEqual(artifact(self.compiler)["sha256"],self.compiler_sha)
        report["provenance"]=self.evidence.finish()
        (self.directory/"weak-conformance.json").write_text(json.dumps(report,indent=2)+"\n")

    def test_weak_native_declarations_cannot_masquerade_as_definitions(self):
        for isa,(target,_,_,_) in TARGETS.items():
            fn = native.function("ordinary")
            global_ = {"name":"weak_global","ty":native.I64,"linkage":"weak","alignment":8,
                       "constant":False,"thread_local":False,"initializer":None}
            for kind in ("global","function"):
                module = native.module(isa,[fn],[global_] if kind=="global" else [])
                if kind=="function":
                    module["functions"][0].update(linkage="weak",entry=None,blocks=[])
                source = self.directory/(isa+"-"+kind+".json"); source.write_text(json.dumps(module))
                receipt = source.with_suffix(".receipt.json")
                result = self.command([self.compiler,source,"--input-kind","native-ir","--verify-native","--receipt",receipt],success=False)
                self.assertNotEqual(result.returncode,0); self.assertFalse(receipt.exists())
                self.assertIn("weak",result.stderr.decode())

    def test_original_rust_llvm_use_cpp_whole_unit_after_weak_increment(self):
        default = Path.home()/".cache/ostadix-runtime-captures/rust-8bab26f4-llvm22-full-first/import-audit-whole-llvm-snapshot-20261010T144337Z/report.json"
        audit = Path(os.environ.get("OCORE_TEST_LLVM_WHOLE_UNIT_AUDIT",str(default)))
        if not audit.is_file():
            self.skipTest("original full-source LLVM capture audit not installed; no synthetic compiler-unit fallback")
        evidence = json.loads(audit.read_text())
        candidates = [unit for unit in evidence["units"]
                      if unit["source"]["path"].endswith("/llvm/lib/IR/Use.cpp")]
        self.assertEqual(len(candidates),1,"exact original LLVM implementation source required")
        original = candidates[0]
        for key in ("input","source","source_journal"):
            info = original[key]
            self.assertEqual(artifact(info["path"])["sha256"],info["sha256"],key)
        self.assertEqual(original["first_diagnostic"]["message"],"unsupported linkage 5")
        self.assertEqual(original["first_diagnostic"]["symbol"],"_ZN4llvm30VerifyDisableABIBreakingChecksE")
        source = Path(original["input"]["path"])
        normalized = self.directory/"original-llvm-Use.native.json"
        result = self.command([self.compiler,source,"--input-kind","llvm-ir","--target","x86_64-unknown-none",
                               "--emit","mir","-o",normalized,*self.llvm_flags],success=False)
        diagnostic = result.stderr.decode(errors="replace")
        details = next((json.loads(line.split("LLVM import failed: ",1)[1])["error"]
                        for line in diagnostic.splitlines() if "LLVM import failed: {" in line), None)
        self.assertNotIn("unsupported linkage 5",diagnostic,"generic weak failure must be resolved for original compiler input")
        record = {"scope":"whole original Rust LLVM implementation-unit diagnostic", "runtime_complete":False,
                  "kernel_execution_verified":False,"dependency_closure_complete":False,
                  "compiler_sha256":self.compiler_sha,"original_audit":artifact(audit),
                  "original_input":original["input"],"original_source":original["source"],
                  "original_source_journal":original["source_journal"],"whole_unit_imported":result.returncode==0,
                  "diagnostic":diagnostic,"first_diagnostic":details,"exit_code":result.returncode}
        if result.returncode:
            self.assertFalse(normalized.exists(),"original compiler source is never partially imported")
            self.assertIn("unsupported",diagnostic)
            (self.directory/"original-llvm-Use-diagnostic.json").write_text(json.dumps(record,indent=2)+"\n")
            reason = (details["symbol"]+": "+details["message"]) if details else diagnostic.strip().splitlines()[0]
            self.skipTest("whole original LLVM Use.cpp still unsupported after weak lowering: "+reason)
        module = json.loads(normalized.read_text())
        self.assertEqual(module["provenance"]["input_sha256"],original["input"]["sha256"])
        text = source.read_text()
        self.assertEqual(module["provenance"]["source_function_count"],len(re.findall(r"^(?:define|declare)\b",text,re.MULTILINE)))
        self.assertEqual(module["provenance"]["source_global_count"],len(re.findall(r"^@[^\n]+ = ",text,re.MULTILINE)))
        guard = next(global_ for global_ in module["globals"] if global_["name"]=="_ZN4llvm30VerifyDisableABIBreakingChecksE")
        self.assertEqual(guard["linkage"],"weak");self.assertIsNotNone(guard["initializer"])
        receipt = self.directory/"original-llvm-Use.verification.json"
        self.command([self.compiler,normalized,"--input-kind","native-ir","--verify-native","--receipt",receipt])
        self.assertEqual(json.loads(receipt.read_text())["module_sha256"],artifact(normalized)["sha256"])
        obj = self.directory/"original-llvm-Use.own.o"
        self.command([self.compiler,normalized,"--input-kind","native-ir","--target","x86_64-unknown-none","-o",obj])
        self.assertEqual(elf_symbols(obj)[guard["name"]]["binding"],2)
        record.update(module=artifact(normalized),verification=artifact(receipt),own_object=artifact(obj))
        (self.directory/"original-llvm-Use-diagnostic.json").write_text(json.dumps(record,indent=2)+"\n")


def capture_closure_prerequisites(olangc, sdk):
    missing=[str(path) for path in (olangc,sdk/"clang++") if not path.is_file()]
    git=shutil.which("git")
    if git is None:
        missing.append("git")
    if missing:
        reason="capture closure prerequisites unavailable: "+", ".join(missing)
        if os.environ.get("OCORE_TEST_REQUIRE_CAPTURE_CLOSURE") == "1":
            raise RuntimeError("required "+reason)
        raise unittest.SkipTest(reason)
    return git


class CaptureClosureGateTests(unittest.TestCase):
    def test_missing_required_capture_prerequisites_fail_instead_of_skip(self):
        with tempfile.TemporaryDirectory(prefix="ocore-required-closure-") as directory:
            missing=Path(directory)/"missing"
            with mock.patch.dict(os.environ,{"OCORE_TEST_REQUIRE_CAPTURE_CLOSURE":"1"}):
                with self.assertRaisesRegex(RuntimeError,"required capture closure prerequisites"):
                    capture_closure_prerequisites(missing,missing)
            with mock.patch.dict(os.environ,{"OCORE_TEST_REQUIRE_CAPTURE_CLOSURE":"0",
                                             "OCORE_TEST_REQUIRE_ALL_ISAS":"1"}):
                with self.assertRaises(unittest.SkipTest):
                    capture_closure_prerequisites(missing,missing)


class WeakRuntimeClosureTests(WeakNativeTests):
    capture_closure_gate = True
    # Suppress inherited native methods: this class adds only capture closure.
    test_actual_weak_elf_bindings_and_selection_match_original_clang_all_three_isas = None
    test_weak_native_declarations_cannot_masquerade_as_definitions = None
    test_original_rust_llvm_use_cpp_whole_unit_after_weak_increment = None

    def test_actual_captured_duplicate_weak_and_strong_definitions_require_compatible_abi(self):
        isa = host_isa()
        self.assertIn(isa, TARGETS, "capture closure requires a supported native Linux host ISA")
        target = TARGETS[isa][0]
        olangc = Path(os.environ.get("OLANGC", str(ROOT/"target/debug/olangc"))).resolve()
        git=capture_closure_prerequisites(olangc,self.sdk)
        for name,path in {"olangc":olangc,"clang++":self.sdk/"clang++","git":git,
                          "python":sys.executable}.items():
            self.evidence.watch_tool(name,path)
        self.evidence.watch_source(ROOT/"scripts/ocore_runtime_capture.py")
        linker_query=self.command([self.sdk/"clang","-print-prog-name=ld.lld"]).stdout.decode().strip()
        capture_linker=shutil.which(linker_query,path=self.evidence.environment.get("PATH"))
        self.assertIsNotNone(capture_linker,"capture driver linker must resolve")
        self.evidence.watch_tool("capture_driver_linker",capture_linker)
        receipts = []
        for mismatch in ("none","function","global","weak-function","weak-global"):
            root = self.directory/mismatch; source = root/"source"; source.mkdir(parents=True)
            (source/"weak.c").write_text('__attribute__((weak)) unsigned long long collide(unsigned long long x){return x+11;}\n__attribute__((weak)) unsigned long long counter=11;\n')
            result_type = "unsigned int" if mismatch.endswith("function") else "unsigned long long"
            global_type = "unsigned int" if mismatch.endswith("global") else "unsigned long long"
            second_binding = "__attribute__((weak)) " if mismatch.startswith("weak-") else ""
            (source/"strong.c").write_text(f'{second_binding}{result_type} collide({result_type} x){{return x+53;}}\n{second_binding}{global_type} counter=53;\n')
            (source/"main.c").write_text('extern unsigned long long collide(unsigned long long);extern unsigned long long counter;\nint main(void){return collide(7)!=60 || counter!=53;}\n')
            (source/"build.py").write_text('''import json,os,pathlib,subprocess,sys
source=pathlib.Path(sys.argv[1]); cc=os.environ["CC"]; flags=json.loads(sys.argv[2])
names=["weak.c","strong.c","main.c"]
for name in names:subprocess.run([cc,*flags,"-c",str(source/name),"-o",name+".o"],check=True)
subprocess.run([cc,*[name+".o" for name in names],"-fuse-ld=lld","-no-pie","-o","app"],check=True)
pathlib.Path("inventory.json").write_text(json.dumps({"schema":"ocore-runtime-unit-inventory-v1","complete":True,"units":[{"id":name,"kind":"clang","source":name,"role":"runtime","build_step":"runtime-build"} for name in names]}))
''')
            for path in source.iterdir():
                self.evidence.watch_source(path)
            for argv in (("git","init","-q"),("git","add","."),("git","-c","user.name=Weak Closure Test","-c","user.email=test@example.invalid","commit","-qm","typed whole units")):
                self.command(argv,cwd=source)
            revision = self.command(["git","rev-parse","HEAD"],cwd=source).stdout.decode().strip()
            recipe = {"schema":"ocore-runtime-recipe-v1","name":"weak-typed-closure-"+mismatch,
                      "source":{"url":"local-pinned-weak-regression","revision":revision},"toolchain":{"llvm_version":"22.1.6"},
                      "commands":[{"name":"runtime-build","argv":[sys.executable,"{source}/build.py","{source}",json.dumps(capture_qa.FLAGS)]}],
                      "coverage":{"required_units":[{"id":name,"kind":"clang","source":name,"role":"runtime"} for name in ("weak.c","strong.c","main.c")],
                                  "required_outputs":["app"],"require_full_unit_inventory":True}}
            recipe_path=root/"recipe.json";recipe_path.write_text(json.dumps(recipe))
            self.evidence.watch_source(recipe_path)
            build,capture,output = root/"build",root/"capture",root/"lowered"
            self.command([sys.executable,ROOT/"scripts/ocore_runtime_capture.py","capture",recipe_path,"--source",source,
                          "--build",build,"--output",capture,"--unit-inventory",build/"inventory.json",
                          "--cc",self.sdk/"clang","--cxx",self.sdk/"clang++","--llvm-nm",self.sdk/"llvm-nm"])
            original=json.loads((capture/"report.json").read_text()); self.assertTrue(original["capture_complete"])
            self.assertEqual(len(original["lowering_unit_ids"]),3)
            result=self.command([olangc,capture/"report.json","--native-runtime","--native-isa",target,
                                 "--native-runtime-output","obj","-o",output,*self.llvm_flags],success=False)
            receipt=json.loads((output/"coverage.json").read_text())
            summary = json.dumps({key:receipt.get(key) for key in ("issues","unit_lowering_complete","module_set_complete","lowered_unit_count","symbol_closure_complete")})
            self.assertTrue(receipt["unit_lowering_complete"],summary)
            self.assertEqual(receipt["module_set_complete"],mismatch=="none",summary)
            self.assertEqual(receipt["lowered_unit_count"],3)
            self.assertEqual(receipt["symbol_closure_complete"],mismatch=="none")
            self.assertEqual(result.returncode==0,mismatch=="none",summary)
            for field in ("runtime_complete","native_execution_qualified","dependency_closure_complete","artifact_complete","link_performed"):
                self.assertFalse(receipt[field],field)
            if mismatch!="none":self.assertRegex(json.dumps(receipt["issues"]),"incompatible|ABI|contract")
            objects=list(output.glob("unit-*/module.o"));self.assertEqual(len(objects),3)
            if mismatch=="none":
                exe=root/"own-linked-selection";self.command([self.sdk/"clang",*objects,"--ld-path="+self.linker,"-no-pie","-o",exe]);self.command([exe])
            receipts.append({"scenario":mismatch,"receipt":artifact(output/"coverage.json"),"symbol_closure_complete":receipt["symbol_closure_complete"]})
        (self.directory/"weak-capture-closure.json").write_text(json.dumps({"scope":"typed compiler symbol closure regression","runtime_complete":False,
            "test_source":artifact(__file__),"olangc":artifact(olangc),"receipts":receipts,
            "profile":{"host_isa":isa,"native_target":target},
            "require_capture_closure":os.environ.get("OCORE_TEST_REQUIRE_CAPTURE_CLOSURE")=="1",
            "provenance":self.evidence.finish()},indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
