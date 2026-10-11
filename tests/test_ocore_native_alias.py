"""Direct LLVM aliases retain storage/code identity and independent ELF binding.

Original ll/bc units are never rewritten. Clang22 compiles those same inputs as
an independent reference; Linux startup and QEMU only carry the comparison.
These are compiler regressions, not complete runtime/compiler qualification.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import struct
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_llvm_optimizer_promises as promises
from tests import test_ocore_native_runtime as capture_qa
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK


def origin(marker=11, root_weak=False, alias_weak=False, extra_aliases=False):
    root_binding = "weak " if root_weak else ""
    alias_binding = "weak " if alias_weak else ""
    body = f"""
@root_global = {root_binding}global i64 {marker}, align 16
@global_alias = {alias_binding}alias i64, ptr @root_global
@alias_global_pointer = constant ptr @global_alias, align 8
@alias_function_pointer = constant ptr @function_alias, align 8
define {root_binding}i64 @root_function(i64 %x) align 64 {{
  %v = add i64 %x, {marker}
  ret i64 %v
}}
@function_alias = {alias_binding}alias i64(i64), ptr @root_function
define i64 @alias_dispatch(i64 %x) {{
  %pointer = load ptr, ptr @alias_function_pointer, align 8
  %v = call i64 %pointer(i64 %x)
  ret i64 %v
}}
define i64 @alias_global_value() align 64 {{
  %pointer = load ptr, ptr @alias_global_pointer, align 8
  %v = load i64, ptr %pointer, align 8
  ret i64 %v
}}
define i64 @alias_write(i64 %value) {{
  %pointer = load ptr, ptr @alias_global_pointer, align 8
  store i64 %value, ptr %pointer, align 8
  %root = load i64, ptr @root_global, align 8
  %alias = load i64, ptr @global_alias, align 8
  %sum = add i64 %root, %alias
  ret i64 %sum
}}
"""
    if extra_aliases:
        for visibility in ("hidden", "protected", "internal"):
            # Internal is linkage, rather than ELF visibility.
            specifier = visibility + " "
            body += f"@global_{visibility}_alias = {specifier}alias i64, ptr @root_global\n"
            body += f"@function_{visibility}_alias = {specifier}alias i64(i64), ptr @root_function\n"
    return body


def replacement(symbol, marker):
    return f"""
@{symbol}_global = global i64 {marker}, align 16
define i64 @{symbol}_function(i64 %x) align 64 {{
  %v = add i64 %x, {marker}
  ret i64 %v
}}
""" if symbol == "root" else f"""
@global_alias = global i64 {marker}, align 16
define i64 @function_alias(i64 %x) align 64 {{
  %v = add i64 %x, {marker}
  ret i64 %v
}}
"""


# Expectations follow LLVM's alias semantics and the independently measured
# original Clang22/LLD behavior. Replacing a root symbol cannot retarget the
# separately named alias to different storage/code in another input object.
SCENARIOS = {
    "identity": {"body": origin(extra_aliases=True), "replacement": None,
                 "root": 11, "alias": 11, "equal": 1},
    "override-root": {"body": origin(root_weak=True), "replacement": replacement("root", 211),
                      "root": 211, "alias": 11, "equal": 0},
    "override-alias": {"body": origin(alias_weak=True), "replacement": replacement("alias", 53),
                       "root": 11, "alias": 53, "equal": 0},
}


def golden(root_marker, alias_marker, equal):
    values = [root_marker, alias_marker, equal, equal, alias_marker, 1, 1]
    for value in weak.inputs():
        values.extend(((value + root_marker) & MASK, (value + alias_marker) & MASK,
                       (value + alias_marker) & MASK, (value + alias_marker) & MASK))
    for value in weak.inputs()[:16]:
        root = value if equal else root_marker
        values.extend(((root + value) & MASK, value, value, root))
    digest = 0xCBF29CE484222325
    for value in values:
        digest = ((digest ^ value) * 0x100000001B3) & MASK
    return f"OCORE-ALIAS digest={digest:016x} checks={len(values)}\n".encode()


def carrier(root_marker, alias_marker, equal):
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    text += f"\n#define ROOT_MARKER {root_marker}ULL\n#define ALIAS_MARKER {alias_marker}ULL\n#define EQUAL {equal}\n"
    text += r"""
extern u64 root_global,global_alias;
extern u64 *alias_global_pointer;
extern u64 root_function(u64),function_alias(u64),alias_dispatch(u64),alias_global_value(void),alias_write(u64);
extern u64 (*alias_function_pointer)(u64);
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
int conformance_main(void){
 /* Volatile address bits prevent the C frontend from folding distinct extern
    object names to unequal before the ELF linker resolves their aliases. */
 u64 volatile addresses[]={(u64)&root_global,(u64)&global_alias,(u64)root_function,(u64)function_alias};
 if(add(root_global,ROOT_MARKER)||add(global_alias,ALIAS_MARKER)||
    add(addresses[0]==addresses[1],EQUAL)||add(addresses[2]==addresses[3],EQUAL)||
    add(alias_global_value(),ALIAS_MARKER)||add(alias_global_pointer==&global_alias,1)||
    add(alias_function_pointer==function_alias,1))return 31;
 u64(*indirect)(u64)=function_alias;
 for(u64 i=0;i<sizeof(values)/sizeof(values[0]);++i){u64 x=values[i];
  if(add(root_function(x),x+ROOT_MARKER)||add(function_alias(x),x+ALIAS_MARKER)||
     add(alias_dispatch(x),x+ALIAS_MARKER)||add(indirect(x),x+ALIAS_MARKER))return 31;
 }
 for(u64 i=0;i<16;++i){u64 x=values[i],root=EQUAL?x:ROOT_MARKER;
  if(add(alias_write(x),root+x)||add(alias_global_value(),x)||add(global_alias,x)||add(root_global,root))return 31;
 }
 if(checks!=391)return 37;
"""
    output = golden(root_marker, alias_marker, equal).decode().rstrip()
    placeholder = "0" * 16
    prefix = output.index("digest=") + len("digest=")
    output = output[:prefix] + placeholder + output[prefix + 16:]
    text += 'static char output[]="' + output + '\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{prefix}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
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


def section_alignment(path, index):
    data = Path(path).read_bytes()
    table = struct.unpack_from("<Q", data, 40)[0]
    return struct.unpack_from("<IIQQQQIIQQ", data, table + index * 64)[8]


def relocation_types(path):
    data = Path(path).read_bytes()
    table, entry_size, count = struct.unpack_from("<Q", data, 40)[0], *struct.unpack_from("<HH", data, 58)
    result = set()
    for index in range(count):
        section = struct.unpack_from("<IIQQQQIIQQ", data, table + index * entry_size)
        if section[1] not in (4, 9):
            continue
        for offset in range(section[4], section[4] + section[5], section[9]):
            result.add(struct.unpack_from("<Q", data, offset + 8)[0] & 0xffffffff)
    return sorted(result)


class AliasSourceApiTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakSourceApiTests.setUpClass.__func__)
    setUp = weak.WeakSourceApiTests.setUp
    roundtrip = weak.WeakSourceApiTests.roundtrip

    def test_direct_alias_inventory_types_linkage_visibility_and_function_alignment_ll_bc_all_three(self):
        for triple in baseline.TRIPLES:
            for module in self.roundtrip(origin(root_weak=True, extra_aliases=True), triple):
                self.assertEqual(module["provenance"]["source_alias_count"], 8)
                self.assertEqual(len(module["aliases"]), 8)
                function = next(item for item in module["functions"] if item["name"] == "root_function")
                self.assertEqual(function["alignment"], 64)
                later = next(item for item in module["functions"] if item["name"] == "alias_global_value")
                self.assertEqual(later["alignment"], 64)
                roots = {item["name"]: item for item in [*module["functions"], *module["globals"]]}
                for alias in module["aliases"]:
                    name = alias["name"]
                    expected_root = "root_function" if name.startswith("function_") else "root_global"
                    self.assertEqual(alias["aliasee"], expected_root)
                    self.assertEqual(alias["linkage"], "internal" if "internal" in name else "external")
                    expected_visibility = "hidden" if "hidden" in name else "protected" if "protected" in name else "default"
                    self.assertEqual(alias["visibility"], expected_visibility)
                    if expected_root == "root_global":
                        self.assertEqual(alias["ty"], roots[expected_root]["ty"])
                    else:
                        self.assertEqual(module["types"][alias["ty"]]["signature"], roots[expected_root]["signature"])
                for name, alias_name in (("alias_global_pointer", "global_alias"), ("alias_function_pointer", "function_alias")):
                    self.assertEqual(roots[name]["initializer"]["relocations"],
                                     [{"offset": 0, "width": 64, "symbol": alias_name, "addend": 0}])

    def test_weak_alias_binding_is_distinct_from_aliasee_binding(self):
        for triple in baseline.TRIPLES:
            for module in self.roundtrip(origin(alias_weak=True), triple):
                self.assertTrue(all(alias["linkage"] == "weak" for alias in module["aliases"]))
                self.assertTrue(all(item["linkage"] == "external" for item in [*module["functions"], *module["globals"]]))

    def test_surviving_unsupported_alias_contracts_reject_whole_original_ll_bc_units(self):
        # These expressions remain outside the first direct-alias contract.
        cases = {
            "chain": "@unsupported = alias i64, ptr @global_alias\n",
            "offset": "@unsupported = alias i64, ptr getelementptr (i8, ptr @root_global, i64 1)\n",
            "type-cast": "@unsupported = alias i32, ptr @root_global\n",
            "tls": "@tls_root = thread_local global i64 0\n@unsupported = thread_local alias i64, ptr @tls_root\n",
            "ifunc": "define ptr @resolver() { ret ptr @root_function }\n@unsupported = ifunc i64(i64), ptr @resolver\n",
        }
        for triple in baseline.TRIPLES:
            for label, body in cases.items():
                with self.subTest(triple=triple, contract=label):
                    source = self.directory / "unsupported.ll"
                    source.write_text(promises.module_text(triple, origin() + body))
                    binary = memory.LlvmMemoryImportTests.bitcode(self, source)
                    for path in (source, binary):
                        with self.assertRaises(importer.ImportFailure) as failure:
                            importer.import_module(path, library_path=self.library)
                        self.assertRegex(str(failure.exception), "alias|TLS|thread|ifunc|IFunc|IFUNC")


class AliasNativeTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    inputs = weak.WeakNativeTests.inputs

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_ALIAS_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-alias-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.sequence = 0

    def test_actual_alias_identity_and_independent_strong_overrides_match_original_clang_all_three(self):
        emulators = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                     for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(emulators.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three execution requires x86 host and both QEMU user emulators")
            self.skipTest("all-three execution tools unavailable")
        report = {"scope": "direct-alias static ELF compiler conformance on Linux carriers",
                  "runtime_complete": False, "kernel_execution_verified": False,
                  "dependency_closure_complete": False, "compiler_sha256": self.compiler_sha,
                  "test_source": weak.artifact(__file__),
                  "tools": {name: weak.artifact(path) for name, path in {
                      "ocorec": self.compiler, "clang": self.sdk / "clang", "llvm-as": self.sdk / "llvm-as",
                      "own_assembler": self.assembler, "ld.lld": self.linker, **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            modules, executions = [], []
            for case, profile in SCENARIOS.items():
                objects = {}
                units = [("origin", profile["body"])]
                if profile["replacement"] is not None:
                    units.append(("replacement", profile["replacement"]))
                for unit, body in units:
                    for source in self.inputs(isa + "-" + case + "-" + unit, triple, body):
                        before = source.read_bytes()
                        own = source.with_name(source.name + ".own.o")
                        reference = source.with_name(source.name + ".clang.o")
                        normalized = source.with_name(source.name + ".native.json")
                        receipt = source.with_name(source.name + ".verification.json")
                        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target,
                                      "--emit", "mir", "-o", normalized])
                        self.command([self.compiler, normalized, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                        self.assertEqual(json.loads(receipt.read_text())["module_sha256"], weak.artifact(normalized)["sha256"])
                        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own])
                        self.command([self.sdk / "clang", "--target=" + triple, *flags, "-O0", "-c", source, "-o", reference])
                        self.assertEqual(source.read_bytes(), before)
                        elf(own, machine, 1)
                        elf(reference, machine, 1)
                        relocs = {"own": relocation_types(own), "original_clang": relocation_types(reference)}
                        if isa == "riscv64":
                            self.assertFalse({43, 51}.intersection(relocs["own"]), "own static RV objects contain no ALIGN/RELAX fixups")
                        parsed = json.loads(normalized.read_text())
                        self.assertEqual(parsed["provenance"]["source_alias_count"], len(parsed["aliases"]))
                        symbol_records = {}
                        for implementation, obj in (("own", own), ("original_clang", reference)):
                            symbols = weak.elf_symbols(obj)
                            for alias in parsed["aliases"]:
                                symbol, root = symbols[alias["name"]], symbols[alias["aliasee"]]
                                for field in ("section", "value", "size", "type"):
                                    self.assertEqual(symbol[field], root[field], (alias["name"], field))
                                self.assertNotEqual(symbol["section"], 0)
                                self.assertEqual(symbol["binding"], {"external": 1, "weak": 2, "internal": 0}[alias["linkage"]])
                                self.assertEqual(symbol["visibility"], {"default": 0, "hidden": 2, "protected": 3}[alias["visibility"]])
                            for function in parsed["functions"]:
                                if function["alignment"]:
                                    symbol = symbols[function["name"]]
                                    # Original RV objects may carry pending
                                    # R_RISCV_ALIGN fixups. Own static objects
                                    # must already realize admitted alignment;
                                    # both implementations are checked again
                                    # after the ELF linker applies relocations.
                                    if implementation == "own" or isa != "riscv64":
                                        self.assertEqual(symbol["value"] % function["alignment"], 0)
                                    self.assertGreaterEqual(section_alignment(obj, symbol["section"]), function["alignment"])
                            symbol_records[implementation] = symbols
                        objects[unit, source.suffix] = own, reference
                        modules.append({"scenario": case, "unit": unit, "input": weak.artifact(source),
                                        "module": weak.artifact(normalized), "verification": weak.artifact(receipt),
                                        "own_object": weak.artifact(own), "original_clang_object": weak.artifact(reference),
                                        "elf_symbols": symbol_records, "relocation_types": relocs})
                for suffix in (".ll", ".bc"):
                    orders = [("origin",)] if len(units) == 1 else [("origin", "replacement"), ("replacement", "origin")]
                    for order in orders:
                        harness = self.directory / (isa + "-" + case + "-" + "-".join(order) + suffix + ".c")
                        harness.write_text(carrier(profile["root"], profile["alias"], profile["equal"]))
                        modes = ("default", "disabled") if isa == "riscv64" else ("disabled",)
                        for mode in modes:
                            for implementation, index in (("own", 0), ("original_clang", 1)):
                                output = harness.with_name(harness.name + "." + implementation + ".relax-" + mode)
                                relaxation = [] if mode == "default" else ["-Wl,--no-relax"]
                                argv = [self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker,
                                        "-O1", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                                        "-nostdlib", "-static", *relaxation, "-Wl,-e,_start", harness,
                                        *[objects[unit, suffix][index] for unit in order], "-o", output]
                                self.command(argv)
                                symbols = weak.elf_symbols(output)
                                requested = {"root_function": 64, "function_alias": 64, "alias_global_value": 64}
                                if case == "identity":
                                    requested.update({"function_" + visibility + "_alias": 64
                                                      for visibility in ("hidden", "protected", "internal")})
                                for name, alignment in requested.items():
                                    symbol = symbols[name]
                                    self.assertEqual(symbol["value"] % alignment, 0, (isa, implementation, mode, name))
                                    self.assertGreaterEqual(section_alignment(output, symbol["section"]), alignment)
                                result = self.command([output] if isa == "x86_64" else [emulators[isa], output])
                                self.assertEqual(result.stdout, golden(profile["root"], profile["alias"], profile["equal"]))
                                executions.append({"scenario": case, "input_kind": suffix, "order": list(order), "link_relaxation": mode,
                                                   "implementation": implementation, "executable": weak.artifact(output),
                                                   "aligned_linked_symbols": {name: symbols[name] for name in requested},
                                                   "stdout": result.stdout.decode(), "exit_code": 0})
                                if implementation == "own" and case == "identity":
                                    corrupt = output.with_name(output.name + ".corrupt")
                                    self.command([*argv[:-2], "-DCORRUPT_ORACLE", "-o", corrupt])
                                    failed = self.command([corrupt] if isa == "x86_64" else [emulators[isa], corrupt], success=False)
                                    self.assertEqual(failed.returncode, 31)
                                    self.assertEqual(failed.stdout, b"")
                                    executions.append({"scenario": case, "input_kind": suffix, "link_relaxation": mode,
                                                       "corrupt_oracle": True, "executable": weak.artifact(corrupt), "exit_code": 31})
            report["targets"][isa] = {"modules": modules, "executions": executions}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "alias-conformance.json").write_text(json.dumps(report, indent=2) + "\n")


class AliasRuntimeClosureTests(AliasNativeTests):
    test_actual_alias_identity_and_independent_strong_overrides_match_original_clang_all_three = None

    def test_actual_captured_alias_provider_remains_attached_to_original_unit(self):
        olangc = Path(os.environ.get("OLANGC", str(ROOT / "target/debug/olangc"))).resolve()
        if not olangc.is_file() or not (self.sdk / "clang++").is_file() or not shutil.which("git"):
            self.skipTest("actual olangc/Git/Clang++ required for capture admission")
        records = []
        for case, weak_root in (("override-root", True), ("override-alias", False)):
            root = self.directory / case
            source = root / "source"
            source.mkdir(parents=True)
            root_binding = "__attribute__((weak)) " if weak_root else ""
            alias_binding = "" if weak_root else ",weak"
            (source / "origin.c").write_text(
                f'{root_binding}unsigned long long root_global=11;\n'
                f'{root_binding}unsigned long long root_function(unsigned long long x){{return x+11;}}\n'
                f'extern unsigned long long global_alias __attribute__((alias("root_global"){alias_binding}));\n'
                f'extern unsigned long long function_alias(unsigned long long) __attribute__((alias("root_function"){alias_binding}));\n')
            prefix = "root" if weak_root else "alias"
            global_name = "root_global" if weak_root else "global_alias"
            function_name = "root_function" if weak_root else "function_alias"
            marker = 211 if weak_root else 53
            (source / "replacement.c").write_text(f'unsigned long long {global_name}={marker};\nunsigned long long {function_name}(unsigned long long x){{return x+{marker};}}\n')
            expected_root, expected_alias = (211, 11) if weak_root else (11, 53)
            (source / "main.c").write_text('extern unsigned long long root_global,global_alias;\nextern unsigned long long root_function(unsigned long long),function_alias(unsigned long long);\n'
                f'int main(void){{return root_global!={expected_root} || global_alias!={expected_alias} || root_function(7)!={expected_root+7} || function_alias(7)!={expected_alias+7} || &root_global==&global_alias || root_function==function_alias;}}\n')
            (source / "build.py").write_text('''import json,os,pathlib,subprocess,sys
source=pathlib.Path(sys.argv[1]);cc=os.environ["CC"];flags=json.loads(sys.argv[2]);names=["origin.c","replacement.c","main.c"]
for name in names:subprocess.run([cc,*flags,"-c",str(source/name),"-o",name+".o"],check=True)
subprocess.run([cc,*[name+".o" for name in names],"-no-pie","-o","app"],check=True)
subprocess.run(["./app"],check=True)
pathlib.Path("inventory.json").write_text(json.dumps({"schema":"ocore-runtime-unit-inventory-v1","complete":True,"units":[{"id":name,"kind":"clang","source":name,"role":"runtime","build_step":"runtime-build"} for name in names]}))
''')
            for argv in (("git", "init", "-q"), ("git", "add", "."),
                         ("git", "-c", "user.name=Alias Closure Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "alias original provider")):
                self.command(argv, cwd=source)
            revision = self.command(["git", "rev-parse", "HEAD"], cwd=source).stdout.decode().strip()
            recipe = {"schema": "ocore-runtime-recipe-v1", "name": "alias-original-provider-" + prefix,
                      "source": {"url": "local-pinned-alias-regression", "revision": revision},
                      "toolchain": {"llvm_version": "22.1.6"},
                      "commands": [{"name": "runtime-build", "argv": [sys.executable, "{source}/build.py", "{source}", json.dumps(capture_qa.FLAGS)]}],
                      "coverage": {"required_units": [{"id": name, "kind": "clang", "source": name, "role": "runtime"}
                                                       for name in ("origin.c", "replacement.c", "main.c")],
                                   "required_outputs": ["app"], "require_full_unit_inventory": True}}
            recipe_path = root / "recipe.json"
            recipe_path.write_text(json.dumps(recipe))
            build, capture, output = root / "build", root / "capture", root / "lowered"
            self.command([sys.executable, ROOT / "scripts/ocore_runtime_capture.py", "capture", recipe_path,
                          "--source", source, "--build", build, "--output", capture, "--unit-inventory", build / "inventory.json",
                          "--cc", self.sdk / "clang", "--cxx", self.sdk / "clang++", "--llvm-nm", self.sdk / "llvm-nm"])
            report = json.loads((capture / "report.json").read_text())
            self.assertTrue(report["capture_complete"])
            self.command([olangc, capture / "report.json", "--native-runtime", "--native-isa", "x86_64-unknown-none",
                          "--native-runtime-output", "obj", "-o", output])
            receipt = json.loads((output / "coverage.json").read_text())
            self.assertTrue(receipt["unit_lowering_complete"])
            self.assertTrue(receipt["symbol_closure_complete"])
            inventory = receipt["symbol_inventory"]
            alias_definitions = [item for item in inventory["definitions"] if item["alias_of"] is not None]
            self.assertEqual({item["symbol"]: item["alias_of"] for item in alias_definitions},
                             {"global_alias": "root_global", "function_alias": "root_function"})
            for alias in alias_definitions:
                original_root = next(item for item in inventory["definitions"]
                                     if item["unit"] == alias["unit"] and item["symbol"] == alias["alias_of"])
                self.assertIsNone(original_root["alias_of"])
                resolution = next(item for item in inventory["export_resolutions"] if item["symbol"] == alias["symbol"])
                root_resolution = next(item for item in inventory["export_resolutions"] if item["symbol"] == alias["alias_of"])
                self.assertEqual(resolution["selected_unit"] == alias["unit"], weak_root)
                self.assertEqual(root_resolution["selected_unit"] == alias["unit"], not weak_root)
            for field in ("runtime_complete", "native_execution_qualified", "dependency_closure_complete", "artifact_complete", "link_performed"):
                self.assertFalse(receipt[field], field)
            objects = list(output.glob("unit-*/module.o"))
            self.assertEqual(len(objects), 3)
            executable = root / "own-original-alias-provider"
            self.command([self.sdk / "clang", *objects, "-no-pie", "-o", executable])
            self.command([executable])
            records.append({"scenario": case, "capture": weak.artifact(capture / "report.json"),
                            "receipt": weak.artifact(output / "coverage.json"), "own_executable": weak.artifact(executable)})
        (self.directory / "alias-capture-closure.json").write_text(json.dumps({
            "scope": "typed alias original-provider closure regression", "runtime_complete": False,
            "test_source": weak.artifact(__file__), "olangc": weak.artifact(olangc), "records": records}, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
