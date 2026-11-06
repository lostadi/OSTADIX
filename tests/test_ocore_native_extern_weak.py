"""Optional weak dependencies through unchanged LLVM, O-core and real ELF links.

These are compiler/linkage regressions, not a complete libc or OS qualification.
Linux syscall carriers and QEMU user emulators only report backend test results.
The retained whole original musl TLS unit is a diagnostic progression gate: its
remaining metadata/assembly requirements must still reject, without partial IR.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, elf, execution_prefix, host_isa
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_native_weak as weak
from tests import test_ocore_native_runtime as capture_qa


PREFIXES = (("optional", ""), ("hidden_optional", "hidden "),
            ("protected_optional", "protected "))


def consumer():
    body = ["@_DYNAMIC = extern_weak hidden constant [0 x i64], align 8",
            "define i64 @dynamic_address() { %p = ptrtoint ptr @_DYNAMIC to i64\n ret i64 %p }"]
    addresses = ["ptr @_DYNAMIC"] + [f"ptr @{name}{suffix}" for name, _ in PREFIXES
                                    for suffix in ("_global", "_function")]
    body.append("@optional_addresses = constant [7 x ptr] ["+", ".join(addresses)+"], align 8")
    for name, visibility in PREFIXES:
        body += [f"@{name}_global = extern_weak {visibility}global i64, align 8",
                 f"declare extern_weak {visibility}i64 @{name}_function(i64)",
                 f"""define i64 @probe_{name}(i64 %x) {{
entry:
  %gpresent = icmp ne ptr @{name}_global, null
  br i1 %gpresent, label %load, label %gmissing
load:
  %g = load i64, ptr @{name}_global, align 8
  br label %gjoin
gmissing:
  br label %gjoin
gjoin:
  %gv = phi i64 [ %g, %load ], [ 7, %gmissing ]
  %fpresent = icmp ne ptr @{name}_function, null
  br i1 %fpresent, label %call, label %fmissing
call:
  %f = call i64 @{name}_function(i64 %x)
  br label %fjoin
fmissing:
  br label %fjoin
fjoin:
  %fv = phi i64 [ %f, %call ], [ 9, %fmissing ]
  %sum = add i64 %gv, %fv
  ret i64 %sum
}}"""]
    return "\n".join(body) + "\n"


def provider(marker, linkage):
    return "\n".join(
        f"@{name}_global = {linkage}{visibility}global i64 {marker}, align 8\n"
        f"define {linkage}{visibility}i64 @{name}_function(i64 %x) {{\n"
        f" %r = add i64 %x, {marker+5}\n ret i64 %r\n}}"
        for name, visibility in PREFIXES) + "\n"


def carrier(marker):
    syscall = weak.LINUX_CARRIER.split("static u64 syscall3", 1)[1].split("static u64 signed_bits", 1)[0]
    startup = weak.LINUX_CARRIER.split("#if defined(__x86_64__)\n__asm__", 1)[1]
    body = "typedef unsigned long long u64;\nstatic u64 syscall3" + syscall
    body += "extern u64 dynamic_address(void);\n"
    body += "extern u64 *optional_addresses[7];\n"
    for name, _ in PREFIXES:
        body += f"extern u64 probe_{name}(u64);\n"
        if marker is not None:
            body += f"extern u64 {name}_global, {name}_function(u64);\n"
    body += "int conformance_main(void) {\n if(dynamic_address()!=0)return 30;\n"
    body += "#ifdef CORRUPT_ORACLE\nconst u64 corrupt=1;\n#else\nconst u64 corrupt=0;\n#endif\n"
    body += "if(optional_addresses[0]!=0)return 32;\n"
    for i, (name, _) in enumerate(PREFIXES):
        if marker is None:
            body += f"if(optional_addresses[{1+2*i}]!=0||optional_addresses[{2+2*i}]!=0)return 32;\n"
        else:
            body += f"if(!optional_addresses[{1+2*i}]||!optional_addresses[{2+2*i}])return 32;\n"
    body += "for(u64 i=0;i<129;++i) { u64 x=i*0x100000001ULL;\n"
    expected = "16" if marker is None else f"x+{2*marker+5}ULL"
    for name, _ in PREFIXES:
        body += f"if(probe_{name}(x)!=(({expected})^corrupt))return 31;\n"
    body += "}\n"
    if marker is not None:
        for i, (name, _) in enumerate(PREFIXES):
            body += f"if(optional_addresses[{1+2*i}]!=&{name}_global||optional_addresses[{2+2*i}]!=(u64*){name}_function)return 32;\n"
            body += f"*optional_addresses[{1+2*i}]={marker+17};\n"
            body += f"if(probe_{name}(0)!={2*marker+22})return 33;\n"
            body += f"*optional_addresses[{1+2*i}]={marker};\n"
    body += f"static const char out[]=\"OCORE-EXTERN-WEAK checks={395 if marker is None else 404}\\n\";\n"
    body += """
#if defined(__x86_64__)
if(syscall3(1,1,(u64)out,sizeof(out)-1)!=sizeof(out)-1)return 99;
#else
if(syscall3(64,1,(u64)out,sizeof(out)-1)!=sizeof(out)-1)return 99;
#endif
return 0;
}
#if defined(__x86_64__)
__asm__""" + startup
    return body


class ExternWeakSourceTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakSourceApiTests.setUpClass.__func__)
    setUp = weak.WeakSourceApiTests.setUp
    roundtrip = weak.WeakSourceApiTests.roundtrip

    def test_whole_ll_bc_keep_optional_declarations_types_visibility_and_named_uses(self):
        for triple in baseline.TRIPLES:
            with self.subTest(triple=triple):
                for module in self.roundtrip(consumer(), triple):
                    declarations = [f for f in module["functions"] if f["entry"] is None]
                    self.assertEqual(len(declarations), 3)
                    globals_ = [g for g in module["globals"] if g["linkage"] == "extern_weak"]
                    self.assertEqual(len(module["globals"]), 5)
                    self.assertEqual(len(globals_), 4)
                    for item in [*declarations, *globals_]:
                        self.assertEqual(item["linkage"], "extern_weak")
                        expected = ("protected" if item["name"].startswith("protected_") else
                                    "hidden" if item["name"].startswith("hidden_") or item["name"] == "_DYNAMIC" else "default")
                        self.assertEqual(item["visibility"], expected)
                    self.assertTrue(all(g["initializer"] is None and g["alignment"] == 8
                                        for g in globals_))
                    pointers = next(g for g in module["globals"] if g["name"] == "optional_addresses")
                    self.assertEqual(len(pointers["initializer"]["relocations"]), 7)
                    self.assertEqual(len([f for f in module["functions"] if f["entry"] is not None]), 4)
                    self.assertIn("STB_WEAK undefined", " ".join(module["provenance"]["refinements"]))


class ExternWeakNativeTests(weak.WeakNativeTests):
    test_actual_weak_elf_bindings_and_selection_match_original_clang_all_three_isas = None
    test_weak_native_declarations_cannot_masquerade_as_definitions = None
    test_original_rust_llvm_use_cpp_whole_unit_after_weak_increment = None

    def test_real_undefined_weak_objects_and_final_link_resolution_all_three_isas(self):
        try:
            runners = {isa: execution_prefix(isa, os.environ.get("OCORE_TEST_QEMU_"+isa.upper())) for isa in TARGETS}
        except RuntimeError as error:
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail(str(error))
            self.skipTest(str(error))
        for isa, runner in runners.items():
            if runner:
                self.evidence.watch_tool(isa, runner[0])
        report = {"scope": "extern_weak compiler and static ELF conformance, Linux test carriers",
                  "runtime_complete": False, "kernel_execution_verified": False, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            objects, records, executions = {}, [], []
            for tag, body in (("consumer", consumer()), ("weak", provider(11, "weak ")),
                              ("strong", provider(53, ""))):
                for source in self.inputs(isa+"-"+tag, triple, body):
                    normalized = source.with_name(source.name+".native.json")
                    own, reference = [source.with_name(source.name+suffix) for suffix in (".own.o", ".clang.o")]
                    self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target,
                                  "--emit", "mir", "-o", normalized, *self.llvm_flags])
                    receipt = source.with_name(source.name+".verification.json")
                    self.command([self.compiler, normalized, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                    self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own, *self.llvm_flags])
                    self.command([self.sdk/"clang", "--target="+triple, *flags, "-O0", "-c", source, "-o", reference])
                    elf(own, machine, 1); elf(reference, machine, 1)
                    for implementation, obj in (("own", own), ("clang", reference)):
                        symbols = weak.elf_symbols(obj)
                        names = [name+suffix for name, _ in PREFIXES for suffix in ("_global", "_function")]
                        if tag == "consumer":
                            names.append("_DYNAMIC")
                        for name in names:
                            symbol = symbols[name]
                            self.assertEqual(symbol["binding"], 1 if tag == "strong" else 2, (isa, name, implementation))
                            self.assertEqual(symbol["section"] == 0, tag == "consumer", (isa, name, implementation))
                            if tag == "consumer":
                                self.assertEqual(symbol["size"], 0)
                                self.assertEqual(symbol["value"], 0)
                                if implementation == "own":
                                    self.assertEqual(symbol["type"], 2 if name.endswith("_function") else 1)
                    self.command([self.sdk/"llvm-readobj", "--symbols", "--relocations", own])
                    objects[tag, source.suffix] = own, reference
                    records.append({"unit": tag, "input": weak.artifact(source), "module": weak.artifact(normalized),
                                    "verification": weak.artifact(receipt), "own": weak.artifact(own), "clang": weak.artifact(reference)})
            for suffix in (".ll", ".bc"):
                for order, marker in (((), None), (("weak",), 11), (("weak", "strong"), 53), (("strong", "weak"), 53)):
                    harness = self.directory/(isa+"-"+("-".join(order) or "absent")+suffix+".c")
                    harness.write_text(carrier(marker)); self.evidence.watch_source(harness)
                    for kind, index in (("own", 0), ("clang", 1)):
                        output = harness.with_name(harness.name+"."+kind)
                        argv = [self.sdk/"clang", "--target="+triple, *flags, "--ld-path="+self.linker,
                                      "-O1", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                                      "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", harness,
                                      objects["consumer", suffix][index], *[objects[tag, suffix][index] for tag in order], "-o", output]
                        self.command(argv)
                        result = self.command([*runners[isa], output])
                        checks = 395 if marker is None else 404
                        self.assertEqual(result.stdout, f"OCORE-EXTERN-WEAK checks={checks}\n".encode())
                        executions.append({"representation": suffix, "providers": list(order), "implementation": kind,
                                           "executable": weak.artifact(output), "stdout": result.stdout.decode(), "checks": checks, "exit_code": 0})
                        if suffix == ".ll" and not order and kind == "own":
                            corrupt = output.with_name(output.name+".corrupt")
                            self.command([*argv[:-2], "-DCORRUPT_ORACLE", "-o", corrupt])
                            rejected = self.command([*runners[isa], corrupt], success=False)
                            self.assertEqual(rejected.returncode, 31)
                            self.assertEqual(rejected.stdout, b"")
                            executions.append({"corrupt_oracle": True, "executable": weak.artifact(corrupt), "exit_code": 31})
            report["targets"][isa] = {"modules": records, "executions": executions, "runner": runners[isa]}
        report["provenance"] = self.evidence.finish()
        (self.directory/"extern-weak-conformance.json").write_text(json.dumps(report, indent=2)+"\n")

    def test_whole_original_musl_tls_unit_progresses_without_partial_import(self):
        default = Path.home()/".cache/okernel-musl-current-import-20261106-t_jqs3yy/__init_tls-2/input.ll"
        source = Path(os.environ.get("OCORE_TEST_MUSL_TLS_LL", str(default)))
        if not source.is_file():
            self.skipTest("retained original whole musl TLS LLVM input not present; no synthetic source fallback")
        expected = os.environ.get("OCORE_TEST_MUSL_TLS_SHA256", "7570620620830e9541b7da1d8cae845beaab43fd82fdbfb67f0b090889f109c3")
        self.assertEqual(weak.artifact(source)["sha256"], expected)
        self.evidence.watch_source(source)
        normalized = self.directory/"original-musl-init-tls.native.json"
        result = self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", "x86_64-unknown-none",
                               "--emit", "mir", "-o", normalized, *self.llvm_flags], success=False)
        diagnostic = result.stderr.decode(errors="replace")
        self.assertNotEqual(result.returncode, 0, "whole TLS has additional real unsupported metadata/asm contracts")
        self.assertNotIn("unsupported linkage 12", diagnostic)
        self.assertNotIn("unsupported attribute kind 75", diagnostic)
        self.assertIn("unsupported metadata kind 47", diagnostic)
        self.assertFalse(normalized.exists(), "an unsupported original unit cannot become a partial artifact")
        (self.directory/"original-musl-tls-progression.json").write_text(json.dumps({
            "scope": "whole unchanged original musl TLS diagnostic progression, not source admission",
            "input": weak.artifact(source), "compiler": weak.artifact(self.compiler), "whole_unit_imported": False,
            "old_linkage_blocker_removed": True, "remaining_diagnostic": diagnostic, "provenance": self.evidence.finish()}, indent=2)+"\n")


class ExternWeakCaptureTests(ExternWeakNativeTests):
    capture_closure_gate = True
    test_real_undefined_weak_objects_and_final_link_resolution_all_three_isas = None
    test_whole_original_musl_tls_unit_progresses_without_partial_import = None

    def test_captured_optional_dependencies_and_detached_module_set_keep_real_link_resolution(self):
        isa = host_isa(); target = TARGETS[isa][0]
        olangc = Path(os.environ.get("OLANGC", str(weak.ROOT/"target/debug/olangc"))).resolve()
        git = weak.capture_closure_prerequisites(olangc, self.sdk)
        for name, path in {"olangc": olangc, "git": git, "python": sys.executable, "clang++": self.sdk/"clang++"}.items():
            self.evidence.watch_tool(name, path)
        cases = []
        for scenario in ("absent", "weak", "weak-strong", "strong-weak", "strong-missing", "function-mismatch", "global-mismatch"):
            root = self.directory/scenario; source = root/"source"; source.mkdir(parents=True)
            # A complete fixture project, captured through its original build.
            # No LLVM body is selected, removed or rewritten by admission.
            weak_attribute = "" if scenario == "strong-missing" else "__attribute__((weak)) "
            (source/"consumer.c").write_text(f"extern {weak_attribute}unsigned long long optional_function(unsigned long long);\n"
                f"extern {weak_attribute}unsigned long long optional_global;\n"
                "unsigned long long probe(unsigned long long x){return (optional_function?optional_function(x):9)+(&optional_global?optional_global:7);}\n")
            names = ["consumer.c"]
            for tag, marker in (("weak", 11), ("strong", 53)):
                if tag not in scenario.split("-") and not (tag == "strong" and scenario.endswith("mismatch")):
                    continue
                if scenario == "strong-missing":
                    continue
                prefix = "__attribute__((weak)) " if tag == "weak" else ""
                function_type = "unsigned int" if scenario == "function-mismatch" else "unsigned long long"
                global_type = "unsigned int" if scenario == "global-mismatch" else "unsigned long long"
                (source/(tag+".c")).write_text(f"{prefix}{function_type} optional_function({function_type} x){{return x+{marker+5};}}\n"
                                                    f"{prefix}{global_type} optional_global={marker};\n")
                names.append(tag+".c")
            if scenario == "strong-weak":
                names = ["consumer.c", "strong.c", "weak.c"]
            # A relocatable final link preserves intentionally unresolved strong
            # references in its reference output; O-core must still reject them.
            (source/"build.py").write_text("""import json,os,pathlib,subprocess,sys
source=pathlib.Path(sys.argv[1]);names=json.loads(sys.argv[2]);flags=json.loads(sys.argv[3]);cc=os.environ['CC']
for name in names: subprocess.run([cc,*flags,'-c',str(source/name),'-o',name+'.o'],check=True)
subprocess.run([cc,*[name+'.o' for name in names],'-nostdlib','-r','-o','combined.o'],check=True)
pathlib.Path('inventory.json').write_text(json.dumps({'schema':'ocore-runtime-unit-inventory-v1','complete':True,'units':[{'id':n,'kind':'clang','source':n,'role':'runtime','build_step':'runtime-build'} for n in names]}))
""")
            for path in source.iterdir(): self.evidence.watch_source(path)
            for argv in ((git,"init","-q"),(git,"add","."),(git,"-c","user.name=Extern Weak Test","-c","user.email=test@example.invalid","commit","-qm","complete regression source")):
                self.command(argv, cwd=source)
            revision = self.command([git,"rev-parse","HEAD"], cwd=source).stdout.decode().strip()
            recipe = {"schema":"ocore-runtime-recipe-v1","name":"extern-weak-"+scenario,
                      "source":{"url":"local-pinned-extern-weak-regression","revision":revision},"toolchain":{"llvm_version":"22.1.6"},
                      "commands":[{"name":"runtime-build","argv":[sys.executable,"{source}/build.py","{source}",json.dumps(names),json.dumps(capture_qa.FLAGS)]}],
                      "coverage":{"required_units":[{"id":n,"kind":"clang","source":n,"role":"runtime"} for n in names],
                                  "required_outputs":["combined.o"],"require_full_unit_inventory":True}}
            recipe_path = root/"recipe.json"; recipe_path.write_text(json.dumps(recipe)); self.evidence.watch_source(recipe_path)
            build, capture, output = [root/n for n in ("build","capture","lowered")]
            self.command([sys.executable,weak.ROOT/"scripts/ocore_runtime_capture.py","capture",recipe_path,"--source",source,
                          "--build",build,"--output",capture,"--unit-inventory",build/"inventory.json",
                          "--cc",self.sdk/"clang","--cxx",self.sdk/"clang++","--llvm-nm",self.sdk/"llvm-nm"])
            self.assertTrue(json.loads((capture/"report.json").read_text())["capture_complete"])
            result = self.command([olangc,capture/"report.json","--native-runtime","--native-isa",target,
                                   "--native-runtime-output","obj","-o",output,*self.llvm_flags], success=False)
            receipt = json.loads((output/"coverage.json").read_text())
            admitted = scenario in {"absent", "weak", "weak-strong", "strong-weak"}
            self.assertEqual(receipt["unit_lowering_complete"], True, receipt.get("issues"))
            self.assertEqual(receipt["symbol_closure_complete"], admitted, receipt.get("issues"))
            self.assertEqual(result.returncode == 0, admitted, result.stderr.decode())
            if admitted:
                module_set = Path(receipt["module_set_artifact"]["path"])
                inventory = json.loads(module_set.read_text())["symbol_inventory"]
                declarations = [d for d in inventory["declarations"] if d.get("linkage") == "extern_weak"]
                self.assertEqual(len(declarations), 2)
                self.assertTrue(all(d["optional_weak"] == (scenario == "absent") for d in declarations))
                if scenario == "absent":
                    self.assertTrue(all(d["resolved_unit"] is None for d in declarations))
                detached = root/"detached.native-set.json"; shutil.copyfile(module_set, detached)
                reemitted = root/"reemitted"
                self.command([olangc,detached,"--native-runtime","--native-isa",target,"--native-runtime-output","obj","-o",reemitted])
                # Test the real final-link semantics after module-set reload.
                harness = root/"harness.c"
                expected = 16 if scenario == "absent" else 80 if "strong" not in scenario else 164
                harness.write_text(f"extern unsigned long long probe(unsigned long long); int main(void){{return probe(53)!={expected};}}\n")
                self.evidence.watch_source(harness)
                executable = root/"own-executable"
                self.command([self.sdk/"clang",*reemitted.glob("unit-*/module.o"),harness,"--ld-path="+self.linker,"-no-pie","-o",executable])
                self.command([executable])
            else:
                self.assertRegex(json.dumps(receipt.get("issues")), "unresolved|incompatible")
            cases.append({"scenario":scenario,"receipt":weak.artifact(output/"coverage.json"),"admitted":admitted})
        (self.directory/"extern-weak-capture.json").write_text(json.dumps({"scope":"complete regression-project capture/typed closure/ELF link",
            "runtime_complete":False,"cases":cases,"provenance":self.evidence.finish()},indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
