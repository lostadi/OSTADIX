"""Original LLVM trap semantics against all own ISA objects on Linux carriers.

Fault signals are compared to the original Clang executable separately for
each ISA. Numeric signal equality across ISAs, complete foreign runtimes and
native OSTADIX exception handling are not claimed.
"""

import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import tempfile
import unittest

from scripts.check_ocore_native_equivalence import TARGETS, elf
from tests import test_ocore_native_alias as alias_qa
from tests import test_ocore_native_weak as weak


ROOT, MASK = weak.ROOT, weak.MASK
BODY = """
declare void @llvm.trap()
declare void @post_trap_marker()
define i64 @trap_unconditional() {
  call void @llvm.trap()
  call void @post_trap_marker()
  ret i64 73
}
define i64 @conditional_trap(i64 %value) {
entry:
  %condition = icmp eq i64 %value, 13
  br i1 %condition, label %fatal, label %safe
fatal:
  call void @llvm.trap()
  call void @post_trap_marker()
  ret i64 99
safe:
  %result = add i64 %value, 17
  ret i64 %result
}
define i64 @nested_trap(i64 %value) {
  %result = call i64 @conditional_trap(i64 %value)
  %next = add i64 %result, 2
  ret i64 %next
}
define i64 @cold_only() cold {
  call void @llvm.trap()
  call void @post_trap_marker()
  ret i64 91
}
define i64 @nested_unconditional() {
  %result = call i64 @trap_unconditional()
  ret i64 %result
}
define i64 @safe_with_dead() {
entry:
  ret i64 41
dead:
  call void @llvm.trap()
  call void @post_trap_marker()
  ret i64 67
}
define i64 @safe_anchor() { ret i64 1337 }
"""
FAULT_MODES = ("unconditional", "conditional", "nested", "cold", "nested-unconditional")


def golden():
    values = [41, 1337]
    for value in weak.inputs():
        value = 14 if value == 13 else value
        values += [(value + 17) & MASK, (value + 19) & MASK]
    digest = 0xCBF29CE484222325
    for value in values:
        digest = ((digest ^ value) * 0x100000001B3) & MASK
    return f"OCORE-TRAP-SAFE digest={digest:016x} checks={len(values)}\n".encode()


def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    text += "extern u64 trap_unconditional(void),conditional_trap(u64),nested_trap(u64),cold_only(void),nested_unconditional(void),safe_with_dead(void),safe_anchor(void);\n"
    text += r"""
static long write_stdout(const char *data,u64 size){
#if defined(__x86_64__)
 return syscall3(1,1,(u64)data,size);
#else
 return syscall3(64,1,(u64)data,size);
#endif
}
void post_trap_marker(void){static const char text[]="POST-TRAP-REACHED\n";write_stdout(text,sizeof(text)-1);}
static u64 digest=0xcbf29ce484222325ULL,checks;
static int add(u64 got,u64 expected){
#ifdef CORRUPT_ORACLE
 expected^=1;
#endif
 if(got!=expected)return 31;
 digest=(digest^got)*0x100000001b3ULL;++checks;return 0;
}
int conformance_main(void){
#if TRAP_CASE==1
 (void)trap_unconditional();
#elif TRAP_CASE==2
 (void)conditional_trap(13);
#elif TRAP_CASE==3
 (void)nested_trap(13);
#elif TRAP_CASE==4
 (void)cold_only();
#elif TRAP_CASE==5
 (void)nested_unconditional();
#else
 if(add(safe_with_dead(),41)||add(safe_anchor(),1337))return 31;
 for(u64 i=0;i<sizeof(values)/sizeof(values[0]);++i){u64 x=values[i];if(x==13)x=14;
  if(add(conditional_trap(x),x+17)||add(nested_trap(x),x+19))return 31;
 }
"""
    count = int(golden().decode().split("checks=")[1])
    text += f"if(checks!={count})return 37;\n"
    output = golden().decode().rstrip()
    start = output.index("digest=") + len("digest=")
    text += 'static char output[]="' + output[:start] + "0" * 16 + output[start+16:] + '\\n";\n'
    text += f"for(u64 i=0;i<16;++i){{u64 n=(digest>>(60-4*i))&15;output[{start}+i]=(char)(n<10?'0'+n:'a'+n-10);}}\n"
    text += r"""
 if(write_stdout(output,sizeof(output)-1)!=sizeof(output)-1)return 99;
 return 0;
#endif
 /* A trap returning normally is a failing observation, even if the marker
    call was optimized away by the reference compiler. */
 return 88;
}
#if defined(__x86_64__)
__asm__""" + reusable.split('#if defined(__x86_64__)\n__asm__', 1)[1]
    return text


def disable_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class TrapNativeTests(alias_qa.AliasNativeTests):
    test_actual_alias_identity_and_independent_strong_overrides_match_original_clang_all_three = None

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_TRAP_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-trap-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.compiler_sha = weak.artifact(self.compiler)["sha256"]
        self.sequence = 0

    def execute(self, argv):
        """Retain actual child fault status while suppressing core files."""
        argv = [str(value) for value in argv]
        result = subprocess.run(argv, cwd=self.directory, capture_output=True, timeout=120,
                                preexec_fn=disable_core_dumps)
        log = self.directory / (f"command-{self.sequence:04d}.json")
        log.write_text(json.dumps({"argv": argv, "cwd": str(self.directory), "exit_code": result.returncode,
            "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace")}, indent=2) + "\n")
        self.sequence += 1
        return result

    def test_actual_safe_paths_and_fatal_traps_match_original_clang_per_target_all_three(self):
        emulators = {isa: shutil.which(os.environ.get("OCORE_TEST_QEMU_" + isa.upper(), "qemu-" + isa))
                     for isa in ("aarch64", "riscv64")}
        if platform.machine() not in {"x86_64", "AMD64"} or not all(emulators.values()):
            if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                self.fail("all-three execution requires x86 host and both QEMU user emulators")
            self.skipTest("all-three execution tools unavailable")
        report = {"scope": "LLVM trap compiler conformance on Linux carriers; target-local original fault status",
                  "runtime_complete": False, "kernel_execution_verified": False, "dependency_closure_complete": False,
                  "cross_isa_numeric_signal_equivalence_claimed": False, "compiler_sha256": self.compiler_sha,
                  "test_source": weak.artifact(__file__), "tools": {name: weak.artifact(path) for name, path in {
                      "ocorec": self.compiler, "reference_clang": self.sdk / "clang", "own_assembler": self.assembler,
                      "llvm-as": self.sdk / "llvm-as", "linker": self.linker, **emulators}.items()}, "targets": {}}
        for isa, (target, triple, machine, flags) in TARGETS.items():
            units, executions = [], []
            harness = self.directory / (isa + "-carrier.c")
            harness.write_text(carrier())
            for source in self.inputs(isa, triple, BODY):
                original = source.read_bytes()
                normalized = source.with_name(source.name + ".native.json")
                receipt = source.with_name(source.name + ".verification.json")
                own, reference = source.with_name(source.name + ".own.o"), source.with_name(source.name + ".clang.o")
                self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "--emit", "mir", "-o", normalized])
                self.command([self.compiler, normalized, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
                self.assertEqual(json.loads(receipt.read_text())["module_sha256"], weak.artifact(normalized)["sha256"])
                self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", own])
                self.command([self.sdk / "clang", "--target=" + triple, *flags, "-fno-pic", "-fno-pie", "-O0", "-c", source, "-o", reference])
                self.assertEqual(source.read_bytes(), original)
                module = json.loads(normalized.read_text())
                self.assertEqual(module["provenance"]["source_function_count"], 9)
                self.assertEqual(len(module["functions"]), 9)
                self.assertEqual(module["globals"], [])
                functions = {item["name"]: item for item in module["functions"]}
                trap = functions["llvm.trap"]
                self.assertEqual(trap["intrinsic"], "llvm.trap")
                self.assertIsNone(trap["entry"])
                self.assertEqual(len(functions["safe_with_dead"]["blocks"]), 2, "source dead block retained in the complete verified module")
                for name in ("trap_unconditional", "conditional_trap", "cold_only", "safe_with_dead"):
                    blocks = functions[name]["blocks"]
                    operations = [instruction["operation"] for block in blocks for instruction in block["instructions"]]
                    trap_index = next(index for index, operation in enumerate(operations) if operation["op"] == "trap")
                    self.assertEqual(operations[trap_index + 1]["op"], "call", "post-trap source continuation is retained")
                    self.assertEqual(operations[trap_index + 1]["callee"]["name"], "post_trap_marker")
                for obj in (own, reference):
                    elf(obj, machine, 1)
                    symbols = weak.elf_symbols(obj)
                    for name in ("cold_only", "trap_unconditional", "conditional_trap", "nested_trap", "safe_with_dead"):
                        self.assertGreater(symbols[name]["size"], 0, "unused/trapping source function has real emitted bytes")
                units.append({"input": weak.artifact(source), "module": weak.artifact(normalized), "verification": weak.artifact(receipt),
                              "own_object": weak.artifact(own), "original_clang_object": weak.artifact(reference)})
                observed = {}
                for implementation, obj in (("own", own), ("original_clang", reference)):
                    for mode, label in enumerate(("safe", *FAULT_MODES)):
                        output = source.with_name(source.name + "." + implementation + "." + label)
                        argv = [self.sdk / "clang", "--target=" + triple, *flags, "--ld-path=" + self.linker, "-O1",
                                "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-fno-pie",
                                "-nostdlib", "-static", "-Wl,--no-relax", "-Wl,-e,_start", "-DTRAP_CASE=" + str(mode), harness, obj, "-o", output]
                        self.command(argv)
                        command = [output] if isa == "x86_64" else [emulators[isa], output]
                        result = self.execute(command)
                        observed[implementation, label] = result.returncode
                        if mode == 0:
                            self.assertEqual(result.returncode, 0)
                            self.assertEqual(result.stdout, golden())
                        else:
                            self.assertLess(result.returncode, 0, (isa, implementation, label, result.stdout, result.stderr))
                            self.assertEqual(result.stdout, b"", "post-trap continuation must never execute")
                        executions.append({"input_kind": source.suffix, "mode": label, "implementation": implementation,
                                           "executable": weak.artifact(output), "stdout": result.stdout.decode(errors="replace"),
                                           "stderr": result.stderr.decode(errors="replace"), "exit_code": result.returncode,
                                           "fatal_signal": -result.returncode if result.returncode < 0 else None})
                        if implementation == "own" and mode == 0:
                            corrupt = output.with_name(output.name + ".corrupt")
                            self.command([*argv[:-2], "-DCORRUPT_ORACLE", "-o", corrupt])
                            failed = self.execute([corrupt] if isa == "x86_64" else [emulators[isa], corrupt])
                            self.assertEqual(failed.returncode, 31)
                            self.assertEqual(failed.stdout, b"")
                            executions.append({"input_kind": source.suffix, "corrupt_oracle": True,
                                               "executable": weak.artifact(corrupt), "exit_code": 31})
                for mode in FAULT_MODES:
                    self.assertEqual(observed["own", mode], observed["original_clang", mode], (isa, source.suffix, mode))
            report["targets"][isa] = {"modules": units, "executions": executions}
        self.assertEqual(weak.artifact(self.compiler)["sha256"], self.compiler_sha)
        (self.directory / "trap-conformance.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
