"""Qualify integer-only strictfp while keeping real FP execution fail closed.

These are capability-boundary tests, not evidence of floating-point lowering.
The original musl vfprintf unit requires both strictfp and constrained f80
operations with dynamic rounding; stripping an attribute cannot qualify it.
"""
import hashlib
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory
from tests import test_ocore_native_weak as weak
from scripts.check_ocore_native_equivalence import TARGETS, execution_prefix


INTEGER_BODY = '''
declare i64 @read_environment()
declare void @write_environment(i64)
define i64 @integer_only(i64 %value) strictfp {
  %a = mul i64 %value, 17
  %b = xor i64 %a, 42
  ret i64 %b
}
define i64 @ordered_effects(i64 %value, i64 %environment) strictfp {
  call void @write_environment(i64 %environment) strictfp
  %actual = call i64 @read_environment() strictfp
  %integer = call i64 @integer_only(i64 %value) strictfp
  %r = xor i64 %actual, %integer
  ret i64 %r
}
'''


def carrier():
    prefix = weak.carrier(11).split("extern u64 chosen_global", 1)[0]
    return prefix + r'''
#if defined(__x86_64__)
u64 read_environment(void) {
 unsigned short cw,sw; unsigned int mx;
 __asm__ volatile("fnstcw %0":"=m"(cw));
 __asm__ volatile("fnstsw %0":"=m"(sw));
 __asm__ volatile("stmxcsr %0":"=m"(mx));
 return cw|((u64)sw<<16)|((u64)mx<<32);
}
void write_environment(u64 state) {
 unsigned short cw=state; unsigned int mx=state>>32;
 __asm__ volatile("fldcw %0"::"m"(cw));
 __asm__ volatile("ldmxcsr %0"::"m"(mx));
}
static u64 environment_case(u64 original,u64 mode,u64 flags) {
 return (original & ~((3ULL<<10)|(3ULL<<45)|(63ULL<<32)))
        |(mode<<10)|(mode<<45)|(flags<<32);
}
#elif defined(__aarch64__)
u64 read_environment(void) {
 u64 control,status;
 __asm__ volatile("mrs %0,fpcr":"=r"(control));
 __asm__ volatile("mrs %0,fpsr":"=r"(status));
 return control|(status<<32);
}
void write_environment(u64 state) {
 u64 control=(unsigned int)state,status=state>>32;
 __asm__ volatile("msr fpcr,%0"::"r"(control));
 __asm__ volatile("msr fpsr,%0"::"r"(status));
}
static u64 environment_case(u64 original,u64 mode,u64 flags) {
 return (original & ~((3ULL<<22)|(31ULL<<32)))|(mode<<22)|((flags&31)<<32);
}
#else
u64 read_environment(void) {
 u64 state; __asm__ volatile("csrr %0,fcsr":"=r"(state)); return state;
}
void write_environment(u64 state) { __asm__ volatile("csrw fcsr,%0"::"r"(state)); }
static u64 environment_case(u64 original,u64 mode,u64 flags) {
 return (original & ~255ULL)|(mode<<5)|(flags&31);
}
#endif
extern u64 integer_only(u64),ordered_effects(u64,u64);
int conformance_main(void) {
 const u64 original=read_environment();
 const u64 flags[]={0,1,2,4,8,16,31};
 const u64 inputs[]={0,1,42,0xffffffffULL,0x8000000000000000ULL,~0ULL};
 for(u64 mode=0;mode<4;mode++)for(u64 flag=0;flag<7;flag++) {
  const u64 state=environment_case(original,mode,flags[flag]);
  write_environment(state);
  if(read_environment()!=state)return 30;
  for(u64 i=0;i<6;i++) {
   const u64 expected=(inputs[i]*17)^42;
   if(integer_only(inputs[i])!=expected)return 31;
   if(read_environment()!=state)return 32;
   // The next call must preserve the original provider's state transition
   // and read it back before the ordinary integer calculation.
   write_environment(original);
   if(ordered_effects(inputs[i],state)!=(expected^state))return 33;
   if(read_environment()!=state)return 34;
  }
 }
 write_environment(original);
 static const char message[]="OCORE-STRICTFP-INTEGER PASS\n";
#if defined(__x86_64__)
 syscall3(1,1,(u64)message,sizeof(message)-1);
#else
 syscall3(64,1,(u64)message,sizeof(message)-1);
#endif
 return 0;
}
#if defined(__x86_64__)
__asm__(".global _start\n_start:\nxor %rbp,%rbp\nand $-16,%rsp\ncall conformance_main\nmov %eax,%edi\nmov $60,%eax\nsyscall\nud2\n");
#elif defined(__aarch64__)
__asm__(".global _start\n_start:\nbl conformance_main\nmov x8,#93\nsvc #0\nbrk #0\n");
#else
__asm__(".global _start\n_start:\ncall conformance_main\nli a7,93\necall\nebreak\n");
#endif
'''


class StrictFloatingPointTests(unittest.TestCase):
    setUpClass = classmethod(baseline.LlvmImportTests.setUpClass.__func__)
    write = baseline.LlvmImportTests.write

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_STRICT_FP_OUTPUT_DIR")
        if retained:
            Path(retained).mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=retained))
            self.source = self.directory / "input.ll"
        else:
            baseline.LlvmImportTests.setUp(self)

    def assert_rejected_text_and_bitcode(self, body, fragments, *, text_only=False):
        for triple in baseline.TRIPLES:
            source = self.write(body, triple=triple)
            paths = (source,) if text_only else (
                source, memory.LlvmMemoryImportTests.bitcode(self, source))
            for path in paths:
                with self.subTest(triple=triple, format=path.suffix):
                    with self.assertRaises(importer.ImportFailure) as raised:
                        importer.import_module(path, library_path=self.library,
                                               expected_sha256=self.library_sha256)
                    self.assertEqual(raised.exception.stage, "import")
                    for fragment in fragments:
                        self.assertIn(fragment, str(raised.exception))

    def test_strictfp_integer_profile_preserves_calls_and_provenance(self):
        for triple in baseline.TRIPLES:
            source = self.write(INTEGER_BODY, triple=triple)
            binary = memory.LlvmMemoryImportTests.bitcode(self, source)
            for path in (source, binary):
                module = importer.import_module(path, library_path=self.library,
                                                expected_sha256=self.library_sha256)
                notes = module["provenance"]["refinements"]
                self.assertTrue(any("strictfp-integer-v1 function" in n for n in notes))
                self.assertTrue(any("strictfp-integer-v1 callsite" in n for n in notes))
                self.assertEqual(module["provenance"]["input_sha256"],
                                 hashlib.sha256(path.read_bytes()).hexdigest())
                function = next(fn for fn in module["functions"] if fn["name"] == "ordered_effects")
                calls = [item["operation"]["callee"]["name"]
                         for block in function["blocks"] for item in block["instructions"]
                         if item["operation"]["op"] == "call"]
                self.assertEqual(calls, ["write_environment", "read_environment", "integer_only"])

    def test_real_fp_cannot_enter_through_a_strict_integer_result(self):
        self.assert_rejected_text_and_bitcode('''
define i32 @not_integer_only(ptr %value) strictfp {
  %x = load double, ptr %value
  %r = fptosi double %x to i32
  ret i32 %r
}
''', ("unsupported LLVM type",))

    def test_constrained_dynamic_rounding_remains_explicit_unsupported(self):
        self.assert_rejected_text_and_bitcode('''
declare double @llvm.experimental.constrained.fadd.f64(double, double, metadata, metadata)
define double @add(double %x, double %y) strictfp {
  %r = call double @llvm.experimental.constrained.fadd.f64(double %x, double %y,
    metadata !"round.dynamic", metadata !"fpexcept.strict") strictfp
  ret double %r
}
''', ("constrained floating-point intrinsic", "rounding-mode", "exception-behavior"))

    def test_existing_integer_admission_and_source_identity_are_preserved(self):
        for triple in baseline.TRIPLES:
            source = self.write('''
define i32 @integer_only(i32 %value) nounwind {
  %r = add i32 %value, 1
  ret i32 %r
}
''', triple=triple)
            module = importer.import_module(source, library_path=self.library,
                                            expected_sha256=self.library_sha256)
            self.assertEqual(module["provenance"]["input_sha256"],
                             hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(module["functions"][0]["name"], "integer_only")

    def test_profile_does_not_silently_expand_to_new_operations(self):
        source = self.write(INTEGER_BODY)
        module = importer.import_module(source, library_path=self.library,
                                        expected_sha256=self.library_sha256)
        fake = object.__new__(importer.Importer)
        fake.types = module["types"]
        altered = copy.deepcopy(module["functions"])
        operation = altered[-1]["blocks"][0]["instructions"][0]["operation"]
        operation["op"] = "future_floating_operation"
        with self.assertRaisesRegex(importer.ImportFailure, "no audited environment-preserving realization"):
            fake.audit_strict_fp_integer_operations(altered)

    def test_native_and_original_preserve_control_status_and_provider_effects(self):
        compiler = Path(os.environ.get("OCOREC", str(baseline.ROOT / "target/debug/ocorec")))
        sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(weak.SDK)))
        linker = shutil.which("ld.lld")
        if not compiler.is_file() or not (sdk / "clang").is_file() or not linker:
            self.skipTest("built compiler, LLVM22 SDK and ld.lld required")
        harness = self.directory / "carrier.c"
        harness.write_text(carrier())
        records = []
        def run(command):
            result = subprocess.run(list(map(str, command)), capture_output=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            return result
        for isa, (target, triple, _, flags) in TARGETS.items():
            try:
                prefix = execution_prefix(isa, os.environ.get("OCORE_TEST_QEMU_" + isa.upper()))
            except RuntimeError:
                if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                    raise
                continue
            source = self.write(INTEGER_BODY, triple=triple)
            module = importer.import_module(source, library_path=self.library,
                                            expected_sha256=self.library_sha256)
            imported = self.directory / f"{isa}.json"
            imported.write_text(json.dumps(module))
            native, reference, host = [self.directory / f"{isa}-{name}.o"
                                       for name in ("native", "reference", "carrier")]
            run([compiler, imported, "--input-kind", "native-ir", "--emit", "obj",
                 "--target", target, "-o", native])
            options = ["--target=" + triple, *flags, "-O1", "-ffreestanding", "-fno-builtin",
                       "-fno-pic", "-fno-pie", "-fno-stack-protector", "-fno-unwind-tables",
                       "-fno-asynchronous-unwind-tables"]
            run([sdk / "clang", *options, "-c", source, "-o", reference])
            run([sdk / "clang", *options, "-c", harness, "-o", host])
            for kind, obj in (("native", native), ("reference", reference)):
                executable = self.directory / f"{isa}-{kind}"
                run([linker, "-static", "--build-id=none", "-e", "_start", host, obj, "-o", executable])
                result = run([*prefix, executable])
                self.assertEqual(result.stdout, b"OCORE-STRICTFP-INTEGER PASS\n")
                records.append({"isa": isa, "kind": kind, "exit_code": result.returncode,
                                "stdout": result.stdout.decode(), "executable": str(executable)})
        self.assertTrue(any(r["isa"] == "x86_64" for r in records))
        (self.directory / "execution.json").write_text(json.dumps({"ok": True,
            "scope": "integer/pointer-only strictfp; actual calls preserve provider effects; no FP arithmetic qualification",
            "rounding_modes": 4, "exception_flag_patterns": 7, "integer_inputs": 6,
            "records": records}, indent=2) + "\n")


if __name__ == "__main__":
    unittest.main()
