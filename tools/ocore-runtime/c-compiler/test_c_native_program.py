"""Run real C through Clang IR and O-core; this is not chibicc lowering proof."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = """static __attribute__((noinline)) void increment(long *value) { *value += 1; }
long c_program(long input) {
  long value = input;
  for (long i = 0; i < 3; ++i) increment(&value);
  return value - 2;
}
"""
PROFILES = {
    "x86_64": ("x86_64-unknown-linux-gnu", "x86_64-unknown-none", "elf_x86_64", 62,
               "mov $41,%rdi; call c_program; cmp $42,%rax; jne .Lbad\n"
               "mov $-3,%rdi; call c_program; cmp $-2,%rax; jne .Lbad\n"
               "xor %edi,%edi; jmp .Lexit\n.Lbad: mov $77,%edi\n"
               ".Lexit: mov $60,%eax; syscall\n"),
    "aarch64": ("aarch64-unknown-linux-gnu", "aarch64-unknown-none", "aarch64elf", 183,
                "mov x0,#41; bl c_program; cmp x0,#42; b.ne .Lbad\n"
                "mov x0,#-3; bl c_program; mov x9,#-2; cmp x0,x9; b.ne .Lbad\n"
                "mov x0,#0; b .Lexit\n.Lbad: mov x0,#77\n"
                ".Lexit: mov x8,#93; svc #0\n"),
    "riscv64": ("riscv64-unknown-linux-gnu", "riscv64-unknown-none", "elf64lriscv", 243,
                "li a0,41; call c_program; li t0,42; bne a0,t0,.Lbad\n"
                "li a0,-3; call c_program; li t0,-2; bne a0,t0,.Lbad\n"
                "li a0,0; j .Lexit\n.Lbad: li a0,77\n"
                ".Lexit: li a7,93; ecall\n"),
}


def artifact(path):
    data = Path(path).read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


@unittest.skipUnless(os.environ.get("OCORE_TEST_C_NATIVE") == "1",
                     "set OCORE_TEST_C_NATIVE=1 with the exact LLVM22 toolchain")
class CProgramNativeTests(unittest.TestCase):
    def test_original_c_program_uses_owned_object_and_executes_on_host(self):
        self.assertEqual(platform.system(), "Linux")
        profile = PROFILES.get(platform.machine())
        self.assertIsNotNone(profile, "this gate requires one supported Linux host ISA")
        linux, target, emulation, machine, body = profile
        binary_directory = Path(os.environ["OCORE_TEST_LLVM22_BIN"]).resolve()
        clang = binary_directory / "clang"
        library = Path(os.environ["OCORE_TEST_LLVM_LIBRARY"]).resolve()
        library_sha = os.environ["OCORE_TEST_LLVM_SHA256"]
        self.assertEqual(artifact(library)["sha256"], library_sha)
        compiler = Path(os.environ.get("OCOREC", "/home/orangepi/.local/bin/ocorec")).resolve()
        linker_path = os.environ.get("OCORE_TEST_LLD") or shutil.which("ld.lld")
        self.assertTrue(linker_path, "an actual ELF linker is required")
        # Preserve argv0: ld.lld may be a symlink to the generic lld driver.
        linker = Path(linker_path).absolute()
        retained = os.environ.get("OCORE_C_NATIVE_OUTPUT")
        if retained:
            directory = Path(tempfile.mkdtemp(prefix="c-program-", dir=Path(retained).resolve()))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-c-program-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name)
        environment = dict(os.environ)
        environment["PATH"] = str(binary_directory) + os.pathsep + environment.get("PATH", "")
        commands = []

        def run(argv):
            result = subprocess.run([str(x) for x in argv], cwd=directory, env=environment,
                                    capture_output=True, text=True, timeout=180)
            commands.append({"argv": [str(x) for x in argv], "exit_code": result.returncode,
                             "stdout": result.stdout, "stderr": result.stderr})
            self.assertEqual(result.returncode, 0, result.stderr)
            return result

        version = run([clang, "--version"]).stdout
        self.assertRegex(version, r"clang version 22\.1\.6(?:\s|$)")
        source = directory / "program.c"
        source.write_text(SOURCE)
        source_artifact = artifact(source)
        ir, reference = directory / "program.ll", directory / "reference.o"
        flags = ["--target=" + linux, "-O1", "-ffreestanding", "-fno-builtin", "-fno-stack-protector"]
        run([clang, *flags, "-S", "-emit-llvm", source, "-o", ir])
        run([clang, *flags, "-c", source, "-o", reference])
        owned, sidecar = directory / "owned.o", directory / "owned.map.json"
        run([compiler, ir, "--input-kind", "llvm-ir", "--emit", "obj", "--keep-asm",
             "--target", target, "--llvm-library", library, "--llvm-sha256", library_sha,
             "--native-map", sidecar, "-o", owned])
        assembly = owned.with_suffix(".s")
        record = json.loads(sidecar.read_text())
        self.assertEqual(record["assembly"]["input_sha256"], artifact(ir)["sha256"])
        self.assertEqual(record["artifact_sha256"], artifact(owned)["sha256"])
        self.assertEqual(int.from_bytes(owned.read_bytes()[18:20], "little"), machine)
        run([compiler, "--target", target, "--verify-native-map", sidecar,
             "--map-assembly", assembly, "--map-artifact", owned])
        start = directory / "start.s"
        start.write_text(".text\n.globl _start\n_start:\n" + body)
        start_object = directory / "start.o"
        run([clang, "--target=" + linux, "-c", start, "-o", start_object])
        executables = []
        for label, obj in (("reference", reference), ("owned", owned)):
            executable = directory / (label + ".elf")
            run([linker, "-m", emulation, "-e", "_start", "-o", executable, start_object, obj])
            run([executable])
            executables.append(artifact(executable))
        self.assertEqual(artifact(source), source_artifact)
        receipt = {"schema": "ocore-c-program-native-gate-v1", "success": True,
                   "source": source_artifact, "llvm_ir": artifact(ir), "target": target,
                   "compiler": artifact(compiler), "frontend": artifact(clang),
                   "llvm_library": artifact(library), "linker": artifact(linker),
                   "owned_object": artifact(owned), "owned_assembly": artifact(assembly),
                   "native_map": artifact(sidecar), "executables": executables,
                   "cases": [{"input": 41, "expected": 42}, {"input": -3, "expected": -2}],
                   "commands": commands, "original_chibicc_lowered": False,
                   "ostadix_kernel_execution_qualified": False, "runtime_complete": False}
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"c_program_native_receipt": str(directory / "receipt.json")}))


if __name__ == "__main__":
    unittest.main()
