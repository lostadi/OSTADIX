"""Original LLVM funnel shifts through O-core, with an integer oracle.

The freestanding Linux carriers only report results. Every scalar width 1..64
is exercised on x86-64, AArch64 and RV64 when their execution tools are present.
This does not establish a complete runtime or kernel compilation profile.
"""
import copy
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS, execution_prefix
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_native_weak as weak

ROOT = Path(__file__).resolve().parents[1]


def oracle(kind, width, a, b, count):
    mask = (1 << width) - 1
    shift = (count & mask) % width
    combined = ((a & mask) << width) | (b & mask)
    return ((combined << shift) >> width if kind == "fshl" else combined >> shift) & mask


def cases(width):
    mask = (1 << width) - 1
    values = (0, 1, mask, mask ^ 1, 1 << (width - 1), 0x123456789abcdef0)
    counts = (0, 1, width - 1, width, width + 1, 2 * width - 1, mask, (1 << 64) - 1)
    rows = [(a, b, count) for a in values for b in values for count in counts]
    rng = random.Random(0xf5a100 + width)
    rows += [tuple(rng.getrandbits(64) for _ in range(3)) for _ in range(32)]
    return list(dict.fromkeys(rows))


def body():
    result = []
    for width in range(1, 65):
        for kind in ("fshl", "fshr"):
            ty = f"i{width}"
            result += [f"declare {ty} @llvm.{kind}.{ty}({ty}, {ty}, {ty})",
                       f"define i64 @{kind}_{width}(i64 %a, i64 %b, i64 %count) {{"]
            if width == 64:
                result += [f"%r = call i64 @llvm.{kind}.i64(i64 %a, i64 %b, i64 %count)", "ret i64 %r", "}"]
            else:
                result += [f"%x = trunc i64 %a to {ty}", f"%y = trunc i64 %b to {ty}",
                           f"%n = trunc i64 %count to {ty}",
                           f"%r = call {ty} @llvm.{kind}.{ty}({ty} %x, {ty} %y, {ty} %n)",
                           f"%wide = zext {ty} %r to i64", "ret i64 %wide", "}"]
    return "\n".join(result) + "\n"


def carrier():
    reusable = weak.carrier(11)
    text = reusable[:reusable.index("extern u64 chosen_global")]
    names = [f"{kind}_{width}" for width in range(1, 65) for kind in ("fshl", "fshr")]
    text += "".join(f"extern u64 {name}(u64,u64,u64);\n" for name in names)
    text += "static u64 (*const functions[])(u64,u64,u64)={" + ",".join(names) + "};\n"
    rows = []
    for width in range(1, 65):
        for a, b, count in cases(width):
            rows.append([(width - 1) * 2, a, b, count, oracle("fshl", width, a, b, count),
                         oracle("fshr", width, a, b, count)])
    text += "static const u64 rows[][6]={" + ",\n".join(
        "{" + ",".join(f"{value}ULL" for value in row) + "}" for row in rows) + "};\n"
    text += '''int conformance_main(void) {
for(u64 i=0;i<sizeof(rows)/sizeof(rows[0]);i++) {
 const u64 *r=rows[i];
 if(functions[r[0]](r[1],r[2],r[3])!=r[4])return 31;
 if(functions[r[0]+1](r[1],r[2],r[3])!=r[5])return 32;
}
static const char message[]="OCORE-FUNNEL-SHIFT PASS\\n";
#if defined(__x86_64__)
syscall3(1,1,(u64)message,sizeof(message)-1);
#else
syscall3(64,1,(u64)message,sizeof(message)-1);
#endif
return 0;}
#if defined(__x86_64__)
__asm__''' + reusable.split('#if defined(__x86_64__)\n__asm__', 1)[1]
    return text


class FunnelShiftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = importer.discover_library()
        cls.compiler = Path(os.environ.get("OCOREC", str(ROOT / "target/debug/ocorec")))
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(weak.SDK)))

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_FUNNEL_OUTPUT_DIR")
        if retained:
            Path(retained).mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=retained))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-funnel-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)

    def source(self, text, triple=baseline.TRIPLES[0], name="original.ll"):
        path = self.directory / name
        path.write_text(f'target triple = "{triple}"\ntarget datalayout = "{baseline.LAYOUT}"\n' + text)
        return path

    def command(self, command, success=True):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=180)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result

    def test_complete_scalar_widths_import_and_lower_without_helper_calls(self):
        for triple in baseline.TRIPLES:
            module = importer.import_module(self.source(body(), triple), library_path=self.library)
            self.assertEqual(len(module["functions"]), 256)
            for fn in module["functions"]:
                if fn["entry"] is None:
                    self.assertEqual(fn["intrinsic"], fn["name"])
                    continue
                operations = [i["operation"] for block in fn["blocks"] for i in block["instructions"]]
                self.assertFalse(any(op["op"] == "call" for op in operations))
                self.assertEqual(sum(op["op"] == "freeze" for op in operations), 3)

    def test_invalid_intrinsic_shapes_and_unsupported_widths_reject(self):
        for declaration in (
            "declare i32 @llvm.fshl.i32(i32,i16,i32)",
            "declare i32 @llvm.fshr.i32(i32,i32)",
            "declare i65 @llvm.fshl.i65(i65,i65,i65)",
            "declare <2 x i32> @llvm.fshr.v2i32(<2 x i32>,<2 x i32>,<2 x i32>)",
            "declare fastcc i32 @llvm.fshl.i32(i32,i32,i32)",
            "declare i32 @llvm.fshl.i32(i32,i32,i32)\n"
            "define i32 @bad(i32 %a,i32 %b,i32 %c) {\n"
            "%r = call i32 @llvm.fshl.i32(i32 signext %a,i32 %b,i32 %c)\nret i32 %r\n}",
        ):
            with self.subTest(declaration=declaration), self.assertRaises(importer.ImportFailure):
                importer.import_module(self.source(declaration), library_path=self.library)

    def test_original_and_native_execution_match_integer_oracle_on_all_isas(self):
        if not self.compiler.is_file() or not (self.sdk / "clang").is_file():
            self.skipTest("built O-core compiler and LLVM22 SDK required")
        linker = shutil.which(os.environ.get("LD_LLD", "ld.lld"))
        if not linker:
            self.skipTest("ld.lld required")
        runners = {}
        for isa in TARGETS:
            try:
                runners[isa] = execution_prefix(isa, os.environ.get("OCORE_TEST_QEMU_" + isa.upper()))
            except RuntimeError:
                if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1":
                    raise
                self.skipTest("all three ISA execution tools required")
        harness = self.directory / "carrier.c"
        harness.write_text(carrier())
        records = []
        for isa, (target, triple, _, flags) in TARGETS.items():
            source = self.source(body(), triple, isa + ".ll")
            native, reference, host = [self.directory / f"{isa}-{name}.o" for name in ("native", "reference", "carrier")]
            self.command([self.compiler, source, "--input-kind", "llvm-ir", "--emit", "obj", "--target", target,
                          "--llvm-library", self.library, "--llvm-sha256", importer.PINNED_SHA256, "-o", native])
            options = ["--target=" + triple, *flags, "-O1", "-ffreestanding", "-fno-builtin", "-fno-pic",
                       "-fno-pie", "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables"]
            self.command([self.sdk / "clang", *options, "-c", source, "-o", reference])
            self.command([self.sdk / "clang", *options, "-c", harness, "-o", host])
            for kind, obj in (("native", native), ("reference", reference)):
                executable = self.directory / f"{isa}-{kind}"
                self.command([linker, "-static", "--build-id=none", "-e", "_start", host, obj, "-o", executable])
                result = self.command([*runners[isa], executable])
                self.assertEqual(result.stdout, b"OCORE-FUNNEL-SHIFT PASS\n")
                records.append({"isa": isa, "kind": kind, "exit_code": result.returncode,
                                "stdout": result.stdout.decode(), "executable": str(executable)})
        (self.directory / "execution.json").write_text(json.dumps({"ok": True, "records": records,
            "checks_per_executable": 2 * sum(len(cases(width)) for width in range(1, 65))}, indent=2) + "\n")

    def test_native_verifier_rejects_forged_intrinsic_contract(self):
        if not self.compiler.is_file():
            self.skipTest("built O-core compiler required")
        module = importer.import_module(self.source(body()), library_path=self.library)
        # The importer and the independent consumer both enforce declaration
        # shape; an admitted module cannot forge a weaker builtin contract.
        for change in ("width", "spelling", "arity"):
            altered = copy.deepcopy(module)
            declaration = altered["functions"][0]
            if change == "width":
                declaration["signature"]["result"] = declaration["signature"]["params"][0] + 1
            elif change == "spelling":
                declaration["name"] = declaration["intrinsic"] = "llvm.fshl.i01"
            else:
                declaration["signature"]["params"].pop()
                declaration["signature"]["param_attributes"].pop()
                declaration["params"].pop()
            path = self.directory / f"invalid-{change}.json"
            path.write_text(json.dumps(altered))
            result = self.command([self.compiler, path, "--input-kind", "native-ir", "--verify-native"], success=False)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
