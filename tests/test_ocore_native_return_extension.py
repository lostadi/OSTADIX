"""Retained distinct narrow return contracts, checked against real Clang22.

Only the low 32 bits are an LLVM i32 result; explicit SSA sext determines the
observed signed i64. Linux syscall carriers compare owned and original LLVM
backend outputs on each ISA without claiming a complete runtime ABI.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_fp128_layout as storage
from tests import test_ocore_llvm_memory_import as memory


ROOT = Path(__file__).resolve().parents[1]
TRIPLES = baseline.TRIPLES
LAYOUT = "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128"
BODY = """
define signext i32 @original_provider(i64 %bits) {
entry:
  %low = trunc i64 %bits to i32
  ret i32 %low
}
define i64 @observe_original(i64 %bits) {
entry:
  %low = call i32 @original_provider(i64 %bits)
  %signed = sext i32 %low to i64
  ret i64 %signed
}
"""

CARRIER = """
extern long long observe_original(unsigned long long);
static int check(void) {
  const unsigned long long values[] = {
    0,1,0x7fffffffULL,0x80000000ULL,0x80000001ULL,0xfffffffeULL,0xffffffffULL,
    0x1234567800000000ULL,0x123456787fffffffULL,0x1234567880000000ULL,
    0x12345678ffffffffULL,0x7fffffff00000001ULL
  };
  for (unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
    unsigned long long low = values[i] & 0xffffffffULL;
    long long expected = low >= 0x80000000ULL ? (long long)low-4294967296LL : (long long)low;
    if (observe_original(values[i]) != expected) return 1+i;
  }
  return 0;
}
__attribute__((noreturn)) void _start(void) {
  int status = check();
#if defined(__x86_64__)
  __asm__ volatile("syscall" : : "a"(60L), "D"((long)status) : "rcx", "r11", "memory");
#elif defined(__aarch64__)
  register long code __asm__("x0") = status;
  register long number __asm__("x8") = 93;
  __asm__ volatile("svc #0" : : "r"(code), "r"(number) : "memory");
#elif defined(__riscv)
  register long code __asm__("a0") = status;
  register long number __asm__("a7") = 93;
  __asm__ volatile("ecall" : : "r"(code), "r"(number) : "memory");
#endif
  __builtin_unreachable();
}
"""


class NarrowReturnExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        cls.library_sha256 = os.environ.get("OCORE_TEST_LLVM_SHA256",importer.PINNED_SHA256)
        if hashlib.sha256(cls.library.read_bytes()).hexdigest() != cls.library_sha256:
            raise RuntimeError("actual LLVM22 parser differs from the explicit pin")
        cls.ocorec = ROOT/"target/debug/ocorec"
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN",str(storage.SDK_DEFAULT)))
        if not cls.ocorec.is_file():
            raise unittest.SkipTest("fresh owned native compiler required")
        retained = os.environ.get("OCORE_TEST_RETURN_EXTENSION_OUTPUT_DIR")
        if retained:
            parent = Path(retained).expanduser().resolve()
            parent.mkdir(parents=True,exist_ok=True)
            cls.directory = Path(tempfile.mkdtemp(prefix="run-",dir=parent))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-return-extension-")
            cls.addClassCleanup(temporary.cleanup)
            cls.directory = Path(temporary.name)

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-",dir=self.directory))

    def write(self,body,triple):
        path = self.case/"original.ll"
        layout = LAYOUT+("-Fn32" if triple.startswith("aarch64-") else "")
        path.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n'+body)
        return path

    def import_path(self,path):
        return importer.import_module(path,library_path=self.library,expected_sha256=self.library_sha256)

    def verify(self,module,accepted=True):
        path = self.case/"module.native-ir.json"
        path.write_text(json.dumps(module))
        receipt = self.case/"verification.json"
        result = storage.command([self.ocorec,path,"--input-kind","native-ir","--verify-native","--receipt",receipt]) if accepted else subprocess.run(
            [str(self.ocorec),str(path),"--input-kind","native-ir","--verify-native","--receipt",str(receipt)],
            capture_output=True,text=True,timeout=120)
        self.assertEqual(result.returncode==0,accepted,result.stdout+result.stderr)
        if accepted:
            self.assertTrue(json.loads(receipt.read_text())["verified"])
        else:
            self.assertIn("direct callee symbol/signature mismatch",result.stderr)
            self.assertFalse(receipt.exists())
        return path

    def test_complete_text_and_bitcode_preserve_distinct_declaration_and_call_attributes_all_three_isas(self):
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                source = self.write(BODY,triple)
                module = self.import_path(source)
                binary = memory.LlvmMemoryImportTests.bitcode(self,source)
                alternate = self.import_path(binary)
                self.assertEqual({k:v for k,v in module.items() if k not in {"name","provenance"}},
                                 {k:v for k,v in alternate.items() if k not in {"name","provenance"}})
                self.assertEqual(len(module["functions"]),2)
                self.assertEqual(module["provenance"]["source_function_count"],2)
                provider = next(f for f in module["functions"] if f["name"]=="original_provider")
                observer = next(f for f in module["functions"] if f["name"]=="observe_original")
                call = next(i["operation"] for b in observer["blocks"] for i in b["instructions"]
                            if i["operation"]["op"]=="call")
                self.assertEqual(provider["signature"]["result_attributes"],["signext"])
                self.assertEqual(call["signature"]["result_attributes"],[])
                self.assertEqual(call["signature"]["result"],provider["signature"]["result"])
                self.verify(module)

    def test_owned_and_llvm22_reference_carriers_agree_on_low32_signed_boundaries_all_three_isas(self):
        clang = self.sdk/"clang"
        if not clang.is_file() or not shutil.which("ld.lld"):
            self.skipTest("actual LLVM22 frontend/backend reference and lld required")
        self.assertRegex(storage.command([clang,"--version"]).stdout,r"clang version 22\.1\.6(?:\s|$)")
        native = {"AMD64":"x86_64","arm64":"aarch64"}.get(platform.machine(),platform.machine())
        records = []
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                arch = triple.split("-")[0]
                source = self.write(BODY,triple)
                module = self.import_path(source)
                path = self.verify(module)
                owned = self.case/(arch+"-owned.o")
                storage.command([self.ocorec,path,"--input-kind","native-ir","--emit","obj",
                                 "--target",arch+"-unknown-none","-o",owned])
                abi = module["target"].get("abi","lp64")
                flags = ["-march=rv64gc","-mabi="+abi] if arch=="riscv64" else []
                reference = self.case/(arch+"-reference.o")
                storage.command([clang,"--target="+triple,*flags,"-O0","-c",source,"-o",reference])
                if arch=="riscv64":
                    self.assertEqual(struct.unpack_from("<I",owned.read_bytes(),48)[0]&6,
                                     struct.unpack_from("<I",reference.read_bytes(),48)[0]&6)
                driver = self.case/"carrier.c"
                driver.write_text(CARRIER)
                for label,obj in (("owned",owned),("llvm22-reference",reference)):
                    binary = self.case/(arch+"-"+label)
                    storage.command([clang,"--target="+triple,*flags,"-O1","-ffreestanding",
                                     "-fno-builtin","-fno-stack-protector","-fno-pic","-fno-pie",
                                     "-fno-unwind-tables","-fno-asynchronous-unwind-tables","-nostdlib",
                                     "-static","-fuse-ld=lld","-Wl,--no-relax","-Wl,-e,_start",driver,obj,"-o",binary])
                    if arch!=native and not shutil.which("qemu-"+arch):
                        self.fail("actual qemu-"+arch+" required for ISA execution")
                    runner = [binary] if arch==native else ["qemu-"+arch,binary]
                    storage.command(runner)
                    records.append({"triple":triple,"backend":label,"source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),
                                    "object_sha256":hashlib.sha256(obj.read_bytes()).hexdigest(),
                                    "executable_sha256":hashlib.sha256(binary.read_bytes()).hexdigest(),"exit_code":0})
        (self.directory/"actual-carriers.json").write_text(json.dumps({"carriers":records,"runtime_complete":False},indent=2)+"\n")

    def test_reverse_conflicting_extension_and_other_signature_differences_remain_rejected(self):
        bodies = {
            "reverse":BODY.replace("define signext i32","define i32").replace("call i32","call signext i32"),
            "conflicting-result":BODY.replace("call i32","call zeroext i32"),
            "unsupported-zeroext-provider":BODY.replace("define signext i32","define zeroext i32"),
            "parameter-contract":BODY.replace("call i32 @original_provider(i64 %bits)","call i32 @original_provider(i64 signext %bits)"),
            "calling-convention":BODY.replace("define signext i32","define fastcc signext i32"),
            "alias-contract":"@provider_alias = alias i32 (i64), ptr @original_provider\n"+
                             BODY.replace("call i32 @original_provider", "call i32 @provider_alias"),
            "result-type":BODY.replace("%low = call i32 @original_provider(i64 %bits)\n  %signed = sext i32 %low to i64\n  ret i64 %signed",
                                       "%wrong = call i64 @original_provider(i64 %bits)\n  ret i64 %wrong"),
        }
        for triple in TRIPLES:
            for name,body in bodies.items():
                with self.subTest(triple=triple,case=name):
                    # These inputs must first pass the real LLVM parser/verifier;
                    # only an independent native ABI rejection satisfies the test.
                    self.verify(self.import_path(self.write(body,triple)),accepted=False)
        # Both are genuine LLVM musttail instructions with matching caller/call
        # function types. Only the first keeps the callee's signext contract;
        # neither may turn into the newly admitted ordinary-call case.
        for triple in TRIPLES:
            for extension in ("signext ", ""):
                with self.subTest(triple=triple,musttail_extension=extension):
                    body = """
define signext i32 @original_provider(i64 %bits) {
entry:
  %low = trunc i64 %bits to i32
  ret i32 %low
}
define EXTENSIONi32 @musttail_observer(i64 %bits) {
entry:
  %low = musttail call EXTENSIONi32 @original_provider(i64 %bits)
  ret i32 %low
}
""".replace("EXTENSION",extension)
                    with self.assertRaises(importer.ImportFailure) as raised:
                        self.import_path(self.write(body,triple))
                    self.assertEqual(raised.exception.stage,"import",
                                     "the real LLVM parser/verifier must accept the fixture before the importer rejects musttail")
                    self.assertIn("musttail",str(raised.exception))


if __name__=="__main__":
    unittest.main()
