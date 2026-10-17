"""Real LLVM22 binary128 storage; arithmetic and floating ABI stay unsupported.

The freestanding Linux carriers inspect original layout and bytes only. Running
them does not qualify a foreign runtime or OSTADIX platform execution.
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
import sys
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from tests import test_ocore_llvm_import as baseline
from tests import test_ocore_llvm_memory_import as memory


ROOT = Path(__file__).resolve().parents[1]
SDK_DEFAULT = (Path.home() / ".local/share/ostadix/llvm22/rootfs/usr/lib/llvm-22/bin")
TRIPLES = baseline.TRIPLES
LAYOUT = "e-p:64:64-i64:64-i128:128-f128:128-n8:16:32:64-S128"
ZERO = "0xL00000000000000000000000000000000"
ONE = "0xL00000000000000003FFF000000000000"
NEGATIVE_ZERO = "0xL00000000000000008000000000000000"

STORAGE_IR = """
%storage = type { i8, fp128, [2 x fp128], i32 }
%packed = type <{ i8, fp128, i32 }>
@zero_box = global %storage zeroinitializer, align 16
@zero_scalar = global fp128 ZERO, align 16
@zero_array = global [3 x fp128] zeroinitializer, align 16
@seed = constant %storage { i8 7, fp128 ZERO, [2 x fp128] zeroinitializer, i32 23 }, align 16
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg)
define void @storage_offsets(ptr %out) {
entry:
  %box = alloca %storage, align 16
  %packed = alloca %packed, align 1
  %wide = alloca [2 x fp128], align 16
  %base = ptrtoint ptr %box to i64
  %field1 = getelementptr %storage, ptr %box, i64 0, i32 1
  %a1 = ptrtoint ptr %field1 to i64
  %o1 = sub i64 %a1, %base
  store i64 %o1, ptr %out, align 8
  %array1 = getelementptr %storage, ptr %box, i64 0, i32 2, i64 1
  %a2 = ptrtoint ptr %array1 to i64
  %o2 = sub i64 %a2, %base
  %out1 = getelementptr i64, ptr %out, i64 1
  store i64 %o2, ptr %out1, align 8
  %tail = getelementptr %storage, ptr %box, i64 0, i32 3
  %a3 = ptrtoint ptr %tail to i64
  %o3 = sub i64 %a3, %base
  %out2 = getelementptr i64, ptr %out, i64 2
  store i64 %o3, ptr %out2, align 8
  %end = getelementptr %storage, ptr %box, i64 1
  %a4 = ptrtoint ptr %end to i64
  %o4 = sub i64 %a4, %base
  %out3 = getelementptr i64, ptr %out, i64 3
  store i64 %o4, ptr %out3, align 8
  %pbase = ptrtoint ptr %packed to i64
  %pfield = getelementptr %packed, ptr %packed, i64 0, i32 1
  %a5 = ptrtoint ptr %pfield to i64
  %o5 = sub i64 %a5, %pbase
  %out4 = getelementptr i64, ptr %out, i64 4
  store i64 %o5, ptr %out4, align 8
  %ptail = getelementptr %packed, ptr %packed, i64 0, i32 2
  %a6 = ptrtoint ptr %ptail to i64
  %o6 = sub i64 %a6, %pbase
  %out5 = getelementptr i64, ptr %out, i64 5
  store i64 %o6, ptr %out5, align 8
  %pend = getelementptr %packed, ptr %packed, i64 1
  %a7 = ptrtoint ptr %pend to i64
  %o7 = sub i64 %a7, %pbase
  %out6 = getelementptr i64, ptr %out, i64 6
  store i64 %o7, ptr %out6, align 8
  %wbase = ptrtoint ptr %wide to i64
  %wnext = getelementptr [2 x fp128], ptr %wide, i64 0, i64 1
  %a8 = ptrtoint ptr %wnext to i64
  %o8 = sub i64 %a8, %wbase
  %out7 = getelementptr i64, ptr %out, i64 7
  store i64 %o8, ptr %out7, align 8
  ret void
}
define void @copy_storage(ptr %destination) {
entry:
  %temporary = alloca %storage, align 16
  call void @llvm.memcpy.p0.p0.i64(ptr align 16 %temporary, ptr align 16 @seed, i64 80, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr %destination, ptr align 16 %temporary, i64 80, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 16 @zero_box, ptr align 16 %temporary, i64 80, i1 false)
  ret void
}
""".replace("ZERO", ZERO)

CARRIER_C = """
extern unsigned char zero_box[], zero_scalar[], zero_array[], seed[];
extern void storage_offsets(unsigned long long *);
extern void copy_storage(unsigned char *);
static int check(void) {
  unsigned long long offsets[8];
  const unsigned long long expected[8] = {16,48,64,80,1,17,21,16};
  unsigned char copied[80];
  if (((unsigned long)zero_box | (unsigned long)zero_scalar |
       (unsigned long)zero_array | (unsigned long)seed) & 15) return 1;
  for (int i=0;i<80;i++) if (zero_box[i]) return 2;
  for (int i=0;i<16;i++) if (zero_scalar[i]) return 3;
  for (int i=0;i<48;i++) if (zero_array[i]) return 4;
  storage_offsets(offsets);
  for (int i=0;i<8;i++) if (offsets[i] != expected[i]) return 5+i;
  copy_storage(copied);
  for (int i=0;i<80;i++) {
    unsigned char byte = i == 0 ? 7 : i == 64 ? 23 : 0;
    if (seed[i] != byte || copied[i] != byte || zero_box[i] != byte) return 20;
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


def command(argv, **kwargs):
    result = subprocess.run([str(value) for value in argv], capture_output=True,
                            text=True, timeout=120, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stdout}{result.stderr}")
    return result


class Fp128StorageLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.library = baseline.llvm_library()
        expected = os.environ.get("OCORE_TEST_LLVM_SHA256", importer.PINNED_SHA256)
        cls.library_sha256 = hashlib.sha256(cls.library.read_bytes()).hexdigest()
        if cls.library_sha256 != expected:
            raise RuntimeError("actual LLVM parser differs from the explicit test pin")
        api = importer.LLVM(cls.library, cls.library_sha256)
        if api.version != (22, 1, 6):
            raise RuntimeError(f"actual LLVM22.1.6 parser required, got {api.version}")
        cls.ocorec = ROOT / "target/debug/ocorec"
        cls.sdk = Path(os.environ.get("OCORE_TEST_LLVM22_BIN", str(SDK_DEFAULT)))
        if not cls.ocorec.is_file():
            raise unittest.SkipTest("built ocorec required for independent native verification")
        retained = os.environ.get("OCORE_TEST_FP128_OUTPUT_DIR")
        if retained:
            destination = Path(retained).expanduser().resolve()
            destination.mkdir(parents=True, exist_ok=True)
            cls.directory = Path(tempfile.mkdtemp(prefix="run-", dir=destination))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-fp128-storage-")
            cls.addClassCleanup(temporary.cleanup)
            cls.directory = Path(temporary.name)
        cls.modules = {}

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.directory))

    def write(self, body, triple, layout=LAYOUT):
        if triple.startswith("aarch64-"):
            layout += "-Fn32"
        source = self.case / "input.ll"
        source.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n' + body)
        return source

    def import_path(self, path):
        return importer.import_module(path, library_path=self.library,
                                      expected_sha256=self.library_sha256)

    def storage_module(self, triple):
        if triple not in self.modules:
            source = self.write(STORAGE_IR, triple)
            module = self.import_path(source)
            self.modules[triple] = (source, module)
        return self.modules[triple]

    def reject(self, body, triple, layout=LAYOUT):
        with self.assertRaises(importer.ImportFailure) as raised:
            self.import_path(self.write(body, triple, layout))
        self.assertEqual(raised.exception.stage, "import",
                         "actual LLVM parse/toolchain failures must not masquerade as unsupported semantics")
        self.assertTrue(str(raised.exception).strip())

    def verify_and_emit(self, module, triple):
        native_ir = self.case / "module.native-ir.json"
        native_ir.write_text(json.dumps(module))
        receipt = self.case / "verification.json"
        command([self.ocorec, native_ir, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
        self.assertTrue(json.loads(receipt.read_text())["verified"])
        obj = self.case / "module.o"
        command([self.ocorec, native_ir, "--input-kind", "native-ir", "--emit", "obj",
                 "--target", triple.split("-")[0]+"-unknown-none", "-o", obj])
        self.assertEqual(obj.read_bytes()[:4], b"\x7fELF")
        return obj

    def test_original_float_type_zero_storage_exact_layout_and_bitcode_all_three_isas(self):
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                source, module = self.storage_module(triple)
                binary = memory.LlvmMemoryImportTests.bitcode(self, source)
                from_binary = self.import_path(binary)
                self.assertEqual({k:v for k,v in module.items() if k not in {"name", "provenance"}},
                                 {k:v for k,v in from_binary.items() if k not in {"name", "provenance"}})
                self.assertIn({"kind":"float", "bits":128}, module["types"])
                self.assertNotIn({"kind":"int", "bits":128}, module["types"])
                globals_ = {item["name"]:item for item in module["globals"]}
                self.assertEqual(set(globals_), {"zero_box", "zero_scalar", "zero_array", "seed"})
                for name, length in (("zero_box",80),("zero_scalar",16),("zero_array",48)):
                    self.assertEqual(globals_[name]["alignment"], 16)
                    self.assertEqual(globals_[name]["initializer"], {"bytes":[0]*length,"relocations":[]})
                expected = [0]*80
                expected[0], expected[64] = 7, 23
                self.assertEqual(globals_["seed"]["initializer"], {"bytes":expected,"relocations":[]})
                allocations = [instruction["operation"] for function in module["functions"]
                               for block in function["blocks"] for instruction in block["instructions"]
                               if instruction["operation"]["op"] == "alloca"]
                self.assertEqual([(item["size"],item["alignment"]) for item in allocations],
                                 [(80,16),(21,1),(32,16),(80,16)])
                self.verify_and_emit(module, triple)

    def test_owned_objects_preserve_offsets_alignment_and_bytes_in_linux_carriers_all_three_isas(self):
        clang = self.sdk / "clang"
        if not clang.is_file() or not shutil.which("ld.lld"):
            self.skipTest("actual LLVM22 clang and ld.lld required for freestanding carriers")
        self.assertRegex(command([clang,"--version"]).stdout, r"clang version 22\.1\.6(?:\s|$)")
        native = {"AMD64":"x86_64", "arm64":"aarch64"}.get(platform.machine(),platform.machine())
        for triple in TRIPLES:
            with self.subTest(triple=triple):
                arch = triple.split("-")[0]
                if arch != native and shutil.which("qemu-"+arch) is None:
                    self.fail(f"qemu-{arch} required to execute this ISA's byte/offset carrier")
                _, module = self.storage_module(triple)
                obj = self.verify_and_emit(module, triple)
                source = self.case / "carrier.c"
                source.write_text(CARRIER_C)
                carrier = self.case / (arch+"-carrier")
                flags = []
                if arch == "riscv64":
                    abi = module["target"].get("abi", "lp64")
                    self.assertIn(abi, {"lp64", "lp64d"})
                    self.assertEqual(struct.unpack_from("<I", obj.read_bytes(), 48)[0] & 6,
                                     4 if abi == "lp64d" else 0)
                    flags = ["-march=rv64gc", "-mabi="+abi]
                command([clang,"--target="+triple,*flags,"-O1","-ffreestanding","-fno-builtin",
                         "-fno-stack-protector","-fno-pic","-fno-pie","-fno-unwind-tables",
                         "-fno-asynchronous-unwind-tables","-nostdlib","-static","-fuse-ld=lld",
                         "-Wl,--no-relax","-Wl,-e,_start",source,obj,"-o",carrier])
                runner = [carrier] if arch == native else ["qemu-"+arch,carrier]
                self.assertEqual(command(runner).returncode, 0)

    def test_first_class_fp128_values_and_recursive_abi_remain_rejected_all_three_isas(self):
        bodies = [
            "define fp128 @identity(fp128 %x) { ret fp128 %x }",
            "declare void @argument(fp128)",
            "declare fp128 @result()",
            "declare void @nested({i8, [2 x fp128]})",
            "declare void @zero_length([0 x fp128])",
            "define fp128 @load(ptr %p) { %v = load fp128, ptr %p, align 16 ret fp128 %v }",
            f"define void @store(ptr %p) {{ store fp128 {ZERO}, ptr %p, align 16 ret void }}",
            f"define fp128 @add() {{ %v = fadd fp128 {ZERO}, {ONE} ret fp128 %v }}",
            f"define i1 @compare() {{ %v = fcmp oeq fp128 {ZERO}, {ZERO} ret i1 %v }}",
            f"define i64 @convert() {{ %v = fptosi fp128 {ONE} to i64 ret i64 %v }}",
            "define {fp128} @aggregate() { ret {fp128} zeroinitializer }",
        ]
        for triple in TRIPLES:
            for body in bodies:
                with self.subTest(triple=triple,body=body):
                    self.reject(body,triple)

    def test_nonzero_negative_zero_and_undefined_fp128_initializers_rejected_all_three_isas(self):
        bodies = [f"@bad = global fp128 {ONE}", f"@bad = global fp128 {NEGATIVE_ZERO}",
                  "@bad = global fp128 poison", "@bad = global fp128 undef",
                  "@bad = global {i8, [2 x fp128]} poison",
                  "@bad = global {i8, [2 x fp128]} undef",
                  "@bad = global {i8, [2 x fp128]} {i8 0, [2 x fp128] poison}",
                  "@bad = global [1 x {fp128}] [{fp128} undef]",
                  f"@bad = global [1 x fp128] [fp128 {ONE}]"]
        for triple in TRIPLES:
            for body in bodies:
                with self.subTest(triple=triple,body=body):
                    self.reject(body,triple)

    def test_float32_float64_x87_ppc128_and_i128_are_not_admitted_by_storage_slice(self):
        for triple in TRIPLES:
            for ty in ("float","double","x86_fp80","ppc_fp128","i128"):
                with self.subTest(triple=triple,ty=ty):
                    self.reject(f"define void @storage() {{ %p = alloca {ty}, align 16 ret void }}",triple)

    def test_incompatible_binary128_abi_alignment_is_rejected(self):
        for triple in TRIPLES:
            for align in (64,256):
                with self.subTest(triple=triple,align=align):
                    self.reject("@storage = global fp128 zeroinitializer",
                                triple,LAYOUT.replace("f128:128",f"f128:{align}"))

    def test_original_c_source_recipe_storage_package_survives_source_capture_removal(self):
        olangc = ROOT/"target/debug/olangc"
        if not olangc.is_file() or not all((self.sdk/name).is_file() for name in ("clang","clang++","llvm-nm")):
            self.skipTest("actual source driver and LLVM22 frontend tools required")
        source = self.case/"original-source"
        source.mkdir()
        (source/"storage.c").write_text("""
#if defined(__x86_64__)
typedef __float128 Wide;
#else
typedef long double Wide;
#endif
struct Storage { unsigned char head; Wide field; Wide array[2]; unsigned int tail; };
_Static_assert(sizeof(Wide) == 16 && _Alignof(Wide) == 16, "binary128 fixture layout");
_Static_assert(sizeof(struct Storage) == 80, "original struct layout");
struct Storage original_zero;
const struct Storage original_seed = {7,0,{0,0},23};
void original_copy(void *destination) { __builtin_memcpy(destination, &original_seed, sizeof(original_seed)); }
""")
        (source/"build.py").write_text("""import json,os,pathlib,subprocess,sys
source=pathlib.Path(sys.argv[1])
subprocess.run([os.environ['CC'],'-O1','-fno-pic','-fno-pie','-fno-stack-protector',
 '-fno-vectorize','-fno-slp-vectorize','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
 '-c',str(source/'storage.c'),'-o','storage.o'],check=True)
pathlib.Path('unit-inventory.json').write_text(json.dumps({
 'schema':'ocore-runtime-unit-inventory-v1','complete':True,
 'units':[{'id':'original-full-storage-unit','kind':'clang','source':'storage.c',
           'build_step':'original-build','role':'runtime'}]}))
""")
        for argv in (["git","init","-q"],["git","add","."],
                     ["git","-c","user.name=Native Storage Test","-c","user.email=test@example.invalid",
                      "commit","-qm","original complete storage fixture"]):
            command(argv,cwd=source)
        revision = command(["git","rev-parse","HEAD"],cwd=source).stdout.strip()
        original = {str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in source.iterdir() if p.is_file()}
        recipe = self.case/"recipe.json"
        recipe.write_text(json.dumps({"schema":"ocore-runtime-recipe-v1",
            "name":"original-binary128-storage-fixture",
            "source":{"url":"local-original-binary128-storage-fixture","revision":revision},
            "toolchain":{"llvm_version":"22.1.6"},
            "commands":[{"name":"original-build","argv":[sys.executable,"{source}/build.py","{source}"]}],
            "coverage":{"required_units":[{"id":"original-storage","kind":"clang","source":"storage.c","role":"runtime"}],
                        "required_outputs":["storage.o"],"require_full_unit_inventory":True}}))
        arch = {"AMD64":"x86_64","arm64":"aarch64"}.get(platform.machine(),platform.machine())
        output = self.case/"compiled"
        command([olangc,recipe,"--native-runtime","--native-runtime-source",source,
                 "--native-isa",arch+"-unknown-none","--native-runtime-output","ir",
                 "--native-runtime-cc",self.sdk/"clang","--native-runtime-cxx",self.sdk/"clang++",
                 "--native-runtime-llvm-nm",self.sdk/"llvm-nm","--llvm-library",self.library,
                 "--llvm-sha256",self.library_sha256,"-o",output])
        receipt = json.loads((output/"source-recipe.json").read_text())
        self.assertTrue(receipt["success"])
        self.assertTrue(receipt["capture_complete"])
        self.assertTrue(receipt["lowering_complete"])
        self.assertFalse(receipt["runtime_complete"])
        coverage = json.loads((output/"lowered/coverage.json").read_text())
        self.assertTrue(coverage["native_module_dependency_closure_complete"])
        self.assertEqual(coverage["lowered_unit_count"],1)
        artifact = Path(coverage["module_set_artifact"]["path"])
        detached = self.case/"detached.native-ir.json"
        shutil.copyfile(artifact,detached)
        package = json.loads(detached.read_text())
        self.assertEqual(len(package["modules"]),1)
        module = json.loads(package["modules"][0]["native_ir"])
        self.assertIn({"kind":"float","bits":128},module["types"])
        globals_ = {g["name"]:g for g in module["globals"]}
        self.assertEqual(globals_["original_zero"]["initializer"],{"bytes":[0]*80,"relocations":[]})
        self.assertEqual(original,{str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in source.iterdir() if p.is_file()})
        source.rename(self.case/"unavailable-source")
        output.rename(self.case/"unavailable-capture-build-and-lowering")
        reused = self.case/"reused"
        command([olangc,detached,"--native-runtime","--native-isa",arch+"-unknown-none",
                 "--native-runtime-output","obj","-o",reused])
        replay = json.loads((reused/"coverage.json").read_text())
        self.assertEqual(replay["input_kind"],"native_module_set")
        self.assertTrue(replay["native_module_dependency_closure_complete"])
        self.assertFalse(replay["source_capture_reverification_performed"])
        self.assertFalse(replay["runtime_complete"])
        objects = list(reused.glob("unit-*/module.o"))
        self.assertEqual(len(objects),1)
        self.assertEqual(objects[0].read_bytes()[:4],b"\x7fELF")
        names = {line.split()[-1] for line in command([self.sdk/"llvm-nm","--defined-only",objects[0]]).stdout.splitlines()}
        self.assertTrue({"original_zero","original_seed","original_copy"} <= names)

    def test_original_pinned_lua_whole_storage_units(self):
        report_path = os.environ.get("OCORE_TEST_LUA_CAPTURE_REPORT")
        if not report_path:
            self.skipTest("set OCORE_TEST_LUA_CAPTURE_REPORT to the unchanged original Lua22 capture")
        report_path = Path(report_path).resolve(strict=True)
        report = json.loads(report_path.read_text())
        self.assertTrue(report["capture_complete"])
        self.assertEqual(report["source"]["revision"], "0b29f408433e92953cc72b1d3e06c7ac8139e439")
        selected = {Path(unit["source"]["path"]).name:unit for unit in report["units"]
                    if Path(unit["source"]["path"]).name in {"lstring.c", "lgc.c"}}
        self.assertEqual(set(selected), {"lstring.c", "lgc.c"})
        evidence = []
        for name, unit in sorted(selected.items()):
            with self.subTest(source=name):
                for key in ("source", "ir"):
                    record = unit[key]
                    data = Path(record["path"]).read_bytes()
                    self.assertEqual(len(data), record["bytes"])
                    self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
                self.case = self.case / name
                self.case.mkdir()
                native_ir = self.case / "whole.native-ir.json"
                command([self.ocorec, unit["ir"]["path"], "--input-kind", "llvm-ir", "--emit", "mir",
                         "--target", "riscv64-unknown-none", "--llvm-library", self.library,
                         "--llvm-sha256", self.library_sha256, "-o", native_ir])
                module = json.loads(native_ir.read_text())
                self.assertEqual(module["provenance"]["input_sha256"], unit["ir"]["sha256"])
                self.assertEqual(len(module["functions"]), module["provenance"]["source_function_count"])
                self.assertEqual(len(module["globals"]), module["provenance"]["source_global_count"])
                self.assertIn({"kind":"float", "bits":128}, module["types"])
                object_path = self.verify_and_emit(module, "riscv64-unknown-linux-gnu")
                evidence.append({"source":name,"unit_id":unit["id"],
                                 "source_sha256":unit["source"]["sha256"],
                                 "llvm_sha256":unit["ir"]["sha256"],
                                 "native_module_sha256":hashlib.sha256(native_ir.read_bytes()).hexdigest(),
                                 "native_object_sha256":hashlib.sha256(object_path.read_bytes()).hexdigest(),
                                 "function_count":len(module["functions"]),
                                 "global_count":len(module["globals"]),
                                 "runtime_complete":False})
        (self.directory/"original-lua-storage-units.json").write_text(json.dumps({
            "capture_report_sha256":hashlib.sha256(report_path.read_bytes()).hexdigest(),
            "ocorec_sha256":hashlib.sha256(self.ocorec.read_bytes()).hexdigest(),
            "units":evidence,"runtime_complete":False},indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
