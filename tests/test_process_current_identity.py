"""Execute the production current-PCB identity query and real registry lifetimes.

The C carrier supplies three privileged CR3/table hooks and an unavailable
image provider whose use is forbidden by the oracle. It does not implement a
process, domain, CSpace or address-space registry. Private process fields are
visible only in a copied test ELF; allocated bytes must remain unchanged.
This is serialized Linux/x86-64 host execution, not kernel/FP/SMP admission.
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
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULES = ["native_abi", "personality", "domain", "capability", "pages",
           "memory_object", "mapping", "elf_loader", "address_space", "process"]
FIELDS = {
    "PROCESS_IDS": ("uint64_t", 4), "DOMAIN_HANDLES": ("uint64_t", 4),
    "PERSONALITY_IDS": ("uint64_t", 4), "ADDRESS_SPACE_HANDLES": ("uint64_t", 4),
    "CSPACE_HANDLES": ("uint64_t", 4), "KERNEL_STACK_TOPS": ("uintptr_t", 4),
    "USER_ENTRIES": ("uintptr_t", 4), "USER_STACK_TOPS": ("uintptr_t", 4),
    "EXIT_CODES": ("uint64_t", 4), "FAULT_VECTORS": ("uint64_t", 4),
    "FAULT_ERRORS": ("uint64_t", 4), "FAULT_RIPS": ("uintptr_t", 4),
    "FAULT_ADDRESSES": ("uintptr_t", 4), "THREAD_REFS": ("uint32_t", 4),
    "GENERATIONS": ("uint32_t", 4), "STATES": ("uint8_t", 4),
    "CURRENT_PROCESS": ("uint64_t", 0), "INITIALIZED": ("uint8_t", 0),
}
PREFIX = "_O_runtime__process__"
PROVIDER = r'''
module runtime::image_vfs;
extern "C" fn unavailable_image_length(object: u64) -> usize;
extern "C" fn unavailable_image_read(object: u64, offset: usize, result: *mut u8) -> u64;
extern "C" fn unavailable_image_release(object: u64) -> u64;
pub unsafe fn object_length(object: u64) -> usize { return unavailable_image_length(object); }
pub unsafe fn read_retained_byte(object: u64, offset: usize, result: *mut u8) -> u64 { return unavailable_image_read(object, offset, result); }
pub unsafe fn release_object(object: u64) -> u64 { return unavailable_image_release(object); }
'''

HARNESS = r'''
#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define P(n) _O_runtime__process__##n
#define A(n) _O_runtime__address_space__##n
#define C(n) _O_runtime__capability__##n
#define M(n) _O_runtime__memory_object__##n
#define D(n) _O_runtime__domain__##n
#define FR(n) _O_runtime__pages__##n
#define MAP(n) _O_runtime__mapping__##n
extern uint64_t P(init)(void),P(current_process_handle)(void);
extern uint64_t P(install_for_owner)(size_t,uint64_t,uint64_t,uint64_t,uint64_t,uintptr_t,uintptr_t,uintptr_t);
extern uint64_t P(scheduler_switch_to)(uint64_t),P(scheduler_deschedule_current)(void);
extern uint64_t P(exit_current)(uint64_t),P(fault_current)(uint64_t,uint64_t,uintptr_t,uintptr_t);
extern uint64_t P(stop_process)(uint64_t,uint64_t),P(mark_reapable)(uint64_t);
extern uint64_t P(begin_reap)(uint64_t),P(finalize_reap)(uint64_t);
extern uint64_t A(install_bootstrap)(uintptr_t),A(create_native_for_owner)(uint64_t),A(destroy)(uint64_t);
extern uint64_t C(init)(void),C(cspace_handle_for_slot)(size_t),C(create_cspace)(size_t);
extern uint64_t C(begin_cspace_drain)(uint64_t),C(destroy_cspace)(uint64_t);
extern uint64_t M(init)(void),M(set_quota_for_owner)(uint64_t,size_t),D(init)(void);
extern uint64_t FR(init)(uintptr_t,uintptr_t),MAP(init)(void);
#ifndef LEGACY_BEFORE_ONLY
extern bool P(current_process_matches)(uint64_t);
#endif
/* FIELD_DECLARATIONS */
static uint64_t kernel_tables[1024] __attribute__((aligned(4096)));
static uint64_t root_table[512] __attribute__((aligned(4096)));
uintptr_t ocore_current_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_management_cr3(void){return (uintptr_t)root_table;}
uintptr_t ocore_kernel_p1_address(void){return (uintptr_t)kernel_tables;}
static unsigned checks,image_calls;
static void check(int ok,unsigned line){checks++;if(!ok){fprintf(stderr,"check failed at line %u\n",line);exit(92);}}
#define CHECK(x) check(!!(x),__LINE__)
size_t unavailable_image_length(uint64_t object){(void)object;image_calls++;return 0;}
uint64_t unavailable_image_read(uint64_t object,size_t offset,unsigned char *out){
 (void)object;(void)offset;(void)out;image_calls++;return 0;
}
uint64_t unavailable_image_release(uint64_t object){(void)object;image_calls++;return 0;}
struct field {const void *pointer;size_t bytes;};
static const struct field fields[]={/* FIELD_VIEWS */};
static size_t snapshot(unsigned char *out){
 size_t n=0;for(size_t i=0;i<sizeof fields/sizeof fields[0];i++){
  CHECK(n+fields[i].bytes<=512);memcpy(out+n,fields[i].pointer,fields[i].bytes);n+=fields[i].bytes;
 }return n;
}
#ifndef LEGACY_BEFORE_ONLY
static void matches(uint64_t expected,bool result){
 unsigned char before[512],after[512];size_t n=snapshot(before);
 bool observed=P(current_process_matches)(expected);
 CHECK(n==snapshot(after));CHECK(!memcmp(before,after,n));
 if(observed!=result){fprintf(stderr,"identity query expected=%016llx result=%u observed=%u\n",
  (unsigned long long)expected,result,observed);exit(93);}
 CHECK(!image_calls);
}
#endif
static uint64_t owners[2],spaces[2],cspaces[2],domain;
static void setup(void){
 void *frames=NULL;CHECK(!posix_memalign(&frames,4096,1048576));
 CHECK(FR(init)((uintptr_t)frames,(uintptr_t)frames+1048576));
 CHECK(C(init)()&&M(init)()&&MAP(init)());domain=D(init)();CHECK(domain&&P(init)());
 CHECK(A(install_bootstrap)((uintptr_t)root_table));
 for(unsigned i=0;i<2;i++)cspaces[i]=C(cspace_handle_for_slot)(i);
 spaces[0]=1;CHECK(M(set_quota_for_owner)(cspaces[1],8));
 spaces[1]=A(create_native_for_owner)(cspaces[1]);CHECK(spaces[1]);
 for(unsigned i=0;i<2;i++){
  owners[i]=P(install_for_owner)(i,101+i,domain,spaces[i],cspaces[i],0x7000+0x1000*i,0x01000000,0x01400000);
  CHECK(owners[i]);
 }CHECK(!image_calls);
}
static void legacy_ambiguities(void){
 CHECK(P(current_process_handle)()==0&&P(CURRENT_PROCESS)==0);
 puts("legacy getter: genuine idle -> zero");
 P(CURRENT_PROCESS)=UINT64_C(0x123456789abcdef0);CHECK(P(current_process_handle)()==0);
 puts("legacy getter: malformed raw current -> zero");P(CURRENT_PROCESS)=0;
 P(CURRENT_PROCESS)=owners[0]^(UINT64_C(1)<<32);CHECK(P(current_process_handle)()==0);
 puts("legacy getter: stale raw generation -> zero");P(CURRENT_PROCESS)=0;
 P(CURRENT_PROCESS)=owners[0];CHECK(P(STATES)[0]==1&&P(current_process_handle)()==0);
 puts("legacy getter: non-running raw current -> zero");P(CURRENT_PROCESS)=0;
 P(STATES)[0]=2;CHECK(P(current_process_handle)()==0);
 puts("legacy getter: hidden RUNNING PCB with raw current zero -> zero");P(STATES)[0]=1;
 CHECK(P(CURRENT_PROCESS)==0&&!image_calls);
}
#ifndef LEGACY_BEFORE_ONLY
static void corruption_controls(void){
 CHECK(P(scheduler_switch_to)(owners[0])==101);matches(owners[0],true);
 uint64_t malformed[]={UINT64_MAX,UINT64_C(0x123456789abcdef0),
  UINT64_C(0x00000001e1000004),UINT64_C(0x00000000e1000000),
  owners[0]^(UINT64_C(1)<<32)};
 for(size_t i=0;i<sizeof malformed/sizeof malformed[0];i++){
  P(CURRENT_PROCESS)=malformed[i];CHECK(P(current_process_handle)()==0);
  matches(0,false);matches(malformed[i],false);matches(owners[0],false);
 }P(CURRENT_PROCESS)=owners[0];matches(owners[0],true);
 P(STATES)[1]=2;matches(owners[0],false);matches(owners[1],false);matches(0,false);
 P(STATES)[1]=1;matches(owners[0],true);
 P(CURRENT_PROCESS)=0;matches(0,false);P(STATES)[1]=2;matches(0,false);
 P(STATES)[1]=1;P(CURRENT_PROCESS)=owners[0];matches(owners[0],true);
 uint32_t generation=P(GENERATIONS)[0];P(GENERATIONS)[0]++;
 CHECK(P(current_process_handle)()==0);matches(owners[0],false);matches(0,false);
 P(GENERATIONS)[0]=generation;matches(owners[0],true);
 for(uint8_t state=0;state<=8;state++)if(state!=2){
  P(STATES)[0]=state;CHECK(P(current_process_handle)()==0);matches(owners[0],false);matches(0,false);
 }P(STATES)[0]=2;matches(owners[0],true);
 P(INITIALIZED)=2;matches(owners[0],false);matches(0,false);P(INITIALIZED)=1;
 matches(owners[0],true);CHECK(P(scheduler_deschedule_current)()==owners[0]);matches(0,true);
 puts("malformed/stale/nonrunning/raw-zero/duplicate-current and exact initialization controls: PASS");
}
static void reap_ready(uint64_t owner,uint64_t space,uint64_t cspace){
 CHECK(P(stop_process)(owner,0));matches(0,true);
 CHECK(P(begin_reap)(owner));matches(0,true);
 CHECK(A(destroy)(space)&&C(begin_cspace_drain)(cspace)&&C(destroy_cspace)(cspace));
 CHECK(P(finalize_reap)(owner));matches(owner,false);matches(0,true);
}
static void legal_lifetimes(void){
 matches(0,true);matches(owners[0],false);matches(owners[1],false);
 CHECK(P(scheduler_switch_to)(owners[0])==101);matches(owners[0],true);matches(owners[1],false);matches(0,false);
 CHECK(P(scheduler_switch_to)(owners[1])==102);matches(owners[1],true);matches(owners[0],false);
 CHECK(P(scheduler_deschedule_current)()==owners[1]);matches(0,true);
 CHECK(P(scheduler_switch_to)(owners[0])==101&&P(fault_current)(14,0,0x01000000,0xdead)==101);
 matches(0,true);matches(owners[0],false);CHECK(P(mark_reapable)(owners[0]));matches(0,true);
 CHECK(P(scheduler_switch_to)(owners[1])==102&&P(exit_current)(7)==102);
 matches(0,true);matches(owners[1],false);CHECK(P(mark_reapable)(owners[1]));
 CHECK(P(begin_reap)(owners[1]));matches(0,true);
 CHECK(A(destroy)(spaces[1])&&C(begin_cspace_drain)(cspaces[1])&&C(destroy_cspace)(cspaces[1]));
 CHECK(P(finalize_reap)(owners[1]));matches(owners[1],false);matches(0,true);
 cspaces[1]=C(create_cspace)(1);CHECK(cspaces[1]&&M(set_quota_for_owner)(cspaces[1],8));
 spaces[1]=A(create_native_for_owner)(cspaces[1]);CHECK(spaces[1]);
 uint64_t fresh=P(install_for_owner)(1,202,domain,spaces[1],cspaces[1],0x8000,0x01000000,0x01400000);
 CHECK(fresh&&fresh!=owners[1]);CHECK(!P(scheduler_switch_to)(owners[1]));matches(0,true);
 CHECK(P(scheduler_switch_to)(fresh)==202);matches(fresh,true);matches(owners[1],false);
 P(CURRENT_PROCESS)=owners[1];CHECK(!P(current_process_handle)());matches(0,false);matches(owners[1],false);matches(fresh,false);
 P(CURRENT_PROCESS)=fresh;matches(fresh,true);CHECK(P(scheduler_deschedule_current)()==fresh);matches(0,true);
 reap_ready(fresh,spaces[1],cspaces[1]);
 puts("real install/switch/deschedule/fault/exit/two-phase reap/generation reuse: PASS");
}
#endif
int main(int argc,char **argv){
 CHECK(argc==2);
#ifdef LEGACY_BEFORE_ONLY
 CHECK(!strcmp(argv[1],"legacy"));setup();legacy_ambiguities();
 printf("Original lossy getter ambiguity witness: PASS (%u checks; image calls=%u)\n",checks,image_calls);
#else
 CHECK(!strcmp(argv[1],"candidate"));matches(0,false);matches(UINT64_MAX,false);
 P(INITIALIZED)=2;matches(0,false);P(INITIALIZED)=0;
 setup();legacy_ambiguities();corruption_controls();legal_lifetimes();CHECK(!image_calls);
 printf("Native current process identity: PASS (%u checks; image calls=%u)\n",checks,image_calls);
#endif
 return 0;
}
'''


def identity(path):
    path = Path(path).resolve(strict=True)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def allocated_sections(path):
    raw = Path(path).read_bytes()
    if raw[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", raw, 18)[0] != 62:
        raise ValueError("requires a little-endian ELF64 x86 object")
    offset = struct.unpack_from("<Q", raw, 40)[0]
    stride, count = struct.unpack_from("<HH", raw, 58)
    if stride != 64 or offset + count * stride > len(raw):
        raise ValueError("invalid ELF section table")
    result = []
    for i in range(count):
        h = struct.unpack_from("<IIQQQQIIQQ", raw, offset + i * stride)
        if h[2] & 2:
            data = b"" if h[1] == 8 else raw[h[4]:h[4] + h[5]]
            if h[1] != 8 and len(data) != h[5]:
                raise ValueError("truncated allocated section")
            result.append((h[1], h[2], h[5], h[8], hashlib.sha256(data).hexdigest()))
    return result


def carrier():
    declarations, views = [], []
    for name, (kind, count) in FIELDS.items():
        declarations.append(f"extern {kind} P({name})" + (f"[{count}]" if count else "") + " __attribute__((aligned(8)));")
        views.append(f"{{&P({name}),sizeof P({name})}}")
    return HARNESS.replace("/* FIELD_DECLARATIONS */", "\n".join(declarations)).replace("/* FIELD_VIEWS */", ",".join(views))


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64", "native carrier requires Linux x86_64")
class ProcessCurrentIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
        selected = [compiler, *[shutil.which(n) for n in ("clang", "objcopy", "nm")]]
        if any(x is None or not Path(x).is_file() for x in selected):
            if os.environ.get("OCORE_PROCESS_IDENTITY_REQUIRED") == "1":
                raise AssertionError("already-built ocorec, clang, objcopy and nm are required")
            raise unittest.SkipTest("already-built ocorec, clang, objcopy and nm are required")
        cls.compiler, cls.clang, cls.objcopy, cls.nm = [Path(x).resolve(strict=True) for x in selected]
        expected = os.environ.get("OCOREC_BIN_SHA256")
        if expected and identity(cls.compiler)["sha256"] != expected:
            raise AssertionError("selected compiler SHA-256 mismatch")
        output = os.environ.get("OCORE_PROCESS_IDENTITY_TEST_OUTPUT")
        cls.temporary = None if output else tempfile.TemporaryDirectory(prefix="process-current-identity-")
        cls.out = Path(output) if output else Path(cls.temporary.name)
        if output:
            cls.out.mkdir(parents=False, exist_ok=False)
        cls.sources = [ROOT / "ocore/runtime/x86_64" / (n + ".oc") for n in MODULES]
        cls.before = [identity(x) for x in [*cls.sources, Path(__file__)]]
        cls.tools = [identity(x) for x in (cls.compiler, cls.clang, cls.objcopy, cls.nm, Path(sys.executable))]
        cls.commands = []
        cls.report = {"schema": "ostadix.process-current-identity/v1", "sources_before": cls.before,
                      "tools": cls.tools, "compiler_scope": os.environ.get("OCORE_PROCESS_IDENTITY_COMPILER_SCOPE", "exact selected executable; build provenance must be qualified separately"),
                      "scope": __doc__, "commands": cls.commands, "native_fp_admission": False,
                      "kernel_or_smp_execution": False, "original_runtime_lowering": False}
        cls.original = cls.sources[-1].read_text()
        actual_fields = re.findall(r"(?m)^static mut (\w+):", cls.original)
        if set(actual_fields) != set(FIELDS) or len(actual_fields) != len(FIELDS):
            raise AssertionError("all production process fields must be snapshotted")
        for source in cls.sources:
            copied = cls.out / "source" / source.relative_to(ROOT)
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copied)
        (cls.out / "provider.oc").write_text(PROVIDER)
        (cls.out / "harness.c").write_text(carrier())
        cls.compile_and_link("candidate", cls.sources)

    @classmethod
    def run_command(cls, label, argv, success=True):
        start = time.monotonic()
        result = subprocess.run(list(map(str, argv)), cwd=cls.out, capture_output=True, timeout=120)
        out, err = cls.out / (label + ".stdout"), cls.out / (label + ".stderr")
        out.write_bytes(result.stdout)
        err.write_bytes(result.stderr)
        cls.commands.append({"label": label, "argv": list(map(str, argv)), "returncode": result.returncode,
                             "seconds": time.monotonic() - start, "stdout": identity(out), "stderr": identity(err)})
        if success and result.returncode != 0:
            raise AssertionError(f"{label}: exit {result.returncode}: {(result.stdout + result.stderr).decode(errors='replace')}")
        if not success:
            mismatch = re.fullmatch(
                rb"identity query expected=[0-9a-f]{16} result=([01]) observed=([01])\n",
                result.stderr,
            )
            if result.returncode != 93 or mismatch is None or mismatch[1] == mismatch[2]:
                raise AssertionError(
                    f"{label}: expected semantic query mismatch exit93, got "
                    f"{result.returncode}: {result.stderr.decode(errors='replace')}"
                )
        return result

    @classmethod
    def compile_and_link(cls, label, sources, legacy=False):
        obj, visible = cls.out / (label + ".o"), cls.out / (label + "-visible.o")
        cls.run_command(label + "-compile", [cls.compiler, cls.out / "provider.oc", *sources,
                                    "--target", "x86_64-unknown-none", "--emit", "obj", "-o", obj])
        undefined = cls.run_command(label + "-undefined", [cls.nm, "-u", obj]).stdout.decode()
        if {line.split()[-1] for line in undefined.splitlines()} != {
            "ocore_current_cr3", "ocore_management_cr3", "ocore_kernel_p1_address",
            "unavailable_image_length", "unavailable_image_read", "unavailable_image_release",
        }:
            raise AssertionError("unexpected external implementation in registry closure")
        cls.run_command(label + "-test-visibility", [cls.objcopy, *["--globalize-symbol=" + PREFIX + n for n in FIELDS], obj, visible])
        if allocated_sections(obj) != allocated_sections(visible):
            raise AssertionError("private symbol visibility changed allocated production bytes")
        flags = ["-DLEGACY_BEFORE_ONLY=1"] if legacy else []
        cls.run_command(label + "-link", [cls.clang, "-O2", "-fno-pie", "-no-pie", *flags,
                                 cls.out / "harness.c", visible, "-o", cls.out / label])

    @classmethod
    def tearDownClass(cls):
        cls.report["sources_after"] = [identity(x) for x in [*cls.sources, Path(__file__)]]
        cls.report["tools_after"] = [identity(x["path"]) for x in cls.tools]
        cls.report["inputs_unchanged"] = cls.before == cls.report["sources_after"] and cls.tools == cls.report["tools_after"]
        cls.report["artifacts"] = [identity(x) for x in sorted(cls.out.rglob("*")) if x.is_file()]
        (cls.out / "result.json").write_text(json.dumps(cls.report, indent=2) + "\n")
        if not cls.report["inputs_unchanged"]:
            raise AssertionError("source or selected tools changed during native qualification")
        if cls.temporary:
            cls.temporary.cleanup()

    def test_production_current_identity_and_read_only_lifecycle(self):
        result = self.run_command("candidate-native", [self.out / "candidate", "candidate"])
        self.assertIn(b"Native current process identity: PASS", result.stdout)
        self.assertIn(b"image calls=0", result.stdout)
        self.assertIn(b"generation reuse: PASS", result.stdout)

    def test_original_getter_ambiguity_is_not_authenticated_absence(self):
        start = self.original.index("// Read-only identity check for serialized lifecycle observations.")
        end = self.original.index("pub unsafe fn current_process_handle()", start)
        baseline = self.out / "before-process.oc"
        baseline.write_text(self.original[:start] + self.original[end:])
        self.compile_and_link("before", [*self.sources[:-1], baseline], legacy=True)
        result = self.run_command("before-native", [self.out / "before", "legacy"])
        self.assertEqual(result.stdout.count(b"legacy getter:"), 5)
        self.assertIn(b"Original lossy getter ambiguity witness: PASS", result.stdout)
        self.report["before_control"] = "Original production process bytes with only the newly added query/comment removed; no absent-symbol link failure is counted as a semantic result."

    def test_incorrect_queries_fail_actual_native_oracle(self):
        start = self.original.index("pub unsafe fn current_process_matches(expected_handle: u64) -> bool {")
        end = self.original.index("\npub unsafe fn current_process_handle()", start)
        correct = self.original[start:end]
        mutants = {
            "lossy-getter": "pub unsafe fn current_process_matches(expected_handle: u64) -> bool {\n    if INITIALIZED != 1 { return false; }\n    return current_process_handle() == expected_handle;\n}\n",
            "nonzero-init": correct.replace("INITIALIZED != 1", "INITIALIZED == 0"),
            "missing-generation": correct.replace("current = checked_process(expected_handle);", "current = process_index(expected_handle);"),
            "duplicate-running": correct.replace("        if STATES[slot] == PROCESS_RUNNING && slot != current {\n            return false;\n        }\n", ""),
        }
        for label, changed in mutants.items():
            with self.subTest(label=label):
                self.assertNotEqual(changed, correct)
                mutant = self.out / (label + ".oc")
                mutant.write_text(self.original[:start] + changed + self.original[end:])
                self.compile_and_link(label, [*self.sources[:-1], mutant])
                self.run_command(label + "-rejected", [self.out / label, "candidate"], success=False)

    def test_target_mir_accepts_current_query_on_all_primary_isas(self):
        for isa in ["x86_64", "aarch64", "riscv64"]:
            with self.subTest(isa=isa):
                output = self.out / (isa + ".mir")
                self.run_command(isa + "-mir", [self.compiler, self.out / "provider.oc", *self.sources,
                                      "--target", isa + "-unknown-none", "--emit", "mir", "-o", output])
                self.assertIn(b"current_process_matches", output.read_bytes())


if __name__ == "__main__":
    unittest.main()
