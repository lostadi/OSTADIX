"""Reference-first whole original C TLS/threading execution on three Linux ISAs.

Whole genuine target-native Clang LL/BC modules are retained. A separately
identified Clang-built carrier creates real musl pthreads; no thread pointer,
TLS allocator, libc provider or runtime is manufactured in this test. Dynamic
DSO/dlopen and native OSTADIX execution are outside this static nonpreemptive
Linux execution profile. Whole compiler/provider lowering remains unqualified.
OCORE_TEST_TLS_REFERENCE_ONLY=1 retains the genuine Clang baseline independently;
otherwise the complete LL/BC units also pass through O-core and explicit TLS
profile admission. OCOREC selects the frozen compiler under test.
"""
import ctypes as C
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS
from tests import test_ocore_native_eh_execution as providers
from tests import test_ocore_native_weak as weak

MASK = (1 << 64) - 1
STEPS = 32
MODE_NAMES = {1: "general_dynamic", 2: "local_dynamic", 3: "initial_exec", 4: "local_exec"}
TLS_PROFILE = "linux-elf-static-nonpreemptive-v1"
JSON_TLS_PROFILE = "linux_elf_static_nonpreemptive_v1"
C_SOURCE = r"""
static long long anchor = 117;
static long long cold_anchor = 707;
_Thread_local long long tls_seed = 17;
_Thread_local unsigned long tls_zero;
_Thread_local long long *tls_pointer = &anchor;
_Thread_local __attribute__((aligned(64))) long long tls_aligned = 41;
struct __attribute__((packed)) Blob {
    unsigned char tag;
    long long number;
    long long *pointer;
    unsigned char tail[3];
};
_Thread_local struct Blob tls_blob = {9, 51, &anchor, {1,2,3}};
_Thread_local __attribute__((tls_model("initial-exec"))) long long tls_ie = 73;
_Thread_local __attribute__((tls_model("local-exec"))) long long tls_le = 89;
_Thread_local __attribute__((tls_model("global-dynamic"))) long long tls_gd = 97;
_Thread_local __attribute__((tls_model("local-dynamic"))) long long tls_ld = 101;
static _Thread_local long long cold_tls = 303;
extern void tls_observe(long long);
extern long long tls_observed(void);
void tls_snapshot(unsigned long *out) {
    out[0]=tls_seed; out[1]=tls_zero; out[2]=tls_aligned; out[3]=tls_blob.number;
    out[4]=tls_blob.tag; out[5]=tls_blob.tail[0]; out[6]=tls_blob.tail[1]; out[7]=tls_blob.tail[2];
    out[8]=tls_pointer==&anchor; out[9]=*tls_pointer;
    out[10]=tls_ie; out[11]=tls_le; out[12]=tls_gd; out[13]=tls_ld;
    out[14]=tls_blob.pointer==&anchor; out[15]=*tls_blob.pointer;
}
void tls_addresses(unsigned long *out) {
    out[0]=(unsigned long)&tls_seed; out[1]=(unsigned long)&tls_zero;
    out[2]=(unsigned long)&tls_pointer; out[3]=(unsigned long)&tls_aligned;
    out[4]=(unsigned long)&tls_blob; out[5]=(unsigned long)&tls_ie;
    out[6]=(unsigned long)&tls_le; out[7]=(unsigned long)&tls_gd;
    out[8]=(unsigned long)&tls_ld; out[9]=(unsigned long)tls_pointer;
}
__attribute__((noinline)) long long tls_step(long long tag,
    long long a1,long long a2,long long a3,long long a4,long long a5,
    long long a6,long long a7,long long a8,long long a9,long long a10,
    long long a11,long long a12,long long a13,long long a14,long long a15) {
    long long sum=a1+2*a2+3*a3+4*a4+5*a5+6*a6+7*a7+8*a8+9*a9+10*a10+
        11*a11+12*a12+13*a13+14*a14+15*a15;
    tls_seed+=sum+tag;
    tls_zero^=(unsigned long)(2*sum+tag);
    tls_aligned+=3*sum+tag;
    tls_blob.number+=5*sum-tag;
    tls_blob.tag=(unsigned char)(tls_blob.tag+tag);
    tls_blob.tail[2]=(unsigned char)tag;
    ++tls_ie; tls_le+=2; tls_gd+=3; tls_ld+=4;
    tls_pointer=(tag&1)?&tls_seed:&anchor;
    tls_observe(tag);
    return tls_seed+(long long)tls_zero+tls_aligned+tls_blob.number+
        tls_blob.tag+tls_blob.tail[2]+*tls_pointer+tls_ie+tls_le+tls_gd+tls_ld+tls_observed();
}
// Cold definitions and their TLS/non-TLS references remain in every whole input.
long long tls_cold_unused(void) { return cold_tls+cold_anchor; }
"""


def initial():
    return [17, 0, 41, 51, 9, 1, 2, 3, 1, 117, 73, 89, 97, 101, 1, 117]


def vectors(worker):
    state, result = initial(), []
    for iteration in range(1, STEPS + 1):
        tag = worker * 31 + iteration
        args = [worker * 100 + iteration * 13 + index * 5 for index in range(1, 16)]
        total = sum(index * value for index, value in enumerate(args, 1))
        state[0] += total + tag
        state[1] ^= 2 * total + tag
        state[2] += 3 * total + tag
        state[3] += 5 * total - tag
        state[4] = (state[4] + tag) & 255
        state[7] = tag & 255
        state[8] = int(not (tag & 1))
        state[9] = state[0] if tag & 1 else 117
        for index, increment in enumerate((1, 2, 3, 4), 10): state[index] += increment
        value = sum([*state[:5], state[7], state[9], *state[10:14], tag])
        result.append({"tag": tag, "args": args, "result": value, "snapshot": list(state)})
    return result


def golden():
    digest, checks = 0xcbf29ce484222325, 0
    # Deterministic collection follows joins, so scheduler order is irrelevant.
    values = [*initial()]
    for worker in (1, 2):
        values.extend(initial())
        for vector in vectors(worker): values.extend([vector["result"], *vector["snapshot"]])
    values.extend(initial())
    values.extend([1] * 11)  # simultaneous address distinctness/alignment/provider identity
    for value in values:
        digest = ((digest ^ value) * 0x100000001b3) & MASK
        checks += 1
    return f"OCORE-TLS-REFERENCE digest={digest:016x} checks={checks}\n".encode()


def carrier():
    rows = []
    for worker in (1, 2):
        items = ["{%d,{%s},%d,{%s}}" %
                 (v["tag"], ",".join(map(str, v["args"])), v["result"], ",".join(map(str, v["snapshot"])))
                 for v in vectors(worker)]
        rows.append("{" + ",\n".join(items) + "}")
    return r"""
#include <pthread.h>
#include <stdio.h>
extern void tls_snapshot(unsigned long *);
extern void tls_addresses(unsigned long *);
extern long long tls_step(long long,long long,long long,long long,long long,long long,
    long long,long long,long long,long long,long long,long long,long long,long long,long long,long long);
static _Thread_local long long carrier_observed;
void tls_observe(long long value) { carrier_observed=value; }
long long tls_observed(void) { return carrier_observed; }
struct Vector { long long tag,args[15],result; unsigned long snapshot[16]; };
static const struct Vector expected[2][32] = {
""" + ",\n".join(rows) + r"""
};
struct Worker {
    unsigned id;
    unsigned long before[16],addresses[10],after[32][16];
    long long results[32];
    int failure;
};
static pthread_barrier_t ready;
static void *worker(void *argument) {
    struct Worker *w=(struct Worker *)argument;
    tls_snapshot(w->before); tls_addresses(w->addresses);
    int status=pthread_barrier_wait(&ready);
    if(status && status!=PTHREAD_BARRIER_SERIAL_THREAD) { w->failure=1; return 0; }
    for(unsigned j=0;j<32;++j) {
        const struct Vector *v=&expected[w->id-1][j]; const long long *a=v->args;
        w->results[j]=tls_step(v->tag,a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],
            a[8],a[9],a[10],a[11],a[12],a[13],a[14]);
        tls_snapshot(w->after[j]);
    }
    return 0;
}
static unsigned long long digest=0xcbf29ce484222325ULL,checks;
static int add(unsigned long got,unsigned long expected) {
    if(got!=expected) return 31;
    digest=(digest^got)*0x100000001b3ULL; ++checks; return 0;
}
static const unsigned long template_values[16]={17,0,41,51,9,1,2,3,1,117,73,89,97,101,1,117};
int main(void) {
    struct Worker workers[2]={{.id=1},{.id=2}};
    pthread_t threads[2]; unsigned long main_before[16],main_after[16],addresses[10];
    tls_snapshot(main_before); tls_addresses(addresses);
    if(pthread_barrier_init(&ready,0,3)) return 41;
    for(unsigned i=0;i<2;++i) if(pthread_create(&threads[i],0,worker,&workers[i])) return 42;
    int status=pthread_barrier_wait(&ready);
    if(status && status!=PTHREAD_BARRIER_SERIAL_THREAD) return 43;
    for(unsigned i=0;i<2;++i) if(pthread_join(threads[i],0) || workers[i].failure) return 44;
    if(pthread_barrier_destroy(&ready)) return 45;
    tls_snapshot(main_after);
    for(unsigned j=0;j<16;++j) if(add(main_before[j],template_values[j])) return 31;
    for(unsigned i=0;i<2;++i) {
        for(unsigned j=0;j<16;++j) if(add(workers[i].before[j],template_values[j])) return 31;
        for(unsigned k=0;k<32;++k) {
            long long wanted=expected[i][k].result;
#ifdef CORRUPT_ORACLE
            if(i==0 && k==0) ++wanted;
#endif
            if(add(workers[i].results[k],wanted)) return 31;
            for(unsigned j=0;j<16;++j) if(add(workers[i].after[k][j],expected[i][k].snapshot[j])) return 31;
        }
    }
    for(unsigned j=0;j<16;++j) if(add(main_after[j],template_values[j])) return 31;
    // All three thread contexts were live at the barrier. TLS objects must have
    // distinct addresses and the requested alignment; the ordinary-global
    // pointer initializer must identify the same provider object in each.
    for(unsigned j=0;j<9;++j) {
        int distinct=addresses[j]!=workers[0].addresses[j] && addresses[j]!=workers[1].addresses[j] &&
            workers[0].addresses[j]!=workers[1].addresses[j];
        if(add(distinct,1)) return 31;
    }
    if(add(!(addresses[3]&63) && !(workers[0].addresses[3]&63) && !(workers[1].addresses[3]&63),1)) return 31;
    if(add(addresses[9]==workers[0].addresses[9] && addresses[9]==workers[1].addresses[9],1)) return 31;
    printf("OCORE-TLS-REFERENCE digest=%016llx checks=%llu\n",digest,checks);
    return 0;
}
"""


class NativeTlsExecutionTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    bind = providers.NativeEhExecutionTests.bind
    original_record = providers.NativeEhExecutionTests.original_record
    profile = providers.NativeEhExecutionTests.profile
    emulators = providers.NativeEhExecutionTests.emulators
    object_identity = providers.NativeEhExecutionTests.object_identity
    original_inventory = providers.NativeEhExecutionTests.original_inventory

    def setUp(self):
        # Reuse exact immutable provider admission for reference objects only.
        providers.NativeEhExecutionTests.setUp(self)
        retained = os.environ.get("OCORE_TEST_NATIVE_TLS_EXECUTION_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-tls-reference-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)

    def tls_inventory(self, source):
        a = self.library
        get_mode = a.lib.LLVMGetThreadLocalMode
        get_mode.restype, get_mode.argtypes = C.c_int, [importer.P]
        context, module, error, message = a.ContextCreate(), importer.P(), importer.P(), importer.P()
        buffer = None
        try:
            data = source.read_bytes()
            buffer = a.CreateMemoryBufferWithMemoryRangeCopy(data, len(data), b"original-tls-census")
            parsed = a.ParseIRInContext2(context, buffer, C.byref(module), C.byref(error))
            self.assertEqual(parsed, 0, C.string_at(error).decode() if error else "LLVM parse failed")
            self.assertEqual(a.VerifyModule(module, 2, C.byref(message)), 0)
            rows = []
            for value in a.sequence(a.GetFirstGlobal, a.GetNextGlobal, module):
                if a.IsThreadLocal(value):
                    rows.append({"name": a.name(value), "model": MODE_NAMES[get_mode(value)],
                                 "alignment": a.GetAlignment(value), "has_initializer": bool(a.GetInitializer(value))})
            return rows
        finally:
            if error: a.DisposeMessage(error)
            if message: a.DisposeMessage(message)
            if module: a.DisposeModule(module)
            if buffer: a.DisposeMemoryBuffer(buffer)
            a.ContextDispose(context)

    def whole_module(self, source, target, original, tls):
        output = source.with_name(source.name+".native.json")
        receipt = source.with_name(source.name+".verified.json")
        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target,
                      "--tls-profile", TLS_PROFILE, "--emit", "mir", "-o", output])
        self.command([self.compiler, output, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
        module = json.loads(output.read_text())
        self.assertEqual(module["target"]["tls_profile"], JSON_TLS_PROFILE)
        for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual({item["name"] for item in module[plural]}, set(original[plural]))
            self.assertEqual(module["provenance"]["source_"+singular+"_count"], len(original[plural]))
        self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None}, set(original["definitions"]))
        self.assertEqual(module["provenance"]["input_sha256"], self.bind(source)["sha256"])
        self.assertEqual(json.loads(receipt.read_text())["module_sha256"], self.bind(output)["sha256"])
        originals = {row["name"]: row for row in tls}
        self.assertEqual({g["name"] for g in module["globals"] if g["thread_local"]}, set(originals))
        for global_ in module["globals"]:
            if global_["name"] in originals:
                source_global = originals[global_["name"]]
                self.assertEqual(global_["tls_model"], source_global["model"], "source TLS access model must not be replaced")
                self.assertEqual(global_["alignment"], source_global["alignment"])
                self.assertEqual(global_["initializer"] is not None, source_global["has_initializer"])
            else:
                self.assertFalse(global_["thread_local"])
                self.assertIsNone(global_.get("tls_model"))
        step = next(f for f in module["functions"] if f["name"] == "tls_step")
        self.assertEqual(len(step["signature"]["params"]), 16)
        addressed = [i["operation"]["global"] for f in module["functions"] for b in f["blocks"]
                     for i in b["instructions"] if i["operation"]["op"] == "thread_local_address"]
        self.assertEqual(set(addressed), set(originals), "cold TLS references and bodies must also survive")
        return module, {"module": self.bind(output), "verification": self.bind(receipt),
                        "whole_function_definitions": len(original["definitions"]),
                        "whole_globals": len(original["globals"]), "tls_address_operation_count": len(addressed)}

    def admission_controls(self, original, target, module):
        controls = []
        expected_diagnostics = {
            "implicit_profile": "TLS globals require explicit --tls-profile",
            "unknown_profile": "invalid value 'linux-dynamic-v1' for '--tls-profile",
            "missing_native_profile": "TLS storage requires an explicit native TLS profile and original access model",
            "unknown_native_profile": "unknown variant `linux_dynamic_v1`",
            "non_linux_profile": "native TLS profile requires Linux",
            "missing_source_model": "TLS storage requires an explicit native TLS profile and original access model",
            "unknown_source_model": "unknown variant `emulated`",
            "ordinary_storage_with_tls_model": "TLS access model requires thread-local storage",
            "missing_tls_storage": "current-thread address requires an included TLS global",
            "ordinary_current_thread_address": "current-thread address requires an included TLS global",
            "ordinary_symbol_tls_address": "TLS symbol address requires a current-thread address operation",
            "static_tls_address_in_template": "initializer cannot contain a static address of TLS storage",
            "non_pointer_tls_address_result": "current-thread address result requires an address-space-zero pointer",
        }
        for label, flags in (("implicit_profile", []), ("unknown_profile", ["--tls-profile", "linux-dynamic-v1"])):
            output = original.with_name(original.name+"."+label+".json")
            result = self.command([self.compiler, original, "--input-kind", "llvm-ir", "--target", target,
                                   *flags, "--emit", "mir", "-o", output], success=False)
            self.assertNotEqual(result.returncode, 0, "profile admission must fail closed")
            self.assertIn(expected_diagnostics[label], result.stderr.decode())
            self.assertFalse(output.exists(), "rejected profile must not publish an artifact")
            controls.append({"case": label, "exit_code": result.returncode, "diagnostic": result.stderr.decode(),
                             "expected_diagnostic": expected_diagnostics[label]})

        def clone(): return json.loads(json.dumps(module))

        def address(value):
            return next(i for f in value["functions"] for b in f["blocks"] for i in b["instructions"]
                        if i["operation"]["op"] == "thread_local_address")

        cases = []
        invalid = clone(); invalid["target"].pop("tls_profile"); cases.append(("missing_native_profile", invalid))
        invalid = clone(); invalid["target"]["tls_profile"] = "linux_dynamic_v1"; cases.append(("unknown_native_profile", invalid))
        invalid = clone(); invalid["target"]["triple"] = invalid["target"]["triple"].split("-", 1)[0]+"-unknown-none"
        cases.append(("non_linux_profile", invalid))
        invalid = clone(); next(g for g in invalid["globals"] if g["thread_local"]).pop("tls_model")
        cases.append(("missing_source_model", invalid))
        invalid = clone(); next(g for g in invalid["globals"] if g["thread_local"])["tls_model"] = "emulated"
        cases.append(("unknown_source_model", invalid))
        invalid = clone(); next(g for g in invalid["globals"] if not g["thread_local"])["tls_model"] = "local_exec"
        cases.append(("ordinary_storage_with_tls_model", invalid))
        invalid = clone(); address(invalid)["operation"]["global"] = "missing_tls_storage"
        cases.append(("missing_tls_storage", invalid))
        invalid = clone(); ordinary = next(g["name"] for g in invalid["globals"] if not g["thread_local"])
        address(invalid)["operation"]["global"] = ordinary; cases.append(("ordinary_current_thread_address", invalid))
        invalid = clone(); instruction = address(invalid)
        instruction["operation"] = {"op": "freeze", "value": {"kind": "symbol", "ty": instruction["result"]["ty"],
                                                               "name": "tls_seed"}}
        cases.append(("ordinary_symbol_tls_address", invalid))
        invalid = clone(); pointer = next(g for g in invalid["globals"] if g["name"] == "tls_pointer")
        pointer["initializer"]["relocations"][0]["symbol"] = "tls_seed"
        cases.append(("static_tls_address_in_template", invalid))
        invalid = clone(); address(invalid)["result"]["ty"] = next(i for i, t in enumerate(invalid["types"])
                                                                  if t["kind"] == "int" and t["bits"] == 64)
        cases.append(("non_pointer_tls_address_result", invalid))
        for label, invalid in cases:
            path = original.with_name(original.name+".negative-"+label+".json")
            path.write_text(json.dumps(invalid, indent=2)+"\n")
            result = self.command([self.compiler, path, "--input-kind", "native-ir", "--verify-native"], success=False)
            self.assertNotEqual(result.returncode, 0, "negative native TLS contract must be rejected: " + label)
            diagnostic = result.stderr.decode()
            self.assertIn(expected_diagnostics[label], diagnostic, "the intended TLS guard must reject: " + label)
            schema_valid = label not in {"unknown_native_profile", "unknown_source_model"}
            if schema_valid:
                self.assertNotIn("invalid native module:", diagnostic,
                                 "schema-valid semantic negative must reach native verification: " + label)
            controls.append({"case": label, "input": self.bind(path), "exit_code": result.returncode,
                             "schema_valid": schema_valid, "expected_diagnostic": expected_diagnostics[label],
                             "diagnostic": diagnostic})
        return controls

    def tls_object(self, obj, machine, module):
        self.object_identity(obj, machine)
        decoded = providers.eh_objects.Elf(obj.read_bytes())
        rows = []
        for global_ in module["globals"]:
            symbol = decoded.named[global_["name"]]
            self.assertEqual(symbol["info"] & 15, 6 if global_["thread_local"] else 1,
                             "actual ELF symbol storage class must preserve source TLS")
            if not global_["thread_local"]: continue
            self.assertNotEqual(symbol["section"], 0)
            section = decoded.sections[symbol["section"]]
            self.assertTrue(section["flags"] & 0x400, "TLS storage requires actual SHF_TLS")
            self.assertEqual(symbol["value"] % global_["alignment"], 0)
            self.assertEqual(symbol["size"], len(global_["initializer"]["bytes"]))
            if global_["name"] == "tls_zero": self.assertEqual(section["kind"], 8, "zero TLS must use a genuine NOBITS template")
            rows.append({"name": global_["name"], "symbol_type": "STT_TLS", "section": section["name"],
                         "section_alignment": section["alignment"], "bytes": symbol["size"], "model": global_["tls_model"]})
        self.assertEqual(len(rows), 10)
        return rows

    def test_whole_original_c_tls_threaded_reference_and_own_all_three(self):
        emulators = self.emulators()
        source = self.directory/"whole-tls.c"; source.write_text(C_SOURCE)
        driver = self.directory/"thread-carrier.c"; driver.write_text(carrier())
        snapshot = self.directory/"test-source-snapshot.py"; snapshot.write_bytes(Path(__file__).read_bytes())
        helper_snapshots = []
        helper_directory = self.directory/"helper-source-snapshots"; helper_directory.mkdir()
        for module in (providers, weak, importer, providers.eh_objects, providers.census,
                       weak.baseline, weak.promises, weak.memory, weak.native, weak.capture_qa):
            original_helper = Path(module.__file__).resolve()
            copied = helper_directory/(module.__name__.replace(".", "_")+".py")
            copied.write_bytes(original_helper.read_bytes())
            original_record, copied_record = self.bind(original_helper), self.bind(copied)
            self.assertEqual(original_record["sha256"], copied_record["sha256"])
            helper_snapshots.append({"module": module.__name__, "original": original_record, "snapshot": copied_record})
        for path in [source, driver, snapshot, __file__, self.compiler, self.sdk/"clang", self.sdk/"llvm-as", self.linker,
                     importer.discover_library(), *emulators.values()]: self.bind(path)
        reference_only = os.environ.get("OCORE_TEST_TLS_REFERENCE_ONLY") == "1"
        report = {"scope": "whole original C TLS compiler conformance with genuine musl pthreads; static nonpreemptive Linux profile",
                  "ocore_tls_execution_qualified": False, "provider_modules_lowered": False,
                  "full_rust_compiler_complete": False, "dependency_closure_complete": False,
                  "dynamic_dso_dlopen_qualified": False, "native_ostadix_qualified": False,
                  "physical_silicon_qualified": False, "steps_per_worker": STEPS, "worker_count": 2,
                  "reference_only": reference_only, "original_tls_models_retained": True,
                  "realization_profile": TLS_PROFILE, "compiler": self.bind(self.compiler),
                  "test_source": self.bind(snapshot),
                  "helper_source_snapshots": helper_snapshots,
                  "golden_stdout": golden().decode(), "targets": {}, "passed": False,
                  "process_environment": {key: os.environ.get(key) for key in
                      ("PATH", "LD_LIBRARY_PATH", "OCOREC", "OCORE_TEST_LLVM22_BIN", "LD_LLD",
                       "OCORE_TEST_QEMU_AARCH64", "OCORE_TEST_QEMU_RISCV64", "OCORE_TEST_REQUIRE_ALL_ISAS",
                       "OCORE_TEST_TLS_REFERENCE_ONLY")}}
        report_path = self.directory/"report.json"
        try:
            for isa, (target, _, machine, _) in TARGETS.items():
                with self.subTest(isa=isa):
                    cpp_args, _ = self.profile(isa)
                    args = [item for item in cpp_args if item not in
                            {"-nostdlib++", "-nostdinc++", "-std=c++14", "-frtti"}]
                    args += ["-std=c11", "-pthread"]
                    if isa == "riscv64": args += ["-march=rv64gc", "-mabi=lp64d"]
                    inputs = []
                    for suffix, mode in (("ll", "-S"), ("bc", "-c")):
                        path = self.directory/(isa+"-whole."+suffix)
                        self.command([self.sdk/"clang", *args, "-emit-llvm", mode, source, "-o", path])
                        self.bind(path); inputs.append(path)
                    carriers = {}
                    for corrupt in (False, True):
                        obj = self.directory/(isa+"-carrier"+("-corrupt" if corrupt else "")+".o")
                        self.command([self.sdk/"clang", *args, *(["-DCORRUPT_ORACLE=1"] if corrupt else []),
                                      "-c", driver, "-o", obj])
                        self.object_identity(obj, machine); self.bind(obj); carriers[corrupt] = obj
                    rows = report["targets"].setdefault(isa, [])
                    for original in inputs:
                        whole, tls = self.original_inventory(original), self.tls_inventory(original)
                        self.assertEqual(set(row["model"] for row in tls), set(MODE_NAMES.values()))
                        self.assertEqual(len(tls), 10)
                        self.assertEqual(next(x["alignment"] for x in tls if x["name"] == "tls_aligned"), 64)
                        self.assertIn("tls_cold_unused", whole["definitions"])
                        row = {"input": self.bind(original), "whole_original_inventory": whole,
                               "original_tls_models": tls, "executions": {}}
                        rows.append(row)
                        obj = original.with_name(original.name+".clang.o")
                        self.command([self.sdk/"clang", *args, "-c", original, "-o", obj])
                        self.object_identity(obj, machine); self.bind(obj)
                        for own in (False, True):
                            if own:
                                if reference_only: continue
                                module, normalized = self.whole_module(original, target, whole, tls)
                                row["whole_verified_import"] = normalized
                                row["admission_controls"] = self.admission_controls(original, target, module)
                                obj = original.with_name(original.name+".own.o")
                                self.command([self.compiler, original, "--input-kind", "llvm-ir", "--target", target,
                                              "--tls-profile", TLS_PROFILE, "-o", obj])
                                self.bind(obj)
                                row["owned_elf_tls_inventory"] = self.tls_object(obj, machine, module)
                            tag = "own" if own else "reference"
                            for corrupt in (False, True):
                                binary = self.directory/(isa+"-"+original.suffix[1:]+"-"+tag+("-corrupt" if corrupt else ""))
                                trace = binary.with_suffix(".link-trace.txt")
                                link = self.command([self.sdk/"clang", *args, "-fuse-ld=lld", "--rtlib=compiler-rt", "--unwindlib=none",
                                                     "-static", "-no-pie", "-Wl,--trace", "-Wl,--why-extract="+str(binary)+".extract.txt",
                                                     carriers[corrupt], obj, "-o", binary])
                                trace.write_bytes(link.stdout+link.stderr); self.bind(trace); self.bind(binary)
                                selected = []
                                for line in link.stdout.decode().splitlines():
                                    path = Path(line.split("(", 1)[0]).resolve()
                                    self.assertIn(str(path), self.bound, "unbound actual provider/test-carrier input: " + line)
                                    selected.append({"artifact": self.bound[str(path)], "trace": line})
                                run = self.command(([emulators[isa]] if isa != "x86_64" else [])+[binary], success=not corrupt)
                                if corrupt: self.assertEqual(run.returncode, 31)
                                else: self.assertEqual(run.stdout, golden()); self.assertEqual(run.stderr, b"")
                                row["executions"][tag+("_corrupt" if corrupt else "")] = {
                                    "executable": self.bind(binary), "ordered_link_trace": self.bind(trace),
                                    "ordered_selected_inputs": selected, "archive_extraction": self.bind(str(binary)+".extract.txt"),
                                    "exit_code": run.returncode, "stdout": run.stdout.decode(), "stderr": run.stderr.decode()}
                    report_path.write_text(json.dumps(report, indent=2)+"\n")
            for item in list(self.bound.values()): self.bind(item["path"], item)
            self.assertEqual(set(report["targets"]), set(TARGETS))
            expected_runs = {"reference", "reference_corrupt"}
            if not reference_only: expected_runs |= {"own", "own_corrupt"}
            self.assertTrue(all(len(rows) == 2 and all(set(row["executions"]) == expected_runs for row in rows)
                                for rows in report["targets"].values()))
            if not reference_only:
                self.assertTrue(all(len(row["admission_controls"]) == 13 for rows in report["targets"].values() for row in rows))
                report["ocore_tls_execution_qualified"] = True
            report["passed"] = True
        finally:
            report["bound_inputs_providers_tools_outputs"] = list(self.bound.values())
            report["commands"] = [weak.artifact(path) for path in sorted(self.directory.glob("command-*.json"))]
            report_path.write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
