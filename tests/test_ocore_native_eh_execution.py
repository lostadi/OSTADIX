"""Whole genuine C++ EH inputs executed with original source-built providers.

The companion C++ oracle is an explicit Clang-built test carrier. No personality,
unwinder, language runtime or imported function is replaced or selected away.
Linux/musl and QEMU execution here does not qualify the full Rust compiler,
provider lowering, dependency closure, OSTADIX kernel or physical silicon.

OCORE_TEST_NATIVE_EH_EXECUTION_OUTPUT_DIR retains all inputs and command receipts.
OCORE_TEST_EH_REFERENCE_ONLY=1 runs the same-source Clang baseline first.
Providers are the immutable original full-source observations named below;
OCORE_TEST_RUNTIME_CAPTURE_ROOT may relocate their common parent directory.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest import mock

from scripts import ocore_llvm_import as importer
from scripts.check_ocore_native_equivalence import TARGETS
from tests import test_ocore_native_allocsize as census
from tests import test_ocore_native_eh_objects as eh_objects
from tests import test_ocore_native_weak as weak

ROOT = weak.ROOT
MASK = (1 << 64) - 1
MODES = (0, 1, 2, 3, 4, 8, 12)
PROVIDERS = {
    "cxxabi": ("original-libcxxabi-linux-musl-dcc36068-20261010", "whole-threaded-source-build-observation-v1.json",
               "8d8129dd993780cd29fce50f51c585c6629116dee30f27a0feae8ffd3acec609"),
    "unwind": ("original-libunwind-linux-musl-dcc36068-20261010", "whole-threaded-source-build-observation-v1.json",
               "b68e8be87c3212ee208df221a63a0cd7488af6d2a8cffcadac0c082046f2d694"),
    "musl": ("original-musl-0784374d-20261010", "whole-source-build-observation-v1.json",
             "f6df8192764741427588393d7386c6160ec92ee87b37c62edf633c0d667d3210"),
    "compiler_rt": ("original-compiler-rt-dcc36068-20261010", "whole-source-build-observation-v1.json",
                    "e8df897cccfafd452e11e459956eaad2eea158424858e4a769a7cf49d0917518"),
}

# One unchanged source is sent to each genuine target frontend. The source does
# not include target-specific assembly or a replacement exception runtime.
CPP_SOURCE = r"""
extern "C" void eh_note(long long) noexcept;
extern "C" void eh_touch(volatile unsigned char *, unsigned long) noexcept;
struct Trace {
    long long mark;
    ~Trace() noexcept { eh_note(mark); }
};
static long long pointer_marker = 117;
__attribute__((noinline)) static long long dispatch(long long mode, long long sum) {
    Trace cleanup{3000};
    if (mode == 1) throw int(sum & 255);
    if (mode == 2) throw (sum + 9000);
    if (mode == 3) throw (void *)&pointer_marker;
    return sum + 11;
}
extern "C" __attribute__((noinline)) long long eh_stress(
    long long mode, long long a1, long long a2, long long a3, long long a4,
    long long a5, long long a6, long long a7, long long a8, long long a9,
    long long a10, long long a11, long long a12, long long a13,
    long long a14, long long a15) {
    volatile unsigned char buffer[32768];
    buffer[0] = (unsigned char)a1;
    buffer[32767] = (unsigned char)(a15 + 1);
    eh_touch(buffer, sizeof(buffer));
    const long long frame = buffer[0] + buffer[16384] + buffer[32767];
    const long long sum = a1 + 2*a2 + 3*a3 + 4*a4 + 5*a5 + 6*a6 + 7*a7 +
        8*a8 + 9*a9 + 10*a10 + 11*a11 + 12*a12 + 13*a13 + 14*a14 + 15*a15;
    Trace outer{1000};
    try {
        Trace inner{2000};
        long long value = dispatch(mode & 3, sum);
        eh_note(2500);
        if (mode >= 4) value = dispatch((mode >> 2) & 3, sum + 17);
        eh_note(4000);
        return value + frame;
    } catch (int value) {
        eh_note(5000); return value + frame + 100;
    } catch (long long value) {
        eh_note(6000); return value + frame + 200;
    } catch (...) {
        eh_note(7000); return sum + frame + 300;
    }
}
extern "C" __attribute__((noinline)) long long eh_unmatched(long long sum) {
    Trace outer{9000};
    try { Trace inner{9001}; return dispatch(1, sum); }
    catch (long long value) { eh_note(9999); return value; }
}
extern "C" __attribute__((noinline)) long long eh_rethrow(long long sum) {
    Trace outer{9100};
    try { Trace inner{9101}; return dispatch(2, sum); }
    catch (const long long &) { eh_note(9102); throw; }
}
// C++14 dynamic exception specifications generate a genuine LLVM filter.
extern "C" __attribute__((noinline)) long long eh_filter(long long sum) throw(int) {
    Trace cleanup{9300};
    if (sum & 1) throw int(sum);
    return sum + 13;
}
"""


def cases():
    result = []
    for seed in range(1, 17):
        args = [seed * 13 + i * 7 for i in range(1, 16)]
        total = sum(i * value for i, value in enumerate(args, 1))
        frame = (args[0] & 255) + ((args[-1] + 1) & 255) + 5
        for mode in MODES:
            second = mode >= 4
            selected = (mode >> 2) & 3 if second else mode & 3
            payload = total + (17 if second else 0)
            events = [3000, 2500, 3000] if second else [3000]
            if selected == 0:
                events += [2500, 4000, 2000, 1000]
                value = payload + 11 + frame
            else:
                events += [2000, {1: 5000, 2: 6000, 3: 7000}[selected], 1000]
                value = {1: (payload & 255) + frame + 100,
                         2: payload + 9000 + frame + 200,
                         3: total + frame + 300}[selected]
            result.append({"kind": 0, "mode": mode, "args": args, "value": value, "events": events})
        for kind, value, events in (
                (1, (total & 255) + 400, [3000, 9001, 9000, 8000]),
                (2, total + 9900, [3000, 9101, 9102, 9100, 9200]),
                (3, seed + (700 if seed & 1 else 13), [9300, 9400] if seed & 1 else [9300])):
            result.append({"kind": kind, "mode": seed if kind == 3 else total,
                           "args": args, "value": value, "events": events})
    return result


def golden():
    digest, checks = 0xcbf29ce484222325, 0
    for case in cases():
        for value in [case["value"], len(case["events"]), *case["events"]]:
            digest = ((digest ^ value) * 0x100000001b3) & MASK
            checks += 1
    return f"OCORE-EH-STRESS digest={digest:016x} checks={checks}\n".encode()


def carrier():
    rows = []
    for case in cases():
        events = case["events"] + [0] * (8 - len(case["events"]))
        rows.append("{%d,%d,{%s},%d,%d,{%s}}" %
                    (case["kind"], case["mode"], ",".join(map(str, case["args"])),
                     case["value"], len(case["events"]), ",".join(map(str, events))))
    return r"""
#include <stdio.h>
extern "C" long long eh_stress(long long,long long,long long,long long,long long,
    long long,long long,long long,long long,long long,long long,long long,
    long long,long long,long long,long long);
extern "C" long long eh_unmatched(long long);
extern "C" long long eh_rethrow(long long);
extern "C" long long eh_filter(long long) throw(int);
static long long events[32];
static unsigned event_count;
static int bad_frame;
extern "C" void eh_note(long long value) noexcept {
    if (event_count < 32) events[event_count] = value;
    ++event_count;
}
extern "C" void eh_touch(volatile unsigned char *p, unsigned long size) noexcept {
    if (size != 32768) bad_frame = 1;
    p[16384] = 5;
}
struct Case { int kind; long long mode,args[15],value; unsigned count; long long events[8]; };
static const Case cases[] = {
""" + ",\n".join(rows) + r"""
};
static unsigned long long digest = 0xcbf29ce484222325ULL, checks;
static int add(long long got, long long expected) {
    if (got != expected) return 31;
    digest = (digest ^ (unsigned long long)got) * 0x100000001b3ULL;
    ++checks; return 0;
}
int main() {
    for (unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        const Case &c=cases[i]; event_count=0; long long got;
        const long long *a=c.args;
        if (c.kind==0) got=eh_stress(c.mode,a[0],a[1],a[2],a[3],a[4],a[5],a[6],
            a[7],a[8],a[9],a[10],a[11],a[12],a[13],a[14]);
        else if(c.kind==1) {
            try { (void)eh_unmatched(c.mode); return 41; }
            catch(int value) { eh_note(8000); got=value+400; }
        } else if(c.kind==2) {
            try { (void)eh_rethrow(c.mode); return 42; }
            catch(long long value) { eh_note(9200); got=value+900; }
        } else {
            try { got=eh_filter(c.mode); }
            catch(int value) { eh_note(9400); got=value+700; }
        }
        long long expected=c.value;
#ifdef CORRUPT_ORACLE
        if(i==0) ++expected;
#endif
        if(bad_frame || add(got,expected) || add(event_count,c.count)) return 31;
        for(unsigned j=0;j<event_count;++j) if(add(events[j],c.events[j])) return 31;
    }
    printf("OCORE-EH-STRESS digest=%016llx checks=%llu\n",digest,checks);
    return 0;
}
"""


def records(value):
    """Traverse receipts without interpreting an artifact as closure admission."""
    if isinstance(value, dict):
        if {"path", "sha256", "bytes"} <= value.keys():
            yield value
        for item in value.values():
            yield from records(item)
    elif isinstance(value, list):
        for item in value:
            yield from records(item)


class NativeEhExecutionTests(unittest.TestCase):
    setUpClass = classmethod(weak.WeakNativeTests.setUpClass.__func__)
    command = weak.WeakNativeTests.command
    emulators = census.AllocsizeNativeTests.emulators
    original_inventory = census.AllocsizeNativeTests.original_inventory

    def setUp(self):
        retained = os.environ.get("OCORE_TEST_NATIVE_EH_EXECUTION_OUTPUT_DIR")
        if retained:
            root = Path(retained).expanduser().resolve(); root.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="run-", dir=root))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="ocore-native-eh-execution-")
            self.addCleanup(temporary.cleanup); self.directory = Path(temporary.name)
        self.sequence = 0
        self.library = importer.LLVM(importer.discover_library(), importer.PINNED_SHA256)
        self.bound = {}
        base = Path(os.environ.get("OCORE_TEST_RUNTIME_CAPTURE_ROOT",
                                  str(Path.home()/".cache/ostadix-runtime-captures")))
        self.provider_bases, self.provider_records = {}, {}
        for name, (folder, filename, digest) in PROVIDERS.items():
            path = base/folder/filename
            if not path.is_file():
                reason = "original full-source provider observation unavailable: " + str(path)
                if os.environ.get("OCORE_TEST_REQUIRE_ALL_ISAS") == "1": self.fail(reason)
                self.skipTest(reason)
            value = self.bind(path)
            self.assertEqual(value["sha256"], digest, "original immutable provider receipt changed")
            self.provider_bases[name] = base/folder
            self.provider_records[name] = list(records(json.loads(path.read_text())))
            # The whole observation binds each complete build inventory by
            # digest. Final archives/startups are recorded inside that inventory.
            inventories = [item for item in self.provider_records[name]
                           if item["path"].endswith("/post-build-inventory.json")]
            for item in inventories:
                self.bind(item["path"], item)
                self.provider_records[name].extend(records(json.loads(Path(item["path"]).read_text())))

    def bind(self, path, expected=None):
        observed = weak.artifact(path)
        if expected is not None:
            self.assertEqual((observed["sha256"], observed["bytes"]),
                             (expected["sha256"], expected["bytes"]), str(path))
        prior = self.bound.setdefault(observed["path"], observed)
        self.assertEqual(prior, observed, "input/provider/tool changed during test")
        return observed

    def original_record(self, provider, path):
        path = str(Path(path).resolve())
        matching = [item for item in self.provider_records[provider] if item["path"] == path]
        self.assertTrue(matching, "artifact absent from original hash-bound provider receipt: " + path)
        self.assertEqual(len({(x["sha256"], x["bytes"]) for x in matching}), 1)
        return matching[0]

    def profile(self, isa):
        build = self.provider_bases["cxxabi"]/(isa+"-threaded-v3")/"build"
        # Bind inventories to the original observation, then every actual final
        # link input to its source-build record. Old diagnostic gaps remain gaps.
        archives = []
        for provider, filename in (("cxxabi", "libc++abi.a"), ("unwind", "libunwind.a")):
            root = self.provider_bases[provider]/(isa+"-threaded-v3")/"build"
            inventory = root/"post-build-inventory.json"
            self.bind(inventory, self.original_record(provider, inventory))
            data = json.loads(inventory.read_text())
            archive = root/"lib"/filename
            expected = next(item for item in data["runtime_outputs"] if item["path"] == str(archive))
            self.bind(archive, expected); archives.append(archive)
        sysroot, resource = build/"target-sysroot", build/"clang-resource"
        header_receipt = self.provider_bases["musl"]/(isa+"-static-v1")/"original-target-header-provenance.json"
        self.bind(header_receipt, self.original_record("cxxabi", header_receipt))
        header_records = list(records(json.loads(header_receipt.read_text())))
        self.provider_records["musl"].extend(header_records)
        for item in header_records:
            if "/build/install/include/" in item["path"]:
                self.bind(item["path"], item)
        # These paths resolve through the unchanged overlays to authentic musl
        # and compiler-rt producers. Record their original membership evidence.
        for path in sorted((sysroot/"usr/lib").glob("*")):
            if path.is_file() and path.suffix in {".a", ".o"}:
                self.bind(path, self.original_record("musl", path))
        for path in sorted((resource/"lib/linux").glob("*")):
            if path.is_file() and path.suffix in {".a", ".o"}:
                self.bind(path, self.original_record("compiler_rt", path))
        self.bind(sysroot/"usr/include/stdio.h", self.original_record("musl", sysroot/"usr/include/stdio.h"))
        return ["--target="+isa+"-unknown-linux-musl", "--sysroot="+str(sysroot),
                "-resource-dir="+str(resource), "-nostdlib++", "-nostdinc++", "-nostdlibinc",
                "-isystem", sysroot/"usr/include", "-std=c++14", "-O0", "-fno-pic", "-fno-pie",
                "-fno-stack-protector", "-fexceptions", "-frtti"], archives

    def whole_module(self, source, target):
        original = self.original_inventory(source)
        output = source.with_name(source.name+".native.json")
        receipt = source.with_name(source.name+".verified.json")
        self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target,
                      "--emit", "mir", "-o", output])
        self.command([self.compiler, output, "--input-kind", "native-ir", "--verify-native", "--receipt", receipt])
        module = json.loads(output.read_text())
        for key in ("functions", "globals", "aliases"):
            self.assertEqual({item["name"] for item in module[key]}, set(original[key]))
        self.assertEqual({f["name"] for f in module["functions"] if f["entry"] is not None}, set(original["definitions"]))
        for singular, plural in (("function", "functions"), ("global", "globals"), ("alias", "aliases")):
            self.assertEqual(module["provenance"]["source_"+singular+"_count"], len(original[plural]))
        self.assertEqual(module["provenance"]["input_sha256"], self.bind(source)["sha256"])
        self.assertEqual(json.loads(receipt.read_text())["module_sha256"], self.bind(output)["sha256"])
        operations = [i["operation"] for f in module["functions"] for b in f["blocks"] for i in b["instructions"]]
        terminators = [b["terminator"] for f in module["functions"] for b in f["blocks"]]
        pads = [i for i in operations if i["op"] == "landing_pad"]
        self.assertTrue(pads, "genuine C++ EH landing pads disappeared")
        self.assertTrue(any(c["kind"] == "filter" for pad in pads for c in pad["clauses"]), "genuine C++ filter disappeared")
        self.assertTrue(any(c["kind"] == "catch" and c["typeinfo"]["kind"] == "null"
                            for pad in pads for c in pad["clauses"]), "genuine catch-all disappeared")
        self.assertTrue(any(t["op"] == "resume" for t in terminators))
        invokes = [t for t in terminators if t["op"] == "invoke"]
        self.assertTrue(invokes)
        stress = next(f for f in module["functions"] if f["name"] == "eh_stress")
        self.assertEqual(len(stress["signature"]["params"]), 16)
        # Several invoke sites must actually share one unwind continuation.
        unwind = [b["terminator"]["unwind"] for b in stress["blocks"] if b["terminator"]["op"] == "invoke"]
        self.assertLess(len(set(unwind)), len(unwind))
        return {"input": self.bind(source), "module": self.bind(output), "verification": self.bind(receipt),
                "original_inventory": original, "invoke_count": len(invokes), "landing_pad_count": len(pads),
                "resume_count": sum(t["op"] == "resume" for t in terminators)}

    def object_identity(self, path, machine):
        data = path.read_bytes()
        self.assertEqual(data[:6], b"\x7fELF\x02\x01")
        self.assertEqual(struct.unpack_from("<HH", data, 16), (1, machine))
        offset = struct.unpack_from("<Q", data, 40)[0]
        entry_size, count = struct.unpack_from("<HH", data, 58)
        self.assertEqual(entry_size, 64); self.assertGreater(count, 0)
        self.assertLessEqual(offset + entry_size * count, len(data))
        if machine == 243:
            self.assertEqual(struct.unpack_from("<I", data, 48)[0] & 6, 4,
                             "original RV64GC LP64D provider profile must survive")

    def test_whole_genuine_cpp_eh_reference_and_own_execution_all_three(self):
        emulators = self.emulators()
        tools = {"ocorec": self.compiler, "clang++": self.sdk/"clang++", "clang": self.sdk/"clang",
                 "llvm-as": self.sdk/"llvm-as", "lld": self.linker, **emulators}
        for path in tools.values(): self.bind(path)
        self.bind(Path(importer.discover_library()))
        cpp = self.directory/"whole-eh.cpp"; cpp.write_text(CPP_SOURCE)
        driver = self.directory/"test-carrier.cpp"; driver.write_text(carrier())
        self.bind(cpp); self.bind(driver); self.bind(__file__)
        worker_snapshot = self.directory/"test-source-snapshot.py"
        worker_snapshot.write_bytes(Path(__file__).read_bytes()); self.bind(worker_snapshot)
        report = {"scope": "whole genuine C++ EH compiler conformance with original Linux/musl reference providers",
                  "provider_modules_lowered": False, "full_rust_compiler_complete": False,
                  "dependency_closure_complete": False, "native_ostadix_qualified": False,
                  "physical_silicon_qualified": False, "reference_only": os.environ.get("OCORE_TEST_EH_REFERENCE_ONLY") == "1",
                  "test_source": self.bind(worker_snapshot),
                  "compiler": self.bind(self.compiler),
                  "process_environment": {key: os.environ.get(key) for key in
                      ("PATH", "LD_LIBRARY_PATH", "OCOREC", "OCORE_TEST_LLVM22_BIN", "LD_LLD",
                       "OCORE_TEST_QEMU_AARCH64", "OCORE_TEST_QEMU_RISCV64", "OCORE_TEST_REQUIRE_ALL_ISAS")},
                  "cases_per_execution": len(cases()), "golden_stdout": golden().decode(), "targets": {}, "passed": False}
        report_path = self.directory/"report.json"
        try:
            for isa, (target, triple, machine, flags) in TARGETS.items():
                with self.subTest(isa=isa):
                    argv, archives = self.profile(isa)
                    # The source-built providers preserve RV64GC LP64D/FPU
                    # context. The integer-only bare-metal carrier's LP64 flags
                    # are deliberately not used for this Linux/musl profile.
                    if isa == "riscv64":
                        argv += ["-march=rv64gc", "-mabi=lp64d"]
                    else:
                        argv += flags
                    inputs = []
                    for extension, mode in (("ll", "-S"), ("bc", "-c")):
                        path = self.directory/(isa+"-whole."+extension)
                        self.command([self.sdk/"clang++", *argv, "-emit-llvm", mode, cpp, "-o", path])
                        self.bind(path); inputs.append(path)
                    text = inputs[0].read_text()
                    self.assertRegex(text, r"alloca \[32768 x i8\]")
                    self.assertIn("filter [1 x ptr]", text)
                    driver_objects = {}
                    for corrupt in (False, True):
                        obj = self.directory/(isa+"-carrier"+("-corrupt" if corrupt else "")+".o")
                        self.command([self.sdk/"clang++", *argv, *(["-DCORRUPT_ORACLE=1"] if corrupt else []),
                                      "-c", driver, "-o", obj])
                        self.object_identity(obj, machine); self.bind(obj)
                        driver_objects[corrupt] = obj
                    rows = report["targets"].setdefault(isa, [])
                    for source in inputs:
                        row = {"input": self.bind(source), "executions": {}}
                        rows.append(row)
                        reference = source.with_name(source.name+".clang.o")
                        self.command([self.sdk/"clang++", *argv, "-c", source, "-o", reference])
                        self.object_identity(reference, machine); self.bind(reference)
                        objects = {"reference": reference}
                        # Baseline always executes before invoking our importer.
                        for own in (False, True):
                            if own:
                                if report["reference_only"]: continue
                                row["whole_inventory"] = self.whole_module(source, target)
                                obj = source.with_name(source.name+".own.o")
                                self.command([self.compiler, source, "--input-kind", "llvm-ir", "--target", target, "-o", obj])
                                self.object_identity(obj, machine); self.bind(obj)
                                decoded = eh_objects.Elf(obj.read_bytes())
                                # Reuse the independent decoder with this genuine
                                # source's personality symbol rather than the
                                # decoder's synthetic structural fixture name.
                                with mock.patch.object(eh_objects, "PERSONALITY", "__gxx_personality_v0"):
                                    frames = eh_objects.dwarf_frames(decoded, isa)
                                # The independent decoder checks eight-byte
                                # personality/LSDA pointers and relocation width;
                                # record lengths legitimately use DWARF32.
                                personality_frames = [f for f in frames if f["cie"]["personality"]]
                                self.assertGreaterEqual(len(personality_frames), 4)
                                self.assertTrue(all(f["lsda"] is not None for f in personality_frames))
                                self.assertTrue(any(s["name"].startswith(".gcc_except_table") for s in decoded.sections))
                                row["owned_eh_frames"] = len(personality_frames)
                                objects["own"] = obj
                            tag = "own" if own else "reference"
                            for corrupt in (False, True):
                                binary = self.directory/(isa+"-"+source.suffix[1:]+"-"+tag+("-corrupt" if corrupt else ""))
                                trace = binary.with_suffix(".link-trace.txt")
                                link = self.command([self.sdk/"clang++", *argv, "-fuse-ld=lld", "--rtlib=compiler-rt", "--unwindlib=none",
                                                     "-static", "-no-pie", "-Wl,--eh-frame-hdr", "-Wl,--trace", "-Wl,--why-extract="+str(binary)+".extract.txt",
                                                     driver_objects[corrupt], objects[tag], *archives, "-o", binary])
                                trace.write_bytes(link.stdout+link.stderr)
                                self.bind(binary); self.bind(trace)
                                # Bind every actual archive/startup selected by the driver,
                                # including implicit CRT/builtins, to the unchanged source
                                # records above. Keep the complete ordered trace on disk.
                                ordered_inputs = []
                                for line in link.stdout.decode().splitlines():
                                    selected = Path(line.split("(", 1)[0]).resolve()
                                    self.assertTrue(selected.is_file(), "unknown linker trace input: " + line)
                                    self.assertIn(str(selected), self.bound, "unbound actual provider or test-carrier input: " + line)
                                    ordered_inputs.append({"artifact": self.bound[str(selected)], "trace": line})
                                self.assertTrue(ordered_inputs)
                                run = self.command(([emulators[isa]] if isa != "x86_64" else [])+[binary], success=not corrupt)
                                if corrupt:
                                    self.assertEqual(run.returncode, 31, "independent mutated oracle must fail")
                                else:
                                    self.assertEqual(run.stdout, golden()); self.assertEqual(run.stderr, b"")
                                row["executions"][tag+("_corrupt" if corrupt else "")] = {
                                    "executable": self.bind(binary), "ordered_link_trace": self.bind(trace),
                                    "ordered_selected_inputs": ordered_inputs,
                                    "archive_extraction": self.bind(str(binary)+".extract.txt"),
                                    "exit_code": run.returncode, "stdout": run.stdout.decode(), "stderr": run.stderr.decode()}
                    report_path.write_text(json.dumps(report, indent=2)+"\n")
            for item in list(self.bound.values()): self.bind(item["path"], item)
            expected_runs = {"reference", "reference_corrupt"}
            if not report["reference_only"]: expected_runs |= {"own", "own_corrupt"}
            self.assertEqual(set(report["targets"]), set(TARGETS))
            self.assertTrue(all(len(rows) == 2 and all(set(row["executions"]) == expected_runs for row in rows)
                                for rows in report["targets"].values()), "all original LL/BC target executions are required")
            report["passed"] = True
        finally:
            report["bound_inputs_providers_tools_outputs"] = list(self.bound.values())
            report["commands"] = [weak.artifact(path) for path in sorted(self.directory.glob("command-*.json"))]
            report_path.write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    unittest.main()
