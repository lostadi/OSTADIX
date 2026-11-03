"""Actual linker-map coexistence through immutable capture-worker wrappers.

The fixture links and executes original native C objects. This tests native
link evidence and preservation of upstream behavior, not O-core lowering or
qualification of the fixture's uncaptured reference objects.
"""
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("OCORE_CAPTURE_MAP_WORKER", ROOT / "scripts/ocore_runtime_capture.py"))
SPEC = importlib.util.spec_from_file_location("capture_map_worker", SCRIPT)
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "real static fixture requires Linux x86-64")
class NativeLinkMapTests(unittest.TestCase):
    def setUp(self):
        evidence = os.environ.get("OCORE_LINK_MAP_EVIDENCE")
        if evidence:
            Path(evidence).mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=evidence))
        else:
            temporary = tempfile.TemporaryDirectory(prefix="capture-link-map-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.worker_before = capture.file_info(SCRIPT)
        self.records = []
        self.clang = shutil.which("clang")
        self.ar = shutil.which("ar")
        self.nm = shutil.which("nm")
        if not all([self.clang, self.ar, self.nm]):
            self.skipTest("native Clang, ar and nm are required")
        self.linkers = {name: shutil.which(name) for name in ["ld.bfd", "ld.lld"]}
        self.linkers = {name: path for name, path in self.linkers.items() if path}
        if not self.linkers:
            self.skipTest("a native GNU ld or ELF LLD is required")
        sources = {
            "entry.c": "extern long provider(long,long); void _start(void) { long x=provider(20,22); "
                       "__asm__ volatile(\"syscall\"::\"a\"(60L),\"D\"((long)(x!=42)):\"rcx\",\"r11\",\"memory\"); "
                       "__builtin_unreachable(); }\n",
            "provider.c": "long provider(long a,long b) { return a+b; }\n",
            "cold.c": "long cold_unselected(long n) { return n*7+19; }\n",
            "missing-entry.c": "extern void absent_provider(void); void _start(void) { absent_provider(); }\n",
        }
        for name, source in sources.items():
            path = self.directory / name
            path.write_text(source)
            self.run_checked([self.clang, "-O2", "-fno-pic", "-fno-pie", "-fno-stack-protector",
                              "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-c", path,
                              "-o", path.with_suffix(".o")])
        self.archive = self.directory / "liboriginal.a"
        self.run_checked([self.ar, "rcsD", self.archive, self.directory / "provider.o", self.directory / "cold.o"])
        self.session = self.directory / "capture"
        self.session.mkdir()
        worker = capture.snapshot_worker(self.session)
        session = {"capture_worker": worker,
                   "native_tools": {name: capture.tool_info(path, name) for name, path in self.linkers.items()},
                   "tools": {"nm": capture.tool_info(self.nm, "nm")}}
        capture.write_json(self.session / "session.json", session)
        self.environment = os.environ.copy()
        for name in ["OCORE_CAPTURE_PARENT_EVENT", "OCORE_CAPTURE_LINKER_IDENTITY", "OCORE_CAPTURE_CARGO_PARENT"]:
            self.environment.pop(name, None)
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self):
        if not hasattr(self, "worker_before"):
            return
        self.assertEqual(capture.file_info(SCRIPT), self.worker_before)
        if os.environ.get("OCORE_LINK_MAP_EVIDENCE"):
            capture.write_json(self.directory / "conformance.json", {
                "schema": "ostadix.native-link-map-conformance/v1", "test": self.id(),
                "worker": self.worker_before, "test_source": capture.file_info(Path(__file__)),
                "records": self.records, "scope": "Actual original linker/driver outputs and capture evidence only",
                "ocore_lowering_complete": False, "runtime_complete": False,
            })

    def run_checked(self, argv, *, cwd=None):
        result = subprocess.run([str(arg) for arg in argv], cwd=cwd or self.directory,
                                env=getattr(self, "environment", None), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def link(self, linker, flags, *, case="case", output="app", map_path=None, fail=False, driver=True,
             initial_map=None):
        work = self.directory / case
        work.mkdir(exist_ok=True)
        chosen = self.linkers[linker]
        entry = self.directory / ("missing-entry.o" if fail else "entry.o")
        if driver:
            args = ["-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none", "-Wl,-e,_start",
                    "-o", output, str(entry), str(self.archive), *flags]
            original_command = [self.clang, "--ld-path=" + chosen, *args]
            captured_command = [self.clang, "--ld-path=" + str(self.session / "wrappers" / linker), *args]
        else:
            args = ["-static", "--build-id=none", "-e", "_start", "-o", output, str(entry), str(self.archive), *flags]
            original_command = [chosen, *args]
            captured_command = [str(self.session / "wrappers" / linker), *args]
        if initial_map is not None:
            map_path.write_bytes(initial_map)
        baseline = subprocess.run(original_command, cwd=work,
                                  env=self.environment, capture_output=True, text=True, timeout=30)
        executable = work / output
        baseline_elf = executable.read_bytes() if executable.exists() else None
        baseline_map = map_path.read_bytes() if map_path is not None and map_path.is_file() else None
        if baseline_elf is not None:
            (work / "baseline.elf").write_bytes(baseline_elf)
            executable.unlink()
        if baseline_map is not None:
            (work / "baseline.map").write_bytes(baseline_map)
            map_path.unlink()
        if initial_map is not None:
            map_path.write_bytes(initial_map)
        old_events = set((self.session / "events").glob("*.json")) if (self.session / "events").exists() else set()
        recorded = subprocess.run(captured_command,
                                  cwd=work, env=self.environment, capture_output=True, text=True, timeout=30)
        events = [capture.read_json(path) for path in set((self.session / "events").glob("*.json")) - old_events]
        links = [event for event in events if event["classification"] == "native-tool"]
        self.assertEqual(len(links), 1, events)
        event = links[0]
        self.assertEqual(recorded.returncode, baseline.returncode, recorded.stderr)
        self.assertEqual(recorded.stdout, baseline.stdout)
        self.assertEqual(recorded.stderr, baseline.stderr)
        self.assertEqual(executable.read_bytes() if executable.exists() else None, baseline_elf)
        if map_path is not None:
            self.assertEqual(map_path.read_bytes() if map_path.is_file() else None, baseline_map)
        if baseline.returncode == 0:
            self.run_checked([executable.resolve()], cwd=work)
        self.assertEqual(event["exit_code"], baseline.returncode)
        self.assertEqual(event["argv"], event["effective_argv"][:len(event["argv"])])
        record = {"case": case, "original_argv": original_command,
                  "instrumented_argv": captured_command, "entry_kind": "clang-driver" if driver else "direct-linker",
                  "original_exit": baseline.returncode, "observed_exit": recorded.returncode,
                  "stdout_equal": True, "stderr_equal": True, "ELF_equal": True, "map_equal": True,
                  "event": event}
        self.records.append(record)
        return event, work

    def require_complete(self, event):
        trace = event["native_linkage"]
        self.assertTrue(trace["complete"], event)
        self.assertFalse(event["capture_errors"], event)
        self.assertEqual(capture.file_info(Path(trace["dependency_trace"]["path"])), trace["dependency_trace"])
        self.assertEqual(capture.file_info(Path(trace["archive_trace"]["path"])), trace["archive_trace"])
        archive = next(item for item in trace["providers"] if item["original"]["path"] == str(self.archive))
        members = capture.native_archive_members(Path(archive["snapshot"]["path"]))
        self.assertEqual([member["member"] for member in members], ["provider.o", "cold.o"])

    def test_original_maps_coexist_with_real_clang_linker_traces(self):
        forms = [["-Map", "original map"], ["-Map=original map"],
                 ["--Map", "original map"], ["--Map=original map"],
                 ["-Map", "unused.map", "--Map=original map"]]
        for linker in self.linkers:
            for index, form in enumerate(forms):
                with self.subTest(linker=linker, form=form):
                    case = linker + "-map-" + str(index)
                    map_path = self.directory / case / "original map"
                    event, _ = self.link(linker, [part for value in form for part in ["-Xlinker", value]],
                                         case=case, map_path=map_path)
                    self.require_complete(event)
                    if linker == "ld.bfd":
                        self.assertEqual(Path(event["native_linkage"]["archive_trace"]["path"]).read_bytes(), map_path.read_bytes())

    def test_no_original_map_keeps_existing_owned_trace(self):
        for linker in self.linkers:
            with self.subTest(linker=linker):
                event, _ = self.link(linker, [], case=linker + "-no-map")
                self.require_complete(event)
                self.assertNotIn("producer_map", event["native_linkage"])

    def test_original_verbose_and_map_flags_preserve_upstream_output(self):
        # This is the combination used by the unchanged BusyBox trylink path.
        for linker in self.linkers:
            with self.subTest(linker=linker):
                case = linker + "-verbose"
                event, _ = self.link(linker, ["-Xlinker", "--verbose", "-Xlinker", "-Map", "-Xlinker", "original.map"],
                                     case=case, map_path=self.directory / case / "original.map")
                self.require_complete(event)

    def test_response_file_map_is_observed_without_rewriting_it(self):
        for linker in self.linkers:
            with self.subTest(linker=linker):
                response = self.directory / (linker + " response file")
                content = '-Map "response map"\n'
                response.write_text(content)
                case = linker + "-response"
                # A producer can pass a response file directly to its native
                # linker. Clang expands explicit @ arguments itself before
                # driver parsing, so use the actual native-tool boundary here.
                event, _ = self.link(linker, ["@" + str(response)], case=case,
                                     map_path=self.directory / case / "response map", driver=False)
                self.require_complete(event)
                self.assertEqual(response.read_text(), content)
                self.assertTrue(event["response_files"])

    def test_sequential_reuse_preserves_prior_map_snapshot(self):
        if "ld.bfd" not in self.linkers:
            self.skipTest("GNU ld is required")
        shared = self.directory / "shared map"
        first, _ = self.link("ld.bfd", ["-Xlinker", "-Map=" + str(shared)], case="first", map_path=shared)
        self.require_complete(first)
        retained = first["native_linkage"]["archive_trace"]
        second, _ = self.link("ld.bfd", ["-Xlinker", "-Map=" + str(shared)], case="second",
                              output="different", map_path=shared)
        self.require_complete(second)
        self.assertNotEqual(retained["sha256"], second["native_linkage"]["archive_trace"]["sha256"])
        self.assertEqual(capture.file_info(Path(retained["path"])), retained)

    def test_failed_links_preserve_exit_diagnostics_and_original_map(self):
        for linker in self.linkers:
            with self.subTest(linker=linker):
                case = linker + "-failed"
                event, _ = self.link(linker, ["-Xlinker", "-Map=original.map"], case=case,
                                     map_path=self.directory / case / "original.map", fail=True)
                self.assertNotEqual(event["exit_code"], 0)
                self.assertFalse(event["native_linkage"]["complete"])
                if linker == "ld.bfd":
                    retained = event["native_linkage"]["producer_map"]["snapshot"]
                    self.assertEqual(capture.file_info(Path(retained["path"])), retained)
                    self.assertEqual(Path(retained["path"]).read_bytes(), (self.directory / case / "original.map").read_bytes())

    def test_failed_link_cannot_claim_a_stale_map(self):
        if "ld.bfd" not in self.linkers:
            self.skipTest("GNU ld is required")
        event, _ = self.link("ld.bfd", ["-Xlinker", "-Map=original.map", "-Xlinker", "--unknown-original-option"],
                             case="stale", map_path=self.directory / "stale/original.map",
                             initial_map=b"OUTPUT(app elf64-x86-64)\n")
        self.assertNotEqual(event["exit_code"], 0)
        self.assertFalse(event["native_linkage"]["complete"])
        self.assertNotIn("producer_map", event["native_linkage"])
        self.assertTrue(any("not rewritten" in issue for issue in event["native_linkage"]["issues"]))

    def test_output_and_map_paths_with_spaces_remain_exact(self):
        for linker in self.linkers:
            with self.subTest(linker=linker):
                case = linker + "-output-spaces"
                event, _ = self.link(linker, ["-Xlinker", "-Map=original map"], case=case,
                                     output="application with spaces", map_path=self.directory / case / "original map")
                self.require_complete(event)

    def test_existing_capture_flags_are_not_overwritten(self):
        for linker in self.linkers:
            with self.subTest(linker=linker):
                event, work = self.link(linker, ["-Xlinker", "--dependency-file=upstream.d",
                                                "-Xlinker", "-Map=upstream.map"],
                                       case=linker + "-occupied",
                                       map_path=self.directory / (linker + "-occupied") / "upstream.map")
                self.assertFalse(event["native_linkage"]["complete"])
                self.assertEqual(event["effective_argv"], event["argv"])
                self.assertTrue((work / "upstream.d").is_file())

    def test_gnu_stdout_map_remains_visible_and_capture_incomplete(self):
        if "ld.bfd" not in self.linkers:
            self.skipTest("GNU ld is required")
        for index, option in enumerate(["-Map=-", "-M", "--print-map"]):
            with self.subTest(option=option):
                event, _ = self.link("ld.bfd", ["-Xlinker", option], case="stdout-" + str(index))
                self.assertFalse(event["native_linkage"]["complete"])
                self.assertEqual(event["effective_argv"], event["argv"])
                self.assertTrue(event["outputs"], "unsupported trace must still record the observed upstream output")

    def test_lld_stdout_map_retains_independent_archive_trace(self):
        if "ld.lld" not in self.linkers:
            self.skipTest("LLD is required")
        event, _ = self.link("ld.lld", ["-Xlinker", "-Map=-"], case="lld-stdout")
        self.require_complete(event)

    def test_gnu_directory_and_percent_maps_are_not_reinterpreted(self):
        if "ld.bfd" not in self.linkers:
            self.skipTest("GNU ld is required")
        for value in ["map-directory/", "map-%"]:
            with self.subTest(value=value):
                case = "unsupported-" + str(len(self.records))
                work = self.directory / case
                work.mkdir()
                (work / "map-directory").mkdir()
                event, _ = self.link("ld.bfd", ["-Xlinker", "-Map=" + value], case=case)
                self.assertFalse(event["native_linkage"]["complete"])
                self.assertEqual(event["effective_argv"], event["argv"])

    def test_snapshot_requires_the_actual_producer_output(self):
        if "ld.bfd" not in self.linkers:
            self.skipTest("GNU ld is required")
        event, work = self.link("ld.bfd", ["-Xlinker", "-Map=original.map"], case="wrong-output",
                               map_path=self.directory / "wrong-output/original.map")
        self.require_complete(event)
        directory = self.directory / "bad-snapshot"
        directory.mkdir()
        with self.assertRaisesRegex(capture.CaptureError, "exact output"):
            capture.snapshot_linker_map(capture.original_linker_map(["-Map", "original.map"], work),
                                        directory, "another-output")
        self.assertFalse((directory / "producer-link.map").exists())

    def test_exclusive_snapshot_does_not_replace_or_remove_an_existing_artifact(self):
        if "ld.bfd" not in self.linkers:
            self.skipTest("GNU ld is required")
        event, work = self.link("ld.bfd", ["-Xlinker", "-Map=original.map"], case="exclusive",
                               map_path=self.directory / "exclusive/original.map")
        self.require_complete(event)
        directory = self.directory / "existing-snapshot"
        directory.mkdir()
        previous = directory / "producer-link.map"
        previous.write_bytes(b"prior immutable snapshot\n")
        retained = capture.file_info(previous)
        with self.assertRaises(FileExistsError):
            capture.snapshot_linker_map(capture.original_linker_map(["-Map", "original.map"], work), directory, "app")
        self.assertEqual(capture.file_info(previous), retained)

    def test_observed_map_mutation_rejects_and_removes_partial_snapshot(self):
        if "ld.bfd" not in self.linkers:
            self.skipTest("GNU ld is required")
        event, work = self.link("ld.bfd", ["-Xlinker", "-Map=original.map"], case="mutation",
                               map_path=self.directory / "mutation/original.map")
        self.require_complete(event)
        directory = self.directory / "mutated-snapshot"
        directory.mkdir()
        original = os.fstat
        calls = []

        def mutate_before_final_stat(descriptor):
            calls.append(descriptor)
            if len(calls) == 2:
                (work / "original.map").write_bytes(b"concurrent writer changed this output\n")
            return original(descriptor)

        with mock.patch.object(capture.os, "fstat", side_effect=mutate_before_final_stat):
            with self.assertRaisesRegex(capture.CaptureError, "changed while snapshotting"):
                capture.snapshot_linker_map(capture.original_linker_map(["-Map", "original.map"], work),
                                            directory, "app")
        self.assertFalse((directory / "producer-link.map").exists())


if __name__ == "__main__":
    unittest.main()
