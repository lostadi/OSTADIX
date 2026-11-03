"""Real frontend stdin capture/replay, including source spelling and failures.

These tests establish capture fidelity; they do not qualify native O-core code.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("stdin_capture", ROOT / "scripts/ocore_runtime_capture.py")
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class StdinCaptureTests(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("OCORE_STDIN_EVIDENCE")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
            self.root = Path(tempfile.mkdtemp(dir=parent, prefix=self._testMethodName + "-"))
        else:
            temp = tempfile.TemporaryDirectory(prefix="ocore-stdin-")
            self.addCleanup(temp.cleanup)
            self.root = Path(temp.name)
        self.clang = shutil.which("clang")
        self.nm = shutil.which("nm")
        if not self.clang or not self.nm:
            self.skipTest("Clang and nm required")
        self.session = self.root / "capture"
        self.session.mkdir()
        worker = capture.snapshot_worker(self.session)
        tool = capture.tool_info(self.clang, "clang")
        capture.write_json(self.session / "session.json", {
            "capture_worker": worker, "recipe": {"toolchain": {}},
            "tools": {"clang": tool, "cxx": tool, "nm": capture.tool_info(self.nm, "nm")}})
        self.environment = dict(os.environ)
        for key in ("OCORE_CAPTURE_PARENT_EVENT", "OCORE_CAPTURE_CARGO_PARENT", "OCORE_CAPTURE_LINKER_IDENTITY"):
            self.environment.pop(key, None)

    def compare(self, args, data, output=None):
        baseline = subprocess.run([self.clang, *args], input=data, cwd=self.root,
                                  capture_output=True, env=self.environment)
        native = (self.root / output).read_bytes() if output and (self.root / output).exists() else None
        if native is not None:
            (self.root / output).unlink()
        result = subprocess.run([str(self.session / "wrappers/cc"), *args], input=data,
                                cwd=self.root, capture_output=True, env=self.environment)
        self.assertEqual(result.returncode, baseline.returncode, result.stderr)
        self.assertEqual(result.stdout, baseline.stdout)
        self.assertEqual(result.stderr, baseline.stderr)
        if native is not None:
            self.assertEqual((self.root / output).read_bytes(), native)
        events = [json.loads(p.read_text()) for p in (self.session / "events").glob("*.json")]
        self.assertEqual(len(events), 1)
        return result, events[0]

    def test_original_bytes_macros_local_include_and_ir_replay(self):
        (self.root / "local.h").write_text("#define ANSWER 42\n")
        data = b'#include "local.h"\nconst char *file = __FILE__;\nconst char *base = __BASE_FILE__;\nint answer(void) { return ANSWER; }\n'
        _, event = self.compare(["-x", "c", "-", "-c", "-o", "original.o"], data, "original.o")
        self.assertEqual(event["capture_errors"], [])
        self.assertTrue(event["translation_required"])
        self.assertEqual(Path(event["stdin_source"]["path"]).read_bytes(), data)
        unit, = event["units"]
        self.assertEqual(unit["source"], event["stdin_source"])
        self.assertEqual(unit["replay_argv"][-1], "-")
        text = Path(unit["ir"]["path"]).read_text()
        self.assertIn("<stdin>", text)
        self.assertNotIn("stdin-source", text)
        self.assertTrue(any(Path(x["path"]).name == "local.h" for x in unit["dependencies"]))

    def test_cpp_response_file_and_empty_stdin(self):
        (self.root / "args.rsp").write_text("-x c++ - -c -o original.o\n")
        _, event = self.compare(["@args.rsp"], b"", "original.o")
        self.assertEqual(event["capture_errors"], [])
        self.assertEqual(event["stdin_source"]["bytes"], 0)
        self.assertEqual(len(event["units"]), 1)
        self.assertEqual(len(event["response_files"]), 1)

    def test_native_failure_keeps_status_and_source_without_successful_ir(self):
        result, event = self.compare(["-x", "c", "-", "-c", "-o", "bad.o"], b"int = ;\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(event["units"], [])
        self.assertEqual(event["exit_code"], result.returncode)
        self.assertEqual(Path(event["stdin_source"]["path"]).read_bytes(), b"int = ;\n")

    def test_preprocessing_is_query_and_preserves_stdout(self):
        _, event = self.compare(["-x", "c", "-", "-E"], b"int n = 7;\n")
        self.assertEqual(event["classification"], "query")
        self.assertEqual(event["units"], [])
        self.assertEqual(event["capture_errors"], [])

    def test_assembly_stdin_preserves_native_result_but_rejects_llvm_capture(self):
        _, event = self.compare(["-x", "assembler", "-", "-c", "-o", "asm.o"],
                                b".text\n.globl answer\nanswer:\n", "asm.o")
        self.assertEqual(event["units"], [])
        self.assertIn("explicit supported C-family language", " ".join(event["capture_errors"]))

    def test_dash_output_does_not_consume_stdin_as_source(self):
        (self.root / "original.c").write_text("int n = 7;\n")
        _, event = self.compare(["original.c", "-S", "-emit-llvm", "-o", "-"], b"unused bytes")
        self.assertNotIn("stdin_source", event)
        self.assertEqual(event["capture_errors"], [])
        self.assertEqual(len(event["units"]), 1)

    def test_mixed_sources_forward_native_build_but_reject_ambiguous_replay(self):
        (self.root / "other.c").write_text("int other(void) { return 1; }\n")
        result, event = self.compare(["-x", "c", "other.c", "-", "-c"], b"int n = 7;\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(event["units"], [])
        self.assertIn("one source and one explicit language", " ".join(event["capture_errors"]))

    def test_language_switches_do_not_silently_change_stdin_abi(self):
        (self.root / "named.cpp").write_text("int named() { return 1; }\n")
        result, event = self.compare(["-x", "c", "-", "-x", "c++", "named.cpp", "-c"],
                                     b"int stdin_answer(void) { return 42; }\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(event["units"], [])
        self.assertTrue(event["capture_errors"])

    def test_default_stdin_object_is_bound_to_actual_output(self):
        _, event = self.compare(["-x", "c", "-", "-c"], b"int answer(void) { return 42; }\n", "-.o")
        self.assertEqual(event["capture_errors"], [])
        output, = event["outputs"]
        self.assertEqual(Path(output["path"]).name, "-.o")
        self.assertEqual(output, {**capture.file_info(self.root / "-.o"), "symbols": output["symbols"]})
        self.assertIn("answer", output["symbols"]["defined"])

    def test_default_stdin_llvm_text_output_is_bound(self):
        _, event = self.compare(["-x", "c", "-", "-S", "-emit-llvm"],
                                b"int answer(void) { return 42; }\n", "-.ll")
        self.assertEqual(event["capture_errors"], [])
        output, = event["outputs"]
        self.assertEqual(output, capture.file_info(self.root / "-.ll"))

    def test_option_values_are_not_stdin_sources(self):
        for args in (["-o", "-"], ["-I", "-"], ["-l", "-"], ["-L", "-"]):
            self.assertFalse(capture.clang_stdin_input(args))
        self.assertTrue(capture.clang_stdin_input(["-x", "c", "-", "-c"]))

    def test_driver_query_does_not_wait_for_stdin_eof(self):
        for flag in ("--version", "-dumpmachine", "-###"):
            command = [str(self.session / "wrappers/cc"), flag, "-x", "c", "-"]
            with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, cwd=self.root, env=self.environment) as process:
                # Keep the write side open while waiting: communicate() would
                # send EOF and conceal this regression.
                try:
                    status = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    self.fail("driver query waited for stdin EOF: " + flag)
                self.assertEqual(status, 0)
                process.communicate()
        for path in (self.session / "events").glob("*.json"):
            event = json.loads(path.read_text())
            self.assertNotIn("stdin_source", event)
            self.assertEqual(event["classification"], "query")

    def test_repeated_stdin_is_not_qualified_as_one_translation_unit(self):
        result, event = self.compare(["-x", "c", "-", "-", "-c"], b"int n = 7;\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(event["units"], [])
        self.assertTrue(event["capture_errors"])


if __name__ == "__main__":
    unittest.main()
