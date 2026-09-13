"""Synthetic launcher tests: no engine, VM, browser, or compiler is executed."""

import ast
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock


EXAMPLE = Path(__file__).resolve().parent
SUCCESS = "OSTADIX_GUIX_PACKAGE:42->43"
FAILURE = "OSTADIX_GUIX_INTENTIONAL_FAILURE"
LINUX_SCHEMA = "ostadix.olang-linux-browser-bundle/v1"


def python_body():
    source = (EXAMPLE / "run.O").read_text(encoding="utf-8")
    if not source.startswith("python^(\n") or not source.endswith(")_python\n"):
        raise AssertionError("Launcher must contain one matching Python block")
    return source[len("python^(\n"):-len(")_python\n")]


def record(path, content):
    return {"path": path, "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest()}


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guix-launcher-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.bundle = self.root / "target/guix-wasm"
        self.bundle.mkdir(parents=True)
        source = b"python^(__oval_result__ = 'synthetic fixture')_python\n"
        artifact = b"\x00asm\x01\x00\x00\x00"  # Header only, not an executable workload.
        plan = b"synthetic plan\n"
        self.manifest = {
            "schema": LINUX_SCHEMA,
            "source": record("program.O", source),
            "artifact": record("program.wasm", artifact),
            "plan": record("program.plan.txt", plan),
            "assets": [], "adapters": [], "backend_grants": [],
            "compatibility": {"local_execution": False,
                              "class": "requires-whole-program-provider", "blockers": []},
            "provider": {"schema": "ostadix.olang-browser-provider/v1",
                         "mode": "whole-program", "required": True},
        }
        for path, content in [("program.O", source), ("program.wasm", artifact),
                              ("program.plan.txt", plan)]:
            (self.bundle / path).write_bytes(content)
        self.build = {
            "schema": "ostadix.olang-wasm-container-build/v1",
            "profile": "embedded-linux-amd64-wasi-experimental",
            "source_sha256": self.manifest["source"]["sha256"],
            "plan_sha256": self.manifest["plan"]["sha256"],
            "runtime_image": "test.invalid/guix@sha256:" + "a" * 64,
            "builder_image": "test.invalid/rust@sha256:" + "b" * 64,
            "backend_grants": [], "adapters": [],
            "runtime_closure_verified": False, "execution_verified": False,
            "browser_bundle_host_qualified": False,
        }
        self.qualification = {
            "schema": "ostadix.guix-wasm-qualification/v1", "status": "passed",
            "source_sha256": self.manifest["source"]["sha256"],
            "artifact_sha256": self.manifest["artifact"]["sha256"],
            "plan_sha256": self.manifest["plan"]["sha256"],
            "runtime_image": self.build["runtime_image"],
            "builder_image": self.build["builder_image"],
            "runs": {name: {"status": "completed", "assertions_passed": True,
                            "returncode": 1 if name.endswith(".failure") else 0}
                     for name in ("build", "wasmtime.success", "wasmtime.failure",
                                  "wasmer.success", "wasmer.failure", "browser")},
        }
        self.write_build()
        self.write_metadata()

    def write_build(self):
        content = json.dumps(self.build).encode()
        (self.bundle / "wasm-build.json").write_bytes(content)
        self.manifest["build"] = record("wasm-build.json", content)
        self.qualification["build_record_sha256"] = self.manifest["build"]["sha256"]

    def write_metadata(self):
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))
        (self.bundle / "qualification.json").write_text(json.dumps(self.qualification))

    def invoke(self, *, engine=None, policy="success", force_failure=None,
               operation_ms=None, elapsed=0, explicit_bundle=True):
        self.calls, self.communications, self.handlers = [], [], {}
        self.clock_reads = 0
        self.namespace = {}
        self.process = types.SimpleNamespace(pid=420567, returncode=None)
        self.output = "synthetic guest boot output\n" + SUCCESS + "\n"
        previous = {signal.SIGINT: object(), signal.SIGTERM: object()}
        environment = {"DO_NOT_FORWARD_HOST_SECRET": "unit-test-only"}
        if explicit_bundle:
            environment["OSTADIX_GUIX_WASM_BUNDLE"] = str(self.bundle)
        if engine is not None:
            environment["OSTADIX_GUIX_WASM_ENGINE"] = engine
        if force_failure is not None:
            environment["OSTADIX_GUIX_FORCE_FAILURE"] = force_failure
        if operation_ms is not None:
            environment["O_BACKEND_OPERATION_TIMEOUT_MS"] = str(operation_ms)

        def monotonic():
            self.clock_reads += 1
            return 0 if self.clock_reads == 1 else elapsed

        def change_signal(number, handler):
            old = self.handlers.get(number, previous[number])
            self.handlers[number] = handler
            return old

        def communicate(timeout):
            self.communications.append(timeout)
            if len(self.communications) == 1:
                if policy == "timeout":
                    raise subprocess.TimeoutExpired(self.calls[0]["argv"], timeout)
                if policy == "interrupt":
                    self.handlers[signal.SIGTERM](signal.SIGTERM, None)
            elif policy in ("timeout", "interrupt"):
                return "", "mocked owned process stopped"
            self.process.returncode = 1 if force_failure == "1" else 0
            if policy == "ignores-failure":
                self.process.returncode = 0
                return self.output, ""
            if policy == "unexpected-exit":
                self.process.returncode = 7
                return "", "unrelated engine failure"
            if force_failure == "1":
                return "", FAILURE + "\n"
            return ("not the required marker\n" if policy == "missing-marker" else self.output), ""

        def popen(command, **kwargs):
            self.assertEqual(kwargs["env"], {})
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stdout"], subprocess.PIPE)
            self.assertEqual(kwargs["stderr"], subprocess.PIPE)
            self.assertIs(kwargs["text"], True)
            self.assertEqual(kwargs["encoding"], "utf-8")
            self.assertNotIn("start_new_session", kwargs)
            self.assertNotIn("process_group", kwargs)
            self.assertNotIn("preexec_fn", kwargs)
            self.assertNotIn("shell", kwargs)
            cwd = Path(kwargs["cwd"])
            self.assertTrue(cwd.is_absolute())
            self.assertEqual(list(cwd.iterdir()), [])
            if os.name == "posix":
                self.assertEqual(cwd.stat().st_mode & 0o777, 0o700)
            self.calls.append({"argv": command, "cwd": cwd})
            self.process.communicate = communicate
            return self.process

        def kill_child():
            self.assertTrue(self.calls[-1]["cwd"].is_dir(), "Reap before removing the owned cwd")
            self.process.returncode = -signal.SIGKILL

        self.process.kill = mock.Mock(side_effect=kill_child)

        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            stack.enter_context(mock.patch.object(Path, "cwd", return_value=self.root))
            stack.enter_context(mock.patch("shutil.which", side_effect=lambda name: str(self.root / "tools" / name)))
            self.popen = stack.enter_context(mock.patch("subprocess.Popen", side_effect=popen))
            stack.enter_context(mock.patch("subprocess.run", side_effect=AssertionError("Unexpected subprocess.run")))
            self.killpg = stack.enter_context(mock.patch("os.killpg", side_effect=AssertionError(
                "The launcher must never signal O's inherited process group")))
            stack.enter_context(mock.patch("os.kill", side_effect=AssertionError("Real process signaling forbidden")))
            stack.enter_context(mock.patch("signal.signal", side_effect=change_signal))
            stack.enter_context(mock.patch.object(time, "monotonic", side_effect=monotonic))
            try:
                exec(compile(python_body(), str(EXAMPLE / "run.O"), "exec"), self.namespace)
            finally:
                if self.handlers:
                    self.assertEqual(self.handlers, previous)
                for call in self.calls:
                    self.assertFalse(call["cwd"].exists(), "Owned temporary runtime directory leaked")
                self.killpg.assert_not_called()
        return self.namespace["__oval_result__"]

    def test_launcher_python_syntax(self):
        ast.parse(python_body())

    def test_default_bundle_and_wasmtime_return_actual_stdout_without_host_access(self):
        self.assertEqual(self.invoke(explicit_bundle=False), self.output)
        self.assertEqual(self.calls[0]["argv"], [str(self.root / "tools/wasmtime"), "run",
                                                str(self.bundle / "program.wasm"), "--no-stdin"])
        self.assertGreater(self.communications[0], 0)
        self.assertLessEqual(self.communications[0], 55)
        self.process.kill.assert_not_called()

    def test_wasmer_uses_argument_separator_and_empty_environment(self):
        self.assertEqual(self.invoke(engine="wasmer"), self.output)
        self.assertEqual(self.calls[0]["argv"], [str(self.root / "tools/wasmer"), "run",
                                                str(self.bundle / "program.wasm"), "--", "--no-stdin"])

    def test_failed_or_incomplete_qualification_prevents_process_launch(self):
        original = json.loads(json.dumps(self.qualification))
        for name in ["status", "schema", *original["runs"]]:
            with self.subTest(field=name):
                self.qualification = json.loads(json.dumps(original))
                if name == "status":
                    self.qualification[name] = "running"
                elif name == "schema":
                    self.qualification[name] = "unrelated-receipt/v1"
                else:
                    self.qualification["runs"][name]["assertions_passed"] = False
                self.write_metadata()
                with self.assertRaises((RuntimeError, ValueError)):
                    self.invoke()
                self.popen.assert_not_called()

    def test_qualification_hash_mismatch_prevents_process_launch(self):
        for key in ("source_sha256", "artifact_sha256", "plan_sha256", "build_record_sha256"):
            with self.subTest(field=key):
                old = self.qualification[key]
                self.qualification[key] = "0" * 64
                self.write_metadata()
                with self.assertRaises((RuntimeError, ValueError)):
                    self.invoke()
                self.popen.assert_not_called()
                self.qualification[key] = old

    def test_missing_failed_or_wrong_exit_qualification_runs_are_rejected(self):
        original = json.loads(json.dumps(self.qualification))
        for case in ("missing", "extra-failed", "wrong-exit", "boolean-exit", "unfinished"):
            with self.subTest(case=case):
                self.qualification = json.loads(json.dumps(original))
                runs = self.qualification["runs"]
                if case == "missing":
                    del runs["browser"]
                elif case == "extra-failed":
                    runs["additional-check"] = {"status": "completed", "assertions_passed": False}
                elif case == "wrong-exit":
                    runs["wasmer.failure"]["returncode"] = 0
                elif case == "boolean-exit":
                    runs["wasmer.failure"]["returncode"] = True
                else:
                    runs["build"]["status"] = "running"
                self.write_metadata()
                with self.assertRaises(RuntimeError):
                    self.invoke()
                self.popen.assert_not_called()

    def test_build_input_cross_bindings_are_checked_after_matching_file_hashes(self):
        original = json.loads(json.dumps(self.build))
        for key, value in (("source_sha256", "0" * 64), ("plan_sha256", "0" * 64),
                           ("runtime_image", "test.invalid/other@sha256:" + "c" * 64),
                           ("builder_image", "test.invalid/other@sha256:" + "d" * 64),
                           ("backend_grants", ["host-process-spawn"]),
                           ("adapters", [{"name": "python", "sha256": "0" * 64}])):
            with self.subTest(field=key):
                self.build = json.loads(json.dumps(original))
                self.build[key] = value
                self.write_build()
                self.write_metadata()
                with self.assertRaisesRegex(RuntimeError, "build inputs"):
                    self.invoke()
                self.popen.assert_not_called()

    def test_payload_tampering_and_direct_wasi_schema_are_rejected(self):
        artifact = self.bundle / "program.wasm"
        original = artifact.read_bytes()
        artifact.write_bytes(original + b"changed")
        with self.assertRaises((RuntimeError, ValueError)):
            self.invoke()
        self.popen.assert_not_called()
        artifact.write_bytes(original)
        self.manifest["schema"] = "ostadix.olang-browser-bundle/v1"
        self.write_metadata()
        with self.assertRaises((RuntimeError, ValueError)):
            self.invoke()
        self.popen.assert_not_called()

    def test_manifest_length_mismatch_and_noncanonical_path_are_rejected(self):
        for field, value in (("bytes", self.manifest["artifact"]["bytes"] + 1),
                             ("path", "../program.wasm")):
            with self.subTest(field=field):
                previous = self.manifest["artifact"][field]
                self.manifest["artifact"][field] = value
                self.write_metadata()
                with self.assertRaises(RuntimeError):
                    self.invoke()
                self.popen.assert_not_called()
                self.manifest["artifact"][field] = previous

    def test_invalid_engine_or_force_failure_never_launches_a_process(self):
        for options in ({"engine": "bash"}, {"engine": "wasmtime --dir=/"},
                        {"force_failure": "yes"}, {"force_failure": "0"}):
            with self.subTest(options=options):
                with self.assertRaises((RuntimeError, ValueError)):
                    self.invoke(**options)
                self.popen.assert_not_called()

    def test_explicit_guest_failure_is_passed_only_as_an_engine_flag_and_raised(self):
        with self.assertRaisesRegex(RuntimeError, FAILURE):
            self.invoke(force_failure="1")
        self.assertIn("--env=OSTADIX_GUIX_FORCE_FAILURE=1", self.calls[0]["argv"])
        self.assertNotIn("__oval_result__", self.namespace)

    def test_unexpected_engine_exit_or_missing_marker_is_never_success(self):
        for policy in ("unexpected-exit", "missing-marker"):
            with self.subTest(policy=policy):
                with self.assertRaises(RuntimeError):
                    self.invoke(policy=policy)
                self.assertNotIn("__oval_result__", self.namespace)

    def test_engine_ignoring_explicit_failure_request_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unexpectedly succeeded"):
            self.invoke(force_failure="1", policy="ignores-failure")
        self.assertNotIn("__oval_result__", self.namespace)

    def test_deadline_and_interruption_kill_only_the_engine_child(self):
        for policy, exception in (("timeout", RuntimeError), ("interrupt", KeyboardInterrupt)):
            with self.subTest(policy=policy):
                with self.assertRaises(exception):
                    self.invoke(policy=policy)
                self.process.kill.assert_called_once_with()
                self.assertGreaterEqual(len(self.communications), 2)
                self.assertLessEqual(self.communications[-1], 3)
                self.assertGreaterEqual(self.communications[-1], 0)
                self.assertNotIn("__oval_result__", self.namespace)

    def test_parent_budget_is_clamped_and_verification_time_is_charged(self):
        self.invoke(operation_ms=999999999, elapsed=12)
        self.assertGreater(self.communications[0], 0)
        self.assertLessEqual(self.communications[0], 3600 - 5 - 12)
        self.invoke(operation_ms=60000, elapsed=12)
        self.assertLessEqual(self.communications[0], 60 - 5 - 12)
        with self.assertRaises((RuntimeError, ValueError)):
            self.invoke(operation_ms=6000, elapsed=2)
        self.popen.assert_not_called()

    def test_timeout_parsing_matches_positive_u64_default_and_ceiling(self):
        for raw, seconds in (("invalid", 55), ("0", 55), ("-1", 55),
                             ("18446744073709551616", 55), (" 70000", 55),
                             ("+00070000", 65), ("00070000", 65),
                             ("18446744073709551615", 3595)):
            with self.subTest(raw=raw):
                self.invoke(operation_ms=raw)
                self.assertEqual(self.communications[0], seconds)


if __name__ == "__main__":
    unittest.main()
