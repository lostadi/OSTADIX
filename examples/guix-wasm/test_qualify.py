"""Mock-only controller regressions; never execute Guix, Docker, engines, or Chrome."""

from contextlib import ExitStack, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import types
import unittest
from unittest import mock


CONTROLLER = Path(__file__).with_name("qualify.py")
LINUX_SCHEMA = "ostadix.olang-linux-browser-bundle/v1"
SUCCESS = "OSTADIX_GUIX_PACKAGE:42->43"
FAILURE = "OSTADIX_GUIX_INTENTIONAL_FAILURE"
RUNTIME = "test.invalid/guix@sha256:" + "a" * 64
GIB = 1024 ** 3


def load_controller():
    # Compile an isolated module without creating a bytecode cache or invoking
    # the script's __main__ entrypoint.
    module = types.ModuleType("guix_qualification_under_test")
    exec(compile(CONTROLLER.read_text(), str(CONTROLLER), "exec"), module.__dict__)
    return module


def file_record(path, content):
    return {"path": path, "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest()}


class QualificationControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="guix-controller-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.root = self.directory / "checkout"
        self.original = self.root / "examples/guix-wasm/guix-package.O"
        self.original.parent.mkdir(parents=True)
        self.source = b"python^(__oval_result__ = 'synthetic unit fixture')_python\n"
        self.original.write_bytes(self.source)
        harness = self.root / "apps/olang-browser-wasi/test-browser.mjs"
        harness.parent.mkdir(parents=True)
        harness.write_text("// Synthetic harness path; never executed.\n")
        (self.root / "Cargo.toml").write_text("# Synthetic checkout marker.\n")
        self.compiler = self.directory / "tools/olangc"
        self.compiler.parent.mkdir()
        self.compiler.write_text("Synthetic compiler bytes; never executed.\n")
        self.compiler.chmod(0o700)
        self.evidence = self.directory / "evidence"
        self.controller = load_controller()

    def emit_bundle(self, command):
        bundle = Path(command[command.index("--browser-bundle") + 1])
        source = Path(command[1]).read_bytes()
        bundle.mkdir()
        contents = {
            "program.O": source,
            "program.wasm": b"\x00asm\x01\x00\x00\x00",  # Header only, not a workload.
            "program.plan.txt": b"synthetic plan fixture\n",
            "runner.mjs": b"// Synthetic asset, never executed.\n",
            "adapters/0000.shim": b"synthetic adapter\n",
        }
        (bundle / "adapters").mkdir()
        for path, content in contents.items():
            (bundle / path).write_bytes(content)
        manifest = {
            "schema": LINUX_SCHEMA,
            "source": file_record("program.O", source),
            "artifact": file_record("program.wasm", contents["program.wasm"]),
            "plan": file_record("program.plan.txt", contents["program.plan.txt"]),
            "assets": [file_record("runner.mjs", contents["runner.mjs"])],
            "adapters": [{"name": "python_shim.py", "file": file_record(
                "adapters/0000.shim", contents["adapters/0000.shim"])}],
            "backend_grants": [],
        }
        build = {
            "schema": "ostadix.olang-wasm-container-build/v1",
            "profile": "embedded-linux-amd64-wasi-experimental",
            "source_sha256": manifest["source"]["sha256"],
            "plan_sha256": manifest["plan"]["sha256"],
            "runtime_image": command[command.index("--wasm-runtime-image") + 1],
            "builder_image": command[command.index("--wasm-builder-image") + 1],
            "backend_grants": [],
            "adapters": [{"name": item["name"], "sha256": item["file"]["sha256"]}
                         for item in manifest["adapters"]],
            "runtime_closure_verified": False,
            "execution_verified": False,
            "browser_bundle_host_qualified": False,
        }
        if self.change_build:
            self.change_build(build)
        build_bytes = json.dumps(build).encode()
        (bundle / "wasm-build.json").write_bytes(build_bytes)
        manifest["build"] = file_record("wasm-build.json", build_bytes)
        (bundle / "manifest.json").write_text(json.dumps(manifest))
        if self.policy == "tampered-asset":
            (bundle / "runner.mjs").write_text("changed after its digest was recorded")

    def fake_popen(self, command, **kwargs):
        self.assertIs(kwargs["start_new_session"], True)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertNotIn("shell", kwargs)
        name = Path(command[0]).name
        process = types.SimpleNamespace(pid=420000 + len(self.calls), returncode=None)
        call = {"argv": command, "kwargs": kwargs, "process": process, "waits": []}
        self.calls.append(call)
        exit_code = 0
        if name == "olangc":
            self.assertEqual(command[2:4], ["--target", "wasm"])
            self.emit_bundle(command)
        elif name in ("wasmtime", "wasmer"):
            self.assertEqual(kwargs["env"], {})
            self.assertEqual(Path(kwargs["cwd"]), self.active_evidence / "unrelated-runtime-cwd")
            self.assertFalse((self.active_evidence / "input").exists())
            failed = "--env=OSTADIX_GUIX_FORCE_FAILURE=1" in command
            artifact = str(self.active_evidence / "bundle/program.wasm")
            expected = [str(self.compiler.parent / name), "run"]
            if failed:
                expected.append("--env=OSTADIX_GUIX_FORCE_FAILURE=1")
            expected += [artifact] + (["--"] if name == "wasmer" else []) + ["--no-stdin"]
            self.assertEqual(command, expected)
            exit_code = 1 if failed else 0
            stream = kwargs["stderr"] if failed else kwargs["stdout"]
            marker = FAILURE if failed else SUCCESS
            stream.write((marker + "\n").encode())
            if self.policy == "wrong-engine-exit":
                exit_code = 2
            elif self.policy == "missing-engine-marker":
                stream.seek(0)
                stream.truncate()
                stream.write(b"not qualification evidence\n")
            elif self.policy == "artifact-changed":
                Path(artifact).write_bytes(b"modified after the preflight hash check")
        elif name == "node":
            environment = kwargs["env"]
            self.assertEqual(environment["OLANG_BROWSER_FAILURE_ENV"], "OSTADIX_GUIX_FORCE_FAILURE")
            self.assertEqual(environment["OLANG_BROWSER_FAILURE_MARKER"], FAILURE)
            browser = Path(environment["OLANG_BROWSER_EVIDENCE_DIR"])
            self.assertEqual(browser, self.active_evidence / "browser")
            browser.mkdir()
            manifest = json.loads((self.active_evidence / "bundle/manifest.json").read_text())
            receipt = {
                "schema": "ostadix.browser-qualification/v1", "status": "passed",
                "profile": LINUX_SCHEMA, "source_sha256": manifest["source"]["sha256"],
                "artifact_sha256": manifest["artifact"]["sha256"],
            }
            if self.policy == "wrong-browser-binding":
                receipt["artifact_sha256"] = "0" * 64
            (browser / "receipt.json").write_text(json.dumps(receipt))
        elif name == "colima":
            self.assertEqual(command, [str(self.compiler.parent / "colima"), "stop", "ostadix-wasm"])
        else:
            self.fail("Unexpected attempted subprocess: " + name)

        def wait(timeout):
            call["waits"].append(timeout)
            if name == "olangc" and len(call["waits"]) == 1:
                if self.policy == "deadline":
                    self.now = 10801
                    raise subprocess.TimeoutExpired(command, timeout)
                if self.policy == "disk-drops":
                    self.free = 1000
                    raise subprocess.TimeoutExpired(command, timeout)
                if self.policy == "interrupt":
                    self.handlers[signal.SIGTERM](signal.SIGTERM, None)
            process.returncode = exit_code
            return exit_code

        process.wait = wait
        return process

    def invoke(self, *, profile="", policy=None, free=10 * GIB, change_build=None,
               evidence=None, runtime=RUNTIME):
        self.active_evidence = evidence or self.evidence
        self.calls, self.handlers, self.now = [], {}, 0
        self.policy, self.free, self.change_build = policy, free, change_build
        previous = {signal.SIGINT: object(), signal.SIGTERM: object()}

        def change_signal(number, handler):
            old = self.handlers.get(number, previous[number])
            self.handlers[number] = handler
            return old

        environment = {
            "OLANG_GUIX_EVIDENCE_DIR": str(self.active_evidence),
            "OLANG_GUIX_RUNTIME_IMAGE": runtime,
            "OLANG_GUIX_BUILDER_PROFILE": profile,
            "OLANGC_GUIX_TEST_BIN": str(self.compiler),
        }
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            stack.enter_context(mock.patch.object(self.controller.Path, "cwd", return_value=self.root))
            stack.enter_context(mock.patch.object(self.controller.shutil, "which",
                                                  side_effect=lambda name: str(self.compiler.parent / name)))
            stack.enter_context(mock.patch.object(self.controller.shutil, "disk_usage",
                                                  side_effect=lambda path: types.SimpleNamespace(free=self.free)))
            stack.enter_context(mock.patch.object(self.controller.time, "monotonic", side_effect=lambda: self.now))
            stack.enter_context(mock.patch.object(self.controller.subprocess, "Popen", side_effect=self.fake_popen))
            stack.enter_context(mock.patch.object(self.controller.subprocess, "run",
                                                  side_effect=AssertionError("Unmocked subprocess.run forbidden")))
            self.killpg = stack.enter_context(mock.patch.object(self.controller.os, "killpg"))
            stack.enter_context(mock.patch.object(self.controller.os, "kill",
                                                  side_effect=AssertionError("Real process signaling forbidden")))
            stack.enter_context(mock.patch.object(self.controller.signal, "signal", side_effect=change_signal))
            stack.enter_context(redirect_stderr(io.StringIO()))
            result = self.controller.main()
        self.assertEqual(self.handlers, previous)
        self.assertFalse((self.active_evidence / ".receipt.json.next").exists())
        return result, json.loads((self.active_evidence / "receipt.json").read_text())

    def test_import_is_safe_without_configuration_or_processes(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("Import spawned a process")), \
                mock.patch.object(Path, "cwd", side_effect=AssertionError("Import entered main")):
            module = load_controller()
        self.assertTrue(callable(module.main))
        self.assertFalse(self.evidence.exists())

    def test_synthetic_success_records_all_checks_and_preserves_original(self):
        result, receipt = self.invoke(profile="ostadix-wasm")
        self.assertEqual((result, receipt["status"]), (0, "passed"))
        self.assertEqual(len(self.calls), 7)  # Build, explicit stop, four engines, browser.
        self.assertTrue(all(run["assertions_passed"] for run in receipt["runs"].values()))
        self.assertEqual(receipt["runs"]["build"]["deadline_seconds"], 10800)
        self.assertEqual(receipt["runs"]["wasmtime.success"]["deadline_seconds"], 600)
        self.assertEqual(receipt["runs"]["browser"]["deadline_seconds"], 1300)
        self.assertEqual(self.original.read_bytes(), self.source)
        self.assertEqual((self.evidence / "bundle/program.O").read_bytes(), self.source)
        self.assertFalse((self.evidence / "input").exists())
        self.killpg.assert_not_called()

    def test_existing_evidence_is_never_overwritten(self):
        self.evidence.mkdir()
        sentinel = self.evidence / "receipt.json"
        sentinel.write_bytes(b"existing evidence")
        with self.assertRaises(FileExistsError):
            self.invoke()
        self.assertEqual(sentinel.read_bytes(), b"existing evidence")
        self.assertEqual(self.calls, [])

    def test_invalid_profile_and_image_fail_without_subprocesses(self):
        for name, options in [("profile", {"profile": "default"}),
                              ("image", {"runtime": "guix:latest"})]:
            with self.subTest(name=name):
                result, receipt = self.invoke(evidence=self.directory / name, **options)
                self.assertEqual((result, receipt["status"]), (1, "failed"))
                self.assertEqual(self.calls, [])

    def test_build_input_binding_mismatches_prevent_engine_execution(self):
        replacements = {
            "source_sha256": "0" * 64, "plan_sha256": "0" * 64,
            "runtime_image": "other.invalid/runtime@sha256:" + "b" * 64,
            "builder_image": "other.invalid/builder@sha256:" + "c" * 64,
            "backend_grants": ["unexpected"], "adapters": [],
        }
        for key, value in replacements.items():
            with self.subTest(field=key):
                result, receipt = self.invoke(
                    evidence=self.directory / key,
                    change_build=lambda build: build.update({key: value}))
                self.assertEqual((result, receipt["status"]), (1, "failed"))
                self.assertEqual([Path(call["argv"][0]).name for call in self.calls], ["olangc"])
                self.assertFalse(receipt["runs"]["build"]["assertions_passed"])

    def test_tampered_assets_and_artifacts_fail_closed(self):
        for policy in ("tampered-asset", "artifact-changed"):
            with self.subTest(policy=policy):
                result, receipt = self.invoke(policy=policy, evidence=self.directory / policy)
                self.assertEqual((result, receipt["status"]), (1, "failed"))
                self.assertNotIn("browser", receipt["runs"])

    def test_wrong_engine_exit_kills_only_its_owned_group(self):
        result, receipt = self.invoke(policy="wrong-engine-exit")
        self.assertEqual((result, receipt["status"]), (1, "failed"))
        process = self.calls[-1]["process"]
        self.assertEqual(self.killpg.call_args_list, [mock.call(process.pid, signal.SIGTERM),
                                                     mock.call(process.pid, signal.SIGKILL)])
        self.assertEqual(receipt["runs"]["wasmtime.success"]["cleanup_scope"], "owned_process_group")
        self.assertNotIn("browser", receipt["runs"])

    def test_markers_and_browser_receipt_bindings_are_required(self):
        for policy in ("missing-engine-marker", "wrong-browser-binding"):
            with self.subTest(policy=policy):
                result, receipt = self.invoke(policy=policy, evidence=self.directory / policy)
                self.assertEqual((result, receipt["status"]), (1, "failed"))
                self.assertTrue(any(not run["assertions_passed"] for run in receipt["runs"].values()))

    def test_deadline_and_interruption_cleanup_owned_build_group_and_profile(self):
        for policy in ("deadline", "interrupt", "disk-drops"):
            with self.subTest(policy=policy):
                result, receipt = self.invoke(profile="ostadix-wasm", policy=policy,
                                              evidence=self.directory / policy)
                self.assertEqual((result, receipt["status"]), (1, "failed"))
                process = self.calls[0]["process"]
                self.assertEqual(self.killpg.call_args_list, [mock.call(process.pid, signal.SIGTERM),
                                                             mock.call(process.pid, signal.SIGKILL)])
                self.assertEqual(self.calls[0]["waits"], [30, 10, 10])
                self.assertEqual(self.calls[-1]["argv"][1:], ["stop", "ostadix-wasm"])
                self.assertEqual(len(self.calls), 2)
                self.assertEqual(receipt["runs"]["build"]["status"], "failed")
                self.assertTrue((self.active_evidence / "input/guix-package.O").exists())
                self.assertEqual(self.original.read_bytes(), self.source)

    def test_low_disk_never_builds_or_stops_an_unconfigured_profile(self):
        for index, profile in enumerate(("", "ostadix-wasm")):
            with self.subTest(profile=profile):
                result, receipt = self.invoke(profile=profile, free=1000,
                                              evidence=self.directory / f"low-disk-{index}")
                self.assertEqual((result, receipt["status"]), (1, "failed"))
                commands = [call["argv"][1:] for call in self.calls]
                self.assertEqual(commands, [["stop", "ostadix-wasm"]] if profile else [])
                self.assertIsNone(receipt["runs"]["build"]["returncode"])
                self.killpg.assert_not_called()


if __name__ == "__main__":
    unittest.main()
