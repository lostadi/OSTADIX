"""Linux client contract tests using real temporary files and mock providers.

These fixtures encode protocol responses; they do not execute original Plan 9,
recycle a domain, or qualify the coordinator's recovery implementation.
Only Linux-private controller ACK/current records can authorize recovery;
shared namespace markers are deliberately tested as insufficient evidence.
"""
from __future__ import annotations

import hashlib
import fcntl
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CLIENT_PATH = ROOT / "ocore/guest/linux/package-domain/p9"
LOADER = SourceFileLoader("plan9_linux_client_under_test", str(CLIENT_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
client_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = client_module
LOADER.exec_module(client_module)
# The repository permits group writes; installed companions are admitted as
# trusted local files. Exercise the loader with an exact private copy.
with tempfile.TemporaryDirectory() as companion_directory:
    companion = Path(companion_directory) / "protocol.py"
    companion.write_bytes((ROOT / "ocore/guest/plan9/unified/protocol.py").read_bytes())
    companion.chmod(0o600)
    protocol = client_module.load_protocol(companion)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def wait_for(predicate, message, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.002)
    raise AssertionError(message)


class Sink:
    def __init__(self):
        self._data = bytearray()
        self._lock = threading.Lock()

    def write(self, data):
        with self._lock:
            self._data.extend(data)
        return len(data)

    def flush(self):
        pass

    def getvalue(self):
        with self._lock:
            return bytes(self._data)


class Task:
    def __init__(self, callback):
        self.value = None
        self.error = None
        self.done = threading.Event()
        def invoke():
            try:
                self.value = callback()
            except BaseException as error:
                self.error = error
            finally:
                self.done.set()
        self.thread = threading.Thread(target=invoke, daemon=True)
        self.thread.start()

    def join(self, timeout=3):
        if not self.done.wait(timeout):
            raise AssertionError("fixture thread did not finish")
        self.thread.join()
        if self.error is not None:
            raise self.error
        return self.value


class Plan9LinuxClientTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root / "control"
        self.mount = self.root / "mounted"
        self.cwd = self.mount / "work" / "space ü"
        self.control.mkdir(mode=0o700)
        self.cwd.mkdir(parents=True)
        self.generation = "1234567890abcdef"
        self.instance = "1234567890abcdef" * 2
        self.service_root = self.mount / "services" / "plan9"
        self.service = self.service_root / ("g" + self.generation) / ("s" + self.instance)
        self.service.mkdir(parents=True)
        self.config = {"schema": "ostadix.p9.client-session/v1", "generation": self.generation,
            "instance": self.instance, "service_root": str(self.service_root),
            "linux_mount": str(self.mount), "plan9_mount": "/n", "recovery_mode": "disabled"}
        self.publish_json(self.control / "current.json", self.config)
        (self.service / "ready").write_bytes(protocol.ready_marker(self.generation, self.instance))
        self.stdout, self.stderr = Sink(), Sink()
        self.client = self.make_client()

    def installed_protocol(self):
        path = self.control / "p9_protocol.py"
        path.write_bytes((ROOT / "ocore/guest/plan9/unified/protocol.py").read_bytes())
        path.chmod(0o600)
        return path

    def make_client(self, **kwargs):
        return client_module.Client(self.control, protocol, self.stdout, self.stderr,
            poll_interval=.002, watchdog_grace=.05, recovery_timeout=kwargs.pop("recovery_timeout", .25), **kwargs)

    def publish(self, path, data):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        stage = path.with_name(path.name + ".fixture-stage")
        stage.write_bytes(data)
        stage.chmod(0o600)
        os.replace(stage, path)

    def publish_json(self, path, data):
        self.publish(path, (json.dumps(data) + "\n").encode())

    def pending(self):
        return json.loads((self.control / "pending.json").read_text())

    def request(self):
        def find():
            return next((p for p in self.service.glob("r*")
                         if p.is_dir() and (p / "submit").exists() and not (p / "done").exists()), None)
        directory = wait_for(find, "client did not publish a fresh request")
        wire = (directory / "request").read_bytes()
        decoded = protocol.validate_submit(wire, (directory / "submit").read_bytes())
        pending = self.pending()
        self.assertEqual(pending["request_id"], decoded.request_id)
        self.assertEqual(pending["request_sha256"], digest(wire))
        self.assertEqual(bytes.fromhex(pending["request_hex"]), wire)
        self.assertEqual(directory.name, "r" + decoded.request_id)
        self.assertEqual(directory.parent.name, "s" + decoded.instance)
        self.assertEqual(directory.parent.parent.name, "g" + decoded.generation)
        self.assertEqual((decoded.generation, decoded.instance), (self.generation, self.instance))
        self.publish(directory / "started", protocol.submit_marker(wire))
        return directory, wire, decoded

    def complete(self, directory, wire, *, stdout=b"", stderr=b"", status=b"", flags=0):
        for name, value in (("stdout", stdout), ("stderr", stderr)):
            path = directory / name
            prefix = path.read_bytes() if path.exists() else b""
            self.assertTrue(value.startswith(prefix), "fixture must append stream data")
            with path.open("ab") as stream:
                stream.write(value[len(prefix):])
        result = protocol.encode_result(wire, flags=flags, stdout=stdout, stderr=stderr, status=status)
        self.publish(directory / "status", status)
        self.publish(directory / "result", result)
        if flags & (protocol.FLAG_TIMEOUT | protocol.FLAG_CANCELLED):
            self.publish(self.service / "reset-required", protocol.reset_marker(wire, result))
        self.publish(directory / "done", protocol.done_marker(wire, result))
        return result

    def invoke(self, argv=None, **kwargs):
        return self.client.run(argv or ["echo"], cwd=str(self.cwd), stdin=kwargs.pop("stdin", b""), **kwargs)

    def with_provider(self, callback, argv=None, **kwargs):
        provider = Task(lambda: callback(*self.request()))
        try:
            return self.invoke(argv, **kwargs)
        finally:
            provider.join()

    def test_exact_binary_argv_cwd_and_raw_status_remain_separate(self):
        stdin = bytes(range(256)) + b"\x00\xfftail\n"
        stdout, stderr, status = b"out\x00\xff", b"err\x00\xfe", b"native failure\xff"
        arguments = ["echo", "one two", "quote'arg", "", "é", "line\nargument"]
        def provider(directory, wire, request):
            self.assertEqual(request.argv, ("/arm64/bin/echo", *arguments[1:]))
            self.assertEqual(request.cwd, "/n/work/space ü")
            self.assertEqual(request.stdin, stdin)
            self.complete(directory, wire, stdout=stdout, stderr=stderr, status=status)
        completion = self.with_provider(provider, arguments, stdin=stdin)
        self.assertEqual(completion.exit_code, 1)
        self.assertEqual(completion.result.status, status)
        self.assertEqual(self.stdout.getvalue(), stdout)
        self.assertEqual(self.stderr.getvalue(), stderr)
        self.assertFalse(completion.recovered)
        self.assertFalse((self.control / "pending.json").exists())

    def test_relative_and_explicit_bin_program_resolution(self):
        for command, expected in (("./program", "/n/work/space ü/program"), ("/bin/cat", "/bin/cat")):
            with self.subTest(command=command):
                def provider(directory, wire, request):
                    self.assertEqual(request.argv, (expected, "argument"))
                    self.complete(directory, wire)
                self.assertEqual(self.with_provider(provider, [command, "argument"]).exit_code, 0)

    def test_output_is_streamed_before_done_without_duplicate_bytes(self):
        first, last = b"first\x00", b"\xfflast\n"
        def provider(directory, wire, request):
            (directory / "stdout").write_bytes(first)
            wait_for(lambda: self.stdout.getvalue() == first, "client buffered output until done")
            self.assertFalse((directory / "done").exists())
            self.complete(directory, wire, stdout=first + last, stderr=b"separate")
        completion = self.with_provider(provider)
        self.assertEqual(completion.exit_code, 0)
        self.assertEqual(self.stdout.getvalue(), first + last)
        self.assertEqual(self.stderr.getvalue(), b"separate")

    def test_changed_or_shrinking_stream_prefix_fails_before_watchdog_and_retains_pending(self):
        for replacement in (b"xirst", b"fi"):
            with self.subTest(replacement=replacement):
                if (self.control / "pending.json").exists():
                    (self.control / "pending.json").unlink()
                for directory in self.service.glob("r*"):
                    if directory.is_dir():
                        import shutil
                        shutil.rmtree(directory)
                self.stdout = Sink(); self.client = self.make_client()
                changed = threading.Event()
                def provider(directory, wire, request):
                    (directory / "stdout").write_bytes(b"first")
                    wait_for(lambda: self.stdout.getvalue() == b"first", "initial prefix was not streamed")
                    self.publish(directory / "stdout", replacement)
                    changed.set()
                started = time.monotonic()
                with self.assertRaises(client_module.ClientError):
                    self.with_provider(provider, timeout_ms=2000)
                self.assertTrue(changed.is_set())
                self.assertLess(time.monotonic() - started, 1, "client waited for watchdog instead of rejecting changed prefix")
                self.assertTrue((self.control / "pending.json").exists())

    def test_missing_stale_or_malformed_ready_never_publishes(self):
        ready = self.service / "ready"
        for marker in (None, b"partial", protocol.ready_marker("fedcba0987654321", self.instance),
                       protocol.ready_marker(self.generation, "f" * 32)):
            with self.subTest(marker=marker):
                if marker is None:
                    ready.unlink(missing_ok=True)
                else:
                    ready.write_bytes(marker)
                with self.assertRaises(client_module.ClientError):
                    self.invoke()
                self.assertFalse(list(self.service.glob("r*/submit")))
                self.assertFalse((self.control / "pending.json").exists())

    def test_missing_current_and_initial_reset_fail_closed(self):
        (self.control / "current.json").unlink()
        with self.assertRaises(client_module.ClientError):
            self.invoke()
        self.publish_json(self.control / "current.json", self.config)
        (self.service / "reset-required").write_bytes(b"untrusted or incomplete reset notice")
        with self.assertRaises(client_module.ClientError):
            self.invoke()
        self.assertFalse(list(self.service.glob("r*/submit")))

    def test_existing_pending_crash_journal_never_replays_old_request(self):
        request_id = "a" * 32
        wire = protocol.encode_request(self.generation, self.instance, request_id,
            ["/arm64/bin/echo", "old"], cwd="/n/work/space ü")
        directory = self.service / ("r" + request_id); directory.mkdir()
        (directory / "request").write_bytes(wire)
        (directory / "started").write_bytes(protocol.submit_marker(wire))
        pending = {"schema": "ostadix.p9.client-pending/v1", "generation": self.generation,
            "instance": self.instance, "request_id": request_id, "request_sha256": digest(wire),
            "service_root": str(self.service_root), "phase": "submitted", "request_hex": wire.hex()}
        self.publish_json(self.control / "pending.json", pending)
        with self.assertRaises(client_module.ClientError):
            self.invoke(["echo", "new"])
        # Acquiring the successor lock declares abandoned work unknown, so a
        # private controller can request recovery. No identities or bytes are
        # replaced, and the old request is still never submitted again.
        self.assertEqual(self.pending(), {**pending, "phase": "unknown"})
        self.assertEqual((directory / "request").read_bytes(), wire)
        self.assertFalse((directory / "submit").exists())
        self.assertEqual([p.name for p in self.service.glob("r*") if p.is_dir()], [directory.name])

    def test_another_client_cannot_dispatch_while_first_holds_lock(self):
        accepted, release = threading.Event(), threading.Event()
        def provider():
            directory, wire, request = self.request()
            accepted.set()
            self.assertTrue(release.wait(2))
            self.complete(directory, wire)
        server = Task(provider)
        first = Task(self.invoke)
        try:
            self.assertTrue(accepted.wait(2))
            with self.assertRaises(client_module.BusyError):
                self.make_client().run(["echo", "second"], cwd=str(self.cwd), stdin=b"")
            self.assertEqual(len(list(self.service.glob("r*/submit"))), 1)
        finally:
            release.set()
            server.join()
        self.assertEqual(first.join().exit_code, 0)

    def test_existing_os_lock_blocks_publication_even_without_pending_journal(self):
        with (self.control / "client.lock").open("a+b") as lock:
            (self.control / "client.lock").chmod(0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(client_module.BusyError):
                self.invoke()
        self.assertFalse((self.control / "pending.json").exists())
        self.assertFalse(list(self.service.glob("r*/submit")))

    def enable_recovery(self, timeout=.25):
        self.config["recovery_mode"] = "controller-v1"
        self.publish_json(self.control / "current.json", self.config)
        self.client = self.make_client(recovery_timeout=timeout)

    def acknowledge(self, directory, wire, result, *, change_current=True, changes=None, fresh_ready=True):
        request = protocol.decode_request(wire)
        new_instance = "fedcba0987654321" * 2
        ready = protocol.ready_marker(self.generation, new_instance)
        if fresh_ready:
            self.publish(self.service_root / ("g" + self.generation) / ("s" + new_instance) / "ready", ready)
        acknowledgment = {"schema": "ostadix.p9.recovered/v1", "generation": self.generation,
            "old_instance": self.instance, "request_id": request.request_id,
            "request_sha256": digest(wire), "result_sha256": digest(result) if result is not None else None,
            "reset_sha256": digest((self.service / "reset-required").read_bytes()) if result is not None else None,
            "done_sha256": digest((directory / "done").read_bytes()) if result is not None else None,
            "new_instance": new_instance, "ready_sha256": digest(ready),
            "outcome": "interrupted" if result is not None else "unknown"}
        acknowledgment.update(changes or {})
        path = self.control / "recovered" / ("g" + self.generation + "-s" + self.instance + "-r" + request.request_id + ".json")
        self.publish_json(path, acknowledgment)
        updated = dict(self.config, instance=new_instance)
        if change_current:
            self.publish_json(self.control / "current.json", updated)
        return updated

    def successful_recovery(self, flag, exit_code):
        self.enable_recovery(timeout=1)
        def provider():
            directory, wire, request = self.request()
            if flag == protocol.FLAG_CANCELLED:
                self.client.cancel_requested = True
                wait_for(lambda: (directory / "cancel").exists(), "client did not publish cancellation")
                protocol.validate_cancel(wire, (directory / "cancel").read_bytes())
            result = self.complete(directory, wire, stdout=b"retained\0\xff", stderr=b"diagnostic",
                status=b"native interrupted status", flags=flag)
            return directory, wire, result
        server = Task(provider)
        invocation = Task(self.invoke)
        directory, wire, result = server.join()
        self.assertFalse(invocation.done.wait(.03), "interrupted completion escaped before recovery acknowledgment")
        updated = self.acknowledge(directory, wire, result, change_current=False)
        self.assertFalse(invocation.done.wait(.03), "acknowledgment alone bypassed current.json publication")
        self.assertTrue((self.control / "pending.json").exists())
        self.publish_json(self.control / "current.json", updated)
        completion = invocation.join()
        self.assertEqual(completion.exit_code, exit_code)
        self.assertTrue(completion.recovered)
        self.assertEqual(completion.result.flags, flag)
        self.assertEqual(completion.result.status, b"native interrupted status")
        self.assertEqual(self.stdout.getvalue(), b"retained\0\xff")
        self.assertEqual(self.stderr.getvalue(), b"diagnostic")
        self.assertFalse((self.control / "pending.json").exists())
        self.assertEqual(len(list(self.service.glob("r*/submit"))), 1)

    def test_cancel_is_request_bound_and_waits_for_ack_fresh_ready_and_current_last(self):
        self.successful_recovery(protocol.FLAG_CANCELLED, 130)

    def test_timeout_exit_124_is_exposed_only_after_recovery(self):
        self.successful_recovery(protocol.FLAG_TIMEOUT, 124)

    def failed_recovery(self, *, changes=None, missing_ack=False, fresh_ready=True, change_current=True):
        self.enable_recovery(timeout=.10)
        def provider(directory, wire, request):
            result = self.complete(directory, wire, flags=protocol.FLAG_TIMEOUT, status=b"timed out")
            if not missing_ack:
                self.acknowledge(directory, wire, result, changes=changes, fresh_ready=fresh_ready,
                    change_current=change_current)
        with self.assertRaises(client_module.ClientError):
            self.with_provider(provider)
        self.assertTrue((self.control / "pending.json").exists())
        self.assertEqual(len(list(self.service.glob("r*/submit"))), 1)

    def test_missing_recovery_ack_retains_pending_and_refuses_completion(self):
        self.failed_recovery(missing_ack=True)

    def test_mismatched_recovery_result_digest_is_rejected(self):
        self.failed_recovery(changes={"result_sha256": "f" * 64})

    def test_recovery_cannot_reuse_old_instance(self):
        self.failed_recovery(changes={"new_instance": self.instance})

    def test_recovery_ack_and_current_without_fresh_ready_are_insufficient(self):
        self.failed_recovery(fresh_ready=False)

    def test_recovery_ack_and_ready_without_current_last_remain_pending(self):
        self.failed_recovery(change_current=False)

    def test_corrupt_final_stream_digest_refuses_completion_and_keeps_pending(self):
        def provider(directory, wire, request):
            stdout = b"otherwise valid output"
            (directory / "stdout").write_bytes(stdout)
            (directory / "stderr").write_bytes(b"")
            (directory / "status").write_bytes(b"")
            result = bytearray(protocol.encode_result(wire, flags=0, stdout=stdout, stderr=b"", status=b""))
            result[136] ^= 1
            result = bytes(result)
            self.publish(directory / "result", result)
            self.publish(directory / "done", protocol.done_marker(wire, result))
        with self.assertRaises(client_module.ClientError):
            self.with_provider(provider)
        self.assertTrue((self.control / "pending.json").exists())

    def test_watchdog_unknown_recovery_never_dispatches_without_another_explicit_call(self):
        self.enable_recovery()
        provider = Task(self.request)
        with self.assertRaisesRegex(client_module.ClientError, "watchdog"):
            self.invoke(["echo", "uncertain"], timeout_ms=20)
        directory, wire, request = provider.join()
        self.assertTrue((self.control / "pending.json").exists())
        updated = self.acknowledge(directory, wire, None)
        with self.assertRaisesRegex(client_module.ClientError, "not submitted"):
            self.invoke(["echo", "new"])
        self.assertFalse((self.control / "pending.json").exists())
        self.assertEqual((directory / "request").read_bytes(), wire)
        self.assertEqual(len(list(self.service.glob("r*/submit"))), 1)
        self.instance = updated["instance"]
        self.service = self.service_root / ("g" + self.generation) / ("s" + self.instance)
        self.assertFalse(list(self.service.glob("r*/submit")))
        def new_provider(new_directory, new_wire, new_request):
            self.assertNotEqual(new_request.request_id, request.request_id)
            self.assertEqual(new_request.argv, ("/arm64/bin/echo", "explicit"))
            self.complete(new_directory, new_wire)
        self.assertEqual(self.with_provider(new_provider, ["echo", "explicit"]).exit_code, 0)

    def test_cwd_outside_mount_including_same_text_prefix_is_not_published(self):
        outside = Path(str(self.mount) + "-outside")
        outside.mkdir()
        for cwd in (self.root, outside):
            with self.subTest(cwd=cwd), self.assertRaises(client_module.ClientError):
                self.client.run(["echo"], cwd=str(cwd), stdin=b"")
            self.assertFalse((self.control / "pending.json").exists())
            self.assertFalse(list(self.service.glob("r*/submit")))

    def test_cli_failure_is_125_and_not_a_program_exit_status(self):
        (self.control / "current.json").unlink()
        outcome = subprocess.run([sys.executable, str(CLIENT_PATH), "--control-dir", str(self.control),
            "--protocol", str(self.installed_protocol()), "--cwd", str(self.cwd), "--", "echo"],
            input=b"", capture_output=True, timeout=2)
        self.assertEqual(outcome.returncode, 125)
        self.assertEqual(outcome.stdout, b"")
        self.assertIn(b"p9:", outcome.stderr)
        self.assertFalse(list(self.service.glob("r*/submit")))

    def test_cli_preserves_raw_status_file_and_binary_streams(self):
        stdin, stdout, stderr, status = b"input\0\xff", b"output\0\xfe", b"stderr\0", b"raw status\xff"
        input_file, status_file = self.root / "stdin.bin", self.root / "status.bin"
        input_file.write_bytes(stdin)
        def provider():
            directory, wire, request = self.request()
            self.assertEqual(request.argv, ("/arm64/bin/echo", "one two", ""))
            self.assertEqual(request.stdin, stdin)
            self.complete(directory, wire, stdout=stdout, stderr=stderr, status=status)
        server = Task(provider)
        try:
            outcome = subprocess.run([sys.executable, str(CLIENT_PATH), "--control-dir", str(self.control),
                "--protocol", str(self.installed_protocol()), "--cwd", str(self.cwd),
                "--stdin-file", str(input_file), "--status-file", str(status_file), "--", "echo", "one two", ""],
                input=b"", capture_output=True, timeout=3)
        finally:
            server.join()
        self.assertEqual(outcome.returncode, 1)
        self.assertEqual(outcome.stdout, stdout)
        self.assertEqual(outcome.stderr, stderr)
        self.assertEqual(status_file.read_bytes(), status)

    def test_private_control_leaf_below_untrusted_nonsticky_ancestor_is_refused(self):
        # Normal successful tests also exercise an owned private leaf below
        # the root-owned sticky /tmp directory, which remains permitted.
        for mode in (0o770, 0o777):
            with self.subTest(mode=oct(mode)):
                parent = self.root / ("untrusted-" + str(mode))
                parent.mkdir(); parent.chmod(mode)
                control = parent / "private"; control.mkdir(mode=0o700)
                self.publish_json(control / "current.json", self.config)
                client = client_module.Client(control, protocol, Sink(), Sink(),
                    poll_interval=.002, watchdog_grace=.01, recovery_timeout=.05)
                with self.assertRaises(client_module.ClientError):
                    client.run(["echo"], cwd=str(self.cwd), stdin=b"", timeout_ms=10)
                self.assertFalse((control / "pending.json").exists())
                self.assertFalse(list(self.service.glob("r*/submit")))

    def abandoned_interrupted_snapshot(self, phase, *, corrupt=False):
        self.enable_recovery()
        request_id = "b" * 32
        wire = protocol.encode_request(self.generation, self.instance, request_id,
            ["/arm64/bin/echo", "abandoned"], cwd="/n/work/space ü")
        directory = self.service / ("r" + request_id); directory.mkdir()
        (directory / "request").write_bytes(wire)
        (directory / "submit").write_bytes(protocol.submit_marker(wire))
        (directory / "started").write_bytes(protocol.submit_marker(wire))
        pending = {"schema": "ostadix.p9.client-pending/v1", "generation": self.generation,
            "instance": self.instance, "request_id": request_id, "request_sha256": digest(wire),
            "service_root": str(self.service_root), "phase": phase, "request_hex": wire.hex()}
        self.publish_json(self.control / "pending.json", pending)
        result = self.complete(directory, wire, stdout=b"old-output\0", stderr=b"old-error",
            status=b"original interruption", flags=protocol.FLAG_TIMEOUT)
        if phase == "interrupted":
            pending.update(result_sha256=digest(result),
                reset_sha256=digest((self.service / "reset-required").read_bytes()),
                done_sha256=digest((directory / "done").read_bytes()))
            self.publish_json(self.control / "pending.json", pending)
        updated = self.acknowledge(directory, wire, result)
        if corrupt:
            self.publish(directory / "stdout", b"changed after acknowledgment")
        with self.assertRaises(client_module.ClientError) as caught:
            self.invoke(["echo", "must-not-dispatch"])
        self.assertEqual(self.stdout.getvalue(), b"", "old output must not replay during crash recovery")
        self.assertEqual(self.stderr.getvalue(), b"")
        self.assertEqual((directory / "request").read_bytes(), wire)
        new_directory = self.service_root / ("g" + self.generation) / ("s" + updated["instance"])
        self.assertFalse(list(new_directory.glob("r*/submit")))
        self.assertFalse((self.control / "results").exists(), "abandoned work must not become a new success receipt")
        if corrupt:
            self.assertTrue((self.control / "pending.json").exists())
        else:
            self.assertIn("not submitted", str(caught.exception))
            self.assertFalse((self.control / "pending.json").exists())

    def test_submitted_crash_journal_can_validate_interrupted_ack_without_replay(self):
        self.abandoned_interrupted_snapshot("submitted")

    def test_unknown_crash_journal_can_validate_interrupted_ack_without_replay(self):
        self.abandoned_interrupted_snapshot("unknown")

    def test_interrupted_crash_journal_with_advanced_private_current_reconciles_without_replay(self):
        self.abandoned_interrupted_snapshot("interrupted")

    def test_crash_window_recovery_cannot_trust_ack_over_corrupt_retained_stream(self):
        self.abandoned_interrupted_snapshot("unknown", corrupt=True)

    def test_final_emission_uses_validated_snapshot_not_later_file_bytes(self):
        paths = {}
        fixture = self
        class ConcurrentChangeProtocol:
            def __getattr__(self, name):
                return getattr(protocol, name)

            def validate_result(self, *args, **kwargs):
                result = protocol.validate_result(*args, **kwargs)
                # Deterministically model an external writer immediately after
                # validation. The returned completion must cover only the
                # byte snapshot that the real protocol validator checked.
                with (paths["directory"] / "stdout").open("ab") as stream:
                    stream.write(b"UNVALIDATED-TAIL")
                fixture.publish(paths["directory"] / "stderr", b"UNVALIDATED-ERROR")
                return result
        self.client = client_module.Client(self.control, ConcurrentChangeProtocol(), self.stdout, self.stderr,
            poll_interval=.002, watchdog_grace=.05, recovery_timeout=.1)
        def provider(directory, wire, request):
            paths["directory"] = directory
            self.complete(directory, wire, stdout=b"validated")
        completion = self.with_provider(provider)
        self.assertEqual(completion.exit_code, 0)
        self.assertEqual(self.stdout.getvalue(), b"validated")
        self.assertEqual(self.stderr.getvalue(), b"")

    def test_cli_sigint_publishes_bound_cancel_and_exits_130_only_after_recovery(self):
        self.enable_recovery()
        status_path = self.root / "cancel-status.bin"
        process = subprocess.Popen([sys.executable, str(CLIENT_PATH), "--control-dir", str(self.control),
            "--protocol", str(self.installed_protocol()), "--cwd", str(self.cwd),
            "--status-file", str(status_path), "--recovery-timeout", "2", "--", "sleep", "30"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            directory, wire, request = self.request()
            process.send_signal(signal.SIGINT)
            wait_for(lambda: (directory / "cancel").exists(), "SIGINT did not publish cancellation")
            protocol.validate_cancel(wire, (directory / "cancel").read_bytes())
            result = self.complete(directory, wire, stdout=b"retained prefix", status=b"signal cancellation",
                flags=protocol.FLAG_CANCELLED)
            time.sleep(.04)
            self.assertIsNone(process.poll(), "CLI returned cancellation before domain recovery acknowledgment")
            self.acknowledge(directory, wire, result)
            stdout, stderr = process.communicate(timeout=2)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)
        self.assertEqual(process.returncode, 130)
        self.assertEqual(stdout, b"retained prefix")
        self.assertEqual(stderr, b"")
        self.assertEqual(status_path.read_bytes(), b"signal cancellation")
        self.assertFalse((self.control / "pending.json").exists())

    def test_cancel_before_publication_creates_no_journal_or_native_request(self):
        self.client.cancel_requested = True
        with self.assertRaises(client_module.ClientError):
            self.invoke(["echo", "must-not-run"])
        self.assertFalse((self.control / "pending.json").exists())
        self.assertFalse(list(self.service.glob("r*/submit")))

    def test_cancel_after_request_write_is_published_before_submit(self):
        self.enable_recovery(timeout=1)
        original_publish = client_module.publish
        observed = {"request": False, "cancel_before_submit": False}

        def publication_boundary(path, data):
            if path.name == "submit":
                # Check at the publication boundary, so scheduler delay cannot
                # hide an incorrectly ordered submit-then-cancel sequence.
                self.assertTrue((path.parent / "cancel").exists())
                protocol.validate_cancel((path.parent / "request").read_bytes(),
                    (path.parent / "cancel").read_bytes())
                observed["cancel_before_submit"] = True
            original_publish(path, data)
            if path.name == "request":
                self.assertEqual(path.read_bytes(), data)
                self.assertFalse((path.parent / "submit").exists())
                observed["request"] = True
                self.client.cancel_requested = True

        def provider(directory, wire, request):
            protocol.validate_cancel(wire, (directory / "cancel").read_bytes())
            result = self.complete(directory, wire, flags=protocol.FLAG_CANCELLED,
                status=b"service: command cancelled")
            wait_for(lambda: self.pending().get("phase") == "interrupted",
                "client did not validate the pre-cancelled completion")
            self.acknowledge(directory, wire, result)

        with patch.object(client_module, "publish", side_effect=publication_boundary):
            completion = self.with_provider(provider)
        self.assertEqual(observed, {"request": True, "cancel_before_submit": True})
        self.assertEqual(completion.exit_code, 130)
        self.assertTrue(completion.recovered)
        self.assertEqual(self.stdout.getvalue(), b"")
        self.assertEqual(self.stderr.getvalue(), b"")
        self.assertFalse((self.control / "pending.json").exists())

    def test_namespace_recovered_and_ready_cannot_authorize_private_controller_recovery(self):
        self.enable_recovery(timeout=.10)
        current_before = (self.control / "current.json").read_bytes()
        marker_written = threading.Event()
        def provider(directory, wire, request):
            result = self.complete(directory, wire, status=b"timed out", flags=protocol.FLAG_TIMEOUT)
            replacement = "f" * 32
            new_directory = self.service_root / ("g" + self.generation) / ("s" + replacement)
            self.publish(new_directory / "ready", protocol.ready_marker(self.generation, replacement))
            marker = (f"OC9RECOVER1 {self.generation} {self.instance} {request.request_id} "
                      f"{digest(wire)} {digest(result)} {replacement}\n").encode()
            self.publish(new_directory / "recovered", marker)
            marker_written.set()
        with self.assertRaises(client_module.ClientError):
            self.with_provider(provider)
        self.assertTrue(marker_written.is_set())
        self.assertTrue((self.control / "pending.json").exists())
        self.assertEqual(self.pending()["phase"], "interrupted")
        self.assertEqual((self.control / "current.json").read_bytes(), current_before)
        self.assertFalse((self.control / "recovered").exists())
        self.assertFalse((self.control / "results").exists())
        self.assertEqual(len(list(self.service.glob("r*/submit"))), 1)
        # Even a controller session pointer advanced to the matching fresh
        # ready cannot replace the required private acknowledgment.
        advanced = dict(self.config, instance="f" * 32)
        self.publish_json(self.control / "current.json", advanced)
        with self.assertRaises(client_module.ClientError):
            self.invoke(["echo", "must-not-dispatch"])
        self.assertTrue((self.control / "pending.json").exists())
        self.assertEqual(json.loads((self.control / "current.json").read_text()), advanced)
        fresh = self.service_root / ("g" + self.generation) / ("s" + advanced["instance"])
        self.assertFalse(list(fresh.glob("r*/submit")))
        self.assertFalse((self.control / "results").exists())

    def test_native_marker_recovery_mode_is_not_an_accepted_current_contract(self):
        self.config["recovery_mode"] = "native-marker-v1"
        self.publish_json(self.control / "current.json", self.config)
        with self.assertRaises(client_module.ClientError):
            self.invoke(timeout_ms=10)
        self.assertFalse((self.control / "pending.json").exists())
        self.assertFalse(list(self.service.glob("r*/submit")))

    def test_removed_session_file_api_and_native_cli_options_are_rejected(self):
        selector = self.root / "session.json"
        self.publish_json(selector, {"generation": self.generation, "instance": self.instance,
                                    "root": str(self.service_root)})
        with self.assertRaises(TypeError):
            client_module.Client(None, protocol, self.stdout, self.stderr, session_file=selector)
        companion = self.installed_protocol()
        for option in (("--session-file", str(selector)), ("--legacy-session",),
                       ("--linux-mount", str(self.mount)), ("--plan9-mount", "/n")):
            with self.subTest(option=option):
                outcome = subprocess.run([sys.executable, str(CLIENT_PATH), "--control-dir", str(self.control),
                    "--protocol", str(companion), *option, "--", "echo"],
                    input=b"", capture_output=True, timeout=2)
                self.assertEqual(outcome.returncode, 2)
                self.assertEqual(outcome.stdout, b"")
                self.assertFalse((self.control / "pending.json").exists())
                self.assertFalse(list(self.service.glob("r*/submit")))


if __name__ == "__main__":
    unittest.main()
