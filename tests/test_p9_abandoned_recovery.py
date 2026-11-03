"""Abandoned-client recovery using the actual Linux client and controller.

The SIGKILL case runs the original p9 CLI. Other cases place crash-window
journals in private temporary files. Only the controller's fixed pathname
mapping is redirected into that fixture. A fixture supplies the native host's
ACK/current frame and fresh ready bytes; this is not a native recycle or guest
boot qualification. Production request framing, locking, journaling,
controller event detection/publication and client ACK checks execute unchanged.
"""
from __future__ import annotations

import fcntl
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CLIENT_PATH = ROOT / "ocore/guest/linux/package-domain/p9"
CONTROLLER_PATH = ROOT / "ocore/guest/linux/package-domain/p9-controller"
PROTOCOL_PATH = ROOT / "ocore/guest/plan9/unified/protocol.py"


def load(name, path):
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


client = load("p9_abandoned_client_under_test", CLIENT_PATH)
controller = load("p9_abandoned_controller_under_test", CONTROLLER_PATH)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def wait_for(callback, description, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = callback()
        if result:
            return result
        time.sleep(.002)
    raise AssertionError(description)


class Task:
    def __init__(self, callback):
        self.error = None
        self.value = None
        self.done = threading.Event()

        def run():
            try:
                self.value = callback()
            except BaseException as error:
                self.error = error
            finally:
                self.done.set()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def join(self):
        if not self.done.wait(3):
            raise AssertionError("successor client did not finish")
        self.thread.join()
        return self.error


class Fixture:
    def __init__(self, recovery_timeout=.75):
        self.temporary = tempfile.TemporaryDirectory(prefix="p9-abandoned-")
        self.root = Path(self.temporary.name)
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.mount = self.root / "shared"
        self.cwd = self.mount / "work"
        self.cwd.mkdir(parents=True)
        self.generation = "1234567890abcdef"
        self.instance = "1234567890abcdef" * 2
        self.new_instance = "fedcba0987654321" * 2
        self.service_root = self.mount / "services/plan9"
        self.service = self.service_root / ("g" + self.generation) / ("s" + self.instance)
        self.service.mkdir(parents=True)
        self.protocol_path = self.control / "protocol.py"
        self.protocol_path.write_bytes(PROTOCOL_PATH.read_bytes())
        self.protocol_path.chmod(0o600)
        self.protocol = client.load_protocol(self.protocol_path)
        self.session = {"schema": client.SESSION_SCHEMA,
            "generation": self.generation, "instance": self.instance,
            "service_root": str(self.service_root), "linux_mount": str(self.mount),
            "plan9_mount": "/n", "recovery_mode": "controller-v1", "state": "ready"}
        self.fd = controller.open_control(str(self.control))
        self.controller = controller.Controller(self.fd)
        self.sequence = 0
        self.apply(self.session)
        (self.service / "ready").write_bytes(self.protocol.ready_marker(self.generation, self.instance))
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()
        self.client = client.Client(self.control, self.protocol, self.stdout, self.stderr,
            poll_interval=.002, recovery_timeout=recovery_timeout)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        os.close(self.fd)
        self.temporary.cleanup()

    def apply(self, current, recovered=None):
        self.sequence += 1
        frame = {"seq": self.sequence, "current": current}
        if recovered is not None:
            frame["recovered"] = recovered
        mapping = {key: self.session[key] for key in controller.MAPPING}
        with patch.object(controller, "MAPPING", mapping):
            self.controller.apply(json.dumps(frame).encode())

    def invoke(self):
        return self.client.run(["echo", "must-not-be-submitted"], str(self.cwd), b"new\x00input")

    def pending(self):
        return json.loads((self.control / "pending.json").read_bytes())

    def abandoned(self, phase):
        wire = self.protocol.encode_request(self.generation, self.instance, "a" * 32,
            ["/arm64/bin/cat", "original"], cwd="/n/work", stdin=b"old\x00\xffinput")
        directory = self.service / ("r" + "a" * 32)
        directory.mkdir()
        (directory / "request").write_bytes(wire)
        (directory / "submit").write_bytes(self.protocol.submit_marker(wire))
        pending = {"schema": client.PENDING_SCHEMA, "generation": self.generation,
            "instance": self.instance, "request_id": "a" * 32,
            "request_sha256": digest(wire), "request_hex": wire.hex(),
            "service_root": str(self.service_root), "phase": phase}
        if phase == "interrupted":
            pending.update(result_sha256="1" * 64, reset_sha256="2" * 64, done_sha256="3" * 64)
        client.local_write(self.control / "pending.json", pending)
        return pending, directory, wire

    def unknown_event(self):
        return wait_for(self.controller.unknown_event, "controller did not emit bound unknown event")

    def acknowledge(self, pending, *, ready=True, changes=None):
        ready_bytes = self.protocol.ready_marker(self.generation, self.new_instance)
        if ready:
            directory = self.service_root / ("g" + self.generation) / ("s" + self.new_instance)
            directory.mkdir(parents=True)
            (directory / "ready").write_bytes(ready_bytes)
        ack = {"schema": client.RECOVERY_SCHEMA, "generation": self.generation,
            "old_instance": self.instance, "new_instance": self.new_instance,
            "request_id": pending["request_id"], "request_sha256": pending["request_sha256"],
            "outcome": "unknown", "result_sha256": None, "reset_sha256": None,
            "done_sha256": None, "ready_sha256": digest(ready_bytes)}
        ack.update(changes or {})
        self.apply(dict(self.session, instance=self.new_instance), ack)


class AbandonedRecoveryTests(unittest.TestCase):
    def assert_no_new_submission(self, fixture, original_directory, original_wire):
        self.assertEqual((original_directory / "request").read_bytes(), original_wire)
        self.assertEqual((original_directory / "submit").read_bytes(), fixture.protocol.submit_marker(original_wire))
        self.assertEqual(list(fixture.service_root.glob("g*/s*/r*/request")), [original_directory / "request"])
        self.assertEqual(list(fixture.service_root.glob("g*/s*/r*/submit")), [original_directory / "submit"])
        self.assertEqual(fixture.stdout.getvalue(), b"")
        self.assertEqual(fixture.stderr.getvalue(), b"")
        self.assertFalse((fixture.control / "results").exists())

    def finish_unknown_recovery(self, fixture, old, directory, wire):
        task = Task(fixture.invoke)
        try:
            event = fixture.unknown_event()
            expected = {key: old[key] for key in ("generation", "instance", "request_id", "request_sha256")}
            self.assertEqual(event, dict(expected, event="unknown"))
            self.assertEqual(fixture.pending(), dict(old, phase="unknown"))
            self.assertIsNone(fixture.controller.unknown_event(), "one identity emits only once")
            # The event appears only after the successor owns the exclusive lock.
            second = client.Client(fixture.control, fixture.protocol, io.BytesIO(), io.BytesIO())
            with self.assertRaises(client.BusyError):
                second.run(["echo", "concurrent"], str(fixture.cwd), b"")
            self.assertEqual(fixture.pending(), dict(old, phase="unknown"))
            fixture.acknowledge(old)
        finally:
            error = task.join()
        self.assertIsInstance(error, client.ClientError)
        self.assertIn("prior request recovered", str(error))
        self.assertIn("this invocation was not submitted", str(error))
        self.assertFalse((fixture.control / "pending.json").exists())
        self.assert_no_new_submission(fixture, directory, wire)

    def test_actual_cli_sigkill_after_submit_recovers_without_replaying_either_command(self):
        if Path("/usr/local/libexec/p9-history").exists():
            self.skipTest("host-installed guest history helper changes the standalone CLI fixture")
        with Fixture() as fixture:
            process = subprocess.Popen([sys.executable, "-B", str(CLIENT_PATH),
                "--control-dir", str(fixture.control), "--protocol", str(fixture.protocol_path),
                "--cwd", str(fixture.cwd), "--timeout-ms", "120000", "--", "cat"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                process.stdin.write(b"original\x00\xffstdin")
                process.stdin.close()
                process.stdin = None

                def submitted():
                    try:
                        pending = fixture.pending()
                    except (FileNotFoundError, json.JSONDecodeError):
                        return None
                    return pending if pending["phase"] == "submitted" else None

                old = wait_for(submitted, "original CLI did not reach submitted journal")
                directory = fixture.service / ("r" + old["request_id"])
                wire = (directory / "request").read_bytes()
                self.assertEqual(fixture.protocol.decode_request(wire).stdin, b"original\x00\xffstdin")
                process.kill()
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, -9)
                self.assertEqual((stdout, stderr), (b"", b""))
                self.assertEqual(fixture.pending(), old, "SIGKILL cannot journal unknown")
                self.finish_unknown_recovery(fixture, old, directory, wire)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)

    def test_each_abandoned_live_phase_journals_unknown_before_requesting_recovery(self):
        for phase in ("prepared", "submitted", "awaiting-completion", "cancelling"):
            with self.subTest(phase=phase), Fixture() as fixture:
                old, directory, wire = fixture.abandoned(phase)
                self.finish_unknown_recovery(fixture, old, directory, wire)

    def test_already_unknown_and_interrupted_journals_are_not_rewritten(self):
        for phase in ("unknown", "interrupted"):
            with self.subTest(phase=phase), Fixture(recovery_timeout=.02) as fixture:
                old, directory, wire = fixture.abandoned(phase)
                before = (fixture.control / "pending.json").read_bytes()
                before_stat = (fixture.control / "pending.json").stat()
                with self.assertRaises(client.RecoveryPending):
                    fixture.invoke()
                after_stat = (fixture.control / "pending.json").stat()
                self.assertEqual((fixture.control / "pending.json").read_bytes(), before)
                self.assertEqual((after_stat.st_ino, after_stat.st_mtime_ns),
                                 (before_stat.st_ino, before_stat.st_mtime_ns))
                self.assertEqual(fixture.pending(), old)
                event = fixture.controller.unknown_event()
                self.assertEqual(event is not None, phase == "unknown")
                self.assert_no_new_submission(fixture, directory, wire)

    def test_active_client_lock_prevents_unknown_escalation_or_journal_mutation(self):
        with Fixture(recovery_timeout=.02) as fixture:
            old, directory, wire = fixture.abandoned("submitted")
            before = (fixture.control / "pending.json").read_bytes()
            lock = os.open(fixture.control / "client.lock", os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(client.BusyError):
                    fixture.invoke()
                self.assertIsNone(fixture.controller.unknown_event())
                self.assertEqual((fixture.control / "pending.json").read_bytes(), before)
                self.assertEqual(fixture.pending(), old)
                self.assert_no_new_submission(fixture, directory, wire)
            finally:
                os.close(lock)

    def test_ack_with_wrong_request_hash_cannot_clear_escalated_pending(self):
        with Fixture() as fixture:
            old, directory, wire = fixture.abandoned("submitted")
            task = Task(fixture.invoke)
            try:
                fixture.unknown_event()
                fixture.acknowledge(old, changes={"request_sha256": "f" * 64})
            finally:
                error = task.join()
            self.assertIsInstance(error, client.RecoveryPending)
            self.assertIn("does not bind", str(error))
            self.assertEqual(fixture.pending(), dict(old, phase="unknown"))
            self.assert_no_new_submission(fixture, directory, wire)

    def test_valid_ack_and_current_without_fresh_ready_cannot_clear_pending(self):
        with Fixture() as fixture:
            old, directory, wire = fixture.abandoned("prepared")
            task = Task(fixture.invoke)
            try:
                fixture.unknown_event()
                fixture.acknowledge(old, ready=False)
            finally:
                error = task.join()
            self.assertIsInstance(error, client.ClientError)
            self.assertEqual(fixture.pending(), dict(old, phase="unknown"))
            self.assert_no_new_submission(fixture, directory, wire)


if __name__ == "__main__":
    unittest.main()
