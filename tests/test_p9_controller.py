"""Actual private-PTY controller IO and publication tests, without guest boot.

The PTY is a host fixture, not proof of the native UART's grant isolation.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ocore/guest/linux/package-domain/p9-controller"
LOADER = SourceFileLoader("p9_controller_under_test", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
controller = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(controller)


def session(instance="1" * 32):
    return {"schema": controller.SESSION_SCHEMA, "generation": "1234567890abcdef", "instance": instance,
            **controller.MAPPING, "program_dir": "/arm64/bin", "recovery_mode": "controller-v1", "state": "ready"}


def ack(old="1" * 32, new="2" * 32, outcome="interrupted"):
    value = {"schema": controller.RECOVERY_SCHEMA, "generation": session()["generation"], "old_instance": old,
             "new_instance": new, "request_id": "3" * 32, "request_sha256": "4" * 64,
             "ready_sha256": hashlib.sha256(("OC9READY1 " + session()["generation"] + " " + new + "\n").encode()).hexdigest(),
             "result_sha256": "5" * 64, "reset_sha256": "6" * 64, "done_sha256": "7" * 64, "outcome": outcome}
    if outcome == "unknown":
        value.update(result_sha256=None, reset_sha256=None, done_sha256=None)
    return value


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


class P9ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="p9-controller-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.fd = controller.open_control(str(self.control))
        self.addCleanup(os.close, self.fd)
        self.subject = controller.Controller(self.fd)

    def put(self, name, value):
        controller.atomic_json(self.fd, name, value)

    def apply(self, seq=1, current=None, recovered=None):
        value = {"seq": seq, "current": current or session()}
        if recovered is not None:
            value["recovered"] = recovered
        self.subject.apply(encode(value))

    def start(self):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        process = subprocess.Popen([sys.executable, str(SCRIPT), "--device", os.ttyname(slave),
                                    "--control-dir", str(self.control)], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        def stop():
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=3)
            process.stderr.close()
        self.addCleanup(stop)
        self.assertTrue(select.select([process.stderr], [], [], 3)[0], "daemon did not start")
        self.assertEqual(process.stderr.readline(), b"p9-controller ready\n")
        return master, process

    def line(self, fd, timeout=2):
        data = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                break
            part = os.read(fd, 1)
            if part == b"\n":
                return json.loads(data)
            data.extend(part)
        self.fail("controller did not reply with a complete JSON line: " + repr(data))

    def send(self, fd, value):
        raw = value if isinstance(value, bytes) else encode(value)
        controller.write_all(fd, raw + b"\n")
        reply = self.line(fd)
        self.assertEqual(reply["sha256"], hashlib.sha256(raw).hexdigest())
        return reply

    def test_gap_sequences_and_restart_replay_denial(self):
        self.apply(4)
        self.apply(19)
        self.subject = controller.Controller(self.fd)
        self.assertIsNone(self.subject.current)
        for seq in (1, 4, 19):
            with self.assertRaisesRegex(controller.ControlError, "replayed"):
                self.apply(seq)
        self.apply(25)
        self.assertEqual(json.loads((self.control / "controller-state.json").read_text())["seq"], 25)

    def test_invalid_sessions_do_not_mutate_any_publication(self):
        invalid = []
        for key, item in (("schema", "wrong"), ("generation", "0" * 16), ("instance", "A" * 32),
                          ("instance", "1" * 31), ("linux_mount", "/other"), ("plan9_mount", "/n/.."),
                          ("service_root", "/n/okernel/services/../plan9"), ("state", "done"),
                          ("program_dir", "/usr/bin"), ("recovery_mode", "native-marker-v1")):
            value = session()
            value[key] = item
            invalid.append(value)
        value = session()
        value["authority"] = "grant"
        invalid.append(value)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(controller.ControlError):
                self.apply(current=value)
        self.assertFalse((self.control / "current.json").exists())
        self.assertFalse((self.control / "controller-state.json").exists())

    def test_strict_json_sequence_length_and_field_types(self):
        for raw in (b'{"seq":1,"seq":2,"current":{}}', b'{"seq":NaN}', b'[]', b'{"seq":true}',
                    b'\xff', b'{"seq":1}\x00', b'{' * 1500, b'x' * 8193):
            with self.subTest(raw=raw[:30]), self.assertRaises(controller.ControlError):
                self.subject.apply(raw)
        for seq in (False, 0, -1, 1 << 64, 1.0, "1"):
            with self.subTest(seq=seq), self.assertRaises(controller.ControlError):
                self.apply(seq)

    def test_ack_is_durable_before_atomic_current_last(self):
        self.apply(2)
        replacement = session("2" * 32)
        recovery = ack()
        recovery_name = "g{generation}-s{old_instance}-r{request_id}.json".format(**recovery)
        original_replace, original_sync = os.replace, os.fsync
        events = []
        def replace(src, dst, **kwargs):
            if dst == "current.json":
                self.assertEqual(json.loads((self.control / "current.json").read_text()), session())
                self.assertEqual(json.loads((self.control / "recovered" / recovery_name).read_text()), recovery)
                self.assertGreater(events.index("sync-recovered", events.index("replace-" + recovery_name)),
                                   events.index("replace-" + recovery_name))
            original_replace(src, dst, **kwargs)
            events.append("replace-" + dst)
        def sync(fd):
            original_sync(fd)
            target = os.readlink("/proc/self/fd/" + str(fd))
            events.append("sync-" + Path(target).name)
        with patch.object(controller.os, "replace", side_effect=replace), patch.object(controller.os, "fsync", side_effect=sync):
            self.apply(8, replacement, recovery)
        self.assertEqual(events[-2:], ["replace-current.json", "sync-control"])
        self.assertEqual(json.loads((self.control / "current.json").read_text()), replacement)
        self.assertEqual((self.control / "current.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.control / "recovered").stat().st_mode & 0o777, 0o700)

    def test_recovery_schema_hash_and_identity_mismatches_rejected(self):
        self.apply(1)
        invalid = []
        for key, value in (("outcome", "completed"), ("ready_sha256", "0" * 64), ("new_instance", "1" * 32),
                           ("generation", "f" * 16), ("request_id", "bad"), ("reset_sha256", None)):
            item = ack()
            item[key] = value
            invalid.append(item)
        unknown = ack(outcome="unknown")
        unknown["done_sha256"] = "5" * 64
        invalid.append(unknown)
        extra = ack()
        extra["grant"] = 4
        invalid.append(extra)
        for recovery in invalid:
            with self.subTest(recovery=recovery), self.assertRaises(controller.ControlError):
                self.apply(2, session("2" * 32), recovery)
        self.assertEqual(self.subject.sequence, 1)
        self.apply(2, session("2" * 32), ack(outcome="unknown"))

    def test_conflicting_ack_fails_closed_without_replacing_current(self):
        self.apply(1)
        recovery = ack()
        self.apply(2, session("2" * 32), recovery)
        recovery["request_sha256"] = "f" * 64
        with self.assertRaisesRegex(controller.ControlError, "conflicting"):
            self.apply(3, session("2" * 32), recovery)
        self.assertEqual(self.subject.sequence, 3)  # Fail-closed reservation: retry requires a new sequence.
        self.assertEqual(json.loads((self.control / "current.json").read_text()), session("2" * 32))

    def test_private_ancestry_symlinks_unsafe_modes_and_shared_mount_rejected(self):
        target = self.root / "target"
        target.mkdir(mode=0o700)
        link = self.root / "link"
        link.symlink_to(target)
        for path in (str(link), str(self.root) + "/target/..", "/n/okernel/control"):
            with self.subTest(path=path), self.assertRaises((OSError, controller.ControlError)):
                controller.open_control(path)
        target.chmod(0o777)
        with self.assertRaises(controller.ControlError):
            controller.open_control(str(target))
        with patch.object(controller, "LOCAL_FILESYSTEMS", set()):
            with self.assertRaisesRegex(controller.ControlError, "local filesystem"):
                controller.open_control(str(self.control))

    def test_output_symlinks_and_special_files_do_not_change_other_paths(self):
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"untouched")
        (self.control / "current.json").symlink_to(sentinel)
        with self.assertRaises(OSError):
            self.apply(1)
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        (self.control / "current.json").unlink()
        os.mkfifo(self.control / "current.json", 0o600)
        with self.assertRaises(controller.ControlError):
            self.apply(2)
        self.assertEqual(sentinel.read_bytes(), b"untouched")

    def test_recovered_directory_symlink_rejected(self):
        self.apply(1)
        other = self.root / "other"
        other.mkdir(mode=0o700)
        (self.control / "recovered").symlink_to(other)
        with self.assertRaises(OSError):
            self.apply(2, session("2" * 32), ack())
        self.assertEqual(list(other.iterdir()), [])
        self.assertEqual(json.loads((self.control / "current.json").read_text()), session())

    def test_pty_fragmentation_raw_no_echo_and_coalesced_frames(self):
        master, _ = self.start()
        raw = encode({"seq": 7, "current": session()})
        controller.write_all(master, raw[:20])
        self.assertFalse(select.select([master], [], [], .08)[0], "raw UART unexpectedly echoed input")
        controller.write_all(master, raw[20:] + b"\n")
        reply = self.line(master)
        self.assertEqual(reply, {"seq": 7, "ok": True, "sha256": hashlib.sha256(raw).hexdigest()})
        frames = [encode({"seq": seq, "current": session()}) for seq in (12, 17)]
        controller.write_all(master, b"\n".join(frames) + b"\n")
        self.assertEqual([self.line(master)["seq"] for _ in frames], [12, 17])

    def test_pty_bad_json_oversized_frame_and_replay_resynchronize(self):
        master, _ = self.start()
        for raw in (b"not-json", b'{"seq":1,"seq":2}', b"x" * 8193):
            self.assertFalse(self.send(master, raw)["ok"])
        self.assertTrue(self.send(master, {"seq": 4, "current": session()})["ok"])
        self.assertFalse(self.send(master, {"seq": 4, "current": session()})["ok"])
        self.assertTrue(self.send(master, {"seq": 9, "current": session()})["ok"])

    def test_pty_publication_while_waiting_client_holds_its_lock(self):
        lock = os.open(self.control / "client.lock", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        master, _ = self.start()
        self.assertTrue(self.send(master, {"seq": 1, "current": session()})["ok"])
        self.assertTrue(self.send(master, {"seq": 3, "current": session("2" * 32), "recovered": ack()})["ok"])
        self.assertEqual(json.loads((self.control / "current.json").read_text())["instance"], "2" * 32)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def pending(self, **changes):
        wire = b"fixture request bytes"
        value = {"schema": "ostadix.p9.client-pending/v1", "generation": session()["generation"],
                 "instance": session()["instance"], "request_id": "3" * 32,
                 "request_sha256": hashlib.sha256(wire).hexdigest(), "request_hex": wire.hex(),
                 "service_root": session()["service_root"], "phase": "unknown"}
        value.update(changes)
        return value

    def test_unknown_event_never_adopts_existing_current_on_startup(self):
        self.put("current.json", session())
        self.put("pending.json", self.pending())
        self.subject = controller.Controller(self.fd)
        self.assertIsNone(self.subject.unknown_event())
        self.apply(1)
        expected = {key: self.pending()[key] for key in ("generation", "instance", "request_id", "request_sha256")}
        self.assertEqual(self.subject.unknown_event(), {"event": "unknown", **expected})
        self.assertIsNone(self.subject.unknown_event())
        self.put("pending.json", self.pending(request_id="8" * 32))
        self.assertEqual(self.subject.unknown_event()["request_id"], "8" * 32)

    def test_unknown_journal_invalid_ids_hash_phase_and_ancestry_emit_nothing(self):
        self.apply(1)
        for changes in ({"generation": "f" * 16}, {"instance": "a" * 32}, {"request_id": "bad"},
                        {"phase": "submitted"}, {"request_sha256": "0" * 64}, {"request_hex": "ff"},
                        {"service_root": "/n/other"}, {"schema": "arbitrary"}):
            with self.subTest(changes=changes):
                self.put("pending.json", self.pending(**changes))
                self.assertIsNone(self.subject.unknown_event())
        (self.control / "pending.json").unlink()
        (self.control / "pending.json").symlink_to(self.root / "outside")
        self.assertIsNone(self.subject.unknown_event())

    def test_pty_unknown_event_once_after_trusted_provisioning(self):
        self.put("current.json", session())
        self.put("pending.json", self.pending())
        master, _ = self.start()
        self.assertFalse(select.select([master], [], [], .15)[0])
        self.assertTrue(self.send(master, {"seq": 3, "current": session()})["ok"])
        event = self.line(master)
        self.assertEqual(event["event"], "unknown")
        self.assertEqual(event["request_sha256"], self.pending()["request_sha256"])
        self.assertNotIn("request_hex", event)
        self.assertFalse(select.select([master], [], [], .25)[0])

    def test_help_and_regular_device_denial(self):
        help_result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, check=True)
        self.assertIn(b"--control-dir", help_result.stdout)
        fake = self.root / "device"
        fake.touch()
        with self.assertRaisesRegex(controller.ControlError, "character terminal"):
            controller.open_device(str(fake))


if __name__ == "__main__":
    unittest.main()
