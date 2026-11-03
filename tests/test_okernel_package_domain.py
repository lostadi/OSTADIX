"""Focused runner contracts: real QMP framing, guest markers and atomic saves."""

from contextlib import contextmanager, ExitStack
import io
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shutil
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("okernel_package_domain", ROOT / "scripts/okernel_package_domain.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


@contextmanager
def fake_qmp(handler, greeting=None):
    """A real AF_UNIX peer; production QMP code still reads/writes the socket."""
    failures = []
    requests = []
    with tempfile.TemporaryDirectory(prefix="kw-qmp-") as directory:
        path = Path(directory) / "qmp.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(3)

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    stream = connection.makefile("rwb", buffering=0)
                    with stream:
                        hello = greeting if greeting is not None else {"QMP": {"version": {}, "capabilities": []}}
                        stream.write(json.dumps(hello).encode() + b"\r\n")
                        while True:
                            line = stream.readline()
                            if not line:
                                return
                            request = json.loads(line)
                            requests.append(request)
                            replies = handler(request)
                            if replies is None:
                                return
                            for reply in replies:
                                stream.write(json.dumps(reply).encode() + b"\r\n")
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield path, requests
        finally:
            thread.join(timeout=4)
            listener.close()
            if thread.is_alive():
                raise AssertionError("fake QMP peer was not closed")
            if failures:
                raise AssertionError(f"fake QMP peer failed: {failures}")


class QMPProtocolTests(unittest.TestCase):
    def test_greeting_capabilities_events_and_response_ids(self):
        def handler(request):
            return [{"event": "STOP", "data": {}},
                    {"return": {"wrong": True}, "id": request["id"] + 100},
                    {"return": {"accepted": request["execute"]}, "id": request["id"]}]

        with fake_qmp(handler) as (path, requests):
            qmp = RUNNER.QMP(path, timeout=1)
            try:
                self.assertEqual(qmp.execute("query-status"), {"accepted": "query-status"})
                qmp.execute("pmemsave", {"val": 123, "size": 512, "filename": "disk.ext4"})
            finally:
                qmp.close()
        self.assertEqual([request["id"] for request in requests], [1, 2, 3])
        self.assertEqual(requests[0]["execute"], "qmp_capabilities")
        self.assertEqual(requests[2]["arguments"]["filename"], "disk.ext4")

    def test_matching_qmp_error_is_not_success(self):
        def handler(request):
            if request["execute"] == "qmp_capabilities":
                return [{"return": {}, "id": request["id"]}]
            return [{"error": {"class": "GenericError", "desc": "export denied"}, "id": request["id"]}]

        with fake_qmp(handler) as (path, _):
            qmp = RUNNER.QMP(path, timeout=1)
            try:
                with self.assertRaisesRegex(RuntimeError, "export denied"):
                    qmp.execute("pmemsave", {})
            finally:
                qmp.close()

    def test_disconnect_before_reply_is_not_success(self):
        def handler(request):
            return [{"return": {}, "id": request["id"]}] if request["execute"] == "qmp_capabilities" else None

        with fake_qmp(handler) as (path, _):
            qmp = RUNNER.QMP(path, timeout=1)
            try:
                with self.assertRaisesRegex(RuntimeError, "disconnected"):
                    qmp.execute("stop")
            finally:
                qmp.close()

    def test_missing_socket_times_out(self):
        with tempfile.TemporaryDirectory(prefix="kw-qmp-absent-") as directory:
            with self.assertRaises(TimeoutError):
                RUNNER.QMP(Path(directory) / "absent.sock", timeout=0.01)


class ArtifactAndProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kw-domain-files-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_artifact_identity_accepts_exact_bytes_and_rejects_tampering(self):
        artifact = self.root / "Image"
        artifact.write_bytes(b"genuine image bytes")
        expected = RUNNER.identity(artifact)
        self.assertEqual(RUNNER.checked_file(artifact, expected), artifact)
        artifact.write_bytes(b"changed image bytes")
        with self.assertRaises(ValueError):
            RUNNER.checked_file(artifact, expected)

    def test_artifact_symlink_and_directory_rejected(self):
        target = self.root / "target"
        target.write_bytes(b"artifact")
        link = self.root / "link"
        link.symlink_to(target)
        for path in (link, self.root):
            with self.subTest(path=path), self.assertRaises(ValueError):
                RUNNER.checked_file(path, RUNNER.identity(target))

    def test_wrong_monitor_profile_rejected_before_process_launch(self):
        monitor = self.root / "monitor"
        monitor.mkdir()
        for filename in ("monitor-profile.json", "monitor-manifest.json"):
            (monitor / filename).write_text(json.dumps({"profile": "withdrawal", "block_backing": None}))
        with patch.object(RUNNER.subprocess, "Popen") as popen:
            with self.assertRaises(ValueError):
                RUNNER.Domain(self.root, "no-qemu-required")
            popen.assert_not_called()

    def test_failed_json_serialization_preserves_published_record(self):
        head = self.root / "head.json"
        head.write_text('{"old":true}\n')
        with self.assertRaises(TypeError):
            RUNNER.write_json(head, {"bad": object()})
        self.assertEqual(json.loads(head.read_text()), {"old": True})

    @staticmethod
    def profile():
        return {
            "schema": "ostadix.kernel-world-linux-monitor/v1", "profile": "package-domain",
            "backing_base": 0x70000000, "backing_bytes": 536870912,
            "block_backing": {"address": 0x70000000, "bytes": 536870912},
            "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000,
            "guest_ram_bytes": 0x20000000, "outer_ram_bytes": 0x80000000,
            "loader_addresses": {"Image": 0x48000000, "guest_dtb": 0x4fe00000, "initramfs": 0x50000000},
        }

    def test_exact_persistent_memory_device_profile_accepted(self):
        RUNNER.validate_profile(self.profile())

    def test_explicit_one_gib_profile_and_generation_are_accepted(self):
        manifest = self.profile()
        manifest.update(backing_bytes=1073741824, block_backing={"address": 0x70000000, "bytes": 1073741824})
        RUNNER.validate_profile(manifest)
        head = self.head()
        head["disk"]["bytes"] = 1073741824
        self.assertEqual(RUNNER.validate_head(self.root, head), head["disk"])
        for size in (0, True, 536870912 + 4096, 1073741824 + 4096, 2 * 1073741824):
            broken = copy.deepcopy(manifest)
            broken.update(backing_bytes=size, block_backing={"address": 0x70000000, "bytes": size})
            with self.subTest(size=size), self.assertRaises(ValueError):
                RUNNER.validate_profile(broken)
            head["disk"]["bytes"] = size
            with self.subTest(head_size=size), self.assertRaises(ValueError):
                RUNNER.validate_head(self.root, head)

    def test_prepare_uses_selected_one_gib_head_instead_of_base_default(self):
        payload, rootfs = self.root / "payload", self.root / "rootfs"
        payload.mkdir()
        rootfs.mkdir()
        (payload / "linux-payload.json").write_text("{}")
        (rootfs / "initramfs.cpio").write_bytes(b"fixed initramfs")
        (rootfs / "package-domain.json").write_text(json.dumps({
            "schema": "ostadix.linux-package-domain/v1", "architecture": "aarch64",
            "artifacts": {"package-domain.ext4": {"path": str(rootfs / "package-domain.ext4"),
                                                    "bytes": 536870912, "sha256": "b" * 64}}}))
        head = self.head()
        head["disk"]["bytes"] = 1073741824
        (self.root / "head.json").write_text(json.dumps(head))
        with patch.object(RUNNER, "checked_file") as checked, patch.object(RUNNER.subprocess, "run") as command:
            RUNNER.prepare(self.root, network=True, namespace=True)
        checked.assert_called_once_with(Path(head["disk"]["path"]), head["disk"])
        self.assertEqual(command.call_args.kwargs["env"]["OCORE_LINUX_BACKING_BYTES"], "1073741824")
        self.assertEqual((payload / "initramfs.cpio").read_bytes(), b"fixed initramfs")

    def test_fresh_prepare_requests_one_gib_but_preserves_existing_selected_size(self):
        with patch.object(RUNNER, "selected_disk_bytes", return_value=1073741824), \
                patch.object(RUNNER.shutil, "copyfile"), patch.object(RUNNER.subprocess, "run") as commands:
            RUNNER.prepare(self.root, network=True, namespace=True)
        rootfs_build = next(call.args[0] for call in commands.call_args_list if "--disk-bytes" in call.args[0])
        self.assertEqual(rootfs_build[rootfs_build.index("--disk-bytes") + 1], "1073741824")
        self.assertEqual(commands.call_args.kwargs["env"]["OCORE_LINUX_BACKING_BYTES"], "1073741824")
        # A legacy selected 512MiB volume retains its exact device grant.
        (self.root / "head.json").write_text(json.dumps(self.head()))
        with patch.object(RUNNER, "checked_file"), patch.object(RUNNER.shutil, "copyfile"), \
                patch.object(RUNNER.subprocess, "run") as commands:
            RUNNER.prepare(self.root, network=True, namespace=True)
        self.assertEqual(commands.call_args.kwargs["env"]["OCORE_LINUX_BACKING_BYTES"], "536870912")

    def test_namespace_accepts_only_the_preprovisioned_grant(self):
        profile = self.profile()
        profile["namespace_grant"] = copy.deepcopy(RUNNER.NAMESPACE_GRANT)
        RUNNER.validate_profile(profile)
        for key, value in (("address", 0x48000000), ("bytes", 0x2000000), ("guest_irq", 49),
                           ("linux_grant", 2), ("epoch_address", 0x40000000), ("mount_tag", "host")):
            broken = copy.deepcopy(profile)
            broken["namespace_grant"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                RUNNER.validate_profile(broken)

    def test_wrong_grant_or_loader_layout_rejected(self):
        changes = {
            "schema": "unknown/v1", "profile": "withdrawal", "backing_base": 0x48000000,
            "backing_bytes": 512, "block_backing": {"address": 0x48000000, "bytes": 536870912},
            "guest_ram_ipa": 0, "guest_ram_pa": 0x70000000,
            "guest_ram_bytes": 0x40000000, "outer_ram_bytes": 0x40000000,
            "loader_addresses": {"Image": 0x40080000, "guest_dtb": 0x4fe00000, "initramfs": 0x50000000},
        }
        for key, value in changes.items():
            manifest = self.profile()
            manifest[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                RUNNER.validate_profile(manifest)
        extra = self.profile()
        extra["loader_addresses"]["extra"] = 0x40080000
        with self.assertRaises(ValueError):
            RUNNER.validate_profile(extra)

    def head(self):
        fingerprint = "a" * 64
        return {"schema": "ostadix.package-domain-disk-head/v1",
                "disk": {"path": str(self.root / "disk-generations" / (fingerprint + ".ext4")),
                         "sha256": fingerprint, "bytes": 536870912}}

    def test_exact_generation_head_accepted(self):
        head = self.head()
        self.assertEqual(RUNNER.validate_head(self.root, head), head["disk"])

    def test_paired_head_requires_bounded_content_addressed_namespace(self):
        head = self.head()
        head["schema"] = "ostadix.package-domain-disk-head/v2"
        with self.assertRaises(ValueError):
            RUNNER.validate_head(self.root, head)
        head["namespace"] = {"path": str(self.root / "namespace-generations" / ("b" * 64 + ".raw")),
                             "bytes": 0x1000000, "sha256": "b" * 64}
        RUNNER.validate_head(self.root, head)
        for key, value in (("bytes", 512), ("path", str(self.root / "escape.raw")), ("sha256", "../escape")):
            broken = copy.deepcopy(head)
            broken["namespace"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                RUNNER.validate_head(self.root, broken)

    def test_unknown_head_schema_or_escaped_generation_rejected(self):
        changes = [
            ("schema", "unknown/v1"), ("sha256", "A" * 64), ("sha256", "a" * 63),
            ("sha256", "../escape"), ("bytes", 1), ("path", str(self.root / "external.ext4")),
            ("path", "disk-generations/" + "a" * 64 + ".ext4"),
        ]
        for key, value in changes:
            head = copy.deepcopy(self.head())
            target = head if key == "schema" else head["disk"]
            target[key] = value
            with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                RUNNER.validate_head(self.root, head)

    def test_symlinked_generation_store_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "disk-generations").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            RUNNER.validate_head(self.root, self.head())

    def constructor_inputs(self):
        manifest = self.profile()
        manifest["artifacts"] = {}
        monitor = self.root / "monitor"
        monitor.mkdir()
        for name in ("monitor", "guest_dtb", "Image", "initramfs"):
            artifact = self.root / name
            # Keep the monitor artifact distinct from its containing directory.
            if name == "monitor":
                artifact = monitor / "monitor.elf"
            artifact.write_bytes(name.encode())
            manifest["artifacts"][name] = RUNNER.identity(artifact)
        (monitor / "monitor-profile.json").write_text(json.dumps(manifest))
        rootfs = self.root / "rootfs"
        rootfs.mkdir()
        return rootfs

    def test_base_rootfs_requires_builder_recorded_artifact_identity(self):
        rootfs = self.constructor_inputs()
        (rootfs / "package-domain.ext4").write_bytes(b"unrecorded bytes")
        (rootfs / "package-domain.json").write_text(json.dumps({
            "schema": "ostadix.linux-package-domain/v1", "architecture": "aarch64", "artifacts": {}}))
        with patch.object(RUNNER.subprocess, "Popen") as popen:
            with self.assertRaises((KeyError, ValueError)):
                RUNNER.Domain(self.root, "no-qemu-required")
            popen.assert_not_called()

    def test_base_rootfs_wrong_architecture_rejected(self):
        rootfs = self.constructor_inputs()
        (rootfs / "package-domain.json").write_text(json.dumps({
            "schema": "ostadix.linux-package-domain/v1", "architecture": "x86_64"}))
        with patch.object(RUNNER.subprocess, "Popen") as popen:
            with self.assertRaises(ValueError):
                RUNNER.Domain(self.root, "no-qemu-required")
            popen.assert_not_called()


class GuestMarkerTests(unittest.TestCase):
    def setUp(self):
        self.domain = RUNNER.Domain.__new__(RUNNER.Domain)
        self.domain.capture = bytearray()
        self.domain.timeout = 0.2
        self.domain.session = Path("/test/session")
        self.domain.process = SimpleNamespace(poll=lambda: None)
        self.token = b"OKERNEL_COMMAND_fixture"
        self.uuid = patch.object(RUNNER.uuid, "uuid4", return_value=SimpleNamespace(hex="fixture"))
        self.uuid.start()
        self.addCleanup(self.uuid.stop)

    def feed(self, chunks, echo=True):
        pending = iter(chunks)

        def pump(*args):
            try:
                self.domain.capture.extend(next(pending))
            except StopIteration:
                raise TimeoutError("no complete marker received")

        self.domain.pump = pump
        self.domain.send = lambda data: self.domain.capture.extend(data) if echo else None

    def test_shell_echo_cannot_acknowledge_command(self):
        self.feed([])
        with self.assertRaises(TimeoutError):
            self.domain.command("true")

    def test_complete_success_line_acknowledges_command(self):
        self.feed([b"\r\n" + self.token + b":0\r\n"])
        self.domain.command("true")

    def test_partial_zero_followed_by_nonzero_is_failure(self):
        self.feed([b"\r\n" + self.token + b":0", b"1\r\n"])
        with self.assertRaisesRegex(RuntimeError, "command failed"):
            self.domain.command("false")

    def test_prompt_prefixed_marker_does_not_acknowledge_command(self):
        self.feed([b"pkg> " + self.token + b":0\n"])
        with self.assertRaises(TimeoutError):
            self.domain.command("true")

    def test_ready_marker_requires_completed_exact_line(self):
        self.feed([RUNNER.READY, b"-not-ready\n"], echo=False)
        with self.assertRaises(TimeoutError):
            self.domain.wait(RUNNER.READY, line=True)


class InteractiveConsoleTests(unittest.TestCase):
    def setUp(self):
        self.running = True
        self.domain = SimpleNamespace(process=SimpleNamespace(poll=lambda: None if self.running else 1),
                                      ready=Mock(), send=Mock(), command=Mock(), save=Mock(), pump=Mock(),
                                      qmp=SimpleNamespace(execute=Mock()), timeout=600,
                                      session=Path("/test/session"))

    def interact(self, inputs):
        terminal = SimpleNamespace(fileno=lambda: 17)
        with ExitStack() as stack:
            stack.enter_context(patch.object(RUNNER.sys, "stdin", terminal))
            self.output = io.StringIO()
            stack.enter_context(patch.object(RUNNER.sys, "stdout", self.output))
            stack.enter_context(patch.object(RUNNER.termios, "tcgetattr", return_value="original"))
            self.restore = stack.enter_context(patch.object(RUNNER.termios, "tcsetattr"))
            self.raw = stack.enter_context(patch.object(RUNNER.tty, "setraw"))
            self.select = stack.enter_context(patch.object(RUNNER.select, "select", return_value=([terminal], [], [])))
            self.read = stack.enter_context(patch.object(RUNNER.os, "read", side_effect=inputs))
            RUNNER.run_interactive(self.domain)

    def test_save_interrupts_foreground_job_and_proves_shell_before_sync(self):
        order = []
        self.domain.send.side_effect = lambda data: order.append(("send", data))
        self.domain.command.side_effect = lambda command, **kwargs: order.append(("probe", command))
        self.domain.save.side_effect = lambda: order.append(("save",))
        self.interact([b"partial input\x1dignored after save"])
        self.assertEqual(order, [("send", b"partial input"), ("send", b"\x03\x15"),
                                 ("probe", "true"), ("save",)])
        self.domain.command.assert_called_once_with("true", timeout=2)
        self.restore.assert_called_once_with(17, RUNNER.termios.TCSADRAIN, "original")

    def test_failed_shell_probe_retains_vm_and_allows_retry(self):
        self.domain.command.side_effect = [TimeoutError("foreground program still owns input"),
                                           TimeoutError("still not a shell"), None]
        self.interact([b"\x1d", b"\x1d"])
        self.domain.qmp.execute.assert_called_once_with("cont")
        self.domain.save.assert_called_once()
        self.assertTrue(self.running)

    def test_probe_retries_with_fresh_interrupt_after_shell_flushes_first(self):
        self.domain.command.side_effect = [TimeoutError("shell discarded pending input"), None]
        self.interact([b"\x1d"])
        self.assertEqual(self.domain.send.call_args_list[0].args, (b"\x03\x15",))
        self.assertEqual(self.domain.send.call_args_list[1].args, (b"\x03\x15",))
        self.assertEqual([call.kwargs["timeout"] for call in self.domain.command.call_args_list], [2, 15])
        self.domain.save.assert_called_once()
        self.domain.qmp.execute.assert_not_called()

    def test_failed_snapshot_resumes_same_vm_and_allows_retry(self):
        self.domain.save.side_effect = [OSError("namespace export failed"), None]
        self.interact([b"\x1d", b"echo still-alive\n", b"\x1d"])
        self.assertEqual(self.domain.save.call_count, 2)
        self.domain.qmp.execute.assert_called_once_with("cont")
        self.domain.send.assert_any_call(b"echo still-alive\n")

    def test_resume_error_does_not_force_exit_or_prevent_another_attempt(self):
        self.domain.save.side_effect = [RuntimeError("export failed"), None]
        self.domain.qmp.execute.side_effect = RuntimeError("QMP temporarily unavailable")
        self.interact([b"\x1d", b"\x1d"])
        self.assertEqual(self.domain.save.call_count, 2)

    def test_ctrl_c_is_forwarded_to_guest_without_requesting_save(self):
        self.interact([b"\x03", b"\x1d"])
        self.assertEqual(self.domain.send.call_args_list[0].args, (b"\x03",))
        self.domain.save.assert_called_once()

    def test_eof_does_not_save_or_repeatedly_poll_closed_input(self):
        self.domain.pump.side_effect = lambda delay: setattr(self, "running", False)
        with self.assertRaisesRegex(RuntimeError, "without a completed interactive save"):
            self.interact([b""])
        self.domain.save.assert_not_called()
        self.domain.send.assert_not_called()
        self.read.assert_called_once()
        self.select.assert_called_once()
        self.domain.pump.assert_called_once_with(0.1)
        self.restore.assert_called_once()

    def test_guest_exit_during_save_reports_failure_and_restores_terminal(self):
        def fail():
            self.running = False
            raise RuntimeError("guest exited")
        self.domain.save.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, "before the requested save completed"):
            self.interact([b"\x1d"])
        self.domain.qmp.execute.assert_not_called()
        self.restore.assert_called_once()

    @unittest.skipUnless(shutil.which("busybox"), "BusyBox ash is required for the real terminal regression")
    def test_actual_ash_foreground_and_continuation_input_can_save(self):
        # Exercise the production nonce protocol against the same shell family
        # as the guest, with a controlling PTY and actual terminal signals.
        # This proves more than a fake send() accepting the Ctrl-C bytes.
        actual_read, actual_select = os.read, select.select
        for pending in (b"", b"cat\n", b"printf 'unfinished\n"):
            with self.subTest(pending=pending):
                master, slave = pty.openpty()
                child = subprocess.Popen([shutil.which("busybox"), "ash", "-i"], stdin=slave,
                                         stdout=slave, stderr=slave, start_new_session=True,
                                         preexec_fn=lambda: RUNNER.fcntl.ioctl(0, RUNNER.termios.TIOCSCTTY, 0),
                                         env=dict(os.environ, PS1="custom-shell> ", PS2="continuation> "))
                os.close(slave)
                domain = RUNNER.Domain.__new__(RUNNER.Domain)
                domain.capture, domain.inputs = bytearray(), []
                domain.timeout, domain.session = 2, Path("/test/pty-session")
                class Writer:
                    def write(self, data):
                        return os.write(master, data)
                    def flush(self):
                        pass
                domain.process = SimpleNamespace(stdin=Writer(), poll=child.poll)
                def pump(timeout=0.02):
                    if actual_select([master], [], [], timeout)[0]:
                        domain.capture.extend(actual_read(master, 65536))
                domain.pump = pump
                domain.ready = lambda: domain.wait(b"custom-shell> ")
                domain.qmp = SimpleNamespace(execute=Mock())
                domain.save = lambda: domain.command("printf 'ACTUAL_SHELL_SAVE_PROOF\\n'")
                try:
                    domain.ready()
                    if pending:
                        domain.send(pending)
                        for _ in range(4):
                            domain.pump(0.02)
                    self.domain = domain
                    try:
                        self.interact([b"\x1d"])
                    except StopIteration:
                        self.fail(f"save did not finish: {self.output.getvalue()!r}; real shell output: {bytes(domain.capture)!r}")
                    self.assertIn(b"\r\nACTUAL_SHELL_SAVE_PROOF\r\n", domain.capture)
                    domain.qmp.execute.assert_not_called()
                finally:
                    os.close(master)
                    child.kill()
                    child.wait(timeout=2)


class SnapshotPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kw-domain-save-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.domain = RUNNER.Domain.__new__(RUNNER.Domain)
        self.domain.state = self.root
        self.domain.session = self.root / "session"
        self.domain.session.mkdir()
        self.domain.record = {"ok": False}
        self.payload = b"persisted guest filesystem" * 32
        self.domain.backing = {"address": 0x70000000, "bytes": len(self.payload)}
        self.domain.disk_identity = {"path": "original.ext4", "bytes": len(self.payload), "sha256": "0" * 64}
        self.domain.command = Mock()
        self.requests = []
        self.failure = None
        self.truncated = False
        self.running = False

        def execute(command, arguments=None):
            self.requests.append((command, arguments))
            if command == "query-status":
                return {"running": self.running, "status": "running" if self.running else "paused"}
            if command == "pmemsave":
                if self.failure:
                    raise self.failure
                Path(arguments["filename"]).write_bytes(self.payload[:-1] if self.truncated else self.payload)
            return {}

        self.domain.qmp = SimpleNamespace(execute=execute)
        self.head = self.root / "head.json"
        self.head.write_text('{"previous_head":true}\n')

    def test_successful_save_publishes_verified_immutable_generation(self):
        self.domain.save()
        self.domain.command.assert_called_once_with("sync")
        commands = [command for command, _ in self.requests]
        self.assertLess(commands.index("stop"), commands.index("query-status"))
        self.assertLess(commands.index("query-status"), commands.index("pmemsave"))
        current = json.loads(self.head.read_text())
        artifact = Path(current["disk"]["path"])
        self.assertEqual(artifact.parent, self.root / "disk-generations")
        self.assertEqual(artifact.name, hashlib.sha256(self.payload).hexdigest() + ".ext4")
        self.assertEqual(artifact.read_bytes(), self.payload)
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o400)
        self.assertEqual(current["previous"], self.domain.disk_identity)
        self.assertTrue(self.domain.record["ok"])

    def test_truncated_export_does_not_replace_previous_head(self):
        self.truncated = True
        with self.assertRaises(RuntimeError):
            self.domain.save()
        self.assertEqual(json.loads(self.head.read_text()), {"previous_head": True})
        self.assertFalse(self.domain.record["ok"])

    def test_failed_export_does_not_replace_previous_head(self):
        self.failure = RuntimeError("QMP export failed")
        with self.assertRaisesRegex(RuntimeError, "export failed"):
            self.domain.save()
        self.assertEqual(json.loads(self.head.read_text()), {"previous_head": True})
        self.assertFalse(self.domain.record["ok"])

    def test_existing_matching_generation_is_reused(self):
        generation = self.root / "disk-generations"
        generation.mkdir()
        artifact = generation / (hashlib.sha256(self.payload).hexdigest() + ".ext4")
        artifact.write_bytes(self.payload)
        artifact.chmod(0o400)
        self.domain.save()
        self.assertEqual(Path(json.loads(self.head.read_text())["disk"]["path"]), artifact)
        self.assertEqual(list(generation.glob("pending-*")), [])

    def test_running_cpu_prevents_export_and_head_replacement(self):
        self.running = True
        with self.assertRaisesRegex(RuntimeError, "did not stop"):
            self.domain.save()
        self.assertNotIn("pmemsave", [name for name, _ in self.requests])
        self.assertEqual(json.loads(self.head.read_text()), {"previous_head": True})
        self.assertFalse(self.domain.record["ok"])

    def test_conflicting_generation_is_not_overwritten(self):
        generation = self.root / "disk-generations"
        generation.mkdir()
        artifact = generation / (hashlib.sha256(self.payload).hexdigest() + ".ext4")
        artifact.write_bytes(b"conflicting object")
        with self.assertRaises(ValueError):
            self.domain.save()
        self.assertEqual(artifact.read_bytes(), b"conflicting object")
        self.assertEqual(json.loads(self.head.read_text()), {"previous_head": True})
        self.assertFalse(self.domain.record["ok"])

    def test_directory_sync_failure_does_not_publish_new_head(self):
        with patch.object(RUNNER, "fsync_directory", side_effect=OSError("directory sync failed")):
            with self.assertRaisesRegex(OSError, "directory sync failed"):
                self.domain.save()
        self.assertEqual(json.loads(self.head.read_text()), {"previous_head": True})
        self.assertFalse(self.domain.record["ok"])

    def enable_namespace(self, fail_namespace=False):
        self.domain.namespace = True
        self.domain.namespace_identity = {"path": "initial.raw", "bytes": 0x1000000, "sha256": "0" * 64}
        disk_execute = self.domain.qmp.execute
        self.quiescence = [bytes(8)]
        self.domain.pump = Mock()

        def execute(command, arguments=None):
            if command == "pmemsave" and arguments["val"] == RUNNER.NAMESPACE_GRANT["quiescence_address"]:
                self.requests.append((command, arguments))
                Path(arguments["filename"]).write_bytes(self.quiescence.pop(0))
                return {}
            if command == "pmemsave" and arguments["val"] == RUNNER.NAMESPACE_GRANT["address"]:
                self.requests.append((command, arguments))
                if fail_namespace:
                    raise RuntimeError("namespace export failed")
                with Path(arguments["filename"]).open("xb") as stream:
                    stream.truncate(arguments["size"])
                return {}
            return disk_execute(command, arguments)
        self.domain.qmp.execute = execute

    def test_pair_is_published_only_after_both_stopped_exports(self):
        self.enable_namespace()
        self.domain.save()
        head = json.loads(self.head.read_text())
        self.assertEqual(head["schema"], "ostadix.package-domain-disk-head/v2")
        self.assertEqual(Path(head["namespace"]["path"]).stat().st_size, 0x1000000)
        self.assertEqual(head["namespace"]["sha256"], RUNNER.digest(Path(head["namespace"]["path"])))
        self.assertEqual(len([cmd for cmd, args in self.requests if cmd == "pmemsave" and args["size"] != 8]), 2)
        self.assertTrue(self.domain.record["paired_snapshot"])
        self.assertTrue(self.domain.record["native_operations_quiescent_before_export"])

    def test_second_export_failure_leaves_entire_previous_pair_selected(self):
        self.enable_namespace(fail_namespace=True)
        with self.assertRaisesRegex(RuntimeError, "namespace export failed"):
            self.domain.save()
        self.assertEqual(json.loads(self.head.read_text()), {"previous_head": True})
        self.assertFalse(self.domain.record["ok"])

    def test_stop_inside_native_transaction_resumes_before_snapshot(self):
        self.enable_namespace()
        self.quiescence = [b"\x01" + bytes(7), bytes(8)]
        self.domain.save()
        self.assertEqual(self.domain.record["quiescence_stop_attempts"], 2)
        self.assertEqual([cmd for cmd, _ in self.requests].count("cont"), 1)

    def test_invalid_quiescence_state_never_replaces_head(self):
        self.enable_namespace()
        self.quiescence = [b"\x02" + bytes(7)]
        with self.assertRaisesRegex(RuntimeError, "quiescence word"):
            self.domain.save()
        self.assertEqual(json.loads(self.head.read_text()), {"previous_head": True})
        self.assertFalse(self.domain.record["ok"])


if __name__ == "__main__":
    unittest.main()
