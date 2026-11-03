"""Real AF_UNIX endpoints for long state paths; no VM or QEMU execution."""
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("control_socket_runner", ROOT / "scripts/okernel_package_domain.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


@contextmanager
def bound_socket(path):
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        peer.bind(str(path))
        peer.listen(1)
        yield peer
    finally:
        peer.close()


class ControlSocketTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="okc-", dir="/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "r"
        self.runtime.mkdir(mode=0o700)
        self.patch = patch.object(RUNNER.ControlSocket, "RUNTIME_ROOT", self.runtime)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def session(self, *, long=False):
        parent = self.root
        if long:
            # Each component stays below NAME_MAX, while encoded path length
            # greatly exceeds sockaddr_un. Non-ASCII names exercise bytes.
            parent = parent / ("namespace-" + "界" * 40) / ("state-" + "é" * 40)
            parent.mkdir(parents=True)
        directory = parent / "session"
        directory.mkdir(mode=0o700)
        return directory

    def test_short_path_preserves_location_and_real_qmp_protocol(self):
        session = self.session()
        control = RUNNER.ControlSocket(session)
        self.assertEqual(control.path, session / "control.sock")
        self.assertFalse(control.external)
        failures = []
        with bound_socket(control.path) as listener:
            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection, connection.makefile("rwb", buffering=0) as stream:
                        stream.write(b'{"QMP":{}}\n')
                        for _ in range(2):
                            request = json.loads(stream.readline())
                            stream.write(json.dumps({"return": {"accepted": request["execute"]},
                                                     "id": request["id"]}).encode() + b"\n")
                except BaseException as error:
                    failures.append(error)
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            qmp = RUNNER.QMP(control.path, timeout=1)
            try:
                control.connected()
                self.assertEqual(qmp.execute("query-status"), {"accepted": "query-status"})
            finally:
                qmp.close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertFalse(failures, failures)
        control.cleanup()
        self.assertFalse(control.path.exists())
        self.assertTrue(session.is_dir())
        control.cleanup()  # Idempotent, without touching session evidence.

    def test_long_unicode_state_uses_private_short_endpoint(self):
        session = self.session(long=True)
        original = session / "control.sock"
        self.assertGreater(len(os.fsencode(original)), RUNNER.ControlSocket.MAX_PATH_BYTES)
        with socket.socket(socket.AF_UNIX) as unsupported:
            with self.assertRaises(OSError):
                unsupported.bind(str(original))
        control = RUNNER.ControlSocket(session)
        self.assertTrue(control.external)
        self.assertLessEqual(len(os.fsencode(control.path)), RUNNER.ControlSocket.MAX_PATH_BYTES)
        token = hashlib.sha256(os.fsencode(session)).hexdigest()[:16]
        self.assertIn(token, control.directory.name)
        self.assertEqual(stat.S_IMODE(control.directory.stat().st_mode), 0o700)
        with bound_socket(control.path) as listener, socket.socket(socket.AF_UNIX) as client:
            client.connect(str(control.path))
            connection, _ = listener.accept()
            with connection:
                client.sendall(b"nonce")
                self.assertEqual(connection.recv(5), b"nonce")
            control.connected()
        control.cleanup()
        self.assertFalse(control.directory.exists())
        self.assertTrue(session.is_dir())

    def test_exact_pathname_byte_limit_is_respected(self):
        remaining = RUNNER.ControlSocket.MAX_PATH_BYTES - len(os.fsencode(self.root)) - len(b"//control.sock")
        session = self.root / ("x" * remaining)
        session.mkdir(mode=0o700)
        control = RUNNER.ControlSocket(session)
        self.assertFalse(control.external)
        self.assertEqual(len(os.fsencode(control.path)), RUNNER.ControlSocket.MAX_PATH_BYTES)
        with bound_socket(control.path):
            control.connected()
        control.cleanup()

    def test_unique_instance_directories_do_not_reuse_stale_socket(self):
        session = self.session(long=True)
        first, second = RUNNER.ControlSocket(session), RUNNER.ControlSocket(session)
        self.assertNotEqual(first.path, second.path)
        with bound_socket(first.path), bound_socket(second.path):
            first.connected()
            second.connected()
        first.cleanup()
        self.assertTrue(second.path.exists())
        second.cleanup()

    def test_long_tmpdir_does_not_change_selected_runtime_root(self):
        session = self.session(long=True)
        with patch.object(tempfile, "tempdir", str(session)):
            control = RUNNER.ControlSocket(session, prefer_session=False)
        self.assertEqual(control.directory.parent, self.runtime)
        control.cleanup()

    def test_existing_short_socket_is_never_replaced(self):
        session = self.session()
        path = session / "control.sock"
        with bound_socket(path):
            original = path.stat().st_ino
            with self.assertRaises(FileExistsError):
                RUNNER.ControlSocket(session)
            self.assertEqual(path.stat().st_ino, original)

    def test_session_symlink_and_unsafe_permissions_are_rejected(self):
        session = self.session()
        link = self.root / "session-link"
        link.symlink_to(session, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            RUNNER.ControlSocket(link)
        session.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "0700"):
            RUNNER.ControlSocket(session)

    def test_runtime_symlink_unsafe_mode_and_too_long_root_are_rejected(self):
        session = self.session(long=True)
        link = self.root / "runtime-link"
        link.symlink_to(self.runtime, target_is_directory=True)
        with patch.object(RUNNER.ControlSocket, "RUNTIME_ROOT", link):
            with self.assertRaisesRegex(ValueError, "symlink"):
                RUNNER.ControlSocket(session)
        self.runtime.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "runtime root"):
            RUNNER.ControlSocket(session)
        self.runtime.chmod(0o700)
        with patch.object(RUNNER.ControlSocket, "RUNTIME_ROOT", session):
            before = set(session.iterdir())
            with self.assertRaisesRegex(ValueError, "too long"):
                RUNNER.ControlSocket(session)
            self.assertEqual(set(session.iterdir()), before)

    def test_changed_directory_mode_and_inode_preserve_contents(self):
        session = self.session(long=True)
        control = RUNNER.ControlSocket(session)
        with bound_socket(control.path):
            control.connected()
            control.directory.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "0700"):
                control.cleanup()
            self.assertTrue(control.path.exists())
        control.directory.chmod(0o700)
        other = RUNNER.ControlSocket(session)
        old = other.directory.with_name(other.directory.name + "-original")
        other.directory.rename(old)
        other.directory.mkdir(mode=0o700)
        sentinel = other.directory / "retained"
        sentinel.write_text("replacement directory")
        with self.assertRaisesRegex(ValueError, "identity changed"):
            other.cleanup()
        self.assertEqual(sentinel.read_text(), "replacement directory")
        self.assertTrue(old.is_dir())

    def test_replaced_endpoint_and_unexpected_files_are_preserved(self):
        session = self.session(long=True)
        for kind in ("regular", "symlink", "socket"):
            with self.subTest(kind=kind):
                control = RUNNER.ControlSocket(session)
                with bound_socket(control.path):
                    control.connected()
                    control.path.unlink()
                    if kind == "regular":
                        control.path.write_text("retain")
                    elif kind == "symlink":
                        control.path.symlink_to(session / "unrelated")
                    else:
                        replacement = socket.socket(socket.AF_UNIX)
                        self.addCleanup(replacement.close)
                        replacement.bind(str(control.path))
                    with self.assertRaisesRegex(ValueError, "preserving"):
                        control.cleanup()
                    self.assertTrue(control.path.exists() or control.path.is_symlink())
        control = RUNNER.ControlSocket(session)
        with bound_socket(control.path):
            control.connected()
            sentinel = control.directory / "unexpected"
            sentinel.write_text("preserve")
            with self.assertRaisesRegex(ValueError, "unexpected"):
                control.cleanup()
            self.assertEqual(sentinel.read_text(), "preserve")
            self.assertTrue(control.path.exists())

    def test_foreign_directory_owner_is_not_accepted(self):
        session = self.session()
        with patch.object(RUNNER.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned"):
                RUNNER.ControlSocket(session)

    def test_comma_path_uses_unambiguous_qemu_option_path(self):
        session = self.root / "session,comma"
        session.mkdir(mode=0o700)
        control = RUNNER.ControlSocket(session)
        self.assertTrue(control.external)
        self.assertNotIn(",", str(control.path))
        control.cleanup()

    def test_failed_process_launch_cleans_fallback_and_keeps_failed_receipt(self):
        state = self.session(long=True)
        monitor, rootfs = state / "monitor", state / "rootfs"
        monitor.mkdir()
        rootfs.mkdir()
        artifacts = {}
        for name in ("monitor", "guest_dtb", "Image", "initramfs"):
            path = monitor / name
            path.write_bytes(b"fixture, never booted")
            artifacts[name] = RUNNER.identity(path)
        fixture_disk = b"negative fixture disk: no execution"
        profile = {
            "schema": "ostadix.kernel-world-linux-monitor/v1", "profile": "package-domain",
            "backing_base": 0x70000000, "backing_bytes": len(fixture_disk),
            "block_backing": {"address": 0x70000000, "bytes": len(fixture_disk)},
            "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000,
            "guest_ram_bytes": 0x20000000, "outer_ram_bytes": 0x80000000,
            "loader_addresses": {"Image": 0x48000000, "guest_dtb": 0x4fe00000, "initramfs": 0x50000000},
            "artifacts": artifacts,
        }
        (monitor / "monitor-profile.json").write_text(json.dumps(profile))
        disk = rootfs / "package-domain.ext4"
        disk.write_bytes(fixture_disk)
        (rootfs / "package-domain.json").write_text(json.dumps({
            "schema": "ostadix.linux-package-domain/v1", "architecture": "aarch64",
            "artifacts": {"package-domain.ext4": RUNNER.identity(disk)}}))
        created = []
        original = RUNNER.ControlSocket
        def allocate(session):
            value = original(session)
            created.append(value)
            return value
        # Profile admission has separate real tests. This tiny negative fixture
        # reaches only the failing Popen lifecycle; no process or VM executes.
        with patch.object(RUNNER, "ControlSocket", side_effect=allocate), \
                patch.object(RUNNER, "validate_profile"), \
                patch.object(RUNNER.shutil, "which", return_value="/bin/true"), \
                patch.object(RUNNER.subprocess, "Popen", side_effect=OSError("intentional no-boot failure")) as launch:
            with self.assertRaisesRegex(OSError, "intentional no-boot"):
                RUNNER.Domain(state, "not-launched")
        launch.assert_called_once()
        self.assertTrue(created[0].external)
        self.assertFalse(created[0].directory.exists())
        record = json.loads(next(state.glob("session-*/result.json")).read_text())
        self.assertFalse(record["ok"])
        self.assertEqual(record["control_socket"]["path"], str(created[0].path))
        with (state / "domain.lock").open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_unified_constructor_uses_same_helper_and_cleans_failed_preflight(self):
        spec = importlib.util.spec_from_file_location("control_socket_unified", ROOT / "scripts/okernel_unified_world.py")
        unified = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(unified)
        state = self.session(long=True)
        (state / "fork.json").write_text(json.dumps({"schema": "ostadix.okernel-state-fork/v1",
                                                     "ok": True, "output": str(state)}))
        build = self.root / "build"
        build.mkdir()
        (build / "monitor-profile.json").write_text("{}")  # Intentionally rejected before any launch.
        created = []
        original = unified.common.ControlSocket
        def allocate(session, **options):
            value = original(session, **options)
            created.append(value)
            return value
        with patch.object(original, "RUNTIME_ROOT", self.runtime), \
                patch.object(unified.common, "ControlSocket", side_effect=allocate), \
                patch.object(tempfile, "tempdir", str(state)), \
                patch.object(unified.subprocess, "Popen") as launch:
            with self.assertRaises(ValueError):
                unified.UnifiedDomain(state, build, "not-launched")
        launch.assert_not_called()
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].external)
        self.assertEqual(created[0].directory.parent, self.runtime)
        self.assertFalse(created[0].directory.exists())
        record = json.loads(next(state.glob("unified-session-*/result.json")).read_text())
        self.assertFalse(record["ok"])
        self.assertEqual(record["control_socket"]["path"], str(created[0].path))


if __name__ == "__main__":
    unittest.main()
