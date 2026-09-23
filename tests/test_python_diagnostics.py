"""Python error dumps remain private and survive shared-temp PID reuse."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BACKENDS = ROOT / "backends"
sys.path.insert(0, str(BACKENDS))
import o_shim_common as wire


def load_shim():
    spec = importlib.util.spec_from_file_location("python_diagnostics_shim", BACKENDS / "python_shim.py")
    shim = importlib.util.module_from_spec(spec)
    with patch.object(wire, "command_loop"):
        spec.loader.exec_module(shim)
    return shim


class PythonDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shim = load_shim()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ostadix-python-diagnostics-")
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        environment = patch.dict(os.environ, {"TMPDIR": str(self.work), "O_PYTHON_DUMP_FILE": ""})
        environment.start()
        self.addCleanup(environment.stop)

    def test_dumps_are_unique_private_and_preserve_source(self):
        source = '# Unicode λ\nraise ValueError("original")\n'
        previous_umask = os.umask(0)
        try:
            paths = [Path(self.shim.dump_generated_python(source)) for _ in range(2)]
        finally:
            os.umask(previous_umask)
        self.assertNotEqual(paths[0], paths[1])
        for path in paths:
            self.assertEqual(path.parent, self.work)
            self.assertEqual(path.read_text(encoding="utf-8"), source)
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_old_pid_symlink_does_not_overwrite_another_file(self):
        target = self.work / "unrelated.txt"
        target.write_text("do not overwrite")
        old_path = self.work / f"O-python-failing-{os.getpid()}.py"
        old_path.symlink_to(target)
        dump = Path(self.shim.dump_generated_python("raise ValueError('diagnostic')"))
        self.assertNotEqual(dump, old_path)
        self.assertEqual(target.read_text(), "do not overwrite")
        self.assertTrue(old_path.is_symlink())
        self.assertTrue(dump.is_file())

    def test_explicit_dump_override_is_preserved(self):
        target = self.work / "requested.py"
        with patch.dict(os.environ, {"O_PYTHON_DUMP_FILE": str(target)}):
            self.assertEqual(self.shim.dump_generated_python("first"), str(target))
            self.assertEqual(self.shim.dump_generated_python("second"), str(target))
        self.assertEqual(target.read_text(), "second")

    def test_unwritable_diagnostic_does_not_replace_original_error(self):
        missing = self.work / "missing" / "directory"
        with patch.dict(os.environ, {"TMPDIR": str(missing)}), \
                patch.object(self.shim, "send_err") as send_error:
            self.shim.handle_exec({"code": "raise ValueError('original execution failure')", "bindings": {}})
        message = send_error.call_args.args[0]
        self.assertIn("ValueError: original execution failure", message)
        self.assertIn("<failed to write generated Python source:", message)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0,
                         "cross-user regression requires a root test runner")
    def test_app_user_can_dump_after_root_owned_pid_collision_and_recover(self):
        # On the Android host HOME belongs to Termux while the maintenance
        # shell is root. Run the real shim as that owner, never as root.
        owner = Path.home().stat()
        if owner.st_uid == 0:
            self.skipTest("no non-root home owner available for the subprocess")
        self.work.chmod(0o1777)
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        with subprocess.Popen(
            [sys.executable, str(BACKENDS / "python_shim.py")],
            env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, user=owner.st_uid, group=owner.st_gid,
            extra_groups=[],
        ) as process:
            old_path = self.work / f"O-python-failing-{process.pid}.py"
            old_path.write_text("previous root diagnostic")
            old_path.chmod(0o644)
            self.assertEqual(old_path.stat().st_uid, 0)
            code = "raise ValueError('app execution failure')"
            requests = [
                {"cmd": "exec", "code": code, "bindings": {}},
                {"cmd": "exec", "code": "6 * 7", "bindings": {}},
                {"cmd": "shutdown"},
            ]
            payload = b""
            for request in requests:
                encoded = wire.cbor_encode(request)
                payload += len(encoded).to_bytes(4, "big") + encoded
            try:
                output, error = process.communicate(payload, timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                self.fail("Python diagnostic regression subprocess timed out")
            self.assertEqual(process.returncode, 0, error.decode(errors="replace"))
        import io
        stream = io.BytesIO(output)
        failed = wire.read_wire_message(stream)
        recovered = wire.read_wire_message(stream)
        shutdown = wire.read_wire_message(stream)
        self.assertEqual(failed["status"], "err")
        self.assertIn("ValueError: app execution failure", failed["message"])
        self.assertNotIn("failed to write", failed["message"])
        self.assertEqual(recovered["value"], {"t": "int", "v": 42})
        self.assertEqual(shutdown, {"status": "ok", "value": {"t": "null"}})
        self.assertEqual(old_path.read_text(), "previous root diagnostic")
        dumps = list(self.work.glob(f"O-python-failing-{process.pid}-*.py"))
        self.assertEqual(len(dumps), 1)
        self.assertEqual(dumps[0].stat().st_uid, owner.st_uid)
        self.assertEqual(dumps[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(dumps[0].read_text(), code)


if __name__ == "__main__":
    unittest.main()
