"""Real interactive ash at the production init shell-return boundary.

Only the lifecycle suffix runs: boot mounts/PID1 and native UART delivery are
not exercised. Fixed guest paths map to a private PTY/directory; the loop is
bounded to one session. Shell, nested-shell and foreground input remain real.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUEST = ROOT / "ocore/guest/linux/package-domain"
INIT = GUEST / "package-domain-init"
SHELLRC = GUEST / "okernel-shellrc"


@unittest.skipUnless(shutil.which("busybox") and shutil.which("setsid"), "interactive ash and setsid required")
class GuestExitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="okernel-exit-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.control = self.root / "run/p9"
        self.marker = self.control / "console-exit.json"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for command in ("setsid", "tr", "mkdir", "chmod", "mktemp", "mv", "rm", "cat"):
            (self.bin / command).symlink_to(shutil.which("busybox"))

    def start(self, *, unified=True):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        source = INIT.read_text().split("# Managed console lifecycle.", 1)[1]
        # Keep every production shell command, substituting only fixture paths,
        # host ash's executable spelling and the loop's iteration bound.
        source = "# Managed console lifecycle." + source
        source = source.replace("/run/okernel/p9", str(self.control)).replace("/run/okernel", str(self.root / "run"))
        source = source.replace("/dev/ttyAMA0", os.ttyname(slave))
        source = source.replace("/dev/ttyAMA1", "/dev/null" if unified else str(self.root / "no-uart"))
        source = source.replace("exec /bin/sh -i", "exec " + shlex.quote(shutil.which("busybox")) + " sh -i")
        source = source.replace("while :; do", "for fixture_session in once; do")
        script = self.root / "console.sh"
        script.write_text(source)
        env = dict(os.environ, PATH=str(self.bin), ENV=str(SHELLRC), HOME=str(self.root), TERM="vt100", PS1="fixture> ")
        process = subprocess.Popen([shutil.which("busybox"), "sh", str(script)], env=env,
                                   stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        def stop():
            if process.poll() is None:
                # Only this fixture's direct managed shell can remain alive.
                children = Path(f"/proc/{process.pid}/task/{process.pid}/children")
                for child in children.read_text().split() if children.exists() else ():
                    try:
                        os.killpg(int(child), signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                process.terminate()
            process.wait(timeout=3)
        self.addCleanup(stop)
        self.until(master, b"fixture> ")
        return master, process

    def until(self, fd, expected):
        data = bytearray()
        deadline = time.monotonic() + 4
        while expected not in data and time.monotonic() < deadline:
            if select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
                try:
                    data.extend(os.read(fd, 4096))
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
        self.assertIn(expected, data, repr(data))
        return bytes(data)

    def test_nested_exit_and_foreground_exit_text_do_not_publish_then_quit_does(self):
        master, process = self.start()
        os.write(master, (shlex.quote(shutil.which("busybox")) + " sh -i\n").encode())
        self.until(master, b"fixture> ")
        os.write(master, b"exit\n")
        self.until(master, b"fixture> ")
        self.assertFalse(self.marker.exists(), "nested shell exit reached the PID1 boundary")
        os.write(master, b"cat\n")
        self.until(master, b"cat\r\n")
        os.write(master, b"exit\nquit\n")
        self.until(master, b"quit\r\n")
        self.assertFalse(self.marker.exists(), "foreground input reached the PID1 boundary")
        os.write(master, b"\x04")
        self.until(master, b"fixture> ")
        os.write(master, b"quit\n")
        self.assertEqual(process.wait(timeout=4), 0)
        value = json.loads(self.marker.read_bytes())
        self.assertEqual(set(value), {"schema", "request_id"})
        self.assertEqual(value["schema"], "ostadix.console-exit-request/v1")
        self.assertRegex(value["request_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.control.stat().st_mode & 0o777, 0o700)
        self.assertEqual(list(self.control.glob(".console-exit.*")), [])

    def test_each_managed_exit_publishes_a_fresh_complete_request(self):
        ids = []
        for _ in range(2):
            master, process = self.start()
            os.write(master, b"exit\n")
            self.assertEqual(process.wait(timeout=4), 0)
            ids.append(json.loads(self.marker.read_bytes())["request_id"])
        self.assertNotEqual(*ids)

    def test_killed_managed_shell_restarts_without_operator_exit_request(self):
        master, process = self.start()
        children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
        self.assertEqual(len(children), 1)
        os.kill(int(children[0]), signal.SIGKILL)
        self.assertEqual(process.wait(timeout=4), 0)
        self.until(master, b"Console shell interrupted;")
        self.assertFalse(self.marker.exists())

    def test_standalone_without_private_uart_does_not_request_save(self):
        master, process = self.start(unified=False)
        os.write(master, b"quit\n")
        self.assertEqual(process.wait(timeout=4), 0)
        self.assertFalse(self.marker.exists())

    def test_private_directory_symlink_fails_without_writing_outside(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / "run").symlink_to(outside)
        master, process = self.start()
        os.write(master, b"exit\n")
        self.assertEqual(process.wait(timeout=4), 0)
        self.until(master, b"Could not publish the private exit request.")
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
