"""Execute the exact audit transport through the original interactive BusyBox."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import signal
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("x12_audit_transport", ROOT / "scripts/verify_okernel_x12_iso.py")
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class AuditTransportTests(unittest.TestCase):
    def test_large_unicode_and_quotes_preserve_exact_bytes_with_short_lines(self):
        source = "x='quotes \\\" and unicode Ω';\n" * 1000
        command = verifier.audit_shell_command(source, "AUDIT_123")
        self.assertLess(max(map(len, command.encode("ascii").splitlines())), 512)
        lines = command.splitlines()
        delimiter = lines[0].rsplit("<<'", 1)[1][:-1]
        end = lines.index(delimiter)
        self.assertNotIn("_", "".join(lines[1:end]))
        decoded = base64.b64decode("".join(lines[1:end]), validate=True)
        self.assertEqual(decoded, source.encode("utf-8"))
        self.assertIn(hashlib.sha256(decoded).hexdigest(), lines[0])
        self.assertIn('"$_audit_rc"', lines[-1])

    def test_completion_marker_rejects_shell_syntax(self):
        for marker in ("", "one\ntwo", "'; reboot; '", "$(command)", "x" * 129):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                verifier.audit_shell_command("pass", marker)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("busybox"), "interactive BusyBox/Linux PTY required")
    def test_real_busybox_ash_runs_large_raw_oracle_and_propagates_failure(self):
        with tempfile.TemporaryDirectory(prefix="x12-audit-pty-") as directory:
            root = Path(directory)
            token, digest = "0123456789abcdefabcd", "a" * 64
            (root / "linux-console.log").write_bytes(
                ("\nOKERNEL_ISO_SOURCE_" + token + "\nOKERNEL_ISO_COMMAND_" + token + ":0\n"
                 + digest + "  /n/okernel/work/iso-" + token + "\n"
                 + digest + "  /work/iso-p9-" + token + "\n").encode())
            observed = root / "observed.json"
            # Actual saved-log assertions plus quote-heavy source well past
            # both ash's editor and the kernel's canonical-line limits.
            source = ("from pathlib import Path;import re,json;p=Path(" + repr(str(root)) + ");"
                      + verifier.raw_application_assertions(token, digest)
                      + "padding=" + repr("Ω ' \" \\ " * 1200) + ";"
                      + "Path(" + repr(str(observed)) + ").write_text(json.dumps({'ok':True,'padding':padding}))")
            expected = "Ω ' \" \\ " * 1200
            pid, terminal = pty.fork()
            if pid == 0:
                environment = dict(os.environ, HOME=str(root), ENV="", PS1="AUDIT_READY> ", PS2="AUDIT_MORE> ", TERM="vt100", PATH="/usr/bin:/bin")
                os.execvpe(shutil.which("busybox"), ["busybox", "ash", "-i"], environment)
            os.set_blocking(terminal, False)
            output = bytearray()
            def exchange(payload, wanted, timeout=15):
                remaining = memoryview(payload)
                until = time.monotonic() + timeout
                while time.monotonic() < until:
                    reads, writes, _ = select.select([terminal], [terminal] if remaining else [], [], .05)
                    if reads:
                        try: data = os.read(terminal, 65536)
                        except BlockingIOError: data = b""
                        if data: output.extend(data)
                    if writes:
                        try: count = os.write(terminal, remaining[:128])
                        except BlockingIOError: count = 0
                        remaining = remaining[count:]
                    if not remaining and wanted in output:
                        return
                self.fail("interactive audit did not complete: " + repr(bytes(output[-2000:])))
            try:
                exchange(b"", b"AUDIT_READY> ")
                command = verifier.audit_shell_command(source, "AUDIT_SUCCESS")
                exchange(command.encode(), b"AUDIT_SUCCESS:0\r\n")
                actual = json.loads(observed.read_bytes())
                self.assertEqual(actual, {"ok": True, "padding": expected})
                # Corrupt real raw evidence, then exercise the same generated
                # transport: a failed assertion must remain status1.
                (root / "linux-console.log").write_bytes(b"missing original source/checksum/status lines\n")
                command = verifier.audit_shell_command(source, "AUDIT_FAILURE")
                exchange(command.encode(), b"AUDIT_FAILURE:1\r\n")
            finally:
                # Interactive ash intentionally ignores SIGTERM. Only this
                # isolated fixture shell is terminated after its assertions.
                try: os.kill(pid, signal.SIGKILL)
                except ProcessLookupError: pass
                os.waitpid(pid, 0)
                os.close(terminal)


if __name__ == "__main__": unittest.main()
