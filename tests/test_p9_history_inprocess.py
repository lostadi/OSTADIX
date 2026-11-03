"""History maintenance reuses checked code/protocol without another process."""
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests.test_plan9_installed_resolution import CLIENT

HELPER = b'''import os
class History:
 def __init__(self, control, protocol): self.control,self.protocol=control,protocol
 def collect(self): self.protocol.update(pid=os.getpid(),control=str(self.control),marker="checked")
if __name__ == "__main__": raise AssertionError("CLI parsing is not the maintenance interface")
'''


class HistoryInProcessTests(unittest.TestCase):
    def test_checked_helper_reuses_protocol_pid_and_leaves_job_stdin_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p9-history"
            path.write_bytes(HELPER)
            path.chmod(0o600)
            protocol = {}
            incoming = io.StringIO("job input is still here")
            with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("extra interpreter")), \
                    mock.patch.object(sys, "stdin", incoming):
                CLIENT.preserve_history(Path(directory) / "control", protocol, path)
            self.assertEqual(protocol, {"pid": os.getpid(), "control": str(Path(directory) / "control"), "marker": "checked"})
            self.assertEqual(incoming.tell(), 0)
            self.assertEqual(incoming.read(), "job input is still here")

    def test_executes_verified_bytes_without_reopening_changed_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p9-history"
            path.write_bytes(HELPER)
            path.chmod(0o600)
            original = CLIENT.read_file
            def checked_then_replaced(*args, **kwargs):
                data = original(*args, **kwargs)
                path.write_bytes(b'raise AssertionError("replacement must not execute")\n')
                return data
            protocol = {}
            with mock.patch.object(CLIENT, "read_file", side_effect=checked_then_replaced):
                CLIENT.preserve_history(Path(directory), protocol, path)
            self.assertEqual(protocol["marker"], "checked")

    def test_missing_optional_helper_is_read_only_and_untrusted_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "p9-history"
            protocol = {}
            CLIENT.preserve_history(Path(directory), protocol, path)
            self.assertEqual(protocol, {})
            path.write_bytes(HELPER)
            path.chmod(0o666)
            with self.assertRaises(CLIENT.ClientError):
                CLIENT.preserve_history(Path(directory), protocol, path)
            path.chmod(0o600)
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                CLIENT.preserve_history(Path(directory), protocol, alias)


if __name__ == "__main__":
    unittest.main()
