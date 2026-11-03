"""Native replay evidence must reject mismatched outcomes and extra syscalls."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
USER = ROOT / "ocore/user"
sys.path.insert(0, str(USER))
SPEC = importlib.util.spec_from_file_location("linux_native_replay", USER / "replay_linux_minimal.py")
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)
sys.path.pop(0)
ORACLE_PATH = USER / "linux-minimal-oracle.json"
TRACE = '''execve("/tmp/linux-minimal.elf", ["/tmp/linux-minimal.elf"], 0x1234 /* 2 vars */) = 0
write(1, "o-core linux stdout\\n", 20) = 20
write(2, "o-core linux stderr\\n", 20) = 20
syscall_0x7fffffff(0, 0, 0, 0, 0, 0) = -1 ENOSYS (Function not implemented)
exit_group(42) = ?
'''


class NativeReplayTests(unittest.TestCase):
    def setUp(self):
        self.oracle = REPLAY.load_oracle(ORACLE_PATH)

    def check(self, trace=TRACE, stdout=b"o-core linux stdout\n",
              stderr=b"o-core linux stderr\n", status=42):
        return REPLAY.check_observation(stdout, stderr, status, trace, self.oracle)

    def test_exact_observed_trace_normalizes_to_expected_syscalls(self):
        self.assertEqual(self.check(), self.oracle["expected"]["syscalls"])

    def test_outputs_and_exit_must_all_match(self):
        for wrong in ({"stdout": b""}, {"stderr": b"extra"}, {"status": 0}, {"status": -11}):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                self.check(**wrong)

    def test_trace_rejects_missing_reordered_and_extra_calls(self):
        lines = TRACE.splitlines(keepends=True)
        for trace in ("".join(lines[:-1]), "".join([lines[0], lines[2], lines[1], *lines[3:]]),
                      TRACE + "getpid() = 123\n", "".join([*lines[:2], lines[1], *lines[2:]])):
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                self.check(trace=trace)

    def test_successful_output_cannot_hide_wrong_syscall_arguments_or_errno(self):
        for old, new in (("write(1,", "write(3,"), ("20) = 20", "20) = 19"),
                         ("0x7fffffff", "0x7ffffffe"), ("ENOSYS", "EPERM"),
                         ("exit_group(42)", "exit_group(0)")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.check(trace=TRACE.replace(old, new))

    def test_wrong_architecture_is_not_treated_as_native(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "observation.json"
            output.write_text('{"result": "PASS"}')
            with patch.object(REPLAY.platform, "machine", return_value="aarch64"), \
                    self.assertRaisesRegex(ValueError, "requires Linux x86_64"):
                REPLAY.replay(Path("unused"), ORACLE_PATH, output)
            self.assertFalse(output.exists())

    def test_unverified_executable_is_never_run_and_no_receipt_written(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "bad.elf"
            output = Path(directory) / "observation.json"
            elf.write_bytes(b"not an ELF")
            output.write_text('{"result": "PASS"}')
            with patch.object(REPLAY.platform, "system", return_value="Linux"), \
                    patch.object(REPLAY.platform, "machine", return_value="x86_64"), \
                    patch.object(REPLAY.shutil, "which", return_value="/usr/bin/strace"), \
                    patch.object(REPLAY.subprocess, "Popen") as run, \
                    self.assertRaises(ValueError):
                REPLAY.replay(elf, ORACLE_PATH, output)
            run.assert_not_called()
            self.assertFalse(output.exists())

    def test_output_alias_cannot_delete_input(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "input.elf"
            elf.write_bytes(b"preserved input")
            alias = Path(directory) / "alias.json"
            alias.symlink_to(elf)
            with self.assertRaisesRegex(ValueError, "must not replace"):
                REPLAY.replay(elf, ORACLE_PATH, alias)
            self.assertEqual(elf.read_bytes(), b"preserved input")


if __name__ == "__main__":
    unittest.main()
