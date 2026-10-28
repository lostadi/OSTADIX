"""Linux conformance carriers need both a matching ISA and host OS."""

import unittest
from unittest.mock import patch

from scripts.check_ocore_native_equivalence import execution_prefix


class ExecutionPrefixTests(unittest.TestCase):
    @patch("scripts.check_ocore_native_equivalence.shutil.which")
    @patch("scripts.check_ocore_native_equivalence.platform.machine", return_value="aarch64")
    @patch("scripts.check_ocore_native_equivalence.platform.system", return_value="Linux")
    def test_linux_aarch64_executes_directly(self, _system, _machine, which):
        self.assertEqual(execution_prefix("aarch64"), [])
        # CLI defaults also supply an emulator name for the native ISA.
        self.assertEqual(execution_prefix("aarch64", "qemu-aarch64"), [])
        which.assert_not_called()

    @patch("scripts.check_ocore_native_equivalence.shutil.which", return_value=None)
    @patch("scripts.check_ocore_native_equivalence.platform.machine", return_value="arm64")
    @patch("scripts.check_ocore_native_equivalence.platform.system", return_value="Darwin")
    def test_darwin_arm64_requires_a_linux_runner(self, _system, _machine, which):
        with self.assertRaisesRegex(RuntimeError, "aarch64 Linux ELF runner on Darwin.*Linux host"):
            execution_prefix("aarch64")
        which.assert_called_once_with("qemu-aarch64")

    @patch("scripts.check_ocore_native_equivalence.shutil.which", return_value="/usr/bin/qemu-aarch64")
    @patch("scripts.check_ocore_native_equivalence.platform.machine", return_value="x86_64")
    @patch("scripts.check_ocore_native_equivalence.platform.system", return_value="Linux")
    def test_linux_cross_isa_uses_matching_emulator(self, _system, _machine, which):
        self.assertEqual(execution_prefix("aarch64"), ["/usr/bin/qemu-aarch64"])
        which.assert_called_once_with("qemu-aarch64")

    def test_explicit_runner_is_preserved_when_native_execution_is_unavailable(self):
        for system, machine in (("Darwin", "arm64"), ("Linux", "x86_64")):
            with self.subTest(system=system), \
                 patch("scripts.check_ocore_native_equivalence.platform.system", return_value=system), \
                 patch("scripts.check_ocore_native_equivalence.platform.machine", return_value=machine), \
                 patch("scripts.check_ocore_native_equivalence.shutil.which", return_value="/opt/tools/linux-arm64") as which:
                self.assertEqual(execution_prefix("aarch64", "linux-arm64"), ["/opt/tools/linux-arm64"])
                which.assert_called_once_with("linux-arm64")


if __name__ == "__main__":
    unittest.main()
