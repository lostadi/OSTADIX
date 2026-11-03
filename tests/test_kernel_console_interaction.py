"""Drive the real native serial console of an explicitly supplied kernel ELF.

No build is implicit. Run with --kernel ELF [--qemu QEMU] [--output LOG], or
set OCORE_CONSOLE_TEST_KERNEL and OCORE_QEMU_BIN for unittest discovery.
"""

import argparse
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
import unittest


class KernelConsoleInteractionTests(unittest.TestCase):
    def setUp(self):
        kernel = os.environ.get("OCORE_CONSOLE_TEST_KERNEL")
        if not kernel:
            self.skipTest("set OCORE_CONSOLE_TEST_KERNEL to a built mode-16 kernel ELF")
        self.assertTrue(Path(kernel).is_file(), kernel)
        qemu = os.environ.get("OCORE_QEMU_BIN", "qemu-system-x86_64")
        self.process = subprocess.Popen(
            [qemu, "-machine", "q35", "-m", "128M", "-nodefaults", "-nic", "none",
             "-kernel", kernel, "-display", "none", "-serial", "stdio",
             "-no-reboot", "-no-shutdown"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.output = bytearray()
        self.errors = bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ, self.output)
        self.selector.register(self.process.stderr, selectors.EVENT_READ, self.errors)
        self.addCleanup(self.stop)

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.pump(0.05)
        self.selector.close()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        destination = os.environ.get("OCORE_CONSOLE_TEST_OUTPUT")
        if destination:
            Path(destination).write_bytes(bytes(self.output) + bytes(self.errors))

    def pump(self, duration):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            for key, _ in self.selector.select(timeout=min(0.05, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if chunk:
                    key.data.extend(chunk)
                else:
                    self.selector.unregister(key.fileobj)

    def await_prompts(self, expected):
        deadline = time.monotonic() + 10
        while self.output.count(b"o> ") < expected and time.monotonic() < deadline:
            self.pump(0.05)
            if self.process.poll() is not None:
                break
        self.pump(0.1)  # Include a trailing LF so CRLF cannot hide a second prompt.
        self.assertEqual(self.output.count(b"o> "), expected, self.transcript())
        self.assertIsNone(self.process.poll(), self.transcript())

    def transcript(self):
        return (bytes(self.output) + bytes(self.errors)).decode("utf-8", "replace")[-12000:]

    def exchange(self, data, prompt_increment=1, status_increment=0, rejected_increment=0):
        prompts = self.output.count(b"o> ")
        statuses = self.output.count(b"M5 serial status: PASS\n")
        rejected = self.output.count(b"M5 serial command: rejected\n")
        start = len(self.output)
        self.process.stdin.write(data)
        self.process.stdin.flush()
        self.await_prompts(prompts + prompt_increment)
        self.assertEqual(self.output.count(b"M5 serial status: PASS\n"), statuses + status_increment, self.transcript())
        self.assertEqual(self.output.count(b"M5 serial command: rejected\n"), rejected + rejected_increment, self.transcript())
        return bytes(self.output[start:])

    def test_native_console_keyboard_help_and_recovery(self):
        self.await_prompts(1)
        for name in (b"init", b"supervisor", b"pkgd", b"repl"):
            self.assertIn(b"M5 " + name + b" service ELF: online\n", self.output)
        self.assertIn(b"Type help for commands.", self.output)

        help_output = self.exchange(b"help\r\n")
        self.assertIn(b"help\r\n", help_output)  # Input is echoed by the guest.
        self.assertIn(b"OKernel native service console\nCommands:\n", help_output)
        self.assertIn(b"install <sha256> 5 1", help_output)
        self.assertIn(b"Activation parks this console", help_output)
        self.assertIn(b"Commands:\n", self.exchange(b"?\n"))
        self.exchange(b"\r\n")  # Empty Enter is harmless and CRLF is one Enter.
        self.exchange(b"status\r\n", status_increment=1)

        edited = self.exchange(b"statuz\x7fs\n", status_increment=1)
        self.assertIn(b"statuz\b \bs\r\n", edited)
        self.exchange(b"statuz\x08s\n", status_increment=1)
        cleared = self.exchange(b"mistake\x15status\n", status_increment=1)
        self.assertIn(b"\b \b" * len(b"mistake"), cleared)
        cancelled = self.exchange(b"wrong\x03status\n", prompt_increment=2, status_increment=1)
        self.assertIn(b"^C\r\n", cancelled)

        rejected = self.exchange(b"ls\n", rejected_increment=1)
        self.assertIn(b"Type help for supported commands and argument syntax.", rejected)
        self.exchange(b"x" * 192 + b"status\n", rejected_increment=1)
        self.exchange(b"status\n", status_increment=1)
        self.exchange(b"\x1b[Astatus\n", rejected_increment=1)
        self.exchange(b"status\n", status_increment=1)
        self.exchange(b"x" * 192 + b"\x03status\n", prompt_increment=2, status_increment=1)

        self.assertNotIn(b"M5 serial package install: PASS", self.output)
        self.assertNotIn(b"M5 serial package activation: PASS", self.output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel")
    parser.add_argument("--qemu")
    parser.add_argument("--output")
    arguments, remaining = parser.parse_known_args()
    for value, name in ((arguments.kernel, "OCORE_CONSOLE_TEST_KERNEL"),
                        (arguments.qemu, "OCORE_QEMU_BIN"),
                        (arguments.output, "OCORE_CONSOLE_TEST_OUTPUT")):
        if value:
            os.environ[name] = value
    unittest.main(argv=[sys.argv[0], *remaining])
