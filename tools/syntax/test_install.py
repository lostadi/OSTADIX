"""Behavioral checks for config preservation and the interactive cat adapter."""

import importlib.util
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("syntax_install", ROOT / "install.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class ConfigTests(unittest.TestCase):
    def test_block_preserves_other_settings_and_is_repeatable(self):
        original = 'set linenumbers\n# User settings\n'
        once = install.managed_block(original, 'include "/tmp/Ostadix.nanorc"')
        self.assertTrue(once.startswith(original))
        self.assertEqual(once, install.managed_block(once, 'include "/tmp/Ostadix.nanorc"'))
        changed = install.managed_block(once + "set tabsize 4\n", 'include "/new/Ostadix.nanorc"')
        self.assertTrue(changed.endswith("set tabsize 4\n"))
        self.assertNotIn("/tmp/Ostadix", changed)

    def test_broken_markers_are_rejected(self):
        for malformed in [install.BEGIN, install.END, install.BEGIN * 2 + install.END]:
            with self.assertRaises(ValueError):
                install.managed_block(malformed, "new")

    def test_write_preserves_original_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            original = directory / "dotfiles/zshrc"
            original.parent.mkdir()
            original.write_text("# personal settings\n")
            original.chmod(0o600)
            link = directory / ".zshrc"
            link.symlink_to(original)
            instance = install.Installer()
            instance.backups = directory / "backups"
            instance.write(link, "# updated settings\n")
            self.assertTrue(link.is_symlink())
            self.assertEqual(original.read_text(), "# updated settings\n")
            self.assertEqual(original.stat().st_mode & 0o777, 0o600)
            backups = list(instance.backups.rglob("zshrc"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), "# personal settings\n")

    def test_reinstall_repairs_executable_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "ocat"
            target.write_text("#!/bin/sh\n")
            target.chmod(0o644)
            install.Installer().write(target, target.read_bytes(), executable=True)
            self.assertEqual(target.stat().st_mode & 0o111, 0o111)


@unittest.skipUnless(shutil.which("zsh"), "zsh unavailable")
class CatTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.fixture = self.directory / "sample.O"
        self.fixture.write_bytes(b'python^(\n42\n)_python\n')
        fake_bat = self.directory / "bat"
        fake_bat.write_text('#!/bin/sh\nprintf "BAT_SELECTED"\n')
        fake_bat.chmod(0o755)
        self.environment = {**os.environ, "PATH": str(self.directory) + os.pathsep + os.environ["PATH"], "TERM": "xterm-256color"}
        self.environment.pop("NO_COLOR", None)
        self.command = ["zsh", "-f", "-i", "-c", 'source "$1"; shift; cat "$@"', "syntax-test", str(ROOT / "terminal/ostadix-cat.zsh")]

    def tearDown(self):
        self.temporary.cleanup()

    def run_cat(self, arguments, tty=False, environment=None, input_bytes=None):
        command = self.command + [str(arg) for arg in arguments]
        env = environment or self.environment
        if not tty:
            return subprocess.run(command, env=env, input=input_bytes, capture_output=True, check=True).stdout
        master, slave = pty.openpty()
        try:
            completed = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            chunks = []
            while select.select([master], [], [], 0.2)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).replace(b"\r\n", b"\n")
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)

    def test_terminal_selects_bat_for_source(self):
        self.assertEqual(self.run_cat([self.fixture], tty=True), b"BAT_SELECTED")

    def test_pipe_preserves_arbitrary_bytes_and_stdin(self):
        binary = b"\x00\xff\x1b[31mbytes\r\n"
        self.fixture.write_bytes(binary)
        self.assertEqual(self.run_cat([self.fixture]), binary)
        self.assertEqual(self.run_cat([], input_bytes=b"stdin\x00\xff"), b"stdin\x00\xff")

    def test_ocat_pipe_bypasses_bat_configuration(self):
        config = self.directory / "bat-config"
        config.write_text("--color=always\n--line-range=2:2\n")
        result = subprocess.run(["sh", str(ROOT / "terminal/ocat"), str(self.fixture)], env={**self.environment, "BAT_CONFIG_PATH": str(config)}, capture_output=True, check=True)
        self.assertEqual(result.stdout, self.fixture.read_bytes())

    def test_options_non_source_and_mixed_files_keep_cat(self):
        expected = self.fixture.read_bytes()
        text = self.directory / "sample.txt"
        text.write_bytes(b"plain\n")
        self.assertEqual(self.run_cat([text], tty=True), b"plain\n")
        self.assertEqual(self.run_cat([self.fixture, text], tty=True), expected + b"plain\n")
        self.assertNotIn(b"BAT_SELECTED", self.run_cat(["-n", self.fixture], tty=True))
        self.assertEqual(self.run_cat([self.fixture], tty=True, environment={**self.environment, "NO_COLOR": "1"}), expected)


if __name__ == "__main__":
    unittest.main()
