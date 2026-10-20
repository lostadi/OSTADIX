"""Behavioral checks for config preservation and the interactive cat adapter."""

import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile
import plistlib

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


class EditorInstallerTests(unittest.TestCase):
    def setUp(self):
        # Most fixtures model XDG paths and fake PATH executables. Do not let
        # an actual macOS application leak into those isolated installations.
        platform = patch.object(install.sys, "platform", "linux")
        platform.start()
        self.addCleanup(platform.stop)
        self.temporary = tempfile.TemporaryDirectory(prefix="ostadix syntax test ")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.bin = self.home / "bin"
        self.bin.mkdir()
        self.log = self.home / "editor-commands"
        self.environment = {
            "HOME": str(self.home), "PATH": str(self.bin),
            "XDG_CONFIG_HOME": str(self.home / "configuration"),
            "XDG_DATA_HOME": str(self.home / "data"),
            "SYNTAX_COMMAND_LOG": str(self.log),
            "SYNTAX_BAT_CONFIG": str(self.home / "configuration/bat"),
        }

    def executable(self, name, body='printf "%s\\n" "$0 $*" >> "$SYNTAX_COMMAND_LOG"\n'):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
        return path

    def run_installer(self, *arguments):
        output = io.StringIO()
        with patch.dict(os.environ, self.environment, clear=True), patch.object(install, "use_login_user", return_value=True), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            status = install.main(list(arguments))
        return status, output.getvalue()

    def test_default_discovers_all_code_editors_and_preserves_nano_without_cat_override(self):
        for name, _, _ in install.CODE_EDITORS:
            self.executable(name)
        self.executable("nano", 'printf "GNU nano 8.4\\n"\n')
        self.executable("batcat", 'if [ "$1" = --config-dir ]; then printf "%s\\n" "$SYNTAX_BAT_CONFIG"; else printf "%s\\n" "$0 $*" >> "$SYNTAX_COMMAND_LOG"; fi\n')
        nanorc = self.home / ".nanorc"
        nanorc.write_text("set linenumbers\n")
        status, output = self.run_installer()
        self.assertEqual(status, 0, output)
        commands = self.log.read_text().splitlines()
        self.assertEqual(sum("--install-extension" in command for command in commands), 4)
        self.assertTrue(any("cache --build" in command for command in commands))
        self.assertTrue(nanorc.read_text().startswith("set linenumbers\n"))
        self.assertEqual(nanorc.read_text().count(install.BEGIN), 1)
        self.assertTrue(list((self.home / "data/ostadix/syntax/backups").rglob(".nanorc")))
        self.assertTrue((self.home / "configuration/nano/syntax/ostadix.nanorc").is_file())
        self.assertFalse((self.home / ".zshrc").exists())
        self.assertFalse((self.home / ".local/bin/ocat").exists())
        vsix = next((self.home / "data/ostadix/syntax").glob("*.vsix"))
        with zipfile.ZipFile(vsix) as archive:
            package = json.loads(archive.read("extension/package.json"))
            self.assertEqual(package["contributes"]["languages"][0]["id"], "ostadix")
            self.assertIn("extension/syntaxes/ostadix.tmLanguage.json", archive.namelist())
        status, output = self.run_installer("--only", "nano")
        self.assertEqual(status, 0, output)
        self.assertEqual(nanorc.read_text().count(install.BEGIN), 1)

    def test_absent_editors_skip_successfully_without_creating_profiles(self):
        status, output = self.run_installer()
        self.assertEqual(status, 0, output)
        for component in install.DEFAULT_COMPONENTS:
            self.assertIn(f"SKIP {component}", output)
        self.assertEqual(set(self.home.iterdir()), {self.bin})

    def test_check_and_dry_run_never_execute_editors_or_write_configuration(self):
        self.executable("code")
        self.executable("nano")
        self.executable("bat")
        for flag in ("--check", "--dry-run"):
            with self.subTest(flag=flag):
                status, output = self.run_installer("--only", "vscode", "nano", "bat", flag)
                self.assertEqual(status, 0, output)
                self.assertFalse(self.log.exists())
                self.assertFalse((self.home / "data").exists())
                self.assertFalse((self.home / "configuration").exists())
                self.assertFalse((self.home / ".nanorc").exists())

    def test_pico_is_skipped_without_launching_it(self):
        pico = self.executable("pico")
        (self.bin / "nano").symlink_to(pico)
        status, output = self.run_installer("--only", "nano")
        self.assertEqual(status, 0, output)
        self.assertIn("SKIP nano", output)
        self.assertFalse(self.log.exists())

    def test_vim_neovim_and_emacs_install_assets_preserve_init_and_do_not_launch_editors(self):
        for name in ("vim", "nvim", "emacs"):
            self.executable(name)
        init = self.home / ".emacs"
        init.write_text("(setq user-setting t)\n")
        status, output = self.run_installer("--only", "vim", "nvim", "emacs")
        self.assertEqual(status, 0, output)
        for directory in (self.home / ".vim", self.home / "configuration/nvim"):
            for kind in ("ftdetect", "syntax"):
                self.assertEqual((directory / kind / "ostadix.vim").read_bytes(), (ROOT / "vim" / kind / "ostadix.vim").read_bytes())
        mode = self.home / "configuration/ostadix/syntax/ostadix-mode.el"
        self.assertEqual(mode.read_bytes(), (ROOT / "emacs/ostadix-mode.el").read_bytes())
        self.assertTrue(init.read_text().startswith("(setq user-setting t)\n"))
        self.assertIn(f'(load "{mode}" nil t)', init.read_text())
        self.assertFalse(self.log.exists())
        status, output = self.run_installer("--only", "emacs")
        self.assertEqual(status, 0, output)
        self.assertEqual(init.read_text().count(";; >>> Ostadix"), 1)

    def test_mac_app_editor_cli_is_detected_without_path_entry(self):
        app_cli = self.home / "Applications/Visual Studio Code.app/Contents/Resources/app/bin/code"
        app_cli.parent.mkdir(parents=True)
        app_cli.write_text('#!/bin/sh\nprintf "%s\\n" "$0 $*" >> "$SYNTAX_COMMAND_LOG"\n')
        app_cli.chmod(0o755)
        is_file = Path.is_file
        with patch.object(install.sys, "platform", "darwin"), patch.object(Path, "is_file", autospec=True, side_effect=lambda path: False if path.is_relative_to("/Applications") else is_file(path)):
            status, output = self.run_installer("--only", "vscode")
        self.assertEqual(status, 0, output)
        self.assertIn(str(app_cli), self.log.read_text())

    def test_existing_vim_and_lua_init_receive_activation_and_later_disable_is_respected(self):
        self.executable("vim")
        self.executable("nvim")
        vimrc = self.home / ".vimrc"
        vimrc.write_text("set number\n")
        lua = self.home / "configuration/nvim/init.lua"
        lua.parent.mkdir(parents=True)
        lua.write_text("vim.g.personal_option = true\n")
        status, output = self.run_installer("--only", "vim", "nvim")
        self.assertEqual(status, 0, output)
        self.assertTrue(vimrc.read_text().startswith("set number\n"))
        self.assertIn('" >>> Ostadix syntax highlighting >>>\nfiletype on\nsyntax enable\n', vimrc.read_text())
        self.assertTrue(lua.read_text().startswith("vim.g.personal_option = true\n"))
        self.assertIn("-- >>> Ostadix syntax highlighting >>>\nvim.cmd('filetype on')\nvim.cmd('syntax enable')\n", lua.read_text())
        vimrc.write_text(vimrc.read_text() + "syntax off\n")
        lua.write_text(lua.read_text() + "vim.cmd('filetype off')\n")
        status, output = self.run_installer("--only", "vim", "nvim")
        self.assertEqual(status, 0, output)
        self.assertEqual(vimrc.read_text(), "set number\nsyntax off\n")
        self.assertEqual(lua.read_text(), "vim.g.personal_option = true\nvim.cmd('filetype off')\n")

    def test_vim_explicit_disable_and_environment_init_are_not_overridden(self):
        self.executable("vim")
        vimrc = self.home / ".vimrc"
        for content in ("syntax off\n", "filetype plugin indent off\n"):
            vimrc.write_text(content)
            status, output = self.run_installer("--only", "vim")
            self.assertEqual(status, 0, output)
            self.assertEqual(vimrc.read_text(), content)
        vimrc.write_text("set number\n")
        self.environment["VIMINIT"] = "source /custom/editor/init.vim"
        status, output = self.run_installer("--only", "vim")
        self.assertEqual(status, 0, output)
        self.assertEqual(vimrc.read_text(), "set number\n")
        self.assertIn("VIMINIT controls", output)

    def test_failure_in_one_code_editor_does_not_omit_other_available_editors(self):
        self.executable("code", "exit 7\n")
        self.executable("cursor")
        status, output = self.run_installer("--only", "vscode")
        self.assertEqual(status, 1, output)
        self.assertIn("cursor", self.log.read_text())

    def test_code_editors_sharing_multicall_launcher_are_each_installed(self):
        launcher = self.executable("multicall-editor-launcher")
        for name, _, _ in install.CODE_EDITORS:
            (self.bin / name).symlink_to(launcher)
        status, output = self.run_installer("--only", "vscode")
        self.assertEqual(status, 0, output)
        commands = self.log.read_text().splitlines()
        self.assertEqual(len(commands), 4)
        for name, _, _ in install.CODE_EDITORS:
            self.assertTrue(any(command.startswith(str(self.bin / name) + " ") for command in commands))

    def test_sublime_existing_profile_is_updated_without_creating_other_variants(self):
        packages = self.home / "configuration/sublime-text-3/Packages"
        packages.mkdir(parents=True)
        with tempfile.TemporaryDirectory() as temporary:
            assets = Path(temporary)
            (assets / "sublime").mkdir()
            (assets / "sublime/Ostadix.tmLanguage").write_text("<plist>fixture</plist>\n")
            with patch.object(install, "SOURCE", assets):
                status, output = self.run_installer("--only", "sublime")
        self.assertEqual(status, 0, output)
        self.assertEqual((packages / "Ostadix/Ostadix.tmLanguage").read_text(), "<plist>fixture</plist>\n")
        self.assertFalse((self.home / "configuration/sublime-text").exists())

    def test_textmate_export_is_importable_and_contains_all_repository_grammars(self):
        status, output = self.run_installer("--only", "textmate")
        self.assertEqual(status, 0, output)
        bundle = self.home / "data/ostadix/syntax/textmate/Ostadix.tmbundle"
        self.assertEqual(plistlib.loads((bundle / "info.plist").read_bytes())["name"], "Ostadix")
        grammar = plistlib.loads((bundle / "Syntaxes/Ostadix.tmLanguage").read_bytes())
        self.assertEqual(grammar["scopeName"], "source.ostadix")
        self.assertEqual(grammar["fileTypes"], ["O", "olang"])
        package = json.loads((ROOT / "vscode/package.json").read_text())
        expected = {json.loads((ROOT / "vscode" / item["path"]).read_text())["scopeName"] for item in package["contributes"]["grammars"]}
        actual = {plistlib.loads(path.read_bytes())["scopeName"] for path in (bundle / "Syntaxes").glob("*.tmLanguage")}
        self.assertEqual(actual, expected)
        self.assertTrue(any("html" in scope for scope in actual))
        self.assertTrue((bundle / "Vendor/NOTICE").is_file())
        self.assertTrue((bundle / "Vendor/manifest.json").is_file())
        for path in (bundle / "Syntaxes").glob("*.tmLanguage"):
            exported = plistlib.loads(path.read_bytes())
            if exported["scopeName"] != "source.ostadix":
                self.assertNotIn("fileTypes", exported)
                self.assertNotIn("firstLineMatch", exported)

    def test_vim_vendor_install_preserves_existing_personal_language_grammar(self):
        self.executable("vim")
        wat = self.home / ".vim/syntax/wat.vim"
        wat.parent.mkdir(parents=True)
        wat.write_text('" personal WAT grammar\n')
        status, output = self.run_installer("--only", "vim")
        self.assertEqual(status, 0, output)
        self.assertEqual(wat.read_text(), '" personal WAT grammar\n')
        self.assertIn("Preserving existing Vim language syntax", output)
        self.assertTrue((self.home / ".vim/syntax/ostadix.vim").is_file())

    @unittest.skipUnless(hasattr(os, "geteuid"), "Unix login-user handling")
    def test_root_install_drops_to_login_user_and_discards_root_xdg_paths(self):
        account = SimpleNamespace(pw_name="editor-user", pw_uid=12345, pw_gid=23456, pw_dir=str(self.home / "login home"))
        with patch.dict(os.environ, {"HOME": "/root", "SUDO_USER": "editor-user", "PATH": "/usr/bin", "XDG_CONFIG_HOME": "/root/config"}, clear=True), patch("os.geteuid", return_value=0), patch("pwd.getpwnam", return_value=account), patch("os.initgroups") as groups, patch("os.setgid") as gid, patch("os.setuid") as uid:
            self.assertTrue(install.use_login_user())
            self.assertEqual(os.environ["HOME"], account.pw_dir)
            self.assertEqual(os.environ["USER"], account.pw_name)
            self.assertNotIn("XDG_CONFIG_HOME", os.environ)
            groups.assert_called_once_with(account.pw_name, account.pw_gid)
            gid.assert_called_once_with(account.pw_gid)
            uid.assert_called_once_with(account.pw_uid)

    @unittest.skipUnless(hasattr(os, "geteuid"), "Unix login-user handling")
    def test_root_without_login_context_skips_instead_of_writing_root_profile(self):
        with patch.dict(os.environ, {"HOME": "/root", "PATH": "/usr/bin"}, clear=True), patch("os.geteuid", return_value=0), patch("os.setuid") as uid:
            self.assertFalse(install.use_login_user())
            uid.assert_not_called()


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
