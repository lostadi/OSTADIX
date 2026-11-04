"""Behavioral checks for safe, repeatable VS Code run configuration."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, SOURCE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


settings = load("vscode_settings_tested", "vscode_settings.py")
install = load("syntax_install_tested", "install.py")


class SettingsTests(unittest.TestCase):
    def test_jsonc_comments_custom_settings_and_other_launches_survive(self):
        original = '''{
  // My editor preferences
  "editor.fontFamily": "FiraCode Variable",
  "url": "https://example.com/*not-a-comment*/",
  "launch": {
    "version": "0.2.0",
    "compounds": [{"name": "Together", "configurations": ["Custom"]}],
    "configurations": [
      // Leave this launch exactly as it is.
      { "name": "Custom", "type": "python", "request": "launch", "program": "${file}" },
    ],
  },
  "code-runner.executorMap": { "python": "python3 -u", /* preserve */ },
  "code-runner.executorMapByFileExtension": {".rs": "cargo run"},
}
'''
        updated = settings.configure_settings(original, Path("/repo"))
        parsed = settings.parse_jsonc(updated).value
        self.assertIn('// My editor preferences', updated)
        self.assertIn('// Leave this launch exactly as it is.', updated)
        self.assertIn('{ "name": "Custom", "type": "python", "request": "launch", "program": "${file}" }', updated)
        self.assertIn('"python": "python3 -u", /* preserve */', updated)
        self.assertEqual(parsed["launch"]["compounds"], [{"name": "Together", "configurations": ["Custom"]}])
        self.assertEqual(parsed["code-runner.executorMapByFileExtension"][".rs"], "cargo run")
        self.assertEqual(len(parsed["launch"]["configurations"]), 2)
        self.assertEqual(updated, settings.configure_settings(updated, Path("/repo")))

    def test_existing_managed_launch_updates_in_place_without_losing_custom_fields(self):
        original = '''{
  "launch": {"configurations": [
    {"name": "Before", "type": "python"},
    {"name": "Ostadix: Run Current File", "command": "old", "presentation": {"order": 2},
     "env": { /* user override */ "CUSTOM": "kept", "OSTADIX_VSCODE_FILE": "old"}},
    {"name": "After", "type": "cppdbg"}
  ]}
}'''
        updated = settings.configure_settings(original, Path("/new repo"))
        runs = settings.parse_jsonc(updated).value["launch"]["configurations"]
        self.assertEqual([run["name"] for run in runs], ["Before", settings.RUN_NAME, "After"])
        self.assertEqual(runs[1]["presentation"], {"order": 2})
        self.assertEqual(runs[1]["env"], {"CUSTOM": "kept", "OSTADIX_VSCODE_FILE": "${file}"})
        self.assertIn('/* user override */', updated)
        self.assertIn("/new repo/target/release/O", runs[1]["command"])
        self.assertTrue(runs[1]["noDebug"])
        self.assertFalse(runs[1]["autoAttachChildProcesses"])
        self.assertEqual(runs[1]["internalConsoleOptions"], "neverOpen")
        self.assertEqual(updated, settings.configure_settings(updated, Path("/new repo")))

    def test_jsonc_container_shapes_and_trailing_comments(self):
        for source in ('{}', '\ufeff{\r\n\t// BOM and CRLF\r\n}', '{/* hello */}', '{"launch":{"configurations":[]}}',
                       '{"a":1 // trailing comment\n}', '{"a":1, /* trailing comma */}',
                       '{"a": [1, true, null, {"b":"\\\""},],}'):
            with self.subTest(source=source):
                once = settings.configure_settings(source, Path("/repo"))
                self.assertEqual(settings.parse_jsonc(once).value["launch"]["configurations"][0]["name"], settings.RUN_NAME)
                self.assertEqual(once, settings.configure_settings(once, Path("/repo")))

    def test_invalid_or_ambiguous_config_is_rejected_without_writing(self):
        invalid = ('{"a": ', '{"a":1 "b":2}', '{"a":1,"a":2}', '[]',
                   '{"launch":false}', '{"launch":{"configurations":{}}}',
                   '{"code-runner.executorMap":"custom"}',
                   '{"launch":{"configurations":[{"name":"Ostadix: Run Current File"},{"name":"Ostadix: Run Current File"}]}}')
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            instance = install.Installer()
            instance.home, instance.config = home, home / "config"
            target = settings.settings_path("Visual Studio Code", "/bin/code", home, instance.config)
            target.parent.mkdir(parents=True)
            for original in invalid:
                with self.subTest(original=original):
                    target.write_text(original)
                    with self.assertRaises(ValueError), patch.object(instance, "write") as writer:
                        settings.install_settings(instance, "Visual Studio Code", "/bin/code", home / "repo")
                    writer.assert_not_called()
                    self.assertEqual(target.read_text(), original)

    def test_code_runner_has_both_language_and_extension_paths(self):
        parsed = settings.parse_jsonc(settings.configure_settings("", Path("/repo"))).value
        command = parsed["code-runner.executorMap"]["ostadix"]
        self.assertIn(" $fullFileName ", command)
        self.assertNotIn('"$fullFileName"', command)
        for extension in (".O", ".olang"):
            self.assertEqual(parsed["code-runner.executorMapByFileExtension"][extension], command)
        for key in ("fileDirectoryAsCwd", "saveFileBeforeRun", "runInTerminal", "showRunIconInEditorTitleMenu"):
            self.assertTrue(parsed["code-runner." + key])

    def test_explicit_code_runner_preferences_are_preserved(self):
        original = {"code-runner." + key: False for key in ("fileDirectoryAsCwd", "saveFileBeforeRun", "runInTerminal", "showRunIconInEditorTitleMenu")}
        parsed = settings.parse_jsonc(settings.configure_settings(json.dumps(original), Path("/repo"))).value
        for key, value in original.items():
            self.assertEqual(parsed[key], value)

    @unittest.skipIf(sys.platform == "win32", "POSIX launch command")
    def test_real_launch_handles_shell_characters_and_clears_inspector_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "repo with spaces ' $literal `chars`"
            runtime = root / "target/release/O"
            runtime.parent.mkdir(parents=True)
            runtime.write_text(f"#!{sys.executable}\nimport json, os, sys\nprint(json.dumps([sys.argv[1:], {{key: os.environ.get(key) for key in ('O_LANG_ROOT', 'O_BACKENDS_DIR', 'NODE_OPTIONS', 'VSCODE_INSPECTOR_OPTIONS')}}]))\n")
            runtime.chmod(0o755)
            file = root / 'program \' " $() `ticks` $HOME.O'
            parsed = settings.parse_jsonc(settings.configure_settings("{}", root)).value
            run = parsed["launch"]["configurations"][0]
            environment = dict(os.environ, OSTADIX_VSCODE_FILE=str(file), O_LANG_ROOT="wrong-root", O_BACKENDS_DIR="wrong-backends", NODE_OPTIONS="--require missing.js", VSCODE_INSPECTOR_OPTIONS="injected")
            result = subprocess.run(["/bin/sh", "-c", run["command"]], env=environment, text=True, capture_output=True, check=True)
            arguments, received = json.loads(result.stdout)
            self.assertEqual(arguments, [str(file), str(root / "backends")])
            self.assertEqual(received, {"O_LANG_ROOT": str(root), "O_BACKENDS_DIR": str(root / "backends"), "NODE_OPTIONS": None, "VSCODE_INSPECTOR_OPTIONS": None})

    def test_default_settings_paths_and_portable_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            for label, directory in settings.EDITOR_DIRECTORIES.items():
                for platform, expected in (("darwin", home / "Library/Application Support"), ("linux", home / "config"), ("win32", home / "roaming")):
                    with self.subTest(label=label, platform=platform):
                        actual = settings.settings_path(label, str(home / "bin/editor"), home, home / "config", platform=platform, environ={"APPDATA": str(home / "roaming")})
                        self.assertEqual(actual, expected / directory / "User/settings.json")
            portable = home / "portable"
            path = settings.settings_path("Visual Studio Code", "/bin/code", home, home / "config", environ={"VSCODE_PORTABLE": str(portable)})
            self.assertEqual(path, portable / "user-data/User/settings.json")
            (home / "archive/data").mkdir(parents=True)
            path = settings.settings_path("Visual Studio Code", str(home / "archive/bin/code"), home, home / "config", platform="linux", environ={})
            self.assertEqual(path, (home / "archive/data/user-data/User/settings.json").resolve())

    def test_install_uses_backup_and_is_idempotent_and_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            instance = install.Installer()
            instance.home, instance.config, instance.backups = home, home / "config", home / "backups"
            target = settings.settings_path("Visual Studio Code", "/bin/code", home, instance.config)
            target.parent.mkdir(parents=True)
            original = '{\r\n  /* preference */ "editor.fontSize": 15,\r\n}\r\n'
            target.write_bytes(original.encode())
            with contextlib.redirect_stdout(io.StringIO()):
                settings.install_settings(instance, "Visual Studio Code", "/bin/code", home / "repo")
                first = target.read_bytes()
                backup = next(instance.backups.rglob("settings.json"))
                self.assertEqual(backup.read_bytes(), original.encode())
                self.assertTrue(first.startswith(b'{\r\n  /* preference */ "editor.fontSize": 15,\r\n'))
                settings.install_settings(instance, "Visual Studio Code", "/bin/code", home / "repo")
                self.assertEqual(target.read_bytes(), first)
                self.assertEqual(backup.read_bytes(), original.encode())
                instance.dry_run = True
                settings.install_settings(instance, "Visual Studio Code", "/bin/code", home / "other-repo")
                self.assertEqual(target.read_bytes(), first)

    def test_windows_skips_run_settings_without_failure(self):
        instance = install.Installer()
        with patch.object(settings.sys, "platform", "win32"), patch.object(instance, "write") as writer, contextlib.redirect_stdout(io.StringIO()) as output:
            settings.install_settings(instance, "Visual Studio Code", "code.cmd", Path("/repo"))
        writer.assert_not_called()
        self.assertIn("POSIX shell", output.getvalue())


if __name__ == "__main__":
    unittest.main()
