#!/usr/bin/env python3
"""Check generated assets and exercise available real editor engines."""
from __future__ import annotations

import json
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import tempfile
import termios
import time
import unittest

HERE = Path(__file__).resolve().parent
SYNTAX = HERE.parent
REPO = SYNTAX.parents[1]
LANGUAGES = json.loads((SYNTAX / "languages.json").read_text())["languages"]


def engine(name: str) -> str | None:
    return os.environ.get("OSTADIX_" + name.upper()) or shutil.which(name)


class GeneratedAssets(unittest.TestCase):
    def test_generated_assets_match_shared_mapping(self):
        subprocess.run(["python3", str(HERE / "generate.py"), "check"], check=True)

    def test_nano_region_coverage_and_documented_limits(self):
        syntax = (SYNTAX / "nano" / "ostadix.nanorc").read_text()
        for language in LANGUAGES:
            self.assertIn(f'# {language["key"]}: {", ".join(language["tags"])}', syntax)
        self.assertIn("cannot balance nested blocks", syntax)
        self.assertIn("cannot delegate a region", syntax)

    def test_vendored_source_and_license_bytes_match_provenance(self):
        for vendor in [SYNTAX / "emacs" / "vendor", SYNTAX / "vim" / "vendor"]:
            manifest = json.loads((vendor / "provenance.json").read_text())
            for package in manifest["packages"]:
                self.assertRegex(package["commit"], r"^[0-9a-f]{40}$")
                self.assertTrue(package["license"])
                base = vendor / package["name"] if vendor.parent.name == "emacs" else vendor
                for record in package["files"] + package.get("additionalFiles", []):
                    source = base / record["file"]
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), record["sha256"],
                                     str(source))


class NativeEditorEngines(unittest.TestCase):
    @unittest.skipUnless(engine("nano"), "Nano is unavailable; set OSTADIX_NANO to a test executable")
    def test_nano_actual_pty_config_load_and_region_colors(self):
        with tempfile.TemporaryDirectory(prefix="ostadix-nano-test-") as directory:
            directory = Path(directory)
            source = directory / "sample.O"
            content = b"O^(\npython^(\n__ostadix_python_probe__ = 42\n)_python\ntext^(plain_probe)_text\n)_O\n"
            source.write_bytes(content)
            config = directory / "nanorc"
            config.write_text('include "' + str(SYNTAX / "nano" / "ostadix.nanorc") + '"\n')
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 120, 0, 0))
            env = os.environ.copy()
            env["TERM"] = "xterm-256color"
            process = subprocess.Popen([engine("nano"), "--rcfile", str(config), "--syntax", "ostadix",
                                        "--view", str(source)], stdin=slave, stdout=slave, stderr=slave, env=env)
            os.close(slave)
            output = b""
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and b"plain_probe" not in output:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            output += os.read(master, 65536)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            break
                os.write(master, b"\x18")  # Exit view mode; never write the source.
                process.wait(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)
            self.assertEqual(process.returncode, 0, output.decode(errors="replace"))
            self.assertNotIn(b"Error in", output)
            self.assertRegex(output, rb"\x1b\[33m__ostadix_python_probe__")
            self.assertRegex(output, rb"\x1b\[37mplain_probe")
            self.assertEqual(source.read_bytes(), content)

    @unittest.skipUnless(engine("emacs"), "Emacs is unavailable; set OSTADIX_EMACS to a test executable")
    def test_emacs_actual_fontification(self):
        env = os.environ.copy()
        env["OSTADIX_TEST_ROOT"] = str(REPO)
        args = [engine("emacs")]
        if os.environ.get("OSTADIX_EMACS_DUMP"):
            args += ["--dump-file", os.environ["OSTADIX_EMACS_DUMP"]]
        subprocess.run(args + ["--batch", "-Q", "-l", str(SYNTAX / "emacs" / "ostadix-mode.el"),
                               "-l", str(HERE / "test_emacs.el"), "-f", "ert-run-tests-batch-and-exit"],
                       check=True, env=env, timeout=90)

    @unittest.skipUnless(engine("vim"), "Vim is unavailable; set OSTADIX_VIM to a test executable")
    def test_vim_actual_recursive_regions_and_native_tokens(self):
        lines = ["O^("]
        checks = []
        for language in LANGUAGES:
            for tag in language["tags"]:
                for suffix in ["", "[*]", "[17]", "{process}", "[17]{process,cap=one[]:/a}"]:
                    header = tag + suffix
                    lines += [header + "^(", "probe_body", ")_" + header]
                    checks.append((len(lines) - 1, 1, language["key"]))
        lines += ["python[7]{process}^(", "def before():",
                  '  value = "rust^(fn child() {42})_rust"',
                  "  # sql^(SELECT 42)_sql", "  return 9",
                  ")_python[8]{process}", "def after_wrong_closer(): pass",
                  ")_python[7]{process}", "text^(outside)_text",
                  "# python^(comment_literal)_python $comment_var", ")_O"]
        tail = len(lines) - 10
        checks += [(tail + 2, 19, "rust"), (tail + 3, 11, "sql"),
                   (tail + 4, 3, "python"), (tail + 6, 5, "python"),
                   (tail + 8, 7, "text"), (tail + 9, 12, "host")]
        with tempfile.TemporaryDirectory(prefix="ostadix-vim-test-") as directory:
            directory = Path(directory)
            source = directory / "matrix.O"
            source.write_text("\n".join(lines) + "\n")
            result = directory / "result.json"
            script = directory / "test.vim"
            statements = ["set nocompatible", "set viminfo=", "set runtimepath^=" + str(SYNTAX / "vim"),
                          "syntax on", "edit " + str(source), "set syntax=ostadix",
                          "function! Family(line, column)",
                          "  let groups = map(synstack(a:line, a:column), 'synIDattr(v:val, \"name\")')",
                          "  call filter(groups, 'v:val =~# \"^ostadixBlock_\"')",
                          "  return empty(groups) ? '' : substitute(groups[-1], '^ostadixBlock_', '', '')",
                          "endfunction"]
            for line, column, expected in checks:
                statements.append(f"call assert_equal({json.dumps(expected)}, Family({line}, {column}), 'line {line}')")
            statements += [f"call assert_match('python', synIDattr(synID({tail + 1}, 1, 1), 'name'))",
                           f"call assert_match('rust', synIDattr(synID({tail + 2}, 19, 1), 'name'))",
                           f"call assert_match('sql', synIDattr(synID({tail + 3}, 11, 1), 'name'))",
                           "call writefile([json_encode({'errors': v:errors, 'missing': b:ostadix_missing_syntax, 'fallbacks': b:ostadix_fallback_syntax})], " + json.dumps(str(result)) + ")",
                           "qa!"]
            script.write_text("\n".join(statements) + "\n")
            subprocess.run([engine("vim"), "-Nu", "NONE", "-i", "NONE", "-n", "-es", "-S", str(script)],
                           check=True, timeout=90)
            evidence = json.loads(result.read_text())
            self.assertEqual(evidence["errors"], [])
            self.assertEqual(evidence["missing"], [])
            self.assertEqual(evidence["fallbacks"], [])
            print("Vim grammar availability:", evidence["missing"], "fallbacks:", evidence["fallbacks"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
