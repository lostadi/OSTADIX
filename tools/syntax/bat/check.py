#!/usr/bin/env python3
"""Exercise the installed bat engine using a temporary Ostadix syntax cache."""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]
SYNTAX = Path(__file__).with_name("Ostadix.sublime-syntax")
SGR = re.compile(rb"\x1b\[([0-9;]*)m")
FIXTURE = r"""let answer = python^(42)_python
python^(x )_python[*] y )_python
python[7]{ lazy,cap=fs.read }^( 12 )_python[7]{lazy,cap=fs.read} 34 )_python[7]{ lazy,cap=fs.read }
python^( html^( )_python )_html 7 )_python
python^( "value $answer and html^(inner)_html" # $answer )_python
python^( \)_python 9 \$answer )_python
python[*]^( 10 )_python[*]{lazy} 11 )_python[*]
python{lazy}^( 12 )_python{lazy}tail
python^( # \)_python 13 )_python
"""


def colored_bytes(output):
    """Return source bytes and each byte's active foreground/style SGR."""
    source = bytearray()
    colors = []
    color = b""
    for index, fragment in enumerate(SGR.split(output)):
        if index % 2:
            color = fragment
        else:
            source.extend(fragment)
            colors.extend([color] * len(fragment))
    return bytes(source), colors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bat", default=shutil.which("bat") or shutil.which("batcat"))
    args = parser.parse_args()
    if not args.bat:
        parser.error("bat or batcat must be installed")

    with tempfile.TemporaryDirectory(prefix="ostadix-bat-check-") as directory:
        directory = Path(directory)
        config = directory / "config"
        (config / "syntaxes").mkdir(parents=True)
        shutil.copyfile(SYNTAX, config / "syntaxes" / SYNTAX.name)
        environment = dict(os.environ, BAT_CONFIG_DIR=str(config),
                           BAT_CONFIG_PATH=str(config / "config"),
                           BAT_CACHE_PATH=str(directory / "cache"))
        environment.pop("NO_COLOR", None)

        def run(*arguments):
            result = subprocess.run([args.bat, *arguments], env=environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors="replace"))
            return result.stdout

        run("cache", "--build")
        assert b"Ostadix-lang:" in run("--list-languages")

        def render(path):
            output = run("--color=always", "--paging=never", "--style=plain",
                         "--theme=TwoDark", str(path))
            source, colors = colored_bytes(output)
            assert source == path.read_bytes(), f"Source bytes changed: {path.name}"
            assert colors and len(set(colors)) > 1, f"No highlighting: {path.name}"
            return colors

        sample = directory / "edges.O"
        sample.write_text(FIXTURE)
        colors = render(sample)
        lines = FIXTURE.splitlines(keepends=True)

        def color_at(line, token, occurrence=0):
            text = lines[line - 1]
            position = -1
            for _ in range(occurrence + 1):
                position = text.index(token, position + 1)
            return colors[sum(map(len, lines[:line - 1])) + position]

        closing = color_at(1, ")_python")
        assert color_at(2, ")_python[*]") != closing
        assert color_at(2, ")_python", 1) == closing
        assert color_at(3, ")_python[7]{lazy") != closing
        assert color_at(3, ")_python[7]{ lazy") == closing
        assert color_at(4, ")_python") != closing
        assert color_at(4, ")_html") == closing
        assert color_at(4, ")_python", 1) == closing
        assert color_at(5, ")_html") == closing
        assert color_at(5, "$answer") == color_at(5, "$answer", 1)
        assert color_at(6, ")_python") != closing
        assert color_at(6, ")_python", 1) == closing
        assert color_at(7, ")_python[*]{lazy}") != closing
        assert color_at(7, ")_python[*]", 1) == closing
        assert color_at(8, ")_python{lazy}") == closing
        assert color_at(9, ")_python") != closing
        assert color_at(9, ")_python", 1) == closing

        examples = ["nested_splice.O", "env_split.O", "lazy_defer_attrs_basic.O",
                    "bindings.O", "html_python_html.O", "python_html_python.O",
                    "coordination_groups.O"]
        for name in examples:
            render(ROOT / "examples" / name)
        sample = directory / "extension.olang"
        sample.write_text("python^(42)_python\n")
        render(sample)
        print("PASS: isolated bat cache, 9 structural edge cases, 7 repository examples,")
        print("      .O/.olang autodetection, ANSI colors, and source-byte preservation.")


if __name__ == "__main__":
    main()
