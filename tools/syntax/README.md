# Ostadix-lang editor support

`setup.sh` and the platform launchers in `setup/` install `.O` and `.olang`
highlighting for supported editors found on the machine. This also runs with
`--minimal` and `--deps-only`. Editors themselves are not installed.
O-core `.oc` is a separate language.

## Install

```sh
./setup.sh -y --minimal
# Update editor support alone, without rebuilding O:
python3 tools/syntax/install.py
```

Supported automatic targets are VS Code, Code Insiders, Cursor, VSCodium,
GNU Nano, Vim, Neovim, Emacs, Sublime Text, and bat. Missing editors produce
`SKIP` messages. Failures are reported individually; setup continues with the
compiler installation. Run the standalone installer to diagnose an editor
installation failure.

```sh
python3 tools/syntax/install.py --check
python3 tools/syntax/install.py --dry-run
python3 tools/syntax/install.py --only vscode nano
./setup.sh --no-editor-support
# --no-syntax is an alias for --no-editor-support.
```

`--check` is read-only. `--dry-run` prints the intended actions without writing
configuration or launching extension installation. Setup passes its own check
and dry-run modes through to editor installation. Installation preserves other
settings, replaces only Ostadix's marked sections, and backs up changed files
under `$XDG_DATA_HOME/ostadix/syntax/backups/` (normally
`~/.local/share/ostadix/syntax/backups/`). It respects XDG paths and drops
sudo/doas privileges before changing the identified login user's editor files.
Running as root without an identified login user skips per-user installation.

The Code installer packages a local VSIX, installs it into each detected Code
variant, and needs no Marketplace account. Reload already-open editor windows.
An `.O` file's language mode should be **Ostadix-lang**. In Nano, reopen the
file; Vim, Neovim, and Emacs load the installed association on the next launch.
Explicit Vim/Neovim syntax disables and `VIMINIT` settings are preserved; these
configurations may require enabling filetype detection and syntax manually.

## Run O files in VS Code

On macOS and Linux, the Code-family installer also configures the editor's
user settings with **Ostadix: Run Current File**. Select it once in **Run and
Debug** or **Debug: Select and Start Debugging**, then use **F5** to run the
active saved `.O` or `.olang` file. Output appears in the integrated terminal.
The configuration also works when a file is open without a workspace folder.

This uses VS Code's built-in terminal launcher to execute O. It does not add
O-language breakpoints, variable inspection, or stepping. The terminal session
can remain open after the program exits; **Shift+F5** closes that launch session.

When Code Runner is installed, the same installer supplies its `ostadix`, `.O`,
and `.olang` executor mappings for **Run Code**. Code Runner is optional and is
not installed by this script. Avoid enabling two Code Runner extensions that
register the same commands. A workspace's own runner settings take precedence
over these user settings, so remove or update old workspace-specific paths if
they still select another checkout.
Use **Run and Debug** for filenames containing shell substitutions or quotes:
that action passes the filename through an environment variable, while Code
Runner substitutes filenames into a shell command using its own quoting.

The runtime and backend paths come from the checkout running the installer.
Running it from another checkout updates the managed launch to that checkout.
Build O with `setup.sh` before using the action; editor-only installation does
not build the runtime. Existing unrelated launch configurations, executor
mappings, JSONC comments, and trailing commas are preserved. Invalid settings
are reported without overwriting the file. The run configuration targets the
default user profile; separately configured profiles may need their own setup.
Windows retains syntax installation, with automatic execution configuration
reported as unsupported.

## Language selection

The shared [language routing map](languages.json) covers every registered
hosted backend and alias. Opening and closing O delimiters, environment indices,
attributes, escapes, and value splices retain O highlighting. Bodies select
their declared language, including Python, JavaScript, Bash, HTML, SQL, Rust,
C, C++, C#, Java, Ruby, Common Lisp, Racket, Nix, Markdown, LaTeX, Haskell,
OCaml, textual WebAssembly (WAT), MATLAB/Octave, and Wolfram Language.
`O`, `o`, and `quote` contain O syntax; `text` and `plain` contain plain text.

```O
O^(
python^(
def double(x):
    return x * 2
)_python
common_lisp^(
(defun double (x) (* x 2))
)_common_lisp
)_O
```

`ubuntu_vm`/`ubuntu` bodies are Bash scripts. `nixos_test` contains a Nix
attrset; a `testScript` string is handled as in a Nix file. Native O's `lisp`
backend executes Common Lisp. The standalone legacy `lisp_shim.py` executes
Scheme instead; code intended only for that adapter needs Scheme highlighting.
Binary WebAssembly is not text source and has no textual syntax highlighting.

## Editor behavior and limits

| Editor | Body highlighting |
| --- | --- |
| Code family | Bundled maintained TextMate grammars plus an O-aware token provider; independent body projections preserve the parent language across nested O blocks and splices. |
| Sublime Text / TextMate bundle | Exported O-aware TextMate grammars, including their foreign grammar dependencies. |
| Vim / Neovim | Recursive O regions include native language syntax files; a pinned WAT grammar provides a fallback on runtimes without one. |
| Emacs | An O scanner delegates each body to its language major mode; pinned modes and their Elisp dependencies fill the stock runtime gaps. |
| GNU Nano | Delimiters, splices, lexical accents, and distinct language body colors; Nano's regex engine cannot select and balance recursive foreign language grammars. |
| bat | Separate lexical rules for all registered language families, with recursive O markers; this is bounded lexical coloring. |

Highlighting does not validate or execute a program. Setup installs the bundled
Vim WAT grammar and Emacs mode dependencies offline, preserving existing user
grammars and packages. All language families were exercised with Vim 9.1 and
Emacs 30.2; older editor releases may not support every bundled mode and expose
missing-mode diagnostics with a lexical fallback. See the [Vim](vim/README.md) and [Emacs](emacs/README.md) notes for version
and provenance details. The Code extension
bundles its foreign grammars and tokenizer dependencies for offline installation. Static TextMate highlighting and Nano have limits that the Code
token provider can address; see the [Code extension documentation](vscode/README.md)
for tested behavior and grammar provenance.

Nano's line-oriented POSIX regular expressions cannot provide the same nested,
language-specific highlighting as Code. In particular, Nano cannot restore a
parent grammar after arbitrarily nested delimiters or restrict each keyword rule
to only its language body. Its configuration is installed automatically, but
these engine limits remain. See the [GNU Nano nanorc manual](https://www.nano-editor.org/dist/latest/nanorc.5.html).

For another TextMate-compatible IDE, export an importable bundle:

```sh
python3 tools/syntax/install.py --only textmate
```

The installer prints the bundle location. Import it through that editor's
TextMate bundle settings; unsupported IDEs are not silently configured.
[Sublime's syntax documentation](https://www.sublimetext.com/docs/syntax.html)
and [VS Code's syntax guide](https://code.visualstudio.com/api/language-extensions/syntax-highlight-guide)
describe their grammar interfaces.

## Optional terminal integration

The default install leaves shell `cat` behavior unchanged. To explicitly enable
O-aware terminal adapters:

```sh
python3 tools/syntax/install.py --only bat cat
```

`ocat` is installed in `~/.local/bin`. In zsh, the marked startup section loads
an interactive `cat` function for `.O`/`.olang` regular files when stdout is a
terminal. Other files, options, stdin, pipes, redirections, `NO_COLOR`, and dumb
terminals use system `cat`. The function replaces an existing interactive
`cat` alias/function when sourced; `command cat` bypasses it. Remove the marked
section and start a new shell to restore the previous behavior. These adapters
preserve the complete source bytes. Direct `bat` keeps its usual configuration.

bat's extension detection is case-insensitive and can also select Ostadix for
textual `.o` files. Use `bat --language='Plain Text' file.o` when needed.

## Development checks

```sh
python3 -m unittest discover -s tools/syntax -p 'test_*.py' -v
python3 tools/syntax/bat/generate.py --check
python3 tools/syntax/bat/check.py
python3 tools/syntax/sublime/generate.py --check
python3 -m unittest discover -s tools/syntax/editors -p test_editors.py -v
node tools/syntax/vscode/test.mjs
zsh -n tools/syntax/terminal/ostadix-cat.zsh
sh -n tools/syntax/terminal/ocat
```

Editor-specific engine checks and asset generation are documented in their
subdirectories. Check rendered tokens with the real engine: a successful syntax
cache build alone does not exercise regex/backreference behavior.

## Remove

Uninstall `lostadi.ostadix-lang` through the Code editor's extension UI. Remove
Ostadix's marked configuration sections and installed syntax assets from each
editor's user configuration directory. For bat, run `bat cache --build` after
removing its syntax. Backups retain the original settings.
