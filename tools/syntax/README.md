# Ostadix-lang syntax highlighting

Local highlighting for `.O` and `.olang` files in VS Code, bat, GNU nano,
and interactive zsh `cat`. These files cover hosted Ostadix orchestration;
O-core `.oc` is a separate language.

## Install

From the repository root:

```sh
# macOS dependencies (Apple's /usr/bin/nano may actually be Pico):
brew install bat nano
python3 tools/syntax/install.py
```

The VS Code `code` CLI must be on PATH. The installer builds a local VSIX using
Python's standard library and installs `lostadi.ostadix-lang`. No Marketplace
publication, account, runtime compilation, or npm dependencies are needed.
Run **Developer: Reload Window** in an already-open VS Code window if `.O`
files have not switched to **Ostadix-lang**.

Choose components when needed:

```sh
python3 tools/syntax/install.py --only bat nano cat
python3 tools/syntax/install.py --only vscode
```

Existing config files are preserved. The installer adds or replaces its own
marked section and saves changed originals under
`~/.local/share/ostadix/syntax/backups/` (or `$XDG_DATA_HOME/ostadix/syntax/backups/`).
It respects XDG configuration paths, Nano's user-config precedence, and zsh's
`ZDOTDIR`. Re-running installation updates the files without duplicating sections.

## Use

```sh
code examples/nested_splice.O
bat examples/nested_splice.O
nano examples/nested_splice.O
```

New zsh terminals load the `cat` integration automatically. For an existing
terminal, source the exact path printed by the installer (normally):

```sh
source ~/.config/ostadix/syntax/ostadix-cat.zsh
cat examples/nested_splice.O
ocat examples/nested_splice.O
```

`cat` is a zsh function that uses bat only when stdout is a terminal and all
arguments are `.O`/`.olang` regular files. Other files, options, stdin, pipes,
redirections, `NO_COLOR`, and dumb terminals use system `cat`. The function
replaces any pre-existing interactive `cat` alias/function after being sourced;
remove the marked `.zshrc` section and start a fresh shell to restore it.
`command cat` always bypasses this function.

`ocat` is also installed in `~/.local/bin` for use in other shells. It supports
bat's automatic language detection for other file types, with plain layout and
no pager; pipes and cat flags use system `cat`. These adapters ignore bat's
config options while highlighting, so options such as `--line-range` cannot
silently truncate a file. Direct `bat` keeps your usual configuration.

## Coverage and limits

The authoritative source is `crates/ostadix-api/src/parser.rs` and
`backend_catalog.inc.rs`. VS Code and bat distinguish evaluator tags,
`[number]`/`[*]` environments, attributes, exact corresponding closing tags,
nested blocks, escaped markers, `$name` splices, native `let`, calls, and comments.

Foreign-language coloring is a bounded lexical aid. O recognizes its own blocks
and splices even inside another language's strings/comments, so simply delegating
the entire body to a stock foreign grammar would conceal real O syntax. VS Code
has more detailed lexical rules for common languages; bat provides common
keyword/string/number accents. Neither is a full foreign-language parser,
diagnostic engine, or language server. Both use theme-standard scopes, including
dark themes already installed in your editor/terminal.

bat's extension fallback is case-insensitive, so it may also choose this grammar
for textual `.o` files. Use `bat --language='Plain Text' file.o` when needed.
The interactive `cat` adapter checks `.O` case-sensitively.

Nano uses line-oriented POSIX regular expressions. It highlights tokens but
cannot balance recursive blocks, check exact paired headers, or determine the
embedded language at every position. In particular, its comment/string colors
and tag recognition are approximations; use the runtime for validation.

Reference formats: [VS Code TextMate grammars](https://code.visualstudio.com/api/language-extensions/syntax-highlight-guide),
[bat custom syntaxes](https://github.com/sharkdp/bat#adding-new-syntaxes--language-definitions),
and [GNU nano nanorc](https://www.nano-editor.org/dist/latest/nanorc.5.html).

## Development checks

```sh
python3 -m unittest discover -s tools/syntax -p test_install.py -v
python3 tools/syntax/bat/check.py
node tools/syntax/vscode/test.mjs
zsh -n tools/syntax/terminal/ostadix-cat.zsh
sh -n tools/syntax/terminal/ocat
```

VS Code grammar generation and tokenization checks are documented in `vscode/`.
After editing the bat grammar, run `bat cache --build` and actually render
representative files with `bat --color=always --paging=never`; a successful cache
build alone does not exercise runtime regex/backreference behavior.

## Remove

Uninstall `lostadi.ostadix-lang` through VS Code or
`code --uninstall-extension lostadi.ostadix-lang`. Remove the marked sections
from your Nano config and `.zshrc`, the installed Ostadix syntax files under
bat/Nano's config directories, `~/.local/bin/ocat`, and the sourced
`ostadix-cat.zsh` file. Run `bat cache --build` and start a fresh shell.
Backups preserve the original settings if you need them.
