# Ostadix-lang for VS Code

Extension `lostadi.ostadix-lang`, version 0.2.0, associates `.O` / `.olang`
files and O shebangs with **Ostadix-lang**. The repository syntax installer
installs it locally as part of setup. Reload VS Code after installation. No
separate language extensions, npm installation, compiler, or language server
are needed for coloring.

Every registered backend and alias uses its language's full maintained
TextMate grammar: Python, JavaScript, Bash, HTML, SQL, Rust, C++, C#, C, Java,
Ruby, Common Lisp, Racket, Nix, Markdown, LaTeX, Haskell, OCaml, WAT, MATLAB,
and Wolfram Language. `text` / `plain` intentionally remain plain text. Native
O statements apply to the document and `O` / `o` / `quote` bodies. `ubuntu_vm`
/ `ubuntu` use Bash; `nixos_test` uses Nix. Both native `lisp` and `common_lisp`
use Common Lisp. The legacy standalone `lisp_shim.py` runs Scheme; code meant
solely for that adapter requires manual Scheme mode selection.

The extension interprets O structure before the foreign grammar. Tags,
environments, attributes, matching closers, nested blocks, `$name` splices,
and O escapes therefore remain visible inside foreign strings and comments.
A closer must repeat the complete literal opener header, including its alias,
numeric spelling, and attribute spacing. Mismatched closers remain ordinary
foreign text. Nested blocks receive independent language states; the parent
string or comment resumes after the child, including children spanning lines.
Host comments suppress O structure through the newline.

VS Code's document token API supplies these **lexical classifications** and
is enabled for `ostadix` by default through
`editor.semanticHighlighting.enabled`. Its API name does not imply semantic
analysis: this extension does not validate programs, resolve symbols, infer
types, execute code, or predict syntax introduced by runtime splice values.
The active theme supplies colors through the original language scopes and
standard token classes; theme support determines the exact colors. Disabling
semantic highlighting leaves the full static TextMate overlay. That overlay
cannot preserve an ancestor's exact header context inside every foreign
string, comment, or `begin` / `while` context, and line-anchored rules see
the actual O document column on a same-line opener; the enabled token provider
handles that O-specific context in VS Code. Editors using only the static
assets retain this limitation.

All 21 foreign code grammars and their available embedded grammar dependencies
are bundled offline: 81 pinned upstream assets, exact source revisions,
SHA-256 checksums, and licenses in [vendor/manifest.json](vendor/manifest.json),
[vendor/NOTICE](vendor/NOTICE), and [vendor/LICENSE](vendor/LICENSE).
The manifest explicitly lists optional upstream snippet includes for which no
grammar is bundled, such as ARM assembly, Asymptote, Slim, and YANG. Those
optional subregions have their enclosing grammar's coloring. They do not
replace any registered backend grammar. The declared upstream injections, including Markdown Nix fences, are enabled
and the actual C++ macro fragment grammar is included. Scope aliases and the extracted
JavaScript regexp repository are documented in the same inventory. The
bundled Microsoft TextMate / Oniguruma JS and WASM tokenizer has its own
[version and checksum inventory](runtime/manifest.json) and license files.
There are no downloads or external runtime dependencies during editing.

VS Code filename associations are case insensitive and may also select this
language for textual `.o` files. Choose **Plain Text** for object files or
adjust your own associations when needed.

## Maintaining and testing

Edit `generate.mjs`, `scanner.cjs`, `tokenizer.cjs`, or `extension.cjs`, then run:

```sh
node tools/syntax/vscode/generate.mjs
node tools/syntax/vscode/test.mjs
```

Generation reads the shared `tools/syntax/languages.json`, verifies every
pinned grammar checksum, and writes the O-aware grammar assets, package
contributions, language map copy, and lexical token scope inventory. The
`contributes.grammars` paths form the complete static asset inventory for
VSIX packaging and Sublime / TextMate export. Foreign scopes are renamed in
the static overlay to avoid replacing other extensions' standalone grammars;
the runtime provider uses the untouched original grammar assets.

The offline tests use the bundled real VS Code TextMate / Oniguruma engine.
They exercise all 36 tags and exact header forms, mismatched closer strings,
multiline nesting, comments, escapes, Unicode offsets, full language-specific
constructs, optional dependency inventory, all bundled checksums, and the
provider's nonoverlapping tokens, version cache, and cancellation behavior.
An extension-host smoke test separately verifies registration and token
commands inside VS Code; packaged VSIX tests verify the offline dependency
closure is included.

For an optional Linux desktop check in a disposable VS Code profile:

```sh
syntax_test_dir=$(mktemp -d)
export OSTADIX_HOST_SOURCE="$syntax_test_dir/nested.O"
export OSTADIX_HOST_REPORT="$syntax_test_dir/provider.json"
export OSTADIX_HOST_COLOR_REPORT="$syntax_test_dir/colors.json"
export OSTADIX_HOST_HOLD=25000
code --user-data-dir "$syntax_test_dir/profile" \
  --extensions-dir "$syntax_test_dir/extensions" \
  --extensionDevelopmentPath="$PWD/tools/syntax/vscode" \
  --extensionTestsPath="$PWD/tools/syntax/vscode/tests/extension-host.cjs" \
  --remote-debugging-port=9237 --disable-workspace-trust \
  --skip-welcome --skip-release-notes &
node tools/syntax/vscode/tests/render-colors.mjs
wait
cat "$OSTADIX_HOST_REPORT" "$OSTADIX_HOST_COLOR_REPORT"
```

This needs a graphical session and a theme with distinct string and keyword
colors. The local debugger is used only for this disposable test window;
`OSTADIX_HOST_DEBUG_PORT` changes the probe's port if the launch flag is changed.
The provider check verifies activation, actual editor token commands, nested
language restoration, mismatched closers, heredocs, and edit invalidation. The
renderer check waits for asynchronous coloring and compares the Python string
before/after nested Common Lisp with the Lisp keyword and Bash heredoc colors.
Both checks assert their results and write JSON evidence. They are excluded from
the installed VSIX.

The contribution points follow the official
[syntax highlighting guide](https://code.visualstudio.com/api/language-extensions/syntax-highlight-guide)
and [document token guide](https://code.visualstudio.com/api/language-extensions/semantic-highlight-guide).
OCaml uses the pinned [OCaml Platform](https://github.com/ocamllabs/vscode-ocaml-platform)
grammars and their bundled ISC license. Other pinned grammars come from the
[Shiki TextMate grammar collection](https://github.com/shikijs/textmate-grammars-themes)
and the original projects identified in the manifest.
