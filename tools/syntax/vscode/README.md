# Ostadix-lang for VS Code

Declarative extension `lostadi.ostadix-lang`, version 0.1.0. Associates `.O` and
`.olang` sources and O shebangs with the **Ostadix-lang** language. No extension
host JavaScript, language server, compiler invocation, or runtime dependency.

Highlights evaluator tags, environments (`[7]`, `[*]`), block attributes,
matching block closers, nested evaluators, `$name` splices, O escapes, bindings,
and calls. Native O comments and statements apply only to the document and
`O` / `o` / `quote` blocks. The grammar follows the tags and aliases in
`crates/ostadix-api/src/backend_catalog.inc.rs` and delimiter rules in
`crates/ostadix-api/src/parser.rs`.

Python, JavaScript, shell, HTML, SQL, C-family languages, Ruby, Lisp, Nix,
Markdown, and LaTeX receive lightweight lexical highlighting. O nesting and
splices remain visible inside foreign strings and comments, because the O
parser processes these before the foreign evaluator. These lexical rules are
not complete grammars for those languages; heredocs, regex literals, and some
language-specific string forms receive basic highlighting. Remaining evaluator
bodies retain O structure and splice highlighting. This extension does not
validate programs or provide semantic analysis.

The opener's complete spelling (including alias, environment, and attribute
spacing) must be repeated in the closer. The grammar handles the parser's
different suffix rules for bare, environment, and attribute tags. Uppercase
`.O` is intentional; this extension does not declare `.o` object files. VS Code
file associations can be overridden explicitly by the user's settings.

Run the repository syntax installer to install locally. Reload VS Code after
installation, then open an `.O` file. The active editor theme supplies colors
through standard TextMate scopes; no theme changes are required.

## Maintaining the grammar

Edit `generate.mjs`, then run `node generate.mjs` to refresh the checked-in
`syntaxes/ostadix.tmLanguage.json`. `node test.mjs` verifies token scopes with
the real VS Code tokenizer, using its installed macOS application packages.
For other installations, set `VSCODE_APP_RESOURCES` to the application's
resources/app directory, or install `vscode-textmate` and `vscode-oniguruma` in
a temporary directory and set `OSTADIX_TEXTMATE_NODE_MODULES` to its
`node_modules` directory. These packages are test dependencies only.

The extension uses the declarative grammar and embedded-language contribution
points described in the [VS Code syntax highlighting guide](https://code.visualstudio.com/api/language-extensions/syntax-highlight-guide).
