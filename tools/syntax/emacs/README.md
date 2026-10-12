# Emacs Ostadix mode

`ostadix-mode.el` colors `.O` and `.olang` files by parsing O delimiters first,
then fontifying each body with its native Emacs major mode. Nested blocks use
their own grammar, including blocks inside foreign strings and comments. The
parent's lexical state resumes after the child. Environment selectors,
attributes, aliases, escapes, splices, and O comments follow the shared language
catalog and the O delimiter rules.

The eight foreign modes absent from a standard Emacs installation are bundled
under `vendor/`: Rust, Racket, Nix, Markdown, Haskell, OCaml, WAT, and Wolfram.
The loader appends these source directories to `load-path` and creates autoloads
only for undefined modes. Existing packages, autoloads, and mode definitions take
precedence. Built-in modes supply the other languages; plain text retains plain
text coloring. MATLAB uses the built-in Octave grammar.

Fontification runs native mode initialization with mode hooks delayed and
deferred native compilation disabled. It does not start language runtimes,
evaluate foreign code, download packages, or invoke compiler subprocesses.
Interactive upstream REPL, formatter, debugger, and optional editor integrations
retain their own prerequisites and are not invoked by this mode.

Some bundled sources require at least Emacs 28.1; the complete native grammar
suite is validated with Emacs 30.2. Older Emacs versions can lack built-in modes.
If a mode is absent or its loading, initialization, or fontification fails,
`ostadix-missing-language-modes` lists it and a small lexical fallback is used.
`ostadix-language-mode-errors` records each mode's exact error message, or an
explicit absence message. Partial native coloring is cleared before fallback;
other bodies continue to receive their own coloring. Existing user modes retain
precedence even when they fail, and diagnostics refresh when the source changes.
Normal complete installations require no optional package download for coloring.

Each upstream file is copied without modification. [vendor/provenance.json](vendor/provenance.json)
records repository URLs, exact commit pins, source paths, licenses, and SHA-256
hashes. Original license notices are retained alongside each source bundle.
The Wolfram and reformatter sources grant their licenses in their original
headers; corresponding GNU license texts are supplied separately.

Regenerate the mode after changing the shared mapping or template:

```sh
python3 tools/syntax/editors/generate.py write
python3 tools/syntax/editors/test_editors.py
```

The real Emacs tests check every language's native tokens, all catalog tags and
header forms, nested lexical state, edits, mode failure recovery, user package precedence, and every
active example. Process and network guards verify that coloring runs offline
without executing programs. Set `OSTADIX_EMACS` to select a test engine and
`OSTADIX_EMACS_DUMP` only when an extracted distribution needs an explicit dump.
