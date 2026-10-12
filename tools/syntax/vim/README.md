# Vim and Neovim Ostadix syntax

The runtime detects `.O` and `.olang` files and delegates each foreign body to
the corresponding native Vim syntax. Recursive O regions restore their parent's
grammar and lexical state, including when a child begins inside a foreign comment
or string. Exact opener headers determine closer matching. Escapes, splices, and
host comments are included in the structural grammar.

The language routing is generated from `../languages.json`. Every catalog family
has a native route; plain text has no foreign syntax. Native grammar availability
is reported in buffer variables `b:ostadix_missing_syntax` and
`b:ostadix_fallback_syntax`. Older Vim runtimes lacking Racket may use Scheme
lexical highlighting, and missing grammars get a visibly reported lexical
fallback. The Vim 9.1 runtime used by the engine tests has no missing grammars or
fallbacks after installing the bundled WAT syntax.

`syntax/wat.vim` is an unchanged MIT-licensed source from
[rhysd/vim-wasm](https://github.com/rhysd/vim-wasm). Its exact commit and source
hashes are recorded in [vendor/provenance.json](vendor/provenance.json), and the
original license is retained in [vendor/LICENSE-wat](vendor/LICENSE-wat).
An existing user WAT syntax should take precedence during installation.

Regenerate the Ostadix syntax after editing its template or the shared mapping:

```sh
python3 tools/syntax/editors/generate.py write
python3 tools/syntax/editors/test_editors.py
```

The real engine test checks all catalog tags, five environment/attribute forms,
exact closer matching, native tokens, children inside comments/strings, and
parent restoration. Set `OSTADIX_VIM` to select a test executable.
