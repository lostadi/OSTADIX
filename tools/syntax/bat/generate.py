#!/usr/bin/env python3
"""Generate bat's bounded lexical grammar from the common language routing map."""

import argparse
import copy
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
LANGUAGES = json.loads((HERE.parent / "languages.json").read_text())["languages"]
WORDS = {
    "python": "and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield",
    "javascript": "async await break case catch class const continue debugger default delete do else export extends finally for from function if import in instanceof let new of return static super switch throw try typeof var void while yield",
    "shell": "case do done elif else esac fi for function if in select then time until while",
    "sql": "select from where insert into values update delete create drop table alter join left right inner outer on as and or not order by group having limit offset union all distinct set with is",
    "rust": "as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return self static struct super trait type unsafe use where while",
    "c": "auto break case const continue default do else enum extern for goto if inline register restrict return sizeof static struct switch typedef union volatile while",
    "cpp": "alignas alignof asm auto break case catch class concept const constexpr continue co_await co_return co_yield decltype default delete do else enum explicit export extern for friend if inline namespace new noexcept nullptr operator private protected public requires return sizeof static struct switch template this throw try typedef typename union using virtual volatile while",
    "csharp": "abstract as async await base break case catch class const continue default delegate do else enum event explicit extern finally fixed for foreach goto if implicit in interface internal is lock namespace new operator out override params private protected public readonly ref return sealed sizeof stackalloc static struct switch this throw try typeof unsafe using virtual void volatile while yield",
    "java": "abstract assert break case catch class const continue default do else enum extends final finally for if implements import instanceof interface native new package private protected public return static strictfp super switch synchronized this throw throws transient try volatile while",
    "ruby": "alias and begin break case class def defined do else elsif end ensure for if in module next not or redo rescue retry return self super then undef unless until when while yield",
    "lisp": "defun defvar defparameter defmacro defclass defmethod lambda let let* labels flet if cond case progn loop do dolist dotimes when unless quote function setf setq multiple-value-bind unwind-protect",
    "racket": "define define-values define-syntax define-syntax-rule lambda case-lambda let let* letrec if cond case begin begin0 quote quasiquote require provide module module+ struct match for for/list for/fold parameterize",
    "nix": "assert else if in inherit let or rec then with",
    "haskell": "case class data default deriving do else foreign hiding if import in infix infixl infixr instance let module newtype of qualified then type where",
    "ocaml": "and as assert begin class constraint do done downto else end exception external false for fun function functor if in include inherit initializer lazy let match method module mutable new nonrec object of open or private rec sig struct then to true try type val virtual when while with",
    "webassembly": "module func param result local global memory table import export start data elem type block loop if then else end call return drop select unreachable nop offset align",
    "matlab": "break case catch classdef continue else elseif end enumeration events for function global if methods otherwise parfor persistent properties return spmd switch try while",
    "mathematica": "Module Block With Function If Which Switch Do For While Table Return Break Continue Catch Throw Set SetDelayed Clear ClearAll Begin BeginPackage End EndPackage",
}
CONSTANTS = {
    "python": "True False None", "javascript": "true false null undefined NaN Infinity",
    "shell": "", "sql": "null true false", "rust": "true false Self", "c": "NULL true false",
    "cpp": "true false nullptr", "csharp": "true false null", "java": "true false null",
    "ruby": "true false nil", "lisp": "nil t", "racket": "", "nix": "true false null",
    "haskell": "True False Nothing Just", "ocaml": "true false None Some",
    "webassembly": "", "matlab": "true false NaN Inf pi", "mathematica": "True False Null Infinity Pi E I",
}


def generate():
    data = json.loads((HERE / "base.json").read_text())
    structural = data["contexts"]["structural"]
    foreign = structural.pop()
    data["contexts"].pop("foreign-code", None)
    data["variables"]["tag"] = "(?:" + "|".join(tag for row in LANGUAGES for tag in row["tags"]) + ")"
    boundary = r"{{header}}\^\(|\)_|\$|\\(?:{{header}}\^\(|\)_{{header}}|\$)"
    for row in LANGUAGES:
        key = row["key"]
        if key == "host":
            continue
        rule = copy.deepcopy(foreign)
        rule["match"] = "((" + "|".join(row["tags"]) + r")({{env}})?({{attrs}})?)(\^\()"
        rule["push"][0]["meta_scope"] = f"meta.embedded.block.{key}.ostadix"
        rule["push"][-1]["include"] = key
        structural.append(rule)
        patterns = [{"include": "structural"}]
        data["contexts"][key] = patterns
        if key == "text":
            continue
        comments = {"python": "#", "shell": "#", "ruby": "#", "nix": "#", "sql": "--",
                    "lisp": ";", "racket": ";", "haskell": "--", "matlab": "%", "latex": "%", "webassembly": ";;"}
        comment = comments.get(key)
        if comment:
            patterns.append({"match": comment + "(?:(?!" + boundary + ").)*", "scope": f"comment.line.{key}"})
        elif key in {"c", "cpp", "csharp", "java", "javascript", "rust"}:
            patterns.append({"match": "//(?:(?!" + boundary + ").)*", "scope": f"comment.line.{key}"})
        for begin, end in ({"nix": [(r"/\*", r"\*/")], "haskell": [(r"\{-", r"-\}")],
                           "ocaml": [(r"\(\*", r"\*\)")], "mathematica": [(r"\(\*", r"\*\)")],
                           "html": [("<!--", "-->")], "webassembly": [(r"\(;", r";\)")]}.get(key, [])
                           or ([(r"/\*", r"\*/")] if key in {"c", "cpp", "csharp", "java", "javascript", "rust", "sql"} else [])):
            patterns.append({"match": begin, "scope": f"punctuation.definition.comment.begin.{key}",
                             "push": [{"meta_scope": f"comment.block.{key}"}, {"match": end, "pop": True},
                                      {"match": r"(?=\)_{{header}})", "pop": True}, {"include": "structural"}]})
        # Reader apostrophes in Lisp are not string delimiters.
        quotes = ['"'] if key in {"lisp", "racket", "mathematica", "webassembly"} else ['"', "'"]
        for quote in quotes:
            patterns.append({"match": quote, "scope": f"punctuation.definition.string.begin.{key}",
                             "push": [{"meta_scope": f"string.quoted.{key}"}, {"match": quote, "pop": True},
                                      {"match": r"(?=\)_{{header}})", "pop": True}, {"include": "structural"},
                                      {"match": r"\\[^\n\\$]", "scope": "constant.character.escape"}]})
        words = WORDS.get(key, "").split()
        if words:
            prefix = "(?i)" if key == "sql" else ""
            patterns.append({"match": prefix + r"\b(?:" + "|".join(map(re.escape, words)) + r")\b", "scope": f"keyword.control.{key}"})
        constants = CONSTANTS.get(key, "").split()
        if constants:
            patterns.append({"match": ("(?i)" if key == "sql" else "") + r"\b(?:" + "|".join(constants) + r")\b", "scope": f"constant.language.{key}"})
        if key == "html":
            patterns.append({"match": r"(</?)([A-Za-z][A-Za-z0-9:-]*)([^>]*)(>)", "captures": {"1": "punctuation.definition.tag", "2": "entity.name.tag.html", "4": "punctuation.definition.tag"}})
        elif key == "markdown":
            patterns.append({"match": r"^#{1,6}(?=\s)", "scope": "markup.heading.markdown"})
        elif key == "latex":
            patterns.append({"match": r"\\[A-Za-z]+", "scope": "support.function.latex"})
        patterns.extend([{"match": r"\b(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|0[oO][0-7_]+|[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?)\b", "scope": "constant.numeric"},
                         {"match": r"[+*/%=<>!&|:-]+", "scope": "keyword.operator"}])
    # syntect expects numeric YAML capture keys. JSON's quoted keys silently
    # lose their capture scopes even though the syntax cache builds successfully.
    output = re.sub(r'(?m)^(\s*)"([0-9]+)":', r'\1\2:', json.dumps(data, indent=2))
    return "%YAML 1.2\n---\n# Generated by tools/syntax/bat/generate.py. Lexical coloring, not a foreign parser.\n" + output + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = HERE / "Ostadix.sublime-syntax"
    output = generate()
    if args.check:
        if path.read_text() != output:
            raise SystemExit("bat grammar is stale; run tools/syntax/bat/generate.py")
        print("PASS: bat grammar matches all registered language families")
    else:
        path.write_text(output)
