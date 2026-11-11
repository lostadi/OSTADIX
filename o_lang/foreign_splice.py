"""Reference-edition source-splice contract v1.

Bounded lexical guards, not guest parsing, admission or effect confinement.
No guest interpreter is imported to validate an O document.
"""
from __future__ import annotations

import json
import math

SPLICE_CONTRACT_VERSION = 1
PRESENTATION = {"text", "plain", "html", "markdown", "md", "latex", "tex", "O", "o", "quote"}
PROFILES = {"python": "python", "py": "python", "sql": "sql", "bash": "shell", "shell": "shell",
            "javascript": "javascript", "nix": "nix", "nix_expr": "nix", "nix_store": "nix", "nixos_test": "nix"}


def validate_segments(language, segments):
    """Validate (text|value|code, text) segments before evaluating any child."""
    if language in PRESENTATION:
        return
    profile = PROFILES.get(language)
    source, holes = [], {}
    for kind, text in segments:
        if kind == "text":
            source.extend(text)
        else:
            holes[len(source)] = kind
            source.append(" ")
    state, quote, triple, escape, doubled = "code", "", False, False, False
    cursor, dynamic = 0, False
    identifier = lambda c: c.isalnum() or c in "_$" or not c.isascii() and not c.isspace()
    while cursor < len(source):
        if cursor in holes:
            if holes[cursor] == "code":
                dynamic = True
            elif (profile is None or dynamic or state != "code"
                  or cursor and identifier(source[cursor - 1])
                  or cursor + 1 < len(source) and identifier(source[cursor + 1])):
                raise ValueError(f"foreign value splice in `{language}` rejected: string/comment, token adjacency, unsupported lexical profile/form or preceding dynamic code; use an unquoted value hole, native ${{name}}, or explicit $!name code")
            cursor += 1
            continue
        ch = source[cursor]
        nxt = source[cursor + 1] if cursor + 1 < len(source) else ""
        tail = "".join(source[cursor:cursor + 4])
        if state == "line":
            if ch == "\n": state = "code"
        elif state == "block":
            if ch == "*" and nxt == "/": state, cursor = "code", cursor + 1
        elif state == "quote":
            if (profile in {"nix", "javascript"} and ch == "$" and nxt == "{"
                or profile == "shell" and (ch == "`" or ch == "$" and nxt == "(")):
                state = "unsupported"
            elif profile == "shell" and ch == "$" and nxt == "{":
                end = _simple_parameter_end(source, cursor)
                if end is None: state = "unsupported"
                else: cursor = end
            elif profile == "shell" and escape and ch == "\\" and nxt == "\n":
                state = "unsupported"
            elif escape and ch == "\\":
                if cursor + 1 not in holes and nxt: cursor += 1
            elif ch == quote:
                if triple:
                    if source[cursor:cursor + 3] == [quote] * 3: state, cursor = "code", cursor + 2
                elif doubled and nxt == quote: cursor += 1
                else: state = "code"
        elif state == "code":
            if profile == "javascript" and (tail.startswith("<!--") or tail.startswith("-->") or tail.startswith("#!")):
                state = "line"
            elif profile in {"python", "javascript"} and ch == "\\": state = "unsupported"
            elif profile == "nix" and (ch == "/" and nxt != "*" or ch == "<"): state = "unsupported"
            elif profile == "shell" and ch == "$" and nxt == "{":
                end = _simple_parameter_end(source, cursor)
                if end is None: state = "unsupported"
                else: cursor = end
            elif profile == "shell" and ch == "$" and nxt == "'":
                # Only an active dollar introduces ANSI-C quoting. Escaped
                # dollars and the consumed native $$ parameter do not.
                state, quote, triple, escape, doubled = "quote" if language == "bash" else "unsupported", "'", False, True, False
                cursor += 1
            elif profile == "shell" and ch == "$" and nxt == "$":
                cursor += 1
            elif profile == "shell" and (ch == "$" and nxt == "(" or ch == "(" and nxt == "(" or ch == "[" and (nxt == "[" or cursor and identifier(source[cursor - 1]))):
                state = "unsupported"
            elif profile == "shell" and ch == "#":
                state = "line" if _shell_comment_start(source, cursor, holes) else "unsupported"
            elif profile in {"python", "nix"} and ch == "#": state = "line"
            elif profile == "sql" and ch == "-" and nxt == "-" or profile == "javascript" and ch == "/" and nxt == "/":
                state, cursor = "line", cursor + 1
            elif profile in {"sql", "javascript", "nix"} and ch == "/" and nxt == "*":
                state, cursor = "block", cursor + 1
            elif profile == "javascript" and ch == "/" or profile == "shell" and ch == "<" and nxt == "<" or profile == "nix" and ch == "'" and nxt == "'":
                state = "unsupported"
            elif ch in "'\"" or profile in {"javascript", "shell"} and ch == "`" or profile == "sql" and ch in "`[":
                if profile == "python" and (cursor and source[cursor - 1] in "fFtT" or cursor > 1 and source[cursor - 1] in "rR" and source[cursor - 2] in "fFtT"):
                    state = "unsupported"
                else:
                    triple = profile == "python" and source[cursor:cursor + 3] == [ch] * 3
                    escape = profile != "sql" and (profile != "shell" or ch != "'")
                    doubled, quote, state = profile == "sql" and ch != "[", "]" if ch == "[" else ch, "quote"
                    if triple: cursor += 2
            elif profile == "shell" and ch == "\\":
                if nxt == "\n" or cursor + 1 in holes: state = "unsupported"
                elif nxt: cursor += 1
        cursor += 1


def _shell_comment_start(source, cursor, holes):
    if cursor == 0: return True
    if cursor - 1 in holes or source[cursor - 1] not in " \t\n": return False
    start = cursor - 1
    while start and source[start - 1] == "\\": start -= 1
    return (cursor - 1 - start) % 2 == 0


def _simple_parameter_end(source, start):
    pos = start + 2
    if pos >= len(source) or not (source[pos].isascii() and (source[pos].isalpha() or source[pos] == "_")): return None
    pos += 1
    while pos < len(source) and source[pos].isascii() and (source[pos].isalnum() or source[pos] == "_"): pos += 1
    return pos if pos < len(source) and source[pos] == "}" else None


def render_literal(language, value, presentation_renderer=None):
    from .ovalue import ONull, OBool, OInt, OFloat, OList, OMap, OStr, to_python, render_plain
    if language in PRESENTATION:
        if presentation_renderer is None: raise ValueError("presentation renderer is required")
        return presentation_renderer(value)
    validate_value_shape(value)
    profile = PROFILES.get(language)
    text = render_plain(value)
    if profile == "python": return repr(to_python(value))
    if profile == "shell":
        if "\0" in text: raise ValueError("shell value contains NUL")
        return "'" + text.replace("'", "'\\''") + "'"
    if profile == "sql":
        if isinstance(value, ONull): return "NULL"
        if isinstance(value, OBool): return "1" if value.value else "0"
        if isinstance(value, OInt) or isinstance(value, OFloat) and math.isfinite(value.value): return repr(value.value)
        if "\0" in text or "\r" in text: return "CAST(X'" + text.encode().hex() + "' AS TEXT)"
        return "'" + text.replace("'", "''") + "'"
    if profile == "javascript":
        if isinstance(value, ONull): return "null"
        if isinstance(value, OBool): return "true" if value.value else "false"
        if isinstance(value, OInt) or isinstance(value, OFloat) and math.isfinite(value.value): return repr(value.value)
        if isinstance(value, OList): return "[" + ",".join(render_literal(language, x) for x in value.items) + "]"
        if isinstance(value, OMap): return "({" + ",".join("[" + json.dumps(k) + "]:" + render_literal(language, v) for k, v in sorted(value.pairs)) + "})"
        return json.dumps(text, ensure_ascii=True)
    if profile == "nix":
        if isinstance(value, ONull): return "null"
        if isinstance(value, OBool): return "true" if value.value else "false"
        if isinstance(value, OInt) and -(1 << 63) <= value.value < (1 << 63): return str(value.value)
        if isinstance(value, OFloat) and math.isfinite(value.value): return repr(value.value)
        if isinstance(value, OList): return "[ " + " ".join("(" + render_literal(language, x) + ")" for x in value.items) + " ]"
        if isinstance(value, OMap): return "{ " + " ".join(_nix_text(k) + " = " + render_literal(language, v) + ";" for k, v in sorted(value.pairs)) + " }"
        return _nix_text(text)
    raise ValueError(f"backend `{language}` has no declared literal renderer; explicit $!name code is required")


def validate_value_shape(value):
    """Reference values carry plain payloads, never user-defined repr code."""
    from .ovalue import ONull, OBool, OInt, OFloat, OList, OMap, OStr, OHtml, OStorePath, OBlob, OScope, OExpr
    kind = type(value)
    expected = {OBool: bool, OInt: int, OFloat: float, OStr: str, OHtml: str}
    if kind in expected:
        if type(value.value) is not expected[kind]: raise ValueError("noncanonical OValue payload cannot be rendered as guest source")
    elif kind is OStorePath:
        if type(value.path) is not str: raise ValueError("noncanonical store path payload")
    elif kind is OBlob:
        if type(value.data) is not bytes or type(value.mime) is not str: raise ValueError("noncanonical blob payload")
    elif kind is OList:
        if type(value.items) not in (tuple, list): raise ValueError("noncanonical list payload")
        for item in value.items: validate_value_shape(item)
    elif kind in (OMap, OScope):
        if type(value.pairs) not in (tuple, list): raise ValueError("noncanonical map payload")
        for key, item in value.pairs:
            if type(key) is not str: raise ValueError("noncanonical map key")
            validate_value_shape(item)
    elif kind is OExpr:
        raise ValueError("Expr requires contextual quote/eval or an explicit code splice")
    elif kind is not ONull:
        raise ValueError("noncanonical OValue family cannot be rendered as guest source")


def _nix_text(text):
    if "\0" in text: raise ValueError("reference Nix literal profile does not support NUL text")
    # JSON's arbitrary \u escapes are not Nix string escapes.
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("${", "\\${").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"'


def render_explicit_code(value):
    from .ovalue import OStr, OExpr
    if type(value) is OStr:
        validate_value_shape(value)
        return value.value
    if isinstance(value, OExpr):
        from .parser import reconstruct_source
        return reconstruct_source(value.ast)
    raise ValueError("explicit code splice requires source Text or Expr")
