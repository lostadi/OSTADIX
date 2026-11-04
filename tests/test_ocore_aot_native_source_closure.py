"""Check the literal Rust source dependency closure shipped in generated AOT.

This checks the source bundle, without building or qualifying an executable.
Dependencies come from the embedded Rust contents, not a second filename list.
"""
from pathlib import Path, PurePosixPath
import json
import posixpath
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/ostadix-api/src/api/aot_source.rs"
ARRAY = "RUNTIME_OCORE_NATIVE_SOURCES"
RAW_STRING = re.compile(r'(?:br|r)(#*)"')
CHARACTER = re.compile(r"'(?:\\.|[^'\\])'")
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


def rust_tokens(source):
    """Lex the literal subset used here; comments and string contents are inert."""
    result, index = [], 0
    while index < len(source):
        if source[index].isspace():
            index += 1
            continue
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            index += 2
            depth = 1
            while depth:
                if index >= len(source):
                    raise AssertionError("unterminated Rust block comment")
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            continue
        raw = RAW_STRING.match(source, index)
        if raw:
            start = raw.end()
            end = source.find('"' + raw[1], start)
            if end < 0:
                raise AssertionError("unterminated Rust raw string")
            result.append(("string", source[start:end]))
            index = end + 1 + len(raw[1])
            continue
        if source[index] == '"' or source.startswith('b"', index):
            start = index + int(source[index] == "b")
            end = start + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                elif source[end] == '"':
                    break
                else:
                    end += 1
            if end >= len(source):
                raise AssertionError("unterminated Rust string")
            # Source filenames use JSON-compatible Rust escapes. Unsupported
            # escape syntax is an explicit failed static check, never ignored.
            try:
                value = json.loads(source[start:end + 1])
            except ValueError:
                value = "<non-path Rust string>"
            result.append(("string", value))
            index = end + 1
            continue
        character = CHARACTER.match(source, index)
        if character:
            result.append(("character", character[0]))
            index = character.end()
            continue
        word = IDENTIFIER.match(source, index)
        if word:
            result.append(("word", word[0]))
            index = word.end()
        else:
            result.append(("punctuation", source[index]))
            index += 1
    return result


def runtime_tokens(source):
    """Generated runtime builds have cfg(test)=false; other cfgs stay visible."""
    tokens = rust_tokens(source)
    result, index = [], 0
    test_attribute = ["#", "[", "cfg", "(", "test", ")", "]"]
    while index < len(tokens):
        if [v for _, v in tokens[index:index + 7]] != test_attribute:
            result.append(tokens[index])
            index += 1
            continue
        index += 7
        depth, body = [], False
        while index < len(tokens):
            value = tokens[index][1]
            if value in {"(", "[", "{"}:
                if value == "{" and not depth:
                    body = True
                depth.append(value)
            elif value in {")", "]", "}"}:
                expected = {")":"(", "]":"[", "}":"{"}[value]
                if not depth or depth.pop() != expected:
                    raise AssertionError("unbalanced cfg(test) item")
                if not depth and body:
                    index += 1
                    break
            elif value == ";" and not depth:
                index += 1
                break
            index += 1
        else:
            raise AssertionError("unterminated cfg(test) item")
    return result


def embedded_native_sources(path=SOURCE):
    tokens = rust_tokens(path.read_text())
    positions = [i for i, token in enumerate(tokens) if token == ("word", ARRAY)]
    if len(positions) != 1:
        raise AssertionError("expected exactly one native runtime source array")
    index = positions[0]
    while tokens[index] != ("punctuation", "="):
        index += 1
    index += 1
    if tokens[index:index + 2] != [("punctuation", "&"), ("punctuation", "[")]:
        raise AssertionError("native runtime sources require a literal slice")
    index += 2
    files = {}
    while tokens[index] != ("punctuation", "]"):
        if tokens[index] != ("punctuation", "(") or tokens[index + 1][0] != "string":
            raise AssertionError("native source entry requires a literal output path")
        output = tokens[index + 1][1]
        if tokens[index + 2:index + 6] != [("punctuation", ","), ("word", "include_str"),
                                          ("punctuation", "!"), ("punctuation", "(")]:
            raise AssertionError("native source entry requires literal include_str!")
        if tokens[index + 6][0] != "string":
            raise AssertionError("dynamic source paths need explicit closure analysis")
        original = path.parent / tokens[index + 6][1]
        index += 7
        if tokens[index] == ("punctuation", ","):
            index += 1
        if tokens[index] != ("punctuation", ")"):
            raise AssertionError("unexpected include_str expression")
        index += 1
        if tokens[index] == ("punctuation", ","):
            index += 1
        if tokens[index] != ("punctuation", ")"):
            raise AssertionError("unexpected native source entry expression")
        index += 1
        if tokens[index] == ("punctuation", ","):
            index += 1
        normalized = posixpath.normpath(output)
        if normalized != output or PurePosixPath(output).is_absolute() or output.startswith("../"):
            raise AssertionError("native source output must stay within its emitted module directory")
        if output in files:
            raise AssertionError("duplicate native runtime output: " + output)
        files[output] = original.read_text()
    return files


def source_dependencies(name, source):
    tokens = runtime_tokens(source)
    dependencies, attributed_modules = [], set()
    values = [value for _, value in tokens]
    for index, token in enumerate(tokens):
        if token != ("word", "path") or index < 2 or values[index - 2:index] != ["#", "["]:
            continue
        if values[index + 1] != "=" or tokens[index + 2][0] != "string" or values[index + 3] != "]":
            raise AssertionError("nonliteral #[path] needs explicit closure analysis: " + name)
        position = index + 4
        if values[position] == "pub":
            position += 1
            if values[position] == "(":
                while values[position] != ")":
                    position += 1
                position += 1
        if values[position] != "mod" or tokens[position + 1][0] != "word" or values[position + 2] != ";":
            raise AssertionError("unsupported #[path] module form: " + name)
        attributed_modules.add(position)
        dependencies.append(("path-module", tokens[index + 2][1]))
    for index, token in enumerate(tokens):
        if token == ("word", "include") and values[index + 1:index + 3] == ["!", "("]:
            if tokens[index + 3][0] != "string" or values[index + 4] not in {",", ")"}:
                raise AssertionError("nonliteral include! needs explicit closure analysis: " + name)
            dependencies.append(("include", tokens[index + 3][1]))
        if (token == ("word", "mod") and index not in attributed_modules
                and index + 2 < len(tokens) and tokens[index + 1][0] == "word"
                and values[index + 2] == ";"):
            # The owned embedded native core uses explicit path attributes.
            # A new implicit external module must add its path resolution here,
            # rather than silently bypassing this closure proof.
            raise AssertionError("implicit external module needs explicit closure analysis: " + name + ":" + values[index + 1])
    return [(kind, posixpath.normpath(posixpath.join(posixpath.dirname(name), path)))
            for kind, path in dependencies]


def require_source_closure(files):
    if "mod.rs" not in files:
        raise AssertionError("generated native core has no module root")
    edges = []
    for name, source in files.items():
        for kind, dependency in source_dependencies(name, source):
            edges.append((name, kind, dependency))
            if dependency not in files:
                raise AssertionError(f"generated native source closure missing {dependency}: {name} references it via {kind}")
    return edges


class NativeAotSourceClosureTests(unittest.TestCase):
    def test_actual_generated_native_core_contains_every_referenced_source(self):
        edges = require_source_closure(embedded_native_sources())
        self.assertTrue(edges, "closure analysis discovered no real Rust dependencies")

    def test_nonlocal_control_source_is_required_by_generated_core(self):
        files = embedded_native_sources()
        edges = require_source_closure(files)
        self.assertIn(("mod.rs", "path-module", "native_nonlocal.rs"), edges)
        del files["native_nonlocal.rs"]
        with self.assertRaisesRegex(AssertionError, "missing native_nonlocal.rs"):
            require_source_closure(files)

    def test_vector_codegen_source_is_required_by_generated_core(self):
        files = embedded_native_sources()
        edges = require_source_closure(files)
        self.assertIn(("native_codegen.rs", "include", "native_vector_codegen.rs"), edges)
        del files["native_vector_codegen.rs"]
        self.assertNotIn("native_vector_codegen.rs", files)
        with self.assertRaisesRegex(AssertionError, "missing native_vector_codegen.rs"):
            require_source_closure(files)

    def test_machine_contract_sources_are_both_required_by_generated_core(self):
        files = embedded_native_sources()
        edges = require_source_closure(files)
        required = ("native_machine_ir.rs", "native_machine_verify.rs")
        for name in required:
            self.assertIn(name, files)
            self.assertIn(("mod.rs", "path-module", name), edges)
        for name in required:
            with self.subTest(source=name):
                missing = dict(files)
                del missing[name]
                self.assertNotIn(name, missing)
                other = next(candidate for candidate in required if candidate != name)
                self.assertIn(other, missing)
                reason = (f"generated native source closure missing {name}: "
                          "mod.rs references it via path-module")
                with self.assertRaisesRegex(AssertionError, "^" + re.escape(reason) + "$"):
                    require_source_closure(missing)

    def test_derived_child_dependency_detects_missing_file_without_a_filename_inventory(self):
        files = {
            "mod.rs": '#[path = "driver.rs"] pub mod driver;',
            "driver.rs": 'mod inline_child { include!("math.rs"); }',
            "math.rs": 'pub fn calculate() {}',
        }
        self.assertEqual(require_source_closure(files),
                         [("mod.rs", "path-module", "driver.rs"), ("driver.rs", "include", "math.rs")])
        del files["math.rs"]
        with self.assertRaisesRegex(AssertionError, "missing math.rs"):
            require_source_closure(files)

    def test_comments_literals_and_nested_comments_do_not_invent_dependencies(self):
        source = r'''
// include!("not-source.rs");
/* #[path="absent.rs"] mod absent; /* include!("nested-comment.rs"); */ */
const TEXT: &str = "include!(\"quoted.rs\");";
const RAW: &str = r##"#[path="raw.rs"] mod raw;"##;
fn f<'a>(s: &'a str) { let _ = ('x', s); }
'''
        self.assertEqual(require_source_closure({"mod.rs": source}), [])

    def test_runtime_excludes_only_test_items_and_keeps_other_cfg_dependencies(self):
        files = {
            "mod.rs": '\n'.join((
                '#[cfg(test)] #[path="test_only.rs"] mod test_only;',
                '#[cfg(test)] mod tests { include!("test_child.rs"); }',
                '#[cfg(not(test))] #[path="live.rs"] mod live;',
            )),
            "live.rs": 'pub fn live() {}',
        }
        self.assertEqual(require_source_closure(files), [("mod.rs", "path-module", "live.rs")])
        del files["live.rs"]
        with self.assertRaisesRegex(AssertionError, "missing live.rs"):
            require_source_closure(files)

    def test_unanalysed_dynamic_includes_and_implicit_modules_fail_closed(self):
        for source in ('include!(concat!("part", ".rs"));', 'mod implicit;'):
            with self.subTest(source=source), self.assertRaisesRegex(AssertionError, "explicit closure analysis"):
                require_source_closure({"mod.rs": source})


    def test_whole_unit_and_assembly_reader_sources_are_both_required_by_generated_core(self):
        files = embedded_native_sources()
        edges = require_source_closure(files)
        required = ("native_machine_asm_reader.rs", "native_machine_unit.rs")
        for name in required:
            self.assertIn(name, files)
            self.assertIn(("mod.rs", "path-module", name), edges)
        for name in required:
            with self.subTest(source=name):
                missing = dict(files)
                del missing[name]
                self.assertNotIn(name, missing)
                other = next(candidate for candidate in required if candidate != name)
                self.assertIn(other, missing)
                reason = (f"generated native source closure missing {name}: "
                          "mod.rs references it via path-module")
                with self.assertRaisesRegex(AssertionError, "^" + re.escape(reason) + "$"):
                    require_source_closure(missing)

    def test_engine_and_generated_native_roots_share_exact_registered_machine_source(self):
        files = embedded_native_sources()
        core_path = ROOT / "crates/ostadix-api/src/ocore/native_core.rs"
        engine_root = ROOT / "crates/ostadix-api/src/ocore/mod.rs"
        self.assertEqual(files["mod.rs"], core_path.read_text())
        root_tokens = rust_tokens(engine_root.read_text())
        include = [("word", "include"), ("punctuation", "!"), ("punctuation", "("),
                   ("string", "native_core.rs"), ("punctuation", ")")]
        matches = sum(root_tokens[i:i + len(include)] == include
                      for i in range(len(root_tokens) - len(include) + 1))
        self.assertEqual(matches, 1, "engine must include the same native_core root exactly once")
        edges = require_source_closure(files)
        for name in ("native_machine_asm_reader.rs", "native_machine_unit.rs"):
            self.assertIn(("mod.rs", "path-module", name), edges)


if __name__ == "__main__":
    unittest.main()
