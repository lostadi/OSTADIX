"""Bounded, real-engine source-splice regressions for Python and C17 editions."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

import unittest

ROOT = Path(__file__).resolve().parents[1]
CORE = [ROOT / "c_cpp/src" / name for name in
        ("value.c", "parser.c", "process.c", "eval.c", "scheduler.c", "nix_ops.c", "nixos_ops.c")]


def _compile(output, main):
    command = ["cc", "-std=c17", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-O0",
               "-D_POSIX_C_SOURCE=200809L", "-D_XOPEN_SOURCE=700", "-I" + str(ROOT / "c_cpp/include"),
               *map(str, CORE), str(main), "-pthread", "-o", str(output)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def _build_editions():
    missing = [name for name in ("cc", "bash", "node", "nix") if not shutil.which(name)]
    if missing:
        if os.environ.get("OSTADIX_TEST_RUNTIME_POLICY") == "required": raise AssertionError(f"required edition runtimes missing: {missing}")
        raise unittest.SkipTest(f"optional edition runtime evidence unavailable: {missing}")
    cache = Path(tempfile.mkdtemp(prefix="ostadix-edition-splice-tests-", dir=os.environ.get("OSTADIX_TEST_CACHE")))
    _compile(cache / "O-c17", ROOT / "c_cpp/src/main.c")
    _compile(cache / "ast-c17", ROOT / "c_cpp/tests/test_splice_contract.c")
    _compile(cache / "olangc-c17", ROOT / "c_cpp/src/olangc.c")
    (cache / "src").symlink_to(ROOT / "c_cpp/src", target_is_directory=True)
    (cache / "include").symlink_to(ROOT / "c_cpp/include", target_is_directory=True)
    return cache


def _identity(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2:].split()
        return int(fields[1]), int(fields[19])
    except (OSError, ValueError, IndexError): return None


def _descendants(parent):
    processes = []
    if sys.platform.startswith("linux"):
        for path in Path("/proc").iterdir():
            if path.name.isdecimal():
                identity = _identity(int(path.name))
                if identity: processes.append((int(path.name), *identity))
    parents, result = [parent], []
    for parent in parents:
        for pid, ppid, started in processes:
            if ppid == parent: parents.append(pid); result.append((pid, started))
    return result


def _bounded(command, directory, limit=5):
    env = dict(os.environ, PYTHONPATH=str(ROOT), O_BACKENDS_DIR=str(ROOT / "backends"), O_BACKEND_STEP_TIMEOUT_MS="3000")
    with tempfile.TemporaryFile(dir=directory) as out, tempfile.TemporaryFile(dir=directory) as err:
        child = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                 stdout=out, stderr=err, start_new_session=os.name == "posix")
        timeout = False
        try: child.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timeout = True
            descendants = _descendants(child.pid)
            if os.name == "posix":
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            else: child.kill()
            for pid, started in reversed(descendants):
                identity = _identity(pid)
                if identity and identity[1] == started:
                    try: os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError: pass
            child.wait(timeout=1)
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(4 * 1024 * 1024).decode(errors="replace"), err.read(4 * 1024 * 1024).decode(errors="replace")
    assert not timeout, f"{limit}s edition timeout: {command!r}\n{stdout}\n{stderr}"
    return child.returncode, stdout, stderr


def _run(edition, source, directory):
    path = directory / "input.O"
    path.write_text(source)
    command = [sys.executable, "-m", "o_lang", str(path), "--as", "json"] if edition == "python" else [str(directory / "O-c17"), str(path), str(ROOT / "backends")]
    return _bounded(command, directory)


def _text(edition, source, directory):
    code, output, error = _run(edition, source, directory)
    assert code == 0, f"{edition}: {source}\n{output}\n{error}"
    if edition == "python": return json.loads(output)["value"]
    return output.rstrip("\n")


def _producer(payload):
    encoded = base64.b64encode(payload.encode()).decode()
    return f"let payload = python^(__import__('base64').b64decode('{encoded}').decode('utf-8'))_python\n"


def check_exact_seven_review_witnesses(editions, edition):
    sys.path.insert(0, str(ROOT))
    from scripts.reproduce_splice_contract import original_cases
    cases = original_cases(json.loads((ROOT / "tests/fixtures/foreign-splice-witnesses.json").read_text()))
    for number, case in enumerate(cases, 1):
        code, output, error = _run(edition, case["source"], editions)
        if case["accept"]:
            assert code == 0, error
            if number == 1:
                if edition == "python":
                    assert json.loads(output) == {"tag": "list", "items": [
                        {"tag": "int", "value": 7}, {"tag": "str", "value": "O'Brien"}]}
                else: assert output == "[7, O'Brien]\n"
            elif edition == "python":
                assert json.loads(output) == {"tag": "str", "value": '[a"; echo SPLICED-AS-CODE; echo "]'}
            else: assert output == '[a"; echo SPLICED-AS-CODE; echo "]', repr(output)
        else:
            assert code != 0 and "foreign value splice" in error, (output, error)


def check_corrected_values_use_real_engines_and_preserve_adversarial_text(editions, edition):
    payloads = ["O'Brien", "nobody' UNION SELECT 'spliced-as-code", 'a"; echo SPLICED-AS-CODE; echo "',
                "${builtins.abort \"SPLICED-AS-CODE\"}", "a\r\n.line\t\\'\" λ😀"]
    # Deterministic corpus retains quoting/control bytes in every native run.
    alphabet = "ab09'\"\\$`();#/*-={}[]\n\r\t λ😀"
    state = 0x4F535441444958
    for _ in range(8):
        text = ""
        for _ in range(36):
            state ^= state << 13; state ^= state >> 7; state ^= state << 17; state &= (1 << 64) - 1
            text += alphabet[state % len(alphabet)]
        payloads.append(text)
    receivers = ["python^($payload.encode('utf-8').hex())_python",
                 "sql^(SELECT lower(hex($payload)) AS h;)_sql",
                 "bash^(printf '%s' $payload | od -An -v -tx1 | tr -d ' \\n')_bash",
                 "bash^(printf '%s' \"${payload}\" | od -An -v -tx1 | tr -d ' \\n')_bash",
                 "javascript^(console.log(Buffer.from($payload,'utf8').toString('hex')))_javascript"]
    for payload in payloads:
        for receiver in receivers:
            assert _text(edition, _producer(payload) + receiver, editions) == payload.encode().hex()
    for payload in payloads[:5]:
        assert _text(edition, _producer(payload) + "nix^($payload)_nix", editions) == payload


def check_explicit_code_is_positional_and_untrusted_profiles_fail_closed(editions, edition):
    assert _text(edition, "let source = text^(40 + 2)_text\npython^($!source)_python", editions) == (42 if edition == "python" else "42")
    assert _text(edition, "let source = text^(40 + 2)_text\nlet ordinary = text^($!source)_text\npython^($ordinary)_python", editions) == "40 + 2"
    code, _, error = _run(edition, "let x = text^(value)_text\ncommon_lisp^($x)_common_lisp", editions)
    assert code != 0 and "foreign value splice" in error


def check_unsupported_placements_precede_all_producer_effects(editions, edition):
    marker = editions / "must-not-exist"
    first = f"python^(__import__('pathlib').Path({str(marker)!r}).write_text('effect'))_python\n"
    placements = ["python^( f\"{ \"prefix $payload\" }\" )_python",
                  "python^( t\"{ \"prefix $payload\" }\" )_python",
                  "python^( rt\"{ \"prefix $payload\" }\" )_python",
                  "python^( tr\"{ \"prefix $payload\" }\" )_python",
                  "bash^( \\$payload )_bash", "bash^( $(( $payload )) )_bash",
                  "bash^([[ $payload -gt 0 ]])_bash",
                  'bash^( "${array[$payload]}" )_bash', 'nix^( "${ "prefix $payload" }" )_nix',
                  "javascript^( `outer${`inner $payload`}` )_javascript", "javascript^( <!-- $payload\n42 )_javascript",
                  "python^(prefix$payload)_python", "sql^(-- $payload\nSELECT 1;)_sql"]
    for placement in placements:
        code, _, error = _run(edition, first + placement, editions)
        assert code != 0 and "foreign value splice" in error, (placement, error)
        assert not marker.exists()
    payload = "a[$(printf owned > " + str(marker) + ")0]"
    code, _, error = _run(edition, _producer(payload) + "bash^([[ $payload -gt 0 ]]; printf done)_bash", editions)
    assert code != 0 and "foreign value splice" in error
    assert not marker.exists()
    # Two source backslashes are a pair; the literal opening quote is not escaped.
    safe = _producer('"; echo SPLICED-AS-CODE') + "bash^(printf '%s' \\\\$payload)_bash"
    assert _text(edition, safe, editions) == "\\" + '\"; echo SPLICED-AS-CODE'


def check_hand_built_python_and_c17_asts_validate_before_effects(editions):
    sys.path.insert(0, str(ROOT))
    from o_lang.evaluator import EvalContext, evaluate_document, _eval_expression
    from o_lang.parser import Document, ExpressionNode, TextPart, VarRef, EPHEMERAL_ENV_ID
    marker = editions / "must-not-exist-direct"
    producer = ExpressionNode("python", EPHEMERAL_ENV_ID, False, [TextPart(f"__import__('pathlib').Path({str(marker)!r}).write_text('effect')")])
    bad = ExpressionNode("sql", EPHEMERAL_ENV_ID, False, [TextPart("SELECT '"), VarRef("payload"), TextPart("' AS who;")])
    with unittest.TestCase().assertRaisesRegex(ValueError, "foreign value splice"): evaluate_document(Document([producer, bad]))
    assert not marker.exists()
    wrapper = ExpressionNode("O", EPHEMERAL_ENV_ID, False, [producer, bad])
    for entry in (lambda node, ctx: _eval_expression(node, ctx),
                  lambda node, ctx: ctx.backend_for("O").eval_ast(node, ctx)):
        with unittest.TestCase().assertRaisesRegex(ValueError, "foreign value splice"): entry(wrapper, EvalContext())
        assert not marker.exists()
    python_wrapper = ExpressionNode("python", EPHEMERAL_ENV_ID, False, [producer, bad])
    context = EvalContext()
    with unittest.TestCase().assertRaisesRegex(ValueError, "foreign value splice"): context.backend_for("python").eval_ast(python_wrapper, context)
    assert not marker.exists()
    code, _, error = _bounded([str(editions / "ast-c17"), str(marker), str(ROOT / "backends")], editions)
    assert code == 0 and "foreign value splice" in error
    assert not marker.exists()


def check_supported_hello_tutorial(editions, edition):
    source = (ROOT / "examples/hello.O").read_text()
    assert _text(edition, source, editions) == "hello from Python and Bash and JavaScript!"
    assert _text(edition, "bash^(sleep 0.01 & wait $!; printf native)_bash", editions) == "native"
    assert _text(edition, "let payload = python^(2)_python\nbash^([[ ${payload} -gt 0 ]] && printf native)_bash", editions) == "native"


def check_javascript_computed_keys(editions, edition):
    source = '''let payload = python^({'__proto__': {'polluted': True}, 'constructor': 'ordinary', 'quote"key': 'text'})_python
javascript^(const obj=$payload;console.log('proto:'+JSON.stringify([Object.prototype.hasOwnProperty.call(obj,'__proto__'),Object.getPrototypeOf(obj)===Object.prototype,obj['__proto__'].polluted,obj.constructor,obj['quote"key']])) )_javascript'''
    assert _text(edition, source, editions) == 'proto:[true,true,true,"ordinary","text"]'


def check_nul_and_cr(editions, edition):
    for payload in ["before\r\nafter", "before\rafter", "before\0after'\"; echo INJECTED"]:
        source = _producer(payload) + "sql^(SELECT lower(hex($payload)) AS h;)_sql"
        if edition == "c17" and "\0" in payload:
            code, _, error = _run(edition, source, editions)
            assert code != 0 and "NUL text is unsupported" in error
        else:
            assert _text(edition, source, editions) == payload.encode().hex()
    code, _, error = _run(edition, _producer("before\0after") + "bash^(printf '%s' $payload)_bash", editions)
    assert code != 0 and "nul" in error.lower()


def check_c17_aot(editions):
    for name, source, accepted, expected in [
        ("hello", (ROOT / "examples/hello.O").read_text(), True, "hello from Python and Bash and JavaScript!"),
        ("code", "let source = text^(40+2)_text\npython^($!source)_python", True, "42"),
        ("bad", f"python^(__import__('pathlib').Path({str(editions / 'aot-must-not-exist')!r}).write_text('effect'))_python\nsql^(SELECT '$missing';)_sql", False, ""),
    ]:
        path = editions / (name + "-aot.O")
        path.write_text(source)
        binary = editions / (name + "-aot")
        code, _, error = _bounded([str(editions / "olangc-c17"), str(path), "-o", str(binary), "--shim-dir", str(ROOT / "backends")], editions, limit=30)
        assert code == 0, error
        code, output, error = _bounded([str(binary)], editions)
        if accepted: assert code == 0 and output.rstrip("\n") == expected, (output, error)
        else:
            assert code != 0 and "foreign value splice" in error
            assert not (editions / "aot-must-not-exist").exists()
    # A copied/installed compiler can resolve runtime sources separately.
    # Require their declared source contract; this is not a source hash proof.
    older = editions / "older-runtime"
    older.mkdir()
    shutil.copytree(ROOT / "c_cpp/src", older / "src", ignore=shutil.ignore_patterns("*.o"))
    shutil.copytree(ROOT / "c_cpp/include", older / "include")
    header = older / "include/parser.h"
    current = header.read_text()
    assert "#define OLANG_SPLICE_CONTRACT_VERSION 1\n" in current
    header.write_text(current.replace("#define OLANG_SPLICE_CONTRACT_VERSION 1\n", ""))
    compiler = older / "olangc-c17"
    shutil.copy2(editions / "olangc-c17", compiler)
    source = older / "input.O"
    source.write_text("python^(42)_python\n")
    binary = older / "must-not-build"
    code, _, error = _bounded([str(compiler), str(source), "-o", str(binary), "--shim-dir", str(ROOT / "backends")], editions, limit=30)
    assert code != 0 and "requires source-splice contract v1" in error, error
    assert not binary.exists()


def check_python_noncanonical_repr_is_not_guest_source(editions):
    marker = editions / "repr-must-not-exist"
    injected = f"__import__('pathlib').Path({str(marker)!r}).write_text('effect')"
    source = f'''let payload = python^(
from o_lang.ovalue import OStr
class Payload(str):
    def __repr__(self):
        return {injected!r}
__oval_result__ = OStr(Payload('ordinary text'))
)_python
python^($payload)_python'''
    code, _, error = _run("python", source, editions)
    assert code != 0 and "noncanonical OValue payload" in error
    assert not marker.exists()


class EditionSpliceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.editions = _build_editions()

    def test_exact_seven(self):
        for edition in ("python", "c17"):
            with self.subTest(edition=edition): check_exact_seven_review_witnesses(self.editions, edition)

    def test_adversarial_native_profiles(self):
        for edition in ("python", "c17"):
            with self.subTest(edition=edition): check_corrected_values_use_real_engines_and_preserve_adversarial_text(self.editions, edition)

    def test_explicit_code(self):
        for edition in ("python", "c17"):
            with self.subTest(edition=edition): check_explicit_code_is_positional_and_untrusted_profiles_fail_closed(self.editions, edition)

    def test_before_producer_effects(self):
        for edition in ("python", "c17"):
            with self.subTest(edition=edition): check_unsupported_placements_precede_all_producer_effects(self.editions, edition)

    def test_direct_ast(self):
        check_hand_built_python_and_c17_asts_validate_before_effects(self.editions)

    def test_supported_hello(self):
        for edition in ("python", "c17"):
            with self.subTest(edition=edition): check_supported_hello_tutorial(self.editions, edition)

    def test_javascript_keys(self):
        for edition in ("python", "c17"):
            with self.subTest(edition=edition): check_javascript_computed_keys(self.editions, edition)

    def test_nul_and_cr(self):
        for edition in ("python", "c17"):
            with self.subTest(edition=edition): check_nul_and_cr(self.editions, edition)

    def test_c17_aot(self):
        check_c17_aot(self.editions)

    def test_python_noncanonical_repr(self):
        check_python_noncanonical_repr_is_not_guest_source(self.editions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
