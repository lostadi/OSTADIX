"""Shell completion records reject wrapped echoes and incomplete output."""
from contextlib import contextmanager
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGE = load("completion_package_runner", "scripts/okernel_package_domain.py")
UNIFIED = load("completion_unified_runner", "scripts/okernel_unified_world.py")


class StatusRecordTests(unittest.TestCase):
    def test_all_unix_status_bytes_and_decimal_leading_zeros(self):
        for status in range(256):
            with self.subTest(status=status):
                self.assertEqual(PACKAGE.command_completion_status(
                    b"nonce:" + str(status).encode(), b"nonce"), status)
        self.assertEqual(PACKAGE.command_completion_status(b"nonce:01", b"nonce"), 1)

    def test_echo_fragments_nondecimal_out_of_range_and_suffixes_are_not_records(self):
        invalid = [b"", b"nonce:", b"other:0", b"prefix nonce:0", b"nonce:0 suffix",
                   b"nonce:%s\\n' \"$_okernel_rc\"", b"nonce:0\\n'", b"nonce:0; true",
                   b"nonce: 0", b"nonce:0 ", b"nonce:+0", b"nonce:-1", b"nonce:1.0",
                   b"nonce:256", b"nonce:999", b"nonce:1000", b"nonce:0000",
                   b"nonce:0\x00", b"nonce:0\r", b"nonce:0\n", b"nonce:\xef\xbc\x90"]
        for line in invalid:
            with self.subTest(line=line):
                self.assertIsNone(PACKAGE.command_completion_status(line, b"nonce"))


class ControllerCompletionTests(unittest.TestCase):
    @contextmanager
    def controller(self, kind, chunks):
        module = PACKAGE if kind == "package" else UNIFIED
        cls = module.Domain if kind == "package" else module.UnifiedDomain
        domain = cls.__new__(cls)
        domain.capture = bytearray(b"old unrelated command output\n")
        domain.timeout = 1
        domain.session = Path("/test/completion-record-session")
        domain.process = SimpleNamespace(poll=lambda: None)
        token = ("OKERNEL_COMMAND_" if kind == "package" else "UNIFIED_COMMAND_") + "f" * 32
        records = iter(chunks(token.encode()))
        pump_calls, sent = [], []

        def send(wire):
            sent.append(wire)
            # The ordinary whole command echo is retained as well as any
            # separately supplied redraw/wrapped fragments from the fixture.
            domain.capture.extend(wire)

        def pump(*args):
            pump_calls.append(args)
            try:
                domain.capture.extend(next(records))
            except StopIteration:
                raise TimeoutError("fixture exhausted without a complete valid record")

        domain.send, domain.pump = send, pump
        with mock.patch.object(module.uuid, "uuid4", return_value=SimpleNamespace(hex="f" * 32)):
            yield domain, pump_calls, sent

    def test_wrapped_printf_echo_is_ignored_before_actual_success(self):
        def chunks(token):
            yield b"\r\n" + token + b":%s\\n' \"$_okernecustom-shell> true; printf 'echo\r\n"
            yield b"\r\n" + token + b":0\r\n"

        for kind in ("package", "unified"):
            with self.subTest(kind=kind), self.controller(kind, chunks) as (domain, pumps, sent):
                domain.command("true")
                self.assertEqual(len(pumps), 2)
                self.assertEqual(len(sent), 1)

    def test_repeated_malformed_and_out_of_range_echoes_do_not_fail_valid_command(self):
        def chunks(token):
            yield (b"\n" + token + b":%s\\n'\n" + token + b":256\n"
                   + token + b":-1\n" + token + b":9999999999999999999999\n"
                   + token + b":0 trailing\n" + token + b":0; printf echo\n")
            yield b"\n" + token + b":%s\\n'\n"
            yield b"\n" + token + b":0\n"

        for kind in ("package", "unified"):
            with self.subTest(kind=kind), self.controller(kind, chunks) as (domain, pumps, _):
                domain.command("true")
                self.assertEqual(len(pumps), 3)

    def test_partial_zero_is_not_accepted_before_remaining_nonzero_digit(self):
        def chunks(token):
            yield b"\n" + token + b":0"
            yield b"1\r\n"

        for kind in ("package", "unified"):
            with self.subTest(kind=kind), self.controller(kind, chunks) as (domain, pumps, _):
                with self.assertRaisesRegex(RuntimeError, "guest command failed"):
                    domain.command("false")
                self.assertEqual(len(pumps), 2)

    def test_partial_crlf_record_requires_the_final_newline(self):
        def chunks(token):
            yield b"\r\n" + token + b":0\r"
            yield b"\n"

        for kind in ("package", "unified"):
            with self.subTest(kind=kind), self.controller(kind, chunks) as (domain, pumps, _):
                domain.command("true")
                self.assertEqual(len(pumps), 2)

    def test_incomplete_or_prompt_prefixed_records_never_acknowledge(self):
        for kind in ("package", "unified"):
            for tail in (b":0", b":255", b":%s\\n'\n", b":256\n", b":0suffix\n"):
                def chunks(token):
                    yield b"\n" + token + tail
                    if tail.endswith(b"\n"):
                        yield b"prompt> " + token + b":0\n"
                with self.subTest(kind=kind, tail=tail), self.controller(kind, chunks) as (domain, _, _):
                    with self.assertRaisesRegex(TimeoutError, "without a complete valid"):
                        domain.command("true")

    def test_exact_nonzero_records_preserve_real_command_failures(self):
        for kind in ("package", "unified"):
            for status in (1, 2, 7, 127, 128, 130, 255):
                def chunks(token):
                    yield b"\n" + token + b":" + str(status).encode() + b"\n"
                with self.subTest(kind=kind, status=status), self.controller(kind, chunks) as (domain, _, _):
                    with self.assertRaisesRegex(RuntimeError, "guest command failed"):
                        domain.command("false")

    def test_first_valid_nonzero_cannot_be_overridden_by_repeated_success(self):
        def chunks(token):
            yield b"\n" + token + b":7\n" + token + b":0\n" + token + b":0\n"

        for kind in ("package", "unified"):
            with self.subTest(kind=kind), self.controller(kind, chunks) as (domain, _, _):
                with self.assertRaisesRegex(RuntimeError, ":7"):
                    domain.command("false")

    def test_first_valid_success_is_not_overridden_by_repeated_nonzero(self):
        def chunks(token):
            yield b"\n" + token + b":0\n" + token + b":7\n"

        for kind in ("package", "unified"):
            with self.subTest(kind=kind), self.controller(kind, chunks) as (domain, _, _):
                domain.command("true")


if __name__ == "__main__":
    unittest.main()
