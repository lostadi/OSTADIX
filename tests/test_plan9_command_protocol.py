"""Wire fixtures, corruption rejection and replay-binding checks; no VM needed."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "ocore/guest/plan9/unified/protocol.py"
SPEC = importlib.util.spec_from_file_location("plan9_command_protocol_tested", SOURCE)
protocol = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = protocol
SPEC.loader.exec_module(protocol)

G = "0123456789abcdef"
S = "0123456789abcdef" * 2
R = "fedcba9876543210" * 2


def request(**changes):
    values = dict(generation=G, instance=S, request_id=R, argv=["/bin/rc", "-I", "a b'\n.rc"],
                  cwd="/n/okernel/work", stdin=b"zero\x00\xff\r\n", timeout_ms=1234,
                  stdout_limit=100, stderr_limit=50)
    values.update(changes)
    return protocol.encode_request(**values)


class Plan9CommandProtocolTests(unittest.TestCase):
    def test_request_matches_independent_wire_fixture(self):
        argv = [b"/bin/rc", b"-I", b"a b'\n.rc"]
        cwd, stdin = b"/n/okernel/work", b"zero\x00\xff\r\n"
        expected = (b"OC9REQ01" + G.encode() + S.encode() + R.encode()
                    + struct.pack("<6I", 3, len(cwd), len(stdin), 1234, 100, 50) + cwd
                    + b"".join(struct.pack("<I", len(arg)) + arg for arg in argv) + stdin)
        self.assertEqual(request(), expected)
        self.assertEqual(protocol.REQUEST_HEADER.size, 112)
        decoded = protocol.decode_request(expected)
        self.assertEqual(decoded.argv, tuple(arg.decode() for arg in argv))
        self.assertEqual(decoded.stdin, stdin)
        self.assertEqual(decoded.cwd, cwd.decode())
        self.assertEqual(decoded.timeout_ms, 1234)

    def test_argument_and_request_limits_count_bytes(self):
        maximum = request(argv=["/bin/echo"] + [""] * 63, cwd="/" + "x" * 4094,
                          stdin=b"", timeout_ms=300000, stdout_limit=0, stderr_limit=1048576)
        self.assertEqual(len(protocol.decode_request(maximum).argv), 64)
        argument = "é" * 32767 + "a"
        self.assertEqual(protocol.decode_request(request(argv=["/bin/echo", argument])).argv[1], argument)
        empty = request(stdin=b"")
        boundary = request(stdin=b"x" * (protocol.MAX_REQUEST_BYTES - len(empty)))
        self.assertEqual(len(boundary), 1048576)
        self.assertEqual(len(protocol.decode_request(boundary).stdin), 1048576 - len(empty))
        with self.assertRaises(protocol.ProtocolError):
            request(stdin=b"x" * (protocol.MAX_REQUEST_BYTES - len(empty) + 1))

    def test_invalid_requests_are_rejected_before_serialization(self):
        cases = [dict(generation=G.upper()), dict(generation="0" * 16), dict(instance=S[:-1]), dict(request_id="../" + R[3:]),
                 dict(argv=[]), dict(argv="/bin/rc"), dict(argv=["rc"]), dict(argv=["/bin/rc", "a\0b"]),
                 dict(argv=["/bin/rc"] * 65), dict(argv=["/bin/rc", "é" * 32768]),
                 dict(cwd="relative"), dict(cwd=""), dict(cwd="/a\0b"), dict(cwd="/" + "x" * 4095),
                 dict(argv=["/bin/rc", "\ud800"]), dict(timeout_ms=0), dict(timeout_ms=300001),
                 dict(timeout_ms=True), dict(stdout_limit=-1), dict(stderr_limit=1048577), dict(stdin="text")]
        for changes in cases:
            with self.subTest(changes=repr(changes)[:100]), self.assertRaises(protocol.ProtocolError):
                request(**changes)

    def test_decoder_rejects_each_truncation_and_trailing_bytes(self):
        valid = request()
        for cut in range(len(valid)):
            with self.subTest(cut=cut), self.assertRaises(protocol.ProtocolError):
                protocol.decode_request(valid[:cut])
        for invalid in (valid + b"x", b"OC9REQ02" + valid[8:], valid[:8] + b"x" + valid[9:]):
            with self.assertRaises(protocol.ProtocolError):
                protocol.decode_request(invalid)

    def test_decoder_rejects_forged_lengths_invalid_utf8_and_limits(self):
        valid = request()
        for offset, value in ((88, 0), (88, 65), (92, 0), (92, 4096), (96, 0xffffffff),
                              (100, 0), (100, 300001), (104, 1048577), (108, 1048577)):
            invalid = bytearray(valid)
            struct.pack_into("<I", invalid, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(protocol.ProtocolError):
                protocol.decode_request(invalid)
        invalid = bytearray(valid)
        invalid[113] = 0xff
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_request(invalid)
        invalid = bytearray(valid)
        struct.pack_into("<I", invalid, 112 + len("/n/okernel/work"), 0xffffffff)
        with self.assertRaises(protocol.ProtocolError):
            protocol.decode_request(invalid)

    def test_exact_publication_markers(self):
        encoded = request()
        digest = hashlib.sha256(encoded).hexdigest()
        self.assertEqual(protocol.ready_marker(G, S), f"OC9READY1 {G} {S}\n".encode())
        self.assertEqual(protocol.parse_ready(protocol.ready_marker(G, S)), (G, S))
        submit = f"OC9SUB01 {G} {S} {R} {digest}\n".encode()
        self.assertEqual(protocol.submit_marker(encoded), submit)
        self.assertEqual(protocol.parse_submit(submit).request_sha256, digest)
        self.assertEqual(protocol.validate_submit(encoded, submit), protocol.decode_request(encoded))
        for malformed in (submit[:-1], submit + b"\n", submit.replace(b" ", b"\t", 1),
                          submit.replace(b"\n", b"\r\n"), submit.upper(), submit + b"ignored"):
            with self.subTest(marker=malformed), self.assertRaises(protocol.ProtocolError):
                protocol.parse_submit(malformed)

    def test_result_matches_independent_wire_fixture_and_preserves_raw_status(self):
        encoded = request()
        stdout, stderr, status = b"one\x00\xff", b"err\r\n", b"rc 17: failure\xff\x00"
        expected = (b"OC9RES01" + G.encode() + S.encode() + R.encode()
                    + hashlib.sha256(encoded).digest()
                    + struct.pack("<4I", 1, len(stdout), len(stderr), len(status))
                    + hashlib.sha256(stdout).digest() + hashlib.sha256(stderr).digest() + status)
        actual = protocol.encode_result(encoded, flags=1, stdout=stdout, stderr=stderr, status=status)
        self.assertEqual(actual, expected)
        self.assertEqual(protocol.RESULT_HEADER.size, 200)
        done = (f"OC9DONE1 {G} {S} {R} {hashlib.sha256(encoded).hexdigest()} "
                f"{hashlib.sha256(expected).hexdigest()}\n").encode()
        self.assertEqual(protocol.done_marker(encoded, actual), done)
        result = protocol.validate_result(encoded, actual, stdout, stderr, done=done,
                                          started=protocol.submit_marker(encoded), status=status)
        self.assertEqual(result.status, status)
        self.assertFalse(result.ok)
        self.assertEqual(protocol.parse_done(done).result_sha256, hashlib.sha256(expected).hexdigest())

    def test_cancel_matches_independent_marker_and_returns_bound_request(self):
        encoded = request()
        expected = f"OC9CAN01 {G} {S} {R} {hashlib.sha256(encoded).hexdigest()}\n".encode()
        self.assertEqual(protocol.cancel_marker(encoded), expected)
        self.assertEqual(protocol.validate_cancel(encoded, expected), protocol.decode_request(encoded))
        self.assertEqual(protocol.cancel_marker(memoryview(encoded)), expected)
        with self.assertRaises(protocol.ProtocolError):
            protocol.cancel_marker(encoded[:-1])

    def test_cancel_rejects_stale_identity_request_changes_and_malformed_markers(self):
        encoded = request()
        cancel = protocol.cancel_marker(encoded)
        for changed in (request(generation="1" * 16), request(instance="2" * 32),
                        request(request_id="3" * 32), request(stdin=b"different"),
                        request(cwd="/different"), request(argv=["/bin/echo", "different"])):
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()), self.assertRaises(protocol.ProtocolError):
                protocol.validate_cancel(changed, cancel)
        changed_digest = cancel[:-2] + (b"1" if cancel[-2:-1] == b"0" else b"0") + b"\n"
        for malformed in (cancel[:-1], cancel + b"\n", cancel + b"extra", cancel.upper(),
                          cancel.replace(b" ", b"\t", 1), cancel.replace(b"\n", b"\r\n"),
                          cancel.replace(b" ", b"  ", 1), b"\xff" + cancel[1:], changed_digest,
                          protocol.submit_marker(encoded)):
            with self.subTest(marker=malformed), self.assertRaises(protocol.ProtocolError):
                protocol.validate_cancel(encoded, malformed)

    def test_cancelled_results_require_recovery_and_preserve_output_integrity(self):
        encoded = request()
        stdout, stderr, status = b"partial\x00\xff", b"diagnostic", b"service: command cancelled"
        self.assertEqual(protocol.FLAG_CANCELLED, 16)
        self.assertEqual(protocol.KNOWN_FLAGS, 31)
        for flags in (16, 18, 20, 24, 30):
            with self.subTest(flags=flags):
                result = protocol.encode_result(encoded, flags=flags, stdout=stdout, stderr=stderr, status=status)
                self.assertEqual(struct.unpack_from("<I", result, 120)[0], flags)
                reset = (f"OC9RESET1 {G} {S} {R} {hashlib.sha256(encoded).hexdigest()} "
                         f"{hashlib.sha256(result).hexdigest()}\n").encode()
                self.assertEqual(protocol.reset_marker(encoded, result), reset)
                decoded = protocol.validate_reset(encoded, result, reset)
                self.assertEqual(decoded, protocol.validate_result(encoded, result, stdout, stderr,
                    status=status, started=protocol.submit_marker(encoded), done=protocol.done_marker(encoded, result)))
                self.assertFalse(decoded.ok)
                self.assertEqual(decoded.status, status)
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_result(encoded, result, b"altered", stderr)
        empty_status = protocol.encode_result(encoded, flags=16, stdout=b"", stderr=b"", status=b"")
        self.assertFalse(protocol.decode_result(empty_status).ok)

    def test_replay_binding_covers_generation_instance_id_and_request_bytes(self):
        encoded = request()
        result = protocol.encode_result(encoded, flags=0, stdout=b"out", stderr=b"", status=b"")
        submission = protocol.submit_marker(encoded)
        for changed in (request(generation="1" * 16), request(instance="2" * 32),
                        request(request_id="3" * 32), request(stdin=b"different"),
                        request(cwd="/different"), request(argv=["/bin/echo", "different"])):
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_submit(changed, submission)
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_result(changed, result, b"out", b"")

    def test_timeout_reset_marker_binds_exact_request_and_result(self):
        encoded = request()
        stdout, stderr, status = b"partial\x00\xff", b"diagnostic", b"service: command timed out"
        result = protocol.encode_result(encoded, flags=3, stdout=stdout, stderr=stderr, status=status)
        expected = (f"OC9RESET1 {G} {S} {R} {hashlib.sha256(encoded).hexdigest()} "
                    f"{hashlib.sha256(result).hexdigest()}\n").encode()
        self.assertEqual(protocol.reset_marker(encoded, result), expected)
        decoded = protocol.validate_reset(encoded, result, expected)
        self.assertEqual(decoded.flags, protocol.FLAG_TIMEOUT | protocol.FLAG_STDOUT_TRUNCATED)
        self.assertFalse(decoded.ok)
        self.assertEqual(decoded, protocol.validate_result(
            encoded, result, stdout, stderr, status=status,
            started=protocol.submit_marker(encoded), done=protocol.done_marker(encoded, result)))
        for changed in (request(generation="1" * 16), request(instance="2" * 32),
                        request(request_id="3" * 32), request(stdin=b"different")):
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()), self.assertRaises(protocol.ProtocolError):
                protocol.validate_reset(changed, result, expected)
        changed_result = protocol.encode_result(encoded, flags=1, stdout=stdout, stderr=stderr, status=status)
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_reset(encoded, changed_result, expected)
        changed_digest = expected[:-2] + (b"1" if expected[-2:-1] == b"0" else b"0") + b"\n"
        for malformed in (expected[:-1], expected + b"\n", expected.replace(b" ", b"\t", 1),
                          expected.replace(b"\n", b"\r\n"), expected.upper(), changed_digest,
                          protocol.done_marker(encoded, result)):
            with self.subTest(marker=malformed), self.assertRaises(protocol.ProtocolError):
                protocol.validate_reset(encoded, result, malformed)

    def test_reset_marker_requires_timeout_or_cancellation_and_does_not_validate_captured_streams(self):
        encoded = request()
        for flags in (0, 2, 4, 8, 14):
            result = protocol.encode_result(encoded, flags=flags, stdout=b"", stderr=b"", status=b"")
            forged = (f"OC9RESET1 {G} {S} {R} {hashlib.sha256(encoded).hexdigest()} "
                      f"{hashlib.sha256(result).hexdigest()}\n").encode()
            with self.subTest(flags=flags):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.reset_marker(encoded, result)
                with self.assertRaises(protocol.ProtocolError):
                    protocol.validate_reset(encoded, result, forged)
        result = protocol.encode_result(encoded, flags=15, stdout=b"out", stderr=b"err", status=b"")
        reset = protocol.reset_marker(encoded, result)
        self.assertEqual(protocol.validate_reset(encoded, result, reset).flags, 15)
        self.assertFalse(protocol.decode_result(result).ok)
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_result(encoded, result, b"OUT", b"err")

    def test_result_rejects_stream_status_and_publication_tampering(self):
        encoded = request()
        result = protocol.encode_result(encoded, flags=0, stdout=b"out", stderr=b"err", status=b"")
        done = protocol.done_marker(encoded, result)
        changed_done = done[:-2] + (b"1" if done[-2:-1] == b"0" else b"0") + b"\n"
        self.assertTrue(protocol.validate_result(encoded, result, b"out", b"err", done=done).ok)
        for out, err, kwargs in ((b"OUT", b"err", {}), (b"out!", b"err", {}),
                                (b"out", b"ERR", {}), (b"out", b"err", {"status": b"bad"}),
                                (b"out", b"err", {"done": changed_done}),
                                (b"out", b"err", {"started": protocol.submit_marker(request(stdin=b"changed"))})):
            with self.subTest(kwargs=kwargs, stdout=out, stderr=err), self.assertRaises(protocol.ProtocolError):
                protocol.validate_result(encoded, result, out, err, **kwargs)

    def test_result_limits_unknown_flags_and_framing(self):
        encoded = request(stdout_limit=0, stderr_limit=0)
        result = protocol.encode_result(encoded, flags=6, stdout=b"", stderr=b"", status=b"")
        self.assertFalse(protocol.validate_result(encoded, result, b"", b"").ok)
        for fields in (dict(flags=32, stdout=b"", stderr=b"", status=b""),
                       dict(flags=0, stdout=b"x", stderr=b"", status=b""),
                       dict(flags=0, stdout=b"", stderr=b"x", status=b""),
                       dict(flags=0, stdout=b"", stderr=b"", status=b"x" * 4097)):
            with self.assertRaises(protocol.ProtocolError):
                protocol.encode_result(encoded, **fields)
        for offset, value in ((120, 32), (124, 1048577), (128, 1048577), (132, 1)):
            invalid = bytearray(result)
            struct.pack_into("<I", invalid, offset, value)
            with self.assertRaises(protocol.ProtocolError):
                protocol.decode_result(invalid)
        for invalid in (result[:199], result + b"extra", b"OC9RES02" + result[8:]):
            with self.assertRaises(protocol.ProtocolError):
                protocol.decode_result(invalid)
        wider_request = request(stdout_limit=10, stderr_limit=0)
        oversized = protocol.encode_result(wider_request, flags=0, stdout=b"x", stderr=b"", status=b"")
        forged = bytearray(oversized)
        forged[88:120] = hashlib.sha256(encoded).digest()
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_result(encoded, forged, b"x", b"")

    def test_canonical_request_paths_do_not_accept_path_components_as_ids(self):
        paths = protocol.request_paths(protocol.DEFAULT_ROOT, G, S, R)
        self.assertEqual(paths["request"], f"/n/okernel/services/plan9/g{G}/s{S}/r{R}/request")
        self.assertEqual(tuple(paths), protocol.REQUEST_FILES)
        self.assertNotIn("cancel", paths)
        plan9_paths = protocol.request_paths(protocol.PLAN9_ROOT, G, S, R, include_optional=True)
        self.assertEqual(plan9_paths["cancel"], f"/n/services/plan9/g{G}/s{S}/r{R}/cancel")
        self.assertEqual(tuple(plan9_paths), protocol.REQUEST_FILES + protocol.OPTIONAL_REQUEST_FILES)
        for root in ("relative", "/n/../tmp", "/n//tmp", "//n/tmp", "/n/./tmp", "/n/tmp/", "/n/\0tmp"):
            with self.subTest(root=root), self.assertRaises(protocol.ProtocolError):
                protocol.request_paths(root, G, S, R)


if __name__ == "__main__":
    unittest.main()
