"""Structural O10 tests; native equivalence is qualified separately."""
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("o10_codec", ROOT / "scripts/o10.py")
codec = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(codec)


def sample_messages():
    """Deterministic complete wire corpus shared with the native harness."""
    messages = []
    for index, (name, schema) in enumerate(codec.SCHEMAS.items()):
        message = {"type": name, "tag": 0x1234}
        if name.startswith("T") and name != "Tversion":
            message.update(epoch=7, seq=0 if name in codec.READ_ONLY else index + 1)
        for field, fmt in schema:
            if fmt in ("bytes", "opaque"):
                value = b"opaque\0bytes"
            elif fmt == "events":
                value = [{"cursor": 9, "type": 1, "flags": 2, "dom": 0x100000001,
                          "lease": 0x100000004, "arg0": 17, "arg1": 23}]
            elif fmt.endswith("s"):
                value = codec.O10_VERSION if field == "version" else bytes(range(int(fmt[:-1])))
            elif field == "msize":
                value = 512
            else:
                value = (1 << (8 * struct.calcsize("<" + fmt))) - 1
            message["negotiated_msize" if field == "msize" else field] = value
        messages.append(message)
    return messages


def fixtures():
    return [codec.reencode(message) for message in sample_messages()]


class O10CodecTests(unittest.TestCase):
    def assert_bad(self, frame, detail=None):
        with self.assertRaises(codec.O10Error) as caught:
            codec.decode(frame)
        self.assertEqual(caught.exception.code, codec.O10_EBADMSG)
        if detail is not None:
            self.assertEqual(caught.exception.detail, detail)

    def test_catalog_roundtrip(self):
        self.assertEqual(set(codec.TYPES), {message["type"] for message in sample_messages()})
        self.assertEqual(len(codec.TYPES), 37)
        for original in sample_messages():
            with self.subTest(message=original["type"]):
                frame = codec.reencode(original)
                self.assertEqual(codec.decode(frame), original)
                self.assertEqual(codec.reencode(codec.decode(frame)), frame)

    def test_version_independent_wire_vector(self):
        frame = bytes.fromhex("13000000a23412000200004f31300000000000")
        self.assertEqual(codec.encode("Tversion", 0x1234, negotiated_msize=512,
                                      version=codec.O10_VERSION), frame)
        self.assertEqual(codec.decode(frame), {"type": "Tversion", "tag": 0x1234,
                                              "negotiated_msize": 512, "version": codec.O10_VERSION})

    def test_restore_offsets_and_max_mutating_request(self):
        frame = codec.encode("Trestore", 0x1234, epoch=1, seq=2, dom=3,
                             inst=bytes(range(16)), img_kernel=4, img_aux=5)
        self.assertEqual(len(frame), 63)
        self.assertEqual(frame[:7], bytes.fromhex("3f000000ae3412"))
        self.assertEqual(frame[7:31], b"\x01" + b"\0" * 7 + b"\x02" + b"\0" * 7 + b"\x03" + b"\0" * 7)
        self.assertEqual(frame[31:47], bytes(range(16)))
        for message in sample_messages():
            if message["type"].startswith("T") and message["type"] not in codec.READ_ONLY:
                self.assertLessEqual(len(codec.reencode(message)), 64)

    def test_unknown_and_9p_types_and_illegal_terror(self):
        for code in list(range(160)) + [160, 198, 199, 200, 255]:
            self.assert_bad(struct.pack("<IBH", 7, code, 0), 4)

    def test_every_truncation_and_surplus_rejected(self):
        for frame in fixtures():
            # Rlstat is intentionally opaque, so length-correct shortening is
            # structurally valid. Truncating a fixed message's fields is not.
            for length in range(len(frame)):
                with self.subTest(code=frame[4], length=length):
                    self.assert_bad(frame[:length])
            self.assert_bad(frame + b"\0")
            if frame[4] != codec.O10_RLSTAT:
                extra = bytearray(frame + b"\0")
                struct.pack_into("<I", extra, 0, len(extra))
                self.assert_bad(extra)

    def test_sizes_and_transport_bound(self):
        frame = fixtures()[0]
        for size in (0, 6, len(frame) - 1, len(frame) + 1, 0xffffffff):
            wrong = bytearray(frame)
            struct.pack_into("<I", wrong, 0, size)
            self.assert_bad(wrong, 0)
        self.assert_bad(struct.pack("<IBH", 513, codec.O10_RLSTAT, 0) + b"x" * 506, 0)
        with self.assertRaises(codec.O10Error):
            codec.decode(frame, msize=len(frame) - 1)
        for msize in (-1, 6, 513, True):
            with self.assertRaises(codec.O10Error):
                codec.decode(frame, msize=msize)

    def test_fixed_bytes_and_integer_boundaries(self):
        kwargs = dict(dom=1, inst=bytes(16))
        for inst in (bytes(15), bytes(17), "abcdefghijklmnop"):
            with self.assertRaises(codec.O10Error):
                codec.encode("Tstart", epoch=1, seq=1, **dict(kwargs, inst=inst))
        for dom in (-1, 1 << 64, True, "1"):
            with self.assertRaises(codec.O10Error):
                codec.encode("Tstat", epoch=1, seq=0, dom=dom)
        for tag in (-1, 1 << 16, True):
            with self.assertRaises(codec.O10Error):
                codec.encode("Rflush", tag)
        with self.assertRaises(codec.O10Error):
            codec.encode("Tversion", negotiated_msize=512, version=b"O10")

    def test_exact_field_set_and_prefix(self):
        for kwargs in ({}, {"dom": 1, "extra": 2}):
            with self.assertRaises(codec.O10Error):
                codec.encode("Tstat", epoch=1, seq=0, **kwargs)
        for kwargs in ({"dom": 1}, {"dom": 1, "epoch": 1}, {"dom": 1, "seq": 0}):
            with self.assertRaises(codec.O10Error):
                codec.encode("Tstat", **kwargs)
        with self.assertRaises(codec.O10Error):
            codec.encode("Rflush", epoch=1, seq=0)
        with self.assertRaises(codec.O10Error):
            codec.encode("Tstat", epoch=1, seq=1, dom=1)
        frame = bytearray(codec.encode("Tstat", epoch=1, seq=0, dom=1))
        struct.pack_into("<Q", frame, 15, 1)
        self.assert_bad(frame, 15)

    def test_variable_lengths_and_event_padding(self):
        reply = codec.encode("Rflush")
        frame = codec.encode("Routcome", state=1, code=0, reply=reply)
        self.assertEqual(codec.decode(frame)["reply"], reply)
        wrong = bytearray(frame)
        struct.pack_into("<H", wrong, 12, len(reply) + 1)
        self.assert_bad(wrong)
        event = {"cursor": 1, "type": 2, "flags": 0, "dom": 3, "lease": 4, "arg0": 5, "arg1": 6}
        frame = codec.encode("Rwait", next=11, events=[event] * 10)
        self.assertEqual(len(frame), 497)
        self.assertEqual(len(codec.decode(frame)["events"]), 10)
        with self.assertRaises(codec.O10Error):
            codec.encode("Rwait", next=12, events=[event] * 11)
        frame = bytearray(codec.encode("Rwait", next=2, events=[event]))
        frame[29] = 1
        self.assert_bad(frame, 29)
        frame[29] = 0
        struct.pack_into("<H", frame, 15, 2)
        self.assert_bad(frame, 15)
        self.assertEqual(codec.decode(codec.encode("Rwait", next=0, events=[]))["events"], [])

    def test_snapshot_mutable_input_and_opaque_lstat(self):
        frame = bytearray(codec.encode("Rlstat", record=b"\0\x80opaque"))
        decoded = codec.decode(frame)
        frame[-1] = 0
        self.assertEqual(decoded["record"], b"\0\x80opaque")
        self.assertEqual(codec.decode(codec.encode("Rlstat", record=b""))["record"], b"")


if __name__ == "__main__":
    unittest.main()
