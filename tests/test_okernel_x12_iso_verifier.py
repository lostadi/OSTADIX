"""Screen parsing regression; this does not launch or qualify an ISO boot."""
import hashlib
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "x12_iso_verifier_tests", ROOT / "scripts/verify_okernel_x12_iso.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

TOKEN = "185fbfd05f74964df3ce"
DIGEST = "0b2ddb2f98cb1e8b8582e7ba5966d6f6cfbc8816526f51e3573786fafb0a4fc0"

# Exact bytes 52992:53689 of acceptance-fixed-clock-1/console.log, whose SHA256
# is 50a1eefc28ad3eda960e87f5277ddfd882809a6b734e0b91c4fe152d549aa3fc.
# Kept inline so regression tests do not depend on a host's retained VM logs.
CAPTURED_APPLICATION = (
    b'0b2ddb2f98cb1e8b8582e7ba5966d6f6cfbc8816526f51e3573786fafb0a4fc0  /n/oke'
    b'rnel/wor\x1b[23;1H\x1b[1;23r\x1b[23;1H\nk\x1b[K\x1b[1;24r\x1b[23;2H/iso-185fbfd05f74964df3c'
    b'e\r\x1b[1;23r\x1b[23;1H\n\x1b[K\x1b[1;24r\x1b[23;1H0b2ddb2f98cb1e8b8582e7ba5966d6f6cfbc88'
    b'16526f51e3573786fafb0a4fc0  /work/iso-p9-1\x1b[23;1H\x1b[1;23r\x1b[23;1H\n8\x1b[K\x1b[1;'
    b'24r\x1b[23;2H5fbfd05f74964df3ce\r\x1b[1;23r\x1b[23;1H\n\x1b[K\x1b[1;24r\x1b[23;1H\x1b[7m\r\n[oker'
    b'nel-u0:console*                          "okernel-x12-live" 23:20 05-Nov'
    b'-26\x1b[m\x0f\x1b[23;1H\x1b[7m\r\n[okernel-u0:console*                          "okern'
    b'el-x12-live" 23:21 05-Nov-26\x1b[m\x0f\x1b[23;1HO\x1b[1;23r\x1b[23;1H\n\x1b[22;2HKERNEL_ISO'
    b'_SOURCE_185fbfd05f74964df3ce\r\n\x1b[K\x1b[1;24r\x1b[23;1H\x1b[1;23r\x1b[23;1H\n\x1b[K\x1b[1;24r'
    b'\x1b[23;1HOKERNEL_ISO_COMMAND_185fbfd05f74964df3ce:0'
)


class X12ApplicationScreenGate(unittest.TestCase):
    def text(self):
        return verifier.terminal_text(CAPTURED_APPLICATION)

    def test_actual_tmux_redraw_advances_to_the_saved_raw_log_audit(self):
        self.assertEqual(len(CAPTURED_APPLICATION), 697)
        self.assertEqual(hashlib.sha256(CAPTURED_APPLICATION).hexdigest(),
                         "367f97c30f48553ea5efaa8f8dc7c6130f6ce6f33e949def44fc401313a3f74a")
        text = self.text()
        self.assertNotIn(("OKERNEL_ISO_SOURCE_" + TOKEN).encode(), text)
        self.assertIn(("O\nKERNEL_ISO_SOURCE_" + TOKEN).encode(), text)
        self.assertTrue(verifier.application_output_ready(text, TOKEN, DIGEST))

    def test_nonzero_status_still_fails_with_both_matching_checksums(self):
        marker = ("OKERNEL_ISO_COMMAND_" + TOKEN + ":0").encode()
        for status in (1, 125):
            with self.subTest(status=status), self.assertRaisesRegex(RuntimeError, "command failed"):
                text = self.text().replace(marker, marker[:-1] + str(status).encode())
                verifier.application_output_ready(text, TOKEN, DIGEST)

    def test_missing_either_checksum_still_fails(self):
        for count in (0, 1):
            with self.subTest(checksum_count=count), self.assertRaisesRegex(RuntimeError, "command failed"):
                text = self.text().replace(DIGEST.encode(), b"wrong checksum", 2 - count)
                verifier.application_output_ready(text, TOKEN, DIGEST)

    def test_echo_and_another_nonce_do_not_complete_the_command(self):
        text = self.text()
        marker = ("OKERNEL_ISO_COMMAND_" + TOKEN + ":0").encode()
        self.assertFalse(verifier.application_output_ready(
            text.replace(marker, marker[:-1] + b"%s"), TOKEN, DIGEST))
        self.assertFalse(verifier.application_output_ready(text, "another-nonce", DIGEST))


if __name__ == "__main__": unittest.main()
