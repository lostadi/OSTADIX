"""Bind the Linux-private PL011 into the actual unified build contract.

The reused builder fixture replaces external compilation/original admission;
these checks prove geometry and manifest/DTS validation, not live guest boot.
"""
import copy
from pathlib import Path
import unittest

from tests import test_unified_world_profile as fixture


EXPECTED = {"guest_address": 0x09001000, "guest_irq": 51,
            "input_address": 0x6d060000, "input_bytes": 8192,
            "output_address": 0x6d080000, "output_bytes": 65536}


class UnifiedCoordinatorProfileTests(unittest.TestCase):
    def setUp(self):
        fixture.UnifiedWorldProfileTests.setUpClass()
        self.addCleanup(fixture.UnifiedWorldProfileTests.doClassCleanups)
        self.profile = fixture.UnifiedWorldProfileTests.profile
        self.output = fixture.UnifiedWorldProfileTests.output

    def test_private_ranges_and_exact_profile_cannot_be_reassigned(self):
        self.assertEqual(self.profile["coordinator_uart"], EXPECTED)
        fixture.RUNNER.validate_profile(self.profile)
        regions = [(EXPECTED["input_address"], EXPECTED["input_bytes"] + 8),
                   (EXPECTED["output_address"], EXPECTED["output_bytes"] + 8)]
        existing = [(domain["guest_ram_pa"], domain["guest_ram_bytes"])
                    for domain in self.profile["domains"]]
        existing += [(0x6c000000, 0x1000000), (0x6d000000, 0x100),
                     (0x6d010000, 4104), (0x6d020000, 65544),
                     (0x6d040000, 65544), (0x6e000000, 0x200000),
                     (0x70000000, 0x40000000)]
        for base, size in regions:
            for other, length in existing:
                self.assertFalse(base < other + length and other < base + size)
            for domain in self.profile["domains"]:
                ipa, length = domain["guest_ram_ipa"], domain["guest_ram_bytes"]
                self.assertFalse(ipa <= base < ipa + length)
        self.assertLessEqual(regions[0][0] + regions[0][1], regions[1][0])
        for key in EXPECTED:
            changed = copy.deepcopy(self.profile)
            changed["coordinator_uart"][key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                fixture.RUNNER.validate_profile(changed)

    def test_linux_dts_clocks_irq_and_native_source_are_bound(self):
        dts = (self.output / "linux.dts").read_text()
        begin = dts.index("    pl011@9001000 {")
        end = dts.index("    };", begin)
        node = dts[begin:end]
        self.assertIn('compatible = "arm,pl011", "arm,primecell";', node)
        self.assertIn("reg = <0 0x09001000 0 0x1000>;", node)
        self.assertIn("interrupts = <0 19 4>;", node)
        self.assertIn("clocks = <&clock>, <&clock>;", node)
        self.assertIn('clock-names = "uartclk", "apb_pclk";', node)
        self.assertLess(dts.index("    pl011@9000000 {"), begin)
        self.assertIn('stdout-path = "/pl011@9000000";', dts)
        source = "ocore/runtime/aarch64/coordinator_uart.oc"
        captured = self.profile["source_artifacts"][source]
        fixture.RUNNER.checked(self.output / captured["path"], captured)
        self.assertEqual(captured["sha256"], self.profile["source_sha256"][source])
        self.assertEqual(captured["sha256"], fixture.BUILDER.fingerprint(Path(fixture.ROOT) / source))
        for marker in ('    pl011@9000000 {', '    virtio_mmio@a000000 {'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                fixture.BUILDER.linux_dts(fixture.UnifiedWorldProfileTests.template.replace(marker, ""), 1)


if __name__ == "__main__":
    unittest.main()
