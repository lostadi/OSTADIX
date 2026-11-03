"""Compare the production vGIC with the exact qualified R8 component.

The immutable baseline is a source fixture, not another runtime provider. Both
modules are actually compiled; only saved LR/CPU-interface/APR effects are
modeled by a native C fixture. Read-only introspection is appended in temporary
copies to compare otherwise private software state. No VM is launched and
these timings do not qualify user-visible guest latency.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ocore/runtime/aarch64/unified_gic.oc"
BASELINE = ROOT / "tests/fixtures/unified_gic_r8.oc.txt"
HARNESS = ROOT / "tests/fixtures/unified_gic_differential.c"
BASELINE_SHA256 = "8b6e45a7ae1e63ade86d6be650aea6ba0076ae8630d29067bd17cda1e1f795a7"

INSPECTION = """
// Read-only private fixture introspection, never added to production sources.
pub unsafe fn test_inspect(domain: u64, kind: u64, index: u64) -> u64 {
    if kind == 0 { if index == 0 { return READY; } return LRS; }
    if kind == 1 { return ERROR[domain as usize]; }
    if kind == 2 { return DIAGNOSTIC[domain as usize]; }
    if kind == 3 { return CONTROL[domain as usize]; }
    if kind == 4 { return WAKER[domain as usize]; }
    if kind == 10 { return ENABLED[item(domain,index)] as u64; }
    if kind == 11 { return GROUP[item(domain,index)] as u64; }
    if kind == 12 { return EDGE[item(domain,index)] as u64; }
    if kind == 13 { return PRIORITY[item(domain,index)] as u64; }
    if kind == 14 { return LEVEL[item(domain,index)] as u64; }
    if kind == 15 { return LATCH[item(domain,index)] as u64; }
    if kind == 16 { return ACTIVE[item(domain,index)] as u64; }
    if kind == 17 { return HARD_ACTIVE[item(domain,index)] as u64; }
    if kind == 18 { return ACTIVE_PRIORITY[item(domain,index)] as u64; }
    if kind == 20 { return ROUTE[item(domain,index)]; }
    if kind == 21 { return LR_OWNER[slot(domain,index)]; }
    if kind == 22 { return LR_SOFT[slot(domain,index)] as u64; }
    return BAD;
}
"""


@unittest.skipUnless(platform.system() == "Linux" and platform.machine() == "x86_64",
                     "production fixture requires Linux x86_64")
class UnifiedGicHotpathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = Path(os.environ.get("OCOREC_BIN", str(ROOT / "target/debug/ocorec")))
        clang = shutil.which("clang")
        if not compiler.is_file() or clang is None:
            raise unittest.SkipTest("already-built ocorec and clang are required")
        baseline = BASELINE.read_bytes()
        if hashlib.sha256(baseline).hexdigest() != BASELINE_SHA256:
            raise AssertionError("qualified R8 baseline fixture identity changed")
        temporary = tempfile.TemporaryDirectory(prefix="unified-native-gic-hotpath-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        current = cls.directory / "current.oc"
        reference = cls.directory / "reference.oc"
        current.write_text(SOURCE.read_text() + INSPECTION)
        reference.write_text(baseline.decode().replace(
            "module runtime::aarch64::unified_gic;",
            "module runtime::aarch64::unified_gic_baseline;", 1) + INSPECTION)
        cls.executable = cls.directory / "test"
        commands = [
            [str(compiler), str(SOURCE), "--target", "aarch64-unknown-none",
             "--emit", "mir", "-o", str(cls.directory / "production-arm.mir")],
            [str(compiler), str(reference), "--target", "aarch64-unknown-none",
             "--emit", "mir", "-o", str(cls.directory / "reference-arm.mir")],
        ]
        for name, source in (("current", current), ("reference", reference)):
            commands.append([str(compiler), str(source), "--target", "x86_64-unknown-none",
                             "--emit", "obj", "-o", str(cls.directory / (name + ".o"))])
        commands.append([clang, "-O2", "-no-pie", str(HARNESS),
                         str(cls.directory / "current.o"), str(cls.directory / "reference.o"),
                         "-o", str(cls.executable)])
        for command in commands:
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)

    def test_randomized_production_state_and_hardware_lr_transitions_match_r8(self):
        result = subprocess.run([str(self.executable)], text=True, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        evidence = json.loads(result.stdout)
        self.assertTrue(evidence["ok"])
        self.assertEqual(evidence["transitions"], 25200)
        self.assertGreater(evidence["comparisons"], 40000000)
        self.assertGreater(evidence["hardware_acks"], 100)
        self.assertGreater(evidence["hardware_eois"], 100)
        self.assertEqual(evidence["corruption_scenarios"], 6)
        self.assertEqual(evidence["lr_counts"], [1, 4, 16])

    def test_idle_callbacks_preserve_state_and_check_hardware_without_lr_rewrites(self):
        result = subprocess.run([str(self.executable), "--hotpath"], text=True,
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("dirty invalidation and hardware transitions: PASS", result.stdout)
        samples = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        self.assertEqual(len(samples), 6)
        for sample in samples:
            self.assertEqual(sample["iterations"], 100000)
            self.assertGreater(sample["cpu_ns"], 0)
            baseline = sample["variant"] == 0
            if sample["mode"] == "unchanged-poll":
                self.assertEqual(sample["reads"], 400000)
                self.assertEqual(sample["writes"], 400000 if baseline else 0)
            elif sample["mode"] == "unchanged-level":
                self.assertEqual(sample["reads"], 400000 if baseline else 0)
                self.assertEqual(sample["writes"], 400000 if baseline else 0)
            else:
                self.assertEqual(sample["mode"], "idle-exit-bundle")
                self.assertEqual(sample["reads"], 5200000 if baseline else 800000)
                self.assertEqual(sample["writes"], 5200000 if baseline else 0)


if __name__ == "__main__":
    unittest.main()
