"""Exercise timeout budgets in actual client requests without a guest VM.

The production CLI and API publish into the existing temporary client fixture;
the fixture only supplies valid protocol replies. This does not qualify an
original compiler, a native provider or elapsed timeout enforcement.
"""
from __future__ import annotations

import subprocess
import sys
import unittest

from tests import test_plan9_linux_client as fixtures


class P9TimeoutDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.Plan9LinuxClientTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def cli(self, *options):
        fixture = self.fixture
        return subprocess.run(
            [sys.executable, "-B", str(fixtures.CLIENT_PATH),
             "--control-dir", str(fixture.control),
             "--protocol", str(fixture.installed_protocol()),
             "--cwd", str(fixture.cwd), *options, "--", "echo", "budget"],
            input=b"", capture_output=True, timeout=3,
        )

    def assert_cli_budget(self, expected, *options):
        fixture = self.fixture

        def provider():
            directory, wire, request = fixture.request()
            self.assertEqual(request.timeout_ms, expected)
            self.assertEqual(request.argv, ("/arm64/bin/echo", "budget"))
            fixture.complete(directory, wire)

        server = fixtures.Task(provider)
        try:
            result = self.cli(*options)
        finally:
            server.join()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        self.assertFalse((fixture.control / "pending.json").exists())

    def test_real_cli_default_publishes_120_second_request(self):
        self.assert_cli_budget(120_000)

    def test_api_default_remains_30_second_request(self):
        fixture = self.fixture

        def provider(directory, wire, request):
            self.assertEqual(request.timeout_ms, 30_000)
            fixture.complete(directory, wire)

        completion = fixture.with_provider(provider)
        self.assertEqual(completion.exit_code, 0)
        self.assertFalse((fixture.control / "pending.json").exists())

    def test_real_cli_explicit_budget_and_wire_maximum(self):
        self.assertEqual(fixtures.protocol.MAX_TIMEOUT_MS, 300_000)
        for budget in (1_234, fixtures.protocol.MAX_TIMEOUT_MS):
            with self.subTest(timeout_ms=budget):
                self.assert_cli_budget(budget, "--timeout-ms", str(budget))

    def test_real_cli_budget_above_wire_maximum_is_rejected_before_publication(self):
        result = self.cli("--timeout-ms", str(fixtures.protocol.MAX_TIMEOUT_MS + 1))
        self.assertEqual(result.returncode, 125)
        self.assertIn(b"timeout", result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertFalse([path for path in self.fixture.service.glob("r*") if path.is_dir()])
        self.assertFalse((self.fixture.control / "pending.json").exists())


if __name__ == "__main__":
    unittest.main()
