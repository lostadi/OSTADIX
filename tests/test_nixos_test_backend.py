"""NixOS caller budgets and retained partial timeout diagnostics across editions."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backends"))
import o_shim_common as wire
from o_lang.backends import nixos_test_backend as reference

NAME = "O_NIXOS_TEST_TIMEOUT_SECONDS"
SHIMS = (
    ROOT / "backends/nixos_test_shim.py",
    ROOT / "crates/ostadix-api/backends/nixos_test_shim.py",
)


def load_shim(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(wire, "command_loop"):
        spec.loader.exec_module(module)
    return module


class NixOSTestBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.targets = [("reference", reference)] + [
            (f"shim-{index}", load_shim(path, f"nixos_timeout_shim_{index}"))
            for index, path in enumerate(SHIMS)
        ]

    def invoke(self, module):
        if module is reference:
            return module.NixOSTestBackend().evaluate("{ nodes = {}; }", None)
        return module.run_nixos_test("{ nodes = {}; }")

    def test_external_and_embedded_shims_match(self):
        self.assertEqual(SHIMS[0].read_bytes(), SHIMS[1].read_bytes())

    def test_default_fractional_and_long_budgets_reach_nix(self):
        for name, module in self.targets:
            for raw, seconds in ((None, 600), ("0.125", 0.125), ("86400", 86400)):
                environment = {} if raw is None else {NAME: raw}
                with self.subTest(target=name, budget=raw), \
                        mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch("platform.system", return_value="Linux"), \
                        mock.patch.object(wire, "admitted_tool_path", return_value="nix"), \
                        mock.patch.object(module.subprocess, "run") as launch:
                    launch.return_value = subprocess.CompletedProcess(
                        ["nix"], 0, "/nix/store/test-output\n", "driver completed"
                    )
                    # Shim imports its resolver directly.
                    resolver = mock.patch.object(module, "nix_command", return_value="nix") \
                        if module is not reference else mock.patch("builtins.open", side_effect=OSError)
                    with resolver:
                        result = self.invoke(module)
                    self.assertEqual(launch.call_args.kwargs["timeout"], seconds)
                    if module is reference:
                        self.assertEqual(result.get("store_path").path, "/nix/store/test-output")
                        self.assertTrue(result.get("success").value)
                    else:
                        self.assertEqual(result["v"]["store_path"]["path"], "/nix/store/test-output")
                        self.assertTrue(result["v"]["success"]["v"])

    def test_invalid_budget_rejected_before_resolution_or_execution(self):
        invalid = ("", " ", "zero", "0", "-1", "nan", "NaN", "inf", "-inf", "1e999")
        for name, module in self.targets:
            for raw in invalid:
                with self.subTest(target=name, budget=raw), \
                        mock.patch.dict(os.environ, {NAME: raw}), \
                        mock.patch.object(module.subprocess, "run") as launch:
                    if module is reference:
                        with self.assertRaisesRegex(ValueError, NAME):
                            self.invoke(module)
                    else:
                        with mock.patch.object(module, "nix_command") as resolve:
                            with self.assertRaisesRegex(ValueError, NAME):
                                self.invoke(module)
                            resolve.assert_not_called()
                    launch.assert_not_called()

    def test_budget_is_read_for_each_invocation(self):
        for name, module in self.targets:
            with self.subTest(target=name):
                with mock.patch.dict(os.environ, {NAME: "7"}):
                    self.assertEqual(module.nixos_test_timeout_seconds(), 7)
                with mock.patch.dict(os.environ, {NAME: "19"}):
                    self.assertEqual(module.nixos_test_timeout_seconds(), 19)

    def test_timeout_retains_partial_streams_and_completion_uncertainty(self):
        for name, module in self.targets:
            for stdout, stderr in ((b"output\xff", b"kernel boot"), ("output", "kernel boot"), (None, None)):
                with self.subTest(target=name, stdout=stdout), \
                        mock.patch.dict(os.environ, {NAME: "12.5"}), \
                        mock.patch("platform.system", return_value="Linux"), \
                        mock.patch.object(module.subprocess, "run") as launch:
                    expired = subprocess.TimeoutExpired(["nix"], 12.5, output=stdout, stderr=stderr)
                    launch.side_effect = expired
                    resolver = mock.patch.object(module, "nix_command", return_value="nix") \
                        if module is not reference else mock.patch("builtins.open", side_effect=OSError)
                    with resolver, self.assertRaises(RuntimeError) as caught:
                        self.invoke(module)
                    message = str(caught.exception)
                    self.assertIn("timed out after 12.5 seconds", message)
                    self.assertIn("completion of daemon-side builds is unknown", message)
                    self.assertIn("PARTIAL STDERR:", message)
                    self.assertIn("PARTIAL STDOUT:", message)
                    if stdout is not None:
                        self.assertIn("output", message)
                        self.assertIn("kernel boot", message)
                    self.assertIs(caught.exception.__cause__, expired)

    def test_nonzero_exit_preserves_both_streams(self):
        for name, module in self.targets:
            with self.subTest(target=name), \
                    mock.patch("platform.system", return_value="Linux"), \
                    mock.patch.dict(os.environ, {NAME: "600"}), \
                    mock.patch.object(module.subprocess, "run", return_value=
                        subprocess.CompletedProcess(["nix"], 17, "partial result", "test assertion")):
                resolver = mock.patch.object(module, "nix_command", return_value="nix") \
                    if module is not reference else mock.patch("builtins.open", side_effect=OSError)
                with resolver, self.assertRaises(RuntimeError) as caught:
                    self.invoke(module)
                self.assertIn("exit 17", str(caught.exception))
                self.assertIn("partial result", str(caught.exception))
                self.assertIn("test assertion", str(caught.exception))

    def test_real_shim_protocol_preserves_timeout_output(self):
        with tempfile.TemporaryDirectory() as directory:
            tool = Path(directory) / "nix"
            tool.write_text(f"#!{sys.executable}\n" +
                            "import sys,time\nprint('partial-out',flush=True)\n"
                            "print('partial-err',file=sys.stderr,flush=True)\ntime.sleep(60)\n")
            tool.chmod(0o755)
            # Exercise the shim's real declared-executable resolver. This is
            # an adapter protocol fixture, not evidence of native admission.
            manifest = {
                "schema": "oexec.direct-executable-manifest/v1",
                "artifacts": [{
                    "role": "direct-launcher", "logical_command": "nix",
                    "invocation_path": str(tool.absolute()),
                    "canonical_path": str(tool.resolve()),
                    "invocation_file_identity": wire._identity_from_stat(tool.lstat()),
                    "file_identity": wire._identity_from_stat(tool.resolve().stat()),
                }],
            }
            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ.get("PATH", ""),
                               O_NIXOS_TEST_TIMEOUT_SECONDS="2", NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM="1",
                               O_ADMITTED_EXECUTABLE_MANIFEST=json.dumps(manifest))
            request = wire.cbor_encode({"cmd": "exec", "code": "{ nodes = {}; }", "bindings": {}})
            for shim in SHIMS:
                with self.subTest(shim=shim):
                    completed = subprocess.run(
                        [sys.executable, str(shim)], input=len(request).to_bytes(4, "big") + request,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=15,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    import io
                    response = wire.read_wire_message(io.BytesIO(completed.stdout))
                    self.assertEqual(response["status"], "err", response)
                    for text in ("timed out after 2 seconds", "partial-out", "partial-err"):
                        self.assertIn(text, response["message"])


if __name__ == "__main__":
    unittest.main()
