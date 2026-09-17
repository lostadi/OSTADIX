"""Contract tests for the bounded JavaScript backend-runtime benchmark."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "benchmarks" / "backend_runtime" / "run.py"
FIXTURE_DIR = RUNNER.parent


class BackendRuntimeBenchmarkTests(unittest.TestCase):
    def write_executable(self, path: Path, source: str) -> None:
        path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
        path.chmod(0o755)

    def fixture_environment(self, directory: Path) -> tuple[Path, Path, dict[str, str]]:
        fake_o = directory / "O"
        self.write_executable(
            fake_o,
            r"""
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys
            import time

            if sys.argv[1:] == ["version", "--json"]:
                print(json.dumps({"schema": "ostadix.version-report/v1", "fake": True}))
                raise SystemExit(0)
            if os.environ.get("FAKE_O_SLEEP"):
                time.sleep(60)
            fixture = Path(sys.argv[-2]).name
            if fixture == "javascript_cold1.O":
                value = {"t": "number", "v": {"kind": "int", "v": "1"}}
                result_type = "number"
                elapsed = 1
            elif fixture == "javascript_warm10.O":
                value = {"t": "number", "v": {"kind": "int", "v": "10"}}
                result_type = "number"
                elapsed = 10
            elif fixture == "javascript_output_1mib.O":
                length = 1048575 if os.environ.get("FAKE_O_DIVERGE") else 1048576
                value = {
                    "t": "text",
                    "v": {"utf8": "x" * length, "encoding": "utf-8"},
                }
                result_type = "text"
                elapsed = 2
            else:
                raise SystemExit(f"unexpected fixture: {fixture}")
            print(json.dumps({
                "ok": True,
                "value": value,
                "type": result_type,
                "elapsed_ms": elapsed,
            }, separators=(",", ":")))
            """,
        )
        fake_node = directory / "node"
        self.write_executable(
            fake_node,
            """
            #!/bin/sh
            if [ "$1" = --version ]; then
                printf '%s\n' v-test
                exit 0
            fi
            exit 64
            """,
        )
        backends = directory / "backends"
        backends.mkdir()
        javascript_shim = backends / "javascript_shim.py"
        self.write_executable(javascript_shim, "#!/usr/bin/env python3\n")
        (backends / "o_shim_common.py").write_text("# test fixture\n", encoding="utf-8")
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{directory}{os.pathsep}{environment.get('PATH', '')}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return fake_o, backends, environment

    def run_benchmark(
        self,
        directory: Path,
        *,
        warmups: int = 1,
        repetitions: int = 2,
        timeout: float = 5,
        environment_updates: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        fake_o, backends, environment = self.fixture_environment(directory)
        if environment_updates:
            environment.update(environment_updates)
        return subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--o-bin",
                str(fake_o),
                "--backends-dir",
                str(backends),
                "--warmups",
                str(warmups),
                "--repetitions",
                str(repetitions),
                "--timeout-seconds",
                str(timeout),
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )

    def test_fixtures_are_exact_bounded_javascript_shapes(self) -> None:
        cold = (FIXTURE_DIR / "javascript_cold1.O").read_text(encoding="utf-8")
        warm = (FIXTURE_DIR / "javascript_warm10.O").read_text(encoding="utf-8")
        large = (FIXTURE_DIR / "javascript_output_1mib.O").read_text(encoding="utf-8")
        self.assertEqual(cold.count("javascript[0]^("), 1)
        self.assertEqual(warm.count("javascript[0]^("), 10)
        self.assertIn("console.log(n8 + 1)", warm)
        self.assertEqual(large.count("javascript[0]^("), 1)
        self.assertIn('process.stdout.write("x".repeat(1048576))', large)
        for source in (cold, warm, large):
            self.assertNotIn("setTimeout", source)
            self.assertNotIn("sleep", source)

    def test_runner_emits_raw_compact_semantically_checked_measurements(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            result = self.run_benchmark(Path(raw_directory))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("x" * 1024, result.stdout)
        document = json.loads(result.stdout)
        self.assertEqual(document["schema"], "ostadix.backend-runtime-benchmark/v1")
        self.assertEqual(
            document["configuration"]["cases"],
            [
                "javascript_cold1",
                "javascript_warm10",
                "javascript_output_1mib",
            ],
        )
        self.assertEqual(len(document["samples"]["warmup"]), 1)
        self.assertEqual(len(document["samples"]["measured"]), 2)
        self.assertEqual(
            document["samples"]["measured"][0]["order"],
            [
                "javascript_warm10",
                "javascript_output_1mib",
                "javascript_cold1",
            ],
        )
        for case in document["configuration"]["cases"]:
            wall = document["measurements"][case]["wall_time"]
            self.assertEqual(wall["unit"], "ns")
            self.assertEqual(wall["count"], 2)
            self.assertEqual(len(wall["raw"]), 2)
            self.assertIn("median", wall)
            self.assertIn("median_absolute_deviation", wall)
        large = document["expected_semantics"]["javascript_output_1mib"]
        self.assertEqual(large["payload_bytes"], 1024 * 1024)
        self.assertRegex(large["payload_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(document["semantics"]["all_samples_match_checked_oracles"])
        self.assertEqual(document["semantics"]["checked_groups"], 3)
        self.assertEqual(document["provenance"]["node"]["version"], "v-test")
        self.assertEqual(
            document["provenance"]["execution_model"],
            {
                "catalog_adapter": "NativeRust",
                "per_operation_component": "fresh Node.js process",
                "persistent_component": "O --o-backend javascript proxy",
                "python_compatibility_shim_executed": False,
            },
        )
        self.assertNotIn("javascript_shim", document["provenance"]["artifacts"])
        compatibility = document["provenance"]["compatibility_files_not_executed"]
        self.assertEqual(
            compatibility["javascript_python_shim"]["execution_role"],
            "compatibility/archive; not selected by NativeRust",
        )

    def test_large_output_semantic_divergence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            result = self.run_benchmark(
                Path(raw_directory),
                warmups=0,
                repetitions=1,
                environment_updates={"FAKE_O_DIVERGE": "1"},
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("payload differs from its checked length/digest oracle", result.stderr)

    def test_timeout_is_bounded_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            started = time.monotonic()
            result = self.run_benchmark(
                Path(raw_directory),
                warmups=0,
                repetitions=1,
                timeout=0.1,
                environment_updates={"FAKE_O_SLEEP": "1"},
            )
            duration = time.monotonic() - started
        self.assertEqual(result.returncode, 2)
        self.assertLess(duration, 3)
        self.assertIn("command timed out after 0.1s", result.stderr)


if __name__ == "__main__":
    unittest.main()
