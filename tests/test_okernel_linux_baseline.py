"""Execute real host Linux workloads/accounting; no candidate or VM is mocked."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/benchmark_okernel_linux_baseline.py"
SPEC = importlib.util.spec_from_file_location("okernel_linux_baseline_test", SCRIPT)
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "wait4"), "Linux wait4 required")
class LinuxBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="Linux baseline test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_real_workloads_all_samples_outputs_medians_and_temporary_cleanup(self):
        if shutil.which("cc") is None:
            self.skipTest("original host C compiler required")
        output = self.root / "new evidence"
        sentinel = self.root / "user-file"
        sentinel.write_bytes(b"must remain untouched")
        command = [sys.executable, "-B", str(SCRIPT), "--output", str(output), "--repetitions", "2", "--bytes", "4096"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        record = json.loads((output / "result.json").read_text())
        self.assertTrue(record["passed"])
        self.assertTrue(record["owned_temporary_workspaces_removed"])
        self.assertTrue(record["tools_unchanged"])
        self.assertFalse(any(record["qualification"].values()))
        self.assertEqual(set(record["workloads"]), {"shell_startup", "file_io", "shell_pipeline", "compile_link_execute"})
        pids = []
        for name, workload in record["workloads"].items():
            samples = workload["samples"]
            self.assertEqual(len(samples), 2)
            expected = [item["elapsed_ns"] for item in samples]
            self.assertEqual(workload["summary"]["elapsed_ns"]["values"], expected)
            self.assertEqual(workload["summary"]["elapsed_ns"]["median"], statistics.median(expected))
            self.assertEqual(workload["summary"]["elapsed_ns"]["p50"], statistics.median(expected))
            self.assertEqual(workload["summary"]["elapsed_ns"]["p95"], max(expected))
            for item in samples:
                self.assertEqual(item["exit_status"], 0)
                self.assertFalse(item["timed_out"])
                self.assertTrue(item["output_verified"])
                self.assertGreater(item["wait4_child_reported_maxrss_bytes"], 0)
                self.assertEqual(item["wait4_child_reported_maxrss_bytes"] % 1024, 0)
                self.assertFalse(Path(item["cwd"]).exists())
                self.assertTrue(Path(item["stdout_file"]["path"]).is_file())
                pids.append(item["child_pid"])
        self.assertEqual(len(set(pids)), 8)
        self.assertEqual(record["tools"]["sh"]["identity"]["path"], str(Path("/bin/sh").resolve()))
        self.assertIn("not simultaneous aggregate", record["memory_measurement"]["meaning"])
        self.assertIn("inherited Python", record["memory_measurement"]["python_parent_launch_floor"])
        self.assertTrue(record["quantile_method"]["all_sample_values_retained"])
        self.assertEqual(record["driver"]["sha256"], hashlib.sha256((output / "driver.py").read_bytes()).hexdigest())
        self.assertEqual(sentinel.read_bytes(), b"must remain untouched")
        expected_hash = hashlib.sha256(bytes(range(256)) * 16).hexdigest()
        self.assertEqual(record["workloads"]["file_io"]["samples"][0]["validation"]["sha256"], expected_hash)
        self.assertEqual(record["workloads"]["compile_link_execute"]["samples"][0]["stdout"], baseline.c_oracle(4096))

    def test_wait4_peak_is_per_run_not_cumulative_previous_child_maximum(self):
        # A large outer test process can lend both children its fork/pre-exec
        # RSS floor. A fresh exec keeps the measurement controller's current
        # memory small before it launches these two real, independently waited
        # children; its own inherited historical peak is not the metric.
        controller = r'''
import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("fresh_linux_baseline",sys.argv[1])
baseline=importlib.util.module_from_spec(spec);spec.loader.exec_module(baseline)
root=Path(sys.argv[2])
large=baseline.measured_run([sys.executable,"-c","data=bytearray(48*1024*1024);print(len(data))"],
                            root,root/"logs","large")
small=baseline.measured_run(["/bin/sh","-c","exit 0"],root,root/"logs","small")
print(json.dumps({"large":large,"small":small}))
'''
        completed = subprocess.run([sys.executable, "-B", "-c", controller, str(SCRIPT), str(self.root)],
                                   capture_output=True, text=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        samples = json.loads(completed.stdout)
        large, small = samples["large"], samples["small"]
        self.assertEqual(large["exit_status"], 0)
        self.assertEqual(small["exit_status"], 0)
        self.assertEqual(large["stdout"], str(48 * 1024 * 1024) + "\n")
        self.assertFalse(large["timed_out"] or small["timed_out"])
        self.assertGreaterEqual(large["wait4_child_reported_maxrss_bytes"], 48 * 1024 * 1024)
        self.assertLess(small["wait4_child_reported_maxrss_bytes"], large["wait4_child_reported_maxrss_bytes"], samples)
        self.assertNotEqual(large["child_pid"], small["child_pid"])

    def test_timeout_reaps_only_the_owned_child_group(self):
        sample = baseline.measured_run([sys.executable, "-c", "import time;time.sleep(5)"],
                                       self.root, self.root / "logs", "timeout", timeout=.05)
        self.assertTrue(sample["timed_out"])
        self.assertEqual(sample["exit_status"], -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            os.wait4(sample["child_pid"], os.WNOHANG)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_existing_output_and_out_of_range_parameters_are_rejected(self):
        for extra, text in ((["--output", str(self.root)], "new directory"),
                            (["--output", str(self.root / "new"), "--repetitions", "0"], "repetitions"),
                            (["--output", str(self.root / "new"), "--bytes", "16777217"], "bytes")):
            result = subprocess.run([sys.executable, "-B", str(SCRIPT), *extra], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn(text, result.stderr)
        self.assertFalse((self.root / "new").exists())

    def test_defined_quantiles_keep_raw_values_and_nearest_rank_p95(self):
        values = [9, 1, 7, 3, 5, 2, 4]
        result = baseline.quantiles(values)
        self.assertEqual(result["values"], values)
        self.assertEqual(result["p50"], 4)
        self.assertEqual(result["p95"], 9)
        self.assertEqual(baseline.quantiles([1, 8])["p50"], 4.5)
        self.assertEqual(baseline.quantiles(list(range(1, 21)))["p95"], 19)
        with self.assertRaises(ValueError):
            baseline.quantiles([])


if __name__ == "__main__":
    unittest.main()
