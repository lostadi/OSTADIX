"""Exercise external child dispatch and independent benchmark rejection paths."""

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("concurrent_benchmark", ROOT / "scripts/benchmark_concurrent_baseline.py")
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class ConcurrentBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "project"
        (self.root / bench.FIXTURE).parent.mkdir(parents=True)
        (self.root / bench.FIXTURE).write_bytes((ROOT / bench.FIXTURE).read_bytes())
        (self.root / "backends").mkdir()
        self.tools = self.base / "tools"
        self.tools.mkdir()
        self.python = self.tools / "python3"
        self.python.write_text(f"#!{sys.executable}\n" + '''
import os, sys
counts = {'test_o_cli_dispatch.py': 2, 'test_setup.py': 3, 'test_ostadix_boot_iso.py': 4}
module = sys.argv[-1]
print('Ran %d tests in 0.001s' % counts[module], file=sys.stderr)
failed = os.environ.get('FAIL_SHARD') == module
print('FAILED (errors=1)' if failed else 'OK', file=sys.stderr)
raise SystemExit(7 if failed else 0)
''')
        self.python.chmod(0o755)
        self.environment = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ["PATH"])

    def logs(self, directory):
        directory.mkdir(exist_ok=True)
        outputs = []
        for index, suite in enumerate(bench.SUITES, 2):
            (directory / (suite + ".log")).write_text(f"...\nRan {index} tests in 0.001s\n\nOK\n")
            outputs.append(f"suite={suite} tests={index} status=pass")
        return outputs

    def test_exact_fixture_preserves_guest_escapes_and_newlines(self):
        source = (ROOT / bench.FIXTURE).read_bytes()
        commands = bench.extract_lanes(source)
        self.assertEqual(len(commands), 3)
        self.assertTrue(all(command.startswith("\n") and command.endswith("\n") for command in commands))
        self.assertIn(r"/\1/p", commands[0])
        self.assertIn(r"status=pass\n", commands[0])
        self.assertIn('log="${O_CI_OUT}/o-cli.log"', commands[0])
        for changed in (source + b"\n", source.replace(b"bash^(", b"python^(", 1),
                        source.replace(b"\\${O_CI_OUT}", b"$name", 1)):
            with self.assertRaises(ValueError):
                bench.extract_lanes(changed)

    def test_logs_reject_missing_extra_corrupt_skipped_and_forged_summaries(self):
        mutations = (
            lambda directory: (directory / "setup.log").unlink(),
            lambda directory: (directory / "extra").mkdir(),
            lambda directory: (directory / "setup.log").write_text("Ran 0 tests in 0.1s\n\nOK\n"),
            lambda directory: (directory / "setup.log").write_text("Ran 3 tests in 0.1s\n\nOK (skipped=1)\n"),
            lambda directory: (directory / "setup.log").write_text("Ran 3 tests in 0.1s\nOK\nRan 3 tests in 0.1s\nOK\n"),
            lambda directory: (directory / "setup.log").write_text("Ran 3 tests in 0.1s\n\nFAILED (errors=1)\nOK\n"),
        )
        for index, mutate in enumerate(mutations):
            directory = self.base / f"bad-{index}"
            outputs = self.logs(directory)
            mutate(directory)
            with self.subTest(index=index), self.assertRaises(ValueError):
                bench.validate_ci(directory, outputs)
        directory = self.base / "valid"
        outputs = self.logs(directory)
        self.assertEqual(bench.validate_ci(directory, outputs)["total_tests"], 9)
        outputs[0] = "suite=o-cli tests=999 status=pass"
        with self.assertRaises(ValueError):
            bench.validate_ci(directory, outputs)

    def test_concurrent_child_retains_every_lane_when_a_real_bash_child_fails(self):
        directory = self.base / "child"
        directory.mkdir()
        artifacts = directory / "artifacts"
        artifacts.mkdir()
        env = dict(self.environment, O_CI_OUT=str(artifacts), FAIL_SHARD="test_setup.py")
        with mock.patch.dict(os.environ, env, clear=True):
            result = bench.concurrent_child(self.root, directory, Path(shutil.which("bash")), 2, "ci")
        self.assertFalse(result["ok"])
        self.assertEqual([row["returncode"] for row in result["lanes"]], [0, 7, 0])
        self.assertLessEqual(result["peak_observed_spawned_unreaped_bash_children"], 2)
        self.assertEqual(len(list(directory.glob("lane-*.stderr"))), 3)
        self.assertEqual({path.name for path in artifacts.iterdir()}, {suite + ".log" for suite in bench.SUITES})

    def fake_runtime(self):
        source = f"#!{sys.executable}\n" + '''
import hashlib, json, os
from pathlib import Path
import sys
args = sys.argv[1:]
bindings = {'lowered_oir_sha256': '1'*64, 'plan_sha256': '2'*64, 'analyzed_graph_sha256': '3'*64, 'admission_sha256': '4'*64}
if Path(sys.argv[0]).name == 'olangc':
    print(json.dumps({'schema':'oexec.schedule-explanation/v2', 'admission':{'schema':'oexec.admission/v6','bindings':bindings}, 'prediction':{'schema':'oexec.schedule-prediction/v1','status':'admitted-static','provenance':'evidence-bound-admission','model':'unit-cost-shim-hosted-tasks','span_unit':'hosted-task-layers','admission_sha256':'4'*64,'task_count':3,'predicted_width':3,'predicted_span':1,'layers':[{'index':1,'operations':['P1','P3','P5']}]}}))
    raise SystemExit(0)
if args == ['version','--json']:
    print(json.dumps({'graph_executor_enabled': True}))
    raise SystemExit(0)
arm = args[args.index('--executor')+1]
workers = int(args[args.index('--workers')+1])
program = Path(args[-2])
useful = program.name == 'ci_shards.O'
summaries = []
for count, suite in enumerate(('o-cli','setup','boot-iso'), 2):
    if useful:
        (Path(os.environ['O_CI_OUT'])/(suite+'.log')).write_text('Ran %d tests in 0.001s\\n\\nOK\\n' % count)
    summaries.append('suite=%s tests=%d status=pass' % (suite,count) if useful else '')
if useful and os.environ.get('FAKE_BAD_ARM') == arm:
    (Path(os.environ['O_CI_OUT'])/'extra.log').write_text('unexpected')
if useful and os.environ.get('FAKE_NONOBJECT_ARM') == arm:
    print('[]')
    raise SystemExit(0)
events = []
if arm == 'graph' and workers >= 3:
    events = [{'event':kind,'plan_node':node} for node in (1,3,5) for kind in ('ready','started')]
    events += [{'event':'finished','plan_node':node} for node in (1,3,5)]
else:
    events = [{'event':kind,'plan_node':node} for node in (1,3,5) for kind in ('ready','started','finished')]
print(json.dumps({'ok':True,'elapsed_ms':1,'value':{'t':'list','v':[{'t':'text','v':{'utf8':value,'encoding':'utf-8'}} for value in summaries]}, 'execution_evidence':{'execution_mode':arm,'source_sha256':hashlib.sha256(program.read_bytes()).hexdigest(),'admission':{'schema':'oexec.admission/v6','oir_sha256':'1'*64,'plan_sha256':'2'*64,'analyzed_graph_sha256':'3'*64,'admission_sha256':'5'*64},'trace':{'schema':'ostadix.graph-execution-trace/v1','events':events}}}))
'''
        paths = []
        for name in ("O", "olangc", "o-cli"):
            path = self.tools / name
            path.write_text(source)
            path.chmod(0o755)
            paths.append(path)
        return paths

    def arguments(self, output):
        o, compiler, cli = self.fake_runtime()
        return argparse.Namespace(root=self.root, output=output, o_bin=o, olangc_bin=compiler,
                                  native_cli_bin=cli, workers=3, repetitions=3, warmups=1,
                                  timeout=10, binary_profile="custom")

    def test_three_arm_runner_rotates_order_excludes_warmups_and_preserves_ratios(self):
        output = self.base / "full"
        args = self.arguments(output)
        with mock.patch.dict(os.environ, self.environment, clear=True), mock.patch.object(
                bench, "source_identity", return_value={"head": "fixture", "files": []}):
            result = bench.run(args)
        self.assertTrue(result["ok"], result)
        self.assertEqual([sample["order"] for sample in result["samples"]], [
            ["serial", "graph", "concurrent"], ["graph", "concurrent", "serial"],
            ["concurrent", "serial", "graph"], ["serial", "graph", "concurrent"],
        ])
        for arm in bench.ARMS:
            self.assertEqual(len(result["statistics"][arm]["raw_whole_process_ns"]), 3)
        self.assertEqual(len(result["controls"]), 3)
        self.assertEqual(len(result["startup_probes"]), 2)

    def test_invalid_sample_retains_all_three_arms_and_never_reports_performance(self):
        output = self.base / "failure"
        args = self.arguments(output)
        env = dict(self.environment, FAKE_BAD_ARM="graph")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                bench, "source_identity", return_value={"head": "fixture", "files": []}):
            result = bench.run(args)
        self.assertFalse(result["ok"])
        self.assertNotIn("statistics", result)
        self.assertEqual(len(result["samples"]), 1)
        self.assertEqual(len(result["samples"][0]["arms"]), 3)
        self.assertTrue(all(Path(row["stdout"]).is_file() for row in result["samples"][0]["arms"]))
        self.assertEqual(json.loads((output / "result.json").read_text())["ok"], False)

    def test_missing_binary_and_invalid_worker_budget_fail_before_measurement(self):
        output = self.base / "never-created"
        args = self.arguments(output)
        args.o_bin = self.base / "missing"
        with self.assertRaises(ValueError):
            bench.run(args)
        self.assertFalse(output.exists())
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit) as error:
            bench.main(["--output", str(output), "--workers", "0"])
        self.assertEqual(error.exception.code, 2)

    def test_launch_failure_has_a_complete_failed_measurement_record(self):
        directory = self.base / "missing-child"
        record = bench.measured([str(self.base / "absent")], directory,
                                self.environment, 5, self.root)
        self.assertEqual(record["returncode"], 127)
        self.assertIn("launch_error", record)
        self.assertTrue(Path(record["stdout"]).is_file())
        self.assertTrue(Path(record["stderr"]).is_file())
        self.assertFalse(record["timed_out"])

    def test_pending_timeout_callback_finishes_before_measurement_returns(self):
        release, finished = threading.Event(), threading.Event()
        threads = []

        class PendingTimer:
            def __init__(self, _timeout, callback):
                def pending():
                    release.wait()
                    callback()
                    finished.set()
                self.thread = threading.Thread(target=pending, daemon=True)
                threads.append(self.thread)

            def start(self):
                self.thread.start()

            def cancel(self):
                pass  # The callback is already running and cannot be cancelled.

            def join(self):
                release.set()
                self.thread.join()

        with mock.patch.object(bench.threading, "Timer", PendingTimer), mock.patch.object(bench.os, "killpg"):
            try:
                record = bench.measured([sys.executable, "-c", "print('finished')"],
                                        self.base / "timer", self.environment, 5, self.root)
                self.assertTrue(finished.is_set())
                self.assertTrue(record["timed_out"])
            finally:
                release.set()
                for thread in threads:
                    thread.join()

    def test_artifact_io_failure_is_retained_before_control_cost_derivation(self):
        args = self.arguments(self.base / "io-failure")
        original = Path.mkdir

        def fail_control(path, *values, **keywords):
            if path.name == "artifacts" and path.parent.name == "noop-graph":
                raise PermissionError("controlled artifact I/O failure")
            return original(path, *values, **keywords)

        with mock.patch.dict(os.environ, self.environment, clear=True), mock.patch.object(
                bench, "source_identity", return_value={"head": "fixture", "files": []}), \
                mock.patch.object(Path, "mkdir", fail_control):
            result = bench.run(args)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "no-op overhead control failed")
        self.assertEqual(len(result["controls"]), 3)
        graph = next(record for record in result["controls"] if record["arm"] == "graph")
        self.assertIn("controlled artifact I/O failure", graph["error"])
        self.assertTrue((args.output / "result.json").is_file())

    def test_non_object_json_is_a_retained_failed_arm(self):
        args = self.arguments(self.base / "non-object")
        env = dict(self.environment, FAKE_NONOBJECT_ARM="graph")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                bench, "source_identity", return_value={"head": "fixture", "files": []}):
            result = bench.run(args)
        self.assertFalse(result["ok"])
        self.assertEqual(len(result["samples"][0]["arms"]), 3)
        graph = next(record for record in result["samples"][0]["arms"] if record["arm"] == "graph")
        self.assertIn("must be a JSON object", graph["error"])
        self.assertTrue(Path(graph["stdout"]).is_file())

    def test_incomplete_or_duplicate_trace_cannot_qualify_an_o_result(self):
        bindings = {"lowered_oir_sha256": "1"*64, "plan_sha256": "2"*64,
                    "analyzed_graph_sha256": "3"*64}
        document = {"ok": True, "value": {"t": "list", "v": [{"t": "str", "v": ""}]*3},
                    "execution_evidence": {"execution_mode": "graph", "source_sha256": "source",
                        "admission": {"schema": "oexec.admission/v6", "oir_sha256": "1"*64,
                                      "plan_sha256": "2"*64, "analyzed_graph_sha256": "3"*64,
                                      "admission_sha256": "4"*64},
                        "trace": {"schema": "ostadix.graph-execution-trace/v1", "events": []}}}
        events = [{"event": kind, "plan_node": node} for node in (1, 3, 5)
                  for kind in ("ready", "started", "finished")]
        for invalid in (events[:-1], events + [events[-1]],
                        [{"event": "failed", "plan_node": 1}], []):
            corrupt = copy.deepcopy(document)
            corrupt["execution_evidence"]["trace"]["events"] = invalid
            with self.assertRaises(ValueError):
                bench.validate_o(corrupt, "graph", "source", ([1, 3, 5], bindings), 3)


if __name__ == "__main__":
    unittest.main()
