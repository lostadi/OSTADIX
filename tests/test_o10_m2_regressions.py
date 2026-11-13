"""The M2 wrapper delegates actual work once; fixtures start no guests."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_o10_m2_regressions as gate


class M2RegressionWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="o10-m2-wrapper-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("build", "seed", "runtime"):
            (self.root/name).mkdir()
        (self.root/"build/monitor.elf").write_bytes(b"fixture monitor")
        (self.root/"build/monitor-profile.json").write_text("{}")
        (self.root/"seed/head.json").write_text("{}")
        for name in ("resident", "restart", "restart-command"):
            (self.root/(name+".json")).write_text("{}")
        self.args = SimpleNamespace(build=self.root/"build", seed_state=self.root/"seed",
            runtime=self.root/"runtime", resident_result=self.root/"resident.json",
            restart_result=self.root/"restart.json", restart_command=self.root/"restart-command.json",
            output=self.root/"output", mcp_release="a"*40, jobs=2, gate_timeout=100,
            minimum_free_gib=3.5, execute=True)

    def complete(self, argv, output, timeout, *, returncode=0, ok=True, skips=False):
        output.mkdir(parents=True)
        (output/"stdout.log").write_text("shared driver output")
        (output/"stderr.log").write_text("")
        result=self.args.output/"six-gates/result.json"
        result.parent.mkdir()
        result.write_text(json.dumps(dict(ok=ok, skips=["fixture"] if skips else [])))
        return dict(argv=argv, returncode=returncode, timed_out=False)

    def test_delegation_uses_shared_explicit_draft0_scheduler_and_two_workers(self):
        argv=gate.delegate_argv(self.args)
        self.assertEqual(Path(argv[1]).name,"verify_o10_m1_regressions.py")
        self.assertEqual(argv[argv.index("--acceptance-scope")+1],"draft0")
        self.assertEqual(argv[argv.index("--jobs")+1],"2")
        self.assertIn("--execute",argv)
        self.assertNotIn("--hostile-mmio-result",argv)

    def test_plan_does_not_create_output_or_claim_execution(self):
        self.args.execute=False
        completed=SimpleNamespace(stdout=json.dumps({"steps":["actual shared plan"]}))
        with patch.object(gate.subprocess,"run",return_value=completed) as call:
            value=gate.run(self.args)
        self.assertFalse(self.args.output.exists())
        self.assertNotIn("ok",value)
        self.assertEqual(value["shared_plan"]["steps"],["actual shared plan"])
        self.assertNotIn("--execute",call.call_args.args[0])

    def test_failed_prerequisite_never_starts_shared_driver(self):
        with patch.object(gate,"validate_prerequisites",side_effect=ValueError("actual wire proof missing")), \
             patch.object(gate.shared,"execute_command") as execute:
            value=gate.run(self.args)
        self.assertFalse(value["ok"]);execute.assert_not_called()
        self.assertFalse(value["full_milestone_qualified"])

    def test_successful_shared_exit_is_retained_without_qualifying_milestone(self):
        with patch.object(gate,"validate_prerequisites",return_value=({},self.args.mcp_release)), \
             patch.object(gate.shared,"execute_command",side_effect=self.complete) as execute:
            value=gate.run(self.args)
        self.assertTrue(value["ok"]);self.assertFalse(value["full_milestone_qualified"])
        self.assertEqual(execute.call_count,1)
        self.assertEqual(value["shared_result"],gate.m2.identity(self.args.output/"six-gates/result.json"))
        self.assertEqual(value["restart_result"],gate.m2.identity(self.args.restart_result))

    def test_unknown_driver_exit_cannot_be_replaced_by_positive_child_receipt(self):
        def unknown(*args):return self.complete(*args,returncode=None)
        with patch.object(gate,"validate_prerequisites",return_value=({},self.args.mcp_release)), \
             patch.object(gate.shared,"execute_command",side_effect=unknown) as execute:
            value=gate.run(self.args)
        self.assertFalse(value["ok"]);self.assertEqual(execute.call_count,1)
        self.assertIn("unknown work",value["error"])

    def test_shared_skips_fail_without_retry(self):
        def skipped(*args):return self.complete(*args,skips=True)
        with patch.object(gate,"validate_prerequisites",return_value=({},self.args.mcp_release)), \
             patch.object(gate.shared,"execute_command",side_effect=skipped) as execute:
            value=gate.run(self.args)
        self.assertFalse(value["ok"]);self.assertEqual(execute.call_count,1)

    def test_existing_output_is_never_overwritten(self):
        self.args.output.mkdir();sentinel=self.args.output/"sentinel";sentinel.write_text("history")
        with self.assertRaises(ValueError):gate.run(self.args)
        self.assertEqual(sentinel.read_text(),"history")

    def test_selected_seed_drift_is_rejected(self):
        def changed(*args):
            value=self.complete(*args);(self.args.seed_state/"head.json").write_text('{"changed":true}')
            return value
        with patch.object(gate,"validate_prerequisites",return_value=({},self.args.mcp_release)), \
             patch.object(gate.shared,"execute_command",side_effect=changed) as execute:
            value=gate.run(self.args)
        self.assertFalse(value["ok"]);self.assertEqual(execute.call_count,1)
        self.assertIn("seed changed",value["error"])
