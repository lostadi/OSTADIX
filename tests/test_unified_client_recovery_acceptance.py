"""Check the targeted recovery test's PID-observation boundary, without a VM.

Live Linux/Plan9 recovery remains a separate real foreground-console gate.
"""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("unified_crash_acceptance_test", ROOT / "scripts/verify_okernel_unified_recovery.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class RecoveryAcceptanceBoundaryTests(unittest.TestCase):
    def test_real_observer_follows_only_owned_children_and_matching_starttime(self):
        source = ast.parse(GATE.HELPER)
        function = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == "processes")
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            def process(pid, parent, ticks, children, args):
                target = folder / str(pid)
                (target / "task" / str(pid)).mkdir(parents=True)
                fields = ["S", str(parent)] + ["0"] * 17 + [str(ticks)]
                (target / "stat").write_text(str(pid) + " (python3) " + " ".join(fields))
                (target / "cmdline").write_bytes(args)
                (target / "task" / str(pid) / "children").write_text(children)
            process(101, 1, 9000, "202 999", b"python3\0/usr/local/bin/p9\0")
            process(202, 101, 9010, "303", b"python3\0/usr/local/libexec/p9-history\0")
            process(303, 202, 9020, "", b"owned-helper\0")
            process(999, 777, 9030, "", b"unrelated-workload-must-not-be-observed\0")
            (folder / "999" / "cmdline").chmod(0)
            def mapped(value):
                text = str(value)
                if not text.startswith("/proc/"):
                    raise AssertionError("observer escaped owned proc fixture")
                return folder / text.removeprefix("/proc/")
            environment = {"Path": mapped}
            exec(compile(ast.Module(body=[function], type_ignores=[]), "actual-owned-observer", "exec"), environment)
            observed = environment["processes"](101, "9000")
            self.assertEqual([item["pid"] for item in observed], [101, 202, 303])
            self.assertNotIn("unrelated", repr(observed))
            self.assertEqual(environment["processes"](101, "reused"), [])

    def test_kill_is_pidfd_bound_and_helper_compiles(self):
        compile(GATE.HELPER, "actual-guest-client-crash-helper", "exec")
        tree = ast.parse(GATE.HELPER)
        calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        self.assertIn("os.pidfd_open", calls)
        self.assertIn("signal.pidfd_send_signal", calls)
        self.assertNotIn("os.kill", calls)
        self.assertNotIn("os.system", calls)
        self.assertIn('retained_phase_before_successor=pending["phase"]', GATE.HELPER)

    def test_diagnostics_do_not_reprint_cumulative_receipts(self):
        source = ast.parse(GATE.HELPER)
        function = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == "observe")
        retained = []
        environment = {"write": retained.append, "json": json, "token": "fixture"}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "actual-bounded-observer", "exec"), environment)
        value = {"client_pid": 123, "warmups": [{"receipt": "large" * 10000}], "pending_seconds": 1.5}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            environment["observe"](value, "pending-observed")
        self.assertIs(retained[0], value)
        self.assertLess(len(output.getvalue()), 500)
        self.assertNotIn("large", output.getvalue())


if __name__ == "__main__":
    unittest.main()
