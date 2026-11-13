"""Check failure boundaries of the foreground-client acceptance oracle.

These host-only checks do not stand in for the separate real-PTY/two-kernel
gate. They ensure a missing native reset/private ACK cannot be called success.
"""
import ast
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("unified_client_acceptance_test", ROOT / "scripts/verify_okernel_unified_client.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ForegroundClientOracleTests(unittest.TestCase):
    def setUp(self):
        self.ack = {"generation": "1" * 16, "old_instance": "2" * 32,
                    "new_instance": "3" * 32, "request_id": "4" * 32,
                    "outcome": "interrupted"}
        self.evidence = {"private_ack": self.ack}
        self.record = {"provider_recoveries": [{"ok": True,
                       "previous": {"generation": "1" * 16, "instance": "2" * 32},
                       "current": {"generation": "1" * 16, "instance": "3" * 32},
                       "withdrawn": {"live_domains": 1}, "restored": {"live_domains": 3}}],
                       "coordinator_updates": [{"frame": {"recovered": self.ack}, "ack": {"ok": True}}]}

    def test_recovery_requires_exact_private_ack_and_native_domain_transition(self):
        self.assertIs(GATE.validate_recovery(self.record, self.evidence), self.record["provider_recoveries"][0])
        cases = []
        for key, value in (("ok", False), ("withdrawn", {"live_domains": 0}),
                           ("restored", {"live_domains": 1}),
                           ("current", {"generation": "1" * 16, "instance": "2" * 32})):
            changed = copy.deepcopy(self.record)
            changed["provider_recoveries"][0][key] = value
            cases.append(changed)
        changed = copy.deepcopy(self.record)
        changed["provider_recoveries"].append(copy.deepcopy(changed["provider_recoveries"][0]))
        cases.append(changed)
        for update in ([], [{"frame": {"recovered": {**self.ack, "request_id": "5" * 32}}, "ack": {"ok": True}}],
                       [{"frame": {"recovered": self.ack}, "ack": {"ok": False}}]):
            changed = copy.deepcopy(self.record)
            changed["coordinator_updates"] = update
            cases.append(changed)
        for index, record in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                GATE.validate_recovery(record, self.evidence)

    def test_only_exact_explicit_monitor_identities_are_admitted(self):
        self.assertEqual(GATE.admitted_monitor_revision(GATE.R8_MONITOR, GATE.MONITOR_PROFILES[GATE.R8_MONITOR]), "R8")
        for digest, revision in GATE.MONITOR_REVISIONS.items():
            self.assertEqual(GATE.admitted_monitor_revision(digest, GATE.MONITOR_PROFILES[digest]), revision)
            for wrong in ("0" * 64, None, {}, True):
                with self.subTest(profile=wrong), self.assertRaises(ValueError):
                    GATE.admitted_monitor_revision(digest, wrong)
        for digest in ("0" * 64, GATE.R8_MONITOR.upper(), "", None, {}, True):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                GATE.admitted_monitor_revision(digest, "0" * 64)

    def test_typed_commands_cannot_cross_terminal_line_boundary(self):
        class Terminal:
            def send(self, _):
                raise AssertionError("invalid command reached the terminal")
        for text in ("echo one\necho two", "x" * 3501):
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                GATE.typed(Terminal(), text)
        compile(GATE.GUEST_HELPER, "typed-private-result-assertions.py", "exec")

    def test_idle_traffic_monitor_cannot_borrow_a_preceding_profile(self):
        self.assertEqual(GATE.admitted_monitor_revision(GATE.R10_MONITOR,
                         "fa30ee495211844c299173b9c079119e73c333d2716bdc85fd1e0899e8719ca5"),
                         "R10-idle-traffic")
        with self.assertRaisesRegex(ValueError, "profile/input identity"):
            GATE.admitted_monitor_revision(GATE.R10_MONITOR, GATE.MONITOR_PROFILES[GATE.R9_MONITOR])

    def test_o10_monitor_cannot_borrow_a_legacy_profile(self):
        for legacy in (GATE.R8_MONITOR, GATE.R9_MONITOR, GATE.R10_MONITOR):
            with self.subTest(legacy=legacy), self.assertRaisesRegex(ValueError, "profile/input identity"):
                GATE.admitted_monitor_revision(GATE.O10_M0_MONITOR, GATE.MONITOR_PROFILES[legacy])
        with self.assertRaisesRegex(ValueError, "profile/input identity"):
            GATE.admitted_monitor_revision(GATE.R9_MONITOR, GATE.O10_M0_PROFILE)

    def test_r7_resident_candidate_requires_its_exact_observed_profile(self):
        self.assertEqual(GATE.admitted_monitor_revision(
            GATE.O10_M1_R7_MONITOR, GATE.O10_M1_R7_PROFILE),
            "O10-M1-R7-resident-candidate")
        for monitor, profile in GATE.MONITOR_PROFILES.items():
            if monitor == GATE.O10_M1_R7_MONITOR:
                continue
            with self.subTest(monitor=monitor), self.assertRaises(ValueError):
                GATE.admitted_monitor_revision(GATE.O10_M1_R7_MONITOR, profile)
            with self.subTest(reverse=monitor), self.assertRaises(ValueError):
                GATE.admitted_monitor_revision(monitor, GATE.O10_M1_R7_PROFILE)

    def test_m2_private_candidate_requires_its_exact_build_profile(self):
        self.assertEqual(GATE.O10_M2_MONITOR,
                         "30a91b43bb78e9202c983417e39609991554914ff0deb76998b69e19ea01dddb")
        self.assertEqual(GATE.O10_M2_PROFILE,
                         "d5a5207a7b0e85963c98e7cefb378a69a32d77c70702aaa8cf783dcc909f964c")
        self.assertEqual(GATE.admitted_monitor_revision(
            GATE.O10_M2_MONITOR, GATE.O10_M2_PROFILE), "O10-M2-private-candidate")
        for monitor, profile in GATE.MONITOR_PROFILES.items():
            if monitor == GATE.O10_M2_MONITOR:
                continue
            with self.subTest(monitor=monitor), self.assertRaises(ValueError):
                GATE.admitted_monitor_revision(GATE.O10_M2_MONITOR, profile)
            with self.subTest(reverse=monitor), self.assertRaises(ValueError):
                GATE.admitted_monitor_revision(monitor, GATE.O10_M2_PROFILE)

    def test_actual_setup_helper_cannot_satisfy_completion_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            control, local, workspace = (folder / name for name in ("control", "local", "workspace"))
            control.mkdir(); (control / "results").mkdir(); workspace.mkdir()
            (control / "current.json").write_text("{}")
            def mapped(path):
                return {"/run/okernel/p9": control, "/run/p9-foreground-acceptance": local}.get(str(path), Path(path))
            import types
            output = io.StringIO()
            protocol = types.ModuleType("p9_protocol")
            before_path = sys.path[:]
            try:
                with mock.patch("pathlib.Path", side_effect=mapped), \
                        mock.patch.object(sys, "argv", ["helper", str(workspace), "begin", "cancel"]), \
                        mock.patch.dict(sys.modules, {"p9_protocol": protocol}), contextlib.redirect_stdout(output):
                    exec(compile(GATE.GUEST_HELPER, "actual-typed-helper", "exec"), {})
            finally:
                sys.path[:] = before_path
            self.assertEqual(output.getvalue(), "\nP9_BEGIN_cancel_workspace\n")
            terminal = object.__new__(GATE.Terminal)
            terminal.capture = bytearray(output.getvalue().encode())
            terminal.process = mock.Mock()
            terminal.process.poll.return_value = 0
            with self.assertRaises(RuntimeError):
                terminal.wait(b"P9_ASSERT_cancel_workspace", timeout=1, line=True)

    def test_completion_starts_fresh_line_after_actual_echoctl_prefix(self):
        tree = ast.parse(GATE.GUEST_HELPER)
        actual_print = ast.Module(body=[tree.body[-1]], type_ignores=[])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(actual_print, "actual-helper-completion", "exec"),
                 {"action": "collect", "name": "cancel", "root": Path("workspace")})
        terminal = object.__new__(GATE.Terminal)
        terminal.capture = bytearray(b"^C" + output.getvalue().encode())
        terminal.process = mock.Mock()
        terminal.process.poll.return_value = 0
        terminal.wait(b"P9_ASSERT_cancel_workspace", timeout=1, line=True)

    def test_watchdog_killer_is_bound_to_all_original_service_arguments(self):
        compile(GATE.WATCHDOG_HELPER, "typed-watchdog-assertions.py", "exec")
        assignment = next(node for node in ast.walk(ast.parse(GATE.WATCHDOG_HELPER))
                          if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "find" for t in node.targets))
        values = {"g": "a" * 16, "s": "b" * 32, "native": "/n/work/test"}
        exec(compile(ast.Module(body=[assignment], type_ignores=[]), "actual-resident-predicate", "exec"), values)
        source = values["find"]
        for predicate in ("~ $#a 4", "~ $a(1) /arm64/bin/p9cmdsrv", "~ $a(2) /n/services/plan9",
                          "~ $a(3) " + values["g"], "~ $a(4) " + values["s"], "if(! ~ $#targets 1)"):
            self.assertIn(predicate, source)
        self.assertNotIn("grep", source)
        self.assertNotIn("echo kill", source)  # Discovery itself cannot kill a process.

    def test_save_oracle_rejects_unstopped_unquiescent_and_dropped_input(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            session = state / "session"
            session.mkdir()
            good = {"ok": True, "paired_snapshot": True, "virtual_cpu_stopped": True,
                    "native_operations_quiescent": True, "after": {"fixture": "pair"}}
            (state / "head.json").write_text(json.dumps(good["after"]))
            (session / "native-observation.json").write_text(json.dumps({"input_dropped": 0}))
            for key in ("ok", "paired_snapshot", "virtual_cpu_stopped", "native_operations_quiescent"):
                value = {**good, key: False}
                (session / "result.json").write_text(json.dumps(value))
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    GATE.read_saved_session(state, session)
            (session / "result.json").write_text(json.dumps(good))
            (session / "native-observation.json").write_text(json.dumps({"input_dropped": 1}))
            with self.assertRaises(RuntimeError):
                GATE.read_saved_session(state, session)
            (session / "native-observation.json").write_text(json.dumps({"input_dropped": 0}))
            (state / "head.json").write_text(json.dumps({"fixture": "other pair"}))
            with self.assertRaises(RuntimeError):
                GATE.read_saved_session(state, session)


if __name__ == "__main__":
    unittest.main()
