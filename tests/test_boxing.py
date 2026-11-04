"""Behavioral regressions for the self-contained boxing.O application.

These load the exact embedded Python engine, without its O entrypoint or terminal
runner. Real O execution and authenticated o-node integration are separate checks.
"""

from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import random
import re
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "boxing.O"


def load_engine():
    document = SOURCE.read_text(encoding="utf-8")
    opening = re.search(r"^python(?:\[91\])?\^\(\n", document, re.MULTILINE)
    if opening is None:
        raise AssertionError("boxing.O has no embedded Python engine")
    closing = re.search(r"^\)_python(?:\[91\])?\s*$", document[opening.end():], re.MULTILINE)
    if closing is None:
        raise AssertionError("boxing.O has no closing engine marker")
    source = document[opening.end():opening.end() + closing.start()]
    tree = ast.parse(source, filename=str(SOURCE))
    ast.increment_lineno(tree, document[:opening.end()].count("\n"))
    # Importing the test engine cannot run a match, open a terminal or submit work.
    definitions = (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef,
                   ast.Assign, ast.AnnAssign)
    tree.body = [statement for statement in tree.body if isinstance(statement, definitions)]
    module = types.ModuleType("boxing_example_under_test")
    module.__spec__ = importlib.util.spec_from_loader(module.__name__, loader=None)
    exec(compile(tree, str(SOURCE), "exec"), module.__dict__)
    return module


def plain(value):
    """Use the same finite JSON data boundary required for cross-device work."""
    return json.loads(json.dumps(value, allow_nan=False))


class BoxingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_engine()

    def setUp(self):
        self.arena = self.engine.BoxingArena()
        self.arena.match_id = "boxing-regression"
        self.arena.seed = 73

    def snapshot(self, tick=1):
        return self.engine.match_snapshot(self.arena, tick)

    def replies(self, snapshot):
        return {side: self.engine.compute_fighter(plain(snapshot), side)
                for side in ("red", "blue")}

    def test_cutman_treats_both_sides_without_negative_injuries(self):
        injury = self.arena.f1.injury
        injury.l_eye_swelling = 80
        injury.r_eye_swelling = 10
        injury.l_brow_cut = 90
        injury.r_brow_cut = 8
        injury.nose_fracture = 36
        injury.liver_trauma = 45
        injury.apply_cutman_treatments()
        self.assertEqual(injury.l_eye_swelling, 58)
        self.assertEqual(injury.r_eye_swelling, 0)
        self.assertEqual(injury.l_brow_cut, 64)
        self.assertEqual(injury.r_brow_cut, 0)
        self.assertEqual(injury.nose_fracture, 36)
        self.assertEqual(injury.liver_trauma, 45)

    def test_fighter_roundtrip_preserves_ragdoll_and_injury_state(self):
        fighter = self.arena.f1
        fighter.x = 13.25
        fighter.vx = -2.5
        fighter.punch_target = (23.5, 11.0)
        fighter.injury.r_brow_cut = 71.5
        fighter.injury.has_mouthguard = False
        fighter.ragdoll = self.engine.VerletRagdoll(13.25, 23, facing=1)
        fighter.ragdoll.apply_knockdown_impulse(2.25, -1.6)
        fighter.ragdoll.step()
        encoded = plain(self.engine.fighter_to_data(fighter))
        restored = self.engine.fighter_from_data(encoded)
        self.assertIsInstance(restored, self.engine.Fighter)
        self.assertIsInstance(restored.injury, self.engine.InjurySystem)
        self.assertIsInstance(restored.ragdoll, self.engine.VerletRagdoll)
        self.assertEqual(plain(self.engine.fighter_to_data(restored)), encoded)

    def test_worker_is_deterministic_and_does_not_mutate_the_input(self):
        self.arena.f1.x = 24
        self.arena.f2.x = 37
        self.arena.f1.vx = 1.5
        snapshot = plain(self.snapshot())
        original = copy.deepcopy(snapshot)
        initial_rng = random.getstate()
        first = self.engine.compute_fighter(snapshot, "red")
        self.assertEqual(random.getstate(), initial_rng)
        random.seed(8192)
        unrelated_rng = random.getstate()
        second = self.engine.compute_fighter(plain(original), "red")
        self.assertEqual(first, second)
        self.assertEqual(snapshot, original)
        self.assertEqual(random.getstate(), unrelated_rng)

    def test_both_workers_are_bound_to_the_same_committed_snapshot(self):
        snapshot = self.snapshot()
        replies = self.replies(snapshot)
        red, blue = replies["red"], replies["blue"]
        self.assertEqual(red["snapshot_sha256"], blue["snapshot_sha256"])
        self.assertEqual(red["tick"], blue["tick"])
        self.assertEqual(red["match_id"], blue["match_id"])
        self.assertEqual({red["side"], blue["side"]}, {"red", "blue"})
        self.assertEqual(plain(snapshot), plain(self.snapshot()))

    def test_invalid_reply_cannot_partially_commit_one_fighter(self):
        for field, value in (("tick", 999), ("match_id", "another-match"),
                             ("snapshot_sha256", "0" * 64), ("side", "red")):
            with self.subTest(field=field):
                snapshot = self.snapshot()
                before = plain(snapshot)
                replies = self.replies(snapshot)
                replies["blue"][field] = value
                with self.assertRaises((ValueError, RuntimeError)):
                    self.engine.apply_fighter_steps(self.arena, snapshot, replies)
                self.assertEqual(plain(self.snapshot()), before)

    def test_missing_worker_reply_does_not_advance_the_match(self):
        snapshot = self.snapshot()
        before = plain(snapshot)
        with self.assertRaises((ValueError, RuntimeError)):
            self.engine.apply_fighter_steps(self.arena, snapshot, {"red": self.replies(snapshot)["red"]})
        self.assertEqual(plain(self.snapshot()), before)

    def test_malformed_physics_is_rejected_before_commit(self):
        self.arena.f1.vx = 1.0
        for invalid in ("oops", None, float("nan"), float("inf"), True):
            with self.subTest(invalid=invalid):
                snapshot = self.snapshot()
                before = plain(snapshot)
                replies = self.replies(snapshot)
                replies["blue"]["rope_impulses"][0][0] = invalid
                with self.assertRaises((ValueError, RuntimeError, TypeError)):
                    self.engine.apply_fighter_steps(self.arena, snapshot, replies)
                self.assertEqual(plain(self.snapshot()), before)

    def test_malformed_injury_and_projectiles_cannot_enter_committed_state(self):
        mutations = (
            lambda reply: reply["fighter"]["injury"].update(r_eye_swelling="bad"),
            lambda reply: reply["fighter"].update(state_duration=[]),
            lambda reply: reply.update(projectiles=[{"type": "blood", "x": "bad"}]),
            lambda reply: reply.update(projectiles=None),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                snapshot = self.snapshot()
                before = plain(snapshot)
                replies = self.replies(snapshot)
                mutate(replies["blue"])
                with self.assertRaises((ValueError, RuntimeError, TypeError)):
                    self.engine.apply_fighter_steps(self.arena, snapshot, replies)
                self.assertEqual(plain(self.snapshot()), before)

    def test_doctor_stops_the_actual_injured_fighter_on_either_side(self):
        for side in ("red", "blue"):
            for field in ("l_brow_cut", "r_brow_cut", "l_eye_swelling", "r_eye_swelling"):
                with self.subTest(side=side, field=field):
                    arena = self.engine.BoxingArena()
                    fighter = arena.f1 if side == "red" else arena.f2
                    opponent_name = arena.f2.name if side == "red" else arena.f1.name
                    setattr(fighter.injury, field, 99)
                    arena.doctor_inspecting = True
                    arena.doctor_timer = 1
                    arena.doctor_fighter = side
                    self.engine.advance_match(arena, 1)
                    self.assertTrue(arena.match_over)
                    self.assertEqual(arena.winner.name, opponent_name)
                    injured = arena.f1 if side == "red" else arena.f2
                    self.assertTrue(injured.injury.doc_stopped)
                    self.assertIn("physician", arena.ko_type.lower())
                    self.assertEqual(arena.round_tick, 0)

    def test_liver_collapse_counts_a_knockdown_once(self):
        self.arena.f1.injury.delayed_liver_timer = 1
        self.engine.advance_match(self.arena, 1)
        self.assertEqual(self.arena.f1.state, "DOWN")
        self.assertEqual(self.arena.f1.knockdowns_taken, 1)
        self.assertEqual(self.arena.f2.knockdowns_scored, 1)
        self.assertEqual(self.arena.f2.damage_dealt, 18)
        self.assertEqual(self.arena.f2.finishing_threat, 20)
        self.assertTrue(self.arena.referee_counting)
        before = plain(vars(self.arena.f1.ragdoll))
        self.engine.advance_match(self.arena, 2)
        self.assertEqual(self.arena.f1.knockdowns_taken, 1)
        self.assertEqual(self.arena.f2.knockdowns_scored, 1)
        self.assertEqual(self.arena.f2.damage_dealt, 18)
        self.assertEqual(self.arena.f2.finishing_threat, 20)
        self.assertNotEqual(plain(vars(self.arena.f1.ragdoll)), before)

    def test_liver_collapse_credits_only_actual_remaining_hp(self):
        self.arena.f1.hp = 7
        self.arena.f1.injury.delayed_liver_timer = 1
        self.engine.advance_match(self.arena, 1)
        self.assertEqual(self.arena.f1.hp, 0)
        self.assertEqual(self.arena.f2.damage_dealt, 7)
        self.assertEqual(self.arena.f2.finishing_threat, 20)
        event = next(event for event in self.arena.events if event.get("punch") == "DELAYED LIVER COLLAPSE")
        self.assertEqual(event["attacker"], "PHANTOM")
        self.assertEqual(event["damage"], 7)
        self.assertEqual(event["finishing_threat"], 20)

    def test_shared_body_contact_separates_fighters_and_preserves_momentum(self):
        for red_x, blue_x in ((30, 34), (10, 12), (49, 52)):
            with self.subTest(red_x=red_x, blue_x=blue_x):
                arena = self.engine.BoxingArena()
                arena.doctor_inspecting = True
                arena.doctor_timer = 10
                arena.doctor_fighter = "red"
                arena.f1.x, arena.f2.x = red_x, blue_x
                arena.f1.vx, arena.f2.vx = 1.0, -0.5
                snapshot = self.engine.match_snapshot(arena, 1)
                workers = [self.engine.compute_fighter(snapshot, side)["fighter"] for side in ("red", "blue")]
                momentum_before_contact = sum(f["mass"] * f["vx"] for f in workers)
                self.engine.advance_match(arena, 1)
                self.assertAlmostEqual(arena.f2.x - arena.f1.x, 8)
                self.assertGreaterEqual(arena.f1.x, 10)
                self.assertLessEqual(arena.f2.x, arena.w - 24)
                self.assertAlmostEqual(arena.f1.vx, arena.f2.vx)
                self.assertAlmostEqual(arena.f1.mass * arena.f1.vx + arena.f2.mass * arena.f2.vx,
                                       momentum_before_contact)

    def test_worker_injury_changes_are_logged_at_the_committed_tick(self):
        self.arena.f1.injury.delayed_liver_timer = 2
        self.engine.advance_match(self.arena, 1)
        events = [event for event in self.arena.events
                  if event["fighter"] == "TITAN" and "delayed_liver_timer" in event["changes"]]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["tick"], 1)
        self.assertEqual(events[0]["changes"]["delayed_liver_timer"], {"before": 2, "after": 1})

    def test_scheduled_rounds_produce_a_real_scored_result(self):
        self.arena.max_rounds = 2
        self.arena.round_time_sec = 1
        for tick in range(1, 9):
            self.engine.advance_match(self.arena, tick)
        self.assertTrue(self.arena.match_over)
        self.assertEqual(len(self.arena.scorecards), 2)
        self.assertEqual(self.arena.scores, [0, 0])
        self.assertIsNone(self.arena.winner)
        self.assertEqual(self.arena.ko_type, "DRAW (damage + finishing danger)")

    def test_decision_records_round_deltas_and_uses_cumulative_damage_and_danger(self):
        self.arena.max_rounds = 2
        self.arena.f1.damage_dealt = 24
        self.arena.f1.finishing_threat = 14
        self.arena.f2.damage_dealt = 12
        self.arena.f2.finishing_threat = 2
        self.engine.score_round(self.arena)
        self.assertFalse(self.arena.match_over)
        self.assertEqual(self.arena.scores, [38, 14])
        self.assertEqual(self.arena.scorecards[0]["damage"], [24, 12])
        self.assertEqual(self.arena.scorecards[0]["finishing_threat"], [14, 2])
        self.arena.f2.damage_dealt += 10
        self.arena.f2.finishing_threat += 10
        self.engine.score_round(self.arena)
        self.assertTrue(self.arena.match_over)
        self.assertEqual(self.arena.scores, [38, 34])
        self.assertEqual(self.arena.scorecards[1]["damage"], [0, 10])
        self.assertEqual(self.arena.scorecards[1]["finishing_threat"], [0, 10])
        self.assertEqual(self.arena.scorecards[1]["points"], [0, 20])
        self.assertEqual(self.arena.winner.name, "TITAN")

    def test_equal_hit_counts_award_decision_to_more_damage(self):
        self.arena.max_rounds = 1
        self.arena.f1.punches_landed = self.arena.f2.punches_landed = 8
        self.arena.f1.damage_dealt = 40
        self.arena.f2.damage_dealt = 20
        self.engine.score_round(self.arena)
        self.assertEqual(self.arena.scores, [40, 20])
        self.assertEqual(self.arena.winner.name, "TITAN")
        self.assertEqual(self.arena.ko_type, "DECISION (damage + finishing danger)")

    def test_same_damage_awards_decision_to_more_dangerous_injury(self):
        self.arena.max_rounds = 1
        self.arena.round_time_sec = 1
        self.arena.round_tick = 3
        # Hold collision geometry constant at its engine boundary. Both contacts
        # remove ten HP, but only the blue fighter causes a large concussion.
        def equal_damage_contacts(attacker, defender):
            defender.hp -= 10
            if attacker.name == "TITAN":
                defender.injury.nose_fracture += 20
            else:
                defender.injury.jaw_concussion += 20
        with patch.object(self.arena, "check_punch_collisions", side_effect=equal_damage_contacts):
            self.engine.advance_match(self.arena, 1)
        self.assertEqual(self.arena.f1.damage_dealt, 10)
        self.assertEqual(self.arena.f2.damage_dealt, 10)
        self.assertEqual(self.arena.f1.finishing_threat, 5)
        self.assertEqual(self.arena.f2.finishing_threat, 30)
        self.assertEqual(self.arena.scores, [15, 40])
        self.assertEqual(self.arena.winner.name, "PHANTOM")

    def test_finishing_danger_weights_both_sides_and_ignores_treatment_reductions(self):
        injury = vars(self.arena.f1.injury).copy()
        after = dict(injury, jaw_concussion=10, liver_trauma=10, rib_fracture=10,
                     nose_fracture=10, l_eye_swelling=10, r_eye_swelling=10,
                     l_brow_cut=10, r_brow_cut=10, blood_loss_ml=1000)
        self.assertAlmostEqual(self.engine.finishing_threat_delta(injury, after, knockdowns=2), 83)
        self.assertEqual(self.engine.finishing_threat_delta(after, injury), 0)

    def test_guard_damage_is_credited_without_inventing_injury_danger(self):
        def guard_contact(attacker, defender):
            if attacker.name == "TITAN":
                defender.hp -= 3.5
        with patch.object(self.arena, "check_punch_collisions", side_effect=guard_contact):
            self.engine.advance_match(self.arena, 1)
        self.assertEqual(self.arena.f1.damage_dealt, 3.5)
        self.assertEqual(self.arena.f1.finishing_threat, 0)
        self.assertEqual(self.arena.scores, [3.5, 0])

    def test_injury_capture_is_detached_complete_and_keeps_node_identity(self):
        self.arena.f1.injury.r_eye_swelling = 115.5
        self.arena.f2.injury.nose_fracture = 36
        before = plain(self.snapshot())
        rng = random.getstate()
        frame = self.engine.injury_snapshot(self.arena, 5, {"red": "mac-node", "blue": "pi-node"})
        self.assertEqual(random.getstate(), rng)
        self.assertEqual(plain(self.snapshot()), before)
        self.assertEqual([f["controller"] for f in frame["fighters"]], ["mac-node", "pi-node"])
        for item, fighter in zip(frame["fighters"], (self.arena.f1, self.arena.f2)):
            self.assertEqual(item["injury"], vars(fighter.injury))
        self.arena.f1.injury.r_eye_swelling = 0
        self.assertEqual(frame["fighters"][0]["injury"]["r_eye_swelling"], 115.5)
        plain(frame)

    def test_report_preserves_timeline_and_escapes_embedded_html(self):
        frames = [self.engine.injury_snapshot(self.arena, 0, {"red": "a", "blue": "b"})]
        self.arena.f2.injury.l_brow_cut = 82.5
        frames.append(self.engine.injury_snapshot(self.arena, 1, {"red": "a", "blue": "b"}))
        hostile = '</script><script>alert("node name")</script>'
        result = {"status": "incomplete", "winner": None, "method": "No official result", "error": hostile}
        events = [{"tick": 1, "fighter": "PHANTOM", "changes": {"l_brow_cut": {"before": 0, "after": 82.5}}}]
        with tempfile.TemporaryDirectory() as folder:
            paths = self.engine.export_injury_report(folder, frames, events, result)
            data = json.loads(Path(paths["json"]).read_text())
            html = Path(paths["html"]).read_text()
            self.assertEqual(data["frames"], plain(frames))
            self.assertEqual(data["events"], events)
            self.assertEqual(data["result"]["error"], hostile)
            self.assertNotIn(hostile, html)
            embedded = re.search(r'<script id="replay-data" type="application/json">(.*?)</script>', html, re.DOTALL)
            self.assertIsNotNone(embedded)
            self.assertEqual(json.loads(embedded.group(1)), data)

    def test_tick_limit_exports_incomplete_without_winner(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "OSTADIX_BOXING_HEADLESS": "1", "OSTADIX_BOXING_OUT": folder,
            "OSTADIX_BOXING_MAX_TICKS": "1", "OSTADIX_BOXING_RED_NODE": "local",
            "OSTADIX_BOXING_BLUE_NODE": "local",
        }), patch.object(self.engine, "term_write"), contextlib.redirect_stdout(io.StringIO()):
            result = self.engine.run_championship_match("engine-test-source")
            self.assertEqual(result["status"], "incomplete")
            self.assertIsNone(result["winner"])
            self.assertEqual(result["method"], "No official result")
            exported = json.loads((Path(result["output_dir"]) / "match.json").read_text())
            self.assertEqual(exported["result"], result)
            self.assertEqual([frame["tick"] for frame in exported["frames"]], [0, 1])

    def test_transport_error_exports_failed_tick_without_retry_or_winner(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "OSTADIX_BOXING_HEADLESS": "1", "OSTADIX_BOXING_OUT": folder,
            "OSTADIX_BOXING_MAX_TICKS": "2", "OSTADIX_BOXING_RED_NODE": "local",
            "OSTADIX_BOXING_BLUE_NODE": "local",
        }), patch.object(self.engine, "term_write"), contextlib.redirect_stdout(io.StringIO()), \
                patch.object(self.engine.BoxingNodes, "steps", side_effect=TimeoutError("completion unknown")) as steps:
            with self.assertRaisesRegex(RuntimeError, "completion unknown"):
                self.engine.run_championship_match("engine-test-source")
            steps.assert_called_once()
            exported = json.loads((Path(folder) / "match.json").read_text())
            self.assertEqual(exported["result"]["status"], "error")
            self.assertEqual(exported["result"]["ticks"], 0)
            self.assertIsNone(exported["result"]["winner"])
            self.assertEqual(len(exported["frames"]), 1)

    def test_terminal_examination_selects_each_fighter_and_quits_incomplete(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "OSTADIX_BOXING_HEADLESS": "1", "OSTADIX_BOXING_OUT": folder,
            "OSTADIX_BOXING_RED_NODE": "local", "OSTADIX_BOXING_BLUE_NODE": "local",
        }), patch.object(self.engine, "term_write"), contextlib.redirect_stdout(io.StringIO()), \
                patch.object(self.engine, "BoxingTerminal") as terminal_class, \
                patch.object(self.engine.time, "sleep"):
            terminal = terminal_class.return_value
            terminal.fd = None
            terminal.keys.side_effect = ["1", "2", "i", "q"]
            result = self.engine.run_championship_match("engine-test-source")
            views = [call.args[0] for call in terminal.draw.call_args_list]
            self.assertIn("TITAN · FACE CLOSE-UP", views[0])
            self.assertNotIn("PHANTOM", views[0])
            self.assertIn("PHANTOM · FACE CLOSE-UP", views[1])
            self.assertNotIn("TITAN", views[1])
            self.assertIn("TITAN", views[2])
            self.assertIn("PHANTOM", views[2])
            self.assertEqual(result["status"], "interrupted")
            self.assertEqual(result["ticks"], 0)
            self.assertIsNone(result["winner"])
            terminal.close.assert_called_once()

    def test_batched_terminal_keys_keep_input_order_and_ctrl_c_is_graceful(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "OSTADIX_BOXING_HEADLESS": "1", "OSTADIX_BOXING_OUT": folder,
            "OSTADIX_BOXING_RED_NODE": "local", "OSTADIX_BOXING_BLUE_NODE": "local",
        }), patch.object(self.engine, "term_write"), contextlib.redirect_stdout(io.StringIO()), \
                patch.object(self.engine, "BoxingTerminal") as terminal_class, \
                patch.object(self.engine.time, "sleep"):
            terminal = terminal_class.return_value
            terminal.fd = None
            # Select red then resume in one input read; select blue; then toggle,
            # examine both and resume in order. Ctrl-C must export the final state.
            terminal.keys.side_effect = ["1 ", "2", " i ", "\x03"]
            result = self.engine.run_championship_match("engine-test-source")
            self.assertEqual(terminal.draw.call_count, 1)
            self.assertIn("PHANTOM · FACE CLOSE-UP", terminal.draw.call_args.args[0])
            self.assertEqual(result["status"], "interrupted")
            self.assertEqual(result["ticks"], 2)
            self.assertIsNone(result["winner"])
            terminal.close.assert_called_once()

    def transport_fixture(self, folder):
        transport = self.engine.BoxingNodes.__new__(self.engine.BoxingNodes)
        transport.controllers = {"red": "red-node", "blue": "blue-node"}
        transport.endpoints = {"red": ("127.0.0.1:7337", "a" * 64)}
        transport.engine_source = "python[91]^(\n# fixture engine\n)_python[91]"
        transport.output_dir = Path(folder)
        transport.timeout = 3
        transport.pool = None
        transport.octl = "/fixture/octl"
        return transport

    def node_receipt(self, args, source, payload):
        return {
            "schema": "ostadix.hosted-operation-receipt/v1",
            "node_id": "red-node",
            "task_id": args[args.index("--task-id") + 1],
            "attempt_id": args[args.index("--attempt-id") + 1],
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "outcome": {"status": "succeeded", "value": {
                "t": "text", "v": {"utf8": json.dumps(payload), "encoding": "utf-8"},
            }},
        }

    def test_node_reply_decodes_canonical_text_and_preserves_receipt(self):
        snapshot = self.snapshot()
        expected = plain(self.engine.compute_fighter(snapshot, "red"))
        with tempfile.TemporaryDirectory() as folder:
            transport = self.transport_fixture(folder)
            with patch.object(transport, "command", side_effect=lambda args, source: self.node_receipt(args, source, expected)) as command:
                actual = transport.remote_step(snapshot, "red")
            self.assertEqual(actual, expected)
            command.assert_called_once()
            args, source = command.call_args.args
            self.assertEqual(args[-1], "-")
            self.assertIn("--address", args)
            self.assertIn("--expected-catalog-sha256", args)
            self.assertNotIn("--manual", args)
            self.assertIn(transport.engine_source, source)
            receipt = json.loads((Path(folder) / "receipts/1-red.json").read_text())
            self.assertEqual(receipt["source_sha256"], hashlib.sha256(source.encode()).hexdigest())

    def test_node_receipt_identity_mismatch_is_never_accepted_or_retried(self):
        snapshot = self.snapshot()
        expected = plain(self.engine.compute_fighter(snapshot, "red"))
        for field in ("schema", "node_id", "task_id", "attempt_id", "source_sha256"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as folder:
                transport = self.transport_fixture(folder)
                def invalid_receipt(args, source):
                    receipt = self.node_receipt(args, source, expected)
                    receipt[field] = "wrong"
                    return receipt
                with patch.object(transport, "command", side_effect=invalid_receipt) as command:
                    with self.assertRaisesRegex(RuntimeError, "receipt mismatch"):
                        transport.remote_step(snapshot, "red")
                command.assert_called_once()
                failure = json.loads((Path(folder) / "receipts/1-red.error.json").read_text())
                self.assertFalse(failure["retried"])
                self.assertEqual(failure["side"], "red")

    def test_node_timeout_preserves_unknown_completion_without_retry(self):
        snapshot = self.snapshot()
        with tempfile.TemporaryDirectory() as folder:
            transport = self.transport_fixture(folder)
            with patch.object(transport, "command", side_effect=TimeoutError("lost after submit")) as command:
                with self.assertRaises(TimeoutError):
                    transport.remote_step(snapshot, "red")
            command.assert_called_once()
            failure = json.loads((Path(folder) / "receipts/1-red.error.json").read_text())
            self.assertIn("unknown", failure["completion"])
            self.assertFalse(failure["retried"])

    def test_failed_native_outcome_is_saved_but_cannot_be_accepted_as_success(self):
        snapshot = self.snapshot()
        with tempfile.TemporaryDirectory() as folder:
            transport = self.transport_fixture(folder)
            def failed_run(command, **kwargs):
                receipt = self.node_receipt(command[1:], kwargs["input"], {})
                receipt["outcome"] = {"status": "failed", "message": "backend unavailable"}
                return subprocess.CompletedProcess(command, 1, json.dumps(receipt), "operation failed")
            with patch.object(self.engine.subprocess, "run", side_effect=failed_run) as run:
                with self.assertRaisesRegex(RuntimeError, "node failed"):
                    transport.remote_step(snapshot, "red")
            run.assert_called_once()
            receipt = json.loads((Path(folder) / "receipts/1-red.json").read_text())
            self.assertEqual(receipt["outcome"], {"status": "failed", "message": "backend unavailable"})
            failure = json.loads((Path(folder) / "receipts/1-red.error.json").read_text())
            self.assertFalse(failure["retried"])

    def test_node_profile_identity_mismatch_fails_before_dispatch(self):
        peers = [{"node_id": "red-node", "remembered": True, "address": "127.0.0.1:7337"}]
        wrong_profile = {"node_id": "other-node", "backend_catalog_sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"OSTADIX_BOXING_OCTL": "/fixture/octl"}), \
                patch.object(self.engine.BoxingNodes, "command", side_effect=[peers, wrong_profile]) as command:
            with self.assertRaisesRegex(RuntimeError, "profile identity mismatch"):
                self.engine.BoxingNodes("engine", {"red": "red-node", "blue": "local"}, folder)
            self.assertEqual(command.call_count, 2)
            self.assertTrue(all(call.args[0][1] != "run" for call in command.call_args_list))


if __name__ == "__main__":
    unittest.main()
