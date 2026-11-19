"""Independent contract checks and failure tests for lifecycle conformance.

Model-only tests are not native execution evidence. The runner tests added
below exercise admission and provenance independently of production ISA runs.
"""
from __future__ import annotations

from dataclasses import replace
import importlib.util
import json
import tempfile
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
import subprocess
from types import SimpleNamespace
import contextlib
import io


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = Path(__file__).with_name("ocore_lifecycle_model.py")
SPEC = importlib.util.spec_from_file_location("ocore_lifecycle_reference", MODEL_PATH)
model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = model
SPEC.loader.exec_module(model)


def claim(epoch=0, new=1, expected=0, sequence=1, tag=91):
    return model.o10_request(164, epoch=epoch, sequence=sequence, tag=tag,
                              payload=struct.pack("<QQ", new, expected))


def withdraw(handle=1 << 32, sequence=2, epoch=1):
    return model.o10_request(172, epoch=epoch, sequence=sequence,
                              payload=struct.pack("<QBI", handle, 0, 0))


def restore(handle=1 << 32, sequence=3, epoch=1, instance=bytes(16)):
    index = handle & model.U32
    return model.o10_request(174, epoch=epoch, sequence=sequence,
                              payload=struct.pack("<Q", handle) + instance
                              + struct.pack("<QQ", *((3, 4) if index == 0 else (1, 2))))


def bind(lease=(2 << 32) | 1, generation=2, sequence=4):
    return model.o10_request(184, sequence=sequence, payload=struct.pack("<QQ", lease, generation << 32))


def error_code(observation):
    return int.from_bytes(observation.reply[7:11], "little") if observation.reply[4] == 161 else 0


class IndependentLifecycleModelTests(unittest.TestCase):
    def test_different_generation_policies_have_distinct_limits(self):
        limits = model.Limits()
        self.assertEqual(limits.domain, 0xffffffff)
        self.assertEqual(limits.transport, (1 << 64) - 1)
        self.assertEqual(limits.session_epoch, (1 << 64) - 1)
        self.assertEqual(limits.serial, (1 << 63) - 1)
        with self.assertRaises(ValueError):
            model.Limits(domain=1 << 32)

    def test_symbolic_sessions_remain_fresh_across_reopen(self):
        state = model.Namespace.fresh()
        state, old = state.session(1, 1)
        state, _, _ = state.version(old, 512, False)
        state, code, _ = state.attach(old, 1)
        self.assertEqual(code, 0)
        state = state.reopen()
        state, fresh = state.session(1, 1)
        self.assertNotEqual(fresh, old)
        self.assertEqual(state.version(old, 512, False)[1], 4)
        self.assertEqual(state.fids, ())

    def test_rejected_session_generation_does_not_revoke_live_fids(self):
        state, token = model.Namespace.fresh().session(1, model.U64)
        state, _, _ = state.version(token, 512, False)
        state, _, _ = state.attach(token, 9)
        for bad in (0, 1, model.U64):
            rejected, value = state.session(1, bad)
            self.assertEqual(value, 0)
            self.assertEqual(rejected, state)

    def test_last_serial_is_live_then_retires_without_wrap(self):
        state = replace(model.Namespace.fresh(), serial=model.SERIAL_MAX - 1)
        state, last = state.session(1, 1)
        self.assertEqual(last, model.SERIAL_MAX)
        self.assertEqual(state.current(1), last)
        rejected, zero = state.session(4, 1)
        self.assertEqual(zero, 0)
        self.assertEqual(rejected, state)

    def test_journalled_error_is_a_state_change_but_replay_has_no_effect(self):
        state, _ = model.Lifecycle.fresh().execute(claim())
        before = state
        bad = withdraw(handle=(1 << 32) | 99)
        state, observed = state.execute(bad)
        self.assertEqual(error_code(observed), 5)
        self.assertEqual(state.domains, before.domains)
        self.assertEqual(state.namespace, before.namespace)
        self.assertEqual(state.journal.last, 2)
        self.assertEqual(observed.admission, "journalled")
        replayed, cached = state.execute(bad)
        self.assertEqual(replayed, state)
        self.assertEqual(cached.reply, observed.reply)
        self.assertEqual(cached.admission, "replay")
        self.assertEqual(cached.effects, ())

    def test_every_request_byte_including_tag_is_retry_identity(self):
        state, _ = model.Lifecycle.fresh().execute(claim())
        request = withdraw()
        state, _ = state.execute(request)
        for offset in (5, 23, 31, 35):
            changed = bytearray(request)
            changed[offset] ^= 1
            rejected, observed = state.execute(bytes(changed))
            self.assertEqual(error_code(observed), 4)
            self.assertEqual(rejected, state)

    def test_retained_old_epoch_reply_precedes_current_epoch_check(self):
        state, _ = model.Lifecycle.fresh().execute(claim())
        old = withdraw()
        state, original = state.execute(old)
        state, _ = state.execute(claim(epoch=1, new=2, expected=1, sequence=3))
        same, observed = state.execute(old)
        self.assertEqual(same, state)
        self.assertEqual(observed.reply, original.reply)
        self.assertEqual(observed.admission, "replay")
        rejected, observed = state.execute(restore(sequence=4))
        self.assertEqual(error_code(observed), 3)
        self.assertEqual(rejected, state)

    def test_full_width_restore_counterexamples(self):
        for epoch in (model.U32, 0x7bed31e65e6f3ac6, 0xe3c89e5e834b8c17, model.U64 - 1):
            with self.subTest(epoch=hex(epoch)):
                state, _ = model.Lifecycle.fresh(transport=epoch).execute(claim())
                survivor = state.namespace.current(4)
                old_linux = state.namespace.current(1)
                state, _ = state.execute(withdraw())
                state, restored = state.execute(restore())
                self.assertEqual(restored.reply[4], 175)
                self.assertEqual(state.domains[0].transport, epoch + 1)
                self.assertEqual(state.domains[0].state, "waiting")
                self.assertFalse(state.domains[0].runnable)
                self.assertEqual(state.namespace.current(1), 0)
                self.assertEqual(state.namespace.current(4), survivor)
                state, bound = state.execute(bind())
                self.assertEqual(bound.reply[4], 185)
                self.assertTrue(state.domains[0].runnable)
                self.assertNotEqual(state.namespace.current(1), old_linux)
                self.assertEqual(state.namespace.current(4), survivor)

    def test_exhausted_restore_is_nondestructive_and_journalled(self):
        state, _ = model.Lifecycle.fresh(transport=model.U64).execute(claim())
        state, _ = state.execute(withdraw())
        before = state
        state, observed = state.execute(restore())
        self.assertEqual(error_code(observed), 8)
        self.assertEqual(observed.effects, ())
        self.assertEqual(state.domains, before.domains)
        self.assertEqual(state.namespace, before.namespace)
        self.assertEqual(state.journal.last, 3)

    def test_containment_and_withdrawal_exhaustion_have_different_outcomes(self):
        state = model.Lifecycle.fresh()
        state = state.domain(0, replace(state.domains[0], lease=model.U32))
        ordinary, rejection = state.withdraw(0)
        terminal, failure = state.withdraw(0, contain=True)
        self.assertEqual(ordinary, state)
        self.assertEqual(rejection.value, 8)
        self.assertEqual(failure.terminal[0], 0x1106)
        self.assertFalse(terminal.domains[0].live)

    def test_finite_profiles_reach_closed_finite_graphs(self):
        for name in ('session_profile', 'journal_profile', 'replacement_profile'):
            with self.subTest(profile=name):
                result = getattr(model, name)()
                self.assertTrue(result['exhaustive'])
                self.assertGreater(result['states'], 1)
                self.assertGreater(result['transitions'], result['states'])

    def test_finite_search_never_labels_a_cutoff_exhaustive(self):
        result = model.session_profile(state_limit=2)
        self.assertFalse(result['exhaustive'])
        self.assertEqual(result['scope'], 'state-limited')

    def test_concrete_session_collision_is_rejected(self):
        mapping = model.TokenCorrespondence()
        mapping.observe(1, 0x1234)
        mapping.observe(1, 0x1234)
        with self.assertRaises(AssertionError):
            mapping.observe(2, 0x1234)
        with self.assertRaises(AssertionError):
            mapping.observe(1, 0x5678)

    def test_terminal_nodes_have_no_outgoing_finite_edges(self):
        terminal = replace(model.Lifecycle.fresh(), terminal=(1, 0, 0, 0))
        result = model.explore(terminal, ('must-not-run',),
            lambda *_: self.fail('terminal state was executed'))
        self.assertTrue(result['exhaustive'])
        self.assertEqual(result['transitions'], 0)

    def test_plan9_failed_session_allocation_preserves_partial_transport_state(self):
        limits = model.Limits(serial=2)
        state = model.Lifecycle.fresh(limits=limits)
        changed, observed = state.bind(1, (1 << 32) | 4, 1 << 32, limits)
        self.assertEqual(observed.value, 12)
        self.assertEqual(changed.domains[1].transport, 2)
        self.assertFalse(changed.domains[1].active)
        self.assertEqual(changed.domains[1].state, 'running')
        self.assertEqual(changed.namespace, state.namespace)

    def test_withdraw_before_binding_keeps_provisional_mechanism_without_authority(self):
        state, _ = model.Lifecycle.fresh().withdraw(0)
        state, _ = state.restore(0)
        self.assertTrue(state.domains[0].detached)
        self.assertTrue(state.domains[0].active)
        state, _ = state.withdraw(0)
        self.assertEqual(state.domains[0].state, 'withdrawn')
        self.assertTrue(state.domains[0].active)
        self.assertFalse(state.domains[0].bound)
        self.assertFalse(state.domains[0].runnable)
        self.assertEqual(state.namespace.current(1), 0)


GATE_SPEC = importlib.util.spec_from_file_location('ocore_lifecycle_gate', ROOT / 'scripts/check_ocore_lifecycle_conformance.py')
gate = importlib.util.module_from_spec(GATE_SPEC)
sys.modules[GATE_SPEC.name] = gate
GATE_SPEC.loader.exec_module(gate)


class LifecycleRunnerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = gate.load_vectors(ROOT / 'tests/fixtures/ocore_lifecycle_vectors.json')
        cls.case = cls.corpus['cases'][0]

    def observed(self):
        rows = []
        for expected in self.case['expected']:
            row = {k: v for k, v in expected.items() if k not in ('value_kind', 'semantic_effects')}
            row['sessions'] = [1000000 + v if v else 0 for v in expected['sessions']]
            if expected['value_kind'] == 'session':
                row['value'] = 1000000 + expected['value'] if expected['value'] else 0
            row['effects'] = expected['semantic_effects']
            rows.append(row)
        return rows

    def encode(self, rows):
        return ('\n'.join(json.dumps(row) for row in rows) + '\n').encode()

    def test_arbitrary_bijective_tokens_do_not_require_production_formula(self):
        result = gate.compare_case(self.case, self.encode(self.observed()), 0)
        self.assertTrue(result['matched'])

    def test_empty_corpus_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'empty.json'
            corpus.write_text(json.dumps({'schema': 'ostadix.ocore-lifecycle-vectors/v1', 'cases': []}))
            with self.assertRaisesRegex(RuntimeError, 'empty lifecycle corpus'):
                gate.load_vectors(corpus)

    def test_stored_expectations_cannot_silently_follow_a_changed_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = json.loads(json.dumps(self.corpus))
            corpus['cases'][0]['expected'][0]['journal'][0] = 999
            path = Path(directory) / 'changed.json'
            path.write_text(json.dumps(corpus))
            with self.assertRaisesRegex(RuntimeError, 'stored oracle expectations differ'):
                gate.load_vectors(path)

    def test_relocated_canonical_bytes_qualify_but_custom_corpus_is_diagnostic(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'vectors.json'
            canonical = gate.ROOT / 'tests/fixtures/ocore_lifecycle_vectors.json'
            path.write_bytes(canonical.read_bytes())
            self.assertTrue(gate.corpus_admission(path, False)['canonical_bytes'])
            changed = json.loads(path.read_text())
            changed['cases'] = changed['cases'][:1]
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(RuntimeError, 'requires --diagnostic'):
                gate.corpus_admission(path, False)
            self.assertEqual(gate.corpus_admission(path, True)['scope'], 'custom diagnostic corpus')

    def test_initial_state_rejects_booleans_and_oversized_integers(self):
        with tempfile.TemporaryDirectory() as name:
            for value in (True, -1, 1 << 64):
                corpus = json.loads(json.dumps(self.corpus))
                corpus['cases'][0]['initial']['serial'] = value
                path = Path(name) / 'bad.json'
                path.write_text(json.dumps(corpus))
                with self.assertRaisesRegex(RuntimeError, 'initial scalar'):
                    gate.load_vectors(path)

    def test_no_output_and_missing_observation_are_not_success(self):
        for output in (b'', self.encode(self.observed()[:-1])):
            with self.subTest(output_bytes=len(output)):
                with self.assertRaises(RuntimeError):
                    gate.compare_case(self.case, output, 0)

    def test_wrong_exit_is_rejected_even_with_expected_observations(self):
        with self.assertRaises(RuntimeError):
            gate.compare_case(self.case, self.encode(self.observed()), 86)

    def test_changed_reply_and_effect_order_are_detected(self):
        rows = self.observed()
        rows[-1]['reply'] = '00'
        with self.assertRaisesRegex(RuntimeError, 'reply'):
            gate.compare_case(self.case, self.encode(rows), 0)
        rows = self.observed()
        row = next(row for row in rows if row['effects'])
        row['effects'] = list(reversed(row['effects']))
        with self.assertRaisesRegex(RuntimeError, 'semantic_effects'):
            gate.compare_case(self.case, self.encode(rows), 0)

    def test_token_collision_and_boolean_numbers_are_detected(self):
        rows = self.observed()
        rows[0]['sessions'][3] = rows[0]['sessions'][0]
        with self.assertRaisesRegex(RuntimeError, 'collided'):
            gate.compare_case(self.case, self.encode(rows), 0)
        rows = self.observed()
        rows[0]['value'] = False
        with self.assertRaisesRegex(RuntimeError, 'non-u64'):
            gate.compare_case(self.case, self.encode(rows), 0)

    def test_existing_output_directory_is_preserved_byte_for_byte(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sentinel = directory / 'failure.json'
            sentinel.write_text('historical evidence\n')
            before = {p.name: p.read_bytes() for p in directory.iterdir()}
            argv = ['gate', '--ocorec', '/does/not/exist', '--output-dir', name]
            with patch.object(sys, 'argv', argv), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gate.main(), 1)
            self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, before)

    def test_inventory_paths_cannot_make_isolated_mutations_overwrite_source(self):
        class Evidence:
            def watch_source(self, _):
                pass
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            root = base / 'work/src'
            (root / 'scripts').mkdir(parents=True)
            victim = root / 'policy.oc'
            original = b'module policy;\n'
            victim.write_bytes(original)
            # Both of the first two names resolve inside root; joining either
            # to generated would previously write the original victim instead.
            names = (str(victim), '../../work/src/policy.oc', './policy.oc')
            for index, entry in enumerate(names):
                with self.subTest(entry=entry):
                    inventory = root / 'scripts/build_okernel_unified_world.py'
                    inventory.write_text('SOURCES = ' + repr([entry]) + '\n')
                    mutation = {'name': 'outside-write', 'path': entry,
                                'old': 'module policy;', 'new': 'overwritten', 'count': 1}
                    with self.assertRaisesRegex(RuntimeError, 'normalized relative'):
                        gate.prepare_inputs(SimpleNamespace(source_root=root),
                            base / ('out' + str(index)), Evidence(), [mutation])
                    self.assertEqual(victim.read_bytes(), original)

    def test_successful_producer_cannot_reuse_a_stale_object(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / 'stale.o'
            output.write_bytes(b'old bytes')
            with self.assertRaises(RuntimeError):
                gate.native.produce([sys.executable, '-c', 'pass'], [output],
                                    runner=gate.native.RunEvidence().checked_run)
            self.assertFalse(output.exists())

    def test_missing_required_runner_and_new_backend_fail_closed(self):
        with patch.object(gate.native, 'host_isa', return_value='other-isa'):
            with self.assertRaisesRegex(RuntimeError, 'missing'):
                gate.native.execution_prefix('riscv64', '/definitely/missing/qemu-riscv64')
        with tempfile.TemporaryDirectory() as name:
            catalog = Path(name) / 'common.rs'
            catalog.write_text("pub enum Target {\n NewIsa,\n}\n"
                "pub fn name(self) -> &'static str { match self { Target::NewIsa => \"newisa\", } }")
            with self.assertRaisesRegex(RuntimeError, 'coverage differs'):
                gate.native.canonical_target_coverage(catalog=catalog)

    def test_changed_source_cannot_keep_old_provenance(self):
        with tempfile.TemporaryDirectory() as name:
            source = Path(name) / 'policy.oc'
            source.write_text('original')
            evidence = gate.native.RunEvidence([source])
            source.write_text('changed')
            with self.assertRaisesRegex(RuntimeError, 'run input changed'):
                evidence.finish()

    def test_batch_requires_every_exit_and_preserves_case_order(self):
        class Evidence:
            def watch_source(self, _):
                pass
            def run(self, _, **__):
                return subprocess.CompletedProcess([], 0, b'{"case":0,"exit":0}\n', b'')
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(RuntimeError, 'skipped'):
                gate.execute_batch([self.case, self.case], Path('/unused'), [], Path(name) / 'run', Evidence())

    def test_modeled_interrupt_reset_requires_all_lrs_and_interface_state(self):
        reset = [list(row) for row in gate.model.interrupt_bank_reset(0)]
        self.assertEqual(gate.canonical_effects(reset + [reset[0]]), reset)
        self.assertEqual(gate.canonical_effects(reset[:4]), [])
        for index in range(len(reset)):
            with self.subTest(omitted=index):
                with self.assertRaisesRegex(RuntimeError, 'interrupt-bank reset'):
                    gate.canonical_effects(reset[:index] + reset[index+1:])


if __name__ == '__main__':
    unittest.main()
