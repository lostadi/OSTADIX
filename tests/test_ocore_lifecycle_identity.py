"""Admission and provenance controls; native identity execution is a separate lane."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('lifecycle_identity_gate', ROOT / 'scripts/check_ocore_lifecycle_identity.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class IdentityAdmissionTests(unittest.TestCase):
    def test_other_cwd_relative_output_cannot_overwrite_repository_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repo, caller = base / 'repo', base / 'caller'
            (repo / 'results').mkdir(parents=True)
            caller.mkdir()
            old = repo / 'results/generated.o'
            old.write_bytes(b'historical object')
            def producer(_, directory):
                # Native producers execute in the repository directory.
                (repo / directory / 'generated.o').write_bytes(b'new object')
                return {'targets': {}, 'complete': True}
            previous = Path.cwd()
            try:
                os.chdir(caller)
                with patch.object(gate, 'check', side_effect=producer), patch.object(
                    sys, 'argv', ['identity', '--ocorec', '/unused', '--output-dir', 'results']
                ), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gate.main(), 0)
            finally:
                os.chdir(previous)
            self.assertEqual(old.read_bytes(), b'historical object')
            self.assertEqual((caller / 'results/generated.o').read_bytes(), b'new object')

    def test_existing_directory_is_preserved_and_never_reaches_producers(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory / 'identity.json'
            marker.write_bytes(b'historical evidence')
            with patch.object(gate, 'check') as check, patch.object(
                sys, 'argv', ['identity', '--ocorec', '/unused', '--output-dir', str(directory)]
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gate.main(), 1)
                check.assert_not_called()
            self.assertEqual(marker.read_bytes(), b'historical evidence')

    def test_every_non_native_runner_is_bound_before_execution(self):
        captured = {}
        class StopAfterSnapshot(Exception):
            pass
        def evidence(directory, sources, tools):
            captured.update(sources=sources, tools=tools)
            raise StopAfterSnapshot
        prefixes = {'x86_64': [], 'aarch64': ['/fake/qemu-aarch64'],
                    'riscv64': ['/fake/qemu-riscv64']}
        with patch.object(gate, 'canonical_target_coverage', return_value={}), patch.object(
            gate, 'tool', side_effect=lambda path, _: path
        ), patch.object(gate, 'execution_prefix', side_effect=prefixes.__getitem__), patch.object(
            gate, 'IdentityEvidence', side_effect=evidence
        ), self.assertRaises(StopAfterSnapshot):
            gate.check('/fake/ocorec', Path('/unused'))
        self.assertEqual(captured['tools']['aarch64_runner'], '/fake/qemu-aarch64')
        self.assertEqual(captured['tools']['riscv64_runner'], '/fake/qemu-riscv64')
        self.assertIn(ROOT / 'scripts/check_ocore_native_equivalence.py', captured['sources'])

    def test_missing_required_runner_rejects_before_any_producer(self):
        def prefix(isa):
            if isa == 'riscv64':
                raise RuntimeError('missing required runner')
            return []
        with patch.object(gate, 'canonical_target_coverage', return_value={}), patch.object(
            gate, 'tool', side_effect=lambda path, _: path
        ), patch.object(gate, 'execution_prefix', side_effect=prefix), patch.object(
            gate, 'IdentityEvidence'
        ) as evidence, self.assertRaisesRegex(RuntimeError, 'missing required runner'):
            gate.check('/fake/ocorec', Path('/unused'))
        evidence.assert_not_called()


if __name__ == '__main__':
    unittest.main()
