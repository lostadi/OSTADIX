"""Exercise the additive launcher with an inert tmux/controller fixture.

No server, VM, compiler or installed package is started by these tests.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts/okernel-unified-console.sh"


PROFILE = {
    "schema": "ostadix.unified-world-monitor/v1", "profile": "linux-original-plan9",
    "outer_ram_bytes": 0xc0000000,
    "domains": [
        {"id": 0, "name": "linux", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000,
         "guest_ram_bytes": 0x20000000, "entry": 0x40000000, "x0": 0x47e00000, "vmid": 1},
        {"id": 1, "name": "plan9", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0xb0000000,
         "guest_ram_bytes": 0x20000000, "entry": 0x40100000, "x0": 0x40000000, "vmid": 2}],
    "loader_addresses": {"inputs/linux.Image": 0x48000000, "linux.dtb": 0x4fe00000,
                         "inputs/linux.initramfs": 0x50000000, "inputs/plan9.kernel": 0xb0100000,
                         "plan9.dtb": 0xb0000000},
    "block_backing": {"address": 0x70000000, "bytes": 0x40000000},
    "namespace": {"address": 0x6c000000, "bytes": 0x1000000, "epoch_address": 0x6d000000,
                  "quiescence_address": 0x6d000008, "clock_address": 0x6d000010,
                  "linux_grant": 1, "plan9_grant": 4, "native_peer_grant": 2},
    "plan9_console": {"input_address": 0x6d010000, "input_bytes": 4096,
                     "output_address": 0x6d020000, "output_bytes": 65536},
    "console_mux": {"escape": 30, "linux_select": 48, "plan9_select": 49,
                    "linux_output_address": 0x6d040000, "output_bytes": 65536},
    "gic": {"version": 3, "physical_controller": "native monitor only",
            "distributor": [0x08000000, 0x08010000], "redistributor": [0x080a0000, 0x080c0000],
            "native_quantum_irq": 26, "quantum_counter_divisor": 100, "lpi_authority": False},
}


TMUX = r'''
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
assert args[:1] == ['-L']
socket = args[1]
args = args[2:]
if args[:1] == ['-f']:
    args = args[2:]
path = Path(os.environ['FIXTURE_TMUX'])
all_state = json.loads(path.read_text()) if path.exists() else {}
state = all_state.setdefault(socket, {'exists': False, 'options': {}, 'calls': [], 'dead': False, 'exit': 0})
state['calls'].append(args)
command = args[0]
code, output = 0, ''
if command == 'has-session':
    code = 0 if state['exists'] else 1
elif command == 'new-session':
    state['exists'] = True
    state['dead'] = False
    state['exit'] = 0
    state['remain_on_exit'] = args[args.index('remain-on-exit') + 1]
    for key in ('@okernel-unified-state', '@okernel-unified-build', '@okernel-unified-before-head'):
        state['options'][key] = args[args.index(key) + 1]
elif command == 'show-options':
    output = state['options'].get(args[-1], '')
elif command == 'display-message':
    output = str(int(state['dead'])) if args[-1] == '#{pane_dead}' else str(state['exit'])
elif command == 'bind-key':
    assert args[1:] == ['-T', 'prefix', 'q', 'send-keys', '-t', '=okernel-unified:console.0', 'C-]']
    state.setdefault('bindings', {})['q'] = args[1:]
elif command == 'send-keys':
    assert args[-1] == 'C-]'
    state['dead'] = True
    mode = os.environ.get('FIXTURE_SAVE', 'complete')
    if mode == 'failed':
        state['exit'] = 7
    elif mode != 'no-save':
        private = Path(state['options']['@okernel-unified-state'])
        head_file = private / 'head.json'
        old = json.loads(head_file.read_text())
        session = private / 'unified-session-fixture-saved'
        session.mkdir(exist_ok=True)
        selected = {**old, 'previous': old['disk'], 'previous_namespace': old['namespace'], 'session': str(session)}
        head_file.write_text(json.dumps(selected))
        result = {'schema': 'ostadix.unified-world-session/v1', 'ok': True, 'after': selected,
                  'paired_snapshot': mode != 'partial', 'virtual_cpu_stopped': True,
                  'native_operations_quiescent': True}
        (session / 'result.json').write_text(json.dumps(result))
    if state['remain_on_exit'] == 'failed' and state['exit'] == 0:
        state['exists'] = False
elif command == 'kill-session':
    state['exists'] = False
elif command != 'attach-session':
    raise AssertionError('Unexpected tmux action: ' + repr(args))
path.write_text(json.dumps(all_state))
if output:
    print(output)
raise SystemExit(code)
'''


class UnifiedConsoleLauncherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="unified launcher fixture ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "private state $(literal)"
        self.build = self.root / "build profile [unified]"
        self.state.mkdir()
        self.build.mkdir()
        (self.state / "fork.json").write_text(json.dumps({
            "schema": "ostadix.okernel-state-fork/v1", "ok": True, "output": str(self.state)}))
        self.head = self.state / "head.json"
        self.head.write_text(json.dumps({
            "schema": "ostadix.package-domain-disk-head/v2",
            "disk": {"path": str(self.state / "disk-generations" / ("d" * 64 + ".ext4")),
                     "bytes": 0x40000000, "sha256": "d" * 64},
            "namespace": {"path": str(self.state / "namespace-generations" / ("e" * 64 + ".raw")),
                          "bytes": 0x1000000, "sha256": "e" * 64},
            "session": str(self.state / "previous-saved-session"),
        }))
        (self.build / "monitor-profile.json").write_text(json.dumps(PROFILE))
        self.tools = self.root / "tools"
        self.tools.mkdir()
        tmux = self.tools / "tmux"
        tmux.write_text("#!" + sys.executable + "\n" + TMUX)
        tmux.chmod(0o755)
        qemu = self.tools / "qemu-system-aarch64"
        qemu.write_text("#!/bin/sh\nprintf 'QEMU MUST NOT RUN IN THIS TEST\\n' >&2\nexit 99\n")
        qemu.chmod(0o755)
        self.database = self.root / "tmux.json"
        self.environment = {**os.environ, "PATH": str(self.tools) + os.pathsep + os.environ['PATH'],
                            "FIXTURE_TMUX": str(self.database), "XDG_STATE_HOME": str(self.root / "xdg")}
        self.environment.pop('OSTADIX_OKERNEL_STATE', None)

    def invoke(self, *arguments, complete=True, environment=None):
        command = ["bash", str(LAUNCHER)]
        if complete:
            command += ["--state", str(self.state), "--build", str(self.build)]
        command += list(arguments)
        return subprocess.run(command, env=environment or self.environment, text=True,
                              capture_output=True, timeout=10)

    def stored(self):
        data = json.loads(self.database.read_text())
        self.assertEqual(len(data), 1)
        socket, values = next(iter(data.items()))
        self.assertTrue(socket.startswith('ostadix-unified-'))
        return values

    def test_help_and_missing_explicit_paths_never_start_a_controller(self):
        self.assertEqual(self.invoke('help', complete=False).returncode, 0)
        result = self.invoke('start', '--detach', complete=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('both --state and --build are required', result.stderr)
        self.assertFalse(self.database.exists())

    def test_status_is_read_only_and_does_not_seed_or_publish_state(self):
        before = {path.name: path.read_bytes() for path in self.state.iterdir()}
        result = self.invoke('status')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Console not running', result.stdout)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.state.iterdir()})
        self.assertEqual([call[0] for call in self.stored()['calls']], ['has-session'])

    def test_repeated_start_uses_one_separate_session_and_exact_controller_arguments(self):
        before = self.head.read_bytes()
        for _ in range(2):
            result = self.invoke('start', '--detach')
            self.assertEqual(result.returncode, 0, result.stderr)
        state = self.stored()
        starts = [call for call in state['calls'] if call[0] == 'new-session']
        self.assertEqual(len(starts), 1)
        self.assertIn(str(ROOT / 'scripts/okernel_unified_world.py'), starts[0])
        self.assertEqual(starts[0][starts[0].index('--state') + 1], str(self.state))
        self.assertEqual(starts[0][starts[0].index('--build') + 1], str(self.build))
        self.assertIn('PYTHONUNBUFFERED=1', starts[0])
        self.assertNotIn('O_BACKEND_OPERATION_TIMEOUT_MS', ' '.join(starts[0]))
        self.assertEqual(before, self.head.read_bytes())

    def test_stop_requests_save_and_cleans_session_only_after_complete_paired_receipt(self):
        self.assertEqual(self.invoke('start', '--detach').returncode, 0)
        result = self.invoke('stop')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('saved and stopped', result.stdout)
        values = self.stored()
        self.assertFalse(values['exists'])
        actions = [call[0] for call in values['calls']]
        self.assertEqual(values['remain_on_exit'], 'failed')
        self.assertNotIn('kill-session', actions)
        self.assertNotIn('kill-server', actions)
        before_head = next(i for i, call in enumerate(values['calls'])
                           if call[0] == 'show-options' and call[-1] == '@okernel-unified-before-head')
        self.assertLess(before_head, actions.index('send-keys'))
        selected = json.loads(self.head.read_text())
        self.assertEqual(selected['schema'], 'ostadix.package-domain-disk-head/v2')
        self.assertIn('Saved namespace: ' + selected['namespace']['sha256'], result.stdout)

    def test_prefix_q_binding_does_not_run_save_or_change_the_head(self):
        before = self.head.read_bytes()
        result = self.invoke('start', '--detach')
        self.assertEqual(result.returncode, 0, result.stderr)
        values = self.stored()
        self.assertTrue(values['exists'])
        self.assertFalse(values['dead'])
        self.assertEqual(values['bindings']['q'],
                         ['-T', 'prefix', 'q', 'send-keys', '-t', '=okernel-unified:console.0', 'C-]'])
        self.assertFalse(any(call[0] in ('send-keys', 'kill-session', 'kill-server') for call in values['calls']))
        self.assertEqual(before, self.head.read_bytes())

    def test_exit_and_quit_require_and_publish_a_complete_paired_save(self):
        initial = self.head.read_bytes()
        for action in ('exit', 'quit'):
            with self.subTest(action=action):
                self.database.unlink(missing_ok=True)
                self.head.write_bytes(initial)
                self.assertEqual(self.invoke('start', '--detach').returncode, 0)
                result = self.invoke(action)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('saved and stopped', result.stdout)
                values = self.stored()
                self.assertFalse(values['exists'])
                sends = [call for call in values['calls'] if call[0] == 'send-keys']
                self.assertEqual(sends, [['send-keys', '-t', '=okernel-unified:console.0', 'C-]']])
                actions = [call[0] for call in values['calls']]
                self.assertEqual(values['remain_on_exit'], 'failed')
                self.assertNotIn('kill-session', actions)
                self.assertNotIn('kill-server', actions)
                selected = json.loads(self.head.read_text())
                receipt = json.loads((Path(selected['session']) / 'result.json').read_text())
                self.assertEqual(receipt['after'], selected)
                self.assertTrue(all(receipt[key] is True for key in
                                    ('ok', 'paired_snapshot', 'virtual_cpu_stopped', 'native_operations_quiescent')))

    def test_legacy_retained_successful_pane_is_cleaned_only_after_paired_save(self):
        self.assertEqual(self.invoke('start', '--detach').returncode, 0)
        database = json.loads(self.database.read_text())
        next(iter(database.values()))['remain_on_exit'] = 'on'
        self.database.write_text(json.dumps(database))
        result = self.invoke('exit')
        self.assertEqual(result.returncode, 0, result.stderr)
        values = self.stored()
        self.assertFalse(values['exists'])
        actions = [call[0] for call in values['calls']]
        self.assertLess(actions.index('send-keys'), actions.index('kill-session'))
        self.assertNotIn('kill-server', actions)
        selected = json.loads(self.head.read_text())
        receipt = json.loads((Path(selected['session']) / 'result.json').read_text())
        self.assertTrue(receipt['ok'] and receipt['paired_snapshot'])

    def test_exit_aliases_without_a_session_do_not_start_a_controller(self):
        before = self.head.read_bytes()
        for action in ('exit', 'quit'):
            with self.subTest(action=action):
                result = self.invoke(action)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('already stopped', result.stdout)
        self.assertEqual(before, self.head.read_bytes())
        self.assertTrue(all(call[0] == 'has-session' for call in self.stored()['calls']))

    def test_no_save_partial_save_or_failed_controller_is_never_reported_as_saved(self):
        initial = self.head.read_bytes()
        for action in ('stop', 'exit', 'quit'):
            for mode in ('no-save', 'partial', 'failed'):
                with self.subTest(action=action, mode=mode):
                    self.database.unlink(missing_ok=True)
                    self.head.write_bytes(initial)
                    self.assertEqual(self.invoke('start', '--detach').returncode, 0)
                    environment = {**self.environment, 'FIXTURE_SAVE': mode}
                    result = self.invoke(action, environment=environment)
                    self.assertNotEqual(result.returncode, 0)
                    values = self.stored()
                    self.assertEqual(values['exists'], mode == 'failed')
                    self.assertFalse(any(call[0] in ('kill-session', 'kill-server') for call in values['calls']))
                    if mode == 'no-save':
                        self.assertEqual(initial, self.head.read_bytes())

    def test_an_existing_session_cannot_be_selected_with_a_different_build(self):
        self.assertEqual(self.invoke('start', '--detach').returncode, 0)
        alternative = self.root / 'other build'
        alternative.mkdir()
        (alternative / 'monitor-profile.json').write_text(json.dumps(PROFILE))
        result = self.invoke('--state', str(self.state), '--build', str(alternative),
                             'start', '--detach', complete=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('different state/build', result.stderr)
        self.assertEqual(sum(call[0] == 'new-session' for call in self.stored()['calls']), 1)

    def test_attach_requires_a_real_terminal(self):
        before = self.head.read_bytes()
        self.assertEqual(self.invoke('start', '--detach').returncode, 0)
        result = self.invoke('attach')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('real foreground terminal', result.stderr)
        self.assertFalse(any(call[0] == 'attach-session' for call in self.stored()['calls']))
        self.assertEqual(sum(call[0] == 'bind-key' for call in self.stored()['calls']), 2)
        self.assertFalse(any(call[0] == 'send-keys' for call in self.stored()['calls']))
        self.assertEqual(before, self.head.read_bytes())

    def test_working_package_domain_is_rejected_even_if_given_explicitly(self):
        working = Path(self.environment['XDG_STATE_HOME']) / 'ostadix/okernel/package-domain'
        working.mkdir(parents=True)
        result = self.invoke('--state', str(working), '--build', str(self.build),
                             'status', complete=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('working package-domain state', result.stderr)
        self.assertFalse(self.database.exists())


if __name__ == '__main__':
    unittest.main()
