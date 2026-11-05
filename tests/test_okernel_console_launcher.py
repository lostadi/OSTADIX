#!/usr/bin/env python3
"""Exercise the installed shell entrypoint with isolated process/tool doubles."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConsoleLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="okernel-launcher-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "checkout with spaces"
        self.scripts = self.root / "scripts"
        self.scripts.mkdir(parents=True)
        self.launcher = self.scripts / "okernel-console.sh"
        shutil.copyfile(ROOT / "scripts/okernel-console.sh", self.launcher)
        self.launcher.chmod(0o755)
        self.state = self.base / "state with spaces"
        self.package = self.state / "package-domain"
        self.profile = self.package / "monitor/monitor-profile.json"
        self.profile.parent.mkdir(parents=True)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.calls = self.base / "calls.jsonl"
        self.sessions = self.base / "sessions.json"
        self.sessions.write_text("{}")
        self.helper_marker = self.base / "helper-loaded"
        (self.scripts / "bm-dev-env.sh").write_text('printf loaded > "$FAKE_HELPER_MARKER"\n')
        # Importing this fixture checks the launcher's policy and file identity
        # calls. Runner protocol/real profile validation have their own tests.
        (self.scripts / "okernel_package_domain.py").write_text('''
from pathlib import Path
import hashlib
import json
NETWORK_GRANT = {"enabled": True, "transport": "mediated"}
NAMESPACE_GRANT = {"enabled": True, "mount_tag": "okernel"}
def selected_disk_bytes(state):
    head = state / "head.json"
    return json.loads(head.read_text())["disk"]["bytes"] if head.exists() else 536870912
def validate_profile(manifest):
    if manifest.get("profile") != "package-domain": raise ValueError("bad profile")
def checked_file(path, record):
    if path.is_symlink() or not path.is_file(): raise ValueError("not a regular artifact")
    if path.stat().st_size != record["bytes"]: raise ValueError("artifact size changed")
    if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]: raise ValueError("artifact digest changed")
    return path
''')
        self.write_tool("python3", f'''#!{sys.executable}
import json, os, sys
if len(sys.argv) > 1 and sys.argv[1] == "-":
    os.execv({sys.executable!r}, [{sys.executable!r}] + sys.argv[1:])
with open(os.environ["FAKE_CALLS"], "a") as stream:
    stream.write(json.dumps(["python3"] + sys.argv[1:]) + "\\n")
if "--version" in sys.argv: print("Python fixture")
''')
        self.write_tool("tmux", f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ["FAKE_CALLS"], "a") as stream:
    stream.write(json.dumps(["tmux"] + args) + "\\n")
if args == ["-V"]: print("tmux fixture"); sys.exit(0)
socket = args[args.index("-L") + 1]
path = Path(os.environ["FAKE_SESSIONS"])
states = json.loads(path.read_text())
state = states.setdefault(socket, {{"exists": False, "dead": "0", "status": "0"}})
if "has-session" in args: sys.exit(0 if state["exists"] else 1)
if "display-message" in args:
    print(state["status"] if args[-1] == "#{{pane_dead_status}}" else state["dead"])
    sys.exit(0)
if "new-session" in args: state.update(exists=True, dead="0", status="0")
if "kill-session" in args: state["exists"] = False
if "bind-key" in args:
    binding = args[args.index("bind-key") + 1:]
    assert binding == ["-T", "prefix", "q", "send-keys", "-t", "okernel:console.0", "C-]"]
    state.setdefault("bindings", {{}})["q"] = binding
elif "send-keys" in args and os.environ.get("FAKE_STOP_SUCCEEDS") == "1":
    if args[-1] in ("C-]", "x"):
        state.update(dead="1", status=os.environ.get("FAKE_EXIT_STATUS", "0"))
if "list-panes" in args: print("OKernel session fixture")
path.write_text(json.dumps(states))
''')
        for tool in ("qemu-system-aarch64", "qemu-system-x86_64", "git", "cargo", "rustc", "clang", "script", "file"):
            self.write_tool(tool, f'''#!{sys.executable}
import json, os, sys
with open(os.environ["FAKE_CALLS"], "a") as stream:
    stream.write(json.dumps([{tool!r}] + sys.argv[1:]) + "\\n")
print({tool!r} + " fixture")
''')
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.bin) + ":" + os.defpath,
                        OSTADIX_OKERNEL_STATE=str(self.state),
                        OSTADIX_OKERNEL_SOCKET="fixture-native",
                        OSTADIX_OKERNEL_PACKAGE_SOCKET="fixture-package",
                        OCORE_QEMU_BIN=str(self.bin / "qemu-system-x86_64"),
                        FAKE_CALLS=str(self.calls), FAKE_SESSIONS=str(self.sessions),
                        FAKE_HELPER_MARKER=str(self.helper_marker),
                        OSTADIX_OKERNEL_STOP_TIMEOUT="0")
        self.manifest = self.valid_manifest()
        self.write_manifest()

    def write_tool(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)

    def valid_manifest(self):
        import hashlib
        artifacts = {}
        for name in ("monitor", "guest_dtb", "Image", "initramfs"):
            path = self.profile.parent / name
            path.write_bytes(("fixture " + name).encode())
            artifacts[name] = {"path": str(path), "bytes": path.stat().st_size,
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        return {"profile": "package-domain", "network_grant": {"enabled": True, "transport": "mediated"},
                "namespace_grant": {"enabled": True, "mount_tag": "okernel"}, "artifacts": artifacts}

    def write_manifest(self):
        self.profile.write_text(json.dumps(self.manifest))

    def launch(self, *args, expected=0, **environment):
        result = subprocess.run([str(self.launcher), *args], env=dict(self.env, **environment),
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def commands(self, name=None):
        entries = [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []
        return [entry for entry in entries if name is None or entry[0] == name]

    def set_session(self, native=False, dead="0", status="0"):
        socket = "fixture-native" if native else "fixture-package"
        states = json.loads(self.sessions.read_text())
        states[socket] = dict(exists=True, dead=dead, status=status)
        self.sessions.write_text(json.dumps(states))

    def test_default_start_uses_package_socket_and_no_build_tools(self):
        self.launch()
        calls = self.commands()
        new = next(entry for entry in calls if "new-session" in entry)
        self.assertEqual(new[2], "fixture-package")
        shell = new[new.index("36") + 1]
        # A real shell must recover exact arguments despite both paths having spaces.
        parsed = subprocess.run(["bash", "-c", "set -- " + shell + '; printf "%s\\n" "$@"'],
                                text=True, capture_output=True, check=True).stdout.splitlines()
        self.assertEqual(parsed[-2:], [str(self.launcher), "run"])
        self.assertIn("OSTADIX_OKERNEL_STATE=" + str(self.state), parsed)
        self.assertFalse(self.helper_marker.exists())
        self.assertFalse(any(entry[0] in ("cargo", "rustc", "clang", "script", "qemu-system-x86_64") for entry in calls))

    def test_start_reconnects_without_revalidating_or_rebuilding(self):
        self.set_session()
        self.profile.unlink()
        self.launch("start", "--detach")
        self.assertFalse(any("new-session" in entry for entry in self.commands()))
        self.assertFalse(self.helper_marker.exists())

    def test_start_binds_prefix_q_without_executing_its_save_command(self):
        self.launch("start", "--detach", FAKE_STOP_SUCCEEDS="1")
        calls = self.commands("tmux")
        bindings = [entry for entry in calls if entry[3] == "bind-key"]
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0][2], "fixture-package")
        self.assertEqual(bindings[0][3:], ["bind-key", "-T", "prefix", "q", "send-keys",
                                         "-t", "okernel:console.0", "C-]"])
        state = json.loads(self.sessions.read_text())["fixture-package"]
        self.assertTrue(state["exists"])
        self.assertEqual(state["dead"], "0")
        self.assertFalse(any(entry[3] in ("send-keys", "kill-session", "kill-server") for entry in calls))

    def test_attach_refreshes_package_exit_key_without_stopping_existing_session(self):
        self.set_session()
        self.set_session(native=True)
        native_before = json.loads(self.sessions.read_text())["fixture-native"]
        self.launch("attach", FAKE_STOP_SUCCEEDS="1")
        calls = self.commands("tmux")
        binding = next(entry for entry in calls if entry[3] == "bind-key")
        attached = next(entry for entry in calls if entry[3] == "attach-session")
        self.assertLess(calls.index(binding), calls.index(attached))
        self.assertTrue(all(entry[2] == "fixture-package" for entry in calls))
        self.assertFalse(any(entry[3] in ("send-keys", "kill-session", "kill-server") for entry in calls))
        states = json.loads(self.sessions.read_text())
        self.assertTrue(states["fixture-package"]["exists"])
        self.assertEqual(states["fixture-package"]["dead"], "0")
        self.assertEqual(states["fixture-native"], native_before)

    def test_missing_profile_explains_explicit_build(self):
        self.profile.unlink()
        result = self.launch("start", expected=1)
        self.assertIn("okernel packages build --network --namespace", result.stderr)
        self.assertFalse(any("new-session" in entry for entry in self.commands()))
        self.assertFalse(self.helper_marker.exists())

    def test_profile_requires_shared_namespace(self):
        self.manifest["namespace_grant"] = {"enabled": False}
        self.write_manifest()
        result = self.launch("run", expected=1)
        self.assertIn("shared native namespace", result.stderr)
        self.assertFalse(self.commands("python3"))

    def test_profile_requires_mediated_network(self):
        self.manifest.pop("network_grant")
        self.write_manifest()
        self.assertIn("mediated network", self.launch("start", expected=1).stderr)

    def test_profile_artifact_tampering_is_rejected_before_tmux(self):
        Path(self.manifest["artifacts"]["Image"]["path"]).write_bytes(b"changed")
        self.launch("start", expected=1)
        self.assertFalse(any("new-session" in entry for entry in self.commands()))

    def test_run_selects_package_state_and_qemu(self):
        self.launch("run")
        call = self.commands("python3")[-1]
        self.assertEqual(call[2:], ["run", "--state", str(self.package), "--qemu", str(self.bin / "qemu-system-aarch64")])
        self.assertFalse(self.helper_marker.exists())

    def test_qemu_override_is_used_for_run(self):
        self.launch("run", OSTADIX_OKERNEL_PACKAGE_QEMU=str(self.bin / "qemu-system-aarch64"))
        self.assertEqual(self.commands("python3")[-1][-1], str(self.bin / "qemu-system-aarch64"))

    def test_package_build_forwards_explicit_flags_and_state(self):
        self.launch("packages", "build", "--network", "--namespace")
        self.assertTrue(self.helper_marker.exists())
        self.assertEqual(self.commands("python3")[-1][2:], ["--state", str(self.package), "build", "--network", "--namespace"])

    def test_default_test_uses_unified_verifier_without_native_tools(self):
        self.launch("test", "--timeout", "900")
        call = self.commands("python3")[-1]
        self.assertEqual(Path(call[1]).name, "verify_okernel_unified.py")
        self.assertEqual(call[2:], ["--state", str(self.package), "--qemu", str(self.bin / "qemu-system-aarch64"), "--timeout", "900"])
        self.assertFalse(self.helper_marker.exists())

    def test_package_stop_sends_save_key_and_removes_only_exited_pane(self):
        self.set_session()
        self.launch("stop", FAKE_STOP_SUCCEEDS="1")
        calls = self.commands("tmux")
        sends = [entry for entry in calls if "send-keys" in entry]
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0][-1], "C-]")
        self.assertTrue(any("kill-session" in entry for entry in calls))
        self.assertFalse(json.loads(self.sessions.read_text())["fixture-package"]["exists"])

    def test_exit_and_quit_save_existing_package_session_without_touching_native(self):
        for action in ("exit", "quit"):
            with self.subTest(action=action):
                self.calls.unlink(missing_ok=True)
                self.set_session()
                self.set_session(native=True)
                native_before = json.loads(self.sessions.read_text())["fixture-native"]
                result = self.launch(action, FAKE_STOP_SUCCEEDS="1")
                self.assertIn("saved and stopped", result.stdout)
                calls = self.commands("tmux")
                sends = [entry for entry in calls if entry[3] == "send-keys"]
                self.assertEqual(len(sends), 1)
                self.assertEqual(sends[0][3:], ["send-keys", "-t", "okernel:console.0", "C-]"])
                self.assertTrue(all(entry[2] == "fixture-package" for entry in calls))
                killed = next(entry for entry in calls if entry[3] == "kill-session")
                self.assertLess(calls.index(sends[0]), calls.index(killed))
                self.assertEqual(killed[-1], "=okernel")
                self.assertFalse(any(entry[3] in ("new-session", "kill-server") for entry in calls))
                self.assertFalse(self.commands("python3"))
                states = json.loads(self.sessions.read_text())
                self.assertFalse(states["fixture-package"]["exists"])
                self.assertEqual(states["fixture-native"], native_before)

    def test_exit_aliases_keep_pending_or_failed_save_session_for_inspection(self):
        for action in ("exit", "quit"):
            for mode in ("pending", "failed"):
                with self.subTest(action=action, mode=mode):
                    self.calls.unlink(missing_ok=True)
                    self.set_session()
                    environment = {"FAKE_STOP_SUCCEEDS": "1", "FAKE_EXIT_STATUS": "1"} if mode == "failed" else {}
                    self.launch(action, expected=1, **environment)
                    self.assertTrue(json.loads(self.sessions.read_text())["fixture-package"]["exists"])
                    self.assertFalse(any(entry[3] in ("kill-session", "kill-server", "new-session")
                                         for entry in self.commands("tmux")))

    def test_exit_alias_extra_arguments_are_rejected_before_session_contact(self):
        self.set_session()
        for action in ("exit", "quit"):
            with self.subTest(action=action):
                self.launch(action, "--unknown", expected=2)
                self.assertFalse(self.commands())

    def test_pending_save_does_not_kill_vm_or_session(self):
        self.set_session()
        result = self.launch("stop", expected=1)
        self.assertIn("left running", result.stderr)
        self.assertFalse(any("kill-session" in entry for entry in self.commands()))
        self.assertTrue(json.loads(self.sessions.read_text())["fixture-package"]["exists"])

    def test_failed_save_preserves_exited_pane_for_inspection(self):
        self.set_session()
        self.launch("stop", expected=1, FAKE_STOP_SUCCEEDS="1", FAKE_EXIT_STATUS="1")
        self.assertFalse(any("kill-session" in entry for entry in self.commands()))

    def test_restart_does_not_start_while_save_is_pending(self):
        self.set_session()
        self.launch("restart", "--detach", expected=1)
        self.assertFalse(any("new-session" in entry for entry in self.commands()))

    def test_invalid_restart_arguments_do_not_stop_running_vm(self):
        self.set_session()
        self.launch("restart", "--unknown", expected=2)
        self.assertFalse(self.commands())

    def test_restart_saves_before_new_session(self):
        self.set_session()
        self.launch("restart", "--detach", FAKE_STOP_SUCCEEDS="1")
        calls = self.commands()
        sent = next(i for i, entry in enumerate(calls) if "send-keys" in entry)
        started = next(i for i, entry in enumerate(calls) if "new-session" in entry)
        self.assertLess(sent, started)

    def test_logs_and_status_use_latest_package_session(self):
        session = self.package / "session-fixture"
        session.mkdir()
        (session / "console.log").write_text("package log fixture\n")
        (self.package / "latest-session").write_text(str(session) + "\n")
        self.assertIn("package log fixture", self.launch("logs").stdout)
        self.assertIn(str(session / "console.log"), self.launch("status").stdout)

    def test_native_keeps_original_separate_session(self):
        self.set_session(native=True)
        self.profile.unlink()
        self.launch("native", "start", "--detach")
        self.assertFalse(any("new-session" in entry for entry in self.commands()))
        self.assertTrue(all(entry[2] == "fixture-native" for entry in self.commands("tmux")))

    def test_native_start_retains_native_run_dispatch(self):
        self.launch("native", "start", "--detach")
        new = next(entry for entry in self.commands() if "new-session" in entry)
        self.assertEqual(new[2], "fixture-native")
        self.assertIn("native run", new[new.index("36") + 1])
        self.assertTrue(self.helper_marker.exists())

    def test_native_run_still_builds_mode16_in_private_directory(self):
        self.launch("native", "run")
        self.assertTrue(self.helper_marker.exists())
        self.assertTrue(self.commands("script"))
        self.assertTrue((self.state / "latest-run").is_file())
        self.assertFalse(self.commands("python3"))

    def test_native_stop_preserves_qemu_escape(self):
        self.set_session(native=True)
        self.launch("native", "stop", FAKE_STOP_SUCCEEDS="1")
        sends = [entry for entry in self.commands("tmux") if "send-keys" in entry]
        self.assertEqual([entry[-1] for entry in sends], ["C-a", "x"])
        self.assertTrue(all(entry[2] == "fixture-native" for entry in sends))

    def test_native_logs_remain_separate(self):
        run = self.state / "native-run"
        run.mkdir()
        (run / "console.log").write_text("native log fixture\n")
        (self.state / "latest-run").write_text(str(run) + "\n")
        self.assertIn("native log fixture", self.launch("native", "logs").stdout)
        self.launch("logs", expected=1)

    def test_help_explains_one_default_and_explicit_native_scope(self):
        help_text = self.launch("help").stdout
        self.assertIn("Ctrl+]", help_text)
        self.assertIn("shared native O-core 9P", help_text)
        self.assertIn("never rebuilds", help_text)
        self.assertIn("no general shell", self.launch("native", "help").stdout)

    def test_invalid_start_arguments_are_rejected(self):
        self.launch("start", "--unknown", expected=2)
        self.assertFalse(self.commands())

    def test_default_verify_selects_unified_monitor_and_output(self):
        output = self.base / "repro evidence"
        self.launch("verify", str(output), "--timeout", "300")
        call = self.commands("python3")[-1]
        self.assertEqual(Path(call[1]).name, "verify_okernel_unified_repro.py")
        self.assertEqual(call[2:], ["--source", str(self.root), "--payload", str(self.package / "payload"),
                                    "--output", str(output), "--backing-bytes", "536870912", "--timeout", "300"])
        self.assertTrue(self.helper_marker.exists())

    def test_default_verify_uses_the_selected_one_gib_generation(self):
        (self.package / "head.json").write_text(json.dumps({"disk": {"bytes": 1073741824}}))
        self.launch("verify")
        call = self.commands("python3")[-1]
        self.assertEqual(call[call.index("--backing-bytes") + 1], "1073741824")

    def test_fork_uses_saved_state_without_contacting_running_vm(self):
        self.set_session()
        before = self.sessions.read_bytes()
        output = self.base / "isolated state with spaces"
        self.launch("fork", str(output))
        self.assertEqual(self.commands("python3"), [["python3", str(self.scripts / "fork_okernel_state.py"),
                          "--source", str(self.package), "--output", str(output)]])
        self.assertFalse(self.commands("tmux"))
        self.assertEqual(self.sessions.read_bytes(), before)
        self.assertFalse(self.helper_marker.exists())

    def test_fork_requires_one_output_and_rejects_native_scope(self):
        self.launch("fork", expected=2)
        self.launch("native", "fork", str(self.base / "output"), expected=2)
        self.assertFalse(self.commands())


if __name__ == "__main__":
    unittest.main()
