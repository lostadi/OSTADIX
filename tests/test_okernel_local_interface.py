"""Local panel behavior and real PTY interaction without touching a live VM."""
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ocore/guest/x12-live/interface.py"
spec = importlib.util.spec_from_file_location("okernel_local_interface_tested", SOURCE)
interface = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interface)


class TTY(io.StringIO):
    def isatty(self):
        return True


class Services:
    def __init__(self, failures=()):
        self.calls = []
        self.failures = set(failures)

    def runtime(self, action, *, interactive=False):
        self.calls.append(("runtime", action, interactive))
        code = 1 if action in self.failures else 0
        return subprocess.CompletedProcess([], code, "runtime:" + action + "\n")

    def run(self, argv, *, interactive=False):
        self.calls.append(("command", argv, interactive))
        return subprocess.CompletedProcess(argv, 1 if argv[-1] in self.failures else 0, "")

    def diagnostics(self):
        self.calls.append(("diagnostics",))
        return "FIXTURE DEVICE REPORT"


class LocalInterfaceTests(unittest.TestCase):
    def panel(self, text, services=None):
        backend = services or Services()
        output = io.StringIO()
        panel = interface.Panel(backend, TTY(text), output)
        return panel.run(), backend.calls, output.getvalue()

    def test_open_status_network_diagnostics_help_and_return(self):
        code, calls, output = self.panel("c\ns\nn\nd\nh\nr\n")
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("runtime", "start", True), ("runtime", "status", False),
                                 ("command", [interface.NETWORK], True), ("diagnostics",)])
        self.assertIn("Type exit to save and return", output)
        self.assertIn("FIXTURE DEVICE REPORT", output)
        self.assertIn("RAM", output)
        self.assertIn("packages", output.lower())

    def test_injected_shell_text_is_never_dispatched(self):
        code, calls, output = self.panel("c; touch /tmp/must-not-exist\n$(poweroff)\nr\n")
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertEqual(output.count("Unknown action."), 2)

    def test_shutdown_requires_exact_confirmation(self):
        for reply in ("", "yes", "power off", "POWER OFF ", "POWER OFF; shutdown"):
            with self.subTest(reply=reply):
                code, calls, output = self.panel("p\n" + reply + "\nr\n")
                self.assertEqual(code, 0)
                self.assertEqual(calls, [])
                self.assertIn("Poweroff cancelled.", output)

    def test_stop_failure_blocks_poweroff_and_panel_stays_usable(self):
        code, calls, output = self.panel("p\nPOWER OFF\ns\nr\n", Services(["stop"]))
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("runtime", "stop", False), ("runtime", "status", False)])
        self.assertIn("Poweroff blocked", output)
        self.assertNotIn("OKERNEL X12 POWEROFF", output)

    def test_confirmed_poweroff_orders_managed_save_sync_then_shutdown(self):
        code, calls, output = self.panel("p\nPOWER OFF\n")
        self.assertEqual(code, 0)
        self.assertEqual(calls, [("runtime", "stop", False),
                                 ("command", ["/usr/bin/sync"], False),
                                 ("command", ["/usr/bin/busybox", "poweroff", "-f"], False)])
        self.assertIn("OKERNEL X12 POWEROFF", output)

    def test_sync_failure_blocks_poweroff(self):
        code, calls, output = self.panel("p\nPOWER OFF\nr\n", Services(["/usr/bin/sync"]))
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 2)
        self.assertIn("Sync failed", output)
        self.assertNotIn("OKERNEL X12 POWEROFF", output)

    def test_no_tty_fails_without_dispatch_or_shutdown(self):
        backend = Services(); output = io.StringIO()
        self.assertEqual(interface.Panel(backend, io.StringIO("p\nPOWER OFF\n"), output).run(), 2)
        self.assertEqual(backend.calls, [])
        self.assertIn("keyboard terminal", output.getvalue())

    def test_eof_preserves_running_state(self):
        code, calls, output = self.panel("")
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertIn("has not been stopped or discarded", output)

    def test_missing_helper_error_returns_to_panel(self):
        backend = Services()
        backend.runtime = mock.Mock(side_effect=FileNotFoundError("missing helper"))
        code, calls, output = self.panel("c\nr\n", backend)
        self.assertEqual(code, 0)
        self.assertIn("Action unavailable", output)
        self.assertIn("missing helper", output)

    def test_services_uses_fixed_argv_without_shell(self):
        with mock.patch.object(interface.subprocess, "run") as run:
            interface.Services().runtime("start", interactive=True)
        run.assert_called_once_with([interface.PYTHON, "-B", interface.RUNTIME,
                                     "--state", interface.STATE, "start"],
                                    check=False, text=True, stdin=None, stdout=None, stderr=None)
        with mock.patch.object(interface.subprocess, "run") as run:
            interface.Services().runtime("stop")
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_legacy_poweroff_cli_obeys_same_barrier(self):
        for success, expected in ((True, 0), (False, 1)):
            with self.subTest(success=success), mock.patch.object(interface.Panel, "shutdown", return_value=success) as shutdown:
                self.assertEqual(interface.main(["--poweroff"]), expected)
                shutdown.assert_called_once_with()
        with mock.patch.object(interface.Panel, "shutdown", side_effect=FileNotFoundError("missing managed runtime")), mock.patch.object(interface.sys, "stderr", io.StringIO()) as error:
            self.assertEqual(interface.main(["--poweroff"]), 1)
            self.assertIn("Poweroff blocked", error.getvalue())

    def test_untrusted_child_output_and_device_controls_are_escaped(self):
        self.assertEqual(interface.visible("name\x1b[2J\x00\r\n\t"), "name?[2J??\n\t")
        backend = Services()
        backend.runtime = mock.Mock(return_value=subprocess.CompletedProcess([], 1, "bad\x1b[2J\n"))
        code, calls, output = self.panel("s\nr\n", backend)
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", output)
        self.assertIn("status 1", output)

    def test_driver_diagnostics_report_actual_fixture_and_missing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = {"usr/share/okernel/image.json": json.dumps({"module_count": 6900, "firmware_entry_count": 6590}),
                    "proc/modules": "i915 1 0\nusbhid 1 0\n",
                    "proc/bus/input/devices": 'N: Name="Local Keyboard"\nH: Handlers=sysrq kbd event0\n',
                    "sys/class/graphics/fb0/name": "i915drmfb\n",
                    "sys/class/drm/card0-eDP-1/status": "connected\n",
                    "sys/class/net/wlp0s20f3/operstate": "up\n"}
            for name, text in data.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
            output = interface.diagnostics(root)
            for text in ("6900", "6590", "Loaded modules: 2", "i915drmfb", "connected", "Local Keyboard", "kbd", "wlp0s20f3: up"):
                self.assertIn(text, output)
            self.assertIn("does not prove", output)
            (root / "proc/bus/input/devices").unlink()
            self.assertIn("No input devices are reported", interface.diagnostics(root))

    def test_real_pty_panel_and_foreground_child_return(self):
        # Execute the actual production panel on a real PTY. Only Services is
        # substituted; the child consumes its own terminal line, then returns.
        harness = """
import importlib.util, json, subprocess, sys
s=importlib.util.spec_from_file_location('panel',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Backend:
 def runtime(self, action, interactive=False):
  if interactive:
   return subprocess.run([sys.executable,'-u','-c',"print('FIXTURE CONSOLE READY',flush=True);v=input();print('FIXTURE CONSOLE GOT:'+v,flush=True)"],check=False)
  return subprocess.CompletedProcess([],0,'FIXTURE STATUS:'+action)
 def diagnostics(self):return 'FIXTURE DEVICES'
 def run(self,*args,**kwargs):raise AssertionError('unexpected action')
sys.exit(m.Panel(Backend()).run())
"""
        master, slave = pty.openpty()
        process = subprocess.Popen([sys.executable, "-B", "-u", "-c", harness, str(SOURCE)],
                                   stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave); capture = bytearray()
        def wait_for(marker):
            until = time.monotonic() + 8
            while time.monotonic() < until:
                if marker in capture:
                    return
                ready, _, _ = select.select([master], [], [], .1)
                if ready:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if data: capture.extend(data)
            self.fail("PTY marker missing: " + repr(marker) + " in " + repr(bytes(capture)))
        try:
            wait_for(b"Choose an action, then Enter:")
            os.write(master, b"c\n"); wait_for(b"FIXTURE CONSOLE READY")
            os.write(master, b"return-to-panel\n"); wait_for(b"FIXTURE CONSOLE GOT:return-to-panel")
            os.write(master, b"s\n"); wait_for(b"FIXTURE STATUS:status")
            os.write(master, b"r\n")
            self.assertEqual(process.wait(timeout=5), 0)
            self.assertGreaterEqual(bytes(capture).count(b"OKERNEL | LOCAL INTERFACE"), 2)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            os.close(master)


if __name__ == "__main__":
    unittest.main()
