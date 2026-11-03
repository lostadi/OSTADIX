"""Production launcher ownership options against the actual installed tmux.

The pane runs an inert host Python fixture, not QEMU or either guest kernel.
Only profile/head validators are fixture stubs; shell dispatch, tmux target
parsing, real session/pane creation and repeated-start ownership are real.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = r'''
from pathlib import Path
import json,os,sys,time
class Common:
 DEFAULT_STATE=Path(__file__).parent/'unused-working-state'
 @staticmethod
 def validate_head(state,head):
  assert head['schema']=='ostadix.package-domain-disk-head/v2'
common=Common()
DISK_BYTES=1073741824
def validate_profile(profile):assert profile=={'fixture':'no VM, no kernel qualification'}
if __name__=='__main__':
 assert sys.argv[1]=='run'
 state=Path(sys.argv[sys.argv.index('--state')+1])
 assert os.isatty(0)
 (state/'fixture-controller.json').write_text(json.dumps({'pid':os.getpid(),'argv':sys.argv}))
 print('inert host tmux fixture ready',flush=True)
 while True:time.sleep(1)
'''


@unittest.skipUnless(shutil.which("tmux"), "actual tmux is required")
class RealTmuxLauncherTests(unittest.TestCase):
    def test_real_create_read_and_repeated_start_use_exact_session_options(self):
        with tempfile.TemporaryDirectory(prefix="unified-real-tmux-") as directory:
            root = Path(directory)
            runtime = root / "runtime/scripts"
            runtime.mkdir(parents=True)
            launcher = runtime / "okernel-unified-console.sh"
            launcher.write_bytes((ROOT / "scripts/okernel-unified-console.sh").read_bytes())
            (runtime / "okernel_unified_world.py").write_text(RUNNER)
            binary = root / "bin"
            binary.mkdir()
            python = binary / "python3"
            python.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + ' "$@"\n')
            python.chmod(0o700)
            state = root / "state"
            state.mkdir()
            (state / "fork.json").write_text(json.dumps({"schema": "ostadix.okernel-state-fork/v1",
                                                        "ok": True, "output": str(state)}))
            head = {"schema": "ostadix.package-domain-disk-head/v2",
                    "disk": {"bytes": 1073741824}, "namespace": {"bytes": 16777216}}
            head_wire = json.dumps(head).encode()
            (state / "head.json").write_bytes(head_wire)
            build = root / "build"
            build.mkdir()
            profile = {"fixture": "no VM, no kernel qualification"}
            (build / "monitor-profile.json").write_text(json.dumps(profile))
            socket = "ostadix-unified-" + hashlib.sha256(os.fsencode(state)).hexdigest()[:24]
            environment = os.environ.copy()
            environment.pop("TMUX", None)
            environment.update(PATH=str(binary) + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
            tmux = shutil.which("tmux")

            def tm(*arguments):
                return subprocess.run([tmux, "-L", socket, *arguments], cwd="/tmp", env=environment,
                                      text=True, capture_output=True, timeout=5)

            def invoke(action, selected=build):
                arguments = ["/bin/bash", str(launcher), "--state", str(state), "--build", str(selected),
                             "--qemu", "/bin/true", action]
                if action == "start":
                    arguments.append("--detach")
                return subprocess.run(arguments, cwd="/tmp", env=environment,
                                      text=True, capture_output=True, timeout=10)

            try:
                first = invoke("start")
                self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
                deadline = time.monotonic() + 5
                started = state / "fixture-controller.json"
                while not started.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(started.exists(), "inert controller did not start in actual tmux")
                original = json.loads(started.read_text())
                expected = {"@okernel-unified-state": str(state), "@okernel-unified-build": str(build),
                            "@okernel-unified-before-head": hashlib.sha256(head_wire).hexdigest()}
                for name, value in expected.items():
                    result = tm("show-options", "-qv", "-t", "=okernel-unified:", name)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), value)
                second = invoke("start")
                self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
                self.assertEqual(json.loads(started.read_text()), original)
                pane = tm("display-message", "-p", "-t", "=okernel-unified:console.0", "#{pane_pid}")
                self.assertEqual(pane.stdout.strip(), str(original["pid"]))
                status = invoke("status")
                self.assertEqual(status.returncode, 0, status.stderr)
                self.assertIn("Console running", status.stdout)
                different = root / "different-build"
                different.mkdir()
                (different / "monitor-profile.json").write_text(json.dumps(profile))
                mismatch = invoke("status", different)
                self.assertEqual(mismatch.returncode, 2)
                self.assertIn("different state/build", mismatch.stderr)
                self.assertEqual(json.loads(started.read_text()), original)
            finally:
                # Only this unique test socket and its inert host fixture.
                tm("kill-server")


if __name__ == "__main__":
    unittest.main()
