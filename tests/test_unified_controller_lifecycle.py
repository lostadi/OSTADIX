"""An abruptly killed controller must not orphan its private execution process."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UnifiedControllerLifecycleTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "unified host profile requires Linux")
    def test_private_child_exits_when_controller_is_killed(self):
        # The child deliberately performs no terminal/pipe IO: EOF cannot be
        # mistaken for the parent-death signal we intend to qualify here.
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "child.json"
            code = r'''
import importlib.util, json, os, subprocess, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("lifecycle_runner", sys.argv[1])
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
owner = os.getpid()
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    start_new_session=True, preexec_fn=lambda: runner.owned_qemu_child(owner))
Path(sys.argv[2]).write_text(json.dumps({"pid": child.pid}))
time.sleep(120)
'''
            parent = subprocess.Popen([sys.executable, "-c", code,
                                       str(ROOT / "scripts/okernel_unified_world.py"), str(receipt)])
            child = None
            try:
                deadline = time.monotonic() + 10
                while not receipt.exists() and time.monotonic() < deadline:
                    if parent.poll() is not None:
                        self.fail("fixture controller exited before spawning private child")
                    time.sleep(0.01)
                self.assertTrue(receipt.exists())
                child = json.loads(receipt.read_text())["pid"]
                self.assertTrue((Path("/proc") / str(child)).exists())
                parent.kill()
                parent.wait(timeout=5)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    state = Path("/proc") / str(child) / "stat"
                    if not state.exists() or state.read_text().rsplit(") ", 1)[1].startswith("Z "):
                        return
                    time.sleep(0.01)
                self.fail("private child remained alive after its controller was killed")
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=5)
                if child is not None:
                    state = Path("/proc") / str(child) / "stat"
                    if state.exists() and not state.read_text().rsplit(") ", 1)[1].startswith("Z "):
                        os.kill(child, signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
