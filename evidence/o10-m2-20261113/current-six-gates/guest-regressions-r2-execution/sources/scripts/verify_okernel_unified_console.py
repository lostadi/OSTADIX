#!/usr/bin/env python3
"""Exercise the real foreground unified console with automated terminal keystrokes.

This uses a private PTY and an explicit stopped fork. It does not claim that a
person typed the test commands. Both original kernels must respond through
the same operator input stream; no hidden guest exec channel supplies commands.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]


def hash_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(data)
    return value.hexdigest()


class Terminal:
    def __init__(self, state: Path, build: Path, directory: Path):
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        self.capture = bytearray()
        self.log = (directory / "terminal.log").open("wb")
        def foreground():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.process = subprocess.Popen([sys.executable, str(ROOT / "scripts/okernel_unified_world.py"),
                                         "run", "--state", str(state), "--build", str(build)],
                                        stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                        preexec_fn=foreground, close_fds=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.master, selectors.EVENT_READ)

    def pump(self, duration=0.1):
        for _, _ in self.selector.select(duration):
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    data = b""
                else:
                    raise
            if data:
                self.capture.extend(data)
                self.log.write(data)
                self.log.flush()

    def send(self, data):
        for index in range(0, len(data), 8):
            os.write(self.master, data[index:index + 8])
            self.pump(0.02)

    def wait(self, marker: bytes, timeout=180, line=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = bytes(self.capture).replace(b"\r", b"")
            if line:
                complete = text.split(b"\n")[:-1]
                if any(value in complete for value in (marker, b"% " + marker, b"; " + marker)):
                    return
            elif marker in text:
                return
            if self.process.poll() is not None:
                raise RuntimeError("unified console exited before " + repr(marker))
            self.pump()
        raise TimeoutError("missing typed-console output " + repr(marker))

    def finish(self, *, dangling_prefix=False):
        if dangling_prefix:
            self.send(b"\x1e")
        self.send(b"\x1d")
        deadline = time.monotonic() + 60
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump()
        if self.process.poll() is None:
            raise TimeoutError("console did not complete explicit paired save/stop")
        self.pump()
        if self.process.returncode != 0:
            raise RuntimeError("console exited with " + str(self.process.returncode))
        after = termios.tcgetattr(self.slave)
        if after != self.before:
            raise RuntimeError("foreground terminal attributes were not fully restored")

    def close(self):
        if self.process.poll() is None:
            # Python's SIGINT raises through the runner's finally blocks,
            # restoring its private tty and closing its own QEMU process.
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.selector.close()
        os.close(self.master)
        os.close(self.slave)
        self.log.close()


def verify(state: Path, build: Path):
    output = Path(tempfile.mkdtemp(prefix="console-acceptance-", dir=state))
    result = {"schema": "ostadix.unified-original-kernel-console/v1", "ok": False,
              "scope": "automated keystrokes through a real foreground PTY into both original shells; not a batch replay or a claim of a human operator",
              "started": time.time(), "sessions": [], "checks": []}
    receipt = output / "result.json"
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    terminal = None
    token = secrets.token_hex(12)
    linux_text, plan9_text = "TYPED_LINUX_" + token, "TYPED_PLAN9_" + token
    linux_name, plan9_name = "typed-linux-" + token, "typed-plan9-" + token
    try:
        for phase in range(2):
            directory = output / ("first" if phase == 0 else "restart")
            directory.mkdir()
            terminal = Terminal(state, build, directory)
            terminal.wait(b"OKERNEL PACKAGE NETWORK ONLINE")
            marker = "KEYBOARD_LINUX_" + secrets.token_hex(12)
            terminal.send(("printf '%s\\n' " + marker + "\n").encode())
            terminal.wait(marker.encode(), line=True)
            session = Path((state / "latest-unified-session").read_text().strip())
            result["sessions"].append(str(session))
            if phase == 0:
                ack = "LINUX_FILE_DONE_" + secrets.token_hex(12)
                terminal.send(("printf '%s\\n' " + linux_text + " > /n/okernel/work/" + linux_name + " && echo " + ack + "\n").encode())
                terminal.wait(ack.encode(), line=True)
                terminal.send(b"\x1e1")
                terminal.wait(b"[O-core console: original Plan 9")
                marker = "KEYBOARD_PLAN9_" + secrets.token_hex(12)
                terminal.send(("echo " + marker + "\n").encode())
                terminal.wait(marker.encode(), line=True)
                terminal.send(("cat /n/work/" + linux_name + "\n").encode())
                terminal.wait(linux_text.encode(), line=True)
                ack = "PLAN9_FILE_DONE_" + secrets.token_hex(12)
                terminal.send(("echo " + plan9_text + " > /n/work/" + plan9_name + "; echo " + ack + "\n").encode())
                terminal.wait(ack.encode(), line=True)
                terminal.send(b"\x1e0")
                terminal.wait(b"[O-core console: Linux")
                terminal.send(("cat /n/okernel/work/" + plan9_name + "\n").encode())
                terminal.wait(plan9_text.encode(), line=True)
                result["checks"].extend(["fresh typed Linux and original Plan9 commands use one operator input stream",
                                         "live bidirectional files cross original kernels through the native backend"])
            else:
                terminal.send(("cat /n/okernel/work/" + plan9_name + "\n").encode())
                terminal.wait(plan9_text.encode(), line=True)
                terminal.send(b"\x1e1")
                terminal.wait(b"[O-core console: original Plan 9")
                terminal.send(("cat /n/work/" + linux_name + "\n").encode())
                terminal.wait(linux_text.encode(), line=True)
                # Exercise actual foreground cancellation during coordinated
                # stop, rather than an already idle preloaded command script.
                # rc reads ahead from its console while parsing. Supply one
                # complete compound command, then wait for execution to begin
                # before sending the child's input; an immediate second line
                # can otherwise remain in rc's own lexer buffer.
                ready = ("PLAN9_CAT_READY_" + secrets.token_hex(12)).encode()
                terminal.send(b"echo " + ready + b"; cat\n")
                terminal.wait(ready, line=True)
                streamed = ("PLAN9_STDIN_STREAM_" + secrets.token_hex(12)).encode()
                terminal.send(streamed + b"\n")
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    lines = bytes(terminal.capture).replace(b"\r", b"").split(b"\n")[:-1]
                    if lines.count(streamed) >= 2:
                        break
                    terminal.pump()
                else:
                    raise RuntimeError("original Plan9 cat did not read and stream typed stdin")
                result["checks"].append("fresh two-kernel boot recovers both newly typed shared files")
                result["checks"].append("original Plan9 cat streams typed foreground input before cancellation/save")
            terminal.finish(dangling_prefix=phase == 0)
            session_result = json.loads((session / "result.json").read_text())
            if not session_result.get("ok") or not session_result.get("paired_snapshot"):
                raise RuntimeError("terminal exited without a verified paired save")
            if json.loads((session / "native-observation.json").read_text()).get("input_dropped") != 0:
                raise RuntimeError("console input was dropped")
            result["checks"].append(("first" if phase == 0 else "restart") +
                                    ": explicit save/stop completes and restores foreground terminal flags")
            terminal.close()
            terminal = None
        result.update(ok=True, finished=time.time())
        print("Unified original Linux/Plan9 real-console keyboard/save/restart: PASS\nEvidence: " + str(receipt))
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        if terminal is not None:
            terminal.close()
        receipt.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.state.expanduser().resolve(), args.build.expanduser().resolve())
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("Unified console acceptance failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
