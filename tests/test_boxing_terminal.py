#!/usr/bin/env python3
"""Explicit macOS/Linux PTY regression for the native O boxing terminal.

Run manually; importing this file or unittest discovery starts no processes:
    python3 tests/test_boxing_terminal.py
    python3 tests/test_boxing_terminal.py --o-bin target/release/O

Each case owns a new PTY, its direct child and temporary output only. No user
terminal configuration, node services or persistent output directories change.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import select
import shutil
import signal
import sys
import tempfile
import time


def run_case(root: Path, evaluator: Path, backends: Path, stop_key: bytes) -> dict:
    import pty
    import termios

    gate_read, gate_write = os.pipe()
    pid, master = pty.fork()
    if pid == 0:
        os.close(gate_write)
        os.read(gate_read, 1)
        os.close(gate_read)
        # The parent supplies a temporary output path through the environment
        # before fork. The source/backend paths are explicit for any caller cwd.
        os.execve(str(evaluator), [str(evaluator), str(root / "examples/boxing.O"), str(backends)], os.environ)
        os._exit(127)

    os.close(gate_read)
    transcript = bytearray()
    status = None
    eof = False
    baseline = termios.tcgetattr(master)[3]
    mask = termios.ICANON | termios.ECHO | termios.ISIG
    os.write(gate_write, b"1")
    os.close(gate_write)

    def read_chunk(timeout=0.1):
        nonlocal eof
        if eof:
            return
        if select.select([master], [], [], timeout)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            if chunk:
                transcript.extend(chunk)
            else:
                eof = True

    def expect(needles, start, timeout=20):
        deadline = time.monotonic() + timeout
        needles = [needle.encode() for needle in needles]
        while time.monotonic() < deadline:
            if all(needle in transcript[start:] for needle in needles):
                return len(transcript)
            if eof:
                break
            read_chunk()
        tail = bytes(transcript[-4000:]).decode(errors="replace")
        raise AssertionError(f"PTY did not render {needles!r}; last output:\n{tail}")

    stages = []
    try:
        position = expect(["Space pause", "full injury replay saved after match"], 0)
        assert termios.tcgetattr(master)[3] & mask == 0, "interactive cbreak/input flags were not enabled"
        stages.append("complete live frame")
        for key, labels, name in (
            (b"1", ["TITAN · FACE CLOSE-UP", "PAUSED —", "Space resume / q end."], "Titan close-up"),
            (b"2", ["PHANTOM · FACE CLOSE-UP", "PAUSED —", "Space resume / q end."], "Phantom close-up"),
            (b"i", ["INJURY EXAMINATION", "TITAN [", "PHANTOM [", "PAUSED —"], "both injury readouts"),
            (b" ", ["Space pause", "full injury replay saved after match"], "complete resumed frame"),
        ):
            position = len(transcript)
            os.write(master, key)
            expect(labels, position)
            stages.append(name)
        position = len(transcript)
        os.write(master, stop_key)
        expect(["Match INTERRUPTED", "Winner: UNDECIDED"], position)
        restored = termios.tcgetattr(master)[3]
        assert restored & mask == baseline & mask, "ICANON/ECHO/ISIG were not restored"

        # Drain output while the evaluator/backend exits. Blocking waitpid before
        # draining can deadlock a backend flushing its final receipt into the PTY.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            read_chunk()
            child, child_status = os.waitpid(pid, os.WNOHANG)
            if child:
                status = child_status
                while not eof and select.select([master], [], [], 0.1)[0]:
                    read_chunk(0)
                break
        assert status is not None, "native O did not exit after the stop key"
        assert os.waitstatus_to_exitcode(status) == 0, f"native O exit status {status}"
        data = json.loads((Path(os.environ["OSTADIX_BOXING_OUT"]) / "match.json").read_text())
        assert data["result"]["status"] == "interrupted", data["result"]
        assert data["result"]["winner"] is None, data["result"]
        assert data["result"]["ticks"] >= 1, data["result"]
        assert len(data["frames"]) == data["result"]["ticks"] + 1
        return {"stop": "Ctrl-C" if stop_key == b"\x03" else "q", "stages": stages,
                "ticks": data["result"]["ticks"], "bytes_drained": len(transcript),
                "terminal_flags_restored": True, "exit_code": 0}
    finally:
        # Closing our PTY first releases blocked terminal writes. Only the exact
        # child created above is signalled/reaped; no global process search/kill.
        os.close(master)
        if status is None:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                child, status = os.waitpid(pid, os.WNOHANG)
                if child:
                    break
                time.sleep(0.05)
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--o-bin", type=Path, default=shutil.which("O"))
    parser.add_argument("--backends", type=Path)
    args = parser.parse_args()
    if sys.platform not in ("darwin", "linux"):
        parser.error("this explicit PTY check supports macOS and Linux")
    if args.o_bin is None:
        parser.error("native O is unavailable; supply --o-bin")
    root = args.root.resolve()
    evaluator = args.o_bin.resolve()
    backends = (args.backends or root / "backends").resolve()
    saved_environment = dict(os.environ)
    evidence = []
    try:
        for stop_key in (b"q", b"\x03"):
            with tempfile.TemporaryDirectory(prefix="ostadix-boxing-pty-") as output:
                os.environ.update({
                    "O_LANG_ROOT": str(root), "O_BACKENDS_DIR": str(backends),
                    "OSTADIX_BOXING_OUT": output, "OSTADIX_BOXING_HEADLESS": "0",
                    "OSTADIX_BOXING_RED_NODE": "local", "OSTADIX_BOXING_BLUE_NODE": "local",
                    "OSTADIX_BOXING_DELAY": "0.05", "OSTADIX_BOXING_MAX_TICKS": "1000",
                    "OSTADIX_BOXING_ROUNDS": "3", "OSTADIX_BOXING_ROUND_SECONDS": "60",
                    "OSTADIX_BOXING_SEED": "42",
                })
                evidence.append(run_case(root, evaluator, backends, stop_key))
    finally:
        os.environ.clear()
        os.environ.update(saved_environment)
    print(json.dumps({"status": "PASS", "cases": evidence}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
