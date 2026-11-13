"""Byte-preserving sparse compaction of explicitly owned CLOSED private test disks."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

BASE = Path("/home/ustad/.cache/o10-m0-acceptance-20261112").resolve()
ALLOWED_NAMES = {"state-live-3", "full-guest-regressions-3"}

def digest_fd(fd):
    value = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            return value.hexdigest()
        value.update(block)
        offset += len(block)

def no_live_vm(state):
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            argv = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
            if argv and argv[0].endswith(b"qemu-system-aarch64") and b"-kernel" in argv:
                kernel = Path(os.fsdecode(argv[argv.index(b"-kernel") + 1]))
                if kernel.is_relative_to(state):
                    return False
        except (OSError, ValueError, IndexError):
            continue
    return True

def compact_state(state, record, save):
    state = state.resolve(strict=True)
    relative = state.relative_to(BASE)
    if relative.parts[0] not in ALLOWED_NAMES or state.is_symlink():
        raise ValueError("state is outside this explicitly owned R3 run")
    if not no_live_vm(state):
        return False
    lock_path = state / "domain.lock"
    if not lock_path.is_file() or lock_path.is_symlink():
        raise ValueError("closed state has no regular domain lock")
    with lock_path.open("r") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        if not no_live_vm(state):
            return False
        for path in sorted(state.rglob("*.ext4")):
            if path.is_symlink() or not path.resolve().is_relative_to(state):
                raise ValueError("private disk escaped its state")
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            writable = None
            before = os.fstat(fd)
            mode = stat.S_IMODE(before.st_mode)
            row = {"path": str(path), "bytes": before.st_size,
                   "inode": before.st_ino, "device": before.st_dev,
                   "blocks_before": before.st_blocks, "mode_before": mode,
                   "ok": False, "started": time.time()}
            try:
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                        or before.st_nlink != 1):
                    raise ValueError("disk is not one independently owned regular inode")
                row["sha256_before"] = digest_fd(fd)
                os.fchmod(fd, mode | stat.S_IWUSR)
                writable = os.open("/proc/self/fd/" + str(fd), os.O_RDWR)
                actual = os.fstat(writable)
                if (actual.st_ino, actual.st_dev) != (before.st_ino, before.st_dev):
                    raise RuntimeError("disk inode changed before compaction")
                argv = ["fallocate", "--dig-holes", "--", "/proc/self/fd/" + str(writable)]
                result = subprocess.run(argv, pass_fds=(writable,), capture_output=True,
                                        text=True, timeout=600)
                row.update(argv=argv, returncode=result.returncode,
                           stdout=result.stdout, stderr=result.stderr)
                os.fsync(writable)
                os.fchmod(fd, mode)
                after = os.fstat(fd)
                row.update(sha256_after=digest_fd(fd), bytes_after=after.st_size,
                           blocks_after=after.st_blocks, mode_after=stat.S_IMODE(after.st_mode))
                if (row["sha256_before"] != row["sha256_after"] or before.st_size != after.st_size
                        or mode != stat.S_IMODE(after.st_mode)
                        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)):
                    raise RuntimeError("compaction changed logical disk identity")
                row["byte_identity_preserved"] = True
                row["reclaimed_bytes"] = max(0, before.st_blocks - after.st_blocks) * 512
                row["ok"] = result.returncode == 0
                if result.returncode:
                    raise RuntimeError("fallocate did not complete successfully")
            except BaseException as error:
                row["error"] = type(error).__name__ + ": " + str(error)
                raise
            finally:
                os.fchmod(fd, mode)
                if writable is not None:
                    os.close(writable)
                os.close(fd)
                row["finished"] = time.time()
                record["files"].append(row)
                save()
        record["states"].append(str(state))
        save()
        return True

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--watch-aggregate", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    record = {"scope": "Only zero extents in independently owned closed private R3 ext4 copies; no original, seed, runtime, build or live VM is modified",
              "ok": False, "started": time.time(), "files": [], "states": []}
    def save():
        target = args.output / "result.json"
        temporary = args.output / "result.tmp"
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        temporary.replace(target)
    for flag in ("--help", "--version"):
        result = subprocess.run(["fallocate", flag], capture_output=True, text=True, timeout=10)
        (args.output / ("fallocate-" + flag[2:] + ".txt")).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("installed fallocate discovery failed")
    try:
        initial = BASE / "state-live-3"
        if not compact_state(initial, record, save):
            raise RuntimeError("initial private live state is still active")
        if args.watch_aggregate:
            deadline = time.monotonic() + 3500
            while time.monotonic() < deadline:
                if args.watch_aggregate.exists():
                    aggregate = json.loads(args.watch_aggregate.read_text())
                    for entry in aggregate.get("gates", []):
                        command = entry.get("command", {})
                        if (entry.get("ok") is True and command.get("returncode") == 0
                                and command.get("timed_out") is False
                                and entry["state"] not in record["states"]):
                            compact_state(Path(entry["state"]), record, save)
                    if aggregate.get("finished"):
                        record["aggregate_finished"] = True
                        break
                time.sleep(3)
            else:
                raise TimeoutError("compaction watcher deadline; no test is replayed")
        record["ok"] = all(row["ok"] and row.get("byte_identity_preserved") for row in record["files"])
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        record["finished"] = time.time()
        record["reclaimed_bytes"] = sum(row.get("reclaimed_bytes", 0) for row in record["files"])
        save()
        print(json.dumps({"ok": record["ok"], "reclaimed_bytes": record["reclaimed_bytes"],
                          "result": str(args.output / "result.json")}))
if __name__ == "__main__":
    main()
