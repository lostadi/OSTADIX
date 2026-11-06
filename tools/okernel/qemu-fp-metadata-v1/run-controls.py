#!/usr/bin/env python3
"""Run fixed R7 recipe host controls in a fresh cache, never the source package.

Requires Linux Python 3.12. No QEMU/build commands are executed by these controls.
Pinned historical JSONs are replay inputs, not new VM qualification or authority.
"""
from pathlib import Path, PurePosixPath
import argparse
import ctypes
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
DRIVERS = ("recipe-error-paths.py", "recipe-structural-checks.py", "recipe-schema-controls.py")
EVIDENCE_PATHS = (
    "recipe-all-v1-r7/work/pointer/attempt-5/result.json",
    "system-controls/final-r6-attempt-1/result.json",
    "real-env-controls/final-r6-attempt-1/result.json",
    "xsave-controls/final-r6-attempt-1/result.json",
    "migration-controls/final-r6-attempt-1/result.json",
    "migration-stream-controls/final-r6-attempt-1/result.json",
)

class ControlError(Exception):
    pass

def need(condition, message):
    if not condition:
        raise ControlError(message)

def identity(st):
    return {key: getattr(st, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
        "st_size", "st_mtime_ns", "st_ctime_ns")}

def held_file(path, single_link=True):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = identity(os.fstat(fd))
        need(stat.S_ISREG(before["st_mode"]), "input is not a regular file: " + str(path))
        need(not single_link or before["st_nlink"] == 1, "input aliases another file: " + str(path))
        chunks = []
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            chunks.append(data)
        data = b"".join(chunks)
        need(identity(os.fstat(fd)) == before and identity(path.lstat()) == before,
             "held/named input changed: " + str(path))
        need(len(data) == before["st_size"], "input read size differs")
        return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "identity": before}, data
    finally:
        os.close(fd)

def simple_pin(path):
    row, _ = held_file(path, single_link=False)
    return {key: row[key] for key in ("path", "bytes", "sha256")}

def relative_name(value):
    need(isinstance(value, str) and value and "\\" not in value
         and not any(ord(c) < 32 for c in value), "unsafe relative input name")
    p = PurePosixPath(value)
    need(not p.is_absolute() and ".." not in p.parts and p.as_posix() == value
         and value not in (".", ""), "noncanonical relative input name")
    return value

def plain_path(root, relative):
    path = root
    for part in PurePosixPath(relative_name(relative)).parts:
        path = path / part
        need(not path.is_symlink(), "symlink input is unsupported: " + str(path))
    need(path.is_file(), "missing regular input: " + str(path))
    return path

def source_snapshot(root=ROOT):
    manifest_path = root / "source-inventory.json"
    manifest_pin, raw = held_file(manifest_path)
    manifest = json.loads(raw)
    need(set(manifest) == {"schema", "files"} and manifest["schema"] == "ostadix.qemu-r7-source-package/v1",
         "source inventory schema differs")
    need(type(manifest["files"]) is list and manifest["files"], "empty source inventory")
    rows = {}
    for selected in manifest["files"]:
        need(type(selected) is dict and set(selected) == {"relative", "bytes", "sha256", "executable"},
             "source inventory fields differ")
        name = relative_name(selected["relative"])
        need(name != "source-inventory.json" and name not in rows, "duplicate/self source inventory entry")
        need(type(selected["bytes"]) is int and selected["bytes"] >= 0
             and isinstance(selected["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", selected["sha256"])
             and type(selected["executable"]) is bool, "invalid source pin")
        observed, _ = held_file(plain_path(root, name))
        need((observed["bytes"], observed["sha256"]) == (selected["bytes"], selected["sha256"]),
             "source bytes mismatch: " + name)
        need(bool(observed["identity"]["st_mode"] & 0o111) == selected["executable"],
             "source executable class mismatch: " + name)
        rows[name] = observed
    actual = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            need(not (Path(directory) / name).is_symlink(), "source directory symlink")
        for name in files:
            path = Path(directory) / name
            need(not path.is_symlink(), "source file symlink")
            actual.add(path.relative_to(root).as_posix())
    need(actual == set(rows) | {"source-inventory.json"}, "source membership differs")
    rows["source-inventory.json"] = manifest_pin
    return rows

def evidence_snapshot(root, package_root=ROOT):
    _, raw = held_file(package_root / "schema-inputs.json")
    selected = json.loads(raw)
    need(set(selected) == {"schema", "files"} and selected["schema"] == "ostadix.qemu-r7-schema-replay-inputs/v1",
         "schema replay manifest differs")
    need(type(selected["files"]) is list and len(selected["files"]) == 6, "exactly six schema inputs required")
    rows = {}
    for row in selected["files"]:
        need(type(row) is dict and set(row) == {"relative", "bytes", "sha256"}, "schema input fields differ")
        name = relative_name(row["relative"])
        need(name in EVIDENCE_PATHS and name not in rows, "unknown/duplicate schema input")
        need(type(row["bytes"]) is int and row["bytes"] >= 0 and isinstance(row["sha256"], str)
             and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]), "invalid schema input pin")
        observed, _ = held_file(plain_path(root, name))
        need((observed["bytes"], observed["sha256"]) == (row["bytes"], row["sha256"]),
             "schema bytes mismatch: " + name)
        rows[name] = observed
    need(set(rows) == set(EVIDENCE_PATHS), "six schema membership differs")
    return rows

def unchanged(rows):
    for row in rows.values():
        current, _ = held_file(row["path"])
        need(current == row, "input changed after preflight: " + row["path"])

def copy_checked(rows, destination):
    for name, row in rows.items():
        current, data = held_file(row["path"])
        need(current == row, "input changed before copy")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                need(n > 0, "copy made no progress")
                view = view[n:]
            os.fchmod(fd, 0o755 if row["identity"]["st_mode"] & 0o111 else 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        copied, _ = held_file(target)
        need((copied["bytes"], copied["sha256"]) == (row["bytes"], row["sha256"]), "copy bytes differ")
        need((copied["identity"]["st_dev"], copied["identity"]["st_ino"]) !=
             (row["identity"]["st_dev"], row["identity"]["st_ino"]), "copy aliases input")

def execute_driver(name, work, output, environment):
    argv = [sys.executable, "-I", "-B", str(work / name)]
    stdout = output / (name + ".stdout")
    stderr = output / (name + ".stderr")
    parent_pid = os.getpid()
    def own_parent_death():
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
            os._exit(126)
    started = time.monotonic()
    with stdout.open("xb") as so, stderr.open("xb") as se:
        child = subprocess.Popen(argv, cwd=work, env=environment, stdout=so, stderr=se,
                                 start_new_session=True, preexec_fn=own_parent_death)
        timed_out = False
        try:
            status = child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            status = child.wait(timeout=5)
    return {"name": name, "argv": argv, "pid": child.pid, "exit_code": status,
            "timed_out": timed_out, "seconds": time.monotonic() - started,
            "stdout": simple_pin(stdout), "stderr": simple_pin(stderr)}

def validate_driver(record, work):
    need(record["exit_code"] == 0 and not record["timed_out"], "control driver failed: " + record["name"])
    summary = json.loads(Path(record["stdout"]["path"]).read_bytes())
    need(summary.get("ok") is True and type(summary.get("result")) is dict, "driver summary is not successful")
    desc = summary["result"]
    need(set(desc) == {"path", "bytes", "sha256"}, "driver result pin fields differ")
    path = Path(desc["path"])
    need(path.is_absolute() and path.resolve().is_relative_to(work), "driver result escaped owned workspace")
    current = simple_pin(plain_path(work, path.relative_to(work).as_posix()))
    need(current == desc, "driver result bytes changed")
    doc = json.loads(path.read_bytes())
    need(doc.get("ok") is True, "control result is false")
    if record["name"] == DRIVERS[0]:
        need(len(doc.get("cases", [])) == 14 and all(c.get("passed") is True for c in doc["cases"]),
             "fourteen recipe controls did not pass")
    elif record["name"] == DRIVERS[1]:
        need(len(doc.get("generators", [])) == 2 and doc.get("owned_parent_death", {}).get("final_state") in ("gone", "Z"),
             "generator/owned-child controls did not pass")
    else:
        cases = doc.get("cases", [])
        need(len(cases) == 3 and all(c.get("passed") is True for c in cases), "schema controls did not pass")
        need(len(cases[0].get("six_actual_schemas", [])) == 6 and cases[0].get("status") == 0
             and cases[1].get("status") == 1 and len(cases[2].get("calls_not_executed", [])) == 1,
             "schema/false-guard/dynamic-constructor coverage differs")
    return desc

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    output = args.output
    evidence = args.evidence_root
    if sys.platform != "linux" or sys.version_info[:2] != (3, 12):
        parser.error("this optional recipe profile requires Linux Python 3.12")
    if not evidence.is_absolute() or not evidence.is_dir() or evidence.resolve() != evidence:
        parser.error("evidence root must be an absolute canonical directory")
    if not output.is_absolute() or not output.parent.is_dir() or output.parent.resolve() != output.parent:
        parser.error("output needs an existing absolute canonical parent directory")
    if output.exists() or output.is_symlink():
        parser.error("output must be absent")
    for root in (ROOT, evidence):
        if output == root or root in output.parents or output in root.parents:
            parser.error("output must not overlap source package or external evidence")
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    report = {"schema": "ostadix.qemu-r7-source-controls/v1", "ok": False,
              "scope": "Fixed host orchestration controls and saved-schema replay only; no build/VM/default emulator action",
              "source_root": str(ROOT), "external_evidence_root": str(evidence), "commands": [],
              "QEMU_executed": False, "emulator_or_native_FP_admitted": False}
    def save():
        temp = output / ".result.tmp"
        with temp.open("w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, output / "result.json")
    save()
    source = None
    schemas = None
    copy_source = None
    try:
        need(evidence.is_dir() and evidence.resolve() == evidence, "evidence root must be canonical directory")
        need(output.resolve() == output, "output must be canonical")
        source = source_snapshot()
        schemas = evidence_snapshot(evidence)
        report["source_before"] = source
        report["schemas_before"] = schemas
        report["interpreter"] = simple_pin(Path(sys.executable).resolve())
        work = output / "work"
        work.mkdir(mode=0o700)
        copy_checked(source, work)
        copy_source = source_snapshot(work)
        copy_checked(schemas, work)
        report["copy_source_before"] = copy_source
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PYTHONPATH="")
        for name in DRIVERS:
            report["phase"] = "running-driver"
            report["active_driver"] = name
            save()
            record = execute_driver(name, work, output, env)
            report["commands"].append(record)
            unchanged(source)
            unchanged(schemas)
            unchanged(copy_source)
            record["result"] = validate_driver(record, work)
            save()
        report["coverage"] = {"recipe_synthetic_cases": 14, "generator_pairs": 2,
                              "own_non_QEMU_parent_death_children": 1, "saved_schema_shapes": 6,
                              "stream_false_guard": 1, "dynamic_constructor_controls": 1}
        report["ok"] = True
    except Exception as error:
        report["error"] = str(error)
    finally:
        try:
            if source is not None:
                need(source_snapshot() == source, "source package changed after run")
                unchanged(source)
            if schemas is not None:
                unchanged(schemas)
            if copy_source is not None:
                unchanged(copy_source)
            report["inputs_unchanged"] = True
        except Exception as error:
            report["inputs_unchanged"] = False
            report["postguard_error"] = str(error)
        report["ok"] = bool(report["ok"] and report["inputs_unchanged"])
        report["phase"] = "finished"
        save()
    print(json.dumps({"ok": report["ok"], "result": simple_pin(output / "result.json")}))
    return 0 if report["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
