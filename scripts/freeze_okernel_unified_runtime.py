#!/usr/bin/env python3
"""Freeze the host runtime and admitted two-domain build without running a VM.

The new bundle needs an explicitly selected existing private state. It does not
seed, migrate, install a launcher, change a head, or launch/stop any guest.
Python>=3.10, its standard library, Bash/coreutils, tmux, the Linux kernel and
recorded native ELF PT_INTERP remain host dependencies. QEMU's installed-module
fallback is not disabled by QEMU_MODULE_DIR: the captured modules/data cover the
fixed qualified direct-kernel profile, not every arbitrary QEMU configuration.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = ("scripts/okernel_unified_world.py", "scripts/okernel_package_domain.py",
                 "scripts/okernel_native_volume.py", "scripts/okernel-unified-console.sh",
                 "ocore/guest/plan9/unified/protocol.py")
SCHEMA = "ostadix.okernel-unified-runtime/v1"

ENTRY = '''#!/usr/bin/env python3
"""Frozen unified terminal. Requires explicit --state; reuses its saved pair."""
import argparse, hashlib, json, os, shutil, sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent

def verify():
    manifest = json.loads((ROOT / "runtime.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "ostadix.okernel-unified-runtime/v1" or manifest.get("passed") is not True:
        raise ValueError("incomplete frozen runtime")
    for name, expected in manifest["inventory"].items():
        parsed = PurePosixPath(name)
        if parsed.is_absolute() or ".." in parsed.parts or str(parsed) != name:
            raise ValueError("invalid runtime inventory path")
        current = ROOT
        for part in parsed.parts:
            current /= part
            if current.is_symlink():
                raise ValueError("runtime inventory symlink: " + name)
        if not current.is_file():
            raise ValueError("runtime file is missing: " + name)
        digest = hashlib.sha256()
        with current.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1048576), b""):
                digest.update(chunk)
        if current.stat().st_size != expected["bytes"] or digest.hexdigest() != expected["sha256"]:
            raise ValueError("runtime file changed: " + name)
    return manifest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="start", choices=("start", "run", "status", "attach", "stop", "check"))
    parser.add_argument("--state", type=Path, help="explicit existing fork; no default state is selected")
    parser.add_argument("--detach", action="store_true")
    parser.add_argument("--stop-timeout", type=int, default=120)
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        parser.error("Python3.10 or newer is required")
    if args.action != "check" and args.state is None:
        parser.error("--state is required")
    if not 1 <= args.stop_timeout <= 600:
        parser.error("--stop-timeout must be between1 and600")
    if args.detach and args.action not in ("start", "run"):
        parser.error("--detach applies only to start/run")
    try:
        manifest = verify()
        if args.action == "check":
            print("Frozen unified runtime: PASS")
            print("Build: " + manifest["admitted_manifest"]["sha256"])
            print("Files: " + str(len(manifest["inventory"])))
            return 0
        # Explicit host prerequisites remain visible. The Python launcher and
        # tmux's child resolve the same interpreter used for this invocation.
        python = Path(sys.executable).resolve()
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONUNBUFFERED"] = "1"
        environment["PATH"] = str(ROOT / "host-bin") + ":/usr/bin:/bin"
        for required in ("bash", "tmux"):
            if shutil.which(required, path=environment["PATH"]) is None:
                raise ValueError("host command required: " + required)
        environment["OKERNEL_UNIFIED_HOST_PYTHON"] = str(python)
        command = ["/bin/bash", str(ROOT / "runtime/scripts/okernel-unified-console.sh"),
                   "--state", str(args.state.expanduser()), "--build", str(ROOT / "build"),
                   "--qemu", str(ROOT / "tools/bin/qemu-system-aarch64"),
                   "--stop-timeout", str(args.stop_timeout), "start" if args.action == "run" else args.action]
        if args.detach:
            command.append("--detach")
        os.execve(command[0], command, environment)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Frozen unified runtime: " + str(error), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
'''


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stream_identity(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def capture_tree(source, target, repro):
    records = {}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_dir():
            if path.is_symlink():
                raise ValueError("directory symlinks are not captured: " + str(path))
            continue
        if not path.is_file():
            raise ValueError("nonregular capture input: " + str(path))
        records[str(relative)] = repro.copy_file(path, target / relative)
        records[str(relative)]["requested_source"] = str(path)
    return records


def freeze_module(source, target, output, repro):
    record = {"module": repro.copy_file(source, target), "dependencies": []}
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    result = subprocess.run(["/usr/bin/ldd", str(source)], env=environment, capture_output=True, text=True, timeout=20)
    if result.returncode or "not found" in result.stdout:
        raise ValueError("cannot resolve QEMU module dependencies: " + str(source) + ": " + result.stdout + result.stderr)
    for line in result.stdout.splitlines():
        match = re.search(r"(?:=>\s+)?(/\S+)\s+\(0x", line)
        if not match:
            continue
        dependency = Path(match.group(1)).resolve()
        soname = line.split("=>", 1)[0].strip() if "=>" in line else Path(match.group(1)).name
        if Path(soname).name != soname:
            raise ValueError("invalid module dependency soname")
        destination = output / "tools/lib" / soname
        if destination.exists():
            repro.matches(destination, repro.identity(dependency))
            item = {"original": repro.identity(dependency), "frozen": repro.identity(destination)}
        else:
            item = repro.copy_file(dependency, destination)
        record["dependencies"].append(item)
    record["ldd"] = result.stdout
    return record


def inspect_private_process(session, build_manifest, engine, repro):
    """Read only a positively bound private unified QEMU; never discover main."""
    record_path = repro.regular(session, "result.json")
    record = repro.document(record_path)
    fork = repro.document(repro.regular(session.parent, "fork.json"))
    if (record.get("schema") != "ostadix.unified-world-session/v1"
            or fork.get("schema") != "ostadix.okernel-state-fork/v1" or fork.get("ok") is not True
            or fork.get("output") != str(session.parent) or session.parent.name == "package-domain"):
        raise ValueError("observed session is not an explicitly isolated unified state")
    expected = record.get("inputs", {}).get("monitor.elf", {})
    admitted = build_manifest["artifacts"]["monitor.elf"]
    if any(expected.get(key) != admitted[key] for key in ("bytes", "sha256")):
        raise ValueError("observed private QEMU does not use this admitted monitor")
    pid = record.get("qemu_pid")
    if type(pid) is not int or pid <= 0:
        raise ValueError("private session has no QEMU process identity")
    process = Path("/proc") / str(pid)
    if not process.exists():
        return {"session": repro.identity(record_path), "pid": pid, "live_observation": False,
                "reason": "qualified process already exited; installed module/data closure captured separately"}
    executable = process / "exe"
    repro.matches(executable, repro.identity(engine))
    status = dict(line.split(":", 1) for line in (process / "status").read_text().splitlines())
    if int(status["PPid"]) != record.get("controller_pid"):
        raise ValueError("observed QEMU is not a child of the recorded private controller")
    command = (process / "cmdline").read_bytes().split(b"\0")[:-1]
    if not command or Path(command[0].decode()).name != "qemu-system-aarch64":
        raise ValueError("observed process is not the selected ARM QEMU command")
    kernel = Path(command[command.index(b"-kernel") + 1].decode())
    if kernel.parent != session / "inputs" or kernel.name != "monitor.elf":
        raise ValueError("observed QEMU command is not bound to this private session")
    repro.matches(kernel, admitted)
    maps = (process / "maps").read_text()
    file_descriptors = {}
    for path in (process / "fd").iterdir():
        try:
            file_descriptors[path.name] = os.readlink(path)
        except FileNotFoundError:
            continue
    mapped_files = []
    for line in maps.splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6 and parts[5].startswith("/") and not parts[5].endswith(" (deleted)"):
            path = Path(parts[5])
            if path.is_file() and path not in mapped_files:
                mapped_files.append(path)
    return {"session": repro.identity(record_path), "pid": pid, "live_observation": True, "observed_unix": time.time(),
            "binding": {"private_fork": fork, "controller_pid": record["controller_pid"], "monitor": expected,
                        "executable": repro.identity(executable), "cmdline": [item.decode() for item in command]},
            "maps": maps, "file_descriptors": file_descriptors,
            "mapped_files": [repro.identity(path) for path in mapped_files]}


def run(args, output, evidence):
    source, build = args.source.resolve(strict=True), args.build.resolve(strict=True)
    repro = load(source / "scripts/verify_okernel_two_domains_repro.py", "frozen_runtime_repro_helpers")
    manifest, admitted = repro.inspect_build(build)
    evidence.update(admitted_manifest=repro.identity(build / "monitor-profile.json"), sources={}, tools={},
                    build_inputs=admitted, host_python=repro.identity(Path(sys.executable).resolve()),
                    host_platform={"python_minimum": "3.10", "observed_python": sys.version,
                                   "sys_platform": sys.platform, "uname": list(os.uname())})
    for name in RUNTIME_FILES:
        evidence["sources"][name] = repro.copy_file(repro.regular(source, name), output / "runtime" / name)
        if name.endswith(".sh"):
            (output / "runtime" / name).chmod(0o555)
    evidence["implementation"] = repro.copy_file(Path(__file__).resolve(), output / "evidence/freeze-runtime.py")
    evidence["repro_helpers"] = repro.copy_file(source / "scripts/verify_okernel_two_domains_repro.py", output / "evidence/repro-helpers.py")
    evidence["build_copies"] = capture_tree(build, output / "build", repro)
    repro.inspect_build(output / "build")
    for name, expected in admitted.items():
        repro.matches(output / "build" / name, expected)
    helper = source / "scripts/verify_okernel_unified_repro.py"
    evidence["tool_freezer"] = repro.copy_file(helper, output / "evidence/tool-freezer.py")
    freezer = repro.load_freezer(output / "evidence/tool-freezer.py")
    engine = args.qemu.resolve(strict=True)
    if engine != Path("/usr/bin/qemu-system-aarch64").resolve() or engine.is_symlink():
        raise ValueError("this qualified runtime requires explicit /usr/bin/qemu-system-aarch64")
    record = freezer.freeze_tool("qemu-system-aarch64", engine, output)
    if not record["version_stdout"].startswith("QEMU emulator version 8.2.2 ("):
        raise ValueError("expected the qualified original QEMU8.2.2 engine")
    evidence["tools"]["qemu-system-aarch64"] = record
    evidence["qemu_modules"] = {}
    modules = Path("/usr/lib/x86_64-linux-gnu/qemu")
    (output / "tools/modules").mkdir(parents=True)
    if modules.is_dir():
        for module in sorted(modules.iterdir()):
            if module.suffix != ".so" or not module.is_file():
                raise ValueError("unexpected installed QEMU module entry")
            evidence["qemu_modules"][module.name] = freeze_module(module, output / "tools/modules" / module.name, output, repro)
    data = Path("/usr/share/qemu")
    evidence["qemu_data"] = capture_tree(data, output / "tools/data", repro)
    if args.observed_session:
        evidence["private_observation"] = inspect_private_process(args.observed_session.resolve(strict=True), manifest, engine, repro)
    if args.observation:
        if args.observation.is_symlink() or not args.observation.is_file():
            raise ValueError("saved observation must be a regular file")
        observation = repro.document(args.observation)
        binding = observation.get("binding", {})
        if observation.get("live_observation") is not True:
            raise ValueError("saved observation must describe an actually observed live private process")
        for key in ("bytes", "sha256"):
            if binding.get("monitor", {}).get(key) != manifest["artifacts"]["monitor.elf"][key]:
                raise ValueError("saved observation does not bind this admitted monitor")
        repro.matches(engine, binding["executable"])
        evidence["saved_private_observation"] = repro.copy_file(args.observation, output / "evidence/private-qemu-observation.json")
        evidence["private_observation"] = observation
    observed = evidence.get("private_observation", {})
    if observed.get("live_observation") is True:
        captured = {item["frozen"]["sha256"] for item in record["dependencies"]}
        captured.add(record["native"]["frozen"]["sha256"])
        # QEMU also mmaps the admitted ARM monitor ELF as guest input. Its
        # bytes belong to the captured build, not the host DSO dependency graph.
        captured.update(item["sha256"] for item in manifest["artifacts"].values())
        for item in evidence["qemu_modules"].values():
            captured.add(item["module"]["frozen"]["sha256"])
            captured.update(dependency["frozen"]["sha256"] for dependency in item["dependencies"])
        for item in observed["mapped_files"]:
            repro.matches(Path(item["path"]), item)
            if item["sha256"] not in captured:
                raise ValueError("observed mapped ELF is outside the captured QEMU closure: " + item["path"])
        evidence["observed_mapped_elf_closure_complete"] = True
    # Relative wrapper paths permit relocation; no mutable checkout path is used.
    qemu = output / "tools/bin/qemu-system-aarch64"
    qemu.chmod(0o644)
    qemu.write_text('''#!/bin/sh
runtime=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P) || exit 1
unset LD_PRELOAD
export LD_LIBRARY_PATH="$runtime/tools/lib"
export QEMU_MODULE_DIR="$runtime/tools/modules"
exec "$runtime/tools/native/qemu-system-aarch64" -L "$runtime/tools/data" "$@"
''')
    qemu.chmod(0o555)
    record["wrapper"] = repro.identity(qemu)
    checked_qemu = subprocess.run([str(qemu), "--version"], capture_output=True, text=True, timeout=20)
    evidence["frozen_qemu_version_check"] = {"exit_status": checked_qemu.returncode, "stdout": checked_qemu.stdout,
                                              "stderr": checked_qemu.stderr}
    if checked_qemu.returncode or checked_qemu.stdout != record["version_stdout"]:
        raise ValueError("resource-preferring frozen QEMU wrapper differs from the captured engine")
    python_wrapper = output / "host-bin/python3"
    python_wrapper.parent.mkdir()
    python_wrapper.write_text('#!/bin/sh\nexec "${OKERNEL_UNIFIED_HOST_PYTHON:?select Python through the frozen entry}" "$@"\n')
    python_wrapper.chmod(0o555)
    entry = output / "okernel-unified"
    entry.write_text(ENTRY)
    entry.chmod(0o555)
    evidence["entry"] = "okernel-unified --state EXPLICIT_PRIVATE_STATE {start|run|status|attach|stop|check}"
    evidence["external_host_dependencies"] = {name: repro.identity(Path(path).resolve()) for name, path in
                                             (("python", sys.executable), ("bash", "/bin/bash"), ("shell", "/bin/sh"),
                                              ("tmux", "/usr/bin/tmux"), ("ldd", "/usr/bin/ldd"))}
    evidence["host_elf_interpreters"] = {}
    interpreter = repro.elf_interpreter(output / "tools/native/qemu-system-aarch64")
    if interpreter:
        evidence["host_elf_interpreters"][interpreter] = repro.identity(Path(interpreter))
    evidence["qemu_resource_search"] = {"module_directory": "tools/modules", "data_directory": "tools/data",
        "scope": "all installed QEMU modules and their DSO closure plus /usr/share/qemu captured; fixed direct-kernel profile has no supplied UEFI firmware",
        "limitation": "QEMU_MODULE_DIR and -L prefer captured resources; compiled host fallback remains for absent names. Arbitrary configurations are outside this capture's claim.",
        "primary_sources": ["https://github.com/qemu/qemu/blob/v8.2.2/util/module.c#L221", "https://github.com/qemu/qemu/blob/v8.2.2/system/vl.c#L2873"]}
    retained = repro.inventory(output, ("runtime", "build", "tools", "host-bin", "evidence", "okernel-unified"))
    evidence["inventory"] = {name: {"bytes": item["bytes"], "sha256": item["sha256"]} for name, item in retained.items()}
    for name, record in evidence["sources"].items():
        repro.matches(repro.regular(source, name), record["original"])
    for name, record in evidence["build_copies"].items():
        repro.matches(build / name, record["original"])
    for record in (record["native"] for record in evidence["tools"].values()):
        repro.matches(Path(record["original"]["path"]), record["original"])
    all_dependencies = evidence["tools"]["qemu-system-aarch64"]["dependencies"][:]
    for item in evidence["qemu_modules"].values():
        all_dependencies.extend(item["dependencies"])
        repro.matches(Path(item["module"]["original"]["path"]), item["module"]["original"])
    for item in all_dependencies:
        repro.matches(Path(item["original"]["path"]), item["original"])
        repro.matches(Path(item["frozen"]["path"]), item["frozen"])
    for item in evidence["qemu_data"].values():
        repro.matches(Path(item["requested_source"]), item["original"])
    for path, expected in evidence["host_elf_interpreters"].items():
        repro.matches(Path(path), expected)
    repro.check_inventory(output, retained)
    evidence.update(passed=True, sources_build_tools_unchanged=True)
    repro.write_json(output / "runtime.json", evidence)
    checked = subprocess.run([sys.executable, "-B", str(entry), "check"], capture_output=True, text=True, timeout=30)
    evidence["self_check"] = {"argv": [sys.executable, "-B", str(entry), "check"], "exit_status": checked.returncode,
                              "stdout": checked.stdout, "stderr": checked.stderr}
    if checked.returncode:
        evidence["passed"] = False
        raise ValueError("frozen runtime inventory self-check failed: " + checked.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, default=Path("/usr/bin/qemu-system-aarch64"))
    parser.add_argument("--observed-session", type=Path, help="optional explicit private unified session for read-only /proc observation")
    parser.add_argument("--observation", type=Path, help="saved live private-process observation from this module's validated read-only audit")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new directory")
    for source in (args.source.resolve(strict=True), args.build.resolve(strict=True)):
        if output == source or source in output.parents:
            parser.error("runtime output must be outside its input source/build")
    output.mkdir(mode=0o700, parents=True)
    evidence = {"schema": SCHEMA, "passed": False, "started_unix": time.time(), "scope": __doc__, "output": str(output)}
    try:
        run(args, output, evidence)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        evidence.update(passed=False, error=str(error))
        (output / "runtime.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print("Frozen unified runtime: FAIL: " + str(error), file=sys.stderr)
        return 1
    (output / "runtime.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("Frozen unified runtime: PASS\nEntry: " + str(output / "okernel-unified") + "\nManifest: " + str(output / "runtime.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
