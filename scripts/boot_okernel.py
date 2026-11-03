#!/usr/bin/env python3
"""Boot the prepared original-codec system, or an explicit native kernel mode.

Preparation is explicit. Normal startup validates the prepared native monitor,
original Linux payload and captured original-codec dependency, then opens its
persistent terminal. The Linux kernel remains guest code beneath O-core.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def default_state() -> Path:
    parent = os.environ.get("OSTADIX_OKERNEL_STATE")
    if parent:
        return Path(parent).expanduser() / "package-domain"
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    return base / "ostadix/okernel/native-source/package-domain"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    if spec is None or spec.loader is None:
        raise ValueError("missing OKernel helper: " + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record_file(runner, state: Path, record: dict) -> Path:
    path = Path(record["path"])
    if not path.is_absolute() or not path.is_relative_to(state) or not path.resolve().is_relative_to(state):
        raise ValueError("prepared artifact is outside the selected state: " + str(path))
    return runner.checked_file(path, record)


def validate_prepared(state: Path) -> dict:
    runner = load("okernel_package_domain")
    codec = load("okernel_native_codec")
    profile_path = state / "monitor/monitor-profile.json"
    if profile_path.is_symlink() or not profile_path.is_file():
        raise ValueError("no prepared native-codec system at " + str(state))
    profile = json.loads(profile_path.read_bytes())
    runner.validate_profile(profile)
    if profile.get("network_grant") != runner.NETWORK_GRANT:
        raise ValueError("boot requires the mediated network grant")
    if profile.get("namespace_grant") != runner.NAMESPACE_GRANT:
        raise ValueError("boot requires the shared native namespace grant")
    for name in ("monitor", "guest_dtb", "profile", "Image", "initramfs"):
        record_file(runner, state, profile["artifacts"][name])

    native = profile.get("native_9p_codec")
    if not isinstance(native, dict) or native.get("schema") != "ostadix.monitor-native-u9fs/v1" or native.get("isa") != "aarch64":
        raise ValueError("prepared monitor lacks the original-source native codec; prepare with --codec-manifest")
    codec.validate_capture(native, state / "monitor")
    if runner.selected_disk_bytes(state) != profile["backing_bytes"]:
        raise ValueError("prepared disk and monitor device grant disagree")
    head_path = state / "head.json"
    if head_path.exists():
        head = json.loads(head_path.read_bytes())
        runner.validate_head(state, head)
        if head.get("namespace") is None:
            raise ValueError("saved system lacks its paired native namespace generation")
        record_file(runner, state, head["namespace"])
    return profile


def native(mode: str, qemu: str | None) -> int:
    environment = dict(os.environ, OCORE_PROBE_MODE=mode)
    if qemu:
        environment["OCORE_QEMU_BIN"] = qemu
    os.execve(ROOT / "ocore/kernel/run-qemu.sh", [str(ROOT / "ocore/kernel/run-qemu.sh")], environment)
    return 127


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", default="run", choices=("run", "doctor", "prepare", "native", "baseline"))
    parser.add_argument("--state", type=Path, default=default_state(), help="exact package-domain state directory")
    parser.add_argument("--qemu", help="QEMU executable; source-system default is OSTADIX_OKERNEL_PACKAGE_QEMU or qemu-system-aarch64")
    preparation = parser.add_mutually_exclusive_group()
    preparation.add_argument("--from-state", type=Path, help="fork a verified saved native-codec state into a new destination")
    preparation.add_argument("--codec-manifest", type=Path, help="build with an admitted AArch64 original-source codec manifest")
    args = parser.parse_args(argv)
    if args.action != "prepare" and (args.from_state is not None or args.codec_manifest is not None):
        parser.error("--from-state and --codec-manifest apply only to prepare")
    if args.action == "prepare" and args.from_state is None and args.codec_manifest is None:
        parser.error("prepare requires --from-state or --codec-manifest")
    if args.action in ("native", "baseline"):
        return native("16" if args.action == "native" else "0", args.qemu)
    if args.action == "run" and "OCORE_PROBE_MODE" in os.environ:
        mode = os.environ["OCORE_PROBE_MODE"]
        if mode not in ("0", "16"):
            parser.error("interactive OCORE_PROBE_MODE must be 0 or 16")
        return native(mode, args.qemu)
    try:
        if args.state.expanduser().is_symlink():
            raise ValueError("selected state must not be a symlink")
        state = args.state.expanduser().resolve()
        if args.action == "prepare":
            if state.exists():
                raise ValueError("prepare requires a new state directory; choose another --state")
            if args.from_state is not None:
                if args.from_state.expanduser().is_symlink():
                    raise ValueError("source state must not be a symlink")
                source = args.from_state.expanduser().resolve(strict=True)
                validate_prepared(source)
                command = [sys.executable, str(ROOT / "scripts/fork_okernel_state.py"),
                           "--source", str(source), "--output", str(state)]
                environment = None
            else:
                manifest = args.codec_manifest.expanduser().resolve(strict=True)
                command = [sys.executable, str(ROOT / "scripts/okernel_package_domain.py"),
                           "build", "--state", str(state), "--network", "--namespace"]
                environment = dict(os.environ, OCORE_LINUX_NATIVE_9P_MANIFEST=str(manifest))
            result = subprocess.run(command, env=environment)
            if result.returncode:
                return result.returncode
            validate_prepared(state)
            print("Prepared native-codec system: " + str(state))
            return 0
        validate_prepared(state)
        qemu = args.qemu or os.environ.get("OSTADIX_OKERNEL_PACKAGE_QEMU", "qemu-system-aarch64")
        executable = shutil.which(qemu)
        if executable is None:
            raise ValueError("QEMU executable is not installed: " + qemu)
        if args.action == "doctor":
            print("Prepared native-codec system: valid\nState: " + str(state) + "\nQEMU: " + executable)
            return 0
        print("Starting Linux under O-core with the original-source native codec.\n"
              "State: " + str(state) + "\nSave and exit: Ctrl+].", flush=True)
        command = [sys.executable, str(ROOT / "scripts/okernel_package_domain.py"),
                   "run", "--state", str(state), "--qemu", executable]
        os.execv(sys.executable, command)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("OKernel boot failed: " + str(error) + "\nPrepare explicitly with boot/boot.sh prepare --from-state SOURCE "
              "or --codec-manifest MANIFEST. Native console: boot/boot.sh native.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
