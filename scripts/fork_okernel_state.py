#!/usr/bin/env python3
"""Copy one verified saved OKernel generation into a new isolated state.

The source VM may remain running. Only the atomically selected saved head is
copied; unsaved guest memory is deliberately outside this operation. There is
no source-state mutation, VM command, network request, or shared disk inode.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("okernel_fork_runner", ROOT / "scripts/okernel_package_domain.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
CODEC_SPEC = importlib.util.spec_from_file_location("okernel_fork_codec", ROOT / "scripts/okernel_native_codec.py")
codec = importlib.util.module_from_spec(CODEC_SPEC)
CODEC_SPEC.loader.exec_module(codec)


def clone_file(source: Path, target: Path, expected: dict, *, immutable: bool = True) -> dict:
    runner.checked_file(source, expected)
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    runner.checked_file(target, expected)
    target.chmod(0o400 if immutable else 0o644)
    runner.fsync_directory(target.parent)
    return runner.identity(target)


def fork(source: Path, output: Path) -> dict:
    if source.is_symlink():
        raise ValueError("source state must not be a symlink")
    source = source.resolve(strict=True)
    output = output.resolve()
    if not source.is_dir() or output.exists() or output.is_symlink():
        raise ValueError("source must be a state directory and output must be a new path")
    if output.is_relative_to(source):
        raise ValueError("isolated output must be outside the source state")
    head_file = source / "head.json"
    profile_file = source / "monitor/monitor-profile.json"
    if head_file.is_symlink() or profile_file.is_symlink():
        raise ValueError("source head and monitor profile must be regular files")
    # Read each control record once. An active VM can publish a newer head;
    # these frozen bytes still identify one complete immutable saved pair.
    head_bytes = head_file.read_bytes()
    profile_bytes = profile_file.read_bytes()
    head = json.loads(head_bytes)
    profile = json.loads(profile_bytes)
    disk = runner.validate_head(source, head)
    runner.validate_profile(profile)
    native_codec = profile.get("native_9p_codec")
    if native_codec is not None:
        codec.validate_capture(native_codec, source / "monitor")
        captured_profile = source / "monitor/native-9p.json"
        if captured_profile.is_symlink() or not captured_profile.is_file():
            raise ValueError("native codec snapshot metadata must be a regular file")
        if json.loads(captured_profile.read_bytes()) != native_codec:
            raise ValueError("native codec snapshot metadata differs from its monitor profile")
    if disk["bytes"] != profile["backing_bytes"]:
        raise ValueError("saved root disk and prepared monitor grant disagree")
    if head.get("namespace") is not None and profile.get("namespace_grant") != runner.NAMESPACE_GRANT:
        raise ValueError("saved namespace requires its native monitor grant")
    locations = {"monitor": "monitor/monitor.elf", "guest_dtb": "monitor/guest.dtb",
                 "profile": "monitor/profile.oc", "Image": "payload/Image", "initramfs": "payload/initramfs.cpio"}
    for name in locations:
        expected = profile["artifacts"][name]
        runner.checked_file(Path(expected["path"]), expected)
    payload_metadata = source / "payload/linux-payload.json"
    payload_inputs = None
    if payload_metadata.exists() or payload_metadata.is_symlink():
        if payload_metadata.is_symlink() or not payload_metadata.is_file():
            raise ValueError("Linux payload metadata must be a regular captured file")
        payload_inputs = json.loads(payload_metadata.read_bytes())
        if payload_inputs.get("schema") != "ostadix.real-linux-payload/v1" or payload_inputs.get("profile") != "package-domain":
            raise ValueError("unsupported captured Linux payload metadata")
        image = payload_inputs["artifacts"]["Image"]
        if any(image[key] != profile["artifacts"]["Image"][key] for key in ("bytes", "sha256")):
            raise ValueError("Linux payload metadata does not describe the selected boot Image")
        runner.checked_file(source / "payload/linux.config", payload_inputs["artifacts"]["linux.config"])
    runner.checked_file(Path(disk["path"]), disk)
    if head.get("namespace") is not None:
        runner.checked_file(Path(head["namespace"]["path"]), head["namespace"])
    output.mkdir(parents=True, exist_ok=False)
    record = {"schema": "ostadix.okernel-state-fork/v1", "ok": False, "source": str(source),
              "output": str(output), "scope": "verified saved generation only; source VM and unsaved memory untouched"}
    try:
        target_head = copy.deepcopy(head)
        target_profile = copy.deepcopy(profile)
        for name, relative in locations.items():
            expected = profile["artifacts"][name]
            target_profile["artifacts"][name] = clone_file(Path(expected["path"]), output / relative, expected, immutable=False)
        if native_codec is not None:
            relocated = copy.deepcopy(native_codec)

            def capture_snapshot(item):
                original = Path(item["path"])
                relative = original.relative_to(source / "monitor")
                return clone_file(original, output / "monitor" / relative, item)

            relocated["captured_manifest"] = capture_snapshot(native_codec["captured_manifest"])
            relocated["objects"] = [capture_snapshot(item) for item in native_codec["objects"]]
            for group in ("receipts", "semantic_evidence"):
                for original, target in zip(native_codec[group], relocated[group]):
                    target["snapshot"] = capture_snapshot(original["snapshot"])
            codec.validate_capture(relocated, output / "monitor")
            runner.write_json(output / "monitor/native-9p.json", relocated)
            target_profile["native_9p_codec"] = relocated
        if payload_inputs is not None:
            clone_file(source / "payload/linux.config", output / "payload/linux.config", payload_inputs["artifacts"]["linux.config"], immutable=False)
            runner.write_json(output / "payload/linux-payload.json", payload_inputs)
        target_head["disk"] = clone_file(Path(disk["path"]), output / "disk-generations" / (disk["sha256"] + ".ext4"), disk)
        if head.get("namespace") is not None:
            native = head["namespace"]
            target_head["namespace"] = clone_file(Path(native["path"]), output / "namespace-generations" / (native["sha256"] + ".raw"), native)
        target_head["fork_origin"] = {"source": str(source), "head_sha256": hashlib.sha256(head_bytes).hexdigest()}
        runner.validate_head(output, target_head)
        runner.validate_profile(target_profile)
        runner.write_json(output / "monitor/monitor-profile.json", target_profile)
        rootfs = output / "rootfs"
        rootfs.mkdir()
        initrd = target_profile["artifacts"]["initramfs"]
        clone_file(Path(initrd["path"]), rootfs / "initramfs.cpio", initrd, immutable=False)
        runner.write_json(rootfs / "package-domain.json", {
            "schema": "ostadix.linux-package-domain/v1", "architecture": "aarch64",
            "disk_bytes": disk["bytes"], "artifacts": {"package-domain.ext4": target_head["disk"]},
            "scope": "derived saved checkpoint; not a fresh upstream root filesystem build"})
        (output / "source-head.json").write_bytes(head_bytes)
        runner.write_json(output / "head.json", target_head)
        record.update(ok=True, selected_head=target_head,
                      source_head_changed_during_copy=head_file.read_bytes() != head_bytes,
                      boot_inputs={key: value for key, value in target_profile["artifacts"].items()})
        runner.write_json(output / "fork.json", record)
        return record
    except BaseException as error:
        record["error"] = str(error)
        runner.write_json(output / "fork.json", record)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=runner.DEFAULT_STATE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = fork(args.source.expanduser(), args.output.expanduser())
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"State fork failed: {error}\n")
    print("OKernel saved-state fork: PASS\nState: " + result["output"] + "\nReceipt: " + str(Path(result["output"]) / "fork.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
