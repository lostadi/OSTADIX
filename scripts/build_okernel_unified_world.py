#!/usr/bin/env python3
"""Build an additive two-domain native O-core EL2 profile from admitted kernels.

This does not boot, mutate a saved state, rebuild Linux/9front, or establish a
merged OS merely by producing an ELF. Live simultaneous-domain acceptance is
separate. The existing single-domain profiles remain available.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "ocore/runtime/aarch64/unified_world.oc",
    "ocore/runtime/aarch64/unified_gic.oc",
    "ocore/runtime/aarch64/kernel_world_monitor.oc",
    "ocore/runtime/aarch64/kernel_world_virtio.oc",
    "ocore/runtime/aarch64/kernel_world_virtio_selftest.oc",
    "ocore/runtime/aarch64/kernel_world_net_host.oc",
    "ocore/runtime/aarch64/kernel_world_net.oc",
    "ocore/runtime/aarch64/kernel_world_9p.oc",
    "ocore/runtime/aarch64/plan9_namespace_uart.oc",
    "ocore/runtime/aarch64/coordinator_uart.oc",
    "ocore/runtime/common/namespace_store.oc",
    "ocore/runtime/common/namespace_peer.oc",
)
PLATFORM = ROOT / "ocore/kernel/aarch64/unified_world"
USERLAND_RECEIPT_SHA = "89bb766092b001a646a60ddc77c3507e05d926528bbde9e92000f006d4b9d9f7"
USERLAND_FROZEN_SHA = "5af4f80faddbf260e4eb188f92b6ccc9a9a953faefff033ec6878ac9ca3a5489"
USERLAND_QUALIFICATION_SHA = "5bc82280fe6f33e5f69ae7a965c6f3eb99e944b7212c7c3cbd707fb9917dad9b"
USERLAND_COEXISTENCE_SHA = "cb50edb12fd4e9d526d01e28318c7990a3ee6eee8d9700a447c532725ad5d318"
SERVICE_SOURCE_SHA = "3606d5182bfb7e03b296e93b84bd5712c63b0cfd1076b21926331a8839a2df98"
STARTUP_SHA = "f5f77df25eca46543906e49c80ab6e1a2cd937077a123b2b8a2fe88b2bac79f8"
SERVICE_SHA = "a53dd1cc3874881524f41be0441b4f2b5396b12585f65bda600225235f4a1675"
IDLE_SCHEDULER = {"schema": "ostadix.unified-idle-scheduler/v1",
                  "blocked_mask_address": 0x6d0000a0, "idle_waits_address": 0x6d0000a8,
                  "plan9_9p_requests_address": 0x6d0000b0,
                  "plan9_9p_request_bytes_address": 0x6d0000b8,
                  "plan9_9p_reply_bytes_address": 0x6d0000c0,
                  "native_poll_frequency_divisor": 200,
                  "policy": "park WFI until waking virtual interrupt; WFE remains a hint"}


def qualified_userland_policy(receipt_sha: str) -> dict:
    """Select an explicitly qualified provider; self-consistent files do not admit one."""
    if receipt_sha == USERLAND_RECEIPT_SHA:
        return {"revision": "build7", "frozen_sha": USERLAND_FROZEN_SHA,
                "source_sha": SERVICE_SOURCE_SHA, "startup_sha": STARTUP_SHA,
                "service_sha": SERVICE_SHA, "unchanged_from_build5": True,
                "prior_service_sha": SERVICE_SHA,
                "qualification_relative": "qualification-7/result.json",
                "qualification_sha": USERLAND_QUALIFICATION_SHA,
                "coexistence_sha": USERLAND_COEXISTENCE_SHA}
    if receipt_sha == "b128b0df09e80318576282c6c2799a4bdde00980ffaddee37c6ac83d326dbbbf":
        return {"revision": "traffic-20261106-build2",
                "frozen_sha": "66fc0080bde1f8a0a17bf2b819320359146e8609c528ba38e5def9dd8eca5f4e",
                "source_sha": "e3e85652ce83159882f14b84a72a9cbaf55085d14f228a9c50b2433f5eb143f3",
                "startup_sha": STARTUP_SHA,
                "service_sha": "701d9c32373d41f145b4d4b5fb346f626ee65ddd3d06581bace87f2290b79942",
                "unchanged_from_build5": False, "prior_service_sha": SERVICE_SHA,
                "qualification_relative": "okernel-plan9-traffic-20261106-qualification-1/result.json",
                "qualification_sha": "0d46c69d9074a8ebc7b04fa0bd2d9c25125310ecbe8e42b077d6480696006d95",
                "coexistence_sha": "b4d69a906424e7a8842f05f639f49f480062104a9e22a18465f29a5fb4786d7d",
                "fresh_behavior": True}
    raise ValueError("Plan9 userland receipt differs from qualified build7 pin or a qualified successor")


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity(path: Path, relative_to: Path | None = None) -> dict:
    return {"path": str(path.relative_to(relative_to) if relative_to is not None else path.resolve()),
            "bytes": path.stat().st_size, "sha256": fingerprint(path)}


def capture(source: Path, target: Path) -> dict:
    if source.is_symlink() or not source.is_file():
        raise ValueError("expected regular admitted input: " + str(source))
    expected = identity(source)
    shutil.copyfile(source, target)
    observed = identity(target)
    if any(expected[key] != observed[key] for key in ("bytes", "sha256")):
        raise ValueError("input changed while capturing: " + str(source))
    target.chmod(0o400)
    return expected


def checked_identity(item: dict) -> dict:
    path = Path(item["path"])
    if path.is_symlink() or not path.is_file() or identity(path) != item:
        raise ValueError("frozen Plan9 derivation evidence changed: " + str(path))
    return item


def capture_expected(item: dict, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    capture(Path(item["path"]), target)
    observed = identity(target)
    if any(observed[key] != item[key] for key in ("bytes", "sha256")):
        raise ValueError("admitted Plan9 input changed while capturing: " + item["path"])


def admit_userland_derivation(receipt: Path, kernel_identity: dict) -> dict:
    """Admit a separately qualified provider without weakening preceding pins.

    Receipt pins are observed provenance, not signatures or source bootstrap.
    Validation reads captured exports without extracting, executing a supplied
    controller, creating temporary files or launching a VM.
    """
    receipt_id = identity(receipt)
    if receipt.is_symlink():
        raise ValueError("Plan9 userland receipt must be a regular nonsymlink file")
    policy = qualified_userland_policy(receipt_id["sha256"])
    document = json.loads(receipt.read_text())
    frozen_path = receipt.parent / "FROZEN.json"
    if frozen_path.is_symlink() or fingerprint(frozen_path) != policy["frozen_sha"]:
        raise ValueError("Plan9 userland FROZEN receipt differs from its qualified pin")
    frozen = json.loads(frozen_path.read_text())
    if (document.get("schema") != "ostadix.original9front-userland-builder/v1" or document.get("ok") is not True
            or document.get("source_commit") != "350266104f1fed81c78c3d05fa44f523bec0ae4d"
            or document.get("exports_captured_after_halt") is not True
            or frozen.get("schema") != "ostadix.frozen-private-native-build/v1"
            or frozen.get("receipt") != receipt_id or frozen.get("artifacts") != document.get("artifacts")):
        raise ValueError("Plan9 userland build/frozen provenance is inconsistent")
    artifacts = document["artifacts"]
    for expected in artifacts.values():
        checked_identity(expected)
    if any(kernel_identity[key] != artifacts["KERNEL.U"][key] for key in ("bytes", "sha256")):
        raise ValueError("Plan9 kernel differs from qualified userland kernel")
    if (artifacts["SERVICE"]["sha256"] != policy["service_sha"]
            or document["inputs"]["P9CMDSRV.C"]["sha256"] != policy["source_sha"]
            or document["inputs"]["START.RC"]["sha256"] != policy["startup_sha"]
            or frozen["source"] != document["inputs"]["P9CMDSRV.C"]
            or frozen["startup"] != document["inputs"]["START.RC"]
            or frozen.get("service_unchanged_from_build5") is not policy["unchanged_from_build5"]
            or frozen["prior_service"]["sha256"] != policy["prior_service_sha"]):
        raise ValueError("Plan9 service/background startup identity is not qualified")
    for group in ("inputs", "platform_artifacts", "host_tools"):
        for item in document[group].values():
            checked_identity(item)
    for name in ("official_image", "source_image", "uart_original", "console"):
        checked_identity(document[name])
    checked_identity(document["original_kernel"]["container"])
    checked_identity(frozen["prior_service"])
    if (document["official_image"]["sha256"] != "67484f032a13eb9760a6287a1c0136a178da38b3c01e19ca7381d2e14a40a20f"
            or document["original_kernel"]["container"]["sha256"] != "df704b7fff3417eeb9924fed7170fed5e0aeb52829d11fabcbf4e9f6732b34ae"
            or document["inputs"]["UART.C"]["sha256"] != "f3c0ec64beafeae20bb5f3fc859724fb648ae8d0109045ba6ae7f77f9a0a8c8c"
            or document["inputs"]["uart.patch"]["sha256"] != "9e264301ac0f6311e3790caaefe9996138af63e62bd6c15da3fac8073b0593d3"
            or any(command.get("exit_code") != 0 for command in document["commands"])):
        raise ValueError("Plan9 original-image/UART/native-build provenance is inconsistent")
    script = Path(document["inputs"]["BUILD.RC"]["path"]).read_text()
    tokens = re.findall(r"echo P9_PROVIDER_PASS_([0-9a-f]{24})", script)
    console = Path(document["console"]["path"]).read_bytes().replace(b"\r", b"")
    if (len(tokens) != 1 or not console.rstrip(b"\n").endswith(b"done halting")
            or ("P9_PROVIDER_PASS_" + tokens[0]).encode() not in console.splitlines()
            or b"P9_USERLAND_NATIVE_HELLO" not in console.splitlines()
            or b"P9_CLOCK 1793431069" not in console.splitlines()
            or "if(! ~ $paqbefore(1) $paqafter(1)) fail changedpaq" not in script):
        raise ValueError("Plan9 native compile/PAQ-continuity/halt evidence is incomplete")
    # Retain the original build controller's provenance, without importing it
    # or invoking its mutating qualify_exports/revalidate operations.
    validator_path = ROOT / "scripts/build_okernel_plan9_userland.py"
    if fingerprint(validator_path) != document["inputs"]["builder.py"]["sha256"]:
        raise ValueError("Plan9 archive validator differs from the qualified builder source")
    declared = {item["guest_path"]: item for item in document["provider_files"]}
    if len(declared) != len(document["provider_files"]):
        raise ValueError("duplicate declared Plan9 provider file")
    for item in declared.values():
        checked_identity({key: item[key] for key in ("path", "bytes", "sha256")})
    verifier_path = ROOT / "scripts/plan9_userland_admission.py"
    if verifier_path.is_symlink() or not verifier_path.is_file():
        raise ValueError("read-only Plan9 verifier must be a regular repository file")
    verifier_id = identity(verifier_path)
    verifier_source = verifier_path.read_bytes()
    if (len(verifier_source) != verifier_id["bytes"]
            or hashlib.sha256(verifier_source).hexdigest() != verifier_id["sha256"]):
        raise ValueError("read-only Plan9 verifier changed before loading")
    spec = importlib.util.spec_from_file_location("unified_readonly_userland_verifier", verifier_path)
    verifier = importlib.util.module_from_spec(spec)
    # Compile trusted repository source directly: loader.exec_module can write
    # __pycache__ even when the verifier itself performs only read operations.
    exec(compile(verifier_source, str(verifier_path), "exec"), verifier.__dict__)
    verified = verifier.verify_exports(receipt.parent, receipt.parent / "inputs", document)
    if identity(verifier_path) != verifier_id:
        raise ValueError("read-only Plan9 verifier changed during admission")
    actual = {item["guest_path"]: (item["bytes"], item["sha256"]) for item in verified["provider_files"]}
    if (actual != {name: (item["bytes"], item["sha256"]) for name, item in declared.items()}
            or verified["provider_bytes"] != document["provider_bytes"]
            or verified["original_tools"] != document["original_tools"]
            or verified["uimage"] != document["uimage"]):
        raise ValueError("complete Plan9 original closure differs from qualified inventory")
    if fingerprint(validator_path) != document["inputs"]["builder.py"]["sha256"]:
        raise ValueError("Plan9 archive validator changed during admission")
    qualification_path = receipt.parent.parent / policy["qualification_relative"]
    if qualification_path.is_symlink() or fingerprint(qualification_path) != policy["qualification_sha"]:
        raise ValueError("Plan9 command-provider qualification differs from its approved pin")
    qualification = json.loads(qualification_path.read_text())
    coexistence_id = qualification["coexistence_gate"]
    checked_identity(coexistence_id)
    coexistence = json.loads(Path(coexistence_id["path"]).read_text())
    if (qualification.get("ok") is not True or qualification["build"] != receipt_id
            or coexistence_id["sha256"] != policy["coexistence_sha"] or coexistence.get("ok") is not True
            or coexistence["builder_receipt"] != receipt_id or coexistence["service"] != artifacts["SERVICE"]
            or coexistence["vm"]["kernel_source"] != artifacts["KERNEL.U"]):
        raise ValueError("Plan9 console/service qualification is not bound to this provider")
    copies = {"FROZEN.json": identity(frozen_path), "qualification.json": identity(qualification_path),
              "coexistence.json": coexistence_id, "console.log": document["console"],
              "admission-verifier.py": verifier_id}
    if policy.get("fresh_behavior"):
        gates = qualification.get("behavior_gates", {})
        if (qualification.get("behavior_cases") != 22
                or set(gates) != {"foreground", "cancel-active", "cancel-before", "cancel-truncated", "timeout"}
                or qualification.get("service_equivalence", {}).get("byte_for_byte_equal") is not False):
            raise ValueError("new Plan9 service lacks its fresh complete behavior qualification")
        for name, item in gates.items():
            checked_identity(item)
            gate = json.loads(Path(item["path"]).read_text())
            if (gate.get("ok") is not True or gate.get("builder_receipt") != receipt_id
                    or gate.get("service") != artifacts["SERVICE"]
                    or gate.get("vm", {}).get("kernel_source") != artifacts["KERNEL.U"]):
                raise ValueError("new Plan9 behavior gate does not bind this service: " + name)
            copies["behavior/" + name + ".json"] = item
        for name in ("unit_tests", "native_polling_fixture"):
            checked_identity(qualification[name])
            copies[name + ".json"] = qualification[name]
    for group in ("inputs", "platform_artifacts", "artifacts"):
        copies.update({group + "/" + name: item for name, item in document[group].items()})
    return {**document, "admission_kind": "qualified-original-userland", "admitted_receipt": receipt_id,
            "admission_copies": copies,
            "provider_admission": {"revision": policy["revision"], "service": artifacts["SERVICE"], "startup": frozen["startup"],
                                   "service_guest_path": "/arm64/bin/p9cmdsrv", "startup_guest_path": "/rc/bin/okernel-start",
                                   "kernel": artifacts["KERNEL.U"], "paq": artifacts["USER.PAQ"],
                                   "files": len(declared), "bytes": document["provider_bytes"],
                                   "frozen": identity(frozen_path), "qualification": identity(qualification_path),
                                   "coexistence": coexistence_id, "export_verifier": verifier_id,
                                   "interruption_policy": "Owning Plan9 domain must be recycled before exposing interrupted completion or admitting another request"}}


def admit_plan9_derivation(receipt: Path, kernel_identity: dict, legacy_admission) -> dict:
    document = json.loads(receipt.read_text())
    if not isinstance(document, dict):
        raise ValueError("Plan9 derivation receipt must be an object")
    schema = document.get("schema")
    if schema == "ostadix.original9front-userland-builder/v1":
        return admit_userland_derivation(receipt, kernel_identity)
    # Preserve the original standalone-kernel admission, including its exact
    # recipe/image/two-build pins. Other schemas are not promoted as userland.
    return {**legacy_admission.admit_derivation(receipt, kernel_identity),
            "admission_kind": "original-kernel", "admitted_receipt": identity(receipt)}


def linux_dts(template: str, initrd_bytes: int) -> str:
    old = """gic: interrupt-controller@8000000 {
        compatible = "arm,cortex-a15-gic";
        #interrupt-cells = <3>;
        #address-cells = <0>;
        interrupt-controller;
        reg = <0 0x08000000 0 0x10000>, <0 0x08010000 0 0x10000>;
    };"""
    new = """gic: interrupt-controller@8000000 {
        compatible = "arm,gic-v3";
        #interrupt-cells = <3>;
        #address-cells = <2>;
        #size-cells = <2>;
        interrupt-controller;
        #redistributor-regions = <1>;
        ranges;
        reg = <0 0x08000000 0 0x10000>, <0 0x080a0000 0 0x20000>;
    };"""
    if template.count(old) != 1:
        raise ValueError("Linux DTB template changed; explicit GICv3 adaptation needs review")
    text = template.replace(old, new).replace("INITRD_END", hex(0x48000000 + initrd_bytes))
    # This Linux-only port is a native private controller channel. Plan9's
    # same-numbered IPA belongs to its separate namespace transport view.
    clock_marker = "    pl011@9000000 {"
    if text.count(clock_marker) != 1:
        raise ValueError("Linux UART template changed; coordinator adapter needs review")
    coordinator = """    pl011@9001000 {
        compatible = "arm,pl011", "arm,primecell";
        reg = <0 0x09001000 0 0x1000>;
        interrupts = <0 19 4>;
        clocks = <&clock>, <&clock>;
        clock-names = "uartclk", "apb_pclk";
    };
"""
    # Append after ttyAMA0 to preserve existing console enumeration.
    endpoint = "    virtio_mmio@a000000 {"
    if text.count(endpoint) != 1:
        raise ValueError("Linux UART insertion point changed; explicit adapter needs review")
    text = text.replace(endpoint, coordinator + endpoint)
    for placeholder, address, irq in (("NETWORK_DEVICE", "a000200", 17), ("NAMESPACE_DEVICE", "a000400", 18)):
        text = text.replace(placeholder, """virtio_mmio@""" + address + """ {
        compatible = "virtio,mmio";
        reg = <0 0x0""" + address + """ 0 0x200>;
        interrupts = <0 """ + str(irq) + """ 4>;
        dma-coherent;
    };""")
    return text


def plan9_recovery_contract(kernel_bytes: int, dtb_bytes: int) -> dict:
    if not 0 < kernel_bytes <= 0x1000000 or not 0 < dtb_bytes <= 0x10000:
        raise ValueError("Plan9 recovery backup exceeds its protected kernel/DTB window")
    return {"control_address": 0x6d000070, "control_bytes": 48,
            "kernel_backup_address": 0xd0000000, "kernel_max_bytes": 0x1000000,
            "dtb_backup_address": 0xd1000000, "dtb_max_bytes": 0x10000,
            "pause": 1, "restart": 2}


def build(payload: Path, plan9: Path, derivation: Path, output: Path, compiler: Path,
          clang: str, lld: str, dtc: str, *, plan9_recovery: bool = False) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("unified output must be a new isolated directory")
    metadata = json.loads((payload / "linux-payload.json").read_text())
    if (metadata.get("schema") != "ostadix.real-linux-payload/v1"
            or metadata.get("profile") != "package-domain"
            or metadata.get("linux_version") != "6.12.43"
            or metadata.get("source_modifications") is not False
            or metadata.get("source_archive_sha256") != "0fcbbbbcd456e87bbbfc8bf37af541fda62ccfcce76903503424fd101ef7bdee"):
        raise ValueError("expected the pinned original Linux package-domain payload")
    image = payload / "Image"
    expected = metadata["artifacts"]["Image"]
    if image.stat().st_size != expected["bytes"] or fingerprint(image) != expected["sha256"]:
        raise ValueError("Linux Image differs from its admitted payload metadata")
    config_file = payload / "linux.config"
    config_expected = metadata["artifacts"]["linux.config"]
    if config_file.stat().st_size != config_expected["bytes"] or fingerprint(config_file) != config_expected["sha256"]:
        raise ValueError("Linux configuration differs from its captured payload identity")
    config = config_file.read_text()
    for required in ("CONFIG_ARM_GIC_V3=y", "CONFIG_PROC_CHILDREN=y"):
        if required not in config.splitlines():
            raise ValueError("unified Linux payload requires " + required)
    initrd_size = (payload / "initramfs.cpio").stat().st_size
    if not 0 < initrd_size <= 0x08000000:
        raise ValueError("Linux initramfs exceeds its declared guest window")
    spec = importlib.util.spec_from_file_location("unified_plan9_admission", ROOT / "scripts/probe_okernel_plan9.py")
    admission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(admission)
    plan9_identity = identity(plan9)
    admitted = admit_plan9_derivation(derivation, plan9_identity, admission)
    container, kernel = admission.inspect_uimage(plan9)
    if identity(plan9) != plan9_identity:
        raise ValueError("Plan9 kernel changed during derivation admission")
    if plan9_recovery:
        plan9_recovery_contract(len(kernel), 1)
    output.mkdir(parents=True)
    inputs = output / "inputs"
    inputs.mkdir()
    for name, source in (("linux.Image", image), ("linux.initramfs", payload / "initramfs.cpio"),
                         ("linux.config", payload / "linux.config"),
                         ("linux-payload.json", payload / "linux-payload.json"),
                         ("plan9.uimage", plan9), ("plan9-derivation.json", derivation)):
        expected_capture = plan9_identity if name == "plan9.uimage" else admitted["admitted_receipt"] if name == "plan9-derivation.json" else None
        if expected_capture is None:
            capture(source, inputs / name)
        else:
            capture_expected(expected_capture, inputs / name)
    userland_captures = {}
    for name, item in admitted.get("admission_copies", {}).items():
        destination = inputs / "plan9-userland" / name
        capture_expected(item, destination)
        userland_captures["inputs/plan9-userland/" + name] = identity(destination, output)
    (inputs / "plan9.kernel").write_bytes(kernel)
    (inputs / "plan9.kernel").chmod(0o400)
    profile = output / "profile.oc"
    profile.write_text("""module runtime::aarch64::kernel_world_profile;
pub const PERSISTENT: u64 = 1;
pub const BACKING_BASE: usize = 0x7000_0000;
pub const BACKING_BYTES: usize = 1_073_741_824;
pub const NETWORK: u64 = 1;
pub const NAMESPACE: u64 = 1;
""")
    (output / "linux.dts").write_text(linux_dts((ROOT / "ocore/kernel/aarch64/kernel_world/guest.dts").read_text(), initrd_size))
    capture(ROOT / "ocore/kernel/aarch64/plan9_probe/guest.dts", output / "plan9.dts")
    tools = {"ocorec": compiler, "clang": Path(shutil.which(clang) or clang),
             "lld": Path(shutil.which(lld) or lld), "dtc": Path(shutil.which(dtc) or dtc)}
    for name, path in tools.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("required build tool unavailable: " + name)
    commands = [
        [str(compiler), str(profile), *(str(ROOT / name) for name in SOURCES),
         "--target", "aarch64-unknown-none", "--emit", "obj", "--keep-asm", "-o", str(output / "kernel.o")],
        [str(tools["clang"]), "-target", "aarch64-unknown-none-elf", "-ffreestanding", "-fno-stack-protector",
         "-c", str(PLATFORM / "monitor.S"), "-o", str(output / "monitor.o")],
        [str(tools["lld"]), "-m", "aarch64elf", "-nostdlib", "--build-id=none", "-z", "max-page-size=0x1000",
         "-T", str(PLATFORM / "linker.ld"), "-o", str(output / "monitor.elf"),
         str(output / "monitor.o"), str(output / "kernel.o")],
    ]
    for name in ("linux", "plan9"):
        commands.append([str(tools["dtc"]), "-I", "dts", "-O", "dtb", "-o",
                         str(output / (name + ".dtb")), str(output / (name + ".dts"))])
    tracked = list(SOURCES) + ["ocore/kernel/aarch64/unified_world/monitor.S",
                              "ocore/kernel/aarch64/unified_world/linker.ld",
                              "ocore/kernel/aarch64/kernel_world/guest.dts",
                              "ocore/kernel/aarch64/plan9_probe/guest.dts",
                              "scripts/build_okernel_unified_world.py", "scripts/probe_okernel_plan9.py"]
    if admitted["admission_kind"] == "qualified-original-userland":
        tracked += ["scripts/build_okernel_plan9_userland.py", "scripts/build_okernel_plan9_original.py",
                    "scripts/plan9_userland_admission.py"]
    before = {name: fingerprint(ROOT / name) for name in tracked}
    if (admitted["admission_kind"] == "qualified-original-userland"
            and before["scripts/plan9_userland_admission.py"] != admitted["provider_admission"]["export_verifier"]["sha256"]):
        raise ValueError("read-only Plan9 verifier changed before build capture")
    for command in commands:
        subprocess.run(command, check=True)
    recovery = None
    if plan9_recovery:
        recovery = plan9_recovery_contract(len(kernel), (output / "plan9.dtb").stat().st_size)
        for name, source in (("plan9-recovery.kernel", inputs / "plan9.kernel"),
                             ("plan9-recovery.dtb", output / "plan9.dtb")):
            capture_expected(identity(source), inputs / name)
    if before != {name: fingerprint(ROOT / name) for name in tracked}:
        raise ValueError("unified source changed during build; use a frozen revision")
    captured_sources = {}
    for name in tracked:
        target = output / "sources" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        capture(ROOT / name, target)
        if fingerprint(target) != before[name]:
            raise ValueError("source changed while archiving build inputs")
        captured_sources[name] = identity(target, output)
    artifacts = {name: identity(output / name, output) for name in
                 ("monitor.elf", "linux.dtb", "plan9.dtb", "profile.oc",
                  "inputs/linux.Image", "inputs/linux.initramfs", "inputs/linux.config",
                  "inputs/linux-payload.json", "inputs/plan9.uimage", "inputs/plan9.kernel",
                  "inputs/plan9-derivation.json")}
    artifacts.update(userland_captures)
    if recovery is not None:
        for name in ("inputs/plan9-recovery.kernel", "inputs/plan9-recovery.dtb"):
            artifacts[name] = identity(output / name, output)
    manifest = {
        "schema": "ostadix.unified-world-monitor/v1", "profile": "linux-original-plan9",
        "scope": "native O-core two-domain EL2 profile for original Linux/9front; build alone is not live acceptance or foreign-engine lowering",
        "outer_ram_bytes": 0xc0000000,
        "domains": [
            {"id": 0, "name": "linux", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000,
             "guest_ram_bytes": 0x20000000, "entry": 0x40000000, "x0": 0x47e00000, "vmid": 1},
            {"id": 1, "name": "plan9", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0xb0000000,
             "guest_ram_bytes": 0x20000000, "entry": 0x40100000, "x0": 0x40000000, "vmid": 2}],
        "loader_addresses": {"inputs/linux.Image": 0x48000000, "linux.dtb": 0x4fe00000,
                             "inputs/linux.initramfs": 0x50000000, "inputs/plan9.kernel": 0xb0100000,
                             "plan9.dtb": 0xb0000000},
        "block_backing": {"address": 0x70000000, "bytes": 0x40000000},
        "namespace": {"address": 0x6c000000, "bytes": 0x1000000, "epoch_address": 0x6d000000,
                      "quiescence_address": 0x6d000008, "clock_address": 0x6d000010,
                      "linux_grant": 1, "plan9_grant": 4, "native_peer_grant": 2},
        "plan9_console": {"input_address": 0x6d010000, "input_bytes": 4096,
                         "output_address": 0x6d020000, "output_bytes": 65536},
        "console_mux": {"escape": 30, "linux_select": 48, "plan9_select": 49,
                        "linux_output_address": 0x6d040000, "output_bytes": 65536},
        "coordinator_uart": {"guest_address": 0x09001000, "guest_irq": 51,
                             "input_address": 0x6d060000, "input_bytes": 8192,
                             "output_address": 0x6d080000, "output_bytes": 65536},
        "gic": {"version": 3, "physical_controller": "native monitor only",
                "distributor": [0x08000000, 0x08010000],
                "redistributor": [0x080a0000, 0x080c0000],
                "native_quantum_irq": 26, "quantum_counter_divisor": 100, "lpi_authority": False},
        "idle_scheduler": dict(IDLE_SCHEDULER),
        "artifacts": artifacts, "tools": {name: identity(path) for name, path in tools.items()},
        "source_sha256": before, "source_artifacts": captured_sources,
        "plan9_source_commit": admitted["source_commit"],
        "plan9_derivation_kind": admitted["admission_kind"],
        "plan9_uimage": container}
    if "provider_admission" in admitted:
        manifest["plan9_command_provider"] = admitted["provider_admission"]
    if recovery is not None:
        manifest["plan9_recovery"] = recovery
        manifest["loader_addresses"].update({"inputs/plan9-recovery.kernel": recovery["kernel_backup_address"],
                                             "inputs/plan9-recovery.dtb": recovery["dtb_backup_address"]})
    (output / "monitor-profile.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Unified O-core profile built: " + str(output / "monitor.elf"))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--plan9-kernel", type=Path, required=True)
    parser.add_argument("--derivation-receipt", "--plan9-derivation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ocorec", type=Path, default=ROOT / "target/debug/ocorec")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--lld", default="ld.lld")
    parser.add_argument("--dtc", default="dtc")
    parser.add_argument("--plan9-recovery", action="store_true", help="provision private native Plan9 pause/restart backup windows")
    args = parser.parse_args()
    try:
        build(args.payload.resolve(), args.plan9_kernel.resolve(), args.derivation_receipt.resolve(),
              args.output.absolute(), args.ocorec.resolve(), args.clang, args.lld, args.dtc,
              plan9_recovery=args.plan9_recovery)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("Unified profile build failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
