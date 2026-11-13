#!/usr/bin/env python3
"""Reproduce an admitted two-domain O-core monitor, without booting a VM.

Two fresh source/output directories use captured O-core, assembly and linker
sources plus the admitted compiler/assembler/linker/dtc ELF and DSO closure.
Both native builds must match each other AND the supplied build byte for byte.
The original Linux/9front kernels and initrd remain fixed admitted inputs; this
does not rebuild foreign kernels, bootstrap compilers, qualify live execution,
or reproduce a mutable disk/native-store state. Python3.10+, /bin/sh, the
recorded host PT_INTERP and host Python standard library remain dependencies.

The output is a retained replay bundle: run its reproduce.py --capture BUNDLE
--output NEW_DIRECTORY to repeat from captured inputs/tools without a checkout.
Captured manifests/hashes are provenance bindings, not signatures.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import sys
import time


SCHEMA = "ostadix.okernel-two-domains-native-repro/v1"
CAPTURE_SCHEMA = "ostadix.okernel-two-domains-repro-capture/v1"
BUILDER = "scripts/build_okernel_unified_world.py"
ASSEMBLY = "ocore/kernel/aarch64/unified_world/monitor.S"
LINKER = "ocore/kernel/aarch64/unified_world/linker.ld"
LINUX_DTS = "ocore/kernel/aarch64/kernel_world/guest.dts"
PLAN9_DTS = "ocore/kernel/aarch64/plan9_probe/guest.dts"
COMPARE = ("monitor.elf", "linux.dtb", "plan9.dtb", "kernel.o", "monitor.o", "kernel.s", "profile.oc", "linux.dts", "plan9.dts")
TOOL_NAMES = {"ocorec": "ocorec", "clang": "clang", "lld": "ld.lld", "dtc": "dtc"}
SCOPE = __doc__.split("\n\n")[1]


def identity(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member: " + key)
        value[key] = item
    return value


def document(path):
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON value")))
    if type(value) is not dict:
        raise ValueError("JSON object required: " + str(path))
    return value


def relative(value):
    if not isinstance(value, str):
        raise ValueError("relative path must be text")
    parsed = PurePosixPath(value)
    if not value or parsed.is_absolute() or ".." in parsed.parts or str(parsed) != value:
        raise ValueError("invalid captured relative path: " + value)
    return Path(value)


def regular(root, name):
    path = root / relative(name)
    current = root
    for part in relative(name).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("symlink in captured input: " + str(current))
    if not path.is_file():
        raise ValueError("missing regular captured input: " + str(path))
    return path


def matches(path, expected):
    if (type(expected) is not dict or type(expected.get("bytes")) is not int or expected["bytes"] < 0
            or not isinstance(expected.get("sha256"), str) or len(expected["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in expected["sha256"])):
        raise ValueError("invalid captured identity declaration")
    observed = identity(path)
    if any(observed[key] != expected[key] for key in ("bytes", "sha256")):
        raise ValueError("captured identity differs: " + str(path))
    return observed


def copy_file(source, target):
    before = identity(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o444)
    matches(target, before)
    if identity(source) != before:
        raise ValueError("input changed during capture: " + str(source))
    return {"original": before, "frozen": identity(target)}


def write_json(path, value):
    pending = path.with_name(path.name + ".pending")
    with pending.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)


NATIVE_SUPPORT = ("o10_native_fixture.py", "build_o10_native_fixture.py",
                  "build_okernel_unified_world.py")


def native_support():
    """Load checked canonical helpers from this checkout or a captured bundle."""
    directory = Path(__file__).resolve().parent
    if not (directory / NATIVE_SUPPORT[0]).is_file():
        directory /= "support/native-admission"
    modules, previous = {}, {}
    previous_path = sys.path[:]
    try:
        for filename in NATIVE_SUPPORT:
            name = Path(filename).stem
            path = regular(directory, filename)
            previous[name] = sys.modules.get(name)
            spec = importlib.util.spec_from_file_location(name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            modules[name] = module
    finally:
        sys.path[:] = previous_path
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
    return directory, modules["o10_native_fixture"], modules["build_o10_native_fixture"], modules["build_okernel_unified_world"]


def validate_profile(value):
    required = {
        "schema": "ostadix.unified-world-monitor/v1", "profile": "linux-original-plan9", "outer_ram_bytes": 0xc0000000,
        "domains": [{"id": 0, "name": "linux", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0x48000000,
                     "guest_ram_bytes": 0x20000000, "entry": 0x40000000, "x0": 0x47e00000, "vmid": 1},
                    {"id": 1, "name": "plan9", "guest_ram_ipa": 0x40000000, "guest_ram_pa": 0xb0000000,
                     "guest_ram_bytes": 0x20000000, "entry": 0x40100000, "x0": 0x40000000, "vmid": 2}],
        "block_backing": {"address": 0x70000000, "bytes": 0x40000000},
        "namespace": {"address": 0x6c000000, "bytes": 0x1000000, "epoch_address": 0x6d000000,
                      "quiescence_address": 0x6d000008, "clock_address": 0x6d000010,
                      "linux_grant": 1, "plan9_grant": 4, "native_peer_grant": 2},
        "plan9_console": {"input_address": 0x6d010000, "input_bytes": 4096, "output_address": 0x6d020000, "output_bytes": 65536},
        "console_mux": {"escape": 30, "linux_select": 48, "plan9_select": 49, "linux_output_address": 0x6d040000, "output_bytes": 65536},
        "coordinator_uart": {"guest_address": 0x09001000, "guest_irq": 51, "input_address": 0x6d060000,
                             "input_bytes": 8192, "output_address": 0x6d080000, "output_bytes": 65536},
        "gic": {"version": 3, "physical_controller": "native monitor only", "distributor": [0x08000000, 0x08010000],
                "redistributor": [0x080a0000, 0x080c0000], "native_quantum_irq": 26, "quantum_counter_divisor": 100, "lpi_authority": False},
        "plan9_recovery": {"control_address": 0x6d000070, "control_bytes": 48, "kernel_backup_address": 0xd0000000,
                           "kernel_max_bytes": 0x1000000, "dtb_backup_address": 0xd1000000, "dtb_max_bytes": 0x10000, "pause": 1, "restart": 2},
        "loader_addresses": {"inputs/linux.Image": 0x48000000, "linux.dtb": 0x4fe00000, "inputs/linux.initramfs": 0x50000000,
                             "inputs/plan9.kernel": 0xb0100000, "plan9.dtb": 0xb0000000,
                             "inputs/plan9-recovery.kernel": 0xd0000000, "inputs/plan9-recovery.dtb": 0xd1000000},
    }
    if "linux_recovery" in value:
        required["linux_recovery"] = {
            "kernel_image": 3, "aux_image": 4, "namespace_version": "9P2000.u",
            "kernel_backup_address": 0xd2000000, "kernel_max_bytes": 0x7e00000,
            "dtb_backup_address": 0xe2000000, "dtb_max_bytes": 0x10000,
            "initrd_backup_address": 0xda000000, "initrd_max_bytes": 0x8000000,
            "kernel_bytes_address": 0x6d000100, "dtb_bytes_address": 0x6d000108,
            "initrd_bytes_address": 0x6d000110,
        }
        required["loader_addresses"].update({
            "inputs/linux-recovery.Image": 0xd2000000,
            "inputs/linux-recovery.dtb": 0xe2000000,
            "inputs/linux-recovery.initramfs": 0xda000000,
        })
    if "native_fixture" in value:
        _, fixture, _, _ = native_support()
        required.update(native_fixture=fixture.CONTRACT, domain_capacity=8,
                        o10_qualification=True)
        required["loader_addresses"].update({
            "inputs/native-fixture.kernel": fixture.CONTRACT["kernel_backup_pa"],
            "inputs/native-fixture.aux": fixture.CONTRACT["aux_backup_pa"],
        })
        if "linux_recovery" not in value:
            raise ValueError("native fixture requires the exact admitted Linux recovery profile")
    if any(json.dumps(value.get(key), sort_keys=True) != json.dumps(item, sort_keys=True) for key, item in required.items()):
        raise ValueError("expected the exact admitted two-domain native/coordinator/recovery profile")


def inspect_build(build):
    manifest_path = regular(build, "monitor-profile.json")
    manifest = document(manifest_path)
    validate_profile(manifest)
    paths = {"monitor-profile.json": identity(manifest_path)}
    for group in ("artifacts", "source_artifacts"):
        if type(manifest.get(group)) is not dict or not manifest[group]:
            raise ValueError("missing captured " + group)
        for name, expected in manifest[group].items():
            selected = expected.get("path")
            if group == "artifacts" and selected != name:
                raise ValueError("artifact name/path mismatch")
            if group == "source_artifacts" and selected != "sources/" + name:
                raise ValueError("source name/path mismatch")
            path = regular(build, selected)
            paths[selected] = matches(path, expected)
            if group == "source_artifacts" and manifest["source_sha256"].get(name) != expected["sha256"]:
                raise ValueError("source digest maps disagree")
    if set(manifest.get("source_sha256", {})) != set(manifest["source_artifacts"]):
        raise ValueError("incomplete source closure")
    if not {BUILDER, ASSEMBLY, LINKER, LINUX_DTS, PLAN9_DTS} <= manifest["source_artifacts"].keys():
        raise ValueError("missing native platform/generator source closure")
    for name in COMPARE:
        paths[name] = identity(regular(build, name))
    for backup, original, maximum in (("inputs/plan9-recovery.kernel", "inputs/plan9.kernel", 0x1000000),
                                       ("inputs/plan9-recovery.dtb", "plan9.dtb", 0x10000)):
        left, right = paths[backup], paths[original]
        if not 0 < left["bytes"] <= maximum or any(left[key] != right[key] for key in ("bytes", "sha256")):
            raise ValueError("recovery input does not equal admitted original")
    if "linux_recovery" in manifest:
        for backup, original, maximum in (
                ("inputs/linux-recovery.Image", "inputs/linux.Image", 0x7e00000),
                ("inputs/linux-recovery.dtb", "linux.dtb", 0x10000),
                ("inputs/linux-recovery.initramfs", "inputs/linux.initramfs", 0x8000000)):
            left, right = paths.get(backup), paths.get(original)
            if (not isinstance(left, dict) or not isinstance(right, dict)
                    or not 0 < left["bytes"] <= maximum
                    or any(left[key] != right[key] for key in ("bytes", "sha256"))):
                raise ValueError("Linux recovery input does not equal admitted original")
        original_initrd = paths.get("inputs/linux-original.initramfs")
        derived_initrd = paths["inputs/linux.initramfs"]
        derivation = manifest.get("linux_initramfs_derivation")
        if (not isinstance(original_initrd, dict) or not isinstance(derivation, dict)
                or derivation.get("schema") != "ostadix.o10-linux-initramfs/v1"
                or derivation.get("original_sha256") != original_initrd["sha256"]
                or derivation.get("derived_sha256") != derived_initrd["sha256"]
                or derivation.get("changed_entries") != ["init"]
                or derivation.get("disk_script_modified") is not False
                or derivation.get("namespace_version") != "9P2000.u"):
            raise ValueError("Linux initramfs derivation is not bound to captured inputs")
    if "native_fixture" in manifest:
        inspect_native_fixture(build, manifest, paths)
    return manifest, paths


def inspect_native_fixture(build, manifest, paths):
    support, fixture, fixture_builder, builder = native_support()
    expected = set(builder.captured_source_paths(manifest.get("plan9_derivation_kind"),
                                                native_fixture=True))
    if set(manifest["source_artifacts"]) != expected:
        raise ValueError("incomplete canonical native fixture source closure")
    # The closure recipe/contract used by this verifier must be the captured ones.
    for filename in NATIVE_SUPPORT:
        matches(regular(build, "sources/scripts/" + filename), identity(regular(support, filename)))
    required_artifacts = {
        "inputs/native-fixture.kernel", "inputs/native-fixture.aux",
        "native-fixture/build.json", "native-fixture/fixture.elf", "native-fixture/fixture.su"}
    if not required_artifacts <= manifest["artifacts"].keys():
        raise ValueError("incomplete native fixture artifact closure")
    contract = fixture.CONTRACT
    kernel = paths["inputs/native-fixture.kernel"]
    aux = regular(build, "inputs/native-fixture.aux")
    if not 0 < kernel["bytes"] <= contract["kernel_max_bytes"]:
        raise ValueError("native fixture kernel exceeds its immutable image window")
    if aux.read_bytes() != fixture.auxiliary_image():
        raise ValueError("native fixture auxiliary bytes differ from the exact contract")
    receipt = document(regular(build, "native-fixture/build.json"))
    if (receipt.get("schema") != "ostadix.o10-m3-native-fixture-build/v1"
            or receipt.get("built") is not True or receipt.get("source_unchanged") is not True
            or json.dumps(receipt.get("contract"), sort_keys=True) != json.dumps(contract, sort_keys=True)):
        raise ValueError("native fixture build receipt is not a successful exact-contract build")
    sources = set(fixture_builder.SOURCES) | {
        "scripts/build_o10_native_fixture.py", "scripts/o10_native_fixture.py"}
    for group in ("source_before", "source_after"):
        if type(receipt.get(group)) is not dict or set(receipt[group]) != sources:
            raise ValueError("native fixture build source closure is incomplete")
        for name in sources:
            matches(regular(build, "sources/" + name), receipt[group][name])
    aliases = {"fixture.bin": "inputs/native-fixture.kernel", "fixture.aux": "inputs/native-fixture.aux",
               "fixture.elf": "native-fixture/fixture.elf", "fixture.su": "native-fixture/fixture.su"}
    if type(receipt.get("artifacts")) is not dict or set(receipt["artifacts"]) != set(aliases):
        raise ValueError("native fixture build artifact closure is incomplete")
    for name, alias in aliases.items():
        matches(regular(build, alias), receipt["artifacts"][name])
        selected = "native-fixture/" + name
        paths[selected] = matches(regular(build, selected), receipt["artifacts"][name])
    header = regular(build, "native-fixture/fixture.elf").read_bytes()[:64]
    if (len(header) != 64 or header[:6] != b"\x7fELF\x02\x01"
            or struct.unpack_from("<H", header, 18)[0] != 183
            or struct.unpack_from("<Q", header, 24)[0] != contract["entry"]):
        raise ValueError("native fixture is not the contracted AArch64 ELF64 image")
    steps = receipt.get("commands")
    if type(steps) is not list or len(steps) != 4:
        raise ValueError("native fixture build needs four completed compiler/linker commands")
    for index, step in enumerate(steps):
        if type(step) is not dict or type(step.get("returncode")) is not int or step["returncode"] != 0:
            raise ValueError("native fixture compiler/linker command did not succeed")
        for stream in ("stdout", "stderr"):
            selected = "native-fixture/command-%d.%s" % (index, stream)
            paths[selected] = matches(regular(build, selected), step.get(stream))
    return receipt


def recipe(build, manifest):
    source = regular(build, "sources/" + BUILDER)
    tree = ast.parse(source.read_text(encoding="utf-8"))
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "SOURCES" for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError("captured builder does not declare one source order")
    order = ast.literal_eval(assignments[0].value)
    if (not isinstance(order, tuple) or len(set(order)) != len(order)
            or set(order) != {name for name in manifest["source_artifacts"] if name.endswith(".oc")}
            or "ocore/runtime/aarch64/unified_world.oc" not in order
            or "ocore/runtime/aarch64/coordinator_uart.oc" not in order):
        raise ValueError("captured compiler source order/closure mismatch")
    for name in (*order, ASSEMBLY, LINKER, LINUX_DTS, PLAN9_DTS):
        regular(build, "sources/" + str(relative(name)))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "linux_dts"]
    if len(functions) != 1:
        raise ValueError("missing captured Linux device-tree generator")
    # Execute only the already admitted generator, never the builder's admission
    # flow or main. All source bytes and this extraction are retained as evidence.
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
    profiles = [call.args[0] for call in ast.walk(tree) if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "profile" and call.func.attr == "write_text"
                and len(call.args) == 1 and not call.keywords]
    if len(profiles) != 1:
        raise ValueError("captured builder profile recipe is not a literal")
    profile = profiles[0]
    if isinstance(profile, ast.Constant) and isinstance(profile.value, str):
        text = profile.value
    elif isinstance(profile, ast.JoinedStr) and type(manifest.get("o10_qualification")) is bool:
        # This sole fixed expression selects the captured qualification build.
        # Do not evaluate arbitrary captured f-string expressions or formatters.
        expression = ast.dump(ast.parse("1 if o10_qualification else 0", mode="eval").body)
        parts, substitutions = [], 0
        for part in profile.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            elif (isinstance(part, ast.FormattedValue) and part.conversion == -1
                  and part.format_spec is None and ast.dump(part.value) == expression):
                parts.append("1" if manifest["o10_qualification"] else "0")
                substitutions += 1
            else:
                raise ValueError("captured builder profile recipe is not a literal or exact qualification expression")
        if substitutions != 1:
            raise ValueError("captured builder profile recipe requires one qualification expression")
        text = "".join(parts)
    else:
        raise ValueError("captured builder profile recipe is not a literal or exact qualification expression")
    return tuple(order), namespace["linux_dts"], text


def commands(source, build, tools, order):
    return [
        [str(tools / "ocorec"), str(build / "profile.oc"), *(str(source / item) for item in order),
         "--target", "aarch64-unknown-none", "--emit", "obj", "--keep-asm", "-o", str(build / "kernel.o")],
        [str(tools / "clang"), "-target", "aarch64-unknown-none-elf", "-ffreestanding", "-fno-stack-protector",
         "-c", str(source / ASSEMBLY), "-o", str(build / "monitor.o")],
        [str(tools / "ld.lld"), "-m", "aarch64elf", "-nostdlib", "--build-id=none", "-z", "max-page-size=0x1000",
         "-T", str(source / LINKER), "-o", str(build / "monitor.elf"), str(build / "monitor.o"), str(build / "kernel.o")],
        *[[str(tools / "dtc"), "-I", "dts", "-O", "dtb", "-o", str(build / (name + ".dtb")),
           str(build / (name + ".dts"))] for name in ("linux", "plan9")],
    ]


def load_freezer(path):
    spec = importlib.util.spec_from_file_location("two_domain_tool_freezer", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.identity = identity  # Keep the old helper's ELF/DSO logic, support Python3.10.
    return module


def elf_interpreter(path):
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:6] != b"\x7fELF\x02\x01" or len(header) != 64:
            raise ValueError("expected native ELF64 little-endian tool")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size != 56 or count > 4096:
            raise ValueError("invalid native ELF program headers")
        for index in range(count):
            stream.seek(offset + index * size)
            program = stream.read(size)
            if len(program) != size:
                raise ValueError("truncated native ELF program header")
            if struct.unpack_from("<I", program)[0] == 3:
                start, length = struct.unpack_from("<Q", program, 8)[0], struct.unpack_from("<Q", program, 32)[0]
                if not 1 < length < 4096:
                    raise ValueError("invalid native ELF interpreter")
                stream.seek(start)
                data = stream.read(length)
                if not data.endswith(b"\0") or b"\0" in data[:-1]:
                    raise ValueError("invalid native ELF interpreter path")
                value = data[:-1].decode("utf-8")
                if not Path(value).is_absolute():
                    raise ValueError("nonabsolute native ELF interpreter")
                return value
    return None


def inventory(root, names):
    result = {}
    for name in names:
        path = root / name
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_symlink():
                    raise ValueError("symlink in replay capture: " + str(child))
                if child.is_file():
                    result[str(child.relative_to(root))] = identity(child)
        else:
            result[name] = identity(regular(root, name))
    return result


def check_inventory(root, records):
    for name, expected in records.items():
        matches(regular(root, name), expected)


def run(args, output, evidence):
    started = time.time()
    replay = args.capture.resolve(strict=True) if args.capture else None
    if replay:
        capture = document(regular(replay, "capture.json"))
        if capture.get("schema") != CAPTURE_SCHEMA:
            raise ValueError("unsupported replay capture")
        check_inventory(replay, capture["inventory"])
        source_build = replay / "captured-build"
        helper_source = regular(replay, "support/freeze_tool.py")
    else:
        source_build = args.build.resolve(strict=True)
        helper_source = Path(__file__).resolve().with_name("verify_okernel_unified_repro.py")
    if output == source_build or source_build in output.parents or replay and replay in output.parents:
        raise ValueError("reproduction output must be outside its admitted input")
    manifest, source_identities = inspect_build(source_build)
    evidence.update(admitted_manifest=identity(source_build / "monitor-profile.json"), input_files=source_identities,
                    admitted_input=str(source_build), source_order=None, tools={}, builds=[], artifacts={})
    evidence["implementation"] = copy_file(Path(__file__).resolve(), output / "reproduce.py")
    evidence["freezer_implementation"] = copy_file(helper_source, output / "support/freeze_tool.py")
    if "native_fixture" in manifest:
        support, _, _, _ = native_support()
        evidence["native_admission_implementations"] = {
            name: copy_file(regular(support, name), output / "support/native-admission" / name)
            for name in NATIVE_SUPPORT}
    for name, expected in source_identities.items():
        copy_file(regular(source_build, name), output / "captured-build" / name)
        matches(output / "captured-build" / name, expected)
    freezer = load_freezer(output / "support/freeze_tool.py")
    if set(manifest.get("tools", {})) != set(TOOL_NAMES):
        raise ValueError("unexpected native tool closure")
    for key, tool_name in TOOL_NAMES.items():
        if replay:
            binary = regular(replay, "tools/native/" + tool_name)
            matches(binary, capture["inventory"]["tools/native/" + tool_name])
            previous = os.environ.get("LD_LIBRARY_PATH")
            os.environ["LD_LIBRARY_PATH"] = str(replay / "tools/lib")
            try:
                record = freezer.freeze_tool(tool_name, binary, output)
            finally:
                if previous is None:
                    os.environ.pop("LD_LIBRARY_PATH", None)
                else:
                    os.environ["LD_LIBRARY_PATH"] = previous
            record["admitted_selection"] = manifest["tools"][key]
            selected_name = "tools/selected/" + tool_name
            if selected_name in capture["inventory"]:
                record["selected_wrapper_capture"] = copy_file(regular(replay, selected_name), output / selected_name)
        else:
            selected = Path(manifest["tools"][key]["path"])
            if selected.is_symlink() or not selected.is_file():
                raise ValueError("admitted selected tool is no longer regular")
            matches(selected, manifest["tools"][key])
            record = freezer.freeze_tool(tool_name, selected, output)
            record["admitted_selection"] = manifest["tools"][key]
            with selected.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    record["selected_wrapper_capture"] = copy_file(selected, output / "tools/selected" / tool_name)
        evidence["tools"][key] = record
        interpreter = elf_interpreter(Path(record["native"]["frozen"]["path"]))
        if interpreter:
            evidence.setdefault("host_elf_interpreters", {})[interpreter] = identity(Path(interpreter))
        write_json(output / "result.json", evidence)
    for name, path in (("python", Path(sys.executable).resolve()), ("shell", Path("/bin/sh").resolve()),
                       ("bash", Path(shutil.which("bash") or "/bin/bash").resolve()),
                       ("ldd", Path(shutil.which("ldd") or "/usr/bin/ldd").resolve())):
        evidence.setdefault("host_dependencies", {})[name] = identity(path)
    evidence["host_dependency_scope"] = "Python standard library, /bin/sh and recorded host PT_INTERP remain external; native tools and DSO payloads are captured, not bootstrapped"
    frozen = output / "captured-build"
    order, generate_linux, profile = recipe(frozen, manifest)
    evidence["source_order"] = list(order)
    (output / "reproduce.py").chmod(0o555)
    retained = inventory(output, ("captured-build", "tools", "support", "reproduce.py"))
    write_json(output / "capture.json", {"schema": CAPTURE_SCHEMA, "scope": SCOPE, "inventory": retained,
               "admitted_manifest": evidence["admitted_manifest"], "source_order": list(order),
               "invocation": "python3 reproduce.py --capture BUNDLE --output NEW_DIRECTORY"})
    environment = {"PATH": str(output / "tools/bin") + ":/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC",
                   "SOURCE_DATE_EPOCH": "0", "PYTHONHASHSEED": "0"}
    evidence["build_environment"] = environment
    for index in (1, 2):
        source, build = output / ("source-" + str(index)), output / ("build-" + str(index))
        shutil.copytree(frozen / "sources", source)
        build.mkdir()
        (build / "profile.oc").write_text(profile, encoding="utf-8")
        (build / "linux.dts").write_text(generate_linux((source / LINUX_DTS).read_text(encoding="utf-8"),
                                                       manifest["artifacts"]["inputs/linux.initramfs"]["bytes"]), encoding="utf-8")
        copy_file(source / PLAN9_DTS, build / "plan9.dts")
        for name in ("profile.oc", "linux.dts", "plan9.dts"):
            matches(build / name, source_identities[name])
        steps = []
        evidence["builds"].append({"source": str(source), "output": str(build), "commands": steps})
        for number, command in enumerate(commands(source, build, output / "tools/bin", order), 1):
            log = output / ("build-%d-command-%d.log" % (index, number))
            step = {"argv": command, "cwd": str(source), "log": str(log), "exit_status": None}
            steps.append(step)
            write_json(output / "result.json", evidence)
            with log.open("wb") as stream:
                completed = subprocess.run(command, cwd=source, env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=args.timeout)
            step["exit_status"] = completed.returncode
            if completed.returncode:
                raise ValueError("native rebuild failed: " + str(log))
        for name in manifest["source_artifacts"]:
            matches(regular(source, name), manifest["source_artifacts"][name])
    for name in COMPARE:
        first, second = output / "build-1" / name, output / "build-2" / name
        first_identity, second_identity = identity(first), identity(second)
        expected = source_identities[name]
        identical = all(first_identity[key] == second_identity[key] == expected[key] for key in ("bytes", "sha256"))
        evidence["artifacts"][name] = {"byte_identical_two_fresh_builds_and_admitted": identical,
                                       "admitted": expected, "build_1": first_identity, "build_2": second_identity}
        if not identical:
            raise ValueError("native rebuild does not reproduce admitted bytes: " + name)
    check_inventory(output, retained)
    for name, expected in source_identities.items():
        matches(regular(source_build, name), expected)
    for record in evidence["tools"].values():
        if not replay:
            matches(Path(record["selected"]["path"]), record["selected"])
        for item in (record["native"], *record["dependencies"]):
            matches(Path(item["original"]["path"]), item["original"])
            matches(Path(item["frozen"]["path"]), item["frozen"])
    for expected in evidence["host_dependencies"].values():
        matches(Path(expected["path"]), expected)
    for entry, expected in evidence.get("host_elf_interpreters", {}).items():
        matches(Path(entry), expected)
    if replay:
        check_inventory(replay, capture["inventory"])
    evidence.update(passed=True, inputs_and_tools_unchanged=True, capture=identity(output / "capture.json"),
                    elapsed_seconds=round(time.time() - started, 3))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    selected = parser.add_mutually_exclusive_group(required=True)
    selected.add_argument("--build", type=Path, help="explicit admitted two-domain build directory")
    selected.add_argument("--capture", type=Path, help="retained replay bundle produced by this verifier")
    parser.add_argument("--output", required=True, type=Path, help="new directory; existing paths are refused")
    parser.add_argument("--timeout", type=int, default=180, help="per native command timeout in seconds")
    args = parser.parse_args()
    if not 0 < args.timeout <= 3600:
        parser.error("timeout must be between1 and3600 seconds")
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        parser.error("output must be a new directory")
    source = (args.capture or args.build).resolve(strict=True)
    if output == source or source in output.parents:
        parser.error("output must be outside its admitted input")
    output.mkdir(parents=True)
    evidence = {"schema": SCHEMA, "passed": False, "scope": SCOPE, "limitations": __doc__.split("\n\n")[1],
                "started_unix": time.time(), "output": str(output)}
    write_json(output / "result.json", evidence)
    try:
        run(args, output, evidence)
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, subprocess.SubprocessError) as error:
        evidence["error"] = str(error)
        write_json(output / "result.json", evidence)
        print("Two-domain native reproduction: FAIL: " + str(error) + "\nEvidence: " + str(output / "result.json"), file=sys.stderr)
        return 1
    write_json(output / "result.json", evidence)
    print("Two-domain native reproduction: PASS\nEvidence: " + str(output / "result.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
