#!/usr/bin/env python3
"""M3 three-domain component gate on one new private QEMU state fork.

An explicit --execute is required. The gate leaves interrupted guest work
unknown and issues new counter requests only after known lifecycle recovery.
Full M3 additionally requires aligned regressions and acceptance binding.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import struct
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import verify_o10_linux_restart as common
import build_okernel_unified_world as builder
import freeze_okernel_unified_runtime as freezer
import verify_okernel_two_domains_repro as repro
from o10_native_fixture import CONTRACT, CORPUS, auxiliary_image, decode_heartbeat

need = common.need
identity = common.identity
digest = common.digest
safe = common.safe
WINDOW_SECONDS = 240
SCOPE = ("Three real EL1 domains under the AArch64 QEMU EL2 monitor, using the "
         "baseline Linux grant1, Plan9 grant4 and native grant3; component gate "
         "only, with full M3 regressions and acceptance binding still required.")


def command(argv, *, cwd=ROOT):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=30)
    return dict(argv=list(map(str, argv)), returncode=result.returncode,
                stdout=result.stdout, stderr=result.stderr)


def checked_relative(root, name):
    path = Path(name)
    need(not path.is_absolute() and path.parts and all(p not in ("", ".", "..") for p in path.parts),
         "unsafe inventory path")
    selected = root
    for part in path.parts:
        selected = selected / part
        need(not selected.is_symlink(), "symlink inventory input")
    return selected


def same_bytes(actual, expected):
    return all(actual.get(key) == expected.get(key) for key in ("bytes", "sha256"))


def compiled_source_identity(profile, build):
    expected = set(builder.captured_source_paths(profile.get("plan9_derivation_kind"),
                                                 native_fixture=True))
    hashes, captures = profile.get("source_sha256"), profile.get("source_artifacts")
    need(isinstance(hashes, dict) and isinstance(captures, dict)
         and set(hashes) == set(captures) == expected, "complete canonical compiled source closure required")
    result = {}
    for name in sorted(expected):
        source = identity(checked_relative(ROOT, name))
        descriptor = captures[name]
        need(descriptor.get("path") == "sources/" + name, "captured source path mismatch")
        captured = identity(checked_relative(Path(build), descriptor["path"]))
        need(source["sha256"] == hashes[name] and same_bytes(source, captured)
             and same_bytes(captured, descriptor), "compiled source capture drift: " + name)
        result[name] = source
    return result


def pinned_seed(seed, requested_sha256):
    seed = Path(seed).absolute()
    need(seed.is_dir() and not seed.is_symlink()
         and re.fullmatch(r"[0-9a-f]{64}", requested_sha256) is not None, "explicit preserved seed pin required")
    path = seed / "head.json"
    need(path.is_file() and not path.is_symlink(), "regular seed head required")
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == requested_sha256, "requested seed head changed")
    head = json.loads(raw)
    need(isinstance(head, dict) and all(isinstance(head.get(name), dict) for name in ("disk", "namespace")),
         "pinned disk and namespace head required")
    return dict(identity=dict(path=str(path.resolve()), bytes=len(raw), sha256=requested_sha256),
                raw_hex=raw.hex(), head=head)


def fork_pinned_seed(forker, seed, state, pin):
    seed, state = Path(seed).absolute(), Path(state).absolute()
    requested = pin["identity"]["sha256"]
    need(pinned_seed(seed, requested) == pin, "seed changed between preflight and fork")
    result = forker.fork(seed, state)
    need(result.get("ok") is True and result.get("source_head_changed_during_copy") is False,
         "verified unchanged pinned fork required")
    need((state / "source-head.json").read_bytes().hex() == pin["raw_hex"],
         "fork selected a different source head")
    selected = result.get("selected_head")
    need(isinstance(selected, dict), "fork selected head missing")
    expected = copy.deepcopy(pin["head"])
    for name, directory, suffix in (("disk", "disk-generations", ".ext4"),
                                     ("namespace", "namespace-generations", ".raw")):
        value = selected.get(name, {})
        original = pin["head"][name]
        destination = state / directory / (original["sha256"] + suffix)
        need(same_bytes(value, original) and value.get("path") == str(destination),
             "fork selected a different pinned " + name)
        expected[name] = dict(original, path=str(destination))
    expected["fork_origin"] = dict(source=str(seed.resolve()), head_sha256=requested)
    need(selected == expected and common.document(state / "head.json") == selected,
         "fork body or original head identity differs from pin")
    need(pinned_seed(seed, requested) == pin, "seed changed while forking pinned state")
    return result


def native_image_envelope(artifacts):
    kernel = Path(artifacts["inputs/native-fixture.kernel"]).read_bytes()
    aux = Path(artifacts["inputs/native-fixture.aux"]).read_bytes()
    need(0 < len(kernel) <= CONTRACT["kernel_max_bytes"] and aux == auxiliary_image(),
         "admitted native image/aux envelope differs")
    expected = bytearray(CONTRACT["memory_bytes"])
    kernel_offset = CONTRACT["entry"] - CONTRACT["ram_ipa"]
    aux_offset = CONTRACT["x0"] - CONTRACT["ram_ipa"]
    expected[kernel_offset:kernel_offset + len(kernel)] = kernel
    expected[aux_offset:aux_offset + len(aux)] = aux
    return bytes(expected)


def check_native_image(domain, expected, record, phase, holder):
    need(len(expected) == CONTRACT["memory_bytes"], "exact native image envelope required")
    raw = ram_read(domain, CONTRACT["private_ram_pa"], len(expected))
    heartbeat_offset = CONTRACT["heartbeat_ipa"] - CONTRACT["ram_ipa"]
    need(raw == expected and raw[heartbeat_offset:heartbeat_offset + 64] == bytes(64),
         "native clean image/zero RAM/heartbeat reset not observed before bind")
    proof = dict(phase=phase, dom=holder, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                 exact_image_and_zero_rest=True, heartbeat_zero=True)
    record.setdefault("native_image_checks", []).append(proof)
    return proof


def elf_magic(path):
    with Path(path).open("rb") as stream:
        return stream.read(4)


def retained_files(root):
    result = {}
    for path in Path(root).rglob("*"):
        need(not path.is_symlink(), "symlink in retained execution closure")
        if path.is_file():
            result[str(path.relative_to(root))] = identity(path)
        else:
            need(path.is_dir(), "nonregular retained execution input")
    return result


def trusted_runtime_tools(manifest):
    """Select host inspection tools from canonical paths, never manifest argv."""
    engine = identity(Path("/usr/bin/qemu-system-aarch64").resolve(strict=True))
    ldd = identity(Path("/usr/bin/ldd").resolve(strict=True))
    selected = manifest.get("tools", {}).get("qemu-system-aarch64", {}).get("selected", {})
    inspector = manifest.get("external_host_dependencies", {}).get("ldd", {})
    need(selected.get("path") == engine["path"] and same_bytes(selected, engine),
         "canonical /usr/bin/qemu-system-aarch64 identity required")
    need(inspector.get("path") == ldd["path"] and same_bytes(inspector, ldd),
         "canonical /usr/bin/ldd identity required before dependency inspection")
    return dict(engine=engine, ldd=ldd)


def runtime_identity(runtime, build):
    """Validate actual captured code/build/ELF/resource closure, including omissions."""
    runtime, build = Path(runtime).absolute(), Path(build).absolute()
    manifest = common.document(runtime / "runtime.json")
    need(manifest.get("schema") == freezer.SCHEMA and manifest.get("passed") is True
         and manifest.get("sources_build_tools_unchanged") is True
         and manifest.get("self_check", {}).get("exit_status") == 0,
         "successful immutable unified runtime required")
    trusted_tools = trusted_runtime_tools(manifest)
    inventory = manifest.get("inventory")
    need(isinstance(inventory, dict) and inventory, "complete runtime inventory required")
    actual = retained_files(runtime)
    actual.pop("runtime.json", None)
    need(set(actual) == set(inventory), "retained files and complete runtime inventory differ")
    for name, expected in inventory.items():
        checked_relative(runtime, name)
        need(same_bytes(actual[name], expected), "runtime inventory drift: " + name)
    def captured_pair(row, relative, original=None):
        need(isinstance(row, dict) and isinstance(row.get("original"), dict)
             and isinstance(row.get("frozen"), dict), "captured original/frozen identity pair required")
        path = checked_relative(runtime, relative)
        need(relative in actual and row["frozen"].get("path") == str(path)
             and same_bytes(actual[relative], row["frozen"])
             and same_bytes(row["original"], row["frozen"]), "captured runtime identity pair differs: " + relative)
        if original is not None:
            expected = identity(Path(original).resolve(strict=True))
            need(same_bytes(expected, row["original"]), "captured original changed: " + relative)
        return path
    sources = manifest.get("sources")
    need(isinstance(sources, dict) and set(sources) == set(freezer.RUNTIME_FILES),
         "canonical complete frozen runtime source closure required")
    for name in freezer.RUNTIME_FILES:
        captured_pair(sources[name], "runtime/" + name, checked_relative(ROOT, name))
    for key, relative, source in (
            ("implementation", "evidence/freeze-runtime.py", "scripts/freeze_okernel_unified_runtime.py"),
            ("repro_helpers", "evidence/repro-helpers.py", "scripts/verify_okernel_two_domains_repro.py"),
            ("tool_freezer", "evidence/tool-freezer.py", "scripts/verify_okernel_unified_repro.py")):
        captured_pair(manifest.get(key), relative, ROOT / source)
    build_profile, admitted = repro.inspect_build(build)
    need(same_bytes(identity(build / "monitor-profile.json"), manifest.get("admitted_manifest", {})),
         "captured runtime admission differs from selected build")
    declared_inputs = manifest.get("build_inputs")
    need(isinstance(declared_inputs, dict) and set(declared_inputs) == set(admitted)
         and all(same_bytes(admitted[name], declared_inputs[name]) for name in admitted),
         "canonical complete runtime build inputs differ")
    originals = retained_files(build)
    copies = manifest.get("build_copies")
    need(isinstance(copies, dict) and set(copies) == set(originals), "complete captured build tree required")
    need({name[6:] for name in actual if name.startswith("build/")} == set(originals),
         "retained runtime build tree differs from selected build")
    for name in originals:
        captured_pair(copies[name], "build/" + name, build / name)
    for name, expected in admitted.items():
        need(same_bytes(actual.get("build/" + name, {}), expected), "runtime build artifact/source omitted: " + name)
    external = manifest.get("external_host_dependencies")
    need(isinstance(external, dict) and set(external) == {"python", "bash", "shell", "tmux", "ldd"},
         "complete actual external host tool identities required")
    for expected in external.values():
        need(same_bytes(identity(Path(expected["path"]).resolve(strict=True)), expected), "runtime external tool drift")
    interpreters = manifest.get("host_elf_interpreters")
    need(isinstance(interpreters, dict) and interpreters, "actual host ELF interpreter identities required")
    for name, expected in interpreters.items():
        need(same_bytes(identity(Path(name).resolve(strict=True)), expected), "host ELF interpreter drift")
    interpreter_paths = {Path(name).resolve(strict=True) for name in interpreters}
    tools = manifest.get("tools")
    need(isinstance(tools, dict) and set(tools) == {"qemu-system-aarch64"}, "actual frozen QEMU engine record required")
    qemu = tools["qemu-system-aarch64"]
    engine = captured_pair(qemu.get("native"), "tools/native/qemu-system-aarch64",
                           trusted_tools["engine"]["path"])
    need(same_bytes(identity(engine), qemu["selected"]), "selected and frozen QEMU differ")
    need(same_bytes(actual.get("tools/bin/qemu-system-aarch64", {}), qemu.get("wrapper", {})),
         "captured QEMU wrapper differs")
    need((runtime / "okernel-unified").read_text() == freezer.ENTRY
         and {"okernel-unified", "host-bin/python3"} <= actual.keys(), "canonical runtime entry closure required")
    need(qemu.get("version_stdout", "").startswith("QEMU emulator version 8.2.2 (")
         and manifest.get("frozen_qemu_version_check", {}).get("exit_status") == 0
         and manifest["frozen_qemu_version_check"].get("stdout") == qemu["version_stdout"],
         "actual captured QEMU version check missing")
    search = manifest.get("qemu_resource_search", {})
    need(search.get("module_directory") == "tools/modules" and search.get("data_directory") == "tools/data",
         "captured QEMU resource search differs")
    dependency_paths = set()
    resolutions = {}
    def elf_resolution(path, dependencies, label, original_path):
        need(elf_magic(path) == b"\x7fELF", "captured native engine/module is not ELF")
        need(isinstance(dependencies, list) and (dependencies or label.startswith("module:")),
             "actual frozen ELF dependencies missing: " + label)
        # Discover the admitted original graph with the independently selected
        # canonical inspector before trusting any dependency source paths.
        original_check = subprocess.run(
            [trusted_tools["ldd"]["path"], str(original_path)],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            capture_output=True, text=True, timeout=30)
        need(original_check.returncode == 0 and "not found" not in original_check.stdout,
             "canonical original ELF dependency resolution failed")
        originals = {Path(match).resolve(strict=True) for match in
                     re.findall(r"(?:=>\s+)?(/\S+)\s+\(0x", original_check.stdout)}
        declared_originals = {Path(item.get("original", {}).get("path", "")) for item in dependencies}
        need(declared_originals == originals
             and (originals or original_check.stdout.strip() == "statically linked"),
             "captured dependency original paths differ from canonical ELF graph: " + label)
        declared = set()
        for item in dependencies:
            frozen = Path(item.get("frozen", {}).get("path", ""))
            need(frozen.parent == runtime / "tools/lib", "ELF dependency escaped captured library directory")
            relative = str(frozen.relative_to(runtime))
            captured_pair(item, relative, Path(item["original"]["path"]))
            need(elf_magic(frozen) == b"\x7fELF", "captured dependency is not ELF")
            declared.add(frozen.resolve(strict=True))
            dependency_paths.add(relative)
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LD_LIBRARY_PATH": str(runtime / "tools/lib")}
        need(identity(Path(trusted_tools["ldd"]["path"])) == trusted_tools["ldd"],
             "canonical dependency inspector changed")
        argv = [trusted_tools["ldd"]["path"], str(path)]
        check = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
        need(check.returncode == 0 and "not found" not in check.stdout, "actual frozen ELF dependency resolution failed")
        resolved = {Path(match).resolve(strict=True) for match in
                    re.findall(r"(?:=>\s+)?(/\S+)\s+\(0x", check.stdout)}
        need((resolved or (not declared and check.stdout.strip() == "statically linked"))
             and resolved <= declared | interpreter_paths
             and declared - resolved <= {p for p in declared if any(
                 same_bytes(identity(p), item) for item in interpreters.values())},
             "actual ELF resolution escaped or omitted captured dependencies: " + label)
        resolutions[label] = dict(originals=[identity(path) for path in sorted(originals)],
                                  frozen_resolution=[identity(path) for path in sorted(resolved)])
    elf_resolution(engine, qemu.get("dependencies"), "engine",
                   Path(trusted_tools["engine"]["path"]))
    # Match the same installed module/data catalogs that the canonical freezer
    # captures on this qualified x86-64 QEMU host, including omitted records.
    module_root = Path("/usr/lib/x86_64-linux-gnu/qemu")
    data_root = Path("/usr/share/qemu")
    module_names = {path.name for path in module_root.iterdir() if path.is_file()}
    modules = manifest.get("qemu_modules")
    need(isinstance(modules, dict) and modules and set(modules) == module_names
         and all(name.endswith(".so") for name in modules), "complete installed QEMU module catalog required")
    for name, row in modules.items():
        module = captured_pair(row.get("module"), "tools/modules/" + name, module_root / name)
        elf_resolution(module, row.get("dependencies"), "module:" + name, module_root / name)
    need({name for name in actual if name.startswith("tools/lib/")} == dependency_paths,
         "captured library files and dependency graph differ")
    data_names = {str(path.relative_to(data_root)) for path in data_root.rglob("*") if path.is_file()}
    data = manifest.get("qemu_data")
    need(isinstance(data, dict) and data and set(data) == data_names,
         "complete installed QEMU resource catalog required")
    for name, row in data.items():
        need(row.get("requested_source") == str(data_root / name), "QEMU resource source path mismatch")
        captured_pair(row, "tools/data/" + name, data_root / name)
    need({name[14:] for name in actual if name.startswith("tools/modules/")} == set(modules)
         and {name[11:] for name in actual if name.startswith("tools/data/")} == set(data),
         "retained QEMU modules/resources differ from capture")
    return dict(manifest=identity(runtime / "runtime.json"),
                qemu_wrapper=identity(runtime / "tools/bin/qemu-system-aarch64"),
                qemu_binary=identity(engine), inventory=inventory, external=external,
                actual_elf_resolution=resolutions, complete_build_inputs=declared_inputs,
                canonical_runtime_sources=list(freezer.RUNTIME_FILES), trusted_host_tools=trusted_tools)


def preflight(seed, seed_sha256, build, runtime, release, runner):
    seed, build = Path(seed).absolute(), Path(build).absolute()
    need(seed.is_dir() and not seed.is_symlink(), "preserved seed directory required")
    need(re.fullmatch(r"[0-9a-f]{64}", seed_sha256) is not None
         and digest(seed / "head.json") == seed_sha256, "explicit seed head identity mismatch")
    revision = command(["git", "rev-parse", "HEAD"])
    status = command(["git", "status", "--porcelain"])
    need(revision["returncode"] == status["returncode"] == 0
         and not status["stdout"].strip(), "clean source checkout required before dispatch")
    revision = revision["stdout"].strip()
    need(revision == release and re.fullmatch(r"[0-9a-f]{40}", release) is not None,
         "source/MCP release mismatch")
    profile = common.document(build / "monitor-profile.json")
    runner.validate_profile(profile)
    need(profile.get("o10_qualification") is True and profile.get("domain_capacity") == 8
         and profile.get("native_fixture") == CONTRACT and profile.get("plan9_command_provider")
         and profile.get("plan9_recovery") and profile.get("linux_recovery", {}).get("namespace_version") == "9P2000.u",
         "exact eight-domain qualification/native-fixture/recovery profile required")
    artifacts = {}
    for name, expected in profile["artifacts"].items():
        path = checked_relative(build, expected["path"])
        actual = identity(path)
        need(actual["bytes"] == expected["bytes"] and actual["sha256"] == expected["sha256"],
             "compiled artifact drift: " + name)
        artifacts[name] = path
    runner.validate_linux_recovery_inputs(artifacts)
    runner.validate_recovery_inputs(artifacts)
    need(artifacts["inputs/native-fixture.aux"].read_bytes() == auxiliary_image(),
         "native immutable aux contract differs")
    need(0 < artifacts["inputs/native-fixture.kernel"].stat().st_size <= CONTRACT["kernel_max_bytes"],
         "native kernel image escaped its fixed window")
    for name, expected in profile["source_sha256"].items():
        need(digest(ROOT / name) == expected, "compiled source drift: " + name)
    compiled_source_identity(profile, build)
    frozen = runtime_identity(runtime, build)
    qemu = str(Path(runtime).absolute() / "tools/bin/qemu-system-aarch64")
    version = command([qemu, "--version"])
    need(version["returncode"] == 0, "captured QEMU version unavailable")
    return revision, profile, artifacts, frozen, version


def ram_read(domain, address, count):
    """Read only; neither guest RAM nor the host write allowlist is extended."""
    need(type(address) is int and type(count) is int and count > 0
         and CONTRACT["private_ram_pa"] <= address
         and address + count <= CONTRACT["private_ram_pa"] + CONTRACT["memory_bytes"],
         "native observer escaped fixed private RAM")
    need(not getattr(domain, "o10_exchange_active", False)
         and not getattr(domain, "linux_restart_witness_pending", None),
         "auxiliary observation inside native operation")
    domain.stopped()
    try:
        first = os.pread(domain.ram, count, address - 0x40000000)
        second = os.pread(domain.ram, count, address - 0x40000000)
        need(len(first) == count and first == second, "stopped native RAM observation changed")
        return first
    finally:
        domain.qmp.execute("cont")


class Observers:
    def __init__(self, domain, record, *, clock=time.monotonic):
        self.domain, self.record, self.clock = domain, record, clock
        self.start = self.previous_poll = clock()
        record["observation_start_monotonic"] = self.start
        self.active = False
        self.current = {}
        self.native = None
        record["counters"], record["native_heartbeats"] = [], []

    def counter(self, label, path, invocation):
        value = common.Counter(self.domain, path)
        row = dict(label=label, path=path, invocation=invocation,
                   completion="active; provider completion unobserved")
        self.record["counters"].append(row)
        self.current[label] = (value, row)
        return row

    def unknown(self, label):
        if label in self.current:
            value, row = self.current.pop(label)
            row["completion"] = "unknown after a definite domain fault; never replayed"
            row["observations"] = counter_observation(value)
            return row

    def native_start(self, holder, reset_proof=None):
        need(isinstance(reset_proof, dict) and reset_proof.get("dom") == holder
             and reset_proof.get("exact_image_and_zero_rest") is True
             and reset_proof.get("heartbeat_zero") is True,
             "native observation requires an exact pre-bind reset/image proof")
        self.native = dict(dom=holder, reset_proof=reset_proof, last=None, samples=[])
        self.record["native_heartbeats"].append(self.native)

    def native_stop(self):
        self.native = None

    def poll(self, force=False):
        if (self.active or getattr(self.domain, "o10_exchange_active", False)
                or getattr(self.domain, "linux_restart_witness_pending", None)):
            return
        now = self.clock()
        need(now - self.start < WINDOW_SECONDS, "240s three-domain observation window exceeded")
        if not force and now - self.previous_poll < .2:
            return
        self.active = True
        try:
            if self.current:
                volume = self.domain.native_volume()
                observed = self.clock()
                for value, row in self.current.values():
                    try:
                        data = volume.get(value.path)
                    except FileNotFoundError:
                        data = b""
                    value.observe(data, observed)
                    row["observations"] = counter_observation(value)
            if self.native is not None:
                address = CONTRACT["private_ram_pa"] + CONTRACT["heartbeat_ipa"] - CONTRACT["ram_ipa"]
                raw = ram_read(self.domain, address, CONTRACT["heartbeat_bytes"])
                row = dict(host_seconds=self.clock() - self.start, raw_hex=raw.hex())
                self.native["samples"].append(row)
                if raw[:8] == bytes(8):
                    row["initializing"] = True
                else:
                    decoded = decode_heartbeat(raw)
                    row["decoded"] = decoded
                    need(decoded["error"] == 0 and decoded["stage"] != 4,
                         "native namespace fixture failed: " + decoded["error_name"])
                    if decoded["stable"]:
                        prior = self.native["last"]
                        need(prior is None or (decoded["seq"] >= prior["seq"] and decoded["reads"] >= prior["reads"]),
                             "native heartbeat regressed within one domain generation")
                        if decoded["reads"]:
                            need(decoded["stage"] == 3 and decoded["seq"] == 2 * decoded["reads"]
                                 and decoded["last_reply_type"] == 117
                                 and decoded["last_bytes"] == len(CORPUS),
                                 "native heartbeat lacks completed exact namespace reads")
                        self.native["last"] = decoded
            self.previous_poll = self.clock()
            need(self.previous_poll - self.start < WINDOW_SECONDS,
                 "240s three-domain observation window exceeded during poll")
        finally:
            self.active = False

    def finish(self, original_pump):
        # Freeze observations before source/runtime validation and VM cleanup.
        self.domain.pump = original_pump
        end = self.clock()
        elapsed = end - self.start
        self.record.update(observation_end_monotonic=end, observation_elapsed_seconds=elapsed)
        need(0 < elapsed <= WINDOW_SECONDS, "240s three-domain observation window ended outside its bound")
        return elapsed

    def values(self, labels):
        result = {}
        for label in labels:
            if label == "native":
                result[label] = 0 if self.native is None or self.native["last"] is None else self.native["last"]["reads"]
            else:
                need(label in self.current, "active counter unavailable: " + label)
                result[label] = len(self.current[label][0].entries)
        return result

    def progress(self, labels, *, baseline=None, minimum=1, timeout=30):
        self.poll(force=True)
        if baseline is None:
            baseline = self.values(labels)
        deadline = self.clock() + timeout
        while True:
            self.poll(force=True)
            current = self.values(labels)
            if all(current[label] >= baseline[label] + minimum for label in labels):
                return dict(baseline=baseline, after=current, host_seconds=self.clock() - self.start)
            need(self.clock() < deadline, "domain progress missing: " + ",".join(labels))
            self.domain.pump(.05)


def counter_observation(value):
    result = dict(path=value.path, start_monotonic=value.start,
                  bytes_hex=value.data.hex(), samples=list(value.entries),
                  timing_scope="host monotonic observation brackets include CPU/QMP pauses; not exact guest timestamps")
    if len(value.entries) >= 3:
        result.update(value.result())
    return result


def linux_counter_command(path):
    path = common.guest_path(path)
    need(path.startswith("/work/o10-m3-linux-"), "Linux counter escaped the declared baseline subtree")
    target = shlex.quote("/n/okernel" + path)
    return ("test ! -e " + target + " && { { i=0; while test \"$i\" -lt 280; do "
            "printf '%s\\n' \"$i\"; i=$((i+1)); sleep 1; done; } >> " + target + " & }")


def start_linux_counter(domain, observers, record, token):
    path = "/work/o10-m3-linux-" + token + "-" + secrets.token_hex(4)
    cmd = linux_counter_command(path)
    row = dict(command=cmd, phase="launch-pending", path=path, dom=domain.o10_linux,
               work_id=secrets.token_hex(16))
    observers.counter("linux", path, row)
    domain.command(cmd)
    row["phase"] = "launched-once"
    observers.progress(["linux"], baseline={"linux": 0}, minimum=3)
    return row


def start_plan9_counter(domain, observers, record, token, protocol):
    service = dict(domain.service)
    path = ("/services/plan9/g" + service["generation"] + "/s" + service["instance"]
            + "/m3-counter-" + token + "-" + secrets.token_hex(4))
    row = dict(phase="preparing-new-explicit-request", path=path, dom=domain.o10_plan9, service=service)
    record.setdefault("plan9_counter_invocations", []).append(row)
    observers.counter("plan9", path, row)
    invocation = common.publish_counter(domain, protocol, path, record=row)
    row["phase"] = "submitted-once"
    observers.progress(["plan9"], baseline={"plan9": 0}, minimum=3)
    return invocation


def states(domain, handles):
    result = {name: domain.o10_call("Tstat", dom=holder) for name, holder in handles.items()}
    need(all(common.live_domain(value) for value in result.values()), "all expected domains must be live")
    return result


def same_survivors(before, after):
    need(set(before) == set(after), "survivor set changed")
    for name in before:
        need(common.live_domain(after[name]) and before[name]["dom"] == after[name]["dom"]
             and before[name]["inst"] == after[name]["inst"], "survivor identity changed: " + name)


def shell_identity(domain):
    marker = "O10_M3_SHELL_" + secrets.token_hex(8)
    start = len(domain.capture)
    domain.command("printf '" + marker + " %s ' \"$$\"; awk '{print $22}' /proc/$$/stat")
    text = bytes(domain.capture[start:]).replace(b"\r", b"")
    matches = re.findall(rb"(?:^|\n)" + marker.encode() + rb" ([0-9]+) ([0-9]+)(?:\n|$)", text)
    need(len(matches) == 1, "one completed Linux shell PID/start-time witness required")
    return dict(pid=int(matches[0][0]), start_ticks=int(matches[0][1]))


def expect_stale(domain, o10, message, *, detail=None, **fields):
    try:
        domain.o10_call(message, **fields)
    except o10.O10Error as error:
        need(error.code == o10.O10_ESTALE and (detail is None or error.detail == detail),
             "old reference did not fail ESTALE: " + message)
        return dict(code=error.code, detail=error.detail)
    raise common.GateError("old reference unexpectedly succeeded: " + message)


def bind_native(domain, o10, holder, lease_generation, record):
    transport = holder & ~0xffffffff
    row = dict(dom=holder, previous_lease_generation=lease_generation)
    record.setdefault("native_bindings", []).append(row)
    try:
        reply = domain.o10_call("Tbind", lease=(lease_generation << 32) | 3, transport=transport)
    except o10.O10Error as error:
        need(error.code == o10.O10_ESTALE and lease_generation < error.detail <= 0xffffffff,
             "native lease refresh requires a newer generation from ESTALE")
        row["observed_stale"] = dict(code=error.code, detail=error.detail)
        lease_generation = error.detail
        # A new explicit request after a definite rejection; unknown mutations
        # never reach this branch and are never resubmitted.
        reply = domain.o10_call("Tbind", lease=(lease_generation << 32) | 3, transport=transport)
    need(reply["type"] == "Rbind" and reply["session"] != 0, "native binding failed")
    row.update(lease_generation=lease_generation, reply=reply)
    return lease_generation


def replay_applied(domain, record, row):
    need(row.get("completion") == "observed" and row.get("reply_hex"), "only known applied requests may be retransmitted")
    reply = domain.o10_exchange(bytes.fromhex(row["request_hex"]))
    repeated = record["o10_exchanges"][-1]
    need(repeated["reply_hex"] == row["reply_hex"], "journal retransmission changed reply bytes")
    record.setdefault("journal_replays", []).append(dict(request_hex=row["request_hex"],
                                                        reply_hex=repeated["reply_hex"]))
    return reply


def create_native(domain, record, expected_image):
    reply = domain.o10_call("Tcreate", kind=3, img_kernel=5, img_aux=6,
                            mem_bytes=CONTRACT["memory_bytes"], vcpus=1)
    row = record["o10_exchanges"][-1]
    holder = reply["dom"]
    need(0 <= (holder & 0xffffffff) < 8 and holder >> 32 > 0
         and (holder & 0xffffffff) not in (domain.o10_linux & 0xffffffff, domain.o10_plan9 & 0xffffffff),
         "new native handle overlaps an existing holder")
    need(domain.o10_call("Tstat", dom=holder)["state"] == 1, "Tcreate must leave native domain PROVISIONED")
    proof = check_native_image(domain, expected_image, record, "created-provisioned-unbound", holder)
    replay_applied(domain, record, row)
    return holder, proof


def start_native(domain, holder):
    state = domain.o10_call("Tstat", dom=holder)
    need(type(state.get("state")) is int and state["state"] == 1 and state.get("dom") == holder,
         "binding must preserve the exact native holder PROVISIONED before Tstart")
    return domain.o10_call("Tstart", dom=holder, inst=secrets.token_bytes(16))


def run_cycles(domain, observers, record, runner, token, expected_image):
    handles = dict(linux=domain.o10_linux, plan9=domain.o10_plan9)
    corpus_path = "/n/okernel/work/" + CONTRACT["corpus_name"]
    domain.command("printf '%s\\n' " + shlex.quote(CONTRACT["corpus_text"].rstrip("\n")) + " > " + shlex.quote(corpus_path))
    need(domain.native_volume().get("/work/" + CONTRACT["corpus_name"]) == CORPUS, "native corpus publication differs")
    native, reset_proof = create_native(domain, record, expected_image)
    lease = bind_native(domain, runner.o10, native, 1, record)
    start_native(domain, native)
    start_row = record["o10_exchanges"][-1]
    observers.native_start(native, reset_proof)
    handles["native"] = native
    start_linux_counter(domain, observers, record, token)
    plan9_request = start_plan9_counter(domain, observers, record, token, runner.protocol)
    observers.progress(["native"], baseline={"native": 0}, minimum=3)
    replay_applied(domain, record, start_row)
    record["initial_states"] = states(domain, handles)
    record["fault_cycles"] = []
    old_native_handles = []
    for target in ("linux", "plan9", "native"):
        record["phase"] = "fault-cycle-" + target
        before = states(domain, handles)
        others = {name: handles[name] for name in handles if name != target}
        before_survivors = {name: before[name] for name in others}
        service_before = dict(domain.service)
        shell_before = shell_identity(domain) if target != "linux" else None
        row = dict(target=target, before=before, service_before=service_before)
        record["fault_cycles"].append(row)
        if target in ("linux", "plan9"):
            row["interrupted_counter"] = observers.unknown(target)
        else:
            observers.native_stop()
            old_native_handles.append(native)
        row["fault"] = domain.o10_call("Tinject", dom=handles[target], fault=1)
        need(domain.o10_call("Tstat", dom=handles[target])["state"] == 4, "target fault was not definite")
        observers.poll(force=True)
        baseline = observers.values(list(others))
        row["survivor_progress_while_faulted"] = observers.progress(list(others), baseline=baseline)
        after_fault = states(domain, others)
        same_survivors(before_survivors, after_fault)
        row["survivors_while_faulted"] = after_fault
        if shell_before is not None:
            need(shell_identity(domain) == shell_before, "surviving Linux shell changed while another domain faulted")
        if target == "linux":
            domain.control_active = False
            try:
                domain.recover_linux()
            finally:
                domain.control_active = True
            handles["linux"] = domain.o10_linux
            need(handles["linux"] == before["linux"]["dom"] + (1 << 32), "Linux restore did not advance its generation")
            start_linux_counter(domain, observers, record, token)
        elif target == "plan9":
            unknown = dict(request_id=plan9_request["id"],
                           request_sha256=hashlib.sha256(plan9_request["request"]).hexdigest())
            row["unknown_service_outcome"] = unknown
            domain.recycle_plan9(None, {}, unknown=unknown)
            domain.control_active = True
            handles["plan9"] = domain.o10_plan9
            need(handles["plan9"] == before["plan9"]["dom"] + (1 << 32), "Plan9 restore did not advance its generation")
            plan9_request = start_plan9_counter(domain, observers, record, token, runner.protocol)
        else:
            reply = domain.o10_call("Trestore", dom=native, inst=secrets.token_bytes(16), img_kernel=5, img_aux=6)
            native = reply["dom"]
            need(native == handles["native"] + (1 << 32)
                 and domain.o10_call("Tstat", dom=native)["state"] == 3,
                 "native restore must wait for fresh binding under a new generation")
            reset_proof = check_native_image(domain, expected_image, record,
                                             "restored-blocked-unbound", native)
            lease = bind_native(domain, runner.o10, native, lease, record)
            handles["native"] = native
            observers.native_start(native, reset_proof)
            observers.progress(["native"], baseline={"native": 0}, minimum=3)
        restored = states(domain, handles)
        need(restored[target]["inst"] != before[target]["inst"], "restored target reused its instance ID")
        same_survivors(before_survivors, {name: restored[name] for name in others})
        if target != "plan9":
            need(domain.service == service_before, "surviving Plan9 provider identity changed")
        if shell_before is not None:
            need(shell_identity(domain) == shell_before, "surviving Linux shell changed during another domain restore")
        row["after"] = restored
        row["all_three_progress_after_restore"] = observers.progress(list(handles))
    record["phase"] = "destroy-and-reuse-native-slot"
    before_destroy = states(domain, handles)
    observers.native_stop()
    old_native_handles.append(native)
    record["native_destroy"] = domain.o10_call("Tdestroy", dom=native)
    raw = ram_read(domain, CONTRACT["private_ram_pa"], CONTRACT["memory_bytes"])
    need(raw == bytes(CONTRACT["memory_bytes"]), "Tdestroy left native private RAM uncleared")
    record["destroyed_ram"] = dict(address=CONTRACT["private_ram_pa"], bytes=len(raw),
                                   sha256=hashlib.sha256(raw).hexdigest(), all_zero=True)
    destroyed = native
    native, reset_proof = create_native(domain, record, expected_image)
    need((native & 0xffffffff) == (destroyed & 0xffffffff) and native >> 32 > destroyed >> 32,
         "Tcreate did not reuse the destroyed slot under a higher generation")
    lease = bind_native(domain, runner.o10, native, lease, record)
    start_native(domain, native)
    observers.native_start(native, reset_proof)
    handles["native"] = native
    observers.progress(["native"], baseline={"native": 0}, minimum=3)
    record["phase"] = "stale-reference-corpus"
    record["stale_references"] = []
    for old in old_native_handles:
        for message, fields in (
                ("Tstat", {}), ("Tstart", dict(inst=secrets.token_bytes(16))),
                ("Twithdraw", dict(mode=0, deadline_ms=0)),
                ("Trestore", dict(inst=secrets.token_bytes(16), img_kernel=5, img_aux=6)), ("Tdestroy", {})):
            record["stale_references"].append(dict(message=message, dom=old,
                error=expect_stale(domain, runner.o10, message, dom=old, detail=native >> 32, **fields)))
    record["stale_references"].append(dict(message="Tbind", kind="old-lease",
        error=expect_stale(domain, runner.o10, "Tbind", detail=lease,
                           lease=((lease-1) << 32) | 3, transport=native & ~0xffffffff)))
    record["stale_references"].append(dict(message="Tbind", kind="old-transport",
        error=expect_stale(domain, runner.o10, "Tbind", detail=native >> 32,
                           lease=(lease << 32) | 3, transport=destroyed & ~0xffffffff)))
    final = states(domain, handles)
    same_survivors({name: before_destroy[name] for name in ("linux", "plan9")},
                   {name: final[name] for name in ("linux", "plan9")})
    record["final_progress"] = observers.progress(list(handles))
    record["final_states"] = states(domain, handles)
    record["native_slot"] = native & 0xffffffff
    record["final_native_lease_generation"] = lease


def verify(*, execute, seed, seed_head_sha256, build, runtime, output, mcp_release, timeout=180):
    need(execute is True, "--execute is required before any fork or VM dispatch")
    need(timeout == 180, "fixed180s bootstrap/recovery bound required")
    output = Path(output).absolute()
    need(not any(output.is_relative_to(Path(path).absolute()) for path in (ROOT, seed, build, runtime)),
         "evidence output must be outside source, seed, build and runtime")
    need(not output.exists() and not output.is_symlink(), "new private evidence directory required")
    output.mkdir(parents=True)
    record = dict(schema="ostadix.o10-three-domains-gate/v1", milestone="M3", gate_id="verify_o10_three_domains",
                  gate_passed=False, milestone_qualified=False, skips=[], scope=SCOPE,
                  started_unix=time.time(), mcp_release=mcp_release,
                  mcp_release_scope="caller-declared equality to clean HEAD; actual MCP executable/stamp requires external aligned launcher/binder",
                  observation_window_seconds=WINDOW_SECONDS,
                  unknown_work_policy="Faulted counter completion remains unknown; each requested new counter has a fresh path/request ID",
                  timing_scope="240s host monotonic observation window after ready, including host/QMP pauses")
    domain = None
    original_pump = None
    try:
        record["phase"] = "preflight"
        runner, forker, _ = common.load_runtime()
        seed_pin = pinned_seed(seed, seed_head_sha256)
        revision, profile, artifacts, frozen, version = preflight(seed, seed_head_sha256, build, runtime, mcp_release, runner)
        names = set(profile["source_sha256"]) | {
            "scripts/verify_o10_three_domains.py", "tests/test_o10_three_domains.py", "scripts/o-kernel.sh",
            "scripts/verify_o10_linux_restart.py", "scripts/okernel_unified_world.py", "scripts/o10.py",
            "scripts/o10_native_fixture.py", "scripts/fork_okernel_state.py", "scripts/verify_okernel_unified_provider.py",
            "scripts/freeze_okernel_unified_runtime.py", "scripts/verify_okernel_two_domains_repro.py",
            "scripts/verify_okernel_unified_repro.py",
            "ocore/guest/plan9/unified/protocol.py", "ocore/guest/plan9/unified/p9cmdsrv.c"}
        record.update(source_revision=revision, build=identity(Path(build) / "monitor-profile.json"),
                      runtime=frozen, native_fixture_contract=dict(CONTRACT), qemu_version=version,
                      host=dict(uname=list(os.uname()), python=sys.version, python_binary=identity(Path(sys.executable).resolve())),
                      artifacts={name: identity(path) for name, path in artifacts.items()},
                      source_sha256={name: digest(ROOT / name) for name in sorted(names)},
                      seed_requested_sha256=seed_head_sha256, seed_pin=seed_pin,
                      seed_head_before=seed_pin["identity"], source_artifacts={})
        for name, expected in record["source_sha256"].items():
            path = output / "sources" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
            need(digest(path) == expected, "source changed during gate capture")
            record["source_artifacts"][name] = identity(path)
        record["phase"] = "private-seed-fork"
        state = output / "state"
        record["fork"] = fork_pinned_seed(forker, seed, state, seed_pin)
        qemu = str(Path(runtime).absolute() / "tools/bin/qemu-system-aarch64")
        domain = runner.UnifiedDomain(state, Path(build).absolute(), qemu, timeout=timeout)
        record["guest_session"] = str(domain.session)
        record["qemu_argv"] = [part.decode() for part in
                               (Path("/proc") / str(domain.process.pid) / "cmdline").read_bytes().split(b"\0") if part]
        common.trace(domain, output, record, runner.o10)
        record["phase"] = "boot-and-claim"
        domain.ready()
        domain.o10_claim()
        domain.control_active = True
        observers = Observers(domain, record)
        original_pump = domain.pump
        def pump(duration=.1):
            original_pump(duration)
            observers.poll()
        domain.pump = pump
        record["phase"] = "initial-three-domain-progress"
        run_cycles(domain, observers, record, runner, secrets.token_hex(12),
                   native_image_envelope(artifacts))
        observers.finish(original_pump)
        record["runner_linux_recoveries"] = safe(domain.record.get("linux_recoveries", []))
        record["runner_plan9_recoveries"] = safe(domain.record.get("provider_recoveries", []))
        need(record["source_sha256"] == {name: digest(ROOT / name) for name in names}, "gate/build source drift")
        need(pinned_seed(seed, seed_head_sha256) == seed_pin, "preserved pinned source seed changed")
        need(runtime_identity(runtime, build) == frozen, "frozen execution closure changed during gate")
        status = command(["git", "status", "--porcelain"])
        need(status["returncode"] == 0 and not status["stdout"].strip(), "source checkout became dirty during gate")
        record.update(gate_passed=True, source_unchanged=True, phase="complete")
    except BaseException as error:
        record["error"] = type(error).__name__ + ": " + str(error)
        record["traceback"] = traceback.format_exc()
    finally:
        if domain is not None:
            if original_pump is not None:
                domain.pump = original_pump
            pending = getattr(domain, "o10_pending", None)
            record["pending_mechanism"] = safe(pending)
            if pending is not None:
                record["pending_mechanism"].update(completion="unknown; never resubmitted",
                    frame_sha256=hashlib.sha256(pending["frame"]).hexdigest())
            record["runner_record"] = safe(domain.record)
            try:
                domain.close()
                record["cleanup"] = dict(closed=True, qemu_exit_code=domain.process.returncode,
                                         process_reaped=domain.process.poll() is not None)
            except BaseException as error:
                record.update(gate_passed=False, cleanup_error=type(error).__name__ + ": " + str(error))
        record["finished_unix"] = time.time()
        (output / "result.json").write_text(json.dumps(safe(record), indent=2) + "\n")
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="explicitly authorize the new private fork and QEMU run")
    for name in ("seed-state", "build", "runtime", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--seed-head-sha256", required=True)
    parser.add_argument("--mcp-release", required=True,
                        help="caller-declared clean revision; aligned launcher/binder proves the running MCP identity")
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error("--execute is required before any fork or VM dispatch")
    result = verify(execute=True, seed=args.seed_state, seed_head_sha256=args.seed_head_sha256,
                    build=args.build, runtime=args.runtime, output=args.output, mcp_release=args.mcp_release)
    print(json.dumps(dict(gate_passed=result["gate_passed"], milestone_qualified=False,
                         result=str(args.output / "result.json"))))
    return 0 if result["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
