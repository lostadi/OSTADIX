#!/usr/bin/env python3
"""Build and execute the native RV64 supervisor bootstrap, with bound evidence.

No Linux image, rootfs, host-language runtime, Cargo build, or global install is
used. The executable core is compiled from .oc; privileged entry is assembly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MARKERS = (
    "RV64 bootstrap O-core supervisor: PASS",
    "RV64 bootstrap stack and DTB: PASS",
    "RV64 bootstrap integer FS-off trap: PASS",
    "RV64 bootstrap integer and FP64 trap: PASS",
    "RV64 bootstrap private TLS round-trip: PASS",
    "RV64 bootstrap supervisor timer: PASS",
    "RV64 bootstrap asynchronous FP and TLS: PASS",
    "RV64 native bootstrap gate: PASS",
)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def select_tool(value: str | None, candidates: list[Path], command: str) -> Path:
    if value:
        selected = Path(value).expanduser()
        if not selected.is_file():
            found = shutil.which(value)
            if found:
                selected = Path(found)
        if not selected.is_file():
            raise RuntimeError(f"required tool does not exist: {value}")
        return selected.absolute()
    for path in candidates:
        if path.is_file():
            return path.absolute()
    found = shutil.which(command)
    if found:
        return Path(found).absolute()
    raise RuntimeError(f"missing {command}; pass its explicit path (see ocore/boot/riscv64/ABI.md)")


def command(argv: list[str], build: Path, name: str, timeout: float = 60) -> dict:
    try:
        completed = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=timeout)
        stdout, stderr = completed.stdout, completed.stderr
        result = {"argv": argv, "returncode": completed.returncode, "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or b"", exc.stderr or b""
        result = {"argv": argv, "returncode": None, "timed_out": True}
    for kind, data in (("stdout", stdout), ("stderr", stderr)):
        path = build / f"{name}.{kind}"
        path.write_bytes(data)
        result[kind] = {"path": str(path), "sha256": digest(path)}
    return result


def require_command(result: dict) -> None:
    if result["timed_out"] or result["returncode"] != 0:
        output = Path(result["stdout"]["path"]).read_text(errors="replace")
        errors = Path(result["stderr"]["path"]).read_text(errors="replace")
        raise RuntimeError(f"command failed: {result['argv']}\n{output}{errors}")


def elf_inventory(path: Path) -> dict:
    data = path.read_bytes()
    if data[:7] != b"\x7fELF\x02\x01\x01" or len(data) < 64:
        raise RuntimeError("image is not a little-endian ELF64 executable")
    fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    kind, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, _ = fields
    if kind != 2 or machine != 243 or entry != 0x80200000:
        raise RuntimeError("image does not implement the declared RV64 S-mode entry ABI")
    if phentsize != 56 or shentsize != 64:
        raise RuntimeError("unexpected ELF table dimensions")
    segments = []
    for index in range(phnum):
        values = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize)
        ptype, flags, offset, vaddr, paddr, filesz, memsz, align = values
        if ptype in (2, 3):
            raise RuntimeError("native bootstrap cannot contain PT_DYNAMIC or PT_INTERP")
        if ptype == 1:
            if not (0x80200000 <= paddr <= paddr + memsz <= 0x88000000):
                raise RuntimeError("load segment is outside the declared QEMU 128 MiB RAM profile")
            if offset + filesz > len(data) or filesz > memsz:
                raise RuntimeError("invalid ELF load extent")
            segments.append({"flags": flags, "physical_address": paddr, "file_size": filesz,
                             "memory_size": memsz, "alignment": align, "virtual_address": vaddr})
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    definitions = set()
    undefined = set()
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = data[strings[4]:strings[4] + strings[5]]
        if section[9] != 24:
            raise RuntimeError("unexpected ELF symbol dimension")
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, shndx, _, _ = struct.unpack_from("<IBBHQQ", data, offset)
            end = names.find(b"\0", name)
            spelling = names[name:end].decode("ascii")
            if shndx == 0 and spelling:
                undefined.add(spelling)
            if shndx != 0 and info & 15 == 2:
                definitions.add(spelling)
    if undefined or not {"rv_boot_main", "rv_boot_trap", "rv_trap_entry"} <= definitions:
        raise RuntimeError(f"native image has missing compiled entry/trap code or undefined symbols: {sorted(undefined)}")
    return {"machine": "EM_RISCV", "entry": entry, "load_segments": segments,
            "defined_functions": sorted(definitions), "undefined_symbols": sorted(undefined)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", default=os.environ.get("OCOREC_BIN"))
    parser.add_argument("--clang", default=os.environ.get("CLANG"))
    parser.add_argument("--linker", default=os.environ.get("LD_LLD"))
    parser.add_argument("--qemu", default=os.environ.get("QEMU_RISCV64_BIN"))
    parser.add_argument("--opensbi", default=os.environ.get("OPENSBI_BIN"))
    parser.add_argument("--build-dir", type=Path, default=ROOT / "target/ocore-riscv64-boot")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--skip-negative-controls", action="store_true",
                        help="omit corruption-detection tests; receipt explicitly records the omission")
    args = parser.parse_args()
    build = args.build_dir.expanduser().resolve()
    build.mkdir(parents=True, exist_ok=True)
    receipt_path = build / "receipt.json"
    receipt = {"schema": "ocore-riscv64-native-bootstrap-v1", "status": "running",
               "scope": "single-hart bare-address S-mode architectural bootstrap, not full userspace/runtime admission",
               "profile": {"machine": "QEMU virt", "isa": "RV64GC", "abi": "LP64",
                           "privilege": "S-mode", "firmware": "OpenSBI M-mode", "ram_mib": 128,
                           "harts": 1, "satp": "Bare", "linux_guest": False},
               "commands": [], "negative_controls": [], "sources": {}, "artifacts": {}}

    def save() -> None:
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

    save()
    try:
        if args.timeout <= 0:
            raise RuntimeError("timeout must be positive")
        scoped = sorted(Path("/tmp").glob("ostadix-riscv-tools-*/root"))
        ocorec = select_tool(args.ocorec, [ROOT / "target/debug/ocorec", ROOT / "target/release/ocorec"], "ocorec")
        clang = select_tool(args.clang, [], "clang")
        linker = select_tool(args.linker, [], "ld.lld")
        qemu = select_tool(args.qemu, [path / "usr/bin/qemu-system-riscv64" for path in scoped], "qemu-system-riscv64")
        bios_candidates = [Path("/usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin"),
                          Path("/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin")]
        bios_candidates += [path / "usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin" for path in scoped]
        firmware = select_tool(args.opensbi, bios_candidates, "opensbi-fw-dynamic")
        tools = {"ocorec": ocorec, "clang": clang, "linker": linker, "qemu": qemu, "opensbi": firmware}
        receipt["tools"] = {name: {"path": str(path), "resolved_path": str(path.resolve()), "sha256": digest(path)} for name, path in tools.items()}
        for name in ("ocorec", "clang", "linker", "qemu"):
            result = command([str(tools[name]), "--version"], build, f"tool-{name}")
            require_command(result)
            receipt["tools"][name]["version"] = Path(result["stdout"]["path"]).read_text().strip()
        receipt["scoped_packages"] = {str(package): digest(package)
                                      for root in scoped for package in sorted(root.parent.glob("*.deb"))}
        core = ROOT / "ocore/runtime/riscv64/bootstrap.oc"
        architecture = ROOT / "ocore/boot/riscv64/entry.S"
        layout = ROOT / "ocore/boot/riscv64/linker.ld"
        for path in (core, architecture, layout, ROOT / "ocore/boot/riscv64/ABI.md", Path(__file__).resolve()):
            receipt["sources"][str(path.relative_to(ROOT))] = digest(path)

        def checked(argv: list[str], label: str) -> None:
            result = command(argv, build, label)
            receipt["commands"].append(result)
            require_command(result)

        assembler = [str(clang), "--target=riscv64-unknown-none-elf", "-march=rv64gc", "-mabi=lp64", "-mno-relax", "-c"]
        core_asm, core_obj = build / "bootstrap.s", build / "bootstrap.o"
        checked([str(ocorec), "--check", str(core)], "parse")
        checked([str(ocorec), str(core), "--target", "riscv64-unknown-none", "--emit", "asm", "-o", str(core_asm)], "compile")
        checked(assembler + [str(core_asm), "-o", str(core_obj)], "assemble-core")

        def image(source: Path, label: str) -> Path:
            arch_obj, output = build / f"{label}-entry.o", build / f"{label}.elf"
            checked(assembler + [str(source), "-o", str(arch_obj)], f"assemble-{label}")
            checked([str(linker), "-m", "elf64lriscv", "--no-relax", "-T", str(layout),
                     str(arch_obj), str(core_obj), "-o", str(output)], f"link-{label}")
            for path in (source, arch_obj, output):
                receipt["artifacts"][str(path)] = digest(path)
            return output

        def boot(output: Path, label: str) -> tuple[dict, str]:
            result = command([str(qemu), "-M", "virt", "-cpu", "rv64", "-smp", "1", "-m", "128M",
                              "-nographic", "-monitor", "none", "-bios", str(firmware), "-kernel", str(output),
                              "-no-reboot"], build, label, args.timeout)
            receipt["commands"].append(result)
            text = Path(result["stdout"]["path"]).read_text(errors="replace")
            return result, text

        output = image(architecture, "bootstrap")
        receipt["elf"] = elf_inventory(output)
        result, transcript = boot(output, "boot")
        require_command(result)
        position = -1
        for marker in MARKERS:
            if transcript.count(marker) != 1:
                raise RuntimeError(f"expected exactly one compiled invariant marker: {marker}\n{transcript}")
            found = transcript.index(marker)
            if found <= position:
                raise RuntimeError("compiled invariant markers are out of execution order")
            position = found
        if "FAIL" in transcript:
            raise RuntimeError(f"native bootstrap reported failure:\n{transcript}")
        receipt["passed_invariants"] = list(MARKERS)
        receipt["firmware_banner"] = next((line.strip() for line in transcript.splitlines()
                                            if line.strip().startswith("OpenSBI v")), None)
        for marker in MARKERS:
            print(marker)

        original = architecture.read_text()
        controls = [
            ("missing-f17-restore", r"        fld f\n, (304 + \n * 8)(\base)",
             r"""        .if \n == 17
            fmv.d.x f17, zero
        .else
            fld f\n, (304 + \n * 8)(\base)
        .endif""", "0000000000000191"),
            ("missing-tp-restore", r"        ld x\n, (\n * 8)(\base)",
             r"""        .if \n == 4
            li tp, 0
        .else
            ld x\n, (\n * 8)(\base)
        .endif""", "0000000000000104"),
        ]
        receipt["negative_controls_omitted"] = args.skip_negative_controls
        if not args.skip_negative_controls:
            for label, before, after, code in controls:
                if original.count(before) != 1:
                    raise RuntimeError(f"negative control mutation does not identify exactly one restore operation: {label}")
                mutant = build / f"{label}.S"
                mutant.write_text(original.replace(before, after))
                mutant_image = image(mutant, label)
                result, text = boot(mutant_image, f"boot-{label}")
                expected = f"RV64 bootstrap FAIL code={code}"
                if result["timed_out"] or result["returncode"] not in (0, 1) or expected not in text or MARKERS[-1] in text:
                    raise RuntimeError(f"corruption detection failed for {label}:\n{text}")
                receipt["negative_controls"].append({"name": label, "result": "rejected", "expected_failure": expected,
                                                     "elf_sha256": digest(mutant_image), "execution": result})
                print(f"RV64 negative control {label}: rejected")
        for path in (core_asm, core_obj):
            receipt["artifacts"][str(path)] = digest(path)
        for name, path in tools.items():
            if digest(path) != receipt["tools"][name]["sha256"]:
                raise RuntimeError(f"tool changed during proof: {name}; rerun against one fixed executable")
        for source, sha in receipt["sources"].items():
            if digest(ROOT / source) != sha:
                raise RuntimeError(f"source changed during proof: {source}; rerun against one fixed source set")
        receipt["status"] = "pass"
        save()
        print(f"RV64 native bootstrap receipt: {receipt_path}")
        return 0
    except (OSError, RuntimeError, ValueError, struct.error) as exc:
        receipt["status"] = "fail"
        receipt["error"] = str(exc)
        save()
        print(str(exc), file=sys.stderr)
        print(f"RV64 failed bootstrap receipt: {receipt_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
