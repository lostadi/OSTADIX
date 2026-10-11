#!/usr/bin/env python3
"""Execute actual Rust frontend/O-core lowering on the native RV supervisor.

The unchanged seven-definition fixture is compiled to LLVM only. All tested
Rust machine code is subsequently emitted by O-core, and the oracle is .oc.
No Linux guest, Rust machine-code substitution, Cargo build, or full-runtime
completion claim is involved. Original source and the baseline gate are intact.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import struct
import sys

from check_ocore_riscv64_boot import (
    ROOT, MARKERS, command, digest, elf_inventory, require_command, select_tool,
)


RUST_RELEASE = "1.97.1"
RUST_COMMIT = "8bab26f4f68e0e26f0bb7960be334d5b520ea452"
LLVM_VERSION = "22.1.6"
RUST_TARGET = "riscv64imac-unknown-none-elf"
FUNCTIONS = {"rust_scalar_" + name for name in
             ("helper", "mix", "choose", "narrow", "loop", "u32", "many")}
RUST_FLAGS = ["--edition=2024", "--crate-type=lib", "--emit=llvm-ir",
              "--crate-name=ocore_import_scalar", "-C", "opt-level=1",
              "-C", "panic=abort", "-C", "overflow-checks=off",
              "-C", "relocation-model=static", "-C", "force-unwind-tables=no",
              "-C", "no-vectorize-loops", "-C", "no-vectorize-slp",
              "-C", "codegen-units=1", "-C", "debuginfo=0"]
BRIDGE_MARKER = "RV64 native Rust scalar bridge: PASS"
FAILURE = "RV64 native Rust scalar FAIL code=0000000000000401"


def expected_digest() -> tuple[str, int]:
    """Third independent oracle: arbitrary-precision Python with explicit bits.

    This calculates transcript bytes, not a machine-code implementation.
    Signed extension uses subtract-by-modulus rather than the .oc XOR formula.
    The 12-argument reference uses an indexed sum rather than the .oc expression.
    """
    mask = (1 << 64) - 1
    mask32 = (1 << 32) - 1
    state = 0x9e3779b97f4a7c15
    value = 0xcbf29ce484222325
    cases = 0

    def extend(bits: int, width: int) -> int:
        bits &= (1 << width) - 1
        return bits - (1 << width) if bits & (1 << (width - 1)) else bits

    def pair(a: int, b: int, shift: int) -> None:
        nonlocal value, cases
        helper = (17 * a + b) & mask
        mix_input = ((a + b) & mask) ^ ((a - b) & mask) ^ ((a * b) & mask)
        mix = ((17 * mix_input + b) ^ (a << (shift & 63)) ^ (a >> (shift & 63))) & mask
        signed_a = a - (1 << 64) if a >> 63 else a
        signed_b = b - (1 << 64) if b >> 63 else b
        choose = (a - b if signed_a < signed_b else a + b) & mask
        narrow = (extend(a, 8) + (a & 255) + extend(a >> 8, 16)
                  + ((a >> 24) & 65535) + extend(a >> 32, 32) + (a >> 32)) & mask
        loop = a
        for index in range(shift & 31):
            loop = (33 * loop + index) & mask
        input32, count32 = a & mask32, shift & 31
        unsigned32 = ((input32 * 0x9e3779b9 + 0xf1234567)
                      ^ (input32 >> count32) ^ (input32 << count32)) & mask32
        arguments = [a, b, a ^ 3, (b + 4) & mask, (a << 5) & mask, b >> 6,
                     (a + 7) & mask, (b * 8) & mask, a ^ 9, (b + 10) & mask,
                     (a - 11) & mask, b ^ 12]
        many = sum((index + 1) * argument for index, argument in enumerate(arguments)) & mask
        for actual in (helper, mix, choose, narrow, loop, unsigned32, many):
            value = ((value ^ actual) * 0x100000001b3) & mask
            cases += 1

    for index in range(4096):
        state = (state ^ (state << 13)) & mask
        state ^= state >> 7
        state = (state ^ (state << 17)) & mask
        pair(state, state ^ (state >> 31), index)
    edges = (0, 1, 127, 128, 255, 256, 32767, 32768, 65535,
             0xffffffff, 0x8000000000000000, 0xffffffffffffffff)
    shifts = (0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 0xffffffff)
    for index, edge in enumerate(edges):
        for shift_index, shift in enumerate(shifts):
            pair(edge, edges[(index + shift_index) % len(edges)], shift)
    return f"{value:016x}", cases


def corrupt_helper_object(original: Path, output: Path) -> dict:
    """Negative control only: replace helper entry with `addi a0,x0,0; ret`.

    Original LLVM, NativeModule, object, and Rust source remain unchanged. The
    altered object's exact byte range and both digests are recorded in evidence.
    """
    data = bytearray(original.read_bytes())
    if data[:7] != b"\x7fELF\x02\x01\x01" or len(data) < 64:
        raise RuntimeError("negative object is not ELF64 little endian")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if header[:2] != (1, 243) or header[10] != 64:
        raise RuntimeError("negative object is not RV64 ET_REL")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, header[5] + i * header[10])
                for i in range(header[11])]
    matches = []
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = data[strings[4]:strings[4] + strings[5]]
        if section[9] != 24:
            raise RuntimeError("unexpected native symbol table dimensions")
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, index, address, size = struct.unpack_from("<IBBHQQ", data, offset)
            if names[name:names.find(b"\0", name)] != b"rust_scalar_helper":
                continue
            if info & 15 != 2 or index == 0 or size < 8:
                raise RuntimeError("helper mutation target is not a defined function")
            code = sections[index]
            if code[1] != 1 or code[2] & 4 == 0 or address + 8 > code[5]:
                raise RuntimeError("helper mutation is outside executable object storage")
            matches.append(code[4] + address)
    if len(matches) != 1:
        raise RuntimeError("helper mutation must resolve exactly one original definition")
    offset = matches[0]
    before = bytes(data[offset:offset + 8])
    after = bytes.fromhex("1305000067800000")
    if before == after:
        raise RuntimeError("helper corruption did not change executable bytes")
    data[offset:offset + 8] = after
    output.write_bytes(data)
    return {"symbol": "rust_scalar_helper", "file_offset": offset,
            "original_bytes": before.hex(), "corrupted_bytes": after.hex(),
            "original_sha256": digest(original), "corrupted_sha256": digest(output)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ocorec", default=os.environ.get("OCOREC_BIN"))
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--llvm-library", type=Path)
    parser.add_argument("--clang", default=os.environ.get("CLANG"))
    parser.add_argument("--linker", default=os.environ.get("LD_LLD"))
    parser.add_argument("--qemu", default=os.environ.get("QEMU_RISCV64_BIN"))
    parser.add_argument("--opensbi", default=os.environ.get("OPENSBI_BIN"))
    parser.add_argument("--build-dir", type=Path, default=ROOT / "target/ocore-riscv64-rust-bridge")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    build = args.build_dir.expanduser().resolve()
    build.mkdir(parents=True, exist_ok=True)
    receipt_path = build / "receipt.json"
    receipt = {"schema": "ocore-rust-native-supervisor-bridge-v1", "status": "running",
               "scope": "seven original Rust scalar implementations on native RV64 OSTADIX supervisor bootstrap",
               "runtime_complete": False, "rust_std_complete": False, "rustc_native_runtime_complete": False,
               "native_platform_execution_verified": False, "linux_guest": False,
               "profile": {"rust_target": RUST_TARGET, "native_target": "riscv64-unknown-none",
                           "platform": "RV64GC QEMU virt/OpenSBI, S-mode, one hart, LP64, Bare"},
               "commands": [], "sources": {}, "artifacts": {}, "negative_controls": []}

    def save() -> None:
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

    save()
    try:
        if args.timeout <= 0:
            raise RuntimeError("timeout must be positive")
        scoped = sorted(Path("/tmp").glob("ostadix-riscv-tools-*/root"))
        ocorec = select_tool(args.ocorec, [ROOT / "target/debug/ocorec", ROOT / "target/release/ocorec"], "ocorec")
        rustc = select_tool(args.rustc, [], "rustc")
        clang = select_tool(args.clang, [], "clang")
        linker = select_tool(args.linker, [], "ld.lld")
        qemu = select_tool(args.qemu, [p / "usr/bin/qemu-system-riscv64" for p in scoped], "qemu-system-riscv64")
        firmware = select_tool(args.opensbi,
                              [Path("/usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin"),
                               Path("/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin")]
                              + [p / "usr/lib/riscv64-linux-gnu/opensbi/generic/fw_dynamic.bin" for p in scoped],
                              "opensbi-fw-dynamic")
        tools = {"ocorec": ocorec, "rustc_proxy": rustc, "clang_assembler": clang,
                 "linker": linker, "qemu": qemu, "opensbi": firmware}

        def checked(argv: list[str], label: str) -> dict:
            result = command(argv, build, label)
            receipt["commands"].append(result)
            require_command(result)
            return result

        result = checked([str(rustc), "-vV"], "rustc-version")
        version = Path(result["stdout"]["path"]).read_text()
        fields = dict(line.split(": ", 1) for line in version.splitlines() if ": " in line)
        if (fields.get("release"), fields.get("commit-hash"), fields.get("LLVM version")) != (RUST_RELEASE, RUST_COMMIT, LLVM_VERSION):
            raise RuntimeError(f"original frontend must be exact rustc {RUST_RELEASE}/{RUST_COMMIT} and LLVM {LLVM_VERSION}:\n{version}")
        result = checked([str(rustc), "--print", "sysroot"], "rustc-sysroot")
        sysroot = Path(result["stdout"]["path"]).read_text().strip()
        sysroot = Path(sysroot)
        core = list((sysroot / "lib/rustlib" / RUST_TARGET / "lib").glob("libcore-*.rlib"))
        if len(core) != 1:
            raise RuntimeError(f"exactly one installed libcore is required for {RUST_TARGET}")
        if args.llvm_library:
            library = args.llvm_library.expanduser().resolve()
        else:
            libraries = {p.resolve() for p in (sysroot / "lib").glob("libLLVM*.so*")
                         if p.is_file() and p.open("rb").read(4) == b"\x7fELF"}
            if len(libraries) != 1:
                raise RuntimeError("exactly one matching Rust LLVM parser ELF is required; pass --llvm-library")
            library = libraries.pop()
        tools["rustc_driver"] = sysroot / "bin/rustc"
        drivers = list((sysroot / "lib").glob("librustc_driver-*.so"))
        if len(drivers) != 1:
            raise RuntimeError("exactly one Rust compiler driver shared library is required")
        tools["rustc_driver_library"] = drivers[0]
        tools["llvm_parser_library"] = library
        tools["rust_core_frontend_dependency"] = core[0]
        receipt["tools"] = {name: {"path": str(path), "resolved_path": str(path.resolve()), "sha256": digest(path)}
                            for name, path in tools.items()}
        receipt["tools"]["rustc_driver"]["version"] = version
        for name in ("ocorec", "clang_assembler", "linker", "qemu"):
            result = checked([str(tools[name]), "--version"], f"tool-{name}")
            receipt["tools"][name]["version"] = Path(result["stdout"]["path"]).read_text().strip()
        fixture = ROOT / "tests/fixtures/ocore_import_scalar.rs"
        oracle = ROOT / "ocore/runtime/riscv64/rust_import_probe.oc"
        baseline = ROOT / "ocore/runtime/riscv64/bootstrap.oc"
        architecture = ROOT / "ocore/boot/riscv64/entry.S"
        layout = ROOT / "ocore/boot/riscv64/linker.ld"
        sources = [fixture, oracle, baseline, architecture, layout,
                   ROOT / "scripts/check_ocore_riscv64_boot.py", Path(__file__).resolve()]
        receipt["sources"] = {str(p.relative_to(ROOT)): digest(p) for p in sources}

        llvm, native, verified = build / "rust.ll", build / "rust.native.json", build / "rust.verified.json"
        checked([str(rustc), str(fixture), *RUST_FLAGS, "--target=" + RUST_TARGET, "-o", str(llvm)], "rust-llvm")
        text = llvm.read_text()
        definitions = set(re.findall(r"^define\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", text, re.MULTILINE))
        declarations = set(re.findall(r"^declare\b[^@\n]*@([A-Za-z_][A-Za-z0-9_.$]*)\(", text, re.MULTILINE))
        if definitions != FUNCTIONS or declarations:
            raise RuntimeError(f"unexpected complete Rust LLVM inventory: {sorted(definitions)}, declarations={sorted(declarations)}")
        importer = [str(ocorec), str(llvm), "--input-kind", "llvm-ir", "--target", "riscv64-unknown-none",
                    "--llvm-library", str(library), "--llvm-sha256", receipt["tools"]["llvm_parser_library"]["sha256"]]
        checked(importer + ["--emit", "mir", "-o", str(native)], "import-whole-unit")
        module = json.loads(native.read_text())
        if (len(module["functions"]) != 7 or module["globals"]
                or {f["name"] for f in module["functions"] if f["entry"] is not None} != FUNCTIONS
                or module["provenance"]["input_sha256"] != digest(llvm)
                or module["provenance"]["source_function_count"] != 7
                or module["provenance"]["source_global_count"] != 0):
            raise RuntimeError("whole-unit import inventory/provenance mismatch")
        if module["target"]["abi"] != "lp64" or module["target"]["pointer_bits"] != 64 or not module["target"]["little_endian"]:
            raise RuntimeError("Rust frontend has an incompatible native RV64 ABI")
        for label, field in (("triple", "target triple"), ("data_layout", "target datalayout")):
            original = re.search(r'^' + field + r' = "([^"\n]+)"$', text, re.MULTILINE)
            if original is None or module["target"][label] != original.group(1):
                raise RuntimeError("import did not preserve frontend target/layout")
        checked([str(ocorec), str(native), "--verify-native", "--receipt", str(verified)], "verify-native")
        evidence = json.loads(verified.read_text())
        if (evidence.get("format") != "ocore-native-verification-v1" or evidence.get("verifier") != "ocore-native-v1"
                or evidence.get("verified") is not True or evidence.get("module_sha256") != digest(native)):
            raise RuntimeError("verification receipt does not bind the actual imported module")
        receipt["import"] = {"functions": sorted(FUNCTIONS), "definition_count": 7, "declaration_count": 0,
                             "target": module["target"], "provenance": module["provenance"],
                             "verification_receipt_sha256": digest(verified)}
        assembler = [str(clang), "--target=riscv64-unknown-none-elf", "-march=rv64gc", "-mabi=lp64", "-mno-relax", "-c"]
        rust_asm, rust_obj = build / "rust.s", build / "rust.o"
        checked([str(ocorec), str(native), "--input-kind", "native-ir", "--target", "riscv64-unknown-none",
                 "--emit", "asm", "-o", str(rust_asm)], "own-rust-assembly")
        direct_asm = build / "rust-direct-llvm.s"
        checked(importer + ["--emit", "asm", "-o", str(direct_asm)], "repeat-original-llvm-lowering")
        if rust_asm.read_bytes() != direct_asm.read_bytes():
            raise RuntimeError("verified NativeModule and original LLVM emission differ")
        checked(assembler + [str(rust_asm), "-o", str(rust_obj)], "own-rust-object")
        repeated = build / "rust.repeated.o"
        checked(assembler + [str(direct_asm), "-o", str(repeated)], "repeat-own-rust-object")
        if rust_obj.read_bytes() != repeated.read_bytes():
            raise RuntimeError("Rust own-emission objects are not reproducible")
        receipt["import"]["reproducible"] = True

        def ocore_object(source: Path, label: str) -> Path:
            assembly, obj = build / f"{label}.s", build / f"{label}.o"
            checked([str(ocorec), "--check", str(source)], f"parse-{label}")
            checked([str(ocorec), str(source), "--target", "riscv64-unknown-none", "--emit", "asm", "-o", str(assembly)], f"compile-{label}")
            checked(assembler + [str(assembly), "-o", str(obj)], f"assemble-{label}")
            for p in (assembly, obj):
                receipt["artifacts"][str(p)] = digest(p)
            return obj

        base_obj = ocore_object(baseline, "baseline")
        oracle_obj = ocore_object(oracle, "oracle")
        arch_obj = build / "entry.o"
        checked(assembler + [str(architecture), "-o", str(arch_obj)], "assemble-entry")

        def image(probe: Path, implementations: Path, label: str) -> Path:
            output = build / f"{label}.elf"
            checked([str(linker), "-m", "elf64lriscv", "--no-relax", "--wrap=rv_boot_main", "-T", str(layout),
                     str(arch_obj), str(base_obj), str(probe), str(implementations), "-o", str(output)], f"link-{label}")
            receipt["artifacts"][str(output)] = digest(output)
            return output

        def boot(output: Path, label: str) -> tuple[dict, str]:
            result = command([str(qemu), "-M", "virt", "-cpu", "rv64", "-smp", "1", "-m", "128M",
                              "-nographic", "-monitor", "none", "-bios", str(firmware), "-kernel", str(output),
                              "-no-reboot"], build, label, args.timeout)
            receipt["commands"].append(result)
            return result, Path(result["stdout"]["path"]).read_text(errors="replace")

        output = image(oracle_obj, rust_obj, "rust-native")
        receipt["elf"] = elf_inventory(output)
        if not FUNCTIONS | {"__wrap_rv_boot_main"} <= set(receipt["elf"]["defined_functions"]):
            raise RuntimeError("native image omitted imported Rust or wrapper definitions")
        result, transcript = boot(output, "boot-rust-native")
        require_command(result)
        golden, cases = expected_digest()
        expected = f"RV64 native Rust scalar digest={golden} cases={cases}"
        ordered = (expected, BRIDGE_MARKER, *MARKERS)
        last = -1
        for marker in ordered:
            if transcript.count(marker) != 1 or transcript.index(marker) <= last:
                raise RuntimeError(f"native compiled evidence missing, duplicate, or unordered: {marker}\n{transcript}")
            last = transcript.index(marker)
        if "FAIL" in transcript or cases != 29680:
            raise RuntimeError(f"native Rust bridge rejected:\n{transcript}")
        receipt["result"] = {"digest": golden, "cases": cases, "independent_python_digest_matched": True,
                             "compiled_ocore_oracle_matched": True, "baseline_passed": list(MARKERS)}
        receipt["firmware_banner"] = next((line.strip() for line in transcript.splitlines()
                                            if line.strip().startswith("OpenSBI v")), None)
        print(expected)
        print(BRIDGE_MARKER)

        changed_oracle = build / "corrupt-oracle.oc"
        original_oracle = oracle.read_text()
        before, after = "const ORACLE_CORRUPT: u64 = 0;", "const ORACLE_CORRUPT: u64 = 1;"
        if original_oracle.count(before) != 1:
            raise RuntimeError("oracle negative control does not select exactly one corruption switch")
        changed_oracle.write_text(original_oracle.replace(before, after))
        changed_obj = ocore_object(changed_oracle, "corrupt-oracle")
        corrupted_object = build / "rust.corrupted.o"
        object_mutation = corrupt_helper_object(rust_obj, corrupted_object)
        for label, probe, implementations, mutation in (
            ("corrupt-oracle", changed_obj, rust_obj, {"source": str(changed_oracle), "source_sha256": digest(changed_oracle)}),
            ("corrupt-imported-object", oracle_obj, corrupted_object, object_mutation),
        ):
            corrupted_image = image(probe, implementations, label)
            result, text = boot(corrupted_image, f"boot-{label}")
            if (result["timed_out"] or result["returncode"] not in (0, 1)
                    or FAILURE not in text or BRIDGE_MARKER in text or MARKERS[-1] in text):
                raise RuntimeError(f"negative control did not reject {label}:\n{text}")
            receipt["negative_controls"].append({"name": label, "result": "rejected", "failure": FAILURE,
                                                 "mutation": mutation, "execution": result})
            print(f"RV64 native Rust negative control {label}: rejected")
        for p in (llvm, native, verified, rust_asm, direct_asm, rust_obj, repeated, arch_obj,
                  changed_oracle, corrupted_object):
            receipt["artifacts"][str(p)] = digest(p)
        for name, path in tools.items():
            if digest(path) != receipt["tools"][name]["sha256"]:
                raise RuntimeError(f"tool/frontend dependency changed during proof: {name}")
        for source, sha in receipt["sources"].items():
            if digest(ROOT / source) != sha:
                raise RuntimeError(f"original source changed during proof: {source}")
        receipt["status"] = "pass"
        receipt["native_platform_execution_verified"] = True
        save()
        print(f"RV64 native Rust bridge receipt: {receipt_path}")
        return 0
    except (OSError, RuntimeError, ValueError, KeyError, IndexError, struct.error) as exc:
        receipt["status"] = "fail"
        receipt["error"] = str(exc)
        save()
        print(str(exc), file=sys.stderr)
        print(f"RV64 failed native Rust bridge receipt: {receipt_path}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
