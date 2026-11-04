#!/usr/bin/env python3
"""Build a closed original u9fs codec component through compiler-owned recipes.

The output manifest is for native linking. It does not claim a complete server,
kernel, POSIX personality, or improved performance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import struct
import subprocess

from build_component import CODECS, MEMORY, FLAGS, identity, write

DIRECTORY = Path(__file__).resolve().parent
SYMBOLS = {"convM2S", "convS2M", "convM2D", "convD2M", "sizeD2M", "statcheck",
           "memmove", "memcpy", "strlen"}


def run(argv, cwd, env, records, timeout=600):
    argv = [str(arg) for arg in argv]
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    record = {"argv": argv, "cwd": str(cwd), "exit_code": result.returncode,
              "stdout": result.stdout, "stderr": result.stderr}
    records.append(record)
    write(cwd / "commands.json", {"commands": records})
    if result.returncode:
        raise RuntimeError("command failed: " + " ".join(argv) + "\n" + result.stdout + result.stderr)
    return result.stdout


def completed(path):
    recipe = json.loads((path / "source-recipe.json").read_text())
    coverage = json.loads((path / "lowered/coverage.json").read_text())
    if not all(recipe.get(key) is True for key in ("success", "capture_complete", "lowering_complete")):
        raise ValueError("source recipe did not complete: " + str(path))
    if not all(coverage.get(key) is True for key in (
            "capture_complete", "module_set_complete", "native_module_dependency_closure_complete", "symbol_closure_complete")):
        raise ValueError("native module dependency closure did not complete: " + str(path))
    return recipe, coverage


def object_paths(coverage):
    result = []
    for unit in coverage["units"]:
        if not unit.get("required_for_lowering"):
            continue
        if not unit.get("verified") or not unit.get("lowered"):
            raise ValueError("unverified unit in closed component")
        expected = unit["object"]
        path = Path(expected["path"])
        if not path.is_file() or identity(path) != expected:
            raise ValueError("owned native object differs from its compiler receipt: " + str(path))
        result.append(path)
    return result


def test_component(args, output, objects, includes, env, commands):
    test = output / "semantic-test"
    test.mkdir()
    reference = []
    rename = ["-D" + symbol + "=ref_" + symbol for symbol in sorted(SYMBOLS)]
    for source, names in ((args.u9fs_source, CODECS), (args.musl_source, MEMORY)):
        for name in names:
            obj = test / ("ref_" + Path(name).stem + ".o")
            run([args.clang, f"--target={args.isa}-unknown-linux-musl", *FLAGS, *rename,
                 *["-I" + str(path) for path in includes], "-c", source / name, "-o", obj],
                output, env, commands)
            reference.append(obj)
    harness, carrier = test / "harness.o", test / "carrier.o"
    run([args.clang, f"--target={args.isa}-unknown-linux-musl", *FLAGS,
         *["-I" + str(path) for path in includes], "-c", DIRECTORY / "verify_component.c", "-o", harness],
        output, env, commands)
    run([args.clang, f"--target={args.isa}-unknown-linux-musl", "-c",
         DIRECTORY / f"carrier-{args.isa}.S", "-o", carrier], output, env, commands)
    executable = test / "verify"
    emulation = "elf_x86_64" if args.isa == "x86_64" else "aarch64elf"
    run([args.linker, "-m", emulation, "-static", "-e", "_start", "-o", executable,
         carrier, harness, *objects, *reference], output, env, commands)
    undefined = run([args.llvm_nm, "--undefined-only", "--format=posix", executable], output, env, commands)
    if undefined.strip():
        raise ValueError("semantic test unexpectedly needs external symbols: " + undefined)
    native_host = {"AMD64": "x86_64", "arm64": "aarch64"}.get(platform.machine(), platform.machine())
    if native_host == args.isa:
        invocation = [executable]
        execution = "native host Linux syscall test carrier"
    elif args.isa == "aarch64" and args.qemu_aarch64:
        invocation = [args.qemu_aarch64, executable]
        execution = "AArch64 Linux syscall test carrier under explicit QEMU user emulation"
    else:
        raise ValueError("semantic execution requires a matching host or explicit --qemu-aarch64")
    stdout = run(invocation, output, env, commands)
    if "Original u9fs and musl via O-core: PASS; checks=" not in stdout:
        raise ValueError("semantic test did not emit its completed checks marker")
    return {"ok": True, "execution": execution, "stdout": stdout,
            "binary": identity(executable), "harness": identity(DIRECTORY / "verify_component.c"),
            "carrier": identity(DIRECTORY / f"carrier-{args.isa}.S"),
            "reference_objects": [identity(path) for path in reference],
            "scope": "original codec and memory dependency semantics; no kernel or hardware qualification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isa", choices=("x86_64", "aarch64"), required=True)
    for option in ("u9fs-source", "musl-source", "olangc", "clang", "clangxx", "llvm-nm", "linker", "llvm-library", "output"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--llvm-sha256", required=True)
    parser.add_argument("--qemu-aarch64", type=Path)
    parser.add_argument("--verify", action="store_true", help="run the freestanding differential test carrier")
    args = parser.parse_args()
    for name in ("u9fs_source", "musl_source"):
        setattr(args, name, getattr(args, name).expanduser().resolve(strict=True))
    # Driver aliases carry semantics: ld.lld must not become generic lld,
    # and clang++ must retain its selected driver spelling.
    for name in ("olangc", "clang", "clangxx", "llvm_nm", "linker", "llvm_library"):
        path = Path(os.path.abspath(getattr(args, name).expanduser()))
        if not path.is_file():
            parser.error("required tool/library is absent: " + str(path))
        setattr(args, name, path)
    if identity(args.llvm_library)["sha256"] != args.llvm_sha256:
        parser.error("LLVM parser library differs from its explicit SHA-256 pin")
    output = args.output.expanduser().resolve()
    output.mkdir(parents=False, exist_ok=False)
    env = os.environ.copy()
    env["OCORE_U9FS_MUSL_SOURCE"] = str(args.musl_source)
    commands = []
    common = ["--native-runtime", "--native-isa", args.isa + "-unknown-none", "--native-runtime-output", "obj",
              "--native-runtime-cc", args.clang, "--native-runtime-cxx", args.clangxx,
              "--native-runtime-llvm-nm", args.llvm_nm, "--native-runtime-jobs", "2",
              "--llvm-library", args.llvm_library, "--llvm-sha256", args.llvm_sha256]
    memory, codecs = output / "memory", output / "codecs"
    run([args.olangc, DIRECTORY / f"{args.isa}.memory.recipe.json", *common,
         "--native-runtime-source", args.musl_source, "-o", memory], output, env, commands)
    _, memory_coverage = completed(memory)
    run([args.olangc, DIRECTORY / f"{args.isa}.codecs.recipe.json", *common,
         "--native-runtime-source", args.u9fs_source, "--native-runtime-dependency",
         memory / "lowered/runtime.native-ir.json", "-o", codecs], output, env, commands)
    _, codec_coverage = completed(codecs)
    objects = object_paths(codec_coverage) + object_paths(memory_coverage)
    if len(objects) != 7:
        raise ValueError("expected four original codecs plus three original musl units")
    machine = 62 if args.isa == "x86_64" else 183
    for path in objects:
        raw = path.read_bytes()
        if raw[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", raw, 18)[0] != machine:
            raise ValueError("native object is not the exact declared ELF ISA: " + str(path))
    linked = output / "codec-closure.o"
    run([args.linker, "-m", "elf_x86_64" if args.isa == "x86_64" else "aarch64elf",
         "-r", "-o", linked, *objects], output, env, commands)
    undefined = run([args.llvm_nm, "--undefined-only", "--format=posix", linked], output, env, commands)
    if undefined.strip():
        raise ValueError("native codec component has unresolved symbols: " + undefined)
    defined = run([args.llvm_nm, "--defined-only", "--extern-only", "--format=posix", linked], output, env, commands)
    symbols = sorted(line.split()[0] for line in defined.splitlines() if line.strip())
    if set(symbols) != SYMBOLS:
        raise ValueError("original component symbol inventory changed: " + repr(symbols))
    includes = [args.u9fs_source, codecs / "build/include", args.musl_source / f"arch/{args.isa}",
                args.musl_source / "arch/generic", args.musl_source / "include"]
    semantic = test_component(args, output, objects, includes, env, commands) if args.verify else None
    manifest = {
        "schema": "ostadix.native-u9fs-codec/v1", "isa": args.isa,
        "objects": [identity(path) for path in objects], "linked_closure": identity(linked),
        "source_recipe_receipts": [identity(path / "source-recipe.json") for path in (memory, codecs)],
        "coverage_receipts": [identity(path / "lowered/coverage.json") for path in (memory, codecs)],
        "native_module_sets": [identity(path / "lowered/runtime.native-ir.json") for path in (memory, codecs)],
        "unresolved_symbols": [], "symbols": symbols,
        "source_dir": str(args.u9fs_source), "header_source": str(args.musl_source),
        "include_roots": [str(path) for path in includes],
        "original_headers": [identity(args.u9fs_source / name) for name in ("plan9.h", "fcall.h")],
        "abi": {"pointer_bits": 64, "Fcall_bytes": 712, "Fcall_alignment": 8, "Qid_bytes": 24},
        "semantic_test": semantic, "commands": identity(output / "commands.json"),
        "scope": "four unchanged original u9fs 9P codec units plus original musl memcpy/memmove/strlen, compiler-owned source capture and O-core native closure; not full server/kernel",
        "limitations": ["Original Rauth decode rejection retained", "No kernel integration or performance claim",
                        "Dependency source_pin is unsupported by module-set schema; selected original sources remain bound in both source recipe receipts"]}
    write(output / "native-codec.json", manifest)
    print("Native original u9fs codec closure: " + str(output / "native-codec.json"))
    if semantic:
        print(semantic["stdout"], end="")


if __name__ == "__main__":
    main()
