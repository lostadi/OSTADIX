#!/usr/bin/env python3
"""Build one original dependency-free library through the existing Rust capture wrapper.

This is an explicit rustc library configuration, not a Cargo implementation.
Only manifests whose default feature closure needs no build script, workspace,
external dependency or proc macro are admitted. Generic future instantiations,
sysroot providers and final executable ownership remain separate obligations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib


def artifact(path: Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def configuration(source: Path) -> dict:
    source = source.resolve()
    manifest = source / "Cargo.toml"
    document = tomllib.loads(manifest.read_text())
    package = document.get("package", {})
    if "workspace" in document or package.get("workspace"):
        raise ValueError("workspace resolution requires a full Cargo source-build recipe")
    if package.get("build", True) is not False and (package.get("build") or (source / "build.rs").exists()):
        raise ValueError("build scripts require a full Cargo source-build recipe")
    library = document.get("lib", {})
    if library.get("proc-macro") or library.get("crate-type", ["rlib"]) not in (["rlib"], ["lib"]):
        raise ValueError("only one ordinary rlib target is supported")
    if "target" in document:
        raise ValueError("target-dependent manifest resolution requires a full Cargo recipe")
    name = library.get("name", package.get("name", "")).replace("-", "_")
    edition = package.get("edition", "2015")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) or edition not in {"2015", "2018", "2021", "2024"}:
        raise ValueError("explicit ordinary crate name and supported edition are required")
    root = (source / library.get("path", "src/lib.rs")).resolve()
    root.relative_to(source)
    if not root.is_file():
        raise ValueError("original library root is missing")
    definitions = document.get("features", {})
    selected = set()

    def enable(feature):
        if feature in selected:
            return
        if feature not in definitions or not isinstance(definitions[feature], list):
            raise ValueError("default feature closure references unsupported dependency/feature: " + feature)
        selected.add(feature)
        for child in definitions[feature]:
            if not isinstance(child, str) or "/" in child or child.startswith("dep:"):
                raise ValueError("dependency feature activation requires a full Cargo recipe")
            enable(child)

    if "default" in definitions:
        enable("default")
    for name_, dependency in document.get("dependencies", {}).items():
        if not isinstance(dependency, dict) or not dependency.get("optional", False) or name_ in selected:
            raise ValueError("enabled dependency requires a source-built provider recipe: " + name_)
    return {"crate_name": name, "edition": edition, "root": str(root.relative_to(source)),
            "features": sorted(selected), "package_name": package["name"], "package_version": package["version"],
            "manifest": artifact(manifest), "crate_root": artifact(root)}


def write_new(path: Path, value: dict):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--rustc-wrapper", required=True)
    args = parser.parse_args(argv)
    source, build = args.source.resolve(), args.build.resolve()
    if source == build or source in build.parents or build in source.parents:
        raise ValueError("original source and build directories must be disjoint")
    config = configuration(source)
    version = subprocess.run([args.rustc, "-vV"], check=True, capture_output=True, text=True).stdout
    fields = dict(line.split(": ", 1) for line in version.splitlines() if ": " in line)
    if fields.get("release") != "1.97.1" or fields.get("LLVM version") != "22.1.6":
        raise ValueError("the configured library requires Rust1.97.1 and LLVM22.1.6")
    output = build / "native"
    output.mkdir()
    command = [args.rustc_wrapper, args.rustc, config["root"], "--crate-name", config["crate_name"],
               "--edition", config["edition"], "--crate-type=rlib", "--target", fields["host"],
               "--emit=link,dep-info", "-Copt-level=1", "-Cpanic=unwind", "-Ccodegen-units=2",
               "--out-dir", str(output)]
    for feature in config["features"]:
        command.extend(["--cfg", 'feature="' + feature + '"'])
    receipt = {"schema": "ocore-configured-original-rust-library-v1", "configuration": config,
               "argv": command, "target": fields["host"], "rustc_verbose_version": version,
               "runtime_complete": False, "native_execution_qualified": False,
               "generic_instantiations_complete": False, "provider_closure_complete": False}
    result = subprocess.run(command, cwd=source, env=os.environ)
    receipt["exit_code"] = result.returncode
    write_new(build / "configured-library.json", receipt)
    if result.returncode:
        return result.returncode
    native = output / ("lib" + config["crate_name"] + ".rlib")
    if not native.is_file():
        raise ValueError("original compiler did not produce the complete requested rlib")
    inventory = {"schema": "ocore-runtime-unit-inventory-v1", "complete": True,
                 "units": [{"id": config["crate_name"] + "-library", "kind": "rustc",
                            "source": config["root"], "role": "runtime"}],
                 "runtime_outputs": [artifact(native)],
                 "configuration_evidence": artifact(build / "configured-library.json")}
    write_new(build / "unit-inventory.json", inventory)
    print(json.dumps({"inventory": str(build / "unit-inventory.json"), "native_output": str(native),
                      "runtime_complete": False, "provider_closure_complete": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
