#!/usr/bin/env python3
"""Retain the complete configured CPython native build graph and module profile.

These artifacts describe a hosted source capture. They do not qualify native
OSTADIX services, external dependency lowering, assembly import, or linking.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess


def artifact(path: Path) -> dict:
    path = path.resolve()
    data = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def profile(source: Path, build: Path) -> dict:
    makefile = (build / "Makefile").read_text()
    states = dict(re.findall(r"^MODULE_([A-Z0-9_]+)_STATE\s*=\s*(\S+)\s*$", makefile, re.M))
    template = source / "Modules/Setup.stdlib.in"
    declared = set(re.findall(r"@MODULE_([A-Z0-9_]+)_TRUE@", template.read_text()))
    missing = declared - set(states)
    omitted = {name: state for name, state in states.items() if state not in {"yes", "n/a"}}
    inapplicable = {name for name, state in states.items() if state == "n/a"}
    # This recipe is explicitly the Linux hosted capture. The pinned upstream
    # _scproxy implementation is Darwin-only; other omissions need a new
    # supported platform profile, not a rewritten n/a flag.
    machdep = re.search(r"^MACHDEP\s*=\s*(\S+)\s*$", makefile, re.M)
    if not machdep or machdep.group(1) != "linux" or inapplicable - {"_SCPROXY"}:
        raise ValueError("unsupported or altered full hosted-Linux module applicability profile")
    # n/a records the upstream platform decision, not permission to disable an
    # applicable module. All applicable modules must remain enabled.
    if missing or omitted:
        raise ValueError(f"full module profile unavailable: absent={sorted(missing)}, omitted={omitted}")
    return {"schema": "ocore-cpython-full-hosted-module-profile-v1",
            "source_template": artifact(template), "configured_makefile": artifact(build / "Makefile"),
            "config_log": artifact(build / "config.log"), "module_states": states,
            "platform_profile": "hosted-linux", "platform_inapplicable_modules": sorted(inapplicable),
            "applicable_modules_enabled": True, "native_execution_qualified": False, "runtime_complete": False}


def compiler_sources(line: str, build: Path, cc: str, cxx: str) -> list[str]:
    if cc not in line and cxx not in line:
        return []
    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    tokens = list(lexer)
    result = []
    for index, token in enumerate(tokens):
        if token not in {cc, cxx}:
            continue
        args = []
        for item in tokens[index + 1:]:
            if item and set(item) <= set(";&|"):
                break
            args.append(item)
        # Never parse include/depfile/output operands as source translation units.
        paired = {"-o", "-I", "-isystem", "-include", "-include-pch", "-imacros", "-MF", "-MT", "-MQ", "-x"}
        skip = False
        for arg in args:
            if skip:
                skip = False
            elif arg in paired:
                skip = True
            elif not arg.startswith("-") and Path(arg).suffix in {".c", ".cc", ".cpp", ".cxx", ".C", ".s", ".S"}:
                result.append(str((build / arg).resolve()))
    return result


def plan(source: Path, build: Path, capture: Path) -> dict:
    checked = profile(source, build)
    result = subprocess.run(["make", "--dry-run", "all"], cwd=build, capture_output=True)
    stdout, stderr = build / "native-build-plan.stdout", build / "native-build-plan.stderr"
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    if result.returncode:
        raise ValueError(f"upstream full build plan failed: exit {result.returncode}; see {stderr}")
    cc, cxx = str(capture / "wrappers/cc"), str(capture / "wrappers/cxx")
    entries = []
    for index, line in enumerate(result.stdout.decode().replace("\\\n", " ").splitlines()):
        sources = compiler_sources(line, build, cc, cxx)
        if sources:
            entries.append({"line": index + 1, "command": line, "sources": sources})
    if not entries:
        raise ValueError("upstream full build plan contains no captured native compiler commands")
    return {"schema": "ocore-cpython-configured-native-build-plan-v1", "profile": checked,
            "upstream_argv": ["make", "--dry-run", "all"], "cwd": str(build),
            "stdout": artifact(stdout), "stderr": artifact(stderr), "entries": entries,
            "native_execution_qualified": False, "runtime_complete": False}


def inventory(source: Path, build: Path, capture: Path) -> dict:
    graph_path = build / "native-build-plan.json"
    graph = json.loads(graph_path.read_text())
    current = profile(source, build)
    if current != graph["profile"]:
        raise ValueError("configured module profile changed after recording its full build plan")
    expected = sorted({name for entry in graph["entries"] for name in entry["sources"]})
    events = [json.loads(path.read_text()) for path in sorted((capture / "events").glob("*.json"))]
    planned = set(expected)
    actual = {item["path"] for event in events
              if event.get("build_step", {}).get("name") == "build-runtime-and-extensions"
              for item in event.get("sources", [])}
    missing, unplanned = sorted(planned - actual), sorted(actual - planned)
    if missing or unplanned:
        raise ValueError(f"full native plan mismatch: missing={missing}, unplanned={unplanned}")
    units = [{"id": f"native-source-{index}", "kind": "clang",
              "source": str(Path(name).relative_to(source)) if Path(name).is_relative_to(source) else name,
              "build_step": "build-runtime-and-extensions", "role": "runtime-or-compiler-helper"}
             for index, name in enumerate(expected)]
    runtime_outputs = [artifact(build / "python"), *[artifact(path) for path in sorted(build.glob("libpython*.a"))],
                       *[artifact(path) for path in sorted((build / "Modules").rglob("*.so"))]]
    # Keep implementation helpers in the lowering set. Only actual configure
    # probe units may be excluded, with stage/log and final membership checks
    # independently repeated by the trusted capture verifier.
    probes = {unit["source"]["path"] for event in events
              if event.get("build_step", {}).get("name") == "configure-full-runtime"
              for unit in event.get("units", []) if "ir" in unit}
    exclusions = [{"id": f"configure-probe-{index}", "kind": "clang", "source": name,
                   "build_step": "configure-full-runtime", "role": "configure_probe",
                   "evidence": {"reason": "Original upstream configure compilation; retained outside full runtime build stage and checked against every declared runtime output/archive member.",
                                "artifacts": [artifact(build / "config.log"), artifact(graph_path)]}}
                  for index, name in enumerate(sorted(probes))]
    return {"schema": "ocore-runtime-unit-inventory-v1", "complete": True, "units": units,
            "non_lowering_units": exclusions, "runtime_outputs": runtime_outputs,
            "configured_native_graph": artifact(graph_path), "configured_profile": current,
            "dependency_implementations_lowered": False, "native_execution_qualified": False,
            "runtime_complete": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["plan", "inventory"])
    for name in ("source", "build", "capture", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    function = plan if args.action == "plan" else inventory
    result = function(args.source.resolve(), args.build.resolve(), args.capture.resolve())
    write(args.output, result)
    print(json.dumps({"artifact": artifact(args.output), "runtime_complete": False}))


if __name__ == "__main__":
    main()
