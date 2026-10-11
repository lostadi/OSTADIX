#!/usr/bin/env python3
"""Reject configuration that silently trims the retained full HotSpot profile."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def check_spec(spec: Path, recipe: dict) -> dict:
    data = spec.read_bytes()
    text = data.decode("utf-8").replace("\\\n", " ")
    def variable(name: str) -> str:
        matches = re.findall(r"^" + re.escape(name) + r"[ \t]*:?=[ \t]*([^\n]*)$", text, flags=re.MULTILINE)
        if len(matches) != 1 or "$" in matches[0] or "@" in matches[0]:
            raise ValueError(f"{spec}: missing/ambiguous configured variable {name}")
        return matches[0].split("#", 1)[0].strip()
    variants = set(variable("JVM_VARIANTS").split())
    if "server" not in variants or variants & {"minimal", "zero", "core"}:
        raise ValueError(f"full HotSpot server is required; configured variants: {sorted(variants)}")
    required = set(recipe["required_hotspot_features"])
    active = set(variable("JVM_FEATURES_server").split())
    if required - active:
        raise ValueError(f"HotSpot features were filtered: {sorted(required - active)}")
    if variable("ENABLE_HEADLESS_ONLY") != "false":
        raise ValueError("full retained desktop modules require ENABLE_HEADLESS_ONLY=false")
    for field in ("IMPORT_MODULES_CLASSES", "IMPORT_MODULES_LIBS", "IMPORT_MODULES_CMDS"):
        if variable(field):
            raise ValueError(f"prebuilt executable/module imports cannot satisfy full source capture: {field}")
    return {"format": "ocore-openjdk-configured-profile-v1", "spec": str(spec.resolve()),
            "spec_sha256": hashlib.sha256(data).hexdigest(), "variants": sorted(variants),
            "features": sorted(active), "full_profile_retained": True,
            "runtime_complete": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--recipe", type=Path, default=Path(__file__).with_name("openjdk.recipe.json"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        candidates = [args.build / "spec.gmk"] if (args.build / "spec.gmk").is_file() else sorted(args.build.rglob("spec.gmk"))
        if len(candidates) != 1:
            raise ValueError(f"expected one selected configured spec.gmk, found {len(candidates)}")
        result = check_spec(candidates[0], json.loads(args.recipe.read_text()))
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(text)
        else:
            print(text, end="")
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(f"OpenJDK profile rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
