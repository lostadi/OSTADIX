#!/usr/bin/env python3
"""Prepare the unified console in an explicit stopped private saved-state fork.

Deploys checked local clients, preserving installed packages, repositories and
user files. The original signed Alpine Python package is the Linux client
dependency; original Plan9 tools remain in the separately admitted provider.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from okernel_unified_world import UnifiedDomain, common


def prepare(state, build):
    state = state.resolve(strict=True)
    fork = json.loads((state / "fork.json").read_text())
    if (state == common.DEFAULT_STATE.resolve() or fork.get("schema") != "ostadix.okernel-state-fork/v1"
            or fork.get("ok") is not True or fork.get("output") != str(state)):
        raise ValueError("preparation requires an explicit isolated saved-state fork")
    spec = importlib.util.spec_from_file_location("unified_tool_update", ROOT / "scripts/update_okernel_guest_tools.py")
    updater = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(updater)
    updater.TOOLS.update({
        "/usr/local/bin/p9": ROOT / "ocore/guest/linux/package-domain/p9",
        "/usr/local/libexec/p9-controller": ROOT / "ocore/guest/linux/package-domain/p9-controller",
        "/usr/local/libexec/p9-history": ROOT / "ocore/guest/linux/package-domain/p9-history",
        "/usr/local/bin/p9-install": ROOT / "ocore/guest/linux/package-domain/p9-install",
        "/usr/local/libexec/p9_protocol.py": ROOT / "ocore/guest/plan9/unified/protocol.py"})
    deployed = updater.update(state)
    domain = None
    try:
        domain = UnifiedDomain(state, build, "qemu-system-aarch64", timeout=300)
        domain.ready()
        domain.command("if ! command -v python3 >/dev/null; then pkg add python3; fi", timeout=300)
        domain.command("python3 --version; apk info -vv > /work/unified-installed-packages.txt; sha256sum /usr/bin/python3* /usr/local/bin/p9 /usr/local/libexec/p9-controller /usr/local/libexec/p9_protocol.py > /work/unified-client-inputs.sha256")
        if domain.guest_coordinator_online:
            domain.command("p9 echo UNIFIED_CLIENT_PREPARATION_READY", timeout=180)
            domain.wait(b"UNIFIED_CLIENT_PREPARATION_READY", line=True)
        domain.save()
        receipt = {"schema": "ostadix.unified-console-preparation/v1", "ok": True,
                   "tools_receipt": deployed["receipt"], "session": str(domain.session / "result.json"),
                   "state": str(state), "build": str(build), "head": domain.head}
        common.write_json(state / "unified-preparation.json", receipt)
        print("Unified console preparation: PASS\nEvidence: " + str(state / "unified-preparation.json"))
    finally:
        if domain is not None:
            domain.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.state.expanduser(), args.build.expanduser().resolve(strict=True))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as error:
        print("Unified preparation failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
