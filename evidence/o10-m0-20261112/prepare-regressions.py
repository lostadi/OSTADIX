"""Prepare checked private regression seed and frozen O10 runtime; no VM starts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path("/home/ustad/OSTADIX-o10-m0-20261112")
AREA = Path("/home/ustad/.cache/o10-m0-acceptance-20261112")
SEED = AREA / "regression-seed"
BUILD = AREA / "unified-build-r2"
RUNTIME = AREA / "runtime-o10-r1"
EVIDENCE = ROOT / "evidence/o10-m0-20261112/regression-preparation"
EVIDENCE.mkdir(parents=True, exist_ok=False)
record = {"scope": "Private saved-pair fork, checked offline helper deployment and frozen-runtime capture only; no VM",
          "source": "/home/ustad/.local/state/ostadix/okernel/unified-system-20261106-idle-ui",
          "seed": str(SEED), "runtime": str(RUNTIME), "build": str(BUILD),
          "started": time.time(), "ok": False, "commands": []}
def run(argv):
    record["commands"].append(argv)
    with (EVIDENCE / ("command-" + str(len(record["commands"])) + ".stdout")).open("w") as stdout, (EVIDENCE / ("command-" + str(len(record["commands"])) + ".stderr")).open("w") as stderr:
        subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr, timeout=600, check=True)
try:
    run(["python3", "scripts/fork_okernel_state.py", "--source", record["source"], "--output", str(SEED)])
    sys.path.insert(0, str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("o10_seed_updater", ROOT / "scripts/update_okernel_guest_tools.py")
    updater = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(updater)
    updater.TOOLS.update({
        "/usr/local/bin/p9": ROOT / "ocore/guest/linux/package-domain/p9",
        "/usr/local/libexec/p9-controller": ROOT / "ocore/guest/linux/package-domain/p9-controller",
        "/usr/local/libexec/p9-history": ROOT / "ocore/guest/linux/package-domain/p9-history",
        "/usr/local/bin/p9-install": ROOT / "ocore/guest/linux/package-domain/p9-install",
        "/usr/local/libexec/p9_protocol.py": ROOT / "ocore/guest/plan9/unified/protocol.py"})
    deployed = updater.update(SEED)
    record["helper_deployment"] = deployed
    run(["python3", "scripts/freeze_okernel_unified_runtime.py", "--source", str(ROOT),
         "--build", str(BUILD), "--qemu", "/usr/bin/qemu-system-aarch64", "--output", str(RUNTIME)])
    manifest = json.loads((RUNTIME / "runtime.json").read_text())
    if manifest.get("passed") is not True:
        raise RuntimeError("frozen runtime did not pass")
    record["frozen_manifest_sha256"] = hashlib.sha256((RUNTIME / "runtime.json").read_bytes()).hexdigest()
    record["ok"] = True
except BaseException as error:
    record["error"] = type(error).__name__ + ": " + str(error)
    raise
finally:
    record["finished"] = time.time()
    (EVIDENCE / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"ok": record["ok"], "evidence": str(EVIDENCE / "result.json")}))
