#!/usr/bin/env python3
"""Run M0 native component evidence; full M0 additionally needs aligned tools and guest regressions.

A passing component run does not qualify M0. Missing tools and skipped tests
remain unqualified. This script never starts a VM or changes a saved state.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest

from build_okernel_unified_world import SOURCES

ROOT = Path(__file__).resolve().parents[1]

def command(argv):
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=15)
    return {"argv": argv, "returncode": result.returncode,
            "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--mcp-release", default="unknown",
                        help="observed MCP release source revision; unknown never qualifies")
    parser.add_argument("--regression-result", type=Path,
                        help="full same-source regression receipt with ok=true and source_revision")
    parser.add_argument("--component-only", action="store_true",
                        help="return component status while recording full gate as unqualified")
    args = parser.parse_args()
    session = args.session.expanduser().resolve()
    session.mkdir(parents=True, exist_ok=True)
    result_path = session / "result.json"
    if result_path.exists():
        parser.error("session result.json already exists; select a fresh session")
    source = command(["git", "rev-parse", "HEAD"])
    revision = source["stdout"] if source["returncode"] == 0 else "unknown"
    compiler = Path(os.environ.get("OCOREC_BIN", ROOT / "target/debug/ocorec"))
    commands = {"source": source, "diff": command(["git", "status", "--short"]),
                "qemu": command(["qemu-system-aarch64", "--version"]) if shutil.which("qemu-system-aarch64") else None}
    files = ["scripts/o10.py", "ocore/runtime/common/o10_codec.oc",
             "ocore/runtime/common/o10_executor.oc", "tests/test_o10_codec.py",
             "tests/test_o10_native.py", "tests/test_o10_platform.py",
             "scripts/verify_o10_journal.py", "scripts/okernel_unified_world.py",
             "scripts/build_okernel_unified_world.py", "tests/test_o10_runner.py",
             "ci/language-sources.json", "scripts/freeze_okernel_unified_runtime.py", *SOURCES]
    files += [str(path.relative_to(ROOT)) for pattern in ("tests/test_o10_*.py", "scripts/verify_o10_*.py") for path in ROOT.glob(pattern)]
    files = sorted(set(files))
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files}
    log = io.StringIO()
    record = {"milestone": "M0", "gate_id": "verify_o10_journal",
              "started": time.time(), "source_revision": revision,
              "mcp_release": args.mcp_release, "host": platform.node(),
              "host_platform": platform.platform(), "machine_options": None,
              "session": str(session), "command": [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
              "observations": commands, "source_sha256": hashes,
              "compiler": str(compiler), "compiler_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest() if compiler.is_file() else None,
              "component_ok": False, "ok": False, "qualified": False,
              "scope": "Python/native structural wire corpus, exactly-once executor journal and x86_64 mailbox/fid component execution; excludes AArch64 EL2 execution, guest boot/replacement and full regression qualification"}
    try:
        os.environ["O10_COMMAND_LOG"] = str(session / "native-commands.jsonl")
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_o10_*.py")
        run = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        record.update(tests_run=run.testsRun, failures=len(run.failures), errors=len(run.errors),
                      skips=[{"test": str(test), "reason": reason} for test, reason in run.skipped])
        record["source_unchanged"] = hashes == {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in files}
        record["component_ok"] = run.wasSuccessful() and not run.skipped and run.testsRun > 0 and record["source_unchanged"]
        aligned = revision != "unknown" and args.mcp_release == revision
        regression = json.loads(args.regression_result.read_text()) if args.regression_result else None
        regressions_ok = bool(regression and regression.get("ok") is True
                              and regression.get("source_revision") == revision
                              and not regression.get("skips"))
        record.update(release_aligned=aligned, regression=regression,
                      qualified=False)
        record["ok"] = False
        record["qualification_note"] = "This component verifier cannot attest the running MCP release or same-build EL2/guest regression evidence; supplied release/receipt metadata never grants M0 qualification."
        record["unqualified_reasons"] = ["external MCP identity and same-build EL2/guest qualification required"] + ([ "component checks failed or skipped" ] if not record["component_ok"] else []) + ([ "MCP release does not match source revision" ] if not aligned else []) + ([ "full same-source regression receipt absent or unqualified" ] if not regressions_ok else [])
    except Exception as error:
        record["error"] = type(error).__name__ + ": " + str(error)
    finally:
        record["finished"] = time.time()
        os.environ.pop("O10_COMMAND_LOG", None)
        (session / "tests.log").write_text(log.getvalue())
        result_path.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"component_ok": record["component_ok"], "qualified": record["qualified"],
                      "result": str(result_path)}, sort_keys=True))
    return 0 if (record["component_ok"] if args.component_only else record["qualified"]) else 1

if __name__ == "__main__":
    raise SystemExit(main())
