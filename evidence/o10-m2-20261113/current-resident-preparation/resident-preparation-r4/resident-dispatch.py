#!/usr/bin/env python3
"""Pinned M2 resident preparation; --dispatch submits one managed canonical gate."""
import argparse, hashlib, json, os, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True

PREP = Path(__file__).resolve().parent
PINS = json.loads((PREP / "pins.json").read_text())
ROOT = Path(PINS["root"])
BASE = Path(PINS["bridge"])
REQUEST = json.loads((PREP / "request.json").read_text())

def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1048576), b""):
            h.update(block)
    return h.hexdigest()

def need(value, message):
    if not value:
        raise ValueError(message)

def call(method, arguments, env, record_dir):
    argv = [sys.executable, "-B", str(ROOT / "scripts/ostadix_mcp_client.py"),
            method, json.dumps(arguments)]
    p = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60)
    (record_dir / (method + ".stdout")).write_text(p.stdout)
    (record_dir / (method + ".stderr")).write_text(p.stderr)
    need(p.returncode == 0, method + " client failed")
    return p.stdout

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-dir", type=Path, required=True)
    parser.add_argument("--dispatch", action="store_true")
    args = parser.parse_args()
    need(not args.record_dir.exists() and not args.record_dir.is_symlink(), "record directory must be new")
    args.record_dir.mkdir(parents=True)
    result = {"schema": "ostadix.o10-m2-resident-controller/v1", "ok": False,
              "gate_passed": False, "full_milestone_qualified": False,
              "scope": "Pinned read-only preflight; --dispatch submits the canonical resident component gate once",
              "started_unix": time.time(), "request": REQUEST}
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        import verify_o10_m2 as m2
        import verify_okernel_unified_runtime as rv
        need(subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
             text=True, check=True).stdout.strip() == PINS["revision"], "HEAD changed")
        for name, wanted in PINS["sources"].items():
            need(sha(ROOT / name) == wanted, "source changed: " + name)
        for name, row in PINS["files"].items():
            p = Path(row["path"])
            need(p.is_file() and not p.is_symlink() and p.stat().st_size == row["bytes"]
                 and sha(p) == row["sha256"], "identity changed: " + name)
        origin = json.loads(Path(PINS["files"]["origin_build"]["path"]).read_text())
        stamp = json.loads(Path(PINS["files"]["stamp_build"]["path"]).read_text())
        alignment = json.loads(Path(PINS["files"]["alignment"]["path"]).read_text())
        need(origin.get("ok") is True and origin.get("source_unchanged") is True
             and origin.get("revision") == PINS["toolchain_origin_revision"], "origin toolchain receipt invalid")
        need(stamp.get("ok") is True and stamp.get("source_unchanged") is True
             and stamp.get("revision") == PINS["revision"]
             and stamp.get("source_root") == str(ROOT)
             and stamp.get("toolchain_origin_revision") == PINS["toolchain_origin_revision"], "MCP stamp receipt invalid")
        need(alignment.get("ok") is True and alignment.get("revision") == PINS["revision"]
             and alignment.get("root") == str(ROOT)
             and alignment.get("toolchain_origin_revision") == PINS["toolchain_origin_revision"], "alignment receipt invalid")
        for name, row in origin["binaries"].items():
            if name == "ostadix-mcp":
                continue
            need(alignment["binaries"].get(name) == row == stamp["binaries"].get(name), "typed tool descriptor differs: " + name)
            need(sha(row["path"]) == row["sha256"], "origin tool bytes changed: " + name)
        need(alignment["mcp"] == alignment["binaries"]["ostadix-mcp"] == stamp["binaries"]["ostadix-mcp"], "new MCP descriptor differs")
        profile = m2.validate_build(ROOT, Path(PINS["build"]))
        runtime = Path(PINS["runtime"])
        manifest = rv.document(runtime / "runtime.json")
        rv.validate_inventory(runtime, manifest)
        need(manifest["admitted_manifest"]["sha256"] == PINS["files"]["profile"]["sha256"],
             "runtime does not bind selected build")
        for name, row in manifest["sources"].items():
            need(sha(ROOT / name) == row["frozen"]["sha256"], "frozen source changed: " + name)
        state = Path(PINS["seed"])
        head = json.loads((state / "head.json").read_text())
        m2.shared.require(sha(state / "head.json") == PINS["files"]["seed_head"]["sha256"], "seed head changed")
        need(head["disk"]["sha256"] == PINS["files"]["seed_disk"]["sha256"]
             and head["namespace"]["sha256"] == PINS["files"]["seed_namespace"]["sha256"], "seed pair changed")
        need(not Path(PINS["session"]).exists() and not Path(PINS["session"]).is_symlink(),
             "resident session already exists; no automatic rerun")
        env = {**os.environ, **json.loads((BASE / "bridge-env.json").read_text()),
               "PYTHONDONTWRITEBYTECODE": "1"}
        observed = json.loads(call("o_env", {}, env, args.record_dir))["structuredContent"]
        need(observed["buildCommitMatchesRuntimeSource"] is True
             and observed["buildSource"]["commit"] == PINS["revision"]
             and observed["runtimeSource"]["commit"] == PINS["revision"]
             and observed["runtimeSource"]["root"] == str(ROOT)
             and observed["binary"]["hashSource"] == "running_process_inode"
             and observed["binary"]["sha256"] == PINS["mcp_sha256"], "MCP alignment changed")
        seen = {row["name"]: row["binary"] for row in observed["tools"]}
        for name in ("O", "olangc"):
            expected = origin["binaries"][name]
            need(seen[name]["sha256"] == expected["sha256"]
                 and Path(seen[name]["canonicalPath"]).resolve() == Path(expected["path"]).resolve(), "selected tool differs: " + name)
        need(observed["buildSource"].get("dirty") is False
             and observed["runtimeSource"].get("dirty") is False, "source is dirty")
        call("o_doctor", {}, env, args.record_dir)
        call("o_runtimes", {}, env, args.record_dir)
        result.update(ok=True, source_revision=PINS["revision"], mcp_release=PINS["revision"],
                      build_sources=len(profile["source_sha256"]), runtime_inventory=len(manifest["inventory"]),
                      seed_head=PINS["files"]["seed_head"], source_unchanged=True,
                      toolchain_origin_revision=PINS["toolchain_origin_revision"],
                      scope=PINS["draft0_scope"], runtime=PINS["files"]["runtime"],
                      typed_toolchain_receipts={name:PINS["files"][name] for name in ("origin_build","stamp_build","alignment","artifact_validation")})
        qemu_processes = []
        for candidate in Path("/proc").iterdir():
            if not candidate.name.isdigit():
                continue
            try:
                executable = Path(os.readlink(candidate / "exe")).name
                if executable.startswith("qemu-system-"):
                    qemu_processes.append({"pid": int(candidate.name), "exe": os.readlink(candidate / "exe")})
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
        result["qemu_processes_before"] = qemu_processes
        need(not subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True,
             text=True, check=True).stdout, "source became dirty")
        if args.dispatch:
            need(not qemu_processes, "another actual QEMU process is active; no submission")
            intent = PREP / "SUBMISSION-ATTEMPT.json"
            with intent.open("x") as f:
                json.dump({"unix": time.time(), "request": REQUEST, "rule": "One attempt; unknown completion is never retried"}, f, indent=2)
            # The start receipt is retained before any interpretation. An
            # unknown submission is never retried by this controller.
            raw = call("o_cli", REQUEST, env, args.record_dir)
            response = json.loads(raw)
            job = response.get("structuredContent", {})
            need(isinstance(job.get("job_id"), str), "submission outcome unknown; inspect retained raw receipt")
            result.update(submitted=True, job_id=job["job_id"], state=job.get("state"),
                          scope="One canonical MCP resident gate submitted; completion and receipt validation remain required")
        else:
            result["submitted"] = False
    except BaseException as error:
        result.update(ok=False, error=type(error).__name__ + ": " + str(error))
    result["finished_unix"] = time.time()
    (args.record_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"ok": result["ok"], "submitted": result.get("submitted", False),
                      "gate_passed": False, "job_id": result.get("job_id"),
                      "result": str(args.record_dir / "result.json"), "error": result.get("error")}))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
