#!/usr/bin/env python3
"""Import a qualified Plan 9 namespace result into a stopped, isolated OKernel fork.

The package disk stays selected exactly as before. This is a sequential ABI
handoff, not concurrent Linux/Plan 9 domain scheduling. The default working
state is never an import target.
"""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("namespace_handoff_runner", ROOT / "scripts/okernel_package_domain.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class NamespaceCommitUncertain(RuntimeError):
    """Head replacement happened or its outcome cannot be read after an I/O error."""


def read_regular(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular control record: {path}")
    return path.read_bytes()


def same_content(left: dict, right: dict) -> bool:
    return all(left.get(key) == right.get(key) for key in ("bytes", "sha256"))


def validate_proof(proof: dict) -> tuple[dict, dict]:
    if proof.get("schema") != "ostadix.plan9-native-namespace-probe/v1" or proof.get("passed") is not True:
        raise ValueError("a successful original Plan 9 native namespace probe is required")
    for flag in ("native_operations_quiescent_before_export", "virtual_cpu_stopped_before_export"):
        if proof.get(flag) is not True:
            raise ValueError("Plan 9 export lacks a stopped, quiescent native transaction boundary")
    for key in ("namespace_before", "namespace_after"):
        artifact = proof[key]
        if type(artifact.get("bytes")) is not int or artifact["bytes"] != runner.NAMESPACE_GRANT["bytes"]:
            raise ValueError("Plan 9 namespace must contain the complete native volume")
        if not isinstance(artifact.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is None:
            raise ValueError("Plan 9 namespace digest is invalid")
        runner.checked_file(Path(artifact["path"]), artifact)
    if same_content(proof["namespace_before"], proof["namespace_after"]):
        raise ValueError("the Plan 9 roundtrip must produce a changed namespace")
    roundtrip = proof["roundtrip"]
    path = roundtrip.get("path", "")
    if not isinstance(path, str) or re.fullmatch(r"/work/[A-Za-z0-9_-]+", path) is None:
        raise ValueError("roundtrip must identify one ordinary file under the shared work directory")
    text = roundtrip.get("text")
    line = text.removesuffix("\n") if isinstance(text, str) else ""
    if not isinstance(text, str) or not line or len(text) > 512 or any(ord(char) < 32 or ord(char) > 126 for char in line):
        raise ValueError("roundtrip must record its exact printable nonce line")
    return proof["namespace_before"], proof["namespace_after"]


def import_namespace(state: Path, proof_file: Path) -> dict:
    if state.is_symlink():
        raise ValueError("target state must not be a symlink")
    state = state.resolve(strict=True)
    configured = Path(os.environ.get("OSTADIX_OKERNEL_STATE") or str(runner.DEFAULT_STATE.parent)) / "package-domain"
    if state in (runner.DEFAULT_STATE.resolve(), configured.expanduser().resolve()):
        raise ValueError("the working default OS cannot be a namespace handoff target")
    fork = json.loads(read_regular(state / "fork.json"))
    if fork.get("schema") != "ostadix.okernel-state-fork/v1" or fork.get("ok") is not True or fork.get("output") != str(state):
        raise ValueError("namespace handoff requires an explicitly created isolated state fork")
    proof_bytes = read_regular(proof_file)
    proof = json.loads(proof_bytes)
    before, after = validate_proof(proof)
    lock_path = state / "domain.lock"
    if lock_path.is_symlink():
        raise ValueError("domain lock must not be a symlink")
    with lock_path.open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("stop the isolated package domain before importing its namespace") from None
        head_file = state / "head.json"
        head_bytes = read_regular(head_file)
        head = json.loads(head_bytes)
        runner.validate_head(state, head)
        if head.get("namespace") is None or not same_content(head["namespace"], before):
            raise ValueError("Plan 9 ran from a different namespace; the selected saved pair was retained")
        runner.checked_file(Path(head["disk"]["path"]), head["disk"])
        runner.checked_file(Path(head["namespace"]["path"]), head["namespace"])
        generations = state / "namespace-generations"
        if generations.is_symlink():
            raise ValueError("namespace generation store must not be a symlink")
        destination = generations / (after["sha256"] + ".raw")
        candidate = generations / ("pending-handoff-" + uuid.uuid4().hex + ".raw")
        try:
            with Path(after["path"]).open("rb") as incoming, candidate.open("xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            runner.checked_file(candidate, after)
            candidate.chmod(0o400)
            if destination.exists() or destination.is_symlink():
                runner.checked_file(destination, after)
                candidate.unlink()
            else:
                candidate.replace(destination)
            runner.fsync_directory(generations)
            # Cooperating state writers hold the same lock. Also reject a
            # changed control record instead of replacing a different pair.
            if read_regular(head_file) != head_bytes:
                raise RuntimeError("selected state changed during namespace import")
            selected = copy.deepcopy(head)
            selected["previous_namespace"] = head["namespace"]
            selected["namespace"] = runner.identity(destination)
            selected["namespace_handoff"] = {
                "schema": "ostadix.plan9-namespace-handoff/v1",
                "proof": str(proof_file.resolve()),
                "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
                "previous_head_sha256": hashlib.sha256(head_bytes).hexdigest(),
                "roundtrip": proof["roundtrip"],
                "scope": "sequential original Plan 9 to Linux namespace handoff in an isolated fork"}
            runner.validate_head(state, selected)
            try:
                runner.write_json(head_file, selected)
            except OSError as error:
                # Atomic replacement precedes its directory fsync. Reporting
                # the old pair as retained after that point would be false.
                try:
                    observed = json.loads(read_regular(head_file))
                except (OSError, ValueError):
                    raise NamespaceCommitUncertain("head publication outcome could not be read after an I/O error; retain both generations and inspect head.json before retrying") from error
                if observed == selected:
                    raise NamespaceCommitUncertain("the new namespace pair is selected, but directory durability could not be confirmed; both generations remain available; inspect head.json before retrying") from error
                if observed != head:
                    raise NamespaceCommitUncertain("head changed during an I/O error; retain both generations and inspect head.json before retrying") from error
                raise
            return selected
        finally:
            candidate.unlink(missing_ok=True)


def verify_linux_recovery(state: Path, selected: dict, qemu: str, timeout: float) -> dict:
    """Use both original Linux filesystem calls and the original 9p client."""
    state = state.resolve()
    receipt = state / "plan9-linux-handoff-acceptance.json"
    if receipt.exists():
        history = state / "acceptance-history"
        history.mkdir(exist_ok=True)
        (history / ("plan9-linux-handoff-" + uuid.uuid4().hex + ".json")).write_bytes(receipt.read_bytes())
    result = {"schema": "ostadix.plan9-linux-namespace-handoff-acceptance/v1", "ok": False,
              "started": time.time(), "sessions": [], "checks": [],
              "imported_pair": selected, "scope": "sequential original Plan 9 and Linux access to one native store in isolated O-core VMs; no simultaneous domain scheduling"}
    runner.write_json(receipt, result)
    domain = None
    try:
        roundtrip = selected["namespace_handoff"]["roundtrip"]
        path, text = roundtrip["path"], shlex.quote(roundtrip["text"])
        # validate_proof restricts this to one simple work-file component.
        reference = "/work/.plan9-handoff-expected-" + uuid.uuid4().hex
        command = "printf '%s' " + text + " > " + reference + " && cmp " + reference + " /n/okernel" + path
        command += " && 9p -n read okernel" + path + " | cmp " + reference + " - && rm -- " + reference
        for phase in ("recovery", "restart"):
            domain = runner.Domain(state, qemu, timeout=timeout)
            result["sessions"].append(str(domain.session))
            if phase == "recovery" and not same_content(domain.namespace_identity, selected["namespace"]):
                raise RuntimeError("another generation was selected before Linux recovery")
            domain.ready()
            domain.command("pkg-9p status && " + command)
            if phase == "recovery":
                domain.command("pkg install plan9port", timeout=180)
                domain.wait(b"OKERNEL SOURCE PACKAGE plan9port VERIFIED", line=True)
            domain.save()
            result["checks"].append(phase + ": original Linux filesystem and original Plan9port 9p client read the exact original Plan 9-written nonce")
            domain.close()
            domain = None
        result.update(ok=True, finished=time.time(), final_pair=json.loads((state / "head.json").read_text()))
        return result
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        if domain is not None:
            domain.close()
        runner.write_json(receipt, result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--verify", action="store_true", help="boot the isolated Linux fork and verify original client reads and saved-state restart")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    try:
        selected = import_namespace(args.state.expanduser(), args.proof.expanduser())
        if args.verify:
            verify_linux_recovery(args.state.expanduser(), selected, args.qemu, args.timeout)
    except NamespaceCommitUncertain as error:
        parser.exit(2, f"Namespace handoff outcome requires inspection: {error}\n")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, TimeoutError) as error:
        parser.exit(1, f"Namespace handoff failed: {error}\n")
    print("Isolated Plan 9 namespace imported\nDisk retained: " + selected["disk"]["sha256"] +
          "\nNamespace: " + selected["namespace"]["sha256"])
    if args.verify:
        print("Original Linux recovery and restart: PASS\nEvidence: " + str(args.state.expanduser().resolve() / "plan9-linux-handoff-acceptance.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
