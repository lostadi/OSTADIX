#!/usr/bin/env python3
"""Read-only join of one managed execution, its command, full logs and result."""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path

SCHEMA = "ostadix.o10-bound-execution/v1"
FORMATS = {"primary": "primary-json", "resident": "resident-text",
           "guest": "shared-six-json", "ordinary": "ordinary-ovalue"}

def need(value, message):
    if not value:
        raise ValueError(message)

def read_ref(ref):
    need(isinstance(ref, dict), "typed file identity required")
    path = Path(ref.get("path", ""))
    need(path.is_absolute() and path.is_file() and not path.is_symlink()
         and path.resolve() == path, "regular canonical evidence path required")
    raw = path.read_bytes()
    need(type(ref.get("bytes")) is int and ref["bytes"] == len(raw)
         and ref.get("sha256") == hashlib.sha256(raw).hexdigest(), "evidence bytes/hash changed")
    return path, raw

def decode_json(raw):
    def reject_constant(value):
        raise ValueError("non-finite JSON constant: " + value)
    def finite_float(value):
        number = float(value)
        need(math.isfinite(number), "non-finite JSON number")
        return number
    return json.loads(raw, parse_constant=reject_constant, parse_float=finite_float)

def same_json(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)

def doc_ref(ref):
    path, raw = read_ref(ref)
    return path, decode_json(raw)

def status_ref(ref):
    _, wrapped = doc_ref(ref)
    need(isinstance(wrapped, dict) and wrapped.get("isError") is not True, "managed tool error")
    value = wrapped.get("structuredContent", wrapped)
    need(isinstance(value, dict), "managed status missing")
    return value

def last_json(raw):
    lines = raw.decode("utf-8").strip().splitlines()
    need(bool(lines), "printed terminal summary missing")
    return decode_json(lines[-1])

def result_name(value):
    need(isinstance(value, dict) and isinstance(value.get("result"), str), "summary result missing")
    return Path(value["result"]).resolve()

def _validate_execution(proof_path, expected_result_path, role, seen_job_ids):
    need(role in FORMATS, "unknown execution role")
    proof = decode_json(Path(proof_path).read_bytes())
    need(proof.get("schema") == SCHEMA and proof.get("role") == role
         and proof.get("summary_format") == FORMATS.get(role), "execution role/schema differs")
    result_path, result = doc_ref(proof["result"])
    terminal_path, terminal = doc_ref(proof["terminal_result"])
    need(result_path == Path(expected_result_path).resolve(), "execution selected another result")
    need(result.get("gate_passed" if role in {"primary", "resident"} else "ok") is True,
         "actual result did not pass")
    start, final = status_ref(proof["start_status"]), status_ref(proof["final_status"])
    job, pid = final.get("job_id"), final.get("pid")
    need(isinstance(job, str) and job and job not in seen_job_ids
         and type(pid) is int and pid > 0, "managed job reused or PID invalid")
    need(proof.get("job_id") == job and type(proof.get("pid")) is int and proof["pid"] == pid,
         "proof/managed identity differs")
    need(type(start.get("pid")) is int and (start.get("job_id"), start.get("pid")) == (job, pid), "managed start/final identity differs")
    need(final.get("state") == "completed" and type(final.get("exit_code")) is int
         and final["exit_code"] == 0 and final.get("error") is None
         and final.get("signal") is None, "managed execution did not complete normally")
    need(start.get("state") in {"running", "completed"}
         and start.get("error") is None and start.get("signal") is None
         and start.get("input_error") is None
         and (start.get("state") == "running" and start.get("exit_code") is None
              or start.get("state") == "completed" and type(start.get("exit_code")) is int
              and start["exit_code"] == 0), "initial managed state was not admissible")
    need(final.get("input_error") is None, "terminal managed input failed")
    cleanup = final.get("cleanup", {})
    need(cleanup.get("child_reaped") is True and cleanup.get("logs_drained") is True
         and type(cleanup.get("session_id")) is int and cleanup.get("session_id") == pid, "managed cleanup/PID join incomplete")
    request_path, request = doc_ref(proof["api_request"])
    _, command = doc_ref(proof["command"])
    need(isinstance(request, dict) and isinstance(request.get("cwd"), str)
         and Path(request["cwd"]).is_absolute() and Path(request["cwd"]).is_dir()
         and Path(request["cwd"]).resolve() == Path(request["cwd"]), "explicit canonical request cwd required")
    if proof["api_tool"] == "o_execute":
        need(request.get("action", "execute") == "execute"
             and request.get("mode", "direct") == "direct"
             and isinstance(request.get("source"), str) and bool(request["source"])
             and request.get("path") is None, "ordinary request must be execute/direct and source-only")
    observed_inputs = []
    for observation in (start, final):
        if "input" in observation:
            observed = observation["input"]
            need(isinstance(observed, dict), "observed input must be an object")
            need("cwd" not in observed or observed["cwd"] == request["cwd"],
                 "observed request cwd differs")
            observed_inputs.append(observed)
            if proof["api_tool"] == "o_execute":
                expected = {"kind": "ordinary", "path": None, "source_inline": True, "temporary_source": False}
                need(all(key not in observed or same_json(observed[key], value)
                         for key, value in expected.items()), "observed inline source context differs")
        if proof["api_tool"] == "o_execute":
            need(isinstance(request.get("source"), str) and bool(request["source"]), "inline ordinary source required")
            need("action" not in observation or observation["action"] == request.get("action", "execute"), "observed action differs")
            need("mode" not in observation or observation["mode"] == request.get("mode", "direct"), "observed mode differs")
    if len(observed_inputs) == 2:
        need(all(same_json(observed_inputs[0][key], observed_inputs[1][key])
                 for key in observed_inputs[0].keys() & observed_inputs[1].keys()),
             "start/final observed input contradicts")
    need(all(key not in start or key not in final or same_json(start[key], final[key])
             for key in ("action", "mode")), "start/final observed context contradicts")
    need(command.get("managed_job") == job and type(command.get("managed_pid")) is int and command["managed_pid"] == pid
         and type(command.get("returncode")) is int and command["returncode"] == 0
         and command.get("timed_out") is False, "command/managed identity differs")
    need(command.get("binding_basis") == "canonical-api" and command.get("os_argv_claimed") is False
         and same_json(command.get("canonical_api"), {"tool": proof.get("api_tool"), "arguments": request})
         and command.get("cwd") == request.get("cwd"), "canonical API command/request differs")
    need(same_json(command.get("result"), proof["result"]) and same_json(command.get("terminal_result"), proof["terminal_result"]),
         "command/result identity differs")
    logs = {}
    for stream in ("stdout", "stderr"):
        original, raw = read_ref(proof[stream + "_original"])
        copied, copy = read_ref(proof[stream + "_copy"])
        meta = final.get(stream, {})
        count = meta.get("bytes", meta.get("total_bytes"))
        need(original != copied and original == Path(meta.get("path", ""))
             and original.parent.name == job and original.name == stream + ".log"
             and type(count) is int and count == len(raw) and raw == copy
             and ("total_bytes" not in meta or type(meta["total_bytes"]) is int and meta["total_bytes"] == len(raw)),
             "full original/copied managed log differs")
        need(same_json(command.get(stream), proof[stream + "_copy"]), "command log identity differs")
        logs[stream] = raw
    raw = logs["stdout"]
    if role == "resident":
        tail = raw.decode("utf-8").strip().splitlines()
        need(terminal_path == result_path and tail[-2:] ==
             ["O10 resident live gate: PASS; full M1 remains unqualified", "Evidence: " + str(result_path)],
             "resident terminal summary differs")
    elif role == "ordinary":
        outer = last_json(raw)
        need(outer.get("ok") is True and outer.get("value", {}).get("t") == "text"
             and proof["api_tool"] == "o_execute"
             and outer.get("execution_evidence", {}).get("source_sha256")
             == hashlib.sha256(request.get("source", "").encode()).hexdigest(), "O execution/request differs")
        lines = outer["value"]["v"]["utf8"].strip().splitlines()
        need(lines[-1:] == ["ORDINARY_CONTROLLER_FINISHED"], "ordinary terminal marker missing")
        printed = decode_json(lines[-2])
        _, inner = doc_ref(command["inner_command"])
        need(same_json(printed, inner) and type(inner.get("returncode")) is int and inner["returncode"] == 0 and inner.get("timed_out") is False
             and inner.get("cwd") == request.get("cwd"), "printed actual controller command differs")
        inner_result = inner.get("result", {})
        need(Path(inner_result.get("path", "")).resolve() == result_path
             and inner_result.get("sha256") == proof["result"]["sha256"], "controller result differs")
        _, inner_stdout = read_ref(inner["stdout"]); read_ref(inner["stderr"])
        need(terminal_path == result_path and result_name(last_json(inner_stdout)) == result_path
             and last_json(inner_stdout).get("ok") is True, "ordinary result summary differs")
    else:
        summary = last_json(raw)
        need(result_name(summary) == terminal_path
             and summary.get("gate_passed" if role == "primary" else "ok") is True, "terminal result differs")
        if terminal_path != result_path:
            need(role == "guest" and terminal.get("ok") is True
                 and terminal.get("shared_result", {}).get("path") == str(result_path)
                 and terminal["shared_result"].get("sha256") == proof["result"]["sha256"],
                 "shared-six wrapper does not bind actual inner result")
    if proof["api_tool"] == "o_cli":
        args = request.get("args", [])
        need(isinstance(args, list) and all(isinstance(arg, str) for arg in args), "canonical args required")
        flags = [flag for arg in args for flag in ("--output", "--session") if flag == arg]
        need(len(flags) == 1 and args.index(flags[0]) + 1 < len(args)
             and Path(args[args.index(flags[0]) + 1]).resolve() == terminal_path.parent
             and command.get("canonical_argv") == ["o", request.get("command")] + args,
             "canonical request output/argv differs")
    else:
        need(role == "ordinary" and proof["api_tool"] == "o_execute", "unsupported API execution proof")
    seen_job_ids.add(job)
    return {"job_id": job, "pid": pid, "role": role, "result": proof["result"],
            "canonical_request": proof["api_request"], "command": proof["command"],
            "canonical_api": command["canonical_api"], "canonical_argv": command.get("canonical_argv"),
            "inner_command": command.get("inner_command"), "available_input_context_verified": True,
            "full_raw_logs_verified": True}


def validate_execution(proof_path, expected_result_path, role, seen_job_ids):
    try:
        return _validate_execution(proof_path, expected_result_path, role, seen_job_ids)
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise ValueError("malformed execution proof: " + str(error)) from error
