#!/usr/bin/env python3
"""Bound execution joins; synthetic corruptions never dispatch work."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("verify_o10_execution", Path(__file__).resolve().parents[1] / "scripts/verify_o10_execution.py")
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

def ref(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True) + "\n").encode())
    return ref(path)

class Fixture:
    def __init__(self, root, role, wrap=False):
        self.root, self.role = root, role
        root.mkdir(parents=True)
        self.job, self.pid = "job-123-456-1-" + role, 1234
        self.result = root / "result.json"
        write(self.result, {"gate_passed" if role in {"primary", "resident"} else "ok": True})
        self.terminal = root / "outer.json" if role == "guest" else self.result
        if role == "guest":
            write(self.terminal, {"ok": True, "shared_result": ref(self.result)})
        tool = "o_execute" if role == "ordinary" else "o_cli"
        request = {"cwd": str(root), "background": True, "timeout_secs": 0}
        if tool == "o_cli":
            request.update(command="kernel", args=["o10-" + role, "--session" if role == "resident" else "--output", str(root)])
        else:
            request["source"] = "python^(print('completed'))_python"
        request_ref = write(root / "request.json", request)
        command = {"managed_job": self.job, "managed_pid": self.pid, "returncode": 0,
                   "timed_out": False, "binding_basis": "canonical-api", "os_argv_claimed": False,
                   "canonical_api": {"tool": tool, "arguments": request}, "cwd": str(root),
                   "result": ref(self.result), "terminal_result": ref(self.terminal)}
        if role == "ordinary":
            inner = {"returncode": 0, "timed_out": False, "cwd": str(root), "sequence": 0,
                     "result": ref(self.result),
                     "stdout": write(root / "inner.stdout", (json.dumps({"ok": True, "result": str(self.result)}) + "\n").encode()),
                     "stderr": write(root / "inner.stderr", b"")}
            command["inner_command"] = write(root / "inner-command.json", inner)
            outer = {"ok": True, "value": {"t": "text", "v": {"utf8": json.dumps(inner) + "\nORDINARY_CONTROLLER_FINISHED\n"}},
                     "execution_evidence": {"source_sha256": hashlib.sha256(request["source"].encode()).hexdigest()}}
            raw = (json.dumps(outer) + "\n").encode()
        elif role == "resident":
            raw = ("progress\nO10 resident live gate: PASS; full M1 remains unqualified\nEvidence: " + str(self.result) + "\n").encode()
        else:
            raw = (json.dumps({"gate_passed" if role == "primary" else "ok": True, "result": str(self.terminal)}) + "\n").encode()
        self.proof = {"schema": VERIFY.SCHEMA, "role": role, "summary_format": VERIFY.FORMATS[role],
                      "job_id": self.job, "pid": self.pid, "api_tool": tool,
                      "api_request": request_ref, "result": ref(self.result), "terminal_result": ref(self.terminal)}
        status = {"job_id": self.job, "pid": self.pid, "state": "completed", "exit_code": 0,
                  "error": None, "signal": None, "cleanup": {"session_id": self.pid, "child_reaped": True, "logs_drained": True}}
        for stream, data in (("stdout", raw), ("stderr", b"")):
            original = write(root / "original" / self.job / (stream + ".log"), data)
            copied = write(root / (stream + ".copy"), data)
            self.proof[stream + "_original"], self.proof[stream + "_copy"] = original, copied
            command[stream] = copied
            status[stream] = {"path": original["path"], "bytes": original["bytes"]}
        if tool == "o_cli":
            command["canonical_argv"] = ["o", request["command"]] + request["args"]
        self.proof["command"] = write(root / "command.json", command)
        start = {"job_id": self.job, "pid": self.pid, "state": "running"}
        self.proof["start_status"] = write(root / "start.json", {"structuredContent": start} if wrap else start)
        self.proof["final_status"] = write(root / "final.json", {"structuredContent": status} if wrap else status)
        self.path = root / "proof.json"
        self.save()
    def save(self):
        write(self.path, self.proof)
    def doc(self, key):
        return json.loads(Path(self.proof[key]["path"]).read_text())
    def change(self, key, fn):
        value = self.doc(key)
        fn(value)
        self.proof[key] = write(Path(self.proof[key]["path"]), value)
        self.save()
    def change_status(self, fn):
        def edit(value):
            fn(value.get("structuredContent", value))
        self.change("final_status", edit)
    def raw(self, fn):
        p = Path(self.proof["stdout_original"]["path"])
        data = fn(p.read_bytes())
        for key in ("stdout_original", "stdout_copy"):
            self.proof[key] = write(Path(self.proof[key]["path"]), data)
        self.change_status(lambda x: x["stdout"].update(bytes=len(data)))
        self.change("command", lambda x: x.update(stdout=self.proof["stdout_copy"]))
        self.save()
    def check(self, seen=None):
        return VERIFY.validate_execution(self.path, self.result, self.role, set() if seen is None else seen)

class BoundExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root, self.n = Path(self.tmp.name).resolve(), 0
    def fixture(self, role="primary", wrap=False):
        self.n += 1
        return Fixture(self.root / str(self.n), role, wrap)
    def reject(self, f):
        seen = set()
        with self.assertRaises((ValueError, OSError)):
            f.check(seen)
        self.assertEqual(seen, set(), "failed proof consumed a job ID")
    def test_all_four_actual_formats_and_status_wrappers(self):
        seen = set()
        for role in VERIFY.FORMATS:
            f = self.fixture(role, wrap=role in {"resident", "ordinary"})
            value = f.check(seen)
            self.assertTrue(value["full_raw_logs_verified"])
        self.assertEqual(len(seen), 4)
    def test_repeated_success_job_rejected(self):
        f = self.fixture(); seen = set(); f.check(seen)
        with self.assertRaises(ValueError): f.check(seen)
        self.assertEqual(seen, {f.job})
    def test_job_pid_start_final_and_command_joins(self):
        changes = [("job_id", "another"), ("pid", 999), ("pid", True)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                f = self.fixture(); f.change_status(lambda x: x.update({key: value})); self.reject(f)
        for key, value in [("managed_job", "other"), ("managed_pid", 999), ("managed_pid", True)]:
            f = self.fixture(); f.change("command", lambda x: x.update({key: value})); self.reject(f)
        f = self.fixture(); f.change("start_status", lambda x: x.update(pid=999)); self.reject(f)
    def test_unrelated_status_and_tool_error_rejected(self):
        f, other = self.fixture(), self.fixture()
        f.proof["final_status"] = other.proof["final_status"]; f.save(); self.reject(f)
        f = self.fixture(); f.change("final_status", lambda x: x.update(isError=True)); self.reject(f)
    def test_terminal_and_cleanup_are_mandatory(self):
        for key, value in [("state", "running"), ("exit_code", False), ("exit_code", 1), ("error", "failed"), ("signal", 15)]:
            f = self.fixture(); f.change_status(lambda x: x.update({key: value})); self.reject(f)
        for change in [lambda x: x.pop("cleanup"), lambda x: x["cleanup"].update(child_reaped=False),
                       lambda x: x["cleanup"].update(logs_drained=False), lambda x: x["cleanup"].update(session_id=999)]:
            f = self.fixture(); f.change_status(change); self.reject(f)
    def test_full_logs_not_tails_or_other_jobs(self):
        for change in [lambda x: x["stdout"].update(bytes=1), lambda x: x["stdout"].update(total_bytes=1),
                       lambda x: x["stdout"].update(path="/elsewhere/stdout.log")]:
            f = self.fixture(); f.change_status(change); self.reject(f)
        f = self.fixture(); f.proof["stdout_copy"] = write(Path(f.proof["stdout_copy"]["path"]), b"tail\n"); f.save(); self.reject(f)
        f = self.fixture(); f.proof["stdout_copy"] = f.proof["stdout_original"]; f.save(); self.reject(f)
    def test_changed_hash_bytes_and_symlink_rejected(self):
        for field, value in [("sha256", "0" * 64), ("bytes", 1), ("bytes", True)]:
            f = self.fixture(); f.proof["stdout_original"][field] = value; f.save(); self.reject(f)
        f = self.fixture(); target = Path(f.proof["stdout_copy"]["path"]); link = f.root / "link"; link.symlink_to(target)
        f.proof["stdout_copy"] = {**ref(target), "path": str(link)}; f.save(); self.reject(f)
    def test_canonical_request_and_command_join(self):
        for change in [lambda x: x.update(os_argv_claimed=True), lambda x: x.update(binding_basis="observed"),
                       lambda x: x.update(cwd="/tmp"), lambda x: x.update(canonical_argv=["fabricated"]),
                       lambda x: x["canonical_api"]["arguments"].update(timeout_secs=99), lambda x: x.update(returncode=False)]:
            f = self.fixture(); f.change("command", change); self.reject(f)
        f = self.fixture(); f.change("api_request", lambda x: x.update(cwd="relative")); self.reject(f)
    def test_api_output_selection_and_duplicate_flags_rejected(self):
        for args in [["x", "--output", "/tmp"], ["x", "--output"], ["x", "--output", "/tmp", "--session", "/tmp"], ["x", "--output", "/tmp", "--output", "/tmp"]]:
            f = self.fixture(); request = f.doc("api_request"); request["args"] = args
            f.proof["api_request"] = write(Path(f.proof["api_request"]["path"]), request)
            f.change("command", lambda x: x.update(canonical_api={"tool":"o_cli","arguments":request},canonical_argv=["o","kernel"]+args)); self.reject(f)
    def test_result_path_hash_and_failure_are_bound(self):
        f = self.fixture()
        with self.assertRaises(ValueError): VERIFY.validate_execution(f.path, f.root / "other.json", f.role, set())
        f.proof["result"]["sha256"] = "0"*64; f.save(); self.reject(f)
        f = self.fixture(); f.change("result", lambda x: x.update(gate_passed=False)); self.reject(f)
        f = self.fixture(); f.raw(lambda x: x.replace(b'"gate_passed": true', b'"gate_passed": false')); self.reject(f)
    def test_resident_exact_footer(self):
        for transform in [lambda x:x.replace(b"PASS;",b"FAIL;"),lambda x:x.replace(b"Evidence:",b"Evidence-wrong:"),lambda x:x+b"extra\n"]:
            f=self.fixture("resident"); f.raw(transform); self.reject(f)
    def test_guest_outer_binds_exact_inner(self):
        for key,value in [("path","/other/result.json"),("sha256","0"*64)]:
            f=self.fixture("guest"); f.change("terminal_result", lambda x: x["shared_result"].update({key:value}))
            f.change("command", lambda x:x.update(terminal_result=f.proof["terminal_result"])); self.reject(f)
    def test_ordinary_execution_source_and_marker(self):
        for transform in [lambda x:x.replace(b"ORDINARY_CONTROLLER_FINISHED",b"WRONG"),
                          lambda x:x.replace(hashlib.sha256(b"python^(print('completed'))_python").hexdigest().encode(),b"0"*64)]:
            f=self.fixture("ordinary"); f.raw(transform); self.reject(f)
    def test_ordinary_printed_command_and_inner_logs(self):
        f=self.fixture("ordinary"); c=f.doc("command"); p=Path(c["inner_command"]["path"]); inner=json.loads(p.read_text()); inner["returncode"]=1
        c["inner_command"]=write(p,inner); f.proof["command"]=write(Path(f.proof["command"]["path"]),c); f.save(); self.reject(f)
        f=self.fixture("ordinary"); inner=json.loads(Path(f.doc("command")["inner_command"]["path"]).read_text()); Path(inner["stdout"]["path"]).write_bytes(b"tampered\n"); self.reject(f)
    def test_json_boolean_number_substitutions_rejected(self):
        f=self.fixture(); f.change("command",lambda x:x["canonical_api"]["arguments"].update(timeout_secs=False)); self.reject(f)
        f=self.fixture(); f.change("command",lambda x:x["stderr"].update(bytes=False)); self.reject(f)
        f=self.fixture("ordinary"); c=f.doc("command"); p=Path(c["inner_command"]["path"]); inner=json.loads(p.read_text()); inner["sequence"]=False
        c["inner_command"]=write(p,inner); f.proof["command"]=write(Path(f.proof["command"]["path"]),c); f.save(); self.reject(f)
    def test_initial_state_must_be_admissible(self):
        for change in [lambda x:x.update(state="failed"),lambda x:x.update(state="cancelled"),
                       lambda x:x.update(state="timed_out"),lambda x:x.update(exit_code=1),
                       lambda x:x.update(error="failed"),lambda x:x.update(input_error="invalid"),
                       lambda x:x.update(state="completed",exit_code=False)]:
            f=self.fixture();f.change("start_status",change);self.reject(f)
        f=self.fixture();f.change("start_status",lambda x:x.update(state="completed",exit_code=0));self.assertTrue(f.check()["full_raw_logs_verified"])
    def test_available_input_context_and_contradictions(self):
        for field,value in [("cwd","/tmp"),("source_inline",False),("source_inline",1),("kind","other"),("path","/other.oc"),("temporary_source",True)]:
            f=self.fixture("ordinary");f.change("start_status",lambda x:x.update(input={field:value}));self.reject(f)
        for field,value in [("action","other"),("mode","other")]:
            f=self.fixture("ordinary");f.change("start_status",lambda x:x.update({field:value}));self.reject(f)
        f=self.fixture("ordinary");f.change("start_status",lambda x:x.update(input={"cwd":str(f.root),"kind":"ordinary","path":None,"source_inline":True,"temporary_source":False},action="execute",mode="direct"));self.assertTrue(f.check()["available_input_context_verified"])
        f=self.fixture("ordinary");f.change("start_status",lambda x:x.update(input={"extra":0}));f.change_status(lambda x:x.update(input={"extra":False}));self.reject(f)
        f=self.fixture();f.change("start_status",lambda x:x.update(input={"cwd":"/other"}));self.reject(f)
    def test_ordinary_request_shape_matches_observed_context(self):
        for key,value in [("action","check"),("mode","admitted"),("path","/other.oc"),("action",None),("mode",None)]:
            f=self.fixture("ordinary");request=f.doc("api_request");request[key]=value
            f.proof["api_request"]=write(Path(f.proof["api_request"]["path"]),request)
            f.change("command",lambda x:x.update(canonical_api={"tool":"o_execute","arguments":request}));self.reject(f)
        f=self.fixture("ordinary");request=f.doc("api_request");request.update(action="execute",mode="direct",path=None)
        f.proof["api_request"]=write(Path(f.proof["api_request"]["path"]),request)
        f.change("command",lambda x:x.update(canonical_api={"tool":"o_execute","arguments":request}));self.assertTrue(f.check()["available_input_context_verified"])
    def test_nonfinite_json_is_rejected_everywhere(self):
        for value in [float("nan"),float("inf"),float("-inf")]:
            f=self.fixture("ordinary");request=f.doc("api_request");request["timeout_secs"]=value
            f.proof["api_request"]=write(Path(f.proof["api_request"]["path"]),request)
            f.change("command",lambda x:x.update(canonical_api={"tool":"o_execute","arguments":request}));self.reject(f)
        for raw in ["NaN","Infinity","-Infinity","1e999"]:
            with self.subTest(raw=raw),self.assertRaises(ValueError):VERIFY.decode_json(raw)
        f=self.fixture();f.change("result",lambda x:x.update(extra=float("nan")));self.reject(f)
        f=self.fixture();f.raw(lambda x:x.rstrip()[:-1]+b',"extra":1e999}\n');self.reject(f)
    def test_unknown_schema_role_and_missing_fields(self):
        for key,value in [("schema","other"),("role","guest"),("summary_format","other")]:
            f=self.fixture(); f.proof[key]=value; f.save(); self.reject(f)
        f=self.fixture(); del f.proof["command"]; f.save(); self.reject(f)
        with self.assertRaises(ValueError): VERIFY.validate_execution(f.path,f.result,"unknown",set())

if __name__ == "__main__": unittest.main(verbosity=2)
