from pathlib import Path
import hashlib,json,os,subprocess,time
ROOT=Path("/home/ustad/OSTADIX-o10-m2-20261112")
BASE=Path("/home/ustad/.cache/o10-m2-acceptance-20261113")
REVISION="72e90d76420ff5c331232b5e3fe7c20e30761e41"
def identity(path):
    path=Path(path);data=path.read_bytes()
    return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
def document(path):return json.loads(Path(path).read_text())
def main():
    plan_path=BASE/"m2-final-binder-plan-r2.json"
    assert identity(plan_path)["sha256"]=="6c70ed7e8fba921d4ac9420525385875cd7df3e7375648c7e127a7d6beb36e6d"
    plan=document(plan_path)
    assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()==REVISION
    assert subprocess.check_output(["git","status","--porcelain"],cwd=ROOT,text=True)==""
    envelope=document(BASE/"guest-regressions-r2/result.json")
    shared=document(BASE/"guest-regressions-r2/six-gates/result.json")
    status=document(BASE/"guest-regressions-r2-execution/final-status.json")
    status=status.get("structuredContent",status)
    assert status["state"]=="completed" and status["exit_code"]==0 and status["error"] is None
    assert status["cleanup"]["child_reaped"] is True and status["cleanup"]["logs_drained"] is True
    assert envelope["ok"] is True and envelope["source_revision"]==envelope["mcp_release"]==REVISION and envelope["skips"]==[]
    assert shared["ok"] is True and len(shared["gates"])==6 and all(row["ok"] is True for row in shared["gates"])
    for key,row in plan["completed_prerequisites"].items():assert identity(row["path"])["sha256"]==row["sha256"],key
    for name,row in document(BASE/"guest-regressions-r2-execution/sources-before.json").items():
        assert identity(ROOT/name)["sha256"]==row["sha256"],name
    assert not (BASE/"acceptance-r2.json").exists()
    execution=BASE/"acceptance-r2-execution";assert not execution.exists();execution.mkdir()
    env=dict(os.environ);env.update(document("/home/ustad/.local/state/ostadix/o10-m2-postmerge-mcp-r4-20261113/bridge-env.json"));env["PYTHONDONTWRITEBYTECODE"]="1"
    def call(tool,args,label):
        p=subprocess.run(["python3","-B",str(ROOT/"scripts/ostadix_mcp_client.py"),tool,json.dumps(args)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=60)
        (execution/(label+".json")).write_text(p.stdout);(execution/(label+".stderr")).write_text(p.stderr)
        assert p.returncode==0 and not p.stderr,(tool,p.returncode)
        wrapped=json.loads(p.stdout);assert wrapped.get("isError") is not True
        return wrapped
    observed=call("o_env",{},"current-env").get("structuredContent")
    assert observed["buildCommitMatchesRuntimeSource"] is True and observed["binary"]["hashSource"]=="running_process_inode"
    assert observed["binary"]["sha256"]=="694ae45ecd21bc376ae0047afee3e70975ddd835c942a37a984b3d3d2b069f3a"
    assert observed["buildSource"]["commit"]==observed["runtimeSource"]["commit"]==REVISION
    assert observed["buildSource"]["dirty"] is False and observed["runtimeSource"]["dirty"] is False
    payload=plan["request"]["arguments"]
    (execution/"request.json").write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n")
    (execution/"SUBMISSION-ATTEMPT.json").write_text(json.dumps({"unix":time.time(),"rule":"One read-only binder request; unknown submission is retained and never automatically repeated."},indent=2)+"\n")
    wrapped=call("o_cli",payload,"start")
    status=wrapped.get("structuredContent") or json.loads(wrapped["content"][0]["text"])
    assert isinstance(status.get("job_id"),str),"unknown binder submission; inspect raw response"
    (execution/"start-structured.json").write_text(json.dumps(status,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"job":status,"execution":str(execution),"scope":"Read-only final evidence binder submitted once. Completion remains required; no VM or service launched."}))
if __name__=="__main__":main()
