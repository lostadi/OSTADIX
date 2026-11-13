from pathlib import Path
import hashlib,json,os,shutil,subprocess,time
root=Path("/home/ustad/OSTADIX-o10-m2-20261112")
base=Path("/home/ustad/.cache/o10-m2-acceptance-20261113")
prepared_path=base/"m2-six-gate-preparation-r1.json"
prepared=json.loads(prepared_path.read_text())
def ident(path):
    path=Path(path);data=path.read_bytes()
    return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
assert ident(prepared_path)["sha256"]=="2e883e326a230ef98165ba47fc3d99a785b1757d9b93e20cd90a14965f4b2a97"
assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()==prepared["source_revision"]
assert subprocess.check_output(["git","status","--porcelain"],cwd=root,text=True)==""
threshold=34896609280
assert shutil.disk_usage(base).free>threshold,"prelaunch disk floor not met; no gate dispatched"
execution=base/"guest-regressions-r1-execution"
assert not execution.exists() and not (base/"guest-regressions-r1").exists()
execution.mkdir()
env=dict(os.environ)
env.update(json.loads(Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-mcp-r3-20261113/bridge-env.json").read_text()))
env["PYTHONDONTWRITEBYTECODE"]="1"
client=root/"scripts/ostadix_mcp_client.py"
def call(name,args,label):
    argv=["python3","-B",str(client),name]+([] if args is None else [json.dumps(args)])
    completed=subprocess.run(argv,cwd=root,env=env,capture_output=True,text=True,timeout=60)
    (execution/(label+".json")).write_text(completed.stdout)
    (execution/(label+".stderr")).write_text(completed.stderr)
    assert completed.returncode==0,(name,completed.returncode)
    try:value=json.loads(completed.stdout)
    except json.JSONDecodeError:
        assert name=="o_runtimes"
        return {"raw_text":completed.stdout,"returncode":completed.returncode}
    assert value.get("isError") is not True,name
    return value
schema=call("--list-tools",None,"current-tools")
cli=next(row["inputSchema"] for row in schema["tools"] if row["name"]=="o_cli")
assert {"command","args","cwd","background","timeout_secs","env"}<=set(cli["properties"])
wrapped=call("o_env",{},"current-env");provenance=wrapped.get("structuredContent",wrapped)
assert provenance["buildCommitMatchesRuntimeSource"] is True
assert provenance["binary"]["hashSource"]=="running_process_inode"
assert provenance["binary"]["sha256"]=="6bac8348f0aa3669ec026bd3ba43928a08d59766492639c4d82e5d791e2fe021"
for field in ("buildSource","runtimeSource"):
    assert provenance[field]["commit"]==prepared["source_revision"]
assert Path(provenance["buildSource"]["sourceRoot"]).resolve()==root
assert Path(provenance["runtimeSource"]["canonicalRoot"]).resolve()==root
assert provenance["buildSource"]["dirty"] is False and provenance["runtimeSource"]["dirty"] is False
doctor=call("o_doctor",{"execution_check":True,"timeout_secs":10},"current-doctor")
assert doctor["structuredContent"]["executionCheck"]["passed"] is True
call("o_runtimes",{},"current-runtimes")
profile=json.loads((Path(prepared["tool_request"]["arguments"]["args"][2])/"monitor-profile.json").read_text())
sources={**profile["source_sha256"],**prepared["shared_source_sha256"],
         "scripts/verify_o10_m2_regressions.py":prepared["wrapper"]["sha256"],
         "scripts/verify_o10_m2.py":"7410497aa4cdfcee4c52c7bcae22e4c16ffd0fe1f3610d8a57b9b893b5cb0490"}
captures={}
for name,expected in sorted(sources.items()):
    original=root/name;assert ident(original)["sha256"]==expected,name
    target=execution/"sources"/name;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(original,target);assert ident(target)["sha256"]==expected
    captures[name]=ident(target)
(execution/"sources-before.json").write_text(json.dumps(captures,indent=2,sort_keys=True)+"\n")
for label in ("restart_command","resident","runtime","seed_head","primary_binder"):
    row=prepared[label];assert ident(row["path"])==row,label
qemu=[]
for process in Path("/proc").iterdir():
    if not process.name.isdigit():continue
    try:
        argv=[os.fsdecode(value) for value in (process/"cmdline").read_bytes().split(b"\0") if value]
        if argv and Path(argv[0]).name.startswith("qemu-system"):
            qemu.append({"pid":int(process.name),"binary":argv[0]})
    except (OSError,PermissionError):pass
available=next(int(line.split()[1])*1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
resource={"observed_unix":time.time(),"free_disk_bytes":shutil.disk_usage(base).free,
          "minimum_prelaunch_bytes":threshold,"mem_available_bytes":available,
          "two_vm_ram_reservation_bytes":8589934592,"existing_qemu":qemu}
(execution/"resources-before.json").write_text(json.dumps(resource,indent=2,sort_keys=True)+"\n")
assert not qemu,"an unrelated QEMU occupies the global qualification VM reservation"
assert resource["free_disk_bytes"]>threshold and available>=8589934592
payload=prepared["tool_request"]["arguments"]
assert payload["args"][-1]=="--execute"
assert payload["args"][payload["args"].index("--jobs")+1]=="2"
assert payload["args"][payload["args"].index("--minimum-free-gib")+1]=="3.5"
(execution/"request.json").write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n")
started=time.time();wrapped=call("o_cli",payload,"start")
status=wrapped.get("structuredContent") or json.loads(wrapped["content"][0]["text"])
(execution/"start-structured.json").write_text(json.dumps(status,indent=2,sort_keys=True)+"\n")
matches=[]
for attempt in range(30):
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():continue
        try:
            argv=[os.fsdecode(value) for value in (process/"cmdline").read_bytes().split(b"\0") if value]
            if any(Path(value).name=="verify_o10_m2_regressions.py" for value in argv) and str(base/"guest-regressions-r1") in argv:
                fields=(process/"stat").read_text().rsplit(")",1)[1].split()
                matches.append({"pid":int(process.name),"ppid":int(fields[1]),"start_ticks":fields[19],
                    "argv":argv,"cwd":os.readlink(process/"cwd")})
        except (OSError,PermissionError,IndexError):pass
    if matches:break
    time.sleep(.1)
(execution/"observed-wrapper-process.json").write_text(json.dumps({"observed_unix":time.time(),"matches":matches,
    "scope":"Actual expanded wrapper process identity; no command resubmission."},indent=2,sort_keys=True)+"\n")
print(json.dumps({"job":status,"observed_wrapper":matches,"execution":str(execution),"started_unix":started,
                 "resources":resource},sort_keys=True))
