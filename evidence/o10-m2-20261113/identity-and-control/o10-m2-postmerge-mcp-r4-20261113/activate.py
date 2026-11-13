#!/usr/bin/env python3
"""Activate a new private bridge using only the audited freshly built tools."""
from pathlib import Path
import argparse, hashlib, json, os, subprocess, time

BASE=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-mcp-r4-20261113")
ORIGIN=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-toolchain-r1-20261113")
ROOT=Path("/home/ustad/OSTADIX-o10-m2-20261112")
parser=argparse.ArgumentParser();parser.add_argument("--revision",required=True)
REVISION=parser.parse_args().revision
ORIGIN_REVISION="7c12ac5fed09786e7f932b4b50ffffe4b48a2148"

def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda:f.read(1048576),b""):h.update(block)
    return h.hexdigest()

build=json.loads((BASE/"build.json").read_text())
assert build.get("ok") is True and build.get("source_unchanged") is True
assert build["revision"]==REVISION and build["toolchain_origin_revision"]==ORIGIN_REVISION
assert build["rust_implementation_source_unchanged"] is True
assert subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()==REVISION
binaries=build["binaries"]
for name,row in binaries.items():
    assert sha(row["path"])==row["sha256"],name
links={}
for name,row in binaries.items():
    if name=="ostadix-mcp":continue
    link=BASE/"bin"/name
    if not link.exists():link.symlink_to(row["path"])
    assert link.resolve()==Path(row["path"]).resolve() and sha(link)==row["sha256"]
    links[name]={"path":str(link),"target":str(link.resolve()),"sha256":row["sha256"]}
for alias,name in [("ostadix-evaluator","O"),("o","o-cli")]:
    link=BASE/"bin"/alias
    if not link.exists():link.symlink_to(binaries[name]["path"])
    assert sha(link)==binaries[name]["sha256"]
    links[alias]={"path":str(link),"target":str(link.resolve()),"sha256":binaries[name]["sha256"]}
(BASE/"private-tool-links.json").write_text(json.dumps({"schema":"ostadix.private-adjacent-tool-links/v1","links":links,"scope":"Private command catalog links select the unchanged audited7c12-origin tools"},indent=2)+"\n")
selected={
 "OSTADIX_MCP":binaries["ostadix-mcp"]["path"],"O_LANG_ROOT":str(ROOT),
 "O_BACKENDS_DIR":str(ROOT/"backends"),
 "OSTADIX_MCP_CLIENT_DIR":"/tmp/o10-m2-postmerge-final-r4-20261113",
 "O_LANG_EVALUATOR_BIN":binaries["O"]["path"],"O_LANG_OLANGC_BIN":binaries["olangc"]["path"],
 "O_LANG_OCLI_BIN":binaries["o-cli"]["path"],"O_LANG_OCOREC_BIN":binaries["ocorec"]["path"],
 "OCOREC_BIN":binaries["ocorec"]["path"],"OLANG":binaries["O"]["path"],
 "O_BACKEND_STEP_TIMEOUT_MS":"3600000","PYTHONDONTWRITEBYTECODE":"1",
 "PATH":str(BASE/"bin")+os.pathsep+str(ORIGIN/"bin")+os.pathsep+os.environ.get("PATH","")}
(BASE/"bridge-env.json").write_text(json.dumps(selected,indent=2)+"\n")
env={**os.environ,**selected}
def invoke(method,args=None,label=None):
    argv=["python3","-B",str(ROOT/"scripts/ostadix_mcp_client.py"),method]
    if args is not None:argv.append(json.dumps(args))
    p=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,text=True,timeout=120)
    prefix=label or method.lstrip("-")
    (BASE/(prefix+".stdout")).write_text(p.stdout)
    (BASE/(prefix+".stderr")).write_text(p.stderr)
    assert p.returncode==0,(method,p.stdout[-1500:],p.stderr[-1500:])
    try:value=json.loads(p.stdout)
    except json.JSONDecodeError:value={"raw_text":p.stdout,"returncode":p.returncode}
    assert not isinstance(value,dict) or value.get("isError") is not True,(method,value)
    (BASE/(prefix+".json")).write_text(json.dumps(value,indent=2)+"\n")
    return value
tools=invoke("--list-tools",label="fresh-tools")
names={r["name"] for r in tools["tools"]}
assert {"o_env","o_doctor","o_cli","o_execute","o_job_status","o_job_read"}.issubset(names)
status=invoke("--status",label="fresh-status")
invoke("o_capabilities",{"query":"kernel o10 qualification"},label="fresh-capabilities")
invoke("o_guide",{"topic":"compiler"},label="fresh-guide-compiler")
observed=invoke("o_env",{},label="fresh-env")["structuredContent"]
assert observed["buildCommitMatchesRuntimeSource"] is True
assert observed["buildSource"]["commit"]==observed["runtimeSource"]["commit"]==REVISION
assert Path(observed["buildSource"]["sourceRoot"]).resolve()==ROOT
assert Path(observed["runtimeSource"]["canonicalRoot"]).resolve()==ROOT
assert observed["binary"]["hashSource"]=="running_process_inode"
assert observed["binary"]["sha256"]==binaries["ostadix-mcp"]["sha256"]
seen={r["name"]:r["binary"] for r in observed["tools"]}
for name in ["O","olangc"]:assert seen[name]["sha256"]==binaries[name]["sha256"]
doctor=invoke("o_doctor",{"execution_check":True,"timeout_secs":10},label="fresh-doctor")
assert doctor["structuredContent"]["executionCheck"]["passed"] is True
invoke("o_runtimes",{},label="fresh-runtimes")
invoke("o_cli",{"command":"ocorec","args":["--help"],"timeout_secs":30},label="fresh-ocorec-help")
invoke("o_cli",{"command":"kernel","args":["unified-build","--help"],"timeout_secs":30},label="fresh-unified-build-help")
entries=[b.decode() for b in (Path("/proc")/str(status["mcp_pid"])/"environ").read_bytes().split(b"\0")
         if b.startswith((b"O_BACKEND_STEP_TIMEOUT_MS=",b"PYTHONDONTWRITEBYTECODE="))]
assert "O_BACKEND_STEP_TIMEOUT_MS=3600000" in entries
assert "PYTHONDONTWRITEBYTECODE=1" in entries
record={"schema":"ostadix.o10-m2-fresh-toolchain-alignment/v1","ok":True,"revision":REVISION,
        "root":str(ROOT),"private_tool_links":json.loads((BASE/"private-tool-links.json").read_text()),"toolchain_origin_revision":ORIGIN_REVISION,"origin_build":str(ORIGIN/"build.json"),"mcp":binaries["ostadix-mcp"],"status":status,"binaries":binaries,
        "built_source_dirty":observed["buildSource"].get("dirty"),
        "runtime_source_dirty":observed["runtimeSource"].get("dirty"),
        "selected_server_environment":entries,"observed_unix":time.time(),
        "scope":"Final-checkpoint stamped MCP with exact running inode/root/revision and new schema session; fourteen unchanged x86 tools retain their separate 7c12 locked-build origin; fixed Python doctor smoke only; no component or guest qualification"}
(BASE/"alignment.json").write_text(json.dumps(record,indent=2)+"\n")
print(json.dumps({"ok":True,"root":str(ROOT),"revision":REVISION,"mcp":binaries["ostadix-mcp"],
                  "ocorec":binaries["ocorec"],"O":binaries["O"],"status":status}))
