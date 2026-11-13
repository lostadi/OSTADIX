#!/usr/bin/env python3
"""Read-only current-source/build/runtime/tool binding, executed by the freshly aligned MCP."""
import hashlib,importlib.util,json,os,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path("/home/ustad/OSTADIX-o10-m2-20261112")
BASE=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-mcp-r4-20261113")
ORIGIN=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-toolchain-r1-20261113")
ACC=Path("/home/ustad/.cache/o10-m2-acceptance-20261113")
BUILD=ACC/"unified-build-qualification-r5";RUNTIME=ACC/"frozen-runtime-r6"
REVISION="72e90d76420ff5c331232b5e3fe7c20e30761e41"
def sha(p):
 h=hashlib.sha256()
 with Path(p).open("rb") as f:
  for block in iter(lambda:f.read(1048576),b""):h.update(block)
 return h.hexdigest()
def desc(p):
 p=Path(p);return {"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p)}
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
assert subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()==REVISION
assert subprocess.run(["git","status","--porcelain","--untracked-files=all"],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()==""
alignment=json.loads((BASE/"alignment.json").read_text())
assert alignment["ok"] and alignment["revision"]==REVISION and alignment["toolchain_origin_revision"]=="7c12ac5fed09786e7f932b4b50ffffe4b48a2148"
build=json.loads((BASE/"build.json").read_text());origin=json.loads((ORIGIN/"build.json").read_text())
for name,d in build["binaries"].items():assert sha(d["path"])==d["sha256"],name
for name,d in origin["binaries"].items():assert sha(d["path"])==d["sha256"],name
profile=json.loads((BUILD/"monitor-profile.json").read_text())
assert sha(BUILD/"monitor-profile.json")=="d5a5207a7b0e85963c98e7cefb378a69a32d77c70702aaa8cf783dcc909f964c"
assert sha(BUILD/"monitor.elf")=="30a91b43bb78e9202c983417e39609991554914ff0deb76998b69e19ea01dddb"
assert len(profile["source_sha256"])==26
for name,h in profile["source_sha256"].items():assert sha(ROOT/name)==h,name
for name,d in profile["artifacts"].items():
 assert desc(BUILD/name)["bytes"]==d["bytes"] and sha(BUILD/name)==d["sha256"],name
assert sha(profile["tools"]["ocorec"]["path"])==profile["tools"]["ocorec"]["sha256"]==build["binaries"]["ocorec"]["sha256"]
assert sha(ORIGIN/"pre-mcp-bin/ocorec")==sha(ORIGIN/"bin/ocorec")
v=load("current_runtime_binding_verifier",ROOT/"scripts/verify_okernel_unified_runtime.py")
assert sha(RUNTIME/"runtime.json")=="72a2dd96be602e10320d8a535be2788ca4dc0110b7feb1e5945964d45a68bdcd"
runtime=json.loads((RUNTIME/"runtime.json").read_text());v.validate_inventory(RUNTIME,runtime)
for name,pair in runtime["sources"].items():
 assert sha(ROOT/name)==pair["original"]["sha256"]==pair["frozen"]["sha256"]==sha(pair["frozen"]["path"]),name
for name,pair in runtime["build_copies"].items():
 assert sha(pair["original"]["path"])==pair["original"]["sha256"]==pair["frozen"]["sha256"]==sha(pair["frozen"]["path"]),name
frozen=v.load_frozen(RUNTIME);assert frozen.__file__==str(RUNTIME/"runtime/scripts/okernel_unified_world.py")
assert not list(RUNTIME.rglob("*.pyc"))
check=subprocess.run(["python3","-B",str(RUNTIME/"okernel-unified"),"check"],env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},capture_output=True,text=True,timeout=45);assert check.returncode==0
report={"schema":"ostadix.o10-m2-poststamp-artifact-validation/v1","ok":True,"revision":REVISION,"source_root":str(ROOT),"toolchain_origin_revision":origin["revision"],"alignment":desc(BASE/"alignment.json"),"stamp_build":desc(BASE/"build.json"),"origin_build":desc(ORIGIN/"build.json"),"binaries":build["binaries"],"monitor":desc(BUILD/"monitor.elf"),"profile":desc(BUILD/"monitor-profile.json"),"profile_ocorec":profile["tools"]["ocorec"],"native_sources_matched":26,"runtime":desc(RUNTIME/"runtime.json"),"runtime_inventory_files":len(runtime["inventory"]),"runtime_sources":runtime["sources"],"runtime_check":{"argv":["python3","-B",str(RUNTIME/"okernel-unified"),"check"],"exit_code":check.returncode,"stdout":check.stdout,"stderr":check.stderr},"observed_unix":time.time(),"scope":"Fresh final-checkpoint MCP process/schema alignment plus read-only native artifact, exact private admission and frozen-runtime provenance validation. No VM or milestone gate executed."}
(BASE/"artifact-validation.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"ok":True,"revision":REVISION,"runtime":report["runtime"],"profile":report["profile"],"monitor":report["monitor"],"sources":26,"runtime_files":len(runtime["inventory"])}))
