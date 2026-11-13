#!/usr/bin/env python3
"""Refresh the MCP stamp at the final source checkpoint; preserve all durable origin tools."""
import argparse,fcntl,hashlib,json,os,shutil,subprocess,time
from pathlib import Path
ROOT=Path("/home/ustad/OSTADIX-o10-m2-20261112")
ORIGIN=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-toolchain-r1-20261113")
BASE=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-mcp-r3-20261113")
TARGET=Path("/dev/shm/o10-m2-postmerge-toolchain-r1-20261113/mcp-target")
ORIGIN_REVISION="7c12ac5fed09786e7f932b4b50ffffe4b48a2148"
CARGO="/home/ustad/.cargo/bin/cargo"
def sha(path):
 h=hashlib.sha256()
 with Path(path).open("rb") as f:
  for block in iter(lambda:f.read(1048576),b""):h.update(block)
 return h.hexdigest()
def desc(p):
 p=Path(p);return {"path":str(p),"bytes":p.stat().st_size,"sha256":sha(p)}
def git(args):return subprocess.run(["git",*args],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()
def sources():return {n:sha(ROOT/n) for n in git(["ls-files"]).splitlines() if (ROOT/n).is_file()}
parser=argparse.ArgumentParser();parser.add_argument("--revision",required=True);args=parser.parse_args()
revision=args.revision
assert git(["rev-parse","HEAD"])==revision and git(["status","--porcelain","--untracked-files=all"])==""
assert not (BASE/"build.json").exists()
origin=json.loads((ORIGIN/"build.json").read_text())
assert origin["ok"] and origin["source_unchanged"] and origin["revision"]==ORIGIN_REVISION
for name,d in origin["binaries"].items():assert sha(d["path"])==d["sha256"],name
prior_mcp=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-mcp-r2-20261113/bin/ostadix-mcp")
assert sha(prior_mcp)=="14a28692aeb8bf4554e3789ac4d972a42b2f74feb1367eec26377aba12bce9d5"
before=sources()
old=origin["source_sha256_after"]
changes={n:{"before":old.get(n),"after":before.get(n)} for n in set(old)|set(before) if old.get(n)!=before.get(n)}
freeze_path=Path("/home/ustad/.cache/o10-m2-acceptance-20261113/namespace-generation-fix-r1/source-freeze.json")
assert sha(freeze_path)=="c91debcbd5f5965bfc7409bcb28d543537de6a183a8eb8b9ced1a9f27cd640eb"
freeze=json.loads(freeze_path.read_text())
assert freeze["ok"] and freeze["toolchain_origin_revision"]==ORIGIN_REVISION
assert changes==freeze["tracked_source_overlay_from_toolchain_origin"],changes
rust_changes={n for n in changes if n.endswith((".rs",".toml")) or Path(n).name=="Cargo.lock"}
assert rust_changes=={"fuzz/Cargo.lock"},rust_changes
BASE.mkdir(exist_ok=True);(BASE/"bin").mkdir()
envsel={"CARGO_HOME":"/dev/shm/o10-m1-toolchain-20261113/cargo-home","RUSTUP_HOME":"/home/ustad/.rustup","CARGO_BUILD_JOBS":"2","PYTHONDONTWRITEBYTECODE":"1"}
cmd=[CARGO,"build","--release","--locked","--manifest-path",str(ROOT/"mcp/ostadix_lang_mcp_server/Cargo.toml"),"--target-dir",str(TARGET)]
record={"schema":"ostadix.o10-m2-mcp-stamp-build/v1","ok":False,"source_root":str(ROOT),"revision":revision,"toolchain_origin_revision":ORIGIN_REVISION,"origin_build":desc(ORIGIN/"build.json"),"prior_stamped_mcp":desc(prior_mcp),"rust_implementation_source_unchanged":True,"source_sha256_before":before,"reviewed_source_overlay":changes,"reviewed_source_freeze":desc(freeze_path),"origin_binaries":origin["binaries"],"environment":envsel,"argv":cmd,"started_unix":time.time(),"scope":"MCP-only final checkpoint source stamp using freshly built 7c12 dependency cache; durable original server and 14 tools preserved; no native rebuild, VM or qualification"}
try:
 with Path("/dev/shm/o10-m1-toolchain-20261113/publication-build.lock").open("a+") as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  release=TARGET/"release";removed=[]
  paths=[*sorted((release/".fingerprint").glob("ostadix-mcp-server-*")),*sorted((release/"build").glob("ostadix-mcp-server-*")),*sorted((release/"deps").glob("ostadix_mcp-*")),release/"ostadix-mcp",release/"ostadix-mcp.d"]
  for p in paths:
   assert p.is_relative_to(release)
   if not p.exists():continue
   if p.is_dir():
    removed.extend(desc(f) for f in p.rglob("*") if f.is_file());shutil.rmtree(p)
   else:removed.append(desc(p));p.unlink()
  record["removed_disposable_package_closure"]=removed
  (BASE/"plan.json").write_text(json.dumps(record,indent=2)+"\n")
  env={**os.environ,**envsel};env.pop("CARGO_NET_OFFLINE",None)
  with (BASE/"build.stdout.log").open("w") as out,(BASE/"build.stderr.log").open("w") as err:
   p=subprocess.run(cmd,cwd=ROOT,env=env,stdout=out,stderr=err,timeout=1800)
  record["exit_code"]=p.returncode
  assert p.returncode==0,"MCP locked stamp build failed"
  assert sources()==before and git(["rev-parse","HEAD"])==revision and git(["status","--porcelain","--untracked-files=all"])==""
  target=release/"ostadix-mcp";output=BASE/"bin/ostadix-mcp";assert not output.exists();shutil.copy2(target,output);output.chmod(0o755)
  assert sha(target)==sha(output)
  binaries={n:d for n,d in origin["binaries"].items() if n!="ostadix-mcp"}
  binaries["ostadix-mcp"]={**desc(output),"built_path":str(target),"elf_machine":62}
  assert output.read_bytes()[:4]==b"\x7fELF" and int.from_bytes(output.read_bytes()[18:20],"little")==62
  for name,d in origin["binaries"].items():assert sha(d["path"])==d["sha256"],name
  assert sha(prior_mcp)==record["prior_stamped_mcp"]["sha256"]
  record.update(ok=True,source_unchanged=True,source_sha256_after=sources(),source_revision_after=git(["rev-parse","HEAD"]),source_status_after=git(["status","--porcelain","--untracked-files=all"]),binaries=binaries)
except BaseException as e:
 record["error"]=type(e).__name__+": "+str(e);raise
finally:
 record["finished_unix"]=time.time()
 record["stdout"]=desc(BASE/"build.stdout.log") if (BASE/"build.stdout.log").exists() else None
 record["stderr"]=desc(BASE/"build.stderr.log") if (BASE/"build.stderr.log").exists() else None
 (BASE/"build.json").write_text(json.dumps(record,indent=2)+"\n")
print(json.dumps({"ok":record["ok"],"revision":revision,"mcp":record.get("binaries",{}).get("ostadix-mcp"),"source_unchanged":record.get("source_unchanged")}))
