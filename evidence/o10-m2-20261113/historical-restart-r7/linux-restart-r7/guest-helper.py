
import base64,hashlib,json,os,pathlib,subprocess,sys,time
def emit(v):print("O10_M2_JSON "+base64.b64encode(json.dumps(v,sort_keys=True).encode()).decode(),flush=True)
def capture(argv):
 p=subprocess.run(argv,capture_output=True)
 return dict(argv=argv,returncode=p.returncode,stdout_base64=base64.b64encode(p.stdout).decode(),stderr_base64=base64.b64encode(p.stderr).decode())
def proc(pid):
 p=pathlib.Path("/proc")/str(pid);v=(p/"stat").read_text().rsplit(")",1)[1].split()
 return dict(pid=pid,ppid=int(v[1]),state=v[0],start=v[19],cmdline_base64=base64.b64encode((p/"cmdline").read_bytes()).decode())
def mount():
 r=[l.split() for l in pathlib.Path("/proc/mounts").read_text().splitlines() if l.split()[1]=="/"]
 assert len(r)==1 and r[0][0]=="/dev/vda" and r[0][2]=="ext4"
 return r[0]
mode,config_file=sys.argv[1:3];config_path=pathlib.Path(config_file)
assert config_path.is_file() and not config_path.is_symlink()
cfg=json.loads(config_path.read_text());assert isinstance(cfg,dict)
run=pathlib.Path(cfg["run"]);f=cfg["fixture"]
if mode=="prepare":
 assert not run.exists();run.mkdir(mode=0o700)
 v=subprocess.run(["apk","--version"],capture_output=True,check=True);assert v.stdout.decode()==f["apk_version_stdout"]
 for group in ("apks","keys"):
  for item in f[group]:
   p=pathlib.Path(item["path"]);assert p.is_file() and str(p.resolve())==str(p)
   assert hashlib.sha256(p.read_bytes()).hexdigest()==item["sha256"]
 assert {str(p) for p in pathlib.Path(f["keys_directory"]).iterdir()}=={r["path"] for r in f["keys"]}
 absence=capture(["apk","info","--installed",f["package"]])
 assert absence["returncode"]==1
 verification=capture(["apk","--no-network","--keys-dir",f["keys_directory"],"verify"]+[r["path"] for r in f["apks"]])
 if verification["returncode"]!=0:
  emit(dict(fixture_verified=False,verification=verification));sys.exit(0)
 assert "rw" in mount()[3].split(",")
 hook=pathlib.Path("/etc/apk/commit_hooks.d")/("o10-restart-"+cfg["nonce"])
 assert not hook.exists();hook.parent.mkdir(parents=True,exist_ok=True)
 body=base64.b64decode(cfg["commit_hook_base64"])
 hook.write_bytes(body);hook.chmod(0o755);os.sync()
 emit(dict(fixture_verified=True,apk_version=v.stdout.decode(),mount=mount(),verification=verification,package_absent=absence,
           hook_path=str(hook),hook_sha256=hashlib.sha256(body).hexdigest()))
elif mode=="writer":
 p=pathlib.Path(cfg["file"]);p.parent.mkdir();durable=hashlib.sha256()
 with p.open("xb") as stream:
  for directory in (p.parent.parent,p.parent):
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(fd)
   finally:os.close(fd)
  for i in range(64):
   block=bytes([i+1])*1048576
   assert stream.write(block)==len(block)
   stream.flush();os.fsync(stream.fileno());durable.update(block)
   progress=dict(bytes=(i+1)*1048576,sha256=durable.hexdigest(),fsync_complete_monotonic_seconds=time.monotonic())
   temporary=run/"writer-progress.tmp";temporary.write_text(json.dumps(progress))
   os.replace(temporary,run/"writer-progress.json")
   time.sleep(2)
 (run/"writer-done").write_text("complete")
elif mode=="worker":
 env=dict(os.environ,O10_RESTART_DIR=str(run),O10_RESTART_NONCE=cfg["nonce"],PYTHONDONTWRITEBYTECODE="1")
 writer=subprocess.Popen([sys.executable,__file__,"writer",str(config_path)],stdout=(run/"writer.stdout").open("wb"),stderr=(run/"writer.stderr").open("wb"),env=env)
 argv=["apk","--no-network","--repositories-file","/dev/null","--keys-dir",f["keys_directory"],"add"]+[r["path"] for r in f["apks"]]
 apk=subprocess.Popen(argv,stdout=(run/"apk.stdout").open("wb"),stderr=(run/"apk.stderr").open("wb"),env=env)
 (run/"children.json").write_text(json.dumps(dict(writer=proc(writer.pid),apk=proc(apk.pid),apk_argv=argv)))
 while writer.poll() is None or apk.poll() is None:time.sleep(.2)
elif mode=="status":
 logs={}
 for name in ("apk.stdout","apk.stderr","writer.stdout","writer.stderr","worker.stdout","worker.stderr"):
  p=run/name;raw=p.read_bytes() if p.exists() else b"";assert len(raw)<=1048576
  logs[name+"_base64"]=base64.b64encode(raw).decode()
 if not (run/"children.json").exists():
  emit(dict(ready=False,logs=logs))
 else:
  children=json.loads((run/"children.json").read_text());failed=False
  for key in ("writer","apk"):
   try:
    current=proc(children[key]["pid"])
    assert current["start"]==children[key]["start"]
    failed=failed or current["state"]=="Z";children[key]=current
   except FileNotFoundError:failed=True
  if failed:emit(dict(ready=False,failed=True,children=children,logs=logs))
  elif not (run/"apk-hook").exists() or not (run/"writer-progress.json").exists():emit(dict(ready=False,logs=logs))
  else:
   nonce,pid,parent,stage=(run/"apk-hook").read_text().split();assert nonce==cfg["nonce"] and stage=="pre-commit"
   chain=[];current=proc(int(pid))
   for i in range(16):
    chain.append(current)
    if current["pid"]==children["apk"]["pid"]:break
    current=proc(current["ppid"])
   assert chain[-1]["pid"]==children["apk"]["pid"]
   progress=json.loads((run/"writer-progress.json").read_text())
   size=pathlib.Path(cfg["file"]).stat().st_size
   assert 0<progress["bytes"]<=size<67108864 and not (run/"writer-done").exists()
   children.update(ready=True,file_bytes=size,durable_prefix=progress,hook_process_chain=chain,
                   nonce=nonce,apk_stage=stage,logs=logs,observed_monotonic_seconds=time.monotonic())
   emit(children)
elif mode=="cleanup-hook":
 hook=pathlib.Path("/etc/apk/commit_hooks.d")/("o10-restart-"+cfg["nonce"])
 existed=hook.exists()
 if existed:
  assert hook.read_bytes()==base64.b64decode(cfg["commit_hook_base64"])
  hook.unlink()
 emit(dict(removed_owned_hook=existed,hook_path=str(hook)))
elif mode=="database":
 emit(dict(info=capture(["apk","info","-vv"]),check=capture(["apk","--no-network","--simulate","fix"])))
elif mode=="recovered-file":
 p=pathlib.Path(cfg["file"]);size=p.stat().st_size;prefix=cfg["durable_prefix"]
 assert 0<prefix["bytes"]<=size<=67108864
 durable=hashlib.sha256();tail=hashlib.sha256()
 with p.open("rb") as stream:
  offset=0
  while offset<prefix["bytes"]:
   raw=stream.read(min(1048576,prefix["bytes"]-offset))
   assert raw and raw==bytes([offset//1048576+1])*len(raw)
   durable.update(raw);offset+=len(raw)
  assert durable.hexdigest()==prefix["sha256"]
  while True:
   raw=stream.read(1048576)
   if not raw:break
   tail.update(raw)
 emit(dict(bytes=size,durable_prefix_bytes=prefix["bytes"],durable_prefix_sha256=durable.hexdigest(),
           unknown_tail_bytes=size-prefix["bytes"],unknown_tail_sha256=tail.hexdigest(),
           file_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
           completion="unknown interrupted tail; only observed fsynced prefix validated",work_not_replayed=True))
elif mode=="quiesce":
 before=mount();assert "rw" in before[3].split(",");os.sync()
 result=capture(["mount","-o","remount,ro","/"]);assert result["returncode"]==0
 after=mount();assert "ro" in after[3].split(",") and "rw" not in after[3].split(",")
 emit(dict(before=before,remount=result,after=after))
else:raise ValueError("unknown fixed gate action")
