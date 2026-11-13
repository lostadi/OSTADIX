from pathlib import Path
import hashlib,json,os,re,subprocess,sys,time,tempfile,shutil
root=Path("/home/ustad/OSTADIX-o10-m0-20261112")
out=root/"evidence/o10-m0-20261112/final-unit-r3d"
out.mkdir(exist_ok=False)
bin=Path("/home/ustad/.local/state/ostadix/o10-toolchain-20261112/bin")
revision=subprocess.run(["git","rev-parse","HEAD"],cwd=root,check=True,capture_output=True,text=True).stdout.strip()
os.chdir(root)
env=dict(os.environ)
env.update({"OCOREC_BIN":str(bin/"ocorec"),"OCORE_U9FS_MANIFEST":"/home/ustad/.cache/okernel-u9fs-native-recipe/runs/x86_64-O1-final/native-codec.json","OSTADIX_9P_COMPONENT_PLAN9_PREFIX":"/home/ustad/.cache/plan9port-probe-rwtjr2p0/plan9port-1f1396913fb5372408f442ed26933f5ae4b399cd","OSTADIX_9P_COMPONENT_U9FS_ARCHIVE":"/home/ustad/.cache/okernel-u9fs-research/u9fs-fcec3e1e2e8e8c28b89270e6c44554c4ca9e50a9.tar.gz"})
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
paths=set()
for pattern in ("tests/test_okernel_*.py","tests/test_o10_*.py","scripts/verify_o10_*.py"):
    paths.update(str(p.relative_to(root)) for p in root.glob(pattern))
paths.update(("scripts/check_language_sources.py","scripts/verify_okernel_repro.py","ci/language-sources.json","scripts/verify_okernel_unified_client.py","scripts/verify_okernel_unified_runtime.py","tests/test_unified_client_acceptance.py","tests/test_unified_runtime_acceptance.py"))
hashes={p:sha(root/p) for p in sorted(paths)}
record={"schema":"ostadix.o10-m0-unit-regressions/v1","source_revision":revision,"mcp_release":revision,"source_sha256":hashes,"compiler_sha256":sha(bin/"ocorec"),"started":time.time(),"results":[],"skips":[],"ok":False}
def save(): (out/"result.json").write_text(json.dumps(record,indent=2)+"\n")
def run(name,argv,timeout=1800,extra_env=None):
    entry={"command":argv,"argv":argv,"started":time.time(),"timed_out":False,"environment_overrides":extra_env or {}}
    with (out/(name+".stdout")).open("w") as stdout,(out/(name+".stderr")).open("w") as stderr:
        try: entry["returncode"]=subprocess.run(argv,cwd=root,env=(env | (extra_env or {})),stdout=stdout,stderr=stderr,timeout=timeout).returncode
        except subprocess.TimeoutExpired: entry.update(returncode=None,timed_out=True)
    entry["finished"]=time.time()
    (out/(name+"-command.json")).write_text(json.dumps(entry,indent=2)+"\n")
    save()
    if entry["returncode"]!=0 or entry["timed_out"]: raise RuntimeError(name+" failed "+str(entry))
    return entry
try:
    component_path=out/"component/result.json"
    component=run("component",[sys.executable,"scripts/verify_o10_journal.py","--session",str(component_path.parent),"--mcp-release",revision,"--component-only"])
    component.update(path=str(component_path),sha256=sha(component_path))
    record["component"]=component
    normal_modules=["tests."+p.stem for p in sorted((root/"tests").glob("test_okernel_*.py")) if p.stem!="test_okernel_repository_staging"]
    normal=run("normal",[sys.executable,"-m","unittest","-v",*normal_modules])
    normal.update(group="normal",summary=(out/"normal.stderr").read_text(),skipped=False)
    record["results"].append(normal)
    ram_dir=Path(tempfile.mkdtemp(prefix="o10-unit-r3d-",dir="/dev/shm"))
    try:
        ram=run("ram-disk",[sys.executable,"-m","unittest","-v","tests.test_okernel_repository_staging"],extra_env={"TMPDIR":str(ram_dir)})
        ram.update(group="ram-disk",summary=(out/"ram-disk.stderr").read_text(),skipped=False)
        record["results"].append(ram)
    finally:
        shutil.rmtree(ram_dir)
    total=0
    for unit in record["results"]:
        counts=re.findall(r"^Ran ([0-9]+) tests in ",unit["summary"],re.M)
        if len(counts)!=1 or not re.search(r"^OK\s*$",unit["summary"],re.M) or re.search(r"\.\.\. skipped|^OK \(",unit["summary"],re.M): raise RuntimeError("unit count, final status or skips")
        total+=int(counts[0])
    if total!=288: raise RuntimeError("total must be 288, got "+str(total))
    targeted=run("admission-and-freezer",[sys.executable,"-m","unittest","-v","tests.test_unified_client_acceptance","tests.test_unified_runtime_acceptance","tests.test_o10_regressions","tests.test_freeze_okernel_unified_runtime"])
    targeted["summary"]=(out/"admission-and-freezer.stderr").read_text()
    record["targeted"]=targeted
    language_path=out/"language.json"
    language=run("language",[sys.executable,"scripts/check_language_sources.py","check","--o-bin",str(bin/"O"),"--ocorec",str(bin/"ocorec"),"--jobs","4","--json-report",str(language_path)])
    language.update(path=str(language_path),sha256=sha(language_path))
    record["language"]=language
    record["source_unchanged"]=hashes=={p:sha(root/p) for p in hashes}
    if not record["source_unchanged"]: raise RuntimeError("source drift")
    record["ok"]=True
except Exception as e: record["error"]=type(e).__name__+": "+str(e)
finally:
    record["finished"]=time.time();save()
print(json.dumps({"ok":record["ok"],"result":str(out/"result.json"),"error":record.get("error")}))
