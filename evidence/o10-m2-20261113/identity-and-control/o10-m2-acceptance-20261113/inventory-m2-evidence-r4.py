from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,time
BASE=Path("/home/ustad/.cache/o10-m2-acceptance-20261113")
ROOT=Path("/home/ustad/OSTADIX-o10-m2-20261112")
LIMIT=16*1024*1024
BINARY_SUFFIXES={".ext4",".raw",".img",".qcow2",".elf",".o",".a",".so",".dtb",".initramfs",".apk",".gz",".zst",".xz",".tar",".bin",".Image"}
SKIP_COMPONENTS={"inputs","payload","disk-generations","namespace-generations","tools","target","root-target","mcp-target","build"}
def digest(data):return hashlib.sha256(data).hexdigest()
def identity(path):
    path=Path(path);data=path.read_bytes()
    return {"path":str(path),"bytes":len(data),"sha256":digest(data)}
def document(path):return json.loads(Path(path).read_text())
def main():
    parser=argparse.ArgumentParser(description="Inventory immutable small M2 evidence without copying or editing it.")
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--acceptance-result",type=Path,required=True)
    parser.add_argument("--expected-revision",required=True)
    parser.add_argument("--expected-seed-head-sha256",required=True)
    args=parser.parse_args();assert not args.output.exists()
    REVISION=args.expected_revision
    assert re.fullmatch(r"[0-9a-f]{40}",REVISION)
    assert re.fullmatch(r"[0-9a-f]{64}",args.expected_seed_head_sha256)
    accepted=args.acceptance_result.resolve(strict=True)
    assert accepted.is_relative_to(BASE) and not args.acceptance_result.is_symlink()
    acceptance=document(accepted)
    assert acceptance["ok"] is True and acceptance["full_milestone_qualified"] is True
    assert acceptance["source_revision"]==acceptance["mcp_release"]==REVISION and acceptance["skips"]==[]
    paths={}
    for name in ("restart","restart_command","resident","guest","component","component_log","unit","language","provenance"):
        descriptor=acceptance["inputs"][name]
        path=Path(descriptor["path"])
        assert path.resolve(strict=True).is_relative_to(BASE) and not path.is_symlink(),name
        actual=identity(path)
        assert actual["sha256"]==descriptor["sha256"],name
        if "bytes" in descriptor:assert actual["bytes"]==descriptor["bytes"],name
        paths[name]=path
    six=document(paths["guest"])
    assert six["ok"] is True and six["source_revision"]==six["mcp_release"]==REVISION and six["skips"]==[]
    shared=document(paths["guest"].parent/"six-gates/result.json")
    assert len(shared["gates"])==6 and all(row["ok"] is True for row in shared["gates"])
    seed=Path(six["seed_head"]["path"])
    assert seed.resolve(strict=True).is_relative_to(BASE) and not seed.is_symlink()
    assert identity(seed)["sha256"]==six["seed_head"]["sha256"]==args.expected_seed_head_sha256
    unit=document(paths["unit"])
    assert unit["ok"] is True and unit["source_revision"]==REVISION and unit["skips"]==[]
    groups={
      "current-restart":[paths["restart"].parent,Path(str(paths["restart"].parent)+"-execution")],
      "current-ordinary":[paths["unit"].parent,Path(str(paths["unit"].parent)+"-execution")],
      "current-resident":[paths["resident"].parent,Path(str(paths["resident"].parent)+"-execution")],
      "current-six-gates":[paths["guest"].parent,Path(str(paths["guest"].parent)+"-execution")],
      "current-final-binder":[accepted.parent/(accepted.stem+"-execution")],
      "current-helper-seed-preparation":[BASE/"helper-seed-r2-preparation"],
      "installer-fix":[Path("/home/ustad/.cache/o10-m2-installer-dotu-fix-20261113-r1"),
                       Path("/home/ustad/.cache/o10-m2-independent-acceptance-review-20261113/installer-fix-review-r1")],
      "historical-restart-r7":[BASE/"linux-restart-r7",BASE/"linux-restart-r7-execution",BASE/"restart-binder-r7"],
      "historical-ordinary-r5":[BASE/"ordinary-regressions-r5",BASE/"ordinary-regressions-r5-execution"],
      "historical-resident-r3":[BASE/"resident-r3",BASE/"resident-r3-execution",BASE/"resident-r3-validation-r1",BASE/"classification-current-r3"],
      "historical-failed-six-r1":[BASE/"guest-regressions-r1",BASE/"guest-regressions-r1-execution",BASE/"failed-batch-r1-closeout"],
      "historical-failure-r5":[BASE/"linux-restart-r5",BASE/"linux-restart-r5-execution",BASE/"runner-serialization-review-r1"],
      "historical-failure-r6":[BASE/"linux-restart-r6",BASE/"linux-restart-r6-execution"],
      "historical-restore-diagnosis":[BASE/"linux-restore-trace-r1",BASE/"linux-slot-reset-probe-r1",BASE/"linux-restore-review-r2"],
      "namespace-epoch-fix":[BASE/"namespace-generation-fix-r1",Path("/home/ustad/.cache/o10-m2-namespace-epoch-input-review-20261113")],
      "mode17-review":[Path("/home/ustad/.cache/o10-m2-mode17-input-review-20261113")],
    }
    restart_suffix=paths["restart"].parent.name.rsplit("-r",1)[-1]
    resident_name=paths["resident"].parent.name
    resident_suffix=resident_name.rsplit("-r",1)[-1]
    groups["current-restart-preparation"]=[BASE/("linux-restart-preparation-r"+restart_suffix)]
    groups["current-resident-preparation"]=[BASE/("resident-preparation-r"+resident_suffix)]
    groups["current-resident-validation"]=sorted(BASE.glob(resident_name+"-validation-*"))
    classification=BASE/("classification-current-r"+resident_name.rsplit("-r",1)[-1])
    groups["current-resident-classification"]=[classification]
    # Current synthetic EL2 fixture files are retained only from exact hashed unit logs.
    targeted_log=Path(unit["targeted"]["log"]["path"])
    assert identity(targeted_log)["sha256"]==unit["targeted"]["log"]["sha256"]
    contexts=re.findall(r"Actual EL2 context/preemption evidence: (/tmp/ostadix-unified-context-[A-Za-z0-9_-]+)",targeted_log.read_text())
    assert len(contexts)==len(set(contexts))==6
    groups["current-synthetic-el2"]=[Path(p) for p in contexts]
    fixture_descriptor=document(paths["restart"])["fixture"]
    fixture_path=Path(fixture_descriptor["path"])
    assert fixture_path.suffix==".json" and not fixture_path.is_symlink()
    assert identity(fixture_path)["sha256"]==fixture_descriptor["sha256"]
    explicit=[accepted,seed,fixture_path,Path(__file__),*paths.values(),
      BASE/"unified-build-r5-readback.json",BASE/"candidate-admission-r4/freeze-handoff.json",
      BASE/"candidate-admission-r4/independent-readback-r1.json",BASE/"frozen-runtime-r6/runtime.json"]
    # Include current and historical cache-only launch/controller/source inventories.
    for pattern in ("pr108-*.json","pr108-*.log","*controller-preparation*.json","*six*preparation*.json",
                    "m2-final-binder-plan*.json","launch-m2-six-*.py","launch-m2-six-*.json",
                    "launch-m2-six-*.stdout","launch-m2-six-*.stderr","launch-final-binder-*.py",
                    "evidence-inventory-*-independent-review.json","independent-*.json"):
        explicit+=sorted(BASE.glob(pattern))
    origin=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-toolchain-r1-20261113")
    for relative in ("build.json","pre-mcp-tools.json","cargo-input-audit/result.json",
                     "build-0.stdout.log","build-0.stderr.log","build-1.stdout.log","build-1.stderr.log"):
        explicit.append(origin/relative)
    for revision in ("r2","r3","r4"):
        stamp=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-mcp-"+revision+"-20261113")
        for relative in ("build.json","alignment.json","artifact-validation.json","fresh-env.json",
                         "build.py","activate.py","validate-artifacts.py"):
            candidate=stamp/relative
            if candidate.exists():explicit.append(candidate)
    rows={};excluded=[];missing=[];external={}
    def references(value,origin_path):
        if isinstance(value,dict):
            if isinstance(value.get("path"),str) and isinstance(value.get("sha256"),str):
                text=value["path"]
                if text.startswith(("/home/ustad/","/tmp/ostadix","/usr/","/dev/shm/")):
                    key=(text,value["sha256"])
                    external[key]={"identity":{k:value[k] for k in ("path","bytes","sha256") if k in value},
                                   "referenced_by":str(origin_path),"verification":"identity retained from original receipt; no binary/state copy"}
            for child in value.values():references(child,origin_path)
        elif isinstance(value,list):
            for child in value:references(child,origin_path)
    def include(path,label,relative=None,explicit=False):
        path=Path(path)
        if not path.exists():
            missing.append({"path":str(path),"group":label});return
        if path.is_symlink():
            excluded.append({"path":str(path),"reason":"symlink; identity retained through original manifests"});return
        if not path.is_file():return
        rel=relative or Path(path.name)
        if "bridge" in path.name.lower() or path.name in (".env","credentials.json"):
            excluded.append({"path":str(path),"reason":"private connection configuration"});return
        if path.suffix in BINARY_SUFFIXES or not explicit and any(part in SKIP_COMPONENTS for part in rel.parts):
            excluded.append({"path":str(path),"reason":"state, binary or copied payload; original manifests retain identity"});return
        before=path.stat()
        if before.st_size>LIMIT:
            excluded.append({"path":str(path),"bytes":before.st_size,"reason":"large raw artifact remains in original cache; reference only"});return
        data=path.read_bytes();after=path.stat()
        assert (before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns),str(path)
        if data.startswith(b"\x7fELF"):
            excluded.append({"path":str(path),"reason":"ELF binary; reference only"});return
        known_raw=path.suffix in (".json",".log",".stdout",".stderr",".txt",".md",".patch",".py",".oc",".O",".S",".sh",".c",".h",".dts",".toml",".yaml") or path.name in ("stdout","stderr")
        if not known_raw:
            try:text=data.decode("utf-8")
            except UnicodeDecodeError:
                excluded.append({"path":str(path),"reason":"binary input; reference only"});return
            if "\0" in text:
                excluded.append({"path":str(path),"reason":"binary input; reference only"});return
        row={"path":str(path),"bytes":len(data),"sha256":digest(data),"group":label,
             "package_relative_path":str(Path(label)/rel)}
        old=rows.get(str(path))
        if old is None:rows[str(path)]=row
        if path.suffix==".json":
            try:references(json.loads(data),path)
            except (ValueError,UnicodeDecodeError):pass
    for label,roots in groups.items():
        for directory in roots:
            if not directory.exists():
                missing.append({"path":str(directory),"group":label});continue
            listing=subprocess.run(["rg","--files","--hidden","--no-ignore",str(directory)],capture_output=True,text=True)
            assert listing.returncode in (0,1) and not listing.stderr,(str(directory),listing.returncode,listing.stderr)
            for name in listing.stdout.splitlines():
                include(Path(name),label,Path(directory.name)/Path(name).relative_to(directory))
    for path in explicit:include(path,"identity-and-control",Path(path.parent.name)/path.name,explicit=True)
    assert rows
    record={"schema":"ostadix.o10-m2-small-evidence-inventory/v1","ok":True,
      "controller":identity(Path(__file__)),"accepted_source_revision":REVISION,"accepted_seed_head":identity(seed),"acceptance":identity(accepted),
      "source_qualification_scope":acceptance["scope"],"included":sorted(rows.values(),key=lambda row:row["package_relative_path"]),
      "included_count":len(rows),"included_bytes":sum(row["bytes"] for row in rows.values()),
      "excluded":excluded,"missing_optional_paths":missing,"external_identities":sorted(external.values(),key=lambda row:row["identity"]["path"]),
      "copied_files":0,"original_bytes_changed":False,"observed_unix":time.time(),
      "scope":"Inventory only, outside frozen worktree. Original raw results/logs/commands/source manifests preserve their own revision and failure scope. Package disks, VM states, compiler targets and ELF binaries remain at recorded cache locations; no private connection configuration included."}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"output":identity(args.output),"files":len(rows),"bytes":record["included_bytes"]}))
if __name__=="__main__":main()
