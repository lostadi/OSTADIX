from pathlib import Path
import os,json,subprocess,hashlib,time,re
root=Path("/home/ustad/OSTADIX-o10-m1-publish-20261113")
toolchain=Path("/home/ustad/.local/state/ostadix/o10-m1-publication-toolchain-20261113")
out=root/"evidence/o10-m1-publication-20261113"
out.mkdir(exist_ok=False)
sha=lambda q:hashlib.sha256(Path(q).read_bytes()).hexdigest()
revision="7655a3e2d5a204a3701af47d841c354877aabb32"
plan=json.loads((toolchain/"plan.json").read_text())
alignment=json.loads((toolchain/"alignment.json").read_text())
assert alignment["ok"] is True and alignment["revision"]==revision
for name in ["plan.json","build.json","alignment.json","fresh-env.json","fresh-doctor.json","fresh-runtimes.json","fresh-ocorec-help.json","worker-timeout-observation.json"]:
 (out/name).write_bytes((toolchain/name).read_bytes())
paths=subprocess.run(["git","ls-files"],cwd=root,capture_output=True,text=True,check=True).stdout.splitlines()
sources={n:sha(root/n) for n in paths if Path(n).suffix in {".rs",".oc",".O",".py",".sh",".toml",".json",".md",".html",".lock"} and not n.startswith("evidence/") and (root/n).is_file() and not (root/n).is_symlink()}
record={"schema":"ostadix.o10-m1-publication-integration/v1","ok":False,"started":time.time(),"source_revision":revision,"mcp_release":revision,"source_sha256":sources,"toolchain_alignment":alignment,"reuse_audit":{"rust_cargo_files":len(plan["reuse_source_hashes"]),"compiled_r7_files":len(plan["compiled_r7_source_sha256"]),"compiled_unchanged":plan["compiled_source_unchanged"],"incoming_compiled_overlap":plan["incoming_compiled_overlap"]},"scope":"Merged-source host component/native-oracle/parser/docs/author integration checks; unchanged historical R7 guest receipts retain their original scope and are not replayed","commands":[]}
def save():
 t=out/"result.tmp";t.write_text(json.dumps(record,indent=2)+"\n");t.replace(out/"result.json")
save()
env=dict(os.environ, OCOREC_BIN=plan["reused_tools"]["ocorec"]["path"],O_LANG_OCOREC_BIN=plan["reused_tools"]["ocorec"]["path"],O_LANG_EVALUATOR_BIN=plan["reused_tools"]["O"]["path"],OLANG=plan["reused_tools"]["O"]["path"],OCOREC_BIN_SHA256=plan["reused_tools"]["ocorec"]["sha256"],OCORE_PROCESS_IDENTITY_REQUIRED="1",OCORE_THREAD_FRAME_REQUIRED="1",OCORE_PROCESS_IDENTITY_TEST_OUTPUT="/home/ustad/.cache/o10-m1-publication-20261113/process-current-identity",OCORE_THREAD_FRAME_TEST_OUTPUT="/home/ustad/.cache/o10-m1-publication-20261113/thread-frame-contents",PYTHONDONTWRITEBYTECODE="1")
commands=[
 ("affected",["python3","-m","unittest","-v","tests.test_process_current_identity","tests.test_thread_frame_contents","tests.test_source_release"]),
 ("inventory-contract",["python3","tools/ocore-runtime/libc/test_inventory_recipe_worker_contract.py","-v"]),
 ("o10-components",["python3","scripts/verify_o10_journal.py","--session",str(out/"components"),"--component-only","--mcp-release",revision]),
 ("language",["python3","scripts/check_language_sources.py","check","--o-bin",plan["reused_tools"]["O"]["path"],"--ocorec",plan["reused_tools"]["ocorec"]["path"],"--jobs","4","--json-report",str(out/"language.json")]),
 ("docs",["python3","scripts/render_docs.py","check","--marked","/home/ustad/.cache/o10-docs-renderer-20261112/node_modules/.bin/marked","--jobs","4"]),
 ("authors",["python3","scripts/check_commit_authors.py","--head","HEAD"]),
 ("diff",["git","diff","--check"])]
for label,argv in commands:
 item={"id":label,"argv":argv,"cwd":str(root),"started":time.time(),"returncode":None,"timed_out":False}
 record["commands"].append(item);save()
 with (out/(label+".stdout.log")).open("w") as a,(out/(label+".stderr.log")).open("w") as b:
  try:
   v=subprocess.run(argv,cwd=root,env=env,stdout=a,stderr=b,timeout=1500)
   item["returncode"]=v.returncode
  except subprocess.TimeoutExpired:
   item["timed_out"]=True
 item["finished"]=time.time()
 text=(out/(label+".stdout.log")).read_text(errors="replace")+(out/(label+".stderr.log")).read_text(errors="replace")
 tests=re.findall(r"Ran (\d+) tests? in",text)
 item["tests_run"]=int(tests[-1]) if tests else None
 skipped=re.findall(r"skipped=(\d+)",text)
 item["skips"]=int(skipped[-1]) if skipped else 0
 item["logs"]={stream:{"path":str(out/(label+"."+stream+".log")),"sha256":sha(out/(label+"."+stream+".log"))} for stream in ["stdout","stderr"]}
 item["ok"]=item["returncode"]==0 and not item["timed_out"] and not item["skips"]
 save()
component=json.loads((out/"components/result.json").read_text())
language=json.loads((out/"language.json").read_text())
record["component"]={"tests_run":component.get("tests_run"),"component_ok":component.get("component_ok"),"skips":component.get("skipped",component.get("skips"))}
record["language_summary"]={k:language.get(k) for k in ["ok","classified","checked","failed","executed","total"]}
record["source_unchanged"]=all(sha(root/n)==h for n,h in sources.items())
record["compiled_r7_unchanged"]=all(sha(root/n)==h for n,h in plan["compiled_r7_source_sha256"].items())
record["tracked_diff"]=subprocess.run(["git","diff","--name-only","HEAD"],cwd=root,capture_output=True,text=True,check=True).stdout
record["final_revision"]=subprocess.run(["git","rev-parse","HEAD"],cwd=root,capture_output=True,text=True,check=True).stdout.strip()
record["ok"]=all(x["ok"] for x in record["commands"]) and component["component_ok"] is True and record["source_unchanged"] and record["compiled_r7_unchanged"] and record["final_revision"]==revision and not record["tracked_diff"]
record["finished"]=time.time();save()
print(json.dumps({"ok":record["ok"],"result":str(out/"result.json"),"commands":[{k:x.get(k) for k in ["id","returncode","tests_run","skips","ok"]} for x in record["commands"]],"component":record["component"],"source_unchanged":record["source_unchanged"]}))
assert record["ok"], "merged publication integration checks failed"
