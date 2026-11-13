#!/usr/bin/env python3
"""Collect one completed resident job; validate its bounded current-source gate receipt."""
import argparse,base64,hashlib,json,os,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
PREP=Path(__file__).resolve().parent;PINS=json.loads((PREP/"pins.json").read_text());ROOT=Path(PINS["root"])
sys.path.insert(0,str(ROOT/"scripts"))
import verify_o10_m1 as shared
import verify_o10_m2 as m2
def need(ok,msg):
 if not ok:raise ValueError(msg)
def desc(p):
 p=Path(p);return {"path":str(p),"bytes":p.stat().st_size,"sha256":shared.digest(p)}
def call(method,args,out,env,label):
 p=subprocess.run(["python3","-B",str(ROOT/"scripts/ostadix_mcp_client.py"),method,json.dumps(args)],cwd=ROOT,env=env,capture_output=True,text=True,timeout=45)
 (out/(label+".json")).write_text(p.stdout);(out/(label+".stderr")).write_text(p.stderr)
 need(p.returncode==0,"client failure "+method)
 v=json.loads(p.stdout);need(not v.get("isError"),"tool error "+method)
 return v.get("structuredContent",v)
parser=argparse.ArgumentParser();parser.add_argument("--execution",type=Path,required=True);parser.add_argument("--output",type=Path,required=True);args=parser.parse_args()
need(not args.output.exists(),"output must be new");args.output.mkdir(parents=True)
record={"schema":"ostadix.o10-m2-resident-current-validation/v1","ok":False,"gate_passed":False,"milestone_qualified":False,"scope":"Draft0 resident invariant component on the final M2 QEMU AArch64 build: 60 seconds with zero runnable guests and original provider restore. Native host-model classification and actual EL2 context logs remain separately scoped. No physical-board or full M2 qualification.","started_unix":time.time()}
try:
 revision=subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip();need(revision==PINS["revision"],"HEAD drift")
 source=shared.document(args.execution/"result.json");need(source.get("ok") is True and source.get("submitted") is True,"missing single submission")
 job=source["job_id"];env={**os.environ,**json.loads((Path(PINS["bridge"])/"bridge-env.json").read_text()),"PYTHONDONTWRITEBYTECODE":"1"}
 status=call("o_job_status",{"job_id":job},args.output,env,"managed-status")
 record.update(job_id=job,job_status=desc(args.output/"managed-status.json"),actual_job_state=status.get("state"),actual_job_exit=status.get("exit_code"))
 need(status.get("state") in ("completed","failed","cancelled","timed_out"),"actual resident job still running; collection does not stop or retry it")
 logs={}
 for stream in ("stdout","stderr"):
  offset=0;data=bytearray();pages=[]
  while True:
   page=call("o_job_read",{"job_id":job,"stream":stream,"offset":offset,"limit":262144,"encoding":"base64"},args.output,env,stream+"-"+str(offset))
   pages.append({"offset":offset,"next_offset":page.get("next_offset"),"eof":page.get("eof"),"total_bytes":page.get("total_bytes")})
   text=page.get("text",page.get("data",page.get("base64")))
   need(isinstance(text,str),"lossless job page missing data")
   data.extend(base64.b64decode(text))
   if page.get("eof") is True:break
   need(type(page.get("next_offset")) is int and page["next_offset"]>offset,"job cursor did not progress")
   offset=page["next_offset"]
  path=args.output/(stream+".log");path.write_bytes(data);logs[stream]={"identity":desc(path),"pages":pages}
 record["logs"]=logs
 need(status.get("state")=="completed" and status.get("exit_code")==0,"actual resident job did not complete successfully; actual exit and complete logs retained")
 profile=m2.validate_build(ROOT,Path(PINS["build"]))
 receipt=Path(PINS["session"])/"result.json"
 resident,sessions,captures=shared.validate_resident(ROOT,receipt,Path(PINS["build"]),profile,PINS["revision"])
 for name in ("seed_head","seed_disk","seed_namespace"):
  need(desc(PINS["files"][name]["path"])==PINS["files"][name],"preserved seed changed: "+name)
 need(shared.digest(Path(PINS["runtime"])/"runtime.json")==PINS["files"]["runtime"]["sha256"],"runtime changed")
 record.update(ok=True,gate_passed=True,source_revision=revision,mcp_release=revision,toolchain_origin_revision=PINS["toolchain_origin_revision"],job_id=job,job_status=desc(args.output/"managed-status.json"),logs=logs,gate_receipt=desc(receipt),execution_receipt=desc(args.execution/"result.json"),profile=PINS["files"]["profile"],monitor=PINS["files"]["monitor"],runtime=PINS["files"]["runtime"],zero_runnable_seconds=resident["zero_runnable_seconds"],samples=len(resident["samples"]),provider=resident["provider"],private_sessions=sorted(sessions),seed_unchanged=True,source_unchanged=True)
except BaseException as error:record["error"]=type(error).__name__+": "+str(error)
record["finished_unix"]=time.time();(args.output/"result.json").write_text(json.dumps(record,indent=2)+"\n")
print(json.dumps({"ok":record["ok"],"gate_passed":record["gate_passed"],"result":str(args.output/"result.json"),"error":record.get("error")}))
raise SystemExit(0 if record["ok"] else 1)
