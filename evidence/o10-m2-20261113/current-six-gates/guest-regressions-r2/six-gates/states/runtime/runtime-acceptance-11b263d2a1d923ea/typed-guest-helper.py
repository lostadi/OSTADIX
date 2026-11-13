
import hashlib,json,os,re,shutil,stat,subprocess,sys
from pathlib import Path
sys.path.insert(0,"/usr/lib/okernel")
import p9_protocol as p
root=Path(sys.argv[1]);action=sys.argv[2];phase=sys.argv[3];expected=sys.argv[4]
control=Path("/run/okernel/p9")
def read(path):return json.loads(path.read_text())
def sha(data):return hashlib.sha256(data).hexdigest()
def write(path,value):path.write_text(json.dumps(value,sort_keys=True)+"\n")
def current():
 value=read(control/"current.json")
 assert value["service_root"]=="/n/okernel/services/plan9" and value["state"]=="ready"
 p.ready_marker(value["generation"],value["instance"])
 return value
def requests(value):
 directory=Path(value["service_root"])/("g"+value["generation"])/("s"+value["instance"])
 return {x.name for x in directory.glob("r*") if re.fullmatch("r[0-9a-f]{32}",x.name) and (x/"submit").exists()}
def clients():
 names=("/usr/local/bin/p9","/usr/local/libexec/p9-history","/usr/local/libexec/p9-controller","/usr/local/bin/p9-install","/usr/lib/okernel/p9_protocol.py")
 values={name:{"bytes":Path(name).stat().st_size,"sha256":sha(Path(name).read_bytes())} for name in names}
 assert values["/usr/local/bin/p9"]["sha256"]==expected
 return values
if action=="identity":
 write(root/("guest-"+phase+".json"),{"clients":clients(),"current":current()})
elif action=="tree-before":
 result=subprocess.run(["apk","info","-e","tree"],capture_output=True)
 write(root/"tree-before.json",{"already_installed":result.returncode==0,"stdout_hex":result.stdout.hex(),"stderr_hex":result.stderr.hex()})
elif action=="tree":
 binary=Path(shutil.which("tree"));value={"binary_sha256":sha(binary.read_bytes()),"binary":str(binary),"version_hex":(root/("linux-tree-version-"+phase+".txt")).read_bytes().hex(),"package_hex":(root/("linux-tree-package-"+phase+".txt")).read_bytes().hex()}
 assert value["version_hex"] and value["package_hex"]
 if phase=="first":value["already_installed"]=read(root/"tree-before.json")["already_installed"]
 else:
  previous=read(root/"tree-first.json");assert all(previous[k]==v for k,v in value.items())
 write(root/("tree-"+phase+".json"),value)
elif action=="linux":
 binary=Path(sys.argv[5]);marker=sys.argv[6];data=binary.read_bytes()
 assert data[:6]==b'\x7fELF\x02\x01' and int.from_bytes(data[18:20],"little")==183
 assert (root/("linux-source-"+phase+".out")).read_bytes()==(marker+"\n").encode()
 value={"source_sha256":sha((root/"linux.c").read_bytes()),"binary_sha256":sha(data),"binary":str(binary),"output_hex":(root/("linux-source-"+phase+".out")).read_bytes().hex()}
 if phase=="first":value["compiler_version"]=subprocess.run(["cc","--version"],check=True,capture_output=True,text=True).stdout
 else:
  previous=read(root/"linux-first.json");assert all(previous[k]==v for k,v in value.items())
 write(root/("linux-"+phase+".json"),value)
elif action=="boundary":
 clients();assert not (control/"pending.json").exists()
 archive=Path("/var/lib/okernel/p9-history")
 for path in (archive,*archive.parents):
  info=path.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and not info.st_mode&0o022
 for kind,manifest in (("keyerror",{"schema":"ostadix.p9.history-archive/v1"}),("typeerror",{"schema":"ostadix.p9.history-archive/v1","source_relative":None,"kind":"completed-job"})):
  before=current();oldresults={x.name for x in (control/"results").glob("*.json")};oldrequests=requests(before)
  # A fresh content-addressed-looking private directory is owned only by this
  # test; record its exact bytes before removing ONLY its own two new entries.
  name=sha((root.name+kind+os.urandom(16).hex()).encode());folder=archive/name
  os.mkdir(folder,0o700);ino=folder.stat().st_ino;wire=json.dumps(manifest,sort_keys=True).encode()+b"\n"
  path=folder/"manifest.json"
  try:
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,"wb") as stream:stream.write(wire)
   (root/(kind+"-manifest.json")).write_bytes(wire)
   result=subprocess.run(["/usr/local/bin/p9","--","echo","MUST_NOT_SUBMIT_"+root.name],input=b"supplied\0input\xff",capture_output=True,timeout=120)
   (root/(kind+".stdout")).write_bytes(result.stdout);(root/(kind+".stderr")).write_bytes(result.stderr)
   assert result.returncode==125 and result.stdout==b"" and b"history" in result.stderr.lower() and b"Traceback" not in result.stderr
   assert not (control/"pending.json").exists() and current()==before
   assert not ({x.name for x in (control/"results").glob("*.json")}-oldresults) and not (requests(before)-oldrequests)
   write(root/(kind+"-proof.json"),{"exit_status":125,"no_new_request":True,"no_new_result":True,"current":before,"manifest_sha256":sha(wire),"client_sha256":expected})
  finally:
   assert folder.stat().st_ino==ino and not folder.is_symlink()
   if path.exists() or path.is_symlink():
    assert path.read_bytes()==wire and not path.is_symlink() and {x.name for x in folder.iterdir()}=={"manifest.json"}
    path.unlink()
   assert not list(folder.iterdir());folder.rmdir()
elif action=="begin":
 clients();assert not (control/"pending.json").exists()
 write(root/("before-"+phase+".json"),{"current":current(),"results":sorted(x.name for x in (control/"results").glob("*.json"))})
elif action=="collect":
 code=int(sys.argv[5]);marker=sys.argv[6];argv=json.loads(sys.argv[7]);before=read(root/("before-"+phase+".json"))
 assert code==0 and current()==before["current"] and not (control/"pending.json").exists()
 fresh=[x for x in (control/"results").glob("*.json") if x.name not in before["results"]];assert len(fresh)==1
 receipt=read(fresh[0]);g,s,r=(receipt[k] for k in ("generation","instance","request_id"));assert (g,s)==(before["current"]["generation"],before["current"]["instance"])
 directory=Path(receipt["service_root"])/("g"+g)/("s"+s)/("r"+r)
 wire={name:(directory/name).read_bytes() for name in p.REQUEST_FILES}
 request=p.decode_request(wire["request"]);assert list(request.argv)==argv and request.cwd=="/n/work/"+root.name
 result=p.validate_result(wire["request"],wire["result"],wire["stdout"],wire["stderr"],started=wire["started"],done=wire["done"],status=wire["status"])
 assert result.ok and result.flags==0 and result.status==b"" and receipt["recovered"] is False
 assert receipt["request_sha256"]==sha(wire["request"]) and receipt["result_sha256"]==sha(wire["result"])
 assert (root/(phase+".out")).read_bytes()==wire["stdout"] and marker.encode() in wire["stdout"].splitlines()
 write(root/("proof-"+phase+".json"),{"receipt":receipt,"argv":list(request.argv),"cwd":request.cwd,"stdout_hex":wire["stdout"].hex(),"client_sha256":expected,"wire_sha256":{name:sha(data) for name,data in wire.items()}})
else:raise AssertionError(action)
print("\nRUNTIME_HELPER_"+action+"_"+phase+"_"+root.name,flush=True)
