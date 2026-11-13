#!/usr/bin/env python3
"""Read-only current QEMU CPU snapshots at exact retained return PCs."""
from pathlib import Path
import hashlib,json,re
BASE=Path("/home/ustad/.cache/o10-m2-acceptance-20261113/linux-restore-trace-r1")
sites=json.loads((BASE/"trace-sites.json").read_text())["sites"]
p=BASE/"restore-cpu.log"
if not p.exists():
 print(json.dumps({"trace_started":False}));raise SystemExit(0)
data=p.read_bytes();text=data.decode("ascii",errors="replace")
starts=list(re.finditer(r"(?m)^\s*PC=([0-9a-fA-F]+)\b",text))
observations=[]
for i,m in enumerate(starts):
 pc=int(m.group(1),16)
 selected=[s for s in sites if s["return_pc"]==pc]
 if not selected:continue
 end=starts[i+1].start() if i+1<len(starts) else len(text)
 block=text[m.start():end]
 registers={int(k):int(v,16) for k,v in re.findall(r"\bX([0-9]{2})=([0-9a-fA-F]+)",block)}
 if 0 not in registers:continue
 observations.append({"target":selected[0]["target"],"return_pc":hex(pc),"x0":registers[0],"registers":{str(k):hex(v) for k,v in registers.items()},"trace_text_offset":m.start(),"raw_snapshot":block})
record={"schema":"ostadix.o10-m2-qemu-return-observations/v1","scope":"Read-only actual CPU/TB snapshots at exact e913 Trestore caller-return PCs. Absence of a snapshot proves no outcome.","trace":{"path":str(p),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},"snapshots":len(starts),"returns":observations,"first_observed_non_one":next((o for o in observations if o["x0"]!=1),None)}
(BASE/"return-observations.json").write_text(json.dumps(record,indent=2)+"\n")
print(json.dumps({"trace_bytes":len(data),"snapshots":len(starts),"returns":[{k:o[k] for k in ["target","return_pc","x0"]} for o in observations],"first_observed_non_one":record["first_observed_non_one"]},indent=2))
