#!/usr/bin/env python3
"""Actual EL2 slot0 reset with surviving slot1, OC AArch64 caller and AAPCS markers."""
from pathlib import Path
import ast,difflib,hashlib,importlib.util,json,os,subprocess,sys,time,types
sys.dont_write_bytecode=True
ROOT=Path("/home/ustad/OSTADIX-o10-m2-20261112")
OUT=Path("/home/ustad/.cache/o10-m2-acceptance-20261113/linux-slot-reset-probe-r1")
ORIGIN=Path("/home/ustad/.local/state/ostadix/o10-m2-postmerge-toolchain-r1-20261113")
OCOREC=ORIGIN/"bin/ocorec";CLANG=Path("/usr/lib/llvm-18/bin/clang");LINKER=Path("/usr/lib/llvm-18/bin/ld.lld");QEMU=Path("/usr/bin/qemu-system-aarch64")
REVISION="619394bafbe2b3f956ee7ec14bd87b0a9202f026"
def desc(p):
 p=Path(p);return {"path":str(p),"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
def need(ok,msg):
 if not ok:raise ValueError(msg)
need(not OUT.exists(),"probe output must be new");OUT.mkdir()
names=["tests/test_unified_world_context.py","ocore/kernel/aarch64/unified_world/monitor.S","ocore/kernel/aarch64/unified_world/linker.ld"]
before={n:desc(ROOT/n) for n in names}
need(subprocess.run(["git","rev-parse","HEAD"],cwd=ROOT,capture_output=True,text=True,check=True).stdout.strip()==REVISION,"revision changed")
need(desc(OCOREC)["sha256"]=="ca56a947e675f713bde6b81595220833799dcd304c415b0737f8703b8eb9eca7","compiler differs")
spec=importlib.util.spec_from_file_location("current_context_reset0_probe",ROOT/names[0]);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
original=m.C;c=original
replacements=[
 ("if(d && recycled)marker=0x33;","if(!d && recycled)marker=0x33;"),
 ("d&&recycled?UINT64_C","!d&&recycled?UINT64_C"),
 ("if(d)target_context=f;else survivor_context=f;","if(!d)target_context=f;else survivor_context=f;"),
 ("if(d && !recycled && visits[0]>=5 && visits[1]>=5)","if(!d && !recycled && visits[0]>=5 && visits[1]>=5)"),
 ("if(!d && !recycled && visits[1]>=5)","if(d && !recycled && visits[0]>=5)"),
 ("Target1 is not running.","Target0 is stopped at the complete saved EL2 boundary."),
 ("0xb1100000","0x49100000"),
 ("uw_domain_reset(1,0x20000000","uw_domain_reset(0,0x20000000"),
 ("uw_domain_reset(1,0x40000000,0x33,0x3c5)","synthetic_reset_call(0,0x40000000,0x33,0x3c5)"),
 ("recycled=1;previous[1]=0;visits[1]=0;","recycled=1;previous[0]=0;visits[0]=0;"),
 ("uw_vgic_hcr_write(1,1);uw_vgic_vmcr_write(1,","uw_vgic_hcr_write(0,1);uw_vgic_vmcr_write(0,"),
 ("uw_timer_write(1,0,0,uw_counter_read()+1000000000);uw_timer_write(1,0,1,3);","uw_timer_write(0,0,0,uw_counter_read()+1000000000);uw_timer_write(0,0,1,3);"),
 ("uw_timer_write(1,1,0,0x12340001);uw_timer_write(1,1,1,0);","uw_timer_write(0,1,0,0x12340000);uw_timer_write(0,1,1,0);"),
 ('out("UNIFIED_CORE_RESET_BANK_CLEAR_PASS\\n");deadline=uw_counter_read()+period;return 1;','out("UNIFIED_CORE_RESET_BANK_CLEAR_PASS\\n");deadline=uw_counter_read()+period;return 0;')]
for old,new in replacements:
 need(c.count(old)==1,"fixture patch anchor differs: "+old);c=c.replace(old,new)
c=c.replace("extern uint64_t uw_domain_reset(uint64_t,uint64_t,uint64_t,uint64_t);","extern uint64_t uw_domain_reset(uint64_t,uint64_t,uint64_t,uint64_t);\nextern uint64_t synthetic_reset_call(uint64_t,uint64_t,uint64_t,uint64_t);")
old="        if(uw_domain_reset(2,0x40000000,0x33,0x3c5)!=0"
need(c.count(old)==1,"real tuple insertion anchor differs")
insert="""        if(synthetic_reset_call(0,0x40000000,0x47e00000,0x3c5)!=1) {
            out("UNIFIED_CORE_RESET0_REAL_TUPLE_ABI_FAIL\\n");return 2;
        }
        for(unsigned n=0;n<512;n++) {
            uint64_t expected=0;
            if(n==0)expected=0x47e00000;if(n==31)expected=0x40000000;if(n==32)expected=0x3c5;
            if(n==35)expected=0x30d00800;if(n==37)expected=0x300000;if(n==64)expected=1;
            if(target_context[n]!=expected){out("UNIFIED_CORE_RESET0_REAL_TUPLE_BANK_FAIL\\n");return 2;}
        }
        if(!same(survivor_copy,survivor_context,4096) || uw_current_domain()!=d) {
            out("UNIFIED_CORE_RESET0_REAL_TUPLE_SURVIVOR_FAIL\\n");return 2;
        }
        out("UNIFIED_CORE_RESET0_REAL_TUPLE_ABI_PASS\\n");
        memcpy(target_copy,target_context,4096);
"""
c=c.replace(old,insert+old)
assembly=[".text",".global uw_probe_domain_reset","uw_probe_domain_reset:","stp x19, x20, [sp, #-96]!","stp x21, x22, [sp, #16]","stp x23, x24, [sp, #32]","stp x25, x26, [sp, #48]","stp x27, x28, [sp, #64]","stp x29, x30, [sp, #80]"]
for reg in range(19,30):assembly.append("mov x"+str(reg)+", #0x1"+str(reg))
assembly.extend(["bl uw_domain_reset","mov x9, x0"])
for reg in range(19,30):assembly.extend(["cmp x"+str(reg)+", #0x1"+str(reg),"b.ne 9f"])
assembly.extend(["mov x0, x9","b 8f","9: mov x0, #2","8: ldp x21, x22, [sp, #16]","ldp x23, x24, [sp, #32]","ldp x25, x26, [sp, #48]","ldp x27, x28, [sp, #64]","ldp x29, x30, [sp, #80]","ldp x19, x20, [sp], #96","ret"])
c+="\n__asm__(\n"+"\n".join(json.dumps(line+"\n") for line in assembly)+"\n);\n"
m.C=c
(OUT/"base-fixture.c").write_text(original);(OUT/"probe-fixture.c").write_text(c)
(OUT/"fixture.diff").write_text("".join(difflib.unified_diff(original.splitlines(True),c.splitlines(True),fromfile="original-context-fixture",tofile="slot0-probe-fixture")))
oc=OUT/"reset_probe.oc";oc.write_text("""module cache::reset_probe;
extern "ocore" fn uw_probe_domain_reset(domain: u64, pc: u64, arg: u64, pstate: u64) -> u64;
@export
@no_mangle
pub unsafe fn synthetic_reset_call(domain: u64, pc: u64, arg: u64, pstate: u64) -> u64 {
    return uw_probe_domain_reset(domain, pc, arg, pstate);
}
""")
commands=[];processes=[]
cmd=[str(OCOREC),str(oc),"--emit","obj","--target","aarch64-unknown-none","-o",str(OUT/"reset-probe.o")]
p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=60);commands.append({"argv":cmd,"exit_code":p.returncode,"stdout":p.stdout,"stderr":p.stderr});need(p.returncode==0,"OC AArch64 caller compile failed")
class SP:
 def run(self,argv,*a,**kw):
  actual=list(argv)
  if actual[0]==str(LINKER):actual.append(str(OUT/"reset-probe.o"))
  p=subprocess.run(actual,*a,**kw);commands.append({"argv":actual,"exit_code":p.returncode,"stdout":p.stdout,"stderr":p.stderr});return p
 def Popen(self,argv,*a,**kw):
  p=subprocess.Popen(argv,*a,**kw);processes.append((p,list(argv)));return p
 def __getattr__(self,n):return getattr(subprocess,n)
m.subprocess=SP();m.shutil=types.SimpleNamespace(which=lambda n:{"clang":str(CLANG),"ld.lld":str(LINKER),"qemu-system-aarch64":str(QEMU)}.get(n))
import tempfile
counter=0;outputs=[]
def directory(*args,**kw):
 global counter
 counter+=1;p=OUT/("case-"+str(counter));p.mkdir();outputs.append(p);return str(p)
m.tempfile=types.SimpleNamespace(mkdtemp=directory)
record={"schema":"ostadix.o10-m2-linux-slot-reset-probe/v1","ok":False,"source_revision":REVISION,"scope":"Synthetic QEMU actual EL2 slot0 reset through the freshly compiled ca56 AArch64 OC caller, production assembly, explicit x19-x29 callee-save canaries, target bank/TLB reuse and surviving slot1 checks. Whole Linux restart and its four-call provision chain remain separate.","sources_before":before,"tools":{n:desc(p) for n,p in [("ocorec",OCOREC),("clang",CLANG),("ld.lld",LINKER),("qemu",QEMU)]},"started_unix":time.time()}
try:
 case=m.UnifiedContextTests()
 case.exercise(False,reset=True,self_reset=False)
 case.exercise(False,reset=True,self_reset=True)
 for output in outputs:
  r=json.loads((output/"result.json").read_text());console=(output/"console.log").read_text()
  need(r["passed"] and "UNIFIED_CORE_RESET0_REAL_TUPLE_ABI_PASS" in console,"slot0/ABI tuple marker missing")
 need({n:desc(ROOT/n) for n in names}==before,"production sources changed")
 record.update(ok=True,source_unchanged=True,cases=[{"output":str(o),"artifacts":{p.name:desc(p) for p in o.iterdir() if p.is_file()}} for o in outputs])
except BaseException as error:record["error"]=type(error).__name__+": "+str(error);raise
finally:
 record["commands"]=commands;record["processes"]=[{"pid":p.pid,"argv":argv,"exit_code":p.poll()} for p,argv in processes]
 record["probe_source"]=desc(oc);record["probe_fixture"]=desc(OUT/"probe-fixture.c");record["finished_unix"]=time.time();(OUT/"result.json").write_text(json.dumps(record,indent=2)+"\n")
print(json.dumps({"ok":record["ok"],"result":str(OUT/"result.json"),"cases":len(outputs)}))
