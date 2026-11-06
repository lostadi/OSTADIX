
# Linux-only owned-child containment; no existing process is signalled.
import ctypes, os, signal
_owned_parent_pid = os.getpid()
def _owned_parent_death():
 libc = ctypes.CDLL(None, use_errno=True)
 if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
  os._exit(126)
 if os.getppid() != _owned_parent_pid:
  os._exit(126)

from pathlib import Path
import sys,os,socket,time,json,subprocess,shutil,tempfile,traceback,hashlib,re,struct,select
sys.dont_write_bytecode=True
B=Path(__file__).resolve().parent;W=B.parent;P=W/'migration-controls/final-r6-attempt-1';O=B/sys.argv[1];O.mkdir();CODE=Path('/usr/share/OVMF/OVMF_CODE_4M.fd');VARS=Path('/usr/share/OVMF/OVMF_VARS_4M.fd');Q=W/'v1r6-bin/qemu-system-x86_64'
def pin(p):p=Path(p);d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
inputs=[Path(__file__),W/'migration-controls/run.py',W/'source/qemu-11.1.3/scripts/analyze-migration.py',P/'high.migration',P/'BOOTX64.EFI',P/'esp.img',P/'result.json',Q,CODE,VARS];(O/'source').mkdir();shutil.copyfile(__file__,O/'source/run.py');shutil.copyfile(W/'migration-controls/run.py',O/'source/snapshot-controller.py');R={'ok':False,'inputs_before':[pin(p)for p in inputs],'processes':[],'commands':[],'checks':[],'scope':'ActualnewQEMU incomingfile transport, exactone-fieldmalformedFOP/MXCSR rejection; no nativekernelFP/wholeISA claim'};procs=[]
def save():(O/'result.json').write_text(json.dumps(R,indent=2)+'\n')
def check(n,a,e):R['checks'].append(dict(name=n,actual=a,expected=e,passed=a==e));save()
def run(n,argv):
 p=subprocess.run(list(map(str,argv)),cwd=O,capture_output=True,timeout=30);(O/(n+'.stdout')).write_bytes(p.stdout);(O/(n+'.stderr')).write_bytes(p.stderr);R['commands'].append(dict(name=n,argv=list(map(str,argv)),exit_code=p.returncode,stdout=pin(O/(n+'.stdout')),stderr=pin(O/(n+'.stderr'))));save();assert p.returncode==0
# Reuse the exact authored QMP transport implementation, freeze its complete
# source and explicit selected class geometry, not a hidden second variant.
source=(W/'migration-controls/run.py').read_text();fragment=source[source.index('class VM:'):source.index('def decode(')];(O/'vm_transport_fragment.py').write_text(fragment);exec(compile(fragment,'retained_vm_transport_fragment','exec'),globals())
# Load only upstream read-only migration decoder classes, excluding its CLI.
analyzer=W/'source/qemu-11.1.3/scripts/analyze-migration.py';fragment=analyzer.read_text().split('parser = argparse.ArgumentParser()')[0];ns={'__name__':'pinned_migration_decoder'};exec(compile(fragment,str(analyzer),'exec'),ns);reads=[];original=ns['VMSDFieldGeneric'].read
def observed_read(self):
 start=self.file.tell();result=original(self);reads.append({'description':{k:self.desc[k]for k in('name','type','size')if k in self.desc},'offset':start,'bytes':self.file.tell()-start,'raw':self.data.hex()});return result
ns['VMSDFieldGeneric'].read=observed_read
try:
 dump=ns['MigrationDump'](str(P/'high.migration'));dump.read();(O/'decoded-state.json').write_text(json.dumps(dump.getDict(),cls=ns['JSONEncoder'],indent=2)+'\n');(O/'field-reads.json').write_text(json.dumps(reads,indent=2)+'\n');(O/'description.json').write_text(json.dumps(dump.vmsd_desc,cls=ns['JSONEncoder'],indent=2)+'\n')
 raw=(P/'high.migration').read_bytes();mutants=[]
 for field,expected,bit in [('env.fpop',0x435,0x8000),('env.mxcsr',0x5f80,0x10000)]:
  candidates=[x for x in reads if x['description'].get('name')==field];assert len(candidates)==1,(field,len(candidates));x=candidates[0];assert int(x['raw'],16)==expected,(field,x);start=x['offset'];width=x['bytes'];mut=bytearray(raw);mut[start:start+width]=(expected|bit).to_bytes(width,'big');changes=[i for i,(a,b)in enumerate(zip(raw,mut))if a!=b];assert changes and all(start<=i<start+width for i in changes);path=O/(field.split('.')[-1]+'-reserved.migration');path.write_bytes(mut);mutants.append((field,path));R.setdefault('mutations',[]).append(dict(field=field,offset=start,width=width,old_hex=raw[start:start+width].hex(),new_hex=mut[start:start+width].hex(),changed_offsets=changes,stream=pin(path)))
 shutil.copyfile(P/'esp.img',O/'esp.img');run('qcow2',['/usr/bin/qemu-img','create','-f','qcow2',O/'state.qcow2','16M'])
 vm=VM('valid-incoming',incoming=True);vm.qmp('migrate-incoming',{'uri':'file:'+str(P/'high.migration')});deadline=time.monotonic()+30
 while True:
  status=vm.qmp('query-status');R.setdefault('incoming_status_samples',[]).append(status)
  if status['status']!='inmigrate':break
  assert time.monotonic()<deadline;time.sleep(.05)
 check('valid_incoming_load_not_inmigrate',status['status']=='inmigrate',False)
 if not status['running']:vm.qmp('cont')
 vm.state='H';rawrecords=vm.cmd('R');(vm.d/'raw-report.bin').write_bytes(rawrecords);records={}
 for n,l,h in re.findall(rb'(?m)^FPREC ([a-z]+) ([0-9a-f]{16}) ([0-9a-f]+)\r?$',rawrecords):records[n.decode()]=bytes.fromhex(h.decode())
 assert set(records)=={'metadata','wide','legacy','env'}
 for n in('wide','legacy','env'):check('file_incoming_'+n,records[n].hex(),(P/'decoded/seed-H'/(n+'.bin')).read_bytes().hex())
 vm.close()
 for field,path in mutants:
  vm=VM('invalid-'+field.split('.')[-1],incoming=True)
  # Incoming may fail synchronously or asynchronously, both retained. It must
  # terminate before any guest continuation or any diagnostic report.
  try:vm.qmp('migrate-incoming',{'uri':'file:'+str(path)})
  except (AssertionError,ConnectionError,OSError)as e:R.setdefault('incoming_error_messages',[]).append({'field':field,'error':repr(e)})
  try:status=vm.p.wait(timeout=15)
  except subprocess.TimeoutExpired:status=None
  vm.so.flush();vm.se.flush();err=(vm.d/'stderr').read_bytes();check(field+'_incoming_rejected',status is not None and status!=0,True);check(field+'_architectural_guard_report',b'invalid migrated x87 opcode or MXCSR reserved bits'in err,True)
  try:
   while True:
    d=vm.s.recv(65536)
    if not d:break
    vm.serial_all+=d
  except (BlockingIOError,ConnectionError):pass
  (vm.d/'serial.log').write_bytes(vm.serial_all);check(field+'_no_guest_report',b'FPREC' in vm.serial_all,False);vm.close()
 R['ok']=all(t['passed']for t in R['checks'])
except Exception as e:R['error']=repr(e);(O/'controller-error.log').write_text(traceback.format_exc())
finally:
 for vm in procs:
  if vm.p.poll()is None:vm.close()
 R['inputs_after']=[pin(p)for p in inputs];R['inputs_unchanged']=R['inputs_before']==R['inputs_after'];save()
print(json.dumps({'result':pin(O/'result.json'),'ok':R['ok'],'checks':len(R['checks']),'error':R.get('error')}))
