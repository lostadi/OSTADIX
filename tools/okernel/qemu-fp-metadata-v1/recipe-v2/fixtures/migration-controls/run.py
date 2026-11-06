
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
B=Path(__file__).resolve().parent;W=B.parent;SDK=Path('/home/ustad/.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin');CODE=Path('/usr/share/OVMF/OVMF_CODE_4M.fd');VARS=Path('/usr/share/OVMF/OVMF_VARS_4M.fd')
def pin(p):p=Path(p);d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
mode=sys.argv[1];assert mode in('baseline','v1r4','v1r6');name=sys.argv[2];O=B/name;O.mkdir();S=O/'source';S.mkdir();inputs=['migration.S','description.json','make_source.py','run.py'];before=[pin(B/n)for n in inputs]
for n in inputs:shutil.copyfile(B/n,S/n)
Q=W/(mode+'-bin')/'qemu-system-x86_64';tools=[Q,SDK/'clang',SDK/'lld-link',SDK/'llvm-objdump',CODE,VARS,Path('/usr/bin/qemu-img'),Path('/usr/sbin/mkfs.vfat'),Path('/usr/bin/mmd'),Path('/usr/bin/mcopy')];R={'ok':False,'scope':'Actual originalQEMU new-new snapshots and freshmigration, no nativeFP admission','source_before':before,'tools_before':[pin(p)for p in tools],'commands':[],'processes':[],'checks':[]};procs=[]
def save():(O/'result.json').write_text(json.dumps(R,indent=2)+'\n')
def check(n,a,e):R['checks'].append(dict(name=n,actual=a,expected=e,passed=a==e));save()
def run(n,argv):
 argv=list(map(str,argv));t=time.monotonic();p=subprocess.run(argv,cwd=O,capture_output=True,timeout=30);so=O/(n+'.stdout');se=O/(n+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr);R['commands'].append(dict(name=n,argv=argv,exit_code=p.returncode,seconds=time.monotonic()-t,stdout=pin(so),stderr=pin(se)));save();assert p.returncode==0,(n,p.stderr)
class VM:
 def __init__(self,n,load=None,incoming=False):
  self.n=n;self.d=O/n;self.d.mkdir();self.tmp=Path(tempfile.mkdtemp(prefix='fpmig-',dir='/tmp'));self.serial=b'';self.serial_all=b'';self.qlog=[];self.count=0;var=self.d/'vars.fd';shutil.copyfile(VARS,var)
  argv=[str(Q),'-L',str(W/'source/qemu-11.1.3/pc-bios'),'-machine','q35','-accel','tcg','-cpu','Nehalem-v1,+x2apic','-m','128M','-smp','1','-nodefaults','-display','none','-monitor','none','-serial','unix:'+str(self.tmp/'s')+',server=on,wait=off','-qmp','unix:'+str(self.tmp/'q')+',server=on,wait=off','-nic','none','-no-reboot','-drive','if=pflash,format=raw,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,readonly=on,file='+str(var),'-drive','if=none,id=esp,format=raw,readonly=on,file='+str(O/'esp.img'),'-device','virtio-blk-pci,drive=esp','-drive','if=none,id=state,format=qcow2,file='+str(O/'state.qcow2'),'-device','virtio-blk-pci,drive=state','-device','isa-debug-exit,iobase=0xf4,iosize=0x04']
  if load:argv+=['-loadvm',load]
  if incoming:argv+=['-incoming','defer']
  self.so=(self.d/'stdout').open('wb');self.se=(self.d/'stderr').open('wb');self.p=subprocess.Popen(argv,cwd=self.d,stdout=self.so,stderr=self.se,start_new_session=True,preexec_fn=_owned_parent_death);procs.append(self);R['processes'].append(dict(name=n,pid=self.p.pid,pgid=self.p.pid,start_ticks=Path(f'/proc/{self.p.pid}/stat').read_text().split()[21],argv=argv));save()
  self.q=self.connect(self.tmp/'q');self.qf=self.q.makefile('rb');self.qlog.append({'greeting':json.loads(self.qf.readline())});self.qmp('qmp_capabilities');self.s=self.connect(self.tmp/'s');self.s.setblocking(False)
 def connect(self,path):
  end=time.monotonic()+10
  while time.monotonic()<end:
   try:x=socket.socket(socket.AF_UNIX);x.connect(str(path));return x
   except OSError:x.close();assert self.p.poll()is None;time.sleep(.02)
  raise TimeoutError('socket')
 def qmp(self,cmd,args=None):
  self.count+=1;req={'execute':cmd,'id':self.count}
  if args is not None:req['arguments']=args
  self.q.sendall(json.dumps(req).encode()+b'\n');self.qlog.append({'send':req});self.q.settimeout(30)
  while True:
   line=self.qf.readline();assert line,('QMPclosed',cmd);v=json.loads(line);self.qlog.append({'recv':v});(self.d/'qmp.json').write_text(json.dumps(self.qlog,indent=2)+'\n')
   if v.get('id')==self.count:
    assert 'error'not in v,(cmd,v)
    return v.get('return')
 def until(self,marker,timeout=60):
  end=time.monotonic()+timeout
  while marker not in self.serial:
   assert self.p.poll()is None,('ownedqemuexit',self.p.returncode)
   if time.monotonic()>end:raise TimeoutError(('serial',marker,self.serial[-300:]))
   rd,_,_=select.select([self.s],[],[],.2)
   if rd:
    d=self.s.recv(65536);assert d;self.serial+=d;self.serial_all+=d;(self.d/'serial.log').write_bytes(self.serial_all)
  pos=self.serial.index(marker)+len(marker);out=self.serial[:pos];self.serial=self.serial[pos:];return out
 def cmd(self,c):self.s.sendall(c.encode());return self.until(b'MIGREADY '+(c if c in'HSZ'else self.state).encode()+b'\n')
 def seed(self,c):self.state=c;return self.cmd(c)
 def stop(self):self.qmp('stop');assert self.qmp('query-status')['running']==False
 def hmp(self,s):r=self.qmp('human-monitor-command',{'command-line':s});assert not r.strip(),(s,r)
 def close(self):
  if self.p.poll()is None:
   try:self.qmp('quit')
   except Exception:pass
   try:self.p.wait(timeout=3)
   except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=3)
  self.so.close();self.se.close();R['processes'][procs.index(self)]['exit_code']=self.p.returncode
  for x in('q','s'):
   try:(self.tmp/x).unlink()
   except FileNotFoundError:pass
  self.tmp.rmdir();save()
def decode(raw,label):
 records={}
 for n,l,h in re.findall(rb'(?m)^FPREC ([a-z]+) ([0-9a-f]{16}) ([0-9a-f]+)\r?$',raw):
  n=n.decode();d=bytes.fromhex(h.decode());assert len(d)==int(l,16);records[n]=d
 assert set(records)=={'metadata','wide','legacy','env'};D=O/'decoded'/label;D.mkdir(parents=True)
 for n,d in records.items():(D/(n+'.bin')).write_bytes(d)
 b=records['wide'];l=records['legacy'];e=records['env'];fields={'fop':int.from_bytes(b[6:8],'little'),'fip':int.from_bytes(b[8:16],'little'),'fdp':int.from_bytes(b[16:24],'little'),'fcs':int.from_bytes(l[12:14],'little'),'fds':int.from_bytes(l[20:22],'little')};return records,fields
try:
 run('assemble',[SDK/'clang','--target=x86_64-pc-windows-msvc','-c',S/'migration.S','-o',O/'migration.obj']);app=O/'BOOTX64.EFI';desc=json.loads((S/'description.json').read_text());run('link',[SDK/'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/base:0x100000','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(O/'migration.map'),'/out:'+str(app),*[('/export:'+n)for n in desc['exports']],O/'migration.obj']);run('disassemble',[SDK/'llvm-objdump','-d','--x86-asm-syntax=intel',app]);R['application']=pin(app)
 run('fat',['/usr/sbin/mkfs.vfat','-C','-F','16','-n','FPMIG',O/'esp.img','16384']);run('fat-dir',['/usr/bin/mmd','-i',O/'esp.img','::/EFI','::/EFI/BOOT']);run('fat-copy',['/usr/bin/mcopy','-i',O/'esp.img',app,'::/EFI/BOOT/BOOTX64.EFI']);run('qcow2',['/usr/bin/qemu-img','create','-f','qcow2',O/'state.qcow2','16M'])
 vm=VM('snapshot-source');vm.until(b'MIGCOMMAND\n');seeds={}
 for c in 'SHZ':
  raw=vm.seed(c);rr,fields=decode(raw,'seed-'+c);seeds[c]=rr
  for k,v in desc['state_seeds'][c].items():check('seed_'+c+'_'+k,fields[k],v)
  vm.stop();vm.hmp('savevm '+c)
  vm.qmp('cont')
 # Dirty destination with selectors/high pointers; zero optional subsections
 # must not inherit their resident destination values on load.
 for c,dirty in [('Z','S'),('S','H'),('H','S')]:
  decode(vm.seed(dirty),'dirty-'+c);vm.stop();vm.hmp('loadvm '+c);vm.state=c;vm.qmp('cont');rr,fields=decode(vm.cmd('R'),'loaded-dirty-'+c)
  for n in('wide','legacy','env'):check('dirty_load_'+c+'_'+n,rr[n].hex(),seeds[c][n].hex())
 # Preserve a separate file transport stream for direct fresh incoming and
 # precise malformed-architectural-state negative controls.
 vm.stop();vm.qmp('migrate',{'uri':'file:'+str(O/'high.migration')})
 deadline=time.monotonic()+30
 while True:
  status=vm.qmp('query-migrate');assert status['status']not in('failed','cancelled'),status
  if status['status']=='completed':break
  assert time.monotonic()<deadline;time.sleep(.05)
 R['migration_stream']=pin(O/'high.migration')
 vm.close()
 for c in 'SHZ':
  vm=VM('fresh-load-'+c,load=c);vm.state=c;rr,fields=decode(vm.cmd('R'),'loaded-fresh-'+c)
  for n in('wide','legacy','env'):check('fresh_load_'+c+'_'+n,rr[n].hex(),seeds[c][n].hex())
  vm.close()
 R['ok']=all(t['passed']for t in R['checks'])
except Exception as e:R['error']=repr(e);(O/'controller-error.log').write_text(traceback.format_exc())
finally:
 for p in procs:
  if p.p.poll()is None:p.close()
 R['source_after']=[pin(B/n)for n in inputs];R['sources_unchanged']=R['source_before']==R['source_after'];R['tools_after']=[pin(p)for p in tools];R['tools_unchanged']=R['tools_before']==R['tools_after'];save()
print(json.dumps({'result':pin(O/'result.json'),'ok':R['ok'],'checks':len(R['checks']),'error':R.get('error')}))
