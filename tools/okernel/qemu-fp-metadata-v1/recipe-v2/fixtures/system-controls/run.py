
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
import sys,hashlib,json,subprocess,shutil,time,os,traceback
sys.dont_write_bytecode=True
import checker
B=Path(__file__).resolve().parent;W=B.parent
SDK=Path('/home/ustad/.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin');CODE=Path('/usr/share/OVMF/OVMF_CODE_4M.fd');VARS=Path('/usr/share/OVMF/OVMF_VARS_4M.fd')
def pin(p):p=Path(p);d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
mode=sys.argv[1];assert mode in('baseline','candidate','v1r2','v1r3','v1r4','v1r6');name=sys.argv[2];O=B/name;O.mkdir();S=O/'source';S.mkdir();inputs=['controls.S','description.json','make_source.py','checker.py','run.py'];before=[pin(B/n)for n in inputs]
for n in inputs:shutil.copyfile(B/n,S/n)
Q=W/(mode+'-bin')/'qemu-system-x86_64';tools=[SDK/'clang',SDK/'lld-link',SDK/'llvm-objdump',Q,CODE,VARS,Path('/usr/sbin/mkfs.vfat'),Path('/usr/bin/mmd'),Path('/usr/bin/mcopy')]
r={'collection_ok':False,'conformance':False,'source_before':before,'tools_before':[pin(p)for p in tools],'commands':[],'scope':'Private authored IDT fault/control EFI app,128MiB1CPU namedNehalem; no production/nativekernel/OS changes'}
def save():(O/'result.json').write_text(json.dumps(r,indent=2)+'\n')
def run(n,argv):
 argv=list(map(str,argv));t=time.monotonic();p=subprocess.run(argv,cwd=O,capture_output=True,timeout=30);so=O/(n+'.stdout');se=O/(n+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr);r['commands'].append(dict(name=n,argv=argv,exit_code=p.returncode,seconds=time.monotonic()-t,stdout=pin(so),stderr=pin(se)));save();assert p.returncode==0,(n,p.returncode)
try:
 run('assemble',[SDK/'clang','--target=x86_64-pc-windows-msvc','-c',S/'controls.S','-o',O/'controls.obj'])
 app=O/'BOOTX64.EFI';desc=json.loads((S/'description.json').read_text());run('link',[SDK/'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/base:0x100000','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(O/'controls.map'),'/out:'+str(app),*[('/export:'+n)for n in desc['exports']],O/'controls.obj'])
 run('disassemble',[SDK/'llvm-objdump','-d','--x86-asm-syntax=intel',app]);r['application']=pin(app)
 disk=O/'esp.img';run('fat-image',['/usr/sbin/mkfs.vfat','-C','-F','16','-n','FPCTRL',disk,'16384']);run('fat-dir',['/usr/bin/mmd','-i',disk,'::/EFI','::/EFI/BOOT']);run('fat-copy',['/usr/bin/mcopy','-i',disk,app,'::/EFI/BOOT/BOOTX64.EFI']);r['esp_before']=pin(disk)
 variables=O/'OVMF_VARS.private.fd';shutil.copyfile(VARS,variables);serial=O/'serial.log'
 argv=[str(Q),'-L',str(W/'source/qemu-11.1.3/pc-bios'),'-machine','q35','-accel','tcg','-cpu','Nehalem-v1,+x2apic','-m','128M','-smp','1','-nodefaults','-display','none','-monitor','none','-serial','file:'+str(serial),'-nic','none','-no-reboot','-drive','if=pflash,format=raw,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,file='+str(variables),'-drive','if=none,id=esp,format=raw,readonly=on,file='+str(disk),'-device','virtio-blk-pci,drive=esp','-device','isa-debug-exit,iobase=0xf4,iosize=0x04']
 with(O/'qemu.stdout').open('wb')as so,(O/'qemu.stderr').open('wb')as se:
  p=subprocess.Popen(argv,cwd=O,stdout=so,stderr=se,start_new_session=True,preexec_fn=_owned_parent_death);r['owned_process']=dict(pid=p.pid,pgid=p.pid,start_ticks=Path(f'/proc/{p.pid}/stat').read_text().split()[21],argv=argv);save();t=time.monotonic()
  try:status=p.wait(timeout=60)
  except subprocess.TimeoutExpired:
   p.terminate()
   try:p.wait(timeout=3)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
   raise TimeoutError('owned diagnostic timeout')
 r['qemu_status']=status;r['qemu_seconds']=time.monotonic()-t;r['serial']=pin(serial);assert status==33,('unexpecteddebugexit',status)
 a=checker.analyze(app,serial,O/'decoded',S/'description.json');r['collection_ok']=a['collection_ok'];r['conformance']=a['conformance'];r['analysis']=pin(O/'decoded/analysis.json');r['passed']=a['passed'];r['failed']=a['failed']
except Exception as e:r['error']=repr(e);(O/'controller-error.log').write_text(traceback.format_exc())
finally:
 r['source_after']=[pin(B/n)for n in inputs];r['sources_unchanged']=before==r['source_after'];r['tools_after']=[pin(p)for p in tools];r['tools_unchanged']=r['tools_before']==r['tools_after'];save()
print(json.dumps(dict(result=pin(O/'result.json'),collection=r['collection_ok'],conformance=r['conformance'],error=r.get('error'),passed=r.get('passed'),failed=r.get('failed'))))
