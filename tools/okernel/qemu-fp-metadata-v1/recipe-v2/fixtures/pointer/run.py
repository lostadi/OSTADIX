
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
import hashlib,json,os,shutil,subprocess,time,traceback
import checker
B=Path(__file__).resolve().parent
SDK=Path('/home/ustad/.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin')
QEMU=Path('/home/ustad/.local/opt/qemu-11.1.3/bin/qemu-system-x86_64')
CODE=Path('/usr/share/OVMF/OVMF_CODE_4M.fd');VARS=Path('/usr/share/OVMF/OVMF_VARS_4M.fd')
EXPECTED_QEMU='72b4a0b1e1a47488bfce74843c5acf17ad1a8dadc1ff3c492b2b574f91f5f176'
def pin(p):
 p=Path(p);d=p.read_bytes();return {'path':str(p),'resolved':str(p.resolve()),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}
def write(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def main():
 out=B/'attempt-5';out.mkdir(exist_ok=False);src=out/'source';src.mkdir()
 before=[pin(B/n)for n in ['probe.S','checker.py','run.py']]
 for p in before:shutil.copyfile(p['path'],src/Path(p['path']).name)
 commands=[];r={'schema':'ostadix.actual-qemu-fx-pointer-diagnostic/v1','collection_ok':False,'isa_pointer_conformance':False,'full_state_profile_admitted':False,'scope':'Authored assembly EFI application on pinned installed QEMU/TCG only; not native O-core/physical/kernel implementation','source_before':before,'commands':commands,'no_production_source_or_old_state_changes':True}
 tools=[SDK/'clang',SDK/'lld-link',SDK/'llvm-objdump',QEMU,CODE,VARS,Path('/usr/sbin/mkfs.vfat'),Path('/usr/bin/mmd'),Path('/usr/bin/mcopy')];r['tools_before']=[pin(p)for p in tools];assert pin(QEMU)['sha256']==EXPECTED_QEMU
 write(out/'result.json',r)
 def run(name,argv,timeout=30):
  start=time.monotonic();p=subprocess.run([str(x)for x in argv],cwd=out,capture_output=True,timeout=timeout);so=out/(name+'.stdout');se=out/(name+'.stderr');so.write_bytes(p.stdout);se.write_bytes(p.stderr);commands.append({'name':name,'argv':[str(x)for x in argv],'exit_code':p.returncode,'seconds':time.monotonic()-start,'stdout':pin(so),'stderr':pin(se)});write(out/'result.json',r)
  if p.returncode:raise RuntimeError(name+' failed; see retained stderr')
  return p
 try:
  run('clang-version',[SDK/'clang','--version']);run('lld-version',[SDK/'lld-link','--version']);run('qemu-version',[QEMU,'--version'])
  run('assemble',[SDK/'clang','--target=x86_64-pc-windows-msvc','-c',src/'probe.S','-o',out/'probe.obj'])
  esp=out/'esp'/'EFI'/'BOOT';esp.mkdir(parents=True)
  exports=['efi_main','fp_load_normal','operand_a','fp_fault_a','zero_a','fp_load_b','operand_b','fp_fault_b','zero_b','fx_a_w','fx_a_l','fx_crafted','save_a_w','save_a_l','restore_a_w','restore_crafted_w','restore_a_l']
  run('link',[SDK/'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64','/base:0x100000','/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(out/'probe.map'),'/out:'+str(esp/'BOOTX64.EFI'),*[('/export:'+n)for n in exports],out/'probe.obj'])
  run('object-disassembly',[SDK/'llvm-objdump','-d','--x86-asm-syntax=intel',out/'probe.obj'])
  run('efi-disassembly',[SDK/'llvm-objdump','-d','--x86-asm-syntax=intel',esp/'BOOTX64.EFI'])
  r['application']=pin(esp/'BOOTX64.EFI');r['object']=pin(out/'probe.obj');r['image_sections']={k:v for k,v in checker.inspect_pe((esp/'BOOTX64.EFI').read_bytes()).items()if k!='offset'}
  disk=out/'esp.img'
  run('fat-image',['/usr/sbin/mkfs.vfat','-C','-F','16','-n','FPPROBE',disk,'16384'])
  run('fat-directories',['/usr/bin/mmd','-i',disk,'::/EFI','::/EFI/BOOT'])
  run('fat-copy',['/usr/bin/mcopy','-i',disk,esp/'BOOTX64.EFI','::/EFI/BOOT/BOOTX64.EFI'])
  r['esp_before']=pin(disk)
  varsfile=out/'OVMF_VARS_4M.private.fd';shutil.copyfile(VARS,varsfile);r['variables_before']=pin(varsfile)
  serial=out/'serial.log';err=out/'qemu.stderr';stdout=out/'qemu.stdout'
  argv=[str(QEMU),'-L',str(B.parent/'source/qemu-11.1.3/pc-bios'),'-machine','q35','-accel','tcg','-cpu','Nehalem-v1,+x2apic','-m','128M','-smp','1','-nodefaults','-display','none','-monitor','none','-serial','file:'+str(serial),'-nic','none','-no-reboot','-drive','if=pflash,format=raw,readonly=on,file='+str(CODE),'-drive','if=pflash,format=raw,file='+str(varsfile),'-drive','if=none,id=esp,format=raw,readonly=on,file='+str(disk),'-device','virtio-blk-pci,drive=esp','-device','isa-debug-exit,iobase=0xf4,iosize=0x04']
  start=time.monotonic()
  with stdout.open('wb')as so,err.open('wb')as se:
   p=subprocess.Popen(argv,cwd=out,stdout=so,stderr=se,start_new_session=True,preexec_fn=_owned_parent_death);stat=Path('/proc')/str(p.pid)/'stat';r['owned_process']={'pid':p.pid,'pgid':p.pid,'start_ticks':stat.read_text().split()[21],'argv':argv};write(out/'result.json',r)
   try:status=p.wait(timeout=60)
   except subprocess.TimeoutExpired:
    r['timed_out']=True;p.terminate()
    try:status=p.wait(timeout=3)
    except subprocess.TimeoutExpired:p.kill();status=p.wait(timeout=3)
    raise TimeoutError('owned diagnostic QEMU timed out; retained serial/stderr')
  r['qemu_status']=status;r['qemu_seconds']=time.monotonic()-start;r['qemu_stdout']=pin(stdout);r['qemu_stderr']=pin(err);r['serial']=pin(serial);r['variables_after']=pin(varsfile);r['esp_after']=pin(disk);assert r['esp_before']==r['esp_after'];write(out/'result.json',r)
  assert status==33,('unexpected debug-exit status',status)
  analysis=checker.analyze(esp/'BOOTX64.EFI',serial,out/'decoded');r['analysis']=pin(out/'decoded/analysis.json');r['collection_ok']=analysis['collection_ok'];r['isa_pointer_conformance']=analysis['isa_pointer_conformance'];r['classification']='conforming_pointer_probe'if analysis['isa_pointer_conformance']else'actual_emulator_pointer_contract_RED'
 except Exception as e:r['error']=repr(e);(out/'controller-error.log').write_text(traceback.format_exc())
 finally:
  r['source_after']=[pin(B/n)for n in ['probe.S','checker.py','run.py']];r['sources_unchanged']=before==r['source_after'];r['tools_after']=[pin(p)for p in tools];r['tools_unchanged']=r['tools_before']==r['tools_after'];write(out/'result.json',r)
 print(json.dumps({'result':pin(out/'result.json'),'collection_ok':r['collection_ok'],'conformance':r['isa_pointer_conformance'],'error':r.get('error')}))
if __name__=='__main__':main()
