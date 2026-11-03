#!/usr/bin/env python3
"""Build/run an isolated production x86 CPL3 native-file boundary profile.

This uses selector25 boot/router machinery with a dedicated probe, not the
historical Mode25 corpus. No default images, launchers, VMs or state are used.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import socket
import subprocess
import tempfile
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
RUNTIME=ROOT/'ocore/runtime/x86_64'
KERNEL=ROOT/'ocore/kernel'
COMMON=ROOT/'ocore/runtime/common'
PROFILE='native-thread-fs-x86_64'
RUNTIME_NAMES='serial pages user_memory domain_namespace image_vfs_storage image_vfs elf_loader service_registry package_root live_supervisor serial_control native_control address_space native_abi personality domain process thread scheduler capability memory_object endpoint cap_transfer ipc_wait ipc_lifecycle personality_supervision personality_rpc kernel_world_record kernel_world_admission kernel_world_device_stub kernel_world_boot_stub vm_object svm_execution kernel_world_execution_stub mapping interrupts trap syscall user m1_user m2_user m3_user posix_file_syscalls linux_tls_syscalls'.split()
KERNEL_NAMES='m1_mode25_stub m2_mode25_stub m3_mode25_stub m3_live_mode25_stub m4_mode25_stub m5_stub m5_selftest_stub m5_semantics_stub m6b_semantics_stub linux_personality_semantics_stub kernel_world_semantics_stub world_identity_semantics_stub world_protocol_semantics_stub world_value_semantics_stub world_receipt_semantics_stub world_project_receipt_semantics_stub world_native_scalar_semantics_stub capability_boot_test_stub smp_probe_stub scheduler_bridge main'.split()
REPLACEMENTS={'start','kernel_m6_linux_syscall','kernel_m6_service_fault','kernel_m6_expire_requests','kernel_m6_phase_one_ready','kernel_m6_crash_continue'}

def info(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def write(p,d):p.write_text(json.dumps(d,indent=2)+'\n')

def adapters(text):
 for name in sorted(REPLACEMENTS):
  pattern=rf'(?:@export\s+@no_mangle\s+)?pub unsafe fn {name}\('
  found=list(re.finditer(pattern,text))
  if len(found)!=1:raise ValueError('expected exact fail-closed adapter '+name)
  start=found[0].start();opening=text.index('{',found[0].end());depth=1;cursor=opening+1
  while depth:
   if text[cursor]=='{':depth+=1
   elif text[cursor]=='}':depth-=1
   cursor+=1
  text=text[:start]+text[cursor:]
 return text

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--output',type=Path,required=True)
 parser.add_argument('--codec-manifest',type=Path,required=True)
 parser.add_argument('--compiler',type=Path,default=ROOT/'target/debug/ocorec')
 parser.add_argument('--qemu',type=Path,default=Path.home()/'.local/opt/qemu-11.1.3/bin/qemu-system-x86_64')
 parser.add_argument('--timeout',type=float,default=90)
 args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
 commands=[];result={'schema':'ostadix.native-thread-fs-cpl3/v1','profile':PROFILE,'ok':False,'scope':'Production native O-core per-TCB FS selector/base capture and restore, ARCH_SET_FS/GET_FS and file/syscall boundary in isolated x86 QEMU CPL3; not original libc/application or Linux/Plan9 OS admission','selector_reuse':'25 for unchanged boot/router selection only; not canonical Mode25 corpus acceptance','platform':{'RAM_bytes':134217728,'CPUs':1,'reserved_native_volume_physical':[67108864,83886080],'volume_mapping':'Temporary supervisor-only RW/NX huge-page aperture during masked synchronous calls; absent on user/scheduler returns','copy_fault_injection':'One second-chunk user-data PTE temporarily absent during actual kernel copy, restored before return'},'commands':commands,'live_existing_vm_actions':[],'launcher_updates':[],'kernel_image_promotions':[]}
 def run(name,argv,timeout=120):
  argv=[str(a) for a in argv];start=time.monotonic();r=subprocess.run(argv,cwd=output,capture_output=True,text=True,timeout=timeout)
  log=output/(name+'.log');log.write_text(r.stdout+r.stderr);commands.append({'name':name,'argv':argv,'exit_code':r.returncode,'seconds':time.monotonic()-start,'log':info(log)})
  if r.returncode:raise RuntimeError(name+': '+(r.stdout+r.stderr)[-5000:])
  return r.stdout
 try:
  clang=Path(shutil.which('clang') or '');lld=Path(shutil.which('ld.lld') or '');nm=Path(shutil.which('nm') or '')
  for p in [args.compiler,args.qemu,clang,lld,nm]:
   if not p.is_file():raise ValueError('missing explicit tool '+str(p))
  sources=[RUNTIME/(n+'.oc') for n in RUNTIME_NAMES]+[KERNEL/(n+'.oc') for n in KERNEL_NAMES]+[KERNEL/'x86_64/boot_info_stub.oc']+[COMMON/(n+'.oc') for n in ['namespace_store','u9fs_codec','posix_namespace_files']]
  originals=sources+[KERNEL/'boot.S',KERNEL/'linker.ld',KERNEL/'m6_stub.oc',KERNEL/'bind-image.py',ROOT/'ocore/user/pack_ovfs.py',ROOT/'ocore/user/verify_ovfs.py',ROOT/'scripts/okernel_native_codec.py',HERE/'probe.oc',HERE/'fixture.c',HERE/'entry.S',HERE/'platform.S',HERE/'user.ld',Path(__file__)]
  before=[info(p) for p in originals];result['source_before']=before;result['tools']=[info(p) for p in [args.compiler,args.qemu,clang,lld,nm]]
  spec=importlib.util.spec_from_file_location('native_file_codec_stage',ROOT/'scripts/okernel_native_codec.py');codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(codec)
  frozen=codec.stage(args.codec_manifest.resolve(),output/'codec','x86_64');result['codec_manifest']=info(args.codec_manifest);result['codec_objects']=frozen['objects']
  (output/'adapters.oc').write_text(adapters((KERNEL/'m6_stub.oc').read_text()))
  run('fixture-compile',[clang,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-mno-sse','-mno-sse2','-mno-red-zone','-c',HERE/'fixture.c','-o',output/'fixture.o'])
  run('fixture-entry',[clang,'-c',HERE/'entry.S','-o',output/'entry.o'])
  run('fixture-link',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','-z','max-page-size=0x1000','-T',HERE/'user.ld','-o',output/'fixture.elf',output/'entry.o',output/'fixture.o'])
  run('pack-ovfs',['python3','-B',ROOT/'ocore/user/pack_ovfs.py',output/'images','--entry','/bin/probe.elf',output/'fixture.elf','3'])
  images=list((output/'images').glob('root-*.ovfs'))
  if len(images)!=1:raise ValueError('expected one exact immutable OVFS image')
  image=images[0];run('verify-ovfs',['python3','-B',ROOT/'ocore/user/verify_ovfs.py',image])
  run('bind-image',['python3','-B',KERNEL/'bind-image.py',HERE/'probe.oc',image,output/'probe.oc','--prefix','PROBE_IMAGE_'])
  adapter_text=(output/'adapters.oc').read_text().replace('module kernel::m6;','').replace('use runtime::native_abi::ERR_NOT_IMPLEMENTED;','')
  probe_text=(output/'probe.oc').read_text().replace('module kernel::m6;','module kernel::m6;\nuse runtime::native_abi::ERR_NOT_IMPLEMENTED;')
  (output/'probe.oc').write_text(probe_text+'\n'+adapter_text)
  built=[]
  for index in range(2):
   suffix=str(index+1)
   run('kernel-object-'+suffix,[args.compiler,*sources,output/'probe.oc','--target','x86_64-unknown-none','--emit','obj','--function-sections','-o',output/('kernel-'+suffix+'.o')])
   run('boot-object-'+suffix,[clang,'-target','x86_64-unknown-none-elf','-c','-x','assembler-with-cpp','-DOCORE_PROBE_MODE=25','-DOCORE_BOOT_INFO_ENABLED=0',f'-DOCORE_M6_LINUX_IMAGE_PATH="{image}"',KERNEL/'boot.S','-o',output/('boot-'+suffix+'.o')])
   run('platform-object-'+suffix,[clang,'-target','x86_64-unknown-none-elf','-c',HERE/'platform.S','-o',output/('platform-'+suffix+'.o')])
   elf=output/('kernel-'+suffix+'.elf')
   run('kernel-link-'+suffix,[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','--gc-sections','-z','max-page-size=0x1000','-T',KERNEL/'linker.ld','-o',elf,output/('boot-'+suffix+'.o'),output/('kernel-'+suffix+'.o'),output/('platform-'+suffix+'.o'),*[x['path'] for x in frozen['objects']]])
   built.append(info(elf))
  if built[0]['sha256']!=built[1]['sha256']:raise ValueError('kernel rebuild bytes differ')
  result['kernel_rebuilds']=built;result['rebuild_scope']='Two native kernel/boot/platform builds using same frozen original-codec objects and same separately compiled fixture; not two upstream source rebuilds'
  result['fixture']=info(output/'fixture.elf');result['image']=info(image);result['undefined_symbols']=run('undefined',[nm,'-u',output/'kernel-1.elf'])
  if result['undefined_symbols'].strip():raise ValueError('native kernel closure unresolved')
  symboltext=run('symbols',[nm,'-S',output/'kernel-1.elf']);symbols={s.split()[-1]:int(s.split()[0],16) for s in symboltext.splitlines() if len(s.split())>=3 and re.fullmatch('[0-9a-fA-F]+',s.split()[0])}
  result['qemu_version']=run('qemu-version',[args.qemu,'--version'])
  with tempfile.TemporaryDirectory(prefix='oposix.',dir='/tmp') as sockets:
   qmp=Path(sockets)/'q';argv=[str(args.qemu),'-machine','q35','-cpu','max','-accel','tcg','-m','128M','-smp','1','-display','none','-monitor','none','-serial','stdio','-no-reboot','-no-shutdown','-d','int','-D',str(output/'qemu-interrupts.log'),'-qmp',f'unix:{qmp},server=on,wait=off','-kernel',str(output/'kernel-1.elf')]
   result['qemu_argv']=argv;proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);result['owned_qemu_pid']=proc.pid
   try:
    selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ);transcript=bytearray();deadline=time.monotonic()+args.timeout
    while time.monotonic()<deadline:
     if proc.poll() is not None:raise RuntimeError('isolated probe QEMU exited '+str(proc.returncode))
     for key,_ in selector.select(.2):
      block=os.read(key.fd,65536)
      if block:transcript.extend(block);(output/'console.log').write_bytes(transcript)
     markers=re.findall(rb'NATIVE POSIX PROBE ([0-9a-f]{16})\n',transcript)
     if b'M02 KERNEL FAULT: halted' in transcript:raise RuntimeError('actual kernel fault; inspect console/interrupt trace')
     for marker in markers:
      if marker not in [b'00000041524d4544',b'0000000050415353']:raise RuntimeError('probe rejected at0x'+marker.decode())
     if b'NATIVE POSIX PROBE 0000000050415353\n' in transcript:break
    else:raise TimeoutError('native probe did not reach acceptance marker')
    result['console']=info(output/'console.log')
    trace=(output/'qemu-interrupts.log').read_text(errors='replace');hardware_faults=[]
    for event in re.finditer(r'(?m)^.*v=0e.*$',trace):
     line=event.group();block=trace[event.start():event.start()+2500]
     ip=re.search(r'IP=[0-9a-fA-F]+:([0-9a-fA-F]+)',line);cr2=re.search(r'CR2=([0-9a-fA-F]+)',block)
     if 'cpl=0' in line and ip and cr2 and symbols['ocore_copy_to_fault_start']<=int(ip.group(1),16)<symbols['ocore_copy_to_fault_end']:
      hardware_faults.append({'line':line,'rip':int(ip.group(1),16),'cr2':int(cr2.group(1),16)})
    if len(hardware_faults)!=1 or not (0x02000000<=hardware_faults[0]['cr2']<0x02100000):raise ValueError('expected exactlyone actual QEMU CPL0 copy-to page fault')
    result['hardware_copy_faults']=hardware_faults;result['hardware_interrupt_trace']=info(output/'qemu-interrupts.log')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
     connection.settimeout(10);connection.connect(str(qmp));stream=connection.makefile('rwb',buffering=0)
     greeting=json.loads(stream.readline());result['qmp_greeting']=greeting
     def request(command,arguments=None):
      data={'execute':command}
      if arguments is not None:data['arguments']=arguments
      stream.write(json.dumps(data).encode()+b'\n')
      while True:
       reply=json.loads(stream.readline())
       if 'error' in reply:raise ValueError(reply)
       if 'return' in reply:return reply['return']
     request('qmp_capabilities');request('stop');result['hardware_interrupt_trace']=info(output/'qemu-interrupts.log');observed={}
     for name,bytes_ in [('WINDOW',8),('DONE',32),('CONTAINED',8),('USER_COPY_FAULTS',8),('WINDOWS',8),('TLS_TESTED',32),('TLS_TIMER_CALLBACKS',32),('TLS_EXPECTED_BASES',32),('TLS_SELECTOR_MASKS',32),('TLS_SELECTOR_TIMER_MASKS',32),('TLS_OBSERVED_SELECTORS',256)]:
      symbol='_O_kernel__m6__'+name
      if symbol not in symbols:raise ValueError('missing actual state symbol '+symbol)
      path=output/(name.lower()+'.bin');request('pmemsave',{'val':symbols[symbol],'size':bytes_,'filename':str(path)})
      raw=path.read_bytes();observed[name]=[int.from_bytes(raw[i:i+8],'little') for i in range(0,len(raw),8)]
     result['runtime_state']=observed
     if observed['WINDOW']!=[0] or observed['DONE']!=[1,1,1,1] or observed['CONTAINED']!=[1] or observed['USER_COPY_FAULTS']!=[1] or observed['WINDOWS'][0]<10:raise ValueError('actual runtime state mismatches '+str(observed))
     if observed['TLS_TESTED']!=[1,1,1,1] or any(x==0 for x in observed['TLS_TIMER_CALLBACKS']) or len(set(observed['TLS_EXPECTED_BASES']))!=4:raise ValueError('actual TLS fixture state mismatch '+str(observed))
     legal_selectors=[*range(0x18,0x1c),*range(0x20,0x24)]
     if observed['TLS_SELECTOR_MASKS']!=[255]*4 or observed['TLS_SELECTOR_TIMER_MASKS']!=[255]*4 or observed['TLS_OBSERVED_SELECTORS']!=legal_selectors*4:raise ValueError('actual selector-RPL capture/restore state mismatch '+str(observed))
     for name,size,width in [('USER_FS_BASES',32,8),('USER_FS_SELECTORS',8,2)]:
      path=output/(name.lower()+'.bin');request('pmemsave',{'val':symbols['_O_runtime__thread__'+name],'size':size,'filename':str(path)})
      raw=path.read_bytes();observed['THREAD_'+name]=[int.from_bytes(raw[i:i+width],'little') for i in range(0,len(raw),width)]
     expected_bases=list(observed['TLS_EXPECTED_BASES']);expected_bases[1]=0
     if observed['THREAD_USER_FS_BASES']!=expected_bases or observed['THREAD_USER_FS_SELECTORS']!=[0,0,0,0]:raise ValueError('actual TCB FS lifecycle state mismatch '+str(observed))
     timers={}
     for event in re.finditer(r'(?m)^.*v=20.*cpl=3.*$',trace):
      state=trace[event.start():event.start()+2200];fs=re.search(r'FS =([0-9a-fA-F]{4}) ([0-9a-fA-F]{16})',state)
      if fs and fs.group(1)=='0000' and int(fs.group(2),16) in observed['TLS_EXPECTED_BASES']:timers.setdefault(fs.group(2),event.group())
     if {int(x,16) for x in timers}!=set(observed['TLS_EXPECTED_BASES']):raise ValueError('QEMU trace lacks actual CPL3 timer entries for every distinct TLS base')
     result['hardware_tls_timer_entries']=timers
     selector_timers={}
     for event in re.finditer(r'(?m)^.*v=20.*cpl=3.*$',trace):
      state=trace[event.start():event.start()+2200];fs=re.search(r'FS =([0-9a-fA-F]{4}) ([0-9a-fA-F]{16})',state)
      if fs and int(fs.group(1),16) in legal_selectors and int(fs.group(2),16)==0:selector_timers.setdefault(fs.group(1),event.group())
     if {int(x,16) for x in selector_timers}!=set(legal_selectors):raise ValueError('QEMU trace lacks actual CPL3 timer entries for every legal selector RPL')
     result['hardware_fs_selector_timer_entries']=selector_timers
     result['registers']=request('human-monitor-command',{'command-line':'info registers'})
     if not re.search(r'FS =0000 0000000000000000',result['registers']):raise ValueError('management hardware FS not selector/base zero')
     control=re.search(r'CR4=([0-9a-fA-F]+)',result['registers'])
     if not control or int(control.group(1),16)&((1<<12)|(1<<16)):raise ValueError('profile requires four-level paging and FSGSBASE disabled')
   finally:
    proc.terminate()
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=10)
  after=[info(p) for p in originals];result['source_after']=after;result['source_stable']=before==after
  if before!=after:raise ValueError('source changed during isolated qualification')
  for p in originals:
   target=output/'source'/p.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(p.read_bytes());target.chmod(0o444)
  result['checks']=['real CPL3 syscall entry and mapped user copies into same native store through original lowered codec','four private loaded CR3s; current-process descriptor isolation and unprovisioned denial','truthful copied argv/env/auxv and mapped program headers at actual fixture entry','supervisor-only transient volume aperture closed before every user/scheduler return','real recoverable kernel-copy page fault restores failing-chunk offset; only4096B returned','scoped process-context withdrawal and generation2 reprovision; other clients survive','production designated#UD fault containment and survivor quiescence','independent QMP reads completed state and no residual aperture; exact kernel double rebuild']
  result['checks'] += ['real user FS canaries at four distinct virtual bases survive syscall yields and actual timer preemption','all eight legal DPL3 descriptor RPL variants survive actual MOV-to-FS, GET_FS, yield and timer capture/restore in all four TCBs; QMP exact captured selector arrays and independent hardware timer traces','ARCH_SET_FS null-selector behavior','GET_FS checked copy and invalid-base/unsupported-operation failure without changing TLS','kernel/management hardware FS zero, faulted TCB state cleared; hosted fixture separately covers reaped generation reuse']
  result['ok']=True
 except Exception as error:
  result['error']=str(error)
 finally:
  write(output/'result.json',result)
 print(json.dumps({'ok':result['ok'],'result':str(output/'result.json'),'error':result.get('error')},indent=2))
 return 0 if result['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
