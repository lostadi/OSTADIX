#!/usr/bin/env python3
"""Actual private native Linux sole-task exit60/231 lifecycle gate.

An owned CPL3 fixture exercises production registries and scheduler. This is
not an upstream application, general Linux ABI or final platform qualification.
"""
import argparse,hashlib,importlib.util,json,os,re,selectors,shutil,socket,subprocess,tempfile,time,traceback,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];KERNEL=ROOT/'ocore/kernel';RUNTIME=ROOT/'ocore/runtime/x86_64';COMMON=ROOT/'ocore/runtime/common'
def info(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
BASE=load('idle_build_base',KERNEL/'native_tls/verify.py')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path);ap.add_argument('--compiler',required=True,type=Path);ap.add_argument('--codec-manifest',required=True,type=Path);ap.add_argument('--qemu',type=Path,default=Path.home()/'.local/opt/qemu-11.1.3/bin/qemu-system-x86_64');ap.add_argument('--boot-source',type=Path,default=KERNEL/'boot.S',help='Explicit recorded boot source for owned semantic mutation tests; default is production boot.S');ap.add_argument('--scheduler-source',type=Path,default=RUNTIME/'scheduler.oc',help='Explicit captured scheduler source for owned semantic counterfactuals');ap.add_argument('--process-source',type=Path,default=RUNTIME/'linux_process_syscalls.oc',help='Explicit captured process service source for owned semantic counterfactuals');ap.add_argument('--timeout',type=float,default=90);ap.add_argument('--negative-case',type=int,default=0,choices=range(19));ap.add_argument('--status-group',type=int,default=0,choices=range(5));a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 result={'schema':'ostadix.native-linux-sole-task-exit/v1','ok':False,'scope':__doc__,'negative_case':a.negative_case,'status_group':a.status_group,'commands':[]}
 def write(): (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 def run(name,argv):
  argv=list(map(str,argv));start=time.monotonic();r=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=180);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr);result['commands'].append({'name':name,'argv':argv,'returncode':r.returncode,'seconds':time.monotonic()-start,'stdout':info(out/(name+'.stdout')),'stderr':info(out/(name+'.stderr'))});write()
  if r.returncode:raise RuntimeError(name+' failed: '+(r.stdout+r.stderr)[-5000:].decode(errors='replace'))
  return r.stdout.decode()
 try:
  clang=Path(shutil.which('clang'));lld=Path(shutil.which('ld.lld'));nm=Path(shutil.which('nm'))
  tools=[a.compiler,a.qemu,clang,lld,nm];result['tools']=[info(p) for p in tools];result['python']=info(Path('/proc/self/exe'))
  sources=[RUNTIME/(n+'.oc') for n in BASE.RUNTIME_NAMES+['linux_thread_syscalls','linux_process_syscalls']]+[KERNEL/(n+'.oc') for n in BASE.KERNEL_NAMES]+[KERNEL/'x86_64/boot_info_stub.oc']+[COMMON/(n+'.oc') for n in ['namespace_store','u9fs_codec','posix_namespace_files']]
  sources=[a.scheduler_source.resolve() if x==RUNTIME/'scheduler.oc' else a.process_source.resolve() if x==RUNTIME/'linux_process_syscalls.oc' else x for x in sources]
  originals=sources+[KERNEL/'boot.S',KERNEL/'linker.ld',KERNEL/'m6_stub.oc',KERNEL/'bind-image.py',ROOT/'ocore/user/pack_ovfs.py',ROOT/'ocore/user/verify_ovfs.py',ROOT/'scripts/okernel_native_codec.py',KERNEL/'native_tls/verify.py',KERNEL/'native_tls/entry.S',KERNEL/'native_tls/user.ld',HERE/'probe.oc',HERE/'fixture.c',HERE/'platform.S',HERE/'scheduler_test_hooks.oc.inc',Path(__file__)];originals += [a.boot_source.resolve()] if a.boot_source.resolve()!=(KERNEL/'boot.S').resolve() else [];originals=list(dict.fromkeys(originals+[RUNTIME/'scheduler.oc',RUNTIME/'linux_process_syscalls.oc']));before=[info(p) for p in originals];result['source_before']=before;result['selected_boot_source']=info(a.boot_source)
  for source in originals:
   relative=source.relative_to(ROOT) if source.is_relative_to(ROOT) else Path('_external')/info(source)['sha256']/source.name
   dest=out/'source'/relative;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(source.read_bytes());dest.chmod(0o444)
  codec=load('idle_codec_stage',ROOT/'scripts/okernel_native_codec.py');frozen=codec.stage(a.codec_manifest.resolve(),out/'codec','x86_64');result['codec_manifest']=info(a.codec_manifest);result['codec_objects']=frozen['objects']
  run('fixture-compile',[clang,f'-DOCORE_NEGATIVE_CASE={a.negative_case}',f'-DOCORE_STATUS_GROUP={a.status_group}','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-mno-sse','-mno-sse2','-mno-red-zone','-c',HERE/'fixture.c','-o',out/'fixture.o'])
  run('fixture-entry',[clang,'-c',KERNEL/'native_tls/entry.S','-o',out/'entry.o']);run('fixture-link',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','-z','max-page-size=0x1000','-T',KERNEL/'native_tls/user.ld','-o',out/'fixture.elf',out/'entry.o',out/'fixture.o'])
  run('pack-ovfs',['python3','-B',ROOT/'ocore/user/pack_ovfs.py',out/'images','--entry','/bin/probe.elf',out/'fixture.elf','3']);images=list((out/'images').glob('root-*.ovfs'));assert len(images)==1;image=images[0];run('verify-ovfs',['python3','-B',ROOT/'ocore/user/verify_ovfs.py',image]);run('bind-image',['python3','-B',KERNEL/'bind-image.py',HERE/'probe.oc',image,out/'probe.oc','--prefix','PROBE_IMAGE_'])
  BASE.REPLACEMENTS=set(BASE.REPLACEMENTS)|{'kernel_m6_linux_process_exit','kernel_m6_prepare_bounded_resume'};adapter=BASE.adapters((KERNEL/'m6_stub.oc').read_text()).replace('module kernel::m6;','').replace('use runtime::native_abi::ERR_NOT_IMPLEMENTED;','');probe=(out/'probe.oc').read_text().replace('module kernel::m6;','module kernel::m6;\nuse runtime::native_abi::ERR_NOT_IMPLEMENTED;');probe=probe.replace('const NEGATIVE_CASE: u64 = 0;',f'const NEGATIVE_CASE: u64 = {a.negative_case};').replace('const STATUS_GROUP: u64 = 0;',f'const STATUS_GROUP: u64 = {a.status_group};');
  if 6<=a.negative_case<=14:
   probe=probe.replace('module kernel::m6;','module kernel::m6;\nuse runtime::scheduler::exit_probe_negative;').replace('unsafe fn negative_action(kind: u64) -> u64 { return 99; }','unsafe fn negative_action(kind: u64) -> u64 { return exit_probe_negative(kind); }')
   original_scheduler=a.scheduler_source.resolve();instrumented=out/'scheduler-instrumented.oc';instrumented.write_bytes(original_scheduler.read_bytes()+b'\n'+(HERE/'scheduler_test_hooks.oc.inc').read_bytes());sources=[instrumented if x==original_scheduler else x for x in sources];result['instrumented_scheduler']=info(instrumented);result['instrumentation_composition']={'production':info(original_scheduler),'fragment':info(HERE/'scheduler_test_hooks.oc.inc'),'separator_hex':'0a','rule':'exact production bytes then LF then captured fragment; no standalone module'}
  (out/'probe.oc').write_text(probe+'\n'+adapter);result['generated_probe']=info(out/'probe.oc')
  rebuilt=[]
  for i in (1,2):
   run(f'kernel-object-{i}',[a.compiler,*sources,out/'probe.oc','--target','x86_64-unknown-none','--emit','obj','--function-sections','-o',out/f'kernel-{i}.o']);run(f'boot-object-{i}',[clang,'-target','x86_64-unknown-none-elf','-c','-x','assembler-with-cpp','-DOCORE_PROBE_MODE=25','-DOCORE_BOOT_INFO_ENABLED=0',f'-DOCORE_M6_LINUX_IMAGE_PATH="{image}"',a.boot_source,'-o',out/f'boot-{i}.o']);run(f'platform-object-{i}',[clang,'-target','x86_64-unknown-none-elf','-c',HERE/'platform.S','-o',out/f'platform-{i}.o']);elf=out/f'kernel-{i}.elf';run(f'kernel-link-{i}',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','--gc-sections','-z','max-page-size=0x1000','-T',KERNEL/'linker.ld','-o',elf,out/f'boot-{i}.o',out/f'kernel-{i}.o',out/f'platform-{i}.o',*[x['path'] for x in frozen['objects']]]);rebuilt.append(info(elf))
  result['kernel_rebuilds']=rebuilt;assert rebuilt[0]['sha256']==rebuilt[1]['sha256'];result['fixture']=info(out/'fixture.elf');result['image']=info(image);assert not run('undefined',[nm,'-u',out/'kernel-1.elf']).strip();symtext=run('symbols',[nm,'-S',out/'kernel-1.elf']);symbols={line.split()[-1]:int(line.split()[0],16) for line in symtext.splitlines() if len(line.split())>=3 and re.fullmatch('[0-9a-fA-F]+',line.split()[0])};sizes={line.split()[-1]:int(line.split()[1],16) for line in symtext.splitlines() if len(line.split())==4 and re.fullmatch('[0-9a-fA-F]+',line.split()[1])};result['qemu_version']=run('qemu-version',[a.qemu,'--version'])
  with tempfile.TemporaryDirectory(prefix='oexit.',dir='/tmp') as sockets:
   qmp=Path(sockets)/'q';argv=[str(a.qemu),'-machine','q35','-cpu','max','-accel','tcg','-m','128M','-smp','1','-display','none','-monitor','none','-serial','stdio','-no-reboot','-no-shutdown','-d','int','-D',str(out/'qemu-interrupts.log'),'-qmp',f'unix:{qmp},server=on,wait=off','-kernel',str(out/'kernel-1.elf')];result['qemu_argv']=argv;proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);result['owned_qemu_pid']=proc.pid
   try:
    selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ);transcript=bytearray();deadline=time.monotonic()+a.timeout;unsupported_deadline=None
    while time.monotonic()<deadline:
     if proc.poll() is not None:raise RuntimeError('owned QEMU exited '+str(proc.returncode))
     for key,_ in selector.select(.05):
      chunk=os.read(key.fd,65536)
      if chunk:transcript.extend(chunk);(out/'console.log').write_bytes(transcript)
     if b'M02 KERNEL FAULT: halted' in transcript:raise RuntimeError('actual kernel fault')
     markers=re.findall(rb'NATIVE EXIT PROBE: ([0-9a-f]{16})\n',transcript)
     if any(m not in (b'00000041524d4544',b'0000000050415353',b'4e45474154495645') for m in markers):raise RuntimeError('probe rejection '+str(markers))
     if a.negative_case in (5,16,18) and b'NATIVE EXIT PROBE: 00000041524d4544\n' in transcript:
      if unsupported_deadline is None:unsupported_deadline=time.monotonic()+1
      if time.monotonic()>=unsupported_deadline:break
     if (a.negative_case in (0,3,4,15) and b'NATIVE EXIT PROBE: 0000000050415353\n' in transcript) or (a.negative_case not in (0,3,4,15) and b'NATIVE EXIT PROBE: 4e45474154495645\n' in transcript):break
    else:raise TimeoutError('actual idle architecture gate timed out')
    result['console']=info(out/'console.log')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
     connection.settimeout(10);connection.connect(str(qmp));stream=connection.makefile('rwb',buffering=0);result['qmp_greeting']=json.loads(stream.readline())
     def request(command,arguments=None):
      req={'execute':command}
      if arguments is not None:req['arguments']=arguments
      stream.write(json.dumps(req).encode()+b'\n')
      while True:
       reply=json.loads(stream.readline())
       if 'error' in reply:raise RuntimeError(reply)
       if 'return' in reply:return reply['return']
     request('qmp_capabilities');request('stop');result['registers']=request('human-monitor-command',{'command-line':'info registers'});state={}
     if a.negative_case in (0,3,4,15):
      samples=[];result['halt_samples']=samples;halted=False
      for attempt in range(40):
       regs=request('human-monitor-command',{'command-line':'info registers'});result['registers']=regs
       ip=re.search(r'RIP=([0-9a-fA-F]+)',regs);sp=re.search(r'RSP=([0-9a-fA-F]+)',regs);flags=re.search(r'RFL=([0-9a-fA-F]+)',regs)
       good=bool(ip and sp and flags and 'HLT=1' in regs and (int(flags.group(1),16)&0x200) and symbols['ocore_scheduler_idle']<=int(ip.group(1),16)<symbols['ocore_scheduler_idle']+sizes['ocore_scheduler_idle'] and symbols['stack_bottom']<=int(sp.group(1),16)<=symbols['stack_top'])
       samples.append({'attempt':attempt,'registers':regs,'dedicated_halted_idle':good})
       if good:halted=True;break
       if attempt<39:request('cont');time.sleep(.02);request('stop')
      assert halted,'no dedicated management HLT/IF/RSP witness in 40 stopped samples'
      result['halted_state_witness']={'rip':int(ip.group(1),16),'rsp':int(sp.group(1),16),'rflags':int(flags.group(1),16),'function_start':symbols['ocore_scheduler_idle'],'function_bytes':sizes['ocore_scheduler_idle'],'samples':len(samples)}
     fields=[('kernel__m6',x,32,8) for x in ['USER_BASES','CALLS','THREADS','OWNERS','READY','SLEPT','WOKE','EXITS','EXIT_DONE','EXIT_RAW','CLEANUP_CALLS','REFUSALS','REGISTERED','SENTINEL_PHYSICAL','SENTINEL_VALUES','ATTEMPTS','REJECTED','ALLOWED']]+[('kernel__m6',x,8,8) for x in ['ACCEPTED','WINDOW','SLEEP_IDLE_TICKS','FINAL_IDLE_TICKS','IDLE_CR3','IDLE_STACK','IDLE_GS','IDLE_KERNEL_GS','NEGATIVE_READY','NEGATIVE_RETURN','SURVIVOR']]+[('runtime__scheduler',x,1,1) for x in ['IDLE_POLICY','ACTIVE','COMPLETE','FAILED','PENDING_ACTION','PENDING_LINUX_EXIT','SYSCALL_PHASE','SYSCALL_IDLE_DISPOSITION']]+[('runtime__scheduler',x,8,8) for x in ['IDLE_TRANSITIONS','IDLE_TICKS','PENDING_SERIAL','SYSCALL_THREAD','SYSCALL_PROCESS','SYSCALL_FRAME','HOSTILE_FRAME_CONTAINMENTS','CONTEXT_SWITCHES']]+[('runtime__thread',x,4,1) for x in ['STATES','PROCESS_REF_HELD','LINUX_SINGLE_TASK']]+[('runtime__thread',x,8,8) for x in ['CURRENT_THREAD']]+[('runtime__thread',x,32,8) for x in ['USER_FS_BASES','CLEAR_CHILD_TIDS']]+[('runtime__thread',x,8,2) for x in ['USER_FS_SELECTORS']]+[('runtime__process',x,4,1) for x in ['STATES']]+[('runtime__process',x,8,8) for x in ['CURRENT_PROCESS']]+[('runtime__process',x,32,8) for x in ['EXIT_CODES']]+[('runtime__process',x,16,4) for x in ['THREAD_REFS']]+[('runtime__posix_file_syscalls','ENABLED',8,1),('runtime__common__posix_namespace_files','FD_DESCRIPTION',512,8),('runtime__linux_process_syscalls','POLICY_ID',8,8)]
     for module,name,n,width in fields:
      symbol='_O_'+module+'__'+name;path=out/(module+'__'+name+'.bin');request('pmemsave',{'val':symbols[symbol],'size':n,'filename':str(path)});raw=path.read_bytes();state[module+'__'+name]=[int.from_bytes(raw[i:i+width],'little') for i in range(0,n,width)]
     result['state']=state
     def get(m,n):return state[m+'__'+n]
     if a.negative_case in (0,3,4,15):
      raws=[[0,0,1,1],[42,42,255,255],[256,256,(1<<64)-1,(1<<64)-1],[0x8123456789abcdef]*2+[(1<<64)-31]*2,[(1<<64)-32]*2+[0x100000001]*2][a.status_group];expected=[(x&255)<<8 for x in raws]
      assert get('kernel__m6','EXIT_DONE')==[1]*4 and get('kernel__m6','CLEANUP_CALLS')==[1]*4
      assert get('kernel__m6','EXIT_RAW')==raws and get('kernel__m6','EXITS')==expected and get('runtime__process','EXIT_CODES')==expected
      assert len(set(get('kernel__m6','USER_BASES')))==4 and all(get('kernel__m6','USER_BASES'))
      for name in ['READY','SLEPT','WOKE']:assert get('kernel__m6',name)==[1]*4
      assert get('kernel__m6','SURVIVOR')==[3] and get('kernel__m6','WINDOW')==[0] and get('kernel__m6','ACCEPTED')==[1]
      assert get('kernel__m6','SLEEP_IDLE_TICKS')[0]>=2 and get('kernel__m6','FINAL_IDLE_TICKS')[0]>=5
      assert get('kernel__m6','IDLE_GS')==[symbols['percpu_entry']] and get('kernel__m6','IDLE_KERNEL_GS')==[0]
      assert get('kernel__m6','IDLE_CR3')==[symbols['p4_table']] and symbols['stack_bottom']<=get('kernel__m6','IDLE_STACK')[0]<symbols['stack_top']
      assert get('runtime__scheduler','ACTIVE')==[1] and get('runtime__scheduler','IDLE_POLICY')==[1]
      for name in ['COMPLETE','FAILED','PENDING_ACTION','PENDING_LINUX_EXIT','SYSCALL_PHASE','SYSCALL_IDLE_DISPOSITION','PENDING_SERIAL','SYSCALL_THREAD','SYSCALL_PROCESS','SYSCALL_FRAME','HOSTILE_FRAME_CONTAINMENTS']:assert get('runtime__scheduler',name)==[0]
      assert get('runtime__thread','STATES')==[4]*4 and get('runtime__process','STATES')==[5]*4
      for m,n in [('runtime__thread','PROCESS_REF_HELD'),('runtime__thread','CURRENT_THREAD'),('runtime__thread','USER_FS_BASES'),('runtime__thread','USER_FS_SELECTORS'),('runtime__thread','LINUX_SINGLE_TASK'),('runtime__thread','CLEAR_CHILD_TIDS'),('runtime__process','CURRENT_PROCESS'),('runtime__process','THREAD_REFS'),('runtime__posix_file_syscalls','ENABLED'),('runtime__common__posix_namespace_files','FD_DESCRIPTION')]:assert not any(get(m,n))
      assert get('kernel__m6','REFUSALS')==([1,0,0,0] if a.negative_case in (3,4) else [0]*4)
      regs=result['registers'];assert re.search(r'FS =0000 0000000000000000',regs);assert re.search(r'GS =0000 '+format(symbols['percpu_entry'],'016x'),regs);assert 'CR3='+format(symbols['p4_table'],'016x') in regs
     elif a.negative_case in (1,2,17):
      assert get('kernel__m6','NEGATIVE_READY')==[1] and get('kernel__m6','REJECTED')==[1]*4
      assert get('kernel__m6','CLEANUP_CALLS')==[0]*4 and get('kernel__m6','EXIT_DONE')==[0]*4 and get('runtime__process','EXIT_CODES')==[0]*4
      assert get('runtime__scheduler','FAILED')==[0] and get('runtime__scheduler','ACTIVE')==[1]
      assert get('runtime__scheduler','PENDING_ACTION')==[0] and get('runtime__scheduler','PENDING_LINUX_EXIT')==[0]
      assert get('kernel__m6','REFUSALS')==([2]*4 if a.negative_case==1 else [2,0,0,0])
     elif a.negative_case in (5,16,18):
      assert get('runtime__scheduler','FAILED')==[1] and get('runtime__scheduler','ACTIVE')==[0]
      assert get('kernel__m6','ALLOWED')[0]==(0 if a.negative_case==5 else 1) and get('kernel__m6','CLEANUP_CALLS')[0]==(1 if a.negative_case==18 else 0) and get('kernel__m6','EXIT_DONE')[0]==0
      assert get('runtime__process','THREAD_REFS')[0]==(2 if a.negative_case==16 else 1) and get('runtime__thread','STATES')[0]==2
      for name in ['PENDING_ACTION','PENDING_LINUX_EXIT','PENDING_SERIAL','SYSCALL_PHASE']:assert get('runtime__scheduler',name)==[0]
     elif 6<=a.negative_case<=14:
      assert get('kernel__m6','NEGATIVE_READY')==[1]
      assert get('kernel__m6','NEGATIVE_RETURN')==[3 if a.negative_case in (6,7,9) else 0]
      assert get('runtime__scheduler','FAILED')==[1] and get('runtime__scheduler','ACTIVE')==[0]
      assert get('kernel__m6','CLEANUP_CALLS')==[0]*4 and get('kernel__m6','EXIT_DONE')==[0]*4
      assert get('runtime__process','THREAD_REFS')==[1]*4 and get('runtime__process','EXIT_CODES')==[0]*4
      assert get('runtime__scheduler','SYSCALL_PHASE')==[0] and get('runtime__scheduler','HOSTILE_FRAME_CONTAINMENTS')==[0]
      if a.negative_case==6:
       assert get('runtime__scheduler','PENDING_ACTION')==[4] and get('runtime__scheduler','PENDING_LINUX_EXIT')==[1] and get('runtime__scheduler','PENDING_SERIAL')[0]!=0
      elif a.negative_case==7:
       assert get('runtime__scheduler','PENDING_ACTION')==[0] and get('runtime__scheduler','PENDING_LINUX_EXIT')==[1] and get('runtime__scheduler','PENDING_SERIAL')==[0]
      else:
       for name in ['PENDING_ACTION','PENDING_LINUX_EXIT','PENDING_SERIAL']:assert get('runtime__scheduler',name)==[0]
     else:raise AssertionError('unqualified test case')
     result['sentinels']=[]
     for i,(physical,value) in enumerate(zip(get('kernel__m6','SENTINEL_PHYSICAL'),get('kernel__m6','SENTINEL_VALUES'))):
      assert physical and value==0x9876543200000000+i
      path=out/f'child-sentinel-{i}.bin';request('pmemsave',{'val':physical,'size':8,'filename':str(path)});raw=path.read_bytes();assert int.from_bytes(raw,'little')==value
      result['sentinels'].append({'physical':physical,'expected':value,'observed':int.from_bytes(raw,'little'),'artifact':info(path)})
     result['hardware_interrupt_trace']=info(out/'qemu-interrupts.log')
   finally:
    if sys.exc_info()[0] is not None and proc.poll() is None and 'state' not in result:
     # Failure-only diagnostic: it cannot set acceptance or replace the error.
     try:
      with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as diag:
       diag.settimeout(3);diag.connect(str(qmp));ds=diag.makefile('rwb',buffering=0);json.loads(ds.readline())
       def dq(command,arguments=None):
        value={'execute':command}
        if arguments is not None:value['arguments']=arguments
        ds.write(json.dumps(value).encode()+b'\n')
        while True:
         reply=json.loads(ds.readline())
         if 'error' in reply:raise RuntimeError(reply)
         if 'return' in reply:return reply['return']
       dq('qmp_capabilities');dq('stop');diagnostic={'registers':dq('human-monitor-command',{'command-line':'info registers'}),'state':{}}
       for module,name,n,width in [('runtime__thread','STATES',4,1),('runtime__process','STATES',4,1),('kernel__m6','EXIT_DONE',32,8),('kernel__m6','CLEANUP_CALLS',32,8),('runtime__scheduler','HOSTILE_FRAME_CONTAINMENTS',8,8),('runtime__scheduler','FAILED',1,1),('runtime__scheduler','ACTIVE',1,1)]:
        dp=out/f'failure-{module}__{name}.bin';dq('pmemsave',{'val':symbols['_O_'+module+'__'+name],'size':n,'filename':str(dp)});raw=dp.read_bytes();diagnostic['state'][module+'__'+name]={'artifact':info(dp),'values':[int.from_bytes(raw[j:j+width],'little') for j in range(0,n,width)]}
       result['failure_diagnostic']=diagnostic
     except Exception as diagnostic_error:result['failure_diagnostic_error']=repr(diagnostic_error)
    proc.terminate()
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=10)
    result['owned_qemu_returncode']=proc.returncode
  after=[info(p) for p in originals];result['source_after']=after;assert before==after
  result['ok']=True
 except Exception as e:result['error']=repr(e);result['traceback']=traceback.format_exc()
 finally:
  if "originals" in locals():
   result["source_after"]=[info(p) for p in originals];result["source_unchanged"]=result.get("source_before")==result["source_after"]
   if not result["source_unchanged"]:result["ok"]=False
  write()
 print(json.dumps({'ok':result['ok'],'result':str(out/'result.json'),'error':result.get('error')},indent=2));return 0 if result['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
