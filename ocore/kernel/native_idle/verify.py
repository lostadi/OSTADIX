#!/usr/bin/env python3
"""Actual private native empty-runqueue syscall/idle/timer architecture gate.

An owned CPL3 fixture exercises production registries and scheduler. This is
not Linux exit60/231, upstream application or final platform qualification.
"""
import argparse,hashlib,importlib.util,json,os,re,selectors,shutil,socket,subprocess,tempfile,time,traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];KERNEL=ROOT/'ocore/kernel';RUNTIME=ROOT/'ocore/runtime/x86_64';COMMON=ROOT/'ocore/runtime/common'
def info(p):
 p=Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
BASE=load('idle_build_base',KERNEL/'native_tls/verify.py')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',required=True,type=Path);ap.add_argument('--compiler',required=True,type=Path);ap.add_argument('--codec-manifest',required=True,type=Path);ap.add_argument('--qemu',type=Path,default=Path.home()/'.local/opt/qemu-11.1.3/bin/qemu-system-x86_64');ap.add_argument('--boot-source',type=Path,default=KERNEL/'boot.S',help='Explicit recorded boot source for owned semantic mutation tests; default is production boot.S');ap.add_argument('--timeout',type=float,default=90);ap.add_argument('--negative-case',type=int,default=0,choices=range(21));a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 result={'schema':'ostadix.native-syscall-idle-architecture/v1','ok':False,'scope':__doc__,'negative_case':a.negative_case,'commands':[]}
 def write(): (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 def run(name,argv):
  argv=list(map(str,argv));start=time.monotonic();r=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=180);(out/(name+'.stdout')).write_bytes(r.stdout);(out/(name+'.stderr')).write_bytes(r.stderr);result['commands'].append({'name':name,'argv':argv,'returncode':r.returncode,'seconds':time.monotonic()-start,'stdout':info(out/(name+'.stdout')),'stderr':info(out/(name+'.stderr'))});write()
  if r.returncode:raise RuntimeError(name+' failed: '+(r.stdout+r.stderr)[-5000:].decode(errors='replace'))
  return r.stdout.decode()
 try:
  clang=Path(shutil.which('clang'));lld=Path(shutil.which('ld.lld'));nm=Path(shutil.which('nm'))
  tools=[a.compiler,a.qemu,clang,lld,nm];result['tools']=[info(p) for p in tools];result['python']=info(Path('/proc/self/exe'))
  sources=[RUNTIME/(n+'.oc') for n in BASE.RUNTIME_NAMES+['linux_thread_syscalls']]+[KERNEL/(n+'.oc') for n in BASE.KERNEL_NAMES]+[KERNEL/'x86_64/boot_info_stub.oc']+[COMMON/(n+'.oc') for n in ['namespace_store','u9fs_codec','posix_namespace_files']]
  originals=sources+[KERNEL/'boot.S',KERNEL/'linker.ld',KERNEL/'m6_stub.oc',KERNEL/'bind-image.py',ROOT/'ocore/user/pack_ovfs.py',ROOT/'ocore/user/verify_ovfs.py',ROOT/'scripts/okernel_native_codec.py',KERNEL/'native_tls/verify.py',KERNEL/'native_tls/entry.S',KERNEL/'native_tls/user.ld',HERE/'probe.oc',HERE/'fixture.c',HERE/'platform.S',HERE/'scheduler_test_hooks.oc.inc',Path(__file__)];originals += [a.boot_source.resolve()] if a.boot_source.resolve()!=(KERNEL/'boot.S').resolve() else [];before=[info(p) for p in originals];result['source_before']=before;result['selected_boot_source']=info(a.boot_source)
  for source in originals:
   relative=source.relative_to(ROOT) if source.is_relative_to(ROOT) else Path('_external')/info(source)['sha256']/source.name
   dest=out/'source'/relative;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(source.read_bytes());dest.chmod(0o444)
  codec=load('idle_codec_stage',ROOT/'scripts/okernel_native_codec.py');frozen=codec.stage(a.codec_manifest.resolve(),out/'codec','x86_64');result['codec_manifest']=info(a.codec_manifest);result['codec_objects']=frozen['objects']
  run('fixture-compile',[clang,f'-DOCORE_NEGATIVE_CASE={a.negative_case}','-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-mno-sse','-mno-sse2','-mno-red-zone','-c',HERE/'fixture.c','-o',out/'fixture.o'])
  run('fixture-entry',[clang,'-c',KERNEL/'native_tls/entry.S','-o',out/'entry.o']);run('fixture-link',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','-z','max-page-size=0x1000','-T',KERNEL/'native_tls/user.ld','-o',out/'fixture.elf',out/'entry.o',out/'fixture.o'])
  run('pack-ovfs',['python3','-B',ROOT/'ocore/user/pack_ovfs.py',out/'images','--entry','/bin/probe.elf',out/'fixture.elf','3']);images=list((out/'images').glob('root-*.ovfs'));assert len(images)==1;image=images[0];run('verify-ovfs',['python3','-B',ROOT/'ocore/user/verify_ovfs.py',image]);run('bind-image',['python3','-B',KERNEL/'bind-image.py',HERE/'probe.oc',image,out/'probe.oc','--prefix','PROBE_IMAGE_'])
  BASE.REPLACEMENTS=set(BASE.REPLACEMENTS)|{'kernel_m6_linux_process_exit','kernel_m6_prepare_bounded_resume'};adapter=BASE.adapters((KERNEL/'m6_stub.oc').read_text()).replace('module kernel::m6;','').replace('use runtime::native_abi::ERR_NOT_IMPLEMENTED;','');probe=(out/'probe.oc').read_text().replace('module kernel::m6;','module kernel::m6;\nuse runtime::native_abi::ERR_NOT_IMPLEMENTED;');probe=probe.replace('const NEGATIVE_CASE: u64 = 0;',f'const NEGATIVE_CASE: u64 = {a.negative_case};');
  if 1<=a.negative_case<=10 or a.negative_case>=18:
   probe=probe.replace('module kernel::m6;','module kernel::m6;\nuse runtime::scheduler::idle_probe_negative;')
   probe=probe.replace('unsafe fn negative_action(kind: u64) -> u64 { return 0; }','unsafe fn negative_action(kind: u64) -> u64 { return idle_probe_negative(kind); }')
   original_scheduler=RUNTIME/'scheduler.oc';instrumented=out/'scheduler-instrumented.oc';instrumented.write_bytes(original_scheduler.read_bytes()+b'\n'+(HERE/'scheduler_test_hooks.oc.inc').read_bytes());sources=[instrumented if x==original_scheduler else x for x in sources];result['instrumented_scheduler']=info(instrumented);result['instrumentation_composition']={'production':info(original_scheduler),'fragment':info(HERE/'scheduler_test_hooks.oc.inc'),'separator_hex':'0a','rule':'exact production bytes, then LF, then exact fragment bytes; fragment has no standalone module'};result['test_instrumentation_scope']='Exact production prefix plus captured same-module trusted-state corruption controls; never a guest API or production build input'
  (out/'probe.oc').write_text(probe+'\n'+adapter);result['generated_probe']=info(out/'probe.oc')
  rebuilt=[]
  for i in (1,2):
   run(f'kernel-object-{i}',[a.compiler,*sources,out/'probe.oc','--target','x86_64-unknown-none','--emit','obj','--function-sections','-o',out/f'kernel-{i}.o']);run(f'boot-object-{i}',[clang,'-target','x86_64-unknown-none-elf','-c','-x','assembler-with-cpp','-DOCORE_PROBE_MODE=25','-DOCORE_BOOT_INFO_ENABLED=0',f'-DOCORE_M6_LINUX_IMAGE_PATH="{image}"',a.boot_source,'-o',out/f'boot-{i}.o']);run(f'platform-object-{i}',[clang,'-target','x86_64-unknown-none-elf','-c',HERE/'platform.S','-o',out/f'platform-{i}.o']);elf=out/f'kernel-{i}.elf';run(f'kernel-link-{i}',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','--gc-sections','-z','max-page-size=0x1000','-T',KERNEL/'linker.ld','-o',elf,out/f'boot-{i}.o',out/f'kernel-{i}.o',out/f'platform-{i}.o',*[x['path'] for x in frozen['objects']]]);rebuilt.append(info(elf))
  result['kernel_rebuilds']=rebuilt;assert rebuilt[0]['sha256']==rebuilt[1]['sha256'];result['fixture']=info(out/'fixture.elf');result['image']=info(image);assert not run('undefined',[nm,'-u',out/'kernel-1.elf']).strip();symtext=run('symbols',[nm,'-S',out/'kernel-1.elf']);symbols={line.split()[-1]:int(line.split()[0],16) for line in symtext.splitlines() if len(line.split())>=3 and re.fullmatch('[0-9a-fA-F]+',line.split()[0])};sizes={line.split()[-1]:int(line.split()[1],16) for line in symtext.splitlines() if len(line.split())==4 and re.fullmatch('[0-9a-fA-F]+',line.split()[1])};result['qemu_version']=run('qemu-version',[a.qemu,'--version'])
  with tempfile.TemporaryDirectory(prefix='oidle.',dir='/tmp') as sockets:
   qmp=Path(sockets)/'q';argv=[str(a.qemu),'-machine','q35','-cpu','max','-accel','tcg','-m','128M','-smp','1','-display','none','-monitor','none','-serial','stdio','-no-reboot','-no-shutdown','-d','int','-D',str(out/'qemu-interrupts.log'),'-qmp',f'unix:{qmp},server=on,wait=off','-kernel',str(out/'kernel-1.elf')];result['qemu_argv']=argv;proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);result['owned_qemu_pid']=proc.pid
   try:
    selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ);transcript=bytearray();deadline=time.monotonic()+a.timeout;unsupported_deadline=None
    while time.monotonic()<deadline:
     if proc.poll() is not None:raise RuntimeError('owned QEMU exited '+str(proc.returncode))
     for key,_ in selector.select(.05):
      chunk=os.read(key.fd,65536)
      if chunk:transcript.extend(chunk);(out/'console.log').write_bytes(transcript)
     if b'M02 KERNEL FAULT: halted' in transcript:raise RuntimeError('actual kernel fault')
     markers=re.findall(rb'NATIVE IDLE PROBE: ([0-9a-f]{16})\n',transcript)
     if any(m not in (b'00000041524d4544',b'0000000050415353',b'4e45474154495645') for m in markers):raise RuntimeError('probe rejection '+str(markers))
     if a.negative_case==17 and b'NATIVE IDLE PROBE: 00000041524d4544\n' in transcript:
      if unsupported_deadline is None:unsupported_deadline=time.monotonic()+1
      if time.monotonic()>=unsupported_deadline:break
     if (not a.negative_case and b'NATIVE IDLE PROBE: 0000000050415353\n' in transcript) or (a.negative_case and b'NATIVE IDLE PROBE: 4e45474154495645\n' in transcript):break
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
     if a.negative_case==0:
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
     fields=[('kernel__m6',x,64,8) for x in ['ADMISSION_BEFORE','ADMISSION_AFTER']]+[('kernel__m6',x,32,8) for x in ['USER_BASES','CALLS','THREADS','OWNERS','READY','SLEPT','WOKE','EXITS']]+[('kernel__m6',x,8,8) for x in ['ACCEPTED','WINDOW','SLEEP_IDLE_TICKS','FINAL_IDLE_TICKS','IDLE_CR3','IDLE_STACK','IDLE_GS','IDLE_KERNEL_GS','NEGATIVE_READY','NEGATIVE_RETURN','MALFORMED_TICKS','MALFORMED_SURVIVOR']]+[('runtime__scheduler',x,1,1) for x in ['IDLE_POLICY','ACTIVE','COMPLETE','FAILED','PENDING_ACTION','SYSCALL_PHASE','SYSCALL_IDLE_DISPOSITION']]+[('runtime__scheduler',x,8,8) for x in ['IDLE_TRANSITIONS','IDLE_TICKS','PENDING_SERIAL','SYSCALL_THREAD','SYSCALL_PROCESS','SYSCALL_FRAME','HOSTILE_FRAME_CONTAINMENTS','CONTEXT_SWITCHES']]+[('runtime__thread',x,4,1) for x in ['STATES','PROCESS_REF_HELD']]+[('runtime__thread',x,8,8) for x in ['CURRENT_THREAD']]+[('runtime__thread',x,32,8) for x in ['USER_FS_BASES']]+[('runtime__thread',x,8,2) for x in ['USER_FS_SELECTORS']]+[('runtime__process',x,4,1) for x in ['STATES']]+[('runtime__process',x,8,8) for x in ['CURRENT_PROCESS']]+[('runtime__process',x,32,8) for x in ['EXIT_CODES']]+[('runtime__process',x,16,4) for x in ['THREAD_REFS']]+[('runtime__posix_file_syscalls','ENABLED',8,1),('runtime__common__posix_namespace_files','FD_DESCRIPTION',512,8)]
     for module,name,n,width in fields:
      symbol='_O_'+module+'__'+name;path=out/(module+'__'+name+'.bin');request('pmemsave',{'val':symbols[symbol],'size':n,'filename':str(path)});raw=path.read_bytes();state[module+'__'+name]=[int.from_bytes(raw[i:i+width],'little') for i in range(0,n,width)]
     result['state']=state
     def get(m,n):return state[m+'__'+n]
     if a.negative_case==17:
      assert get('kernel__m6','ACCEPTED')==[0] and get('kernel__m6','NEGATIVE_READY')==[0]
      assert get('kernel__m6','CALLS')[0]==1
      assert get('runtime__scheduler','IDLE_POLICY')==[1] and get('runtime__scheduler','ACTIVE')==[0] and get('runtime__scheduler','FAILED')==[1]
      assert get('runtime__scheduler','PENDING_ACTION')==[0] and get('runtime__scheduler','PENDING_SERIAL')==[0] and get('runtime__scheduler','SYSCALL_PHASE')==[0] and get('runtime__scheduler','IDLE_TRANSITIONS')==[0]
      assert re.search(r'GS =001b',result['registers'])
     elif a.negative_case==16:
      assert get('kernel__m6','NEGATIVE_READY')==[1] and get('kernel__m6','NEGATIVE_RETURN')==[1] and get('kernel__m6','MALFORMED_TICKS')[0]>=3
      assert get('runtime__scheduler','HOSTILE_FRAME_CONTAINMENTS')==[1] and get('runtime__scheduler','ACTIVE')==[1] and get('runtime__scheduler','FAILED')==[0] and get('runtime__scheduler','COMPLETE')==[0]
      assert get('runtime__scheduler','PENDING_ACTION')==[0] and get('runtime__scheduler','PENDING_SERIAL')==[0] and get('runtime__scheduler','SYSCALL_PHASE')==[0]
      assert get('runtime__thread','STATES')[0]==4 and get('runtime__thread','PROCESS_REF_HELD')[0]==0 and get('runtime__thread','USER_FS_BASES')[0]==0
      assert get('runtime__thread','CURRENT_THREAD')[0] in get('kernel__m6','THREADS')[1:] and get('kernel__m6','MALFORMED_SURVIVOR')==get('runtime__thread','CURRENT_THREAD')
      assert get('runtime__process','STATES')[0]==1 and get('runtime__process','CURRENT_PROCESS')[0] in get('kernel__m6','OWNERS')[1:]
     elif 11<=a.negative_case<=15 or a.negative_case==18:
      assert get('kernel__m6','NEGATIVE_READY')==[1] and get('kernel__m6','NEGATIVE_RETURN')==[0]
      assert get('runtime__scheduler','IDLE_POLICY')==[0] and get('runtime__scheduler','ACTIVE')==[1] and get('runtime__scheduler','FAILED')==[0] and get('runtime__scheduler','COMPLETE')==[0]
      assert get('runtime__scheduler','IDLE_TRANSITIONS')==[0] and get('runtime__scheduler','PENDING_ACTION')==[0] and get('runtime__scheduler','PENDING_SERIAL')==[0]
      observed_before=get('kernel__m6','ADMISSION_BEFORE');observed_after=get('kernel__m6','ADMISSION_AFTER');assert observed_before==observed_after
      if a.negative_case==11:assert observed_before[5]==0x12340000
      if a.negative_case==12:assert observed_before[3]==0x98765000
      if a.negative_case==18:assert get('runtime__scheduler','CONTEXT_SWITCHES')==[1]
      if a.negative_case==13:
       path=out/'bad-stack-seen.bin';request('pmemsave',{'val':symbols['idle_probe_bad_stack_seen'],'size':8,'filename':str(path)});seen=int.from_bytes(path.read_bytes(),'little');assert symbols['ring0_stack_bottom']<=seen<symbols['ring0_stack_top'];result['bad_stack_seen']=seen
      assert get('kernel__m6','ACCEPTED')==[0]
     elif a.negative_case:
      expected={1:2,2:3,3:3,4:3,5:2,6:2,7:0,8:0,9:2,10:2,19:2,20:2}[a.negative_case]
      assert get('kernel__m6','NEGATIVE_READY')==[1] and get('kernel__m6','NEGATIVE_RETURN')==[expected]
      assert get('runtime__scheduler','IDLE_POLICY')==[1] and get('runtime__scheduler','ACTIVE')==[0] and get('runtime__scheduler','FAILED')==[1] and get('runtime__scheduler','COMPLETE')==[0]
      assert get('runtime__scheduler','IDLE_TRANSITIONS')==[0] and get('runtime__scheduler','SYSCALL_PHASE')==[0] and get('runtime__scheduler','SYSCALL_IDLE_DISPOSITION')==[0]
      if a.negative_case==2:assert get('runtime__scheduler','PENDING_ACTION')==[2] and get('runtime__scheduler','PENDING_SERIAL')[0]!=0
      else:assert get('runtime__scheduler','PENDING_ACTION')==[0] and get('runtime__scheduler','PENDING_SERIAL')==[0]
      assert get('kernel__m6','ACCEPTED')==[0] and get('kernel__m6','WINDOW')==[0]
      if a.negative_case in (19,20):
       path=out/'entry-side-effects.bin';request('pmemsave',{'val':symbols['_O_runtime__scheduler__TEST_ENTRY_SIDE_EFFECTS'],'size':8,'filename':str(path)});assert path.read_bytes()==b'\0'*8
      if a.negative_case==7:
       assert get('runtime__thread','CURRENT_THREAD')==[0] and get('runtime__process','CURRENT_PROCESS')==[0]
       assert 1 in get('runtime__thread','STATES') and all(x in (1,3) for x in get('runtime__thread','STATES'))
       assert get('runtime__process','THREAD_REFS')==[1]*4 and get('runtime__process','EXIT_CODES')==[0]*4
     else:
      assert len(set(get('kernel__m6','USER_BASES')))==4 and all(get('kernel__m6','USER_BASES'))
      for n in ['READY','SLEPT','WOKE']:assert get('kernel__m6',n)==[1]*4
      assert get('kernel__m6','EXITS')==[160,161,162,163] and get('kernel__m6','WINDOW')==[0] and get('kernel__m6','ACCEPTED')==[1]
      assert get('kernel__m6','SLEEP_IDLE_TICKS')[0]>=2 and get('kernel__m6','FINAL_IDLE_TICKS')[0]>=5
      assert get('kernel__m6','IDLE_GS')==[symbols['percpu_entry']] and get('kernel__m6','IDLE_KERNEL_GS')==[0]
      assert get('kernel__m6','IDLE_CR3')==[symbols['p4_table']] and symbols['stack_bottom']<=get('kernel__m6','IDLE_STACK')[0]<symbols['stack_top']
      for n in ['ACTIVE','IDLE_POLICY']:assert get('runtime__scheduler',n)==[1]
      for n in ['COMPLETE','FAILED','PENDING_ACTION','SYSCALL_PHASE','SYSCALL_IDLE_DISPOSITION','PENDING_SERIAL','SYSCALL_THREAD','SYSCALL_PROCESS','SYSCALL_FRAME']:assert get('runtime__scheduler',n)==[0]
      assert get('runtime__scheduler','IDLE_TRANSITIONS')[0]>=2 and get('runtime__scheduler','IDLE_TICKS')[0]>=2
      assert get('runtime__thread','STATES')==[4]*4 and get('runtime__process','STATES')==[5]*4
      assert get('runtime__process','EXIT_CODES')==[160,161,162,163]
      for m,n in [('runtime__thread','PROCESS_REF_HELD'),('runtime__thread','CURRENT_THREAD'),('runtime__thread','USER_FS_BASES'),('runtime__thread','USER_FS_SELECTORS'),('runtime__process','CURRENT_PROCESS'),('runtime__process','THREAD_REFS'),('runtime__posix_file_syscalls','ENABLED'),('runtime__common__posix_namespace_files','FD_DESCRIPTION')]:assert not any(get(m,n))
      regs=result['registers'];assert re.search(r'FS =0000 0000000000000000',regs);assert re.search(r'GS =0000 '+format(symbols['percpu_entry'],'016x'),regs);assert 'CR3='+format(symbols['p4_table'],'016x') in regs
     result['hardware_interrupt_trace']=info(out/'qemu-interrupts.log')
   finally:
    proc.terminate()
    try:proc.wait(timeout=10)
    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=10)
    result['owned_qemu_returncode']=proc.returncode
  after=[info(p) for p in originals];result['source_after']=after;assert before==after
  result['ok']=True
 except Exception as e:result['error']=repr(e);result['traceback']=traceback.format_exc()
 finally:write()
 print(json.dumps({'ok':result['ok'],'result':str(out/'result.json'),'error':result.get('error')},indent=2));return 0 if result['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
