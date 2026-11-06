#!/usr/bin/env python3
"""Original musl getuid/_Exit USER integration with bounded native providers.

Requires the COMPLETE compiler-owned original two-unit source artifact and a
fresh detached source/body readmission. USER notes remain allocated/readonly in
PT_NOTE. The kernel links only native O-core plus its separately admitted safe
codec, never these Linux USER objects. Authored bootstrap/controls are explicit.
This is not whole musl/CRT, a complete Linux provider, SMP, or a usable OS.
"""
import argparse,hashlib,importlib.util,json,os,re,selectors,shutil,socket,struct,subprocess,tempfile,time,traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];KERNEL=ROOT/'ocore/kernel';RUNTIME=ROOT/'ocore/runtime/x86_64';COMMON=ROOT/'ocore/runtime/common'
def info(p):
 p=Path(p).resolve(strict=True);v=p.read_bytes();return {'path':str(p),'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
BASE=load('original_process_build_base',KERNEL/'native_tls/verify.py')
def elf(path,expected_machine=62):
 b=Path(path).read_bytes();assert b[:6]==b'\x7fELF\x02\x01';h=struct.unpack_from('<HHIQQQIHHHHHH',b,16);assert h[1]==expected_machine
 so,se,sn,si=h[5],h[10],h[11],h[12];assert se>=64 and so+se<=len(b);s0=struct.unpack_from('<IIQQQQIIQQ',b,so);sn=sn or s0[5];si=s0[6] if si==0xffff else si;assert so+se*sn<=len(b) and si<sn
 sh=[struct.unpack_from('<IIQQQQIIQQ',b,so+i*se)for i in range(sn)];strings=b[sh[si][4]:sh[si][4]+sh[si][5]]
 def string(s,n):assert n<len(s);e=s.index(0,n);return s[n:e].decode()
 sec=[{'index':i,'name':string(strings,x[0]),'type':x[1],'flags':x[2],'addr':x[3],'offset':x[4],'size':x[5],'link':x[6],'entsize':x[9],'data':b[x[4]:x[4]+x[5]] if x[1]!=8 else bytes(x[5])}for i,x in enumerate(sh)];symbols={};undefined=[]
 for s in sec:
  if s['type']!=2:continue
  assert s['entsize']>=24 and s['size']%s['entsize']==0;names=sec[s['link']]['data']
  for p in range(0,s['size'],s['entsize']):
   n,k,v,ndx,value,size=struct.unpack_from('<IBBHQQ',s['data'],p);name=string(names,n)
   if not name:continue
   if ndx==0 and k>>4:undefined.append(name)
   if ndx and k&15==2:
    assert name not in symbols;section=sec[ndx];start=value-section['addr'];assert start>=0 and start+size<=section['size'];symbols[name]={'value':value,'size':size,'bytes':section['data'][start:start+size],'section':ndx,'section_offset':start}
 phn=h[9] if h[9]!=0xffff else s0[7];assert not phn or(h[8]>=56 and h[4]+h[8]*phn<=len(b));ph=[dict(zip(('type','flags','offset','vaddr','paddr','filesz','memsz','align'),struct.unpack_from('<IIQQQQQQ',b,h[4]+i*h[8])))for i in range(phn)]
 notes=[];ns=[s for s in sec if s['name']=='.note.ocore.platform']
 for s in ns:
  assert s['type']==7 and s['flags']&7==2;at=0
  while at<len(s['data']):
   assert at+12<=len(s['data']);nn,dn,nt=struct.unpack_from('<III',s['data'],at);start=at+12;dnstart=start+((nn+3)&~3);end=dnstart+dn;nextat=dnstart+((dn+3)&~3);assert end<=len(s['data']) and nextat<=len(s['data']);assert s['data'][start:start+nn]==b'Ocore\0' and nt==1
   desc=s['data'][dnstart:end];notes.append({'type':nt,'payload':json.loads(desc),'payload_sha256':hashlib.sha256(desc).hexdigest(),'raw_sha256':hashlib.sha256(s['data'][at:nextat]).hexdigest()});at=nextat
  if ph:
   assert any(p['type']==4 and p['flags']==4 and p['offset']<=s['offset'] and s['offset']+s['size']<=p['offset']+p['filesz']for p in ph),'USER note missing RO PT_NOTE'
   assert any(p['type']==1 and p['flags']==4 and p['offset']<=s['offset'] and s['offset']+s['size']<=p['offset']+p['filesz']for p in ph),'USER note missing readonly nonexec PT_LOAD'
 relocations=[]
 for section in sec:
  if section['type']not in(4,9):continue
  required=24 if section['type']==4 else 16;assert section['entsize']>=required and section['size']%section['entsize']==0
  for at in range(0,section['size'],section['entsize']):
   offset,kind=struct.unpack_from('<QQ',section['data'],at);relocations.append({'source_section':sh[section['index']][7],'offset':offset,'kind':kind&0xffff_ffff,'symbol_index':kind>>32})
 return {'symbols':symbols,'notes':notes,'loads':[p for p in ph if p['type']==1],'undefined':undefined,'relocations':relocations}
def source_objects(product,reopened):
 p=Path(product).resolve(strict=True);pg=json.loads((p/'provider-group.json').read_bytes());assert pg['source_group_complete'] and pg['lowering_complete'] and pg['object_reemission_complete'],'original two-unit source lowering prerequisite incomplete';r=Path(reopened).resolve(strict=True)
 group_path=p/'source-group.native-ir.json';group=json.loads(group_path.read_bytes());readmission=json.loads((r/'source-readmission.json').read_bytes());assert readmission['source_group_sha256']==info(group_path)['sha256'] and not readmission['issues'] and readmission['included_original_ir_body_consistency'];assert len(readmission['units'])==2 and all(x['fresh_typed_import_match']for x in readmission['units'])
 modules=group['module_set']['modules'];assert len(modules)==2 and len(group['components'])==1;calls=[];names=[]
 component=group['components'][0];recipe=ROOT/'tools/ocore-runtime/linux-process-components/x86_64.recipe.json';assert component['recipe_sha256']==info(recipe)['sha256']and component['recipe_json']==recipe.read_text(),'not the declared pinned original two-source recipe'
 build_path=p/'component-000000/build/component-build.json';build=json.loads(build_path.read_bytes());assert build['source']['revision']=='0784374d561435f7c787a555aeab8ede699ed298'and build['isa']=='x86_64'
 assert sorted(Path(x['path']).name for x in build['original_sources'])==['_Exit.c','getuid.c']
 for x in build['original_sources']:assert info(x['path'])==x
 for m in modules:
  assert hashlib.sha256(m['native_ir'].encode()).hexdigest()==m['sha256'];v=json.loads(m['native_ir']);assert len(v['functions'])==1;fn=v['functions'][0];assert fn['exception_handling']is None,'required unwind profile unsupported';names.append(fn['name'])
  for block in fn['blocks']:
   for ins in block['instructions']:
    op=ins['operation']
    if op['op']=='linux_syscall':calls.append((fn['name'],int(op['number']['bits']),len(op['arguments'])))
 assert sorted(names)==['_Exit','getuid'] and sorted(calls)==[('_Exit',60,1),('_Exit',231,1),('getuid',102,0)],calls
 coverage_path=r/'lowered/coverage.json';coverage=json.loads(coverage_path.read_bytes());assert not coverage['issues'] and coverage['unit_lowering_complete'] and coverage['lowering_complete'] and coverage['symbol_closure_complete'] and len(coverage['units'])==2
 for unit in coverage['units']:
  assert unit['verified']and unit['lowered']and info(unit['object']['path'])==unit['object']
  assert info(unit['module']['path'])['sha256']==unit['module']['sha256']
 objs=sorted((r/'lowered').glob('unit-*/module.o'));assert len(objs)==2 and set(str(x)for x in objs)==set(x['object']['path']for x in coverage['units']);objects=[];expected=readmission['required_platform_interfaces'];assert len(expected)==2
 for obj in objs:
  e=elf(obj);assert len(e['notes'])==1 and not e['undefined'];note=e['notes'][0]['payload'];assert note in[x['interface']for x in expected];assert note['architecture']=='x86_64' and note['privilege']=='user_mode_only';objects.append(obj)
 return objects,{'source_group':info(group_path),'provider_group':info(p/'provider-group.json'),'source_readmission':info(r/'source-readmission.json'),'object_coverage':info(coverage_path),'original_component_build':info(build_path),'original_sources':build['original_sources'],'recipe':info(recipe),'source_compiler':{'path':coverage['compiler'],'sha256':coverage['compiler_sha256']},'calls':calls,'objects':[info(x)for x in objects],'notes':[n for x in objects for n in elf(x)['notes']],'scope':'Complete declared two-source component plus fresh readmission; platform_resource/runtime/whole-libc completeness are not inferred'}
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--compiler',type=Path,required=True);ap.add_argument('--component-compiler',type=Path,help='Explicit source-module verifier when separately qualified from kernel compiler');ap.add_argument('--source-product',type=Path,required=True);ap.add_argument('--readmitted',type=Path,required=True);ap.add_argument('--codec-manifest',type=Path,required=True);ap.add_argument('--status-group',type=int,choices=(0,1),default=0);ap.add_argument('--fallback-231-unavailable',action='store_true');ap.add_argument('--qemu',type=Path,default=Path.home()/'.local/opt/qemu-11.1.3/bin/qemu-system-x86_64');ap.add_argument('--timeout',type=float,default=90);a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 result={'schema':'ostadix.native-original-musl-process/v1','ok':False,'scope':__doc__,'commands':[],'fallback_231_unavailable':a.fallback_231_unavailable,'status_group':a.status_group,'native_provider_complete':False,'native_returning_fenv_qualified':False,'fenv_scope':'Integer-only USER execution; no per-TCB FP/SIMD or returning provider control/sticky-state proof. Compiler platform obligation remains unmet.','uid_policy':{'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid()}}
 def write():(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 def run(label,argv):
  argv=list(map(str,argv));start=time.monotonic();p=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=180);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);result['commands'].append({'label':label,'argv':argv,'returncode':p.returncode,'seconds':time.monotonic()-start,'stdout':info(out/(label+'.stdout')),'stderr':info(out/(label+'.stderr'))});write();assert p.returncode==0,(label,p.stderr[-5000:].decode(errors='replace'));return p.stdout.decode()
 initial=[Path(__file__),HERE/'probe.oc',HERE/'bootstrap.c',HERE/'user.ld',a.source_product/'provider-group.json']
 result['entry_input_snapshot']=[info(x)for x in initial if x.is_file()]
 for x in initial:
  if x.is_file():
   d=out/'entry-inputs'/info(x)['sha256']/x.name;d.parent.mkdir(parents=True,exist_ok=True);d.write_bytes(x.read_bytes());d.chmod(0o444)
 write()
 try:
  result['prerequisite_state']='checking complete original O2 source artifact';objects,provenance=source_objects(a.source_product,a.readmitted);result['component']=provenance
  clang=Path(shutil.which('clang'));lld=Path(shutil.which('ld.lld'));nm=Path(shutil.which('nm'));objdump=Path(shutil.which('objdump'));result['tools']=[info(p)for p in [a.compiler,a.component_compiler or a.compiler,a.qemu,clang,lld,nm,objdump,Path('/proc/self/exe')]]
  sources=[RUNTIME/(n+'.oc')for n in BASE.RUNTIME_NAMES+['linux_thread_syscalls','linux_process_syscalls','linux_credentials']]+[KERNEL/(n+'.oc')for n in BASE.KERNEL_NAMES]+[KERNEL/'x86_64/boot_info_stub.oc']+[COMMON/(n+'.oc')for n in['namespace_store','u9fs_codec','posix_namespace_files']]
  originals=list(dict.fromkeys(sources+[KERNEL/'boot.S',KERNEL/'linker.ld',KERNEL/'m6_stub.oc',KERNEL/'bind-image.py',ROOT/'ocore/user/pack_ovfs.py',ROOT/'ocore/user/verify_ovfs.py',ROOT/'scripts/okernel_native_codec.py',KERNEL/'native_tls/verify.py',KERNEL/'native_tls/entry.S',KERNEL/'native_idle/platform.S',HERE/'probe.oc',HERE/'bootstrap.c',HERE/'user.ld',Path(__file__),*[Path(provenance[k]['path'])for k in['source_group','provider_group','source_readmission','object_coverage','original_component_build','recipe']],*objects,*[Path(x['path'])for x in provenance['original_sources']]]));before=[info(p)for p in originals];result['source_before']=before
  for source in originals:
   relative=source.relative_to(ROOT)if source.is_relative_to(ROOT)else Path('_external')/info(source)['sha256']/source.name;d=out/'source'/relative;d.parent.mkdir(parents=True,exist_ok=True);d.write_bytes(source.read_bytes());d.chmod(0o444)
  codec=load('original_process_codec',ROOT/'scripts/okernel_native_codec.py');frozen=codec.stage(a.codec_manifest.resolve(),out/'codec','x86_64');result['codec_manifest']=info(a.codec_manifest);result['codec_objects']=frozen['objects'];assert not set(str(x.resolve())for x in objects)&set(str(Path(x['path']).resolve())for x in frozen['objects'])
  assert info(a.component_compiler or a.compiler)['sha256']==provenance['source_compiler']['sha256'],'selected component verifier differs from captured emitter; explicit new tool qualification required'
  for i,obj in enumerate(objects):run(f'component-verify-{i}',[a.component_compiler or a.compiler,obj.parent/'module.native-ir.json','--input-kind','native-ir','--verify-native'])
  flags=[f'-DHOST_{k.upper()}={v}'for k,v in result['uid_policy'].items()];run('bootstrap',[clang,f'-DSTATUS_GROUP={a.status_group}',*flags,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-mno-sse','-mno-sse2','-mno-mmx','-mno-80387','-fno-vectorize','-fno-slp-vectorize','-mno-red-zone','-c',HERE/'bootstrap.c','-o',out/'bootstrap.o']);run('entry',[clang,'-c',KERNEL/'native_tls/entry.S','-o',out/'entry.o']);run('USER-link',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','-z','max-page-size=0x1000','-T',HERE/'user.ld','-o',out/'user.elf',out/'entry.o',out/'bootstrap.o',*objects])
  ue=elf(out/'user.elf');assert len(ue['notes'])==2 and ue['notes']==provenance['notes'] and not ue['undefined'];assert all(not(p['flags']&3==3)for p in ue['loads']);result['user_notes']=ue['notes']
  for obj in objects:
   for name,sym in elf(obj)['symbols'].items():
    if name in('getuid','_Exit'):assert ue['symbols'][name]['bytes']==sym['bytes'],'linked original function bytes changed'
  dis=run('USER-disassembly',[objdump,'-d',out/'user.elf']);sites={name:[]for name in('getuid','_Exit')};audited=[]
  for line in dis.splitlines():
   instruction=re.match(r'\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+([a-z][a-z0-9_.]*)\s*(.*)',line)
   if instruction:
    mnemonic=instruction.group(2).lower();operands=instruction.group(3).lower()
    assert not mnemonic.startswith(('f','v','xsave','xrstor'))and mnemonic not in('wait','emms','ldmxcsr','stmxcsr','wrmsr','rdmsr','cli','sti','hlt','iret','iretq','sysret','sysretq')and not re.search(r'%(?:[xyz]mm[0-9]+|mm[0-7]|cr[0-9]+|dr[0-9]+)\b',operands),'outside declared integer USER instruction profile: '+line
    audited.append({'address':int(instruction.group(1),16),'mnemonic':mnemonic})
  assert audited;result['user_instruction_audit']={'instructions':len(audited),'no_fp_simd_or_privileged_state_instructions':True,'disassembly':info(out/'USER-disassembly.stdout'),'scope':'Actual fixed USER instruction inventory only; not general FP/SIMD context support or opaque-provider FENV qualification'}
  for line in dis.splitlines():
   m=re.match(r'\s*([0-9a-f]+):\s+0f 05\s+syscall\b',line)
   if m:
    pc=int(m.group(1),16)+2
    for name in sites:
     s=ue['symbols'][name]
     if s['value']<pc<=s['value']+s['size']:sites[name].append(pc)
  assert len(sites['getuid'])==1 and len(sites['_Exit'])==2;result['source_post_syscall_sites']=sites
  run('pack',['python3','-B',ROOT/'ocore/user/pack_ovfs.py',out/'images','--entry','/bin/probe.elf',out/'user.elf','3']);images=list((out/'images').glob('root-*.ovfs'));assert len(images)==1;image=images[0];run('image-verify',['python3','-B',ROOT/'ocore/user/verify_ovfs.py',image]);run('bind',['python3','-B',KERNEL/'bind-image.py',HERE/'probe.oc',image,out/'probe.oc','--prefix','PROBE_IMAGE_'])
  BASE.REPLACEMENTS|={'kernel_m6_linux_process_exit','kernel_m6_prepare_bounded_resume'};adapter=BASE.adapters((KERNEL/'m6_stub.oc').read_text()).replace('module kernel::m6;','').replace('use runtime::native_abi::ERR_NOT_IMPLEMENTED;','');probe=(out/'probe.oc').read_text().replace('module kernel::m6;','module kernel::m6;\nuse runtime::native_abi::ERR_NOT_IMPLEMENTED;')
  replacements={'STATUS_GROUP':a.status_group,'GETUID_SITE':sites['getuid'][0],'EXIT_SITE_A':sites['_Exit'][0],'EXIT_SITE_B':sites['_Exit'][1],**{'HOST_'+k.upper():v for k,v in result['uid_policy'].items()}}
  for name,value in replacements.items():probe,n=re.subn(rf'const {name}: u64 = [0-9]+;',f'const {name}: u64 = {value};',probe);assert n==1,name
  if a.fallback_231_unavailable:probe=probe.replace('const FALLBACK_231_UNAVAILABLE: bool = false;','const FALLBACK_231_UNAVAILABLE: bool = true;')
  (out/'probe.oc').write_text(probe+'\n'+adapter);result['generated_probe']=info(out/'probe.oc');kernels=[]
  for i in(1,2):
   run(f'kernel-object-{i}',[a.compiler,*sources,out/'probe.oc','--target','x86_64-unknown-none','--emit','obj','--function-sections','--data-sections','-o',out/f'kernel-{i}.o']);run(f'boot-{i}',[clang,'-target','x86_64-unknown-none-elf','-c','-x','assembler-with-cpp','-DOCORE_PROBE_MODE=25','-DOCORE_BOOT_INFO_ENABLED=0',f'-DOCORE_M6_LINUX_IMAGE_PATH="{image}"',KERNEL/'boot.S','-o',out/f'boot-{i}.o']);run(f'platform-{i}',[clang,'-target','x86_64-unknown-none-elf','-c',KERNEL/'native_idle/platform.S','-o',out/f'platform-{i}.o']);run(f'kernel-link-{i}',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','--gc-sections','-z','max-page-size=0x1000','-T',KERNEL/'linker.ld','-Map',out/f'kernel-{i}.map','-o',out/f'kernel-{i}.elf',out/f'boot-{i}.o',out/f'kernel-{i}.o',out/f'platform-{i}.o',*[x['path']for x in frozen['objects']]]);kernels.append(info(out/f'kernel-{i}.elf'))
  assert kernels[0]['sha256']==kernels[1]['sha256'];result['kernel_rebuilds']=kernels;ke=elf(out/'kernel-1.elf');assert not ke['undefined'];run('symbols',[nm,'-S',out/'kernel-1.elf']);symboltext=(out/'symbols.stdout').read_text();symbols={line.split()[-1]:int(line.split()[0],16)for line in symboltext.splitlines()if len(line.split())>=3 and re.fullmatch('[0-9a-fA-F]+',line.split()[0])};sizes={line.split()[-1]:int(line.split()[1],16)for line in symboltext.splitlines()if len(line.split())==4 and re.fullmatch('[0-9a-fA-F]+',line.split()[1])};assert 'getuid' not in symbols and '_Exit' not in symbols,'USER function linked into kernel privilege';result['user_elf']=info(out/'user.elf');result['image']=info(image);run('qemu-version',[a.qemu,'--version']);result['prerequisite_state']='complete two-unit source/reopened USER ELF, notes, bounded provider and separate kernel linked'
  with tempfile.TemporaryDirectory(prefix='oprocess.',dir='/tmp')as sockets:
   qmp=Path(sockets)/'q';argv=list(map(str,[a.qemu,'-machine','q35','-cpu','max','-accel','tcg','-m','128M','-smp','1','-display','none','-monitor','none','-serial','stdio','-no-reboot','-no-shutdown','-d','int','-D',out/'qemu-interrupts.log','-qmp',f'unix:{qmp},server=on,wait=off','-kernel',out/'kernel-1.elf']));result['qemu_argv']=argv;proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);result['owned_qemu_pid']=proc.pid
   try:
    selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ);transcript=bytearray();deadline=time.monotonic()+a.timeout
    while time.monotonic()<deadline:
     assert proc.poll()is None,'owned QEMU ended early'
     for key,_ in selector.select(.05):
      chunk=os.read(key.fd,65536)
      if chunk:transcript.extend(chunk);(out/'console.log').write_bytes(transcript)
     if b'M02 KERNEL FAULT: halted'in transcript:raise RuntimeError('actual kernel fault')
     markers=re.findall(rb'NATIVE ORIG PROBE: ([0-9a-f]{16})\n',transcript);assert all(x in(b'00000041524d4544',b'0000000050415353')for x in markers),markers
     if b'0000000050415353'in markers:break
    else:raise TimeoutError('original USER provider gate timed out')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)as conn:
     conn.settimeout(10);conn.connect(str(qmp));stream=conn.makefile('rwb',buffering=0);result['qmp_greeting']=json.loads(stream.readline())
     def request(command,arguments=None):
      req={'execute':command}
      if arguments is not None:req['arguments']=arguments
      stream.write(json.dumps(req).encode()+b'\n')
      while True:
       x=json.loads(stream.readline())
       if'error'in x:raise RuntimeError(x)
       if'return'in x:return x['return']
     request('qmp_capabilities');request('stop');samples=[]
     for i in range(40):
      regs=request('human-monitor-command',{'command-line':'info registers'});ip=re.search(r'RIP=([0-9a-fA-F]+)',regs);sp=re.search(r'RSP=([0-9a-fA-F]+)',regs);fl=re.search(r'RFL=([0-9a-fA-F]+)',regs);good=bool(ip and sp and fl and'HLT=1'in regs and int(fl.group(1),16)&512 and symbols['ocore_scheduler_idle']<=int(ip.group(1),16)<symbols['ocore_scheduler_idle']+sizes['ocore_scheduler_idle']and symbols['stack_bottom']<=int(sp.group(1),16)<=symbols['stack_top']);samples.append({'attempt':i,'registers':regs,'dedicated_idle':good})
      if good:break
      request('cont');time.sleep(.02);request('stop')
     assert good,'no actual dedicated HLT/IF/stack witness';result['halt_samples']=samples;result['registers']=regs;state={}
     fields=[('kernel__m6',x,32,8)for x in['CALLS','THREADS','OWNERS','READY','SLEPT','WOKE','EXITS','EXIT_DONE','EXIT_RAW','CLEANUP_CALLS','UID_CALLS','UID_REPORTS','EXIT_GROUP_CALLS','EXIT_CALLS','READS']]+[('kernel__m6','SOURCE_PCS',96,8),('kernel__m6','UID_VALUES',64,8)]+[('kernel__m6',x,8,8)for x in['ACCEPTED','WINDOW','SLEEP_IDLE_TICKS','FINAL_IDLE_TICKS','IDLE_CR3','IDLE_STACK','IDLE_GS','IDLE_KERNEL_GS','SURVIVOR']]+[('runtime__scheduler',x,1,1)for x in['IDLE_POLICY','ACTIVE','COMPLETE','FAILED','PENDING_ACTION','PENDING_LINUX_EXIT','SYSCALL_PHASE','SYSCALL_IDLE_DISPOSITION']]+[('runtime__thread',x,4,1)for x in['STATES','PROCESS_REF_HELD','LINUX_SINGLE_TASK']]+[('runtime__thread',x,32,8)for x in['USER_FS_BASES','CLEAR_CHILD_TIDS']]+[('runtime__thread','CURRENT_THREAD',8,8),('runtime__process','CURRENT_PROCESS',8,8),('runtime__process','STATES',4,1),('runtime__process','EXIT_CODES',32,8),('runtime__process','THREAD_REFS',16,4),('runtime__posix_file_syscalls','ENABLED',8,1),('runtime__common__posix_namespace_files','FD_DESCRIPTION',512,8)]
     for module,name,n,width in fields:
      key=module+'__'+name;p=out/(key+'.bin');request('pmemsave',{'val':symbols['_O_'+key],'size':n,'filename':str(p)});raw=p.read_bytes();state[key]=[int.from_bytes(raw[i:i+width],'little')for i in range(0,n,width)]
     hardware={}
     for name,address in [('TSS_RSP0',symbols['tss64']+4),('PERCPU_ENTRY_STACK',symbols['percpu_entry']+24)]:
      p=out/(name+'.bin');request('pmemsave',{'val':address,'size':8,'filename':str(p)});hardware[name]=int.from_bytes(p.read_bytes(),'little')
     result['hardware_state']=hardware;assert hardware=={'TSS_RSP0':symbols['stack_top'],'PERCPU_ENTRY_STACK':symbols['stack_top']}
     result['state']=state
     def get(m,n):return state[m+'__'+n]
     raw=[0,1,42,255]if a.status_group==0 else[256,(1<<64)-1,2147483647,(1<<64)-2147483648];codes=[(x&255)<<8 for x in raw];assert get('kernel__m6','ACCEPTED')==[1]and get('kernel__m6','EXIT_RAW')==raw and get('kernel__m6','EXITS')==codes and get('runtime__process','EXIT_CODES')==codes;assert get('kernel__m6','EXIT_DONE')==[1]*4 and get('kernel__m6','CLEANUP_CALLS')==[1]*4 and get('kernel__m6','UID_CALLS')==[1,1,2,2]and get('kernel__m6','UID_REPORTS')==[1,1,2,2]and get('kernel__m6','EXIT_GROUP_CALLS')==[1]*4 and get('kernel__m6','EXIT_CALLS')==[int(a.fallback_231_unavailable)]*4 and get('kernel__m6','READS')==[2,2,3,3];assert get('kernel__m6','UID_VALUES')==[os.getuid(),0,os.getuid(),0,os.getuid(),os.getuid(),os.getuid(),os.getuid()]
     assert get('runtime__thread','STATES')==[4]*4 and get('runtime__thread','PROCESS_REF_HELD')==[0]*4 and get('runtime__thread','LINUX_SINGLE_TASK')==[0]*4 and get('runtime__thread','CURRENT_THREAD')==[0]and get('runtime__process','CURRENT_PROCESS')==[0];assert get('runtime__process','THREAD_REFS')==[0]*4 and get('runtime__scheduler','FAILED')==[0]and get('runtime__scheduler','COMPLETE')==[0]and get('runtime__scheduler','IDLE_POLICY')==[1]and get('runtime__scheduler','ACTIVE')==[1];assert not any(get('runtime__posix_file_syscalls','ENABLED'))and not any(get('runtime__common__posix_namespace_files','FD_DESCRIPTION'));assert get('kernel__m6','SLEEP_IDLE_TICKS')[0]>=2 and get('kernel__m6','FINAL_IDLE_TICKS')[0]>=5;assert get('kernel__m6','WINDOW')==[0]and get('kernel__m6','SURVIVOR')==[3]
     assert get('runtime__process','STATES')==[5]*4 and all(get('runtime__scheduler',x)==[0]for x in['PENDING_ACTION','PENDING_LINUX_EXIT','SYSCALL_PHASE','SYSCALL_IDLE_DISPOSITION'])
     assert get('kernel__m6','IDLE_CR3')==[symbols['p4_table']]and get('kernel__m6','IDLE_GS')==[symbols['percpu_entry']]and get('kernel__m6','IDLE_KERNEL_GS')==[0]
     assert symbols['stack_bottom']<=get('kernel__m6','IDLE_STACK')[0]<=symbols['stack_top']
     assert re.search(r'FS =0000 0000000000000000',regs)and re.search(r'GS =0000 '+format(symbols['percpu_entry'],'016x'),regs)and 'CR3='+format(symbols['p4_table'],'016x')in regs
     for i in range(4):
      pc=get('kernel__m6','SOURCE_PCS')[i*3:i*3+3];assert pc[0]==sites['getuid'][0]and pc[1]in sites['_Exit']
      assert (pc[2]in sites['_Exit']and pc[2]!=pc[1])if a.fallback_231_unavailable else pc[2]==0
     result['native_source_calls']=[{'role':i,'getuid_pc':get('kernel__m6','SOURCE_PCS')[i*3],'exit_group_pc':get('kernel__m6','SOURCE_PCS')[i*3+1],'exit_pc':get('kernel__m6','SOURCE_PCS')[i*3+2]}for i in range(4)];request('quit')
    proc.wait(timeout=10);result['owned_qemu_returncode']=proc.returncode
   finally:
    if proc.poll()is None:proc.terminate();proc.wait(timeout=10)
  result['source_after']=[info(p)for p in originals];assert before==result['source_after'];result['source_unchanged']=True;result['ok']=True
 except Exception:result['error']=traceback.format_exc()
 finally:
  if'originals'in locals():result['source_after']=[info(p)for p in originals];result['source_unchanged']=result.get('source_before')==result['source_after'];result['ok']=result['ok']and result['source_unchanged']
  write()
 print(json.dumps({'ok':result['ok'],'result':str(out/'result.json'),'error':result.get('error')},indent=2));return 0 if result['ok']else 1
if __name__=='__main__':raise SystemExit(main())
