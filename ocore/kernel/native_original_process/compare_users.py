#!/usr/bin/env python3
"""Original/reference versus freshly readmitted O-core USER components.

External Linux user-process execution only, using actual per-ISA captures.
QEMU-user foreign execution is not a native O-core kernel provider proof.
No foreign seccomp/exit fallback, complete musl/CRT or general OS claim.
"""
import argparse,hashlib,importlib.util,json,os,re,shutil,struct,subprocess,time,traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('original_user_artifact_tools',HERE/'verify.py');A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
info=A.info
PROFILES={'x86_64':{'machine':62,'format':'elf64-x86-64','arch':'i386:x86-64','emulation':'elf_x86_64','syscalls':(102,60,231)},'aarch64':{'machine':183,'format':'elf64-littleaarch64','arch':'aarch64','emulation':'aarch64elf','syscalls':(174,93,94)},'riscv64':{'machine':243,'format':'elf64-littleriscv','arch':'riscv','emulation':'elf64lriscv','syscalls':(174,93,94)}}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--isa',required=True,choices=PROFILES);p.add_argument('--source-run',required=True,type=Path,help='Successful frozen build_components.py output containing product+reopened');p.add_argument('--output',required=True,type=Path);p.add_argument('--runner',type=Path,help='Explicit Linux tracer or actual foreign-ISA Linux user emulator');a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);profile=PROFILES[a.isa]
 result={'schema':'ostadix.original-musl-user-pair/v1','ok':False,'scope':__doc__,'isa':a.isa,'commands':[],'cases':[],'identity':{'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid()}}
 def write():(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 def run(label,argv):
  argv=list(map(str,argv));p=subprocess.run(argv,cwd=ROOT,capture_output=True,timeout=120);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);result['commands'].append({'label':label,'argv':argv,'returncode':p.returncode,'stdout':info(out/(label+'.stdout')),'stderr':info(out/(label+'.stderr'))});write();assert p.returncode==0,(label,p.stderr.decode(errors='replace'));return p.stdout
 try:
  sr=a.source_run.resolve(strict=True);result['entry_inputs']=[info(x)for x in[Path(__file__),HERE/'verify.py',HERE/'bootstrap.c',HERE/'user.ld',sr/'result.json',sr/'product/provider-group.json']]
  for x in result['entry_inputs']:
   d=out/'entry-inputs'/x['sha256']/Path(x['path']).name;d.parent.mkdir(parents=True,exist_ok=True);d.write_bytes(Path(x['path']).read_bytes());d.chmod(0o444)
  prior=json.loads((sr/'result.json').read_bytes());pg=json.loads((sr/'product/provider-group.json').read_bytes());assert prior['ok']and prior['isa']==a.isa and prior['source_unchanged']and pg['source_group_complete']and pg['lowering_complete']and pg['object_reemission_complete'],'complete original two-unit build/reopen prerequisite unmet'
  group_path=sr/'product/source-group.native-ir.json';group=json.loads(group_path.read_bytes());readmission_path=sr/'reopened/source-readmission.json';readmission=json.loads(readmission_path.read_bytes());assert readmission['source_group_sha256']==info(group_path)['sha256']and not readmission['issues']and readmission['included_original_ir_body_consistency']and len(readmission['units'])==2 and all(x['fresh_typed_import_match']for x in readmission['units']);assert len(group['components'])==1 and len(group['module_set']['modules'])==2
  component=group['components'][0];recipe=ROOT/'tools/ocore-runtime/linux-process-components'/(a.isa+'.recipe.json');assert component['recipe_sha256']==info(recipe)['sha256']and component['recipe_json']==recipe.read_text()
  calls=[]
  for m in group['module_set']['modules']:
   assert hashlib.sha256(m['native_ir'].encode()).hexdigest()==m['sha256'];v=json.loads(m['native_ir']);assert len(v['functions'])==1 and v['functions'][0]['exception_handling']is None
   for b in v['functions'][0]['blocks']:
    for item in b['instructions']:
     op=item['operation']
     if op['op']=='linux_syscall':calls.append((v['functions'][0]['name'],int(op['number']['bits']),len(op['arguments'])))
  uid,ex,grp=profile['syscalls'];assert sorted(calls)==sorted([('getuid',uid,0),('_Exit',ex,1),('_Exit',grp,1)]);result['static_calls']=calls
  references=[sr/'product/component-000000/build/obj/src/unistd/getuid.o',sr/'product/component-000000/build/obj/src/exit/_Exit.o'];owned=sorted((sr/'reopened/lowered').glob('unit-*/module.o'));assert len(owned)==2
  manifest_path=sr/'product/component-000000/build/component-build.json';manifest=json.loads(manifest_path.read_bytes());assert manifest['reference_objects']==[info(x)for x in references]and manifest['isa']==a.isa and manifest['source']['revision']=='0784374d561435f7c787a555aeab8ede699ed298';assert sorted(Path(x['path']).name for x in manifest['original_sources'])==['_Exit.c','getuid.c']
  for x in manifest['original_sources']:assert info(x['path'])==x
  coverage_path=sr/'reopened/lowered/coverage.json';coverage=json.loads(coverage_path.read_bytes());assert coverage['unit_lowering_complete']and coverage['lowering_complete']and coverage['symbol_closure_complete']and not coverage['issues']and len(coverage['units'])==2
  for unit in coverage['units']:
   assert unit['verified']and unit['lowered']and info(unit['object']['path'])==unit['object']and info(unit['module']['path'])['sha256']==unit['module']['sha256']
  assert set(str(x)for x in owned)==set(x['object']['path']for x in coverage['units']);result['object_coverage']=info(coverage_path);result['source_compiler']={'path':coverage['compiler'],'sha256':coverage['compiler_sha256']}
  assert info(coverage['compiler'])['sha256']==coverage['compiler_sha256'],'source compiler image changed after captured emission'
  expected_notes=[x['interface']for x in readmission['required_platform_interfaces']];assert len(expected_notes)==2
  for x in owned:
   e=A.elf(x,profile['machine']);assert len(e['notes'])==1 and e['notes'][0]['payload']in expected_notes and not e['undefined'];assert e['notes'][0]['payload']['architecture']==a.isa and e['notes'][0]['payload']['privilege']=='user_mode_only'
  clang=Path(shutil.which('clang'));lld=Path(shutil.which('ld.lld'));runner=(a.runner or(Path(shutil.which('strace'))if a.isa=='x86_64'else Path.home()/'.local/share/ostadix/bm-dev/host/usr/bin'/('qemu-'+a.isa))).resolve(strict=True);result['tools']=[info(x)for x in[clang,lld,runner,Path('/proc/self/exe')]];run('runner-version',[runner,'--version']);inputs=[Path(__file__),HERE/'verify.py',HERE/'bootstrap.c',HERE/'user.ld',group_path,readmission_path,manifest_path,coverage_path,*references,*owned,*[Path(x['path'])for x in manifest['original_sources']]];before=[info(x)for x in inputs];result['source_before']=before
  for x in inputs:
   d=out/'source'/info(x)['sha256']/x.name;d.parent.mkdir(parents=True,exist_ok=True);d.write_bytes(x.read_bytes());d.chmod(0o444)
  text=(HERE/'user.ld').read_text().replace('OUTPUT_FORMAT(elf64-x86-64)','OUTPUT_FORMAT('+profile['format']+')').replace('OUTPUT_ARCH(i386:x86-64)','OUTPUT_ARCH('+profile['arch']+')');linker=out/'user.ld';linker.write_text(text)
  entry=out/'entry.S';entry.write_text({'x86_64':(ROOT/'ocore/kernel/native_tls/entry.S').read_text(),'aarch64':'.text\n.global _start\n.type _start,%function\n_start:\n mov x0,sp\n mov x29,xzr\n bl probe\n brk #1\n.section .note.GNU-stack,"",%progbits\n','riscv64':'.text\n.global _start\n.type _start,@function\n_start:\n mv a0,sp\n andi sp,sp,-16\n call probe\n unimp\n.section .note.GNU-stack,"",@progbits\n'}[a.isa]);target=a.isa+'-unknown-linux-musl';archflags=['-march=rv64gc','-mabi=lp64d']if a.isa=='riscv64'else[];run('entry',[clang,'--target='+target,*archflags,'-c',entry,'-o',out/'entry.o'])
  for groupnum in(0,1):
   flags=[f'-DHOST_{k.upper()}={v}'for k,v in result['identity'].items()];boot=out/f'bootstrap-{groupnum}.o';run(f'bootstrap-{groupnum}',[clang,'--target='+target,*archflags,'-DNATIVE_USER_PROVIDER=0',f'-DSTATUS_GROUP={groupnum}',*flags,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie',*(['-mno-sse','-mno-sse2','-mno-red-zone']if a.isa=='x86_64'else[]),'-c',HERE/'bootstrap.c','-o',boot]);statuscodes=([0,1,42,255]if groupnum==0 else[256,-1,2147483647,-2147483648]);paired={}
   for kind,objects in[('reference',references),('owned',owned)]:
    executable=out/f'{kind}-{groupnum}.elf';run(f'link-{kind}-{groupnum}',[lld,'-m',profile['emulation'],'-nostdlib','--build-id=none',*(['--no-relax']if a.isa=='riscv64'else[]),'-z','max-page-size=0x1000','-T',linker,'-o',executable,out/'entry.o',boot,*objects]);e=A.elf(executable,profile['machine']);assert not e['undefined']
    if kind=='owned':assert e['notes']==[n for o in owned for n in A.elf(o,profile['machine'])['notes']]
    else:assert e['notes']==[]
    bindings=[]
    for obj in objects:
     oe=A.elf(obj,profile['machine'])
     for name,symbol in oe['symbols'].items():
      if name not in('getuid','_Exit'):continue
      final=e['symbols'][name];relocations=[x for x in oe['relocations']if x['source_section']==symbol['section']and symbol['section_offset']<=x['offset']<symbol['section_offset']+symbol['size']];assert final['size']==symbol['size'],'unexpected function extent change under no-relax link'
      equal=final['bytes']==symbol['bytes']
      if not relocations:assert equal,(kind,name,'unrelocated function bytes changed')
      bindings.append({'function':name,'input_object':info(obj),'input_bytes_sha256':hashlib.sha256(symbol['bytes']).hexdigest(),'final_bytes_sha256':hashlib.sha256(final['bytes']).hexdigest(),'raw_bytes_equal':equal,'input_text_relocations':relocations,'scope':'Exact captured linker inputs/outputs and no-relax extent; functions without input text relocations must remain byte-identical. Relocated bytes are retained, never normalized or called raw-byte-identical.'})
    for role in range(4):
     label=f'{kind}-g{groupnum}-role{role}';stdout=out/(label+'.stdout');stderr=out/(label+'.stderr');trace=out/(label+'.trace')
     argv=[str(runner),'-D','-i','-n','-e','trace=getuid,exit,exit_group,execve','-o',str(trace),'--',str(executable),str(role)]if a.isa=='x86_64'else[str(runner),'-strace',str(executable),str(role)]
     of=os.open(stdout,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);ef=os.open(stderr,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);pid=os.posix_spawn(str(runner),argv,os.environ.copy(),file_actions=[(os.POSIX_SPAWN_DUP2,of,1),(os.POSIX_SPAWN_DUP2,ef,2),(os.POSIX_SPAWN_CLOSE,of),(os.POSIX_SPAWN_CLOSE,ef)],setsid=True);os.close(of);os.close(ef);start=time.monotonic();status=None
     while time.monotonic()-start<15:
      got,value=os.waitpid(pid,os.WNOHANG)
      if got:status=value;break
      time.sleep(.01)
     if status is None:os.kill(pid,9);os.waitpid(pid,0);raise TimeoutError(label)
     data=stdout.read_bytes();expected_words=tuple(v for ordinal in range(1 if role<2 else 2)for v in(0x4f50524f43554944,role,ordinal,os.getuid()));assert data==struct.pack('<'+'Q'*len(expected_words),*expected_words);assert status==(statuscodes[role]&255)<<8,(label,status,statuscodes[role])
     logpath=trace if a.isa=='x86_64'else stderr
     for _ in range(100):
      log=logpath.read_text()if logpath.exists()else''
      if 'exit_group('in log:break
      time.sleep(.01)
     assert log.count('getuid()')==(1 if role<2 else 2)and log.count('exit_group(')==1 and not re.search(r'(?<!_)\bexit\(',log),log
     row={'kind':kind,'status_group':groupnum,'role':role,'argv':argv,'owned_pid':pid,'raw_waitpid':status,'source_int_status':statuscodes[role],'binary_uid_words':expected_words,'stdout':info(stdout),'stderr':info(stderr),'syscall_trace':info(logpath),'executable':info(executable),'user_notes':e['notes'],'function_bindings':bindings};result['cases'].append(row);paired[(kind,role)]=(status,data);write()
   assert all(paired['reference',i]==paired['owned',i]for i in range(4))
  result['source_after']=[info(x)for x in inputs];assert result['source_after']==before;result['source_unchanged']=True;assert len(result['cases'])==16;result['ok']=True
 except Exception:result['error']=traceback.format_exc()
 write();print(json.dumps({'ok':result['ok'],'result':str(out/'result.json'),'error':result.get('error')},indent=2));return 0 if result['ok']else 1
if __name__=='__main__':raise SystemExit(main())
