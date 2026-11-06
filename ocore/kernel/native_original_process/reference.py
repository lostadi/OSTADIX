#!/usr/bin/env python3
"""Bounded original-Makefile Linux x86 reference, not O-core admission.

The owned launcher applies an exact231 seccomp filter only in its own child.
strace -D preserves the actual source child's parent; the PID/PPID diagnostic
and raw waitpid word are checked rather than inferred from tracer status.
"""
import argparse,hashlib,json,os,re,shutil,struct,subprocess,time,traceback
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def info(p):
 p=Path(p).resolve(strict=True);b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--original-build',type=Path,required=True);a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 r={'schema':'ostadix.original-musl-process-reference/v1','ok':False,'scope':__doc__,'commands':[],'cases':[],'parent_identity':{'pid':os.getpid(),'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid()}}
 def write():(out/'result.json').write_text(json.dumps(r,indent=2)+'\n')
 def run(label,argv):
  argv=list(map(str,argv));p=subprocess.run(argv,capture_output=True,cwd=ROOT,timeout=120);(out/(label+'.stdout')).write_bytes(p.stdout);(out/(label+'.stderr')).write_bytes(p.stderr);r['commands'].append({'label':label,'argv':argv,'returncode':p.returncode,'stdout':info(out/(label+'.stdout')),'stderr':info(out/(label+'.stderr'))});write();assert p.returncode==0,(label,p.stderr.decode(errors='replace'));return p.stdout
 try:
  assert os.uname().machine=='x86_64','actual x86-64 host required'
  clang=Path(shutil.which('clang'));lld=Path(shutil.which('ld.lld'));nm=Path(shutil.which('nm'));objdump=Path(shutil.which('objdump'));strace=Path(shutil.which('strace'))
  build=a.original_build.resolve(strict=True);record=json.loads((build/'component-build.json').read_bytes());objects=[build/'obj/src/unistd/getuid.o',build/'obj/src/exit/_Exit.o'];assert record['isa']=='x86_64' and record['reference_objects']==[info(p) for p in objects]
  originals=[Path(__file__),HERE/'bootstrap.c',HERE/'reference_launcher.c',HERE/'user.ld',ROOT/'ocore/kernel/native_tls/entry.S',build/'component-build.json',*objects,*[Path(x['path']) for x in record['original_sources']]]
  before=[info(p) for p in originals];r['source_before']=before;r['tools']=[info(p) for p in [clang,lld,nm,objdump,strace,Path('/proc/self/exe')]]
  for i,p in enumerate(originals):
   d=out/'source'/str(i)/p.name;d.parent.mkdir(parents=True,exist_ok=True);d.write_bytes(p.read_bytes());d.chmod(0o444)
  r['original_build']=info(build/'component-build.json');r['lowering_claim']=False;r['original_source_revision']=record['source']['revision'];r['strace_help']=run('strace-help',[strace,'--help']).decode();assert 'run tracer process as a grandchild' in r['strace_help']
  run('launcher-compile',[clang,'-O2','-Wall','-Wextra','-Werror',HERE/'reference_launcher.c','-o',out/'launcher']);run('launcher-ldd',['ldd',out/'launcher']);run('entry-compile',[clang,'-c',ROOT/'ocore/kernel/native_tls/entry.S','-o',out/'entry.o'])
  identities=[f'-DHOST_{k.upper()}={getattr(os,"get"+k)()}' for k in ['uid','euid','gid','egid']]
  for group in range(2):
   b=out/f'bootstrap-{group}.o';elf=out/f'original-{group}.elf'
   run(f'bootstrap-{group}',[clang,'-DNATIVE_USER_PROVIDER=0',f'-DSTATUS_GROUP={group}',*identities,'-O2','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pic','-fno-pie','-mno-sse','-mno-sse2','-mno-red-zone','-c',HERE/'bootstrap.c','-o',b])
   run(f'link-{group}',[lld,'-m','elf_x86_64','-nostdlib','--build-id=none','-z','max-page-size=0x1000','-T',HERE/'user.ld','-o',elf,out/'entry.o',b,*objects]);assert not run(f'undefined-{group}',[nm,'-u',elf]).strip()
   symbols=run(f'symbols-{group}',[nm,'-S',elf]).decode();ranges={x[3]:(int(x[0],16),int(x[0],16)+int(x[1],16)) for line in symbols.splitlines() if len(x:=line.split())==4 and x[3] in ('getuid','_Exit')};assert set(ranges)=={'getuid','_Exit'}
   disasm=run(f'disasm-{group}',[objdump,'-d',elf]).decode();sites={name:[] for name in ranges}
   for line in disasm.splitlines():
    m=re.match(r'\s*([0-9a-f]+):\s+0f 05\s+syscall\b',line)
    if m:
     pc=int(m.group(1),16)+2
     for name,(lo,hi) in ranges.items():
      if lo<=pc<=hi:sites[name].append(pc)
   assert len(sites['getuid'])==1 and len(sites['_Exit'])==2,sites
   for fallback in (0,1):
    for role in range(4):
     label=f'g{group}-fallback{fallback}-role{role}';trace=out/(label+'.trace');stdout=out/(label+'.stdout');stderr=out/(label+'.stderr');argv=[str(strace),'-D','-i','-n','-e','trace=execve,getuid,exit,exit_group,prctl,seccomp','-o',str(trace),'--',str(out/'launcher'),str(fallback),str(elf),str(role)]
     outfd=os.open(stdout,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);errfd=os.open(stderr,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
     pid=os.posix_spawn(str(strace),argv,os.environ.copy(),file_actions=[(os.POSIX_SPAWN_DUP2,outfd,1),(os.POSIX_SPAWN_DUP2,errfd,2),(os.POSIX_SPAWN_CLOSE,outfd),(os.POSIX_SPAWN_CLOSE,errfd)],setsid=True);os.close(outfd);os.close(errfd)
     started=time.monotonic();status=None
     while time.monotonic()-started<10:
      got,word=os.waitpid(pid,os.WNOHANG)
      if got:status=word;break
      time.sleep(.01)
     if status is None:os.kill(pid,9);os.waitpid(pid,0);raise TimeoutError(label)
     for _ in range(100):
      text=trace.read_text() if trace.exists() else ''
      if '+++ exited with' in text:break
      time.sleep(.01)
     diag=stderr.read_text();m=re.search(r'owned-launcher pid=(\d+) ppid=(\d+) uid=(\d+) euid=(\d+) gid=(\d+) egid=(\d+) fallback=([01])',diag);assert m,(label,diag);assert tuple(map(int,m.groups()))==(pid,os.getpid(),os.getuid(),os.geteuid(),os.getgid(),os.getegid(),fallback),(label,pid,m.groups())
     rawcode=([0,1,42,255] if group==0 else [256,-1,2147483647,-2147483648])[role];expected=(rawcode&255)<<8;assert status==expected,(label,status,expected)
     words=struct.unpack('<'+'Q'*(len(stdout.read_bytes())//8),stdout.read_bytes());expected_words=tuple(v for ordinal in range(1 if role<2 else 2) for v in (0x4f50524f43554944,role,ordinal,os.getuid()));assert words==expected_words,(label,words)
     boundary='execve("'+str(elf)+'"';assert text.count(boundary)==1,(label,text);body=text.split(boundary,1)[1];calls=[]
     for line in body.splitlines():
      mt=re.match(r'\[\s*(\d+)\]\s+\[([0-9a-f]+)\]\s+(getuid|exit_group|exit)\((.*?)\)\s*=\s*(.*)',line)
      if mt:calls.append({'pc':int(mt.group(2),16),'number':int(mt.group(1)),'name':mt.group(3),'argument':mt.group(4),'result':mt.group(5)})
     assert [x['name'] for x in calls]==['getuid']*(1 if role<2 else 2)+['exit_group']+(['exit'] if fallback else []),(label,body,calls)
     for call in calls:
      assert call['pc'] in sites['getuid' if call['name']=='getuid' else '_Exit'],(label,call,sites)
      if call['name']=='getuid':assert call['number']==102 and call['result']==str(os.getuid()),call
      else:assert call['number']==(231 if call['name']=='exit_group' else 60),call
     if fallback:assert 'ENOSYS' in calls[-2]['result'] and 'seccomp(SECCOMP_SET_MODE_FILTER' in text and 'PR_SET_NO_NEW_PRIVS' in text
     else:assert 'seccomp(' not in text
     r['cases'].append({'label':label,'argv':argv,'owned_pid':pid,'raw_waitpid':status,'source_int_status':rawcode,'expected_linux_wait_word':expected,'syscalls':calls,'stdout_words':words,'source_sites':sites,'elf':info(elf),'trace':info(trace),'stdout':info(stdout),'stderr':info(stderr)});write()
  after=[info(p) for p in originals];r['source_after']=after;assert after==before;r['source_unchanged']=True;r['parent_identity_after']={'pid':os.getpid(),'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid()};assert r['parent_identity_after']==r['parent_identity'];assert len(r['cases'])==16;r['ok']=True
 except Exception:r['error']=traceback.format_exc()
 write();return 0 if r['ok'] else 1
if __name__=='__main__':raise SystemExit(main())
