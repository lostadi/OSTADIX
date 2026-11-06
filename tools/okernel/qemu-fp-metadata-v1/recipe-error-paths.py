"""Execute recipe entrypoints with only external commands mocked; never build/boot.

Synthetic source, wheel and tool-output files are private cache fixtures. This
qualifies fail-closed orchestration/error paths, not a QEMU build or VM result.
"""
from pathlib import Path
from unittest import mock
import contextlib, hashlib, io, json, os, runpy, subprocess, sys, tempfile, traceback, zipfile
W=Path(__file__).resolve().parent
O=Path(tempfile.mkdtemp(prefix='recipe-error-paths-',dir=W))
R={'ok':False,'scope':'Synthetic command/failure paths only; no QEMU build or VM execution','cases':[]}
def pin(p):
 p=Path(p);b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def invoke(script,argv,fake,drift):
 old=sys.argv;out=io.StringIO();err=io.StringIO();status=None;real=Path.read_bytes
 def rd(p):
  b=real(p)
  return b+b'\nSYNTHETIC_TOOL_DRIFT' if drift[0] and str(p)=='/usr/bin/ar' else b
 try:
  sys.argv=[str(script)]+list(map(str,argv))
  with mock.patch('subprocess.run',side_effect=fake),mock.patch.object(Path,'read_bytes',rd),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
   try:runpy.run_path(str(script),run_name='__main__')
   except SystemExit as e:status=e.code
 except Exception:status='unexpected-exception';err.write(traceback.format_exc())
 finally:sys.argv=old
 return status,out.getvalue(),err.getvalue()
def build_case(kind):
 C=O/kind;C.mkdir();S=C/'source';S.mkdir();(S/'changed.c').write_text('current source\n');(S/'python/wheels').mkdir(parents=True)
 for n in ('meson-1.11.1-py3-none-any.whl','pycotap-1.3.1-py3-none-any.whl','qemu_qmp-0.0.6-py3-none-any.whl'):
  with zipfile.ZipFile(S/'python/wheels'/n,'w')as z:z.writestr(n+'.txt','synthetic wheel')
 files=[]
 for q in S.rglob('*'):
  if q.is_file():
   x=pin(q);x['relative']=str(q.relative_to(S));x['mode']=oct(q.stat().st_mode&0o777);del x['path'];files.append(x)
 base=[dict(x)for x in files];next(x for x in base if x['relative']=='changed.c')['sha256']='0'*64
 (C/'base.json').write_text(json.dumps({'files':base}));(C/'freeze.json').write_text(json.dumps({'paths':[x for x in files if x['relative']=='changed.c']}))
 if kind=='build-missing-manifest':(C/'base.json').write_text('{bad')
 script=C/'build.py';script.write_bytes((W/'recipe-v2/build.py').read_bytes());pins=json.loads((W/'recipe-v2/pins.json').read_text());pins['original_files_sha256']=hashlib.sha256(json.dumps(base,sort_keys=True,separators=(',',':')).encode()).hexdigest();pins['source_freeze']['sha256']=pin(C/'freeze.json')['sha256'];
 if kind=='build-unpinned-base':pins['original_files_sha256']='f'*64
 if kind=='build-unpinned-freeze':pins['source_freeze']['sha256']='f'*64
 (C/'pins.json').write_text(json.dumps(pins));drift=[False];commands=[]
 def fake(argv,**kw):
  commands.append(list(map(str,argv)))
  if kw.get('stdout'):kw['stdout'].write(b'SYNTHETIC command, not executed\n')
  if kind=='build-configure-failure' and str(argv[0]).endswith('/configure'):return subprocess.CompletedProcess(argv,9)
  if kind=='build-compile-timeout' and '-j2' in argv:raise subprocess.TimeoutExpired(argv,1200)
  if '-j2' in argv:
   d=Path(kw['cwd'])
   for n in ('qemu-system-x86_64','qemu-x86_64','qemu-i386'):(d/n).write_bytes(b'NOT AN EXECUTABLE: '+n.encode())
   (d/'compile_commands.json').write_text(json.dumps([{'file':str(S/'target/i386/tcg/fpu_helper.c'),'command':'gcc -O2 -g0 -c file.c'}]*3))
   if kind=='build-source-drift':(S/'changed.c').write_text('unexpected drift\n')
   if kind=='build-tool-drift':drift[0]=True
  return subprocess.CompletedProcess(argv,0)
 status,so,se=invoke(script,['--source',S,'--base-manifest',C/'base.json','--freeze',C/'freeze.json','--output',C/'output','--prefix',C/'prefix'],fake,drift)
 return finish(kind,C,status,so,se,commands,kind=='build-success')
def verify_case(kind):
 C=O/kind;C.mkdir();B=C/'bin';B.mkdir()
 for n in ('qemu-system-x86_64','qemu-x86_64','qemu-i386'):(B/n).write_bytes(b'NOT EXECUTED: '+n.encode())
 S=C/'source';S.mkdir();drift=[False];commands=[]
 def fake(argv,**kw):
  commands.append(list(map(str,argv)));D=Path(argv[-1]).parent/'attempt-5';D.mkdir();(D/'result.json').write_text(json.dumps({'ok':kind!='verify-failed-qualification','sources_unchanged':kind!='verify-child-source-drift','tools_unchanged':True}))
  if kind=='verify-tool-drift':
   q=Path(kw['cwd'])/'v1r6-bin/qemu-i386';q.chmod(0o755);q.write_bytes(b'changed private copied bytes')
  if kind=='verify-fixture-drift':(Path(kw['cwd'])/'pointer/probe.S').write_text('SYNTHETIC unexpected fixture drift')
  return subprocess.CompletedProcess(argv,7 if kind=='verify-command-failure' else 0,b'',b'SYNTHETIC no child executed\n')
 status,so,se=invoke(W/'recipe-v2/verify.py',['--source',S,'--bin-dir',B,'--sdk',C,'--output',C/'output','--only','pointer'],fake,drift)
 return finish(kind,C,status,so,se,commands,kind=='verify-success')
def finish(kind,C,status,so,se,commands,success):
 (C/'controller.stdout').write_text(so);(C/'controller.stderr').write_text(se);x=json.loads((C/'output/result.json').read_text())
 assert status==(0 if success else 1),(kind,status,se)
 assert x['ok']==success,(kind,x)
 if kind=='build-source-drift':assert x['sources_unchanged'] is False
 if kind=='build-tool-drift' or kind=='verify-tool-drift':assert x['tools_unchanged'] is False
 if not success:assert x.get('error')
 row={'case':kind,'passed':True,'actual_exit':status,'recipe_ok':x['ok'],'commands_mocked_not_executed':commands,'receipt':pin(C/'output/result.json'),'stdout':pin(C/'controller.stdout'),'stderr':pin(C/'controller.stderr')}
 R['cases'].append(row)
try:
 for n in ('build-success','build-configure-failure','build-compile-timeout','build-source-drift','build-tool-drift','build-missing-manifest','build-unpinned-base','build-unpinned-freeze'):build_case(n)
 for n in ('verify-success','verify-command-failure','verify-failed-qualification','verify-tool-drift','verify-fixture-drift','verify-child-source-drift'):verify_case(n)
 R['ok']=True
except Exception:R['error']=traceback.format_exc()
R['controller']=pin(__file__);R['recipes']=[pin(W/'recipe-v2'/n)for n in ('build.py','verify.py')];(O/'result.json').write_text(json.dumps(R,indent=2)+'\n')
print(json.dumps({'output':str(O),'result':pin(O/'result.json'),'ok':R['ok'],'cases':len(R['cases'])}))
sys.exit(0 if R['ok'] else 1)
