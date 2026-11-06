from pathlib import Path
from unittest import mock
import contextlib,hashlib,io,json,os,runpy,shutil,subprocess,sys,tempfile,traceback
W=Path(__file__).resolve().parent;D=W/'recipe-v2';O=Path(tempfile.mkdtemp(prefix='recipe-schema-controls-',dir=W));R={'ok':False,'scope':'Real retained result schemas and dynamic VM-class constructor command interception only; no build/QEMU execution','cases':[]}
def pin(p):p=Path(p);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
refs={'pointer':W/'recipe-all-v1-r7/work/pointer/attempt-5/result.json','system-controls':W/'system-controls/final-r6-attempt-1/result.json','real-env-controls':W/'real-env-controls/final-r6-attempt-1/result.json','xsave-controls':W/'xsave-controls/final-r6-attempt-1/result.json','migration-controls':W/'migration-controls/final-r6-attempt-1/result.json','migration-stream-controls':W/'migration-stream-controls/final-r6-attempt-1/result.json'}
try:
 for fail in (False,True):
  C=O/('valid-six-schemas'if not fail else'failed-stream-postguard');C.mkdir();B=C/'bin';B.mkdir();S=C/'source';S.mkdir()
  for n in('qemu-system-x86_64','qemu-x86_64','qemu-i386'):(B/n).write_bytes(b'SYNTHETIC not executed')
  calls=[]
  def fake(argv,**kw):
   script=Path(argv[2]);name=script.parent.name;f=refs[name];x=json.loads(f.read_text());dest=Path(kw['cwd'])/name/('attempt-5'if name=='pointer'else'final-r6-attempt-1');dest.mkdir();
   if fail and name=='migration-stream-controls':x['inputs_unchanged']=False
   (dest/'result.json').write_text(json.dumps(x));calls.append({'name':name,'retained_schema':pin(f)});return subprocess.CompletedProcess(argv,0,b'SYNTHETIC no external command\n',b'')
  old=sys.argv;status=None;so=io.StringIO();se=io.StringIO()
  try:
   sys.argv=[str(D/'verify.py'),'--bin-dir',str(B),'--source',str(S),'--sdk',str(C),'--output',str(C/'output')]
   with mock.patch('subprocess.run',side_effect=fake),contextlib.redirect_stdout(so),contextlib.redirect_stderr(se):
    try:runpy.run_path(str(D/'verify.py'),run_name='__main__')
    except SystemExit as e:status=e.code
  finally:sys.argv=old
  (C/'stdout').write_text(so.getvalue());(C/'stderr').write_text(se.getvalue());x=json.loads((C/'output/result.json').read_text());assert len(calls)==6;assert x['ok']==(not fail);assert status==(1 if fail else 0);R['cases'].append({'case':C.name,'passed':True,'status':status,'receipt':pin(C/'output/result.json'),'six_actual_schemas':calls})
 # Execute the exact reused VM class in the stream runner's real helper scope.
 C=O/'dynamic-stream-class';C.mkdir();F=D/'fixtures';code=(F/'migration-stream-controls/run_r6.py').read_text();prefix=code[:code.index('from pathlib import Path')];fragment=(F/'migration-controls/run.py').read_text();fragment=fragment[fragment.index('class VM:'):fragment.index('def decode(')];(C/'helper.py').write_text(prefix);(C/'class.py').write_text(fragment)
 ns={'Path':Path,'O':C,'W':C,'Q':C/'not-executed-qemu','CODE':C/'code','VARS':C/'vars','shutil':shutil,'tempfile':tempfile,'subprocess':subprocess};(C/'vars').write_bytes(b'not firmware');(C/'tmp').mkdir();exec(compile(prefix,str(C/'helper.py'),'exec'),ns);exec(compile(fragment,str(C/'class.py'),'exec'),ns)
 class ReachedOwnPopen(Exception):pass
 seen=[]
 def fake_popen(argv,**kw):
  assert kw['preexec_fn'] is ns['_owned_parent_death'];assert kw['start_new_session'] is True;seen.append({'argv':argv,'has_exact_stream_helper':True});raise ReachedOwnPopen()
 with mock.patch('subprocess.Popen',side_effect=fake_popen),mock.patch('tempfile.mkdtemp',return_value=str(C/'tmp')):
  try:ns['VM']('intercepted-incoming',incoming=True)
  except ReachedOwnPopen:pass
 assert len(seen)==1
 R['cases'].append({'case':'actual-stream-reused-VM-constructor-resolves-own-parent-death-helper','passed':True,'calls_not_executed':seen,'helper':pin(C/'helper.py'),'class_fragment':pin(C/'class.py')});R['ok']=True
except Exception:R['error']=traceback.format_exc()
R['controller']=pin(__file__);R['source_inputs']=[pin(D/'verify.py'),pin(D/'fixtures/migration-controls/run.py'),pin(D/'fixtures/migration-stream-controls/run_r6.py')];(O/'result.json').write_text(json.dumps(R,indent=2)+'\n');print(json.dumps({'result':pin(O/'result.json'),'ok':R['ok'],'cases':len(R['cases'])}));raise SystemExit(0 if R['ok'] else 1)
