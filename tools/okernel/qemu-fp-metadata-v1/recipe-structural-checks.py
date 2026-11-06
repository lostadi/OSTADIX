from pathlib import Path
import ast,hashlib,json,shutil,subprocess,tempfile,time,os
w=Path(__file__).resolve().parent;d=w/'recipe-v2';o=Path(tempfile.mkdtemp(prefix='recipe-structural-',dir=w));r={'ok':False,'scope':'Generator byte-equality, syntax and owned non-QEMU parent-death control only; no build or VM','prior_attempt':'Inline checker had SyntaxError at final else1 expression before any command execution; preserved in session transcript'}
def pin(p):p=Path(p);b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
try:
 for p in d.rglob('*.py'):ast.parse(p.read_text(),filename=str(p))
 shutil.copytree(d/'fixtures',o/'fixtures');rows=[]
 for name,outname in [('system-controls','controls.S'),('migration-controls','migration.S')]:
  base=o/'fixtures'/name;args=['/usr/bin/python3.12','-B',str(base/'make_source.py')];c=subprocess.run(args,capture_output=True,timeout=10);(o/(name+'.stdout')).write_bytes(c.stdout);(o/(name+'.stderr')).write_bytes(c.stderr);assert c.returncode==0,(name,c.stderr)
  for n in(outname,'description.json'):assert (base/n).read_bytes()==(d/'fixtures'/name/n).read_bytes(),(name,n)
  rows.append(dict(argv=args,status=c.returncode,generated=[pin(base/n)for n in(outname,'description.json')]))
 r['generators']=rows
 helper=(d/'fixtures/system-controls/run.py').read_text().split('from pathlib import Path')[0];assert 'libc.prctl(1, signal.SIGKILL' in helper
 launcher=o/'owned-parent.py';launcher.write_text(helper+'''\nimport subprocess,sys,json\np=subprocess.Popen(['/usr/bin/python3.12','-c','import time; time.sleep(60)'],start_new_session=True,preexec_fn=_owned_parent_death)\nprint(json.dumps({'pid':p.pid,'start':open('/proc/%s/stat'%p.pid).read().split()[21]}),flush=True)\n''')
 c=subprocess.run(['/usr/bin/python3.12','-B',str(launcher)],capture_output=True,timeout=10);(o/'owned-parent.stdout').write_bytes(c.stdout);(o/'owned-parent.stderr').write_bytes(c.stderr);assert c.returncode==0,c.stderr;child=json.loads(c.stdout);state=None
 for _ in range(50):
  q=Path('/proc')/str(child['pid'])/'stat'
  if not q.exists():state='gone';break
  fields=q.read_text().split();assert fields[21]==child['start'];state=fields[2]
  if state=='Z':break
  time.sleep(.02)
 assert state in ('gone','Z'),state
 r['owned_parent_death']={'launcher':pin(launcher),'parent_status':c.returncode,'child':child,'final_state':state,'scope':'Only own non-QEMU sleeping Python child; no existing process signalled'};r['ok']=True
except Exception:
 import traceback;r['error']=traceback.format_exc()
r['recipes']=[pin(p)for p in d.rglob('*')if p.is_file()];r['controller']=pin(__file__);(o/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'result':pin(o/'result.json'),'ok':r['ok']}));raise SystemExit(0 if r['ok'] else 1)
