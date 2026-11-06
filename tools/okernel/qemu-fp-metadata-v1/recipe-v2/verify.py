"""Run fixed original-emulator fixtures in a fresh owned cache, one VM at a time.

This script does not install QEMU, alter any public tree, or touch existing VMs.
It copies the reviewed test programs/checkers, binds operator-selected tools,
and retains each generated controller so location edits are reviewable.
"""
from pathlib import Path
import argparse,os,json,hashlib,shutil,subprocess,sys,time,traceback
B=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--bin-dir',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--sdk',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--ovmf-code',type=Path,default=Path('/usr/share/OVMF/OVMF_CODE_4M.fd'));p.add_argument('--ovmf-vars',type=Path,default=Path('/usr/share/OVMF/OVMF_VARS_4M.fd'));p.add_argument('--only',choices=['pointer','system','all'],default='all');a=p.parse_args();a.output.mkdir();O=a.output.resolve();W=O/'work';shutil.copytree(B/'fixtures',W);N=W/'v1r6-bin';N.mkdir()
def pin(p):d=Path(p).read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
tools=[]
for n in('qemu-system-x86_64','qemu-x86_64','qemu-i386'):
 q=N/n;shutil.copyfile(a.bin_dir/n,q);q.chmod(0o555);tools.append(pin(q))
(W/'source').mkdir();(W/'source/qemu-11.1.3').symlink_to(a.source.resolve(),target_is_directory=True)
OLD='/home/ustad/.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin'
for q in W.rglob('*.py'):
 s=q.read_text().replace(OLD,str(a.sdk.resolve())).replace('/usr/share/OVMF/OVMF_CODE_4M.fd',str(a.ovmf_code.resolve())).replace('/usr/share/OVMF/OVMF_VARS_4M.fd',str(a.ovmf_vars.resolve()))
 if q==W/'pointer/run.py':
  s=s.replace("QEMU=Path('/home/ustad/.local/opt/qemu-11.1.3/bin/qemu-system-x86_64')","QEMU=Path("+repr(str(N/'qemu-system-x86_64'))+")");s=s.replace("EXPECTED_QEMU='72b4a0b1e1a47488bfce74843c5acf17ad1a8dadc1ff3c492b2b574f91f5f176'","EXPECTED_QEMU="+repr(tools[0]['sha256']));s=s.replace('Authored assembly EFI application on pinned installed QEMU/TCG only','Authored assembly EFI application on selected source-built QEMU/TCG only')
 q.write_text(s)
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',PYTHONPATH='');r={'ok':False,'controller':pin(__file__),'tools_before':tools,'generated_controllers':[pin(p)for p in W.rglob('*.py')],'commands':[],'scope':'Rebuildablefixed metadata/format/error/reset/migration fixtures; sourceprograms original/authoredasdeclared, no nativeFP orfullFPUadmission'}
fixture_inputs=[pin(p) for p in W.rglob('*') if p.is_file()]
r['fixture_inputs_before']=fixture_inputs
def save():(O/'result.json').write_text(json.dumps(r,indent=2)+'\n')
commands=[('pointer',[sys.executable,'-B',str(W/'pointer/run.py')],W/'pointer/attempt-5/result.json')]
if a.only!='pointer':commands.append(('system',[sys.executable,'-B',str(W/'system-controls/run.py'),'v1r6','final-r6-attempt-1'],W/'system-controls/final-r6-attempt-1/result.json'))
if a.only=='system':commands=commands[1:]
if a.only=='all':
 for name in('real-env-controls','xsave-controls','migration-controls'):commands.append((name,[sys.executable,'-B',str(W/name/'run.py'),'v1r6','final-r6-attempt-1'],W/name/'final-r6-attempt-1/result.json'))
 commands.append(('migration-stream-controls',[sys.executable,'-B',str(W/'migration-stream-controls/run_r6.py'),'final-r6-attempt-1'],W/'migration-stream-controls/final-r6-attempt-1/result.json'))
try:
 for n,argv,result in commands:
  start=time.monotonic();c=subprocess.run(argv,cwd=W,env=env,capture_output=True,timeout=360);(O/(n+'.stdout')).write_bytes(c.stdout);(O/(n+'.stderr')).write_bytes(c.stderr);x=json.loads(result.read_text())if result.is_file()else{};guard=(x.get('inputs_unchanged') is True) if n=='migration-stream-controls' else (x.get('sources_unchanged') is True and x.get('tools_unchanged') is True);okay=x.get('ok',x.get('conformance',x.get('isa_pointer_conformance',False))) and guard;r['commands'].append(dict(name=n,argv=argv,status=c.returncode,seconds=time.monotonic()-start,result=pin(result)if result.exists()else None,qualified=okay));save();assert c.returncode==0 and okay,(n,x.get('error'))
 r['ok']=True
except Exception as e:
 r['error']=repr(e);(O/'controller-error.log').write_text(traceback.format_exc())
finally:
 try:
  r['tools_after']=[pin(N/n)for n in('qemu-system-x86_64','qemu-x86_64','qemu-i386')];r['tools_unchanged']=r['tools_before']==r['tools_after'];r['fixture_inputs_after']=[pin(x['path']) for x in fixture_inputs];r['fixtures_unchanged']=fixture_inputs==r['fixture_inputs_after']
 except Exception as e:
  r['final_verification_error']=repr(e);r['tools_unchanged']=False;r['fixtures_unchanged']=False
 r['ok']=bool(r['ok'] and r['tools_unchanged'] and r['fixtures_unchanged'])
 if not r['ok'] and 'error' not in r:r['error']='Final tool stability verification failed'
 save()
print(json.dumps({'result':pin(O/'result.json'),'ok':r['ok']}))

sys.exit(0 if r['ok'] else 1)
