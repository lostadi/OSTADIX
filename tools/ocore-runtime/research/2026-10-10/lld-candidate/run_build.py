#!/usr/bin/env python3
"""Root-executed original LLD hook build. Preparation never runs a compiler.

Private files only; direct pinned SDK tools; no legacy capture environment.
Each real command/status/log is retained and a failure stops this attempt.
"""
import argparse,hashlib,json,os,shutil,subprocess,time
from pathlib import Path
R=Path(__file__).resolve().parent
B=R/'private-build';S=B/'source';P=B/'llvm-prefix'
def info(p):
 p=Path(p);d=p.read_bytes();return {'path':str(p.absolute()),'resolved_path':str(p.resolve()),'sha256':hashlib.sha256(d).hexdigest(),'bytes':len(d)}
def checked(row):
 got=info(row['path']);assert got['sha256']==row['sha256'] and got['bytes']==row['bytes'],row['path']
 return Path(row['path'])
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def macros(p):
 # Preserve generated ABI/feature definitions, ignoring descriptive comments.
 return [x.rstrip() for x in p.read_text().splitlines() if x.startswith(('#define ','#undef '))]
def main():
 a=argparse.ArgumentParser();a.add_argument('--execute',action='store_true');args=a.parse_args()
 plan_ref=info(R/'evidence/build-plan.json');plan=json.loads(checked(plan_ref).read_bytes())
 if not args.execute:
  print(json.dumps({'plan':plan_ref,'commands':[plan[k] for k in ('configure_support','build_support','configure_lld','build_lld')],'execution_requested':False},indent=2));return
 for row in plan['tools'].values():checked(row)
 checked(plan['source_tree']);checked(plan['llvm_prefix']);checked(plan['source_patch'])
 static=json.loads((R/'evidence/static-checks.json').read_bytes())
 for row in static['source_files']:
  got=info(S/row['relative']);assert got['sha256']==row['sha256'],row['relative']
 prefix=json.loads(checked(plan['llvm_prefix']).read_bytes())
 for row in prefix['files']:
  if 'copy' in row:checked(row['copy'])
  else:assert os.readlink(P/row['relative'])==row['symlink']
 orig=json.loads((R/'evidence/original-source.json').read_bytes())
 for row in orig['files']:checked(row)
 env={'HOME':str(Path.home()),'USER':os.environ.get('USER','ustad'),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8',**plan['environment']}
 attempt=R/'evidence'/('build-attempt-'+str(time.time_ns()));attempt.mkdir()
 record={'schema':'ocore-original-lld-hook-build-attempt-v1','plan':plan_ref,'runner':info(__file__),'environment':env,'steps':[],'source_hook_build_passed':False,'source_hook_executed':False,'ocore_lowering_complete':False,'runtime_complete':False}
 def run(name,argv):
  log=attempt/(name+'.log');start=time.time_ns()
  with log.open('wb') as out:result=subprocess.run(argv,cwd=B,env=env,stdout=out,stderr=subprocess.STDOUT)
  step={'name':name,'argv':argv,'cwd':str(B),'started_ns':start,'finished_ns':time.time_ns(),'returncode':result.returncode,'log':info(log)};record['steps'].append(step);dump(attempt/'receipt.json',record)
  print(json.dumps(step),flush=True)
  if result.returncode:raise RuntimeError(f'original build command failed: {name}; retained {log}')
 run('configure-support',plan['configure_support'])
 # Standalone LLD will use old immutable target libraries with new Support.
 # Reject changed configuration macros before mixing these artifacts.
 comparisons=[]
 for rel in plan['required_generated_config_identity']:
  old=P/'include'/rel;new=B/'support-build/include'/rel
  equal=macros(old)==macros(new) if old.suffix=='.h' else old.read_bytes()==new.read_bytes()
  comparisons.append({'relative':rel,'original':info(old),'fresh':info(new),'equal_contract':equal})
  assert equal,('generated LLVM contract mismatch',rel)
 old_config=Path(plan['original_llvm_cache']['path']).parent/'include/llvm/Config/config.h'
 new_config=B/'support-build/include/llvm/Config/config.h'
 comparisons.append({'relative':'internal llvm/Config/config.h','original':info(old_config),'fresh':info(new_config),'equal_contract':macros(old_config)==macros(new_config)})
 assert comparisons[-1]['equal_contract'],'internal LLVM feature configuration changed'
 record['generated_contract_checks']=comparisons;dump(attempt/'receipt.json',record)
 run('build-support',plan['build_support'])
 replacements=[]
 for rel in plan['support_archive_replacements']:
  new=B/'support-build'/rel;old=P/rel
  replacements.append({'relative':rel,'before':info(old),'rebuilt':info(new)})
  shutil.copy2(new,old);replacements[-1]['installed']=info(old)
 header=S/'llvm/include/llvm/Support/CommandLine.h';shutil.copy2(header,P/'include/llvm/Support/CommandLine.h')
 record['coherent_support_replacements']=replacements;record['installed_changed_header']=info(P/'include/llvm/Support/CommandLine.h')
 dump(attempt/'receipt.json',record)
 run('configure-lld',plan['configure_lld'])
 run('build-lld',plan['build_lld'])
 # The new LLD image is unexecuted here. Registering or testing it is a later
 # original-link gate; source build success never fills driver/provider gaps.
 image=B/'lld-build/bin/lld'
 record['built_lld_image']=info(image)
 record['link_artifacts']={name:info(B/'lld-build'/name) for name in ('lib/liblldELF.a','lib/liblldCommon.a')}
 record['generated_build_files']={name:info(B/name) for name in ('support-build/CMakeCache.txt','support-build/build.ninja','support-build/compile_commands.json','lld-build/CMakeCache.txt','lld-build/build.ninja','lld-build/compile_commands.json')}
 unchanged=[]
 replacements=set(plan['support_archive_replacements'])|{'include/llvm/Support/CommandLine.h'}
 for row in prefix['files']:
  if 'copy' not in row or row['relative'] in replacements:continue
  got=info(P/row['relative']);assert got['sha256']==row['copy']['sha256'],row['relative'];unchanged.append(got)
 record['retained_unchanged_package_artifacts']=unchanged
 for row in orig['files']:checked(row)
 record['source_hook_build_passed']=True;record['original_source_selected_files_unchanged']=True
 dump(attempt/'receipt.json',record);print(json.dumps({'receipt':info(attempt/'receipt.json'),'source_hook_build_passed':True,'source_hook_execution_qualified':False}),flush=True)
if __name__=='__main__':main()
