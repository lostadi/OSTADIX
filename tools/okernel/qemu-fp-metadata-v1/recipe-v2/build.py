"""Offline three-target QEMU recipe using only wheels in the original release.

A source tree is supplied separately and verified against the complete original
release inventory plus exact reviewed replacement bytes. Host compiler/headers/
libraries remain explicit dependencies, not a hermetic whole-toolchain claim.
"""
from pathlib import Path,PurePosixPath
import os,sys,argparse,json,hashlib,subprocess,time,shutil,zipfile,stat,traceback,shlex
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--base-manifest',type=Path,required=True);p.add_argument('--freeze',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--prefix',type=Path,required=True);a=p.parse_args();S=a.source.resolve();O=a.output.resolve();O.mkdir();D=O/'build';D.mkdir();T=O/'python-tools';T.mkdir()
def pin(p):p=Path(p);d=p.read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
def scan():
 rows=[]
 for root,dirs,files in os.walk(S,followlinks=False):
  for n in list(dirs):
   pp=Path(root)/n
   if pp.is_symlink():files.append(n);dirs.remove(n)
  for n in files:
   pp=Path(root)/n;rel=pp.relative_to(S).as_posix()
   if pp.is_symlink():rows.append(dict(relative=rel,symlink=os.readlink(pp)))
   else:
    d=pp.read_bytes();rows.append(dict(relative=rel,bytes=len(d),sha256=hashlib.sha256(d).hexdigest(),mode=oct(stat.S_IMODE(pp.stat().st_mode))))
 return sorted(rows,key=lambda r:r['relative'])
R={'ok':False,'schema':'ostadix.private-original-qemu-offline-build/v1','scope':'Original-release-wheel offline dependency closure, exactsource/config/toolpins; hostCtoolchain remainsrequired; no nativeFP/fullFPU admission','controller':pin(__file__),'base_manifest':pin(a.base_manifest),'source_freeze':pin(a.freeze),'commands':[],'tools_before':[pin('/usr/bin/'+n)for n in('gcc','g++','ninja','python3.12','pkg-config','ar','ld')],'prefix':str(a.prefix),'build':str(D)}
def save():(O/'result.json').write_text(json.dumps(R,indent=2)+'\n')
rows = None
def run(n,argv,timeout=60):
 argv=list(map(str,argv));start=time.monotonic()
 with(O/(n+'.stdout')).open('wb')as so,(O/(n+'.stderr')).open('wb')as se:r=subprocess.run(argv,cwd=D,env=env,stdout=so,stderr=se,timeout=timeout)
 R['commands'].append(dict(name=n,argv=argv,exit_code=r.returncode,seconds=time.monotonic()-start,stdout=pin(O/(n+'.stdout')),stderr=pin(O/(n+'.stderr'))));save();assert r.returncode==0,n
try:
 base=json.loads(a.base_manifest.read_text());freeze=json.loads(a.freeze.read_text());pins=json.loads((Path(__file__).resolve().parent/'pins.json').read_text());assert pin(a.freeze)['sha256']==pins['source_freeze']['sha256'];assert hashlib.sha256(json.dumps(base['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==pins['original_files_sha256'];rows=scan();(O/'source-before.json').write_text(json.dumps(rows,indent=2)+'\n');R['fullsource_before']=pin(O/'source-before.json');bm={x['relative']:x for x in base['files']};now={x['relative']:x for x in rows};changed=[n for n in bm if now.get(n)!=bm[n]];assert set(now)==set(bm);assert set(changed)=={x['relative']for x in freeze['paths']},changed
 for x in freeze['paths']:assert now[x['relative']]['sha256']==x['sha256']and now[x['relative']]['bytes']==x['bytes']
 R['fullsource_before']=pin(O/'source-before.json');R['changed_paths']=changed
 wheels=sorted((S/'python/wheels').glob('*.whl'));assert {x.name for x in wheels}=={'meson-1.11.1-py3-none-any.whl','pycotap-1.3.1-py3-none-any.whl','qemu_qmp-0.0.6-py3-none-any.whl'};R['release_wheels']=[pin(w)for w in wheels];inventory=[]
 for w in wheels:
  with zipfile.ZipFile(w)as z:
   for info in z.infolist():
    rel=PurePosixPath(info.filename);assert not rel.is_absolute()and'..'not in rel.parts;assert not stat.S_ISLNK(info.external_attr>>16);dest=T/rel
    if info.is_dir():dest.mkdir(parents=True,exist_ok=True);continue
    d=z.read(info);dest.parent.mkdir(parents=True,exist_ok=True);assert not dest.exists();dest.write_bytes(d);inventory.append(dict(relative=str(rel),bytes=len(d),sha256=hashlib.sha256(d).hexdigest(),original_wheel=w.name))
 (O/'python-tools-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n');R['python_tools_inventory']=pin(O/'python-tools-inventory.json')
 env={k:v for k,v in os.environ.items()if k not in('CFLAGS','CXXFLAGS','CPPFLAGS','LDFLAGS','LD_LIBRARY_PATH','LIBRARY_PATH','CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','PKG_CONFIG_PATH','PKG_CONFIG_LIBDIR','RUSTFLAGS','RUSTC','CARGO_TARGET_DIR','PYTHONPATH','PYTHONHOME')};env.update(PATH='/usr/bin:/bin',CC='/usr/bin/gcc',CXX='/usr/bin/g++',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',PYTHONPATH=str(T),PIP_NO_INDEX='1',PIP_DISABLE_PIP_VERSION_CHECK='1');R['environment']={k:env[k]for k in('PATH','CC','CXX','LC_ALL','PYTHONDONTWRITEBYTECODE','PYTHONNOUSERSITE','PYTHONPATH','PIP_NO_INDEX','PIP_DISABLE_PIP_VERSION_CHECK')}
 for n in('gcc','ninja','python3.12','pkg-config'):run(n+'-version',['/usr/bin/'+n,'--version'])
 run('configure',[S/'configure','--prefix='+str(a.prefix),'--target-list=x86_64-softmmu,x86_64-linux-user,i386-linux-user','--disable-download','--disable-debug-info','--disable-werror','--disable-docs','--disable-rust','--disable-gtk','--disable-sdl','--disable-vnc','--disable-spice','--disable-slirp','--disable-curl','--disable-libnfs','--disable-guest-agent','--disable-tools','--disable-plugins','--python=/usr/bin/python3.12'],180)
 run('compile',['/usr/bin/ninja','-j2','qemu-system-x86_64','qemu-x86_64','qemu-i386'],1200)
 run('actual-selected-command-graph',['/usr/bin/ninja','-t','commands','qemu-system-x86_64','qemu-x86_64','qemu-i386']);commands=json.loads((D/'compile_commands.json').read_text());selected=[x for x in commands if x['file'].endswith('/target/i386/tcg/fpu_helper.c')];assert len(selected)==3
 for x in selected:assert not any(t.startswith('-g')and t!='-g0'for t in shlex.split(x['command']))
 (O/'fpu-compiler-commands.json').write_text(json.dumps(selected,indent=2)+'\n');R['actual_fpu_flags']=pin(O/'fpu-compiler-commands.json');N=O/'bin';N.mkdir()
 for n in('qemu-system-x86_64','qemu-x86_64','qemu-i386'):shutil.copyfile(D/n,N/n);(N/n).chmod(0o555)
 R['binaries']=[pin(N/n)for n in('qemu-system-x86_64','qemu-x86_64','qemu-i386')];R['ok']=True
except Exception as e:R['error']=repr(e);(O/'controller-error.log').write_text(traceback.format_exc())
finally:
 try:
  after=scan();(O/'source-after.json').write_text(json.dumps(after,indent=2)+'\n');R['fullsource_after']=pin(O/'source-after.json')
  beforemap={x['relative']:x for x in rows} if rows is not None else None
  aftermap={x['relative']:x for x in after}
  R['original_source_entries_unchanged']=beforemap is not None and all(aftermap.get(n)==v for n,v in beforemap.items())
  R['generated_added_paths']=[x for x in after if beforemap is None or x['relative'] not in beforemap]
  R['sources_unchanged']=R['original_source_entries_unchanged'] and all(x['relative']=='subprojects/.wraplock' and x.get('bytes')==0 for x in R['generated_added_paths'])
  R['tools_after']=[pin('/usr/bin/'+n)for n in('gcc','g++','ninja','python3.12','pkg-config','ar','ld')]
  R['tools_unchanged']=R['tools_before']==R['tools_after']
 except Exception as e:
  R['final_verification_error']=repr(e);R['sources_unchanged']=False;R['tools_unchanged']=False
 R['ok']=bool(R['ok'] and R['sources_unchanged'] and R['tools_unchanged'])
 if not R['ok'] and 'error' not in R:
  R['error']='Final source/tool stability verification failed'
 save()
print(json.dumps({'result':pin(O/'result.json'),'ok':R['ok'],'error':R.get('error'),'sources_unchanged':R['sources_unchanged']}))

sys.exit(0 if R['ok'] else 1)
