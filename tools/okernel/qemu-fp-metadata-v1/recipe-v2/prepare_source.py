"""Create a NEW exact original QEMU11.1.3 source tree and apply the pinned delta.

No download, install, existing tree writes, or original-source Git vendoring.
The sole absolute upstream EDK2 symlink is retained opaque, never traversed.
"""
from pathlib import Path
import argparse,hashlib,tarfile,os,stat,json,subprocess,sys
B=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();pins=json.loads((B/'pins.json').read_text())
def pin(p):d=Path(p).read_bytes();return dict(path=str(p),bytes=len(d),sha256=hashlib.sha256(d).hexdigest())
archive=pin(a.archive);assert archive['sha256']==pins['original_archive']['sha256']and archive['bytes']==pins['original_archive']['bytes'];assert pin(B/'qemu-fp-v1.patch')['sha256']==pins['patch']['sha256'];assert pin(B/'source-freeze.json')['sha256']==pins['source_freeze']['sha256'];a.output.mkdir();S=a.output/'qemu-11.1.3'
normalizations=[]
def filt(member,destination):
 try:
  filtered=tarfile.data_filter(member,destination)
  if member.issym()and filtered.linkname!=member.linkname:normalizations.append({'relative':member.name.split('/',1)[1],'archive_target':member.linkname,'extracted_target':filtered.linkname})
  return filtered
 except tarfile.AbsoluteLinkError:
  assert member.name=='qemu-11.1.3/roms/edk2/EmulatorPkg/Unix/Host/X11IncludeHack'and member.issym()and member.linkname=='/opt/X11/include'
  return member.replace(uid=None,gid=None,uname=None,gname=None)
with tarfile.open(a.archive,'r:xz')as t:t.extractall(a.output,filter=filt)
def scan():
 out=[]
 for root,dirs,files in os.walk(S,followlinks=False):
  for n in list(dirs):
   q=Path(root)/n
   if q.is_symlink():files.append(n);dirs.remove(n)
  for n in files:
   q=Path(root)/n;rel=q.relative_to(S).as_posix()
   if q.is_symlink():out.append(dict(relative=rel,symlink=os.readlink(q)))
   else:d=q.read_bytes();out.append(dict(relative=rel,bytes=len(d),sha256=hashlib.sha256(d).hexdigest(),mode=oct(stat.S_IMODE(q.stat().st_mode))))
 return sorted(out,key=lambda x:x['relative'])
assert sorted(normalizations,key=lambda x:x['relative'])==sorted([{k:v for k,v in x.items()if k in('relative','archive_target','extracted_target')}for x in pins['source_symlink_normalization']],key=lambda x:x['relative'])
base=scan();assert hashlib.sha256(json.dumps(base,sort_keys=True,separators=(',',':')).encode()).hexdigest()==pins['original_files_sha256'];(a.output/'original-source.json').write_text(json.dumps({'schema':'ostadix.original-release-inventory/v1','archive':archive,'files':base},indent=2)+'\n');env={k:v for k,v in os.environ.items()if not k.startswith('GIT_')};commands=[]
for argv in [['/usr/bin/git','apply','--check',str(B/'qemu-fp-v1.patch')],['/usr/bin/git','apply',str(B/'qemu-fp-v1.patch')]]:
 r=subprocess.run(argv,cwd=S,env=env,capture_output=True,timeout=30);commands.append(dict(argv=argv,status=r.returncode,stdout=r.stdout.decode(errors='replace'),stderr=r.stderr.decode(errors='replace')));assert r.returncode==0,commands[-1]
after=scan();bm={x['relative']:x for x in base};am={x['relative']:x for x in after};freeze=json.loads((B/'source-freeze.json').read_text());assert set(am)==set(bm);changed={n for n in bm if bm[n]!=am[n]};assert changed=={x['relative']for x in freeze['paths']}
for x in freeze['paths']:assert am[x['relative']]['sha256']==x['sha256']and am[x['relative']]['bytes']==x['bytes']
(a.output/'patched-source.json').write_text(json.dumps(after,indent=2)+'\n');(a.output/'result.json').write_text(json.dumps(dict(ok=True,source=str(S),archive=archive,patch=pin(B/'qemu-fp-v1.patch'),source_freeze=pin(B/'source-freeze.json'),original_inventory=pin(a.output/'original-source.json'),patched_inventory=pin(a.output/'patched-source.json'),commands=commands,symlink_normalization=normalizations,scope='Exactoriginalregularreleasebytes+specifieddata_filtersymlinktransforms+revieweddelta, not fullsourcebootstrappingofembeddedROMs ornewFPprofileadmission'),indent=2)+'\n');print(S)
