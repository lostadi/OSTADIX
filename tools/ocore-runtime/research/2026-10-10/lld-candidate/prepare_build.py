#!/usr/bin/env python3
"""Prepare only. No configure, compile, link, producer or importer execution."""
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
R=Path(__file__).resolve().parent
SRC=Path.home()/'.cache/ostadix-runtime-sources/rust-8bab26f4/src/llvm-project'
CACHE=Path.home()/'.cache/ostadix-research/rust-producer-native-link-build-8z2gyi1q/build/bootstrap/x86_64-unknown-linux-gnu/llvm'
SDK=Path.home()/'.cache/ostadix-toolchains/llvm-22.1.6/sdk/LLVM-22.1.6-Linux-X64/bin'
B=R/'private-build'; S=B/'source'; P=B/'llvm-prefix'
def info(p):
 p=Path(p);d=p.read_bytes();return {'path':str(p.absolute()),'resolved_path':str(p.resolve()),'sha256':hashlib.sha256(d).hexdigest(),'bytes':len(d)}
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def cache(p):
 out={}
 for line in p.read_text().splitlines():
  if line.startswith(('#','//')) or ':' not in line or '=' not in line:continue
  left,value=line.split('=',1);name,kind=left.split(':',1);out[name]=(kind,value)
 return out
base=json.loads((R/'evidence/original-source.json').read_text())
assert subprocess.check_output(['git','-C',str(SRC),'rev-parse','HEAD'],text=True).strip()==base['source_revision']
assert not subprocess.check_output(['git','-C',str(SRC),'status','--porcelain'],text=True)
for row in base['files']:
 assert info(row['path'])['sha256']==row['sha256']
B.mkdir(exist_ok=True)
if not S.exists():
 subprocess.run(['/usr/bin/cp','-a','--reflink=auto',str(SRC),str(S)],check=True)
 # The original submodule .git locator points outside this copy. Never retain it
 # as mutable Git identity; the source-tree byte manifest binds the full copy.
 (S/'.git').unlink()
assert not (S/'.git').exists()
source_rows=[]
for src in sorted(SRC.rglob('*')):
 rel=src.relative_to(SRC)
 if rel.parts[0]=='.git' or src.is_dir():continue
 dst=S/rel
 if src.is_symlink():
  assert dst.is_symlink() and os.readlink(src)==os.readlink(dst)
  source_rows.append({'relative':str(rel),'symlink':os.readlink(src)});continue
 assert src.is_file() and dst.is_file() and src.stat().st_ino!=dst.stat().st_ino
 orig=info(src);copy=info(dst);assert orig['sha256']==copy['sha256']
 source_rows.append({'relative':str(rel),'original':orig,'copy':copy})
dump(R/'evidence/private-original-source-tree.json',{'schema':'ocore-private-original-source-copy-v1','original':str(SRC),'private':str(S),'source_revision':base['source_revision'],'files':source_rows,'distinct_file_inodes':True})
# Only this private full source copy receives the sealed selected modifications.
for p in sorted((R/'stage').rglob('*')):
 if p.is_file():
  dst=S/p.relative_to(R/'stage');dst.parent.mkdir(parents=True,exist_ok=True)
  dst.write_bytes(p.read_bytes())
if not P.exists():
 P.mkdir()
 for component in ['bin','include','lib','share']:
  subprocess.run(['/usr/bin/cp','-a','--reflink=auto',str(CACHE/component),str(P/component)],check=True)
package_rows=[]
for src in sorted(CACHE.rglob('*')):
 rel=src.relative_to(CACHE)
 if rel.parts[0] not in ('bin','include','lib','share') or src.is_dir():continue
 dst=P/rel
 if src.is_symlink():
  assert dst.is_symlink() and os.readlink(src)==os.readlink(dst)
  package_rows.append({'relative':str(rel),'symlink':os.readlink(src)});continue
 assert src.is_file() and dst.is_file() and src.stat().st_ino!=dst.stat().st_ino
 orig=info(src);copy=info(dst);assert orig['sha256']==copy['sha256']
 package_rows.append({'relative':str(rel),'original':orig,'copy':copy})
dump(R/'evidence/private-original-llvm-prefix.json',{'schema':'ocore-private-original-llvm-prefix-v1','original':str(CACHE),'private':str(P),'files':package_rows,'distinct_file_inodes':True,'libraries_rebuilt':False})
llvm_cache=cache(CACHE/'build/CMakeCache.txt')
lld_cache=cache(CACHE.parent/'lld/build/CMakeCache.txt')
# Preserve original non-internal feature settings. All compiler/build/source
# paths are explicit private/direct overrides, not historical capture wrappers.
opts={n:v for n,(t,v) in llvm_cache.items() if n.startswith('LLVM_') and t!='INTERNAL' and not n.startswith(('LLVM_EXTERNAL_','LLVM_TOOL_')) and n not in ('LLVM_BINARY_DIR','LLVM_IS_TOP_LEVEL','LLVM_MAIN_SRC_DIR','LLVM_NATIVE_TOOL_DIR')}
opts.update({'CMAKE_BUILD_TYPE':'Release','CMAKE_C_COMPILER':str(SDK/'clang'),'CMAKE_CXX_COMPILER':str(SDK/'clang++'),'CMAKE_ASM_COMPILER':str(SDK/'clang'),'CMAKE_INSTALL_PREFIX':str(P),'CMAKE_EXPORT_COMPILE_COMMANDS':'ON','CMAKE_AR':str(SDK/'llvm-ar'),'CMAKE_RANLIB':str(SDK/'llvm-ranlib'),'CMAKE_EXE_LINKER_FLAGS':llvm_cache['CMAKE_EXE_LINKER_FLAGS'][1],'CMAKE_SHARED_LINKER_FLAGS':llvm_cache['CMAKE_SHARED_LINKER_FLAGS'][1],'CMAKE_CXX_FLAGS':llvm_cache['CMAKE_CXX_FLAGS'][1],'CMAKE_C_FLAGS':llvm_cache['CMAKE_C_FLAGS'][1],'CMAKE_ASM_FLAGS':llvm_cache['CMAKE_ASM_FLAGS'][1]})
# Existing source-generated commands are not reused. Building Support alone
# leaves all cached target codegenerators present and unmodified in the prefix.
llvm_cmd=['/usr/bin/cmake','-S',str(S/'llvm'),'-B',str(B/'support-build'),'-G','Ninja']+[f'-D{k}={v}' for k,v in sorted(opts.items())]
lld_opts={n:v for n,(t,v) in lld_cache.items() if n.startswith('LLD_') and t!='INTERNAL'}
lld_opts.update({'CMAKE_BUILD_TYPE':'Release','CMAKE_C_COMPILER':str(SDK/'clang'),'CMAKE_CXX_COMPILER':str(SDK/'clang++'),'CMAKE_INSTALL_PREFIX':str(B/'lld-install'),'LLVM_DIR':str(P/'lib/cmake/llvm'),'LLVM_MAIN_SRC_DIR':str(S/'llvm'),'LLVM_INCLUDE_TESTS':lld_cache['LLVM_INCLUDE_TESTS'][1],'CMAKE_EXPORT_COMPILE_COMMANDS':'ON','CMAKE_AR':str(SDK/'llvm-ar'),'CMAKE_RANLIB':str(SDK/'llvm-ranlib'),'CMAKE_EXE_LINKER_FLAGS':lld_cache['CMAKE_EXE_LINKER_FLAGS'][1],'CMAKE_SHARED_LINKER_FLAGS':lld_cache['CMAKE_SHARED_LINKER_FLAGS'][1],'CMAKE_CXX_FLAGS':lld_cache['CMAKE_CXX_FLAGS'][1],'CMAKE_C_FLAGS':lld_cache['CMAKE_C_FLAGS'][1]})
lld_cmd=['/usr/bin/cmake','-S',str(S/'lld'),'-B',str(B/'lld-build'),'-G','Ninja']+[f'-D{k}={v}' for k,v in sorted(lld_opts.items())]
plan={'schema':'ocore-original-lld-hook-build-plan-v1','source_revision':base['source_revision'],'source_tree':info(R/'evidence/private-original-source-tree.json'),'llvm_prefix':info(R/'evidence/private-original-llvm-prefix.json'),'source_patch':info(R/'evidence/original-lld22-native-link-capture.patch'),'original_llvm_cache':info(CACHE/'build/CMakeCache.txt'),'original_lld_cache':info(CACHE.parent/'lld/build/CMakeCache.txt'),'tools':{n:info(p) for n,p in {'cmake':Path('/usr/bin/cmake'),'ninja':Path('/usr/bin/ninja'),'clang':SDK/'clang','clangxx':SDK/'clang++','lld':SDK/'ld.lld','ar':SDK/'llvm-ar','ranlib':SDK/'llvm-ranlib'}.items()},'configure_support':llvm_cmd,'build_support':['/usr/bin/cmake','--build',str(B/'support-build'),'--target','LLVMSupport','LLVMDemangle','--parallel','2'],'configure_lld':lld_cmd,'build_lld':['/usr/bin/cmake','--build',str(B/'lld-build'),'--target','lld','--parallel','2'],'environment':{'PATH':str(SDK)+':/usr/bin:/bin','LD_LIBRARY_PATH':str(SDK.parent.parent/'compat/root/usr/lib/x86_64-linux-gnu')},'support_archive_replacements':['lib/libLLVMSupport.a','lib/libLLVMDemangle.a'],'required_generated_config_identity':['llvm/Config/llvm-config.h','llvm/Config/abi-breaking.h','llvm/Config/Targets.def','llvm/Config/AsmParsers.def','llvm/Config/AsmPrinters.def','llvm/Config/Disassemblers.def'],'source_hook_build_attempted':False,'original_source_mutated':False,'original_v3_mutated':False,'compiler_feature_disabled':False,'full_original_compiler_lowered':False}
# Compatibility libraries live beside sdk/ rather than under its parent llvm-22.
plan['environment']['LD_LIBRARY_PATH']=str(SDK.parents[2]/'compat/root/usr/lib/x86_64-linux-gnu')
dump(R/'evidence/build-plan.json',plan)
print(json.dumps({'private_source':str(S),'private_prefix':str(P),'source_files':len(source_rows),'prefix_files':len(package_rows),'plan':info(R/'evidence/build-plan.json'),'build_attempted':False}))
