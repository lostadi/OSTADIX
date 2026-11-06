"""Versioned source-metadata identity, raw diagnostics and strict readmission.

The authored LLVM fixture tests compiler-only metadata preservation. The optional
original-source lane uses retained actual frontend units and never retargets
those units or qualifies their unresolved libc/platform closure.
"""
import copy,hashlib,importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(os.environ.get('OCORE_METADATA_ROOT',Path(__file__).resolve().parents[1]))
PROFILES={'x86_64':('x86_64-unknown-linux-musl','e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128'),
'aarch64':('aarch64-unknown-linux-musl','e-m:e-p270:32:32-p271:32:32-p272:64:64-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32'),
'riscv64':('riscv64-unknown-linux-musl','e-m:e-p:64:64-i64:64-i128:128-n32:64-S128')}
BODY=r'''
declare void @llvm.experimental.noalias.scope.decl(metadata)
define i64 @probe(ptr %p) {
entry:
 call void @llvm.experimental.noalias.scope.decl(metadata !3), !noalias !4, !alias.scope !3
 %a = load i64, ptr %p, align 8, !noalias !4, !alias.scope !5
 call void @llvm.experimental.noalias.scope.decl(metadata !6)
 %b = load i64, ptr %p, align 8, !alias.scope !3, !noalias !4
 %sum = add i64 %a, %b
 ret i64 %sum
}
!0 = distinct !{!0, !"domain\00\FF<0x1234>"}
!1 = distinct !{!1, !0, !"same"}
!2 = distinct !{!2, !0, !"same"}
!3 = !{!1}
!4 = !{!2, !1, !2, !8}
!5 = !{!1}
!6 = !{!2}
!8 = !{!"identity\00\FE", !0, !""}
'''
def pin(path):
 p=Path(path);raw=p.read_bytes();return {'path':str(p.resolve()),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def write(path,data):path.write_text(json.dumps(data,indent=2)+'\n')
def differences(a,b,path=()):
 if type(a)!=type(b):return [path]
 if isinstance(a,dict):
  if set(a)!=set(b):return [path]
  return [q for k in a for q in differences(a[k],b[k],path+(k,))]
 if isinstance(a,list):
  if len(a)!=len(b):return [path]
  return [q for i,(x,y) in enumerate(zip(a,b)) for q in differences(x,y,path+(i,))]
 return [] if a==b else [path]
class MetadataGraphSourceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.core=Path(os.environ.get('OCOREC_BIN',ROOT/'target/debug/ocorec'))
  cls.lib=Path(os.environ['OCORE_METADATA_LLVM_LIBRARY']);cls.libpin=pin(cls.lib)
  cls.sdk=Path(os.environ['OCORE_METADATA_LLVM_BIN']);cls.env=dict(os.environ,PATH=str(cls.sdk)+':'+os.environ['PATH'],PYTHONDONTWRITEBYTECODE='1')
  cls.before=[pin(p) for p in [cls.core,cls.lib,cls.sdk/'llvm-as',ROOT/'scripts/ocore_llvm_import.py',ROOT/'src/bin/olangc/native_runtime/source_inventory.py']]
  selected=os.environ.get('OCORE_METADATA_TEST_OUTPUT')
  cls.tmp=None
  if selected:cls.out=Path(selected);cls.out.mkdir(parents=True,exist_ok=False)
  else:cls.tmp=tempfile.TemporaryDirectory(prefix='ocore-metadata-graph-');cls.out=Path(cls.tmp.name)
  cls.commands=[]
  help_=cls.command([cls.core,'--help'],'capability')
  if b'--llvm-metadata-diagnostics' not in help_.stdout.split():raise AssertionError('selected compiler must be rebuilt with metadata graph support')
  catalog=json.loads(cls.command([cls.core,'--list-targets'],'catalog').stdout)
  assert {x['target'] for x in catalog['targets']}=={isa+'-unknown-none' for isa in PROFILES},'missing implemented ISA source-metadata gate'
  helper=Path(os.environ.get('OCORE_METADATA_ORACLE',Path(__file__).with_name('ocore_metadata_graph_oracle.py')))
  spec=importlib.util.spec_from_file_location('independent_graph_oracle',helper);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);cls.oracle=m.GraphOracle(cls.lib)
  cls.cache={}
 @classmethod
 def tearDownClass(cls):
  write(cls.out/'commands.json',cls.commands)
  after=[pin(x['path']) for x in cls.before]
  assert after==cls.before,'source/tool bytes changed during graph tests'
  write(cls.out/'tools.json',{'before':cls.before,'after':after})
  files=[pin(p) for p in cls.out.rglob('*') if p.is_file()]
  write(cls.out/'inventory.json',files)
  if cls.tmp:cls.tmp.cleanup()
 @classmethod
 def command(cls,argv,label,success=True,environment=None):
  n=len(cls.commands);p=subprocess.run([str(x) for x in argv],env=cls.env if environment is None else environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  out=cls.out/f'{n:04}-{label}.stdout';err=cls.out/f'{n:04}-{label}.stderr';out.write_bytes(p.stdout);err.write_bytes(p.stderr)
  cls.commands.append({'argv':[str(x) for x in argv],'exit':p.returncode,'stdout':pin(out),'stderr':pin(err)})
  if success and p.returncode:raise AssertionError(f'command failed {p.returncode}: {argv}\n{p.stderr.decode(errors="replace")}')
  return p
 @classmethod
 def import_(cls,path,isa,label,success=True):
  dest=cls.out/(label+'.native-ir.json');diag=cls.out/(label+'.raw.json')
  q=cls.command([cls.core,path,'--input-kind','llvm-ir','--emit','mir','--target',isa+'-unknown-none','--llvm-library',cls.lib,'--llvm-sha256',cls.libpin['sha256'],'--llvm-metadata-diagnostics',diag,'-o',dest],label,success)
  return q,dest,diag
 @classmethod
 def verify(cls,path,label,success=True):
  receipt=cls.out/(label+'.verification.json')
  q=cls.command([cls.core,path,'--input-kind','native-ir','--verify-native','--receipt',receipt],label,success)
  if not success and q.returncode==0:raise AssertionError('forged inconsistent module verified')
  if not success:assert not receipt.exists()
  return q
 @classmethod
 def fixture(cls,isa='x86_64'):
  if isa not in cls.cache:
   triple,layout=PROFILES[isa];ll=cls.out/(isa+'-fixture.ll')
   ll.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n'+BODY)
   _,module,diag=cls.import_(ll,isa,isa+'-fixture')
   cls.verify(module,isa+'-fixture')
   cls.cache[isa]=(ll,module,diag)
  return cls.cache[isa]
 @classmethod
 def readmit(cls,original,claimed,isa,label,success):
  module=json.loads(Path(claimed).read_text());request=cls.out/(label+'.request.json');toolfile=cls.out/(label+'.tools.json')
  write(request,{'schema':'ocore-original-unit-readmission-request-v1','unit_id':label,'original_unit':{'id':label,'llvm_ir':pin(original)},'claimed_module':pin(claimed),'target':{'target':isa+'-unknown-none','native_target':module['target'],'import_profiles':{}}})
  write(toolfile,{'schema':'ocore-original-runtime-toolchain-v1','tools':{'ocorec':pin(cls.core),'llvm_library':cls.libpin,'inventory_helper':pin(ROOT/'src/bin/olangc/native_runtime/source_inventory.py')},'environment':{'PATH':cls.env['PATH'],'PYTHONDONTWRITEBYTECODE':'1'}})
  out=cls.out/(label+'-readmission')
  q=cls.command(['/usr/bin/python3','-I',ROOT/'tools/ocore-runtime/acceptance/check_runtime.py','readmit-unit',request,'--tools',toolfile,'--output',out],label,success)
  report=json.loads((out/'report.json').read_text())
  assert report['runtime_accepted'] is False and report['complete'] is False
  if success:
   assert q.returncode==0 and report['unit_readmission_complete'] is True
  else:
   assert q.returncode!=0 and report['unit_readmission_complete'] is False
   body=json.loads((out/'unit/readmission.json').read_text());assert body['same_typed_module'] is False
  return report,out
 def test_actual_original_profiles_text_and_bitcode_repeat_and_readmit(self):
  casefile=os.environ.get('OCORE_METADATA_ORIGINAL_CASES')
  if not casefile:self.skipTest('retained upstream source/capture profile not selected; no original-runtime qualification')
  cases=json.loads(Path(casefile).read_text())['cases'];self.assertEqual(len(cases),6)
  self.assertEqual({(x['isa'],x['format']) for x in cases},{(i,f) for i in PROFILES for f in ['llvm-text','derived-bitcode']})
  for i,case in enumerate(cases):
   with self.subTest(isa=case['isa'],format=case['format']):
    path=Path(case['input']['path']);self.assertEqual(pin(path),case['input'])
    self.assertEqual(pin(case['original_source']['path']),case['original_source'])
    outputs=[]
    for n in [1,2]:
     _,module,diag=self.import_(path,case['isa'],f'original-{i}-{n}');self.verify(module,f'original-{i}-{n}');outputs.append(module)
     data=json.loads(module.read_text());self.assertEqual(data['target']['triple'],case['original_capture_input']['target_triple']);self.assertEqual(data['target']['data_layout'],case['original_capture_input']['data_layout'])
     self.check_oracle(path,data,json.loads(diag.read_text()))
    self.assertEqual(outputs[0].read_bytes(),outputs[1].read_bytes())
    self.readmit(path,outputs[0],case['isa'],f'original-{i}-green',True)
 def check_oracle(self,path,module,diag):
  graph=module['provenance']['noalias_metadata_graph_source'];observed=self.oracle.read(path)
  self.assertEqual(graph['nodes'],observed['nodes']);self.assertEqual(graph['roots'],observed['roots'])
  self.assertEqual(module['provenance']['noalias_metadata_source'],[])
  self.assertEqual(diag['graph_source'],graph);self.assertTrue(diag['import_complete']);self.assertEqual(diag['input_sha256'],pin(path)['sha256']);self.assertEqual(diag['input_bytes'],pin(path)['bytes'])
  bindings={x['alias_id']:x['node'] for x in graph['alias_bindings']};self.assertEqual(len(set(bindings.values())),len(bindings))
  tuples={x['id']:x for x in graph['nodes'] if x['kind']=='tuple'};self.assertEqual(set(bindings.values()),set(tuples))
  self.assertEqual({x['id'] for x in diag['alias_nodes']},set(bindings));self.assertEqual(len(diag['alias_nodes']),len(bindings))
  for raw in diag['alias_nodes']:
   self.assertEqual(raw['metadata_kind'],4);text=bytes(raw['printer_bytes']);self.assertEqual(hashlib.sha256(text).hexdigest(),raw['printer_sha256'])
   body=text.partition(b' = ')[2];prefix=b'distinct !{' if tuples[bindings[raw['id']]]['storage']=='distinct' else b'!{';self.assertTrue(body.startswith(prefix))
 def test_independent_oracle_binary_strings_cycles_sharing_and_source_order(self):
  for isa in PROFILES:
   ll,module,diag=self.fixture(isa);bc=self.out/(isa+'-fixture.bc');self.command([self.sdk/'llvm-as',ll,'-o',bc],isa+'-serialize')
   for fmt,path in [('ll',ll),('bc',bc)]:
    with self.subTest(isa=isa,format=fmt):
     outputs=[]
     for n in [1,2]:
      _,mod,raw=self.import_(path,isa,f'authored-{isa}-{fmt}-{n}');self.verify(mod,f'authored-{isa}-{fmt}-{n}');outputs.append(mod)
      data=json.loads(mod.read_text());self.check_oracle(path,data,json.loads(raw.read_text()))
      graph=data['provenance']['noalias_metadata_graph_source'];strings=[bytes(x['bytes']) for x in graph['nodes'] if x['kind']=='string']
      self.assertIn(b'domain\0\xff<0x1234>',strings);self.assertIn(b'identity\0\xfe',strings);self.assertIn(b'',strings)
      self.assertTrue(any(x['kind']=='tuple' and x['id'] in x['operands'] for x in graph['nodes']))
      roots=graph['roots'];self.assertEqual(roots[0]['kind'],'scope_declaration');self.assertEqual(roots[3]['kind'],'alias_scope')
      self.assertEqual(roots[0]['node'],next(x['node'] for x in roots if x['kind']=='alias_scope' and x['site']['source_instruction']==1))
      self.assertNotEqual(roots[0]['node'],next(x['node'] for x in roots if x['kind']=='scope_declaration' and x['site']['source_instruction']==2))
     self.assertEqual(outputs[0].read_bytes(),outputs[1].read_bytes())
     self.readmit(path,outputs[0],isa,f'authored-{isa}-{fmt}-green',True)
 def test_inconsistent_unknown_mixed_and_ordered_graphs_fail_native_verification(self):
  ll,path,diag=self.fixture();good=json.loads(path.read_text());graph=good['provenance']['noalias_metadata_graph_source'];cases=[]
  def variant(name,change):
   m=copy.deepcopy(good);change(m);cases.append((name,m))
  variant('unknown-version',lambda m:m['provenance']['noalias_metadata_graph_source'].__setitem__('schema','future-v2'))
  variant('mixed',lambda m:m['provenance'].__setitem__('noalias_metadata_source',json.loads(diag.read_text())['alias_nodes']))
  variant('missing-root',lambda m:m['provenance']['noalias_metadata_graph_source']['roots'].pop())
  variant('duplicate-root',lambda m:m['provenance']['noalias_metadata_graph_source']['roots'].append(copy.deepcopy(graph['roots'][0])))
  def swap(m):
   r=m['provenance']['noalias_metadata_graph_source']['roots'];r[0],r[1]=r[1],r[0]
  variant('root-order',swap)
  variant('missing-graph',lambda m:m['provenance'].pop('noalias_metadata_graph_source'))
  variant('duplicate-binding',lambda m:m['provenance']['noalias_metadata_graph_source']['alias_bindings'].append(copy.deepcopy(graph['alias_bindings'][0])))
  variant('wrong-sharing',lambda m:m['provenance']['noalias_metadata_graph_source']['alias_bindings'][0].__setitem__('node',graph['alias_bindings'][1]['node']))
  tupleid=next(i for i,x in enumerate(graph['nodes']) if x['kind']=='tuple' and x['id'] in x['operands'])
  variant('broken-cycle',lambda m:m['provenance']['noalias_metadata_graph_source']['nodes'][tupleid]['operands'].__setitem__(0,0xffffffff))
  stringid=next(i for i,x in enumerate(graph['nodes']) if x['kind']=='string' and x['bytes'])
  variant('opaque-byte',lambda m:m['provenance']['noalias_metadata_graph_source']['nodes'][stringid]['bytes'].__setitem__(0,0))
  variant('out-of-range-byte',lambda m:m['provenance']['noalias_metadata_graph_source']['nodes'][stringid]['bytes'].__setitem__(0,256))
  variant('missing-source-order',lambda m:m['noalias_metadata']['attachments'][0].pop('source_order'))
  variant('duplicated-source-order',lambda m:m['noalias_metadata']['attachments'][0].__setitem__('source_order',['alias_scope','alias_scope']))
  variant('unknown-source-order',lambda m:m['noalias_metadata']['attachments'][0].__setitem__('source_order',['scope_declaration']))
  for name,module in cases:
   with self.subTest(name=name):
    forged=self.out/('inconsistent-'+name+'.json');write(forged,module);self.verify(forged,'inconsistent-'+name,False)
 def test_coherent_metadata_forgery_cannot_claim_original_source(self):
  original,claimed,_=self.fixture();old=json.loads(claimed.read_text());changed=self.out/'coherent-changed.ll';changed.write_text(original.read_text().replace('domain\\00\\FF','forged\\00\\FE'))
  _,forged,_=self.import_(changed,'x86_64','coherent-forged')
  m=json.loads(forged.read_text());m['name']=old['name'];m['provenance']['input_sha256']=old['provenance']['input_sha256'];write(forged,m)
  self.verify(forged,'coherent-forged-valid')
  diffs=differences(old,m);self.assertTrue(diffs)
  self.assertTrue(all(p[:1]==('noalias_metadata',) or p[:2]==('provenance','noalias_metadata_graph_source') for p in diffs),diffs)
  self.readmit(original,forged,'x86_64','coherent-forged-red',False)
 def test_legacy_verification_keeps_packet_and_noalias_free_default_shape(self):
  oldcases=os.environ.get('OCORE_METADATA_LEGACY_CASES')
  if not oldcases:self.skipTest('retained pre-change packets not selected')
  cases=json.loads(Path(oldcases).read_text())['cases']
  for i,case in enumerate(cases):
   legacy=Path(case['modules'][0]['path']);self.assertEqual(pin(legacy),case['modules'][0]);before=legacy.read_bytes()
   self.verify(legacy,f'legacy-{i}')
   output=self.out/f'legacy-{i}-canonical.json';self.command([self.core,legacy,'--input-kind','native-ir','--emit','mir','--target',case['isa']+'-unknown-none','-o',output],f'legacy-{i}-canonical')
   self.assertEqual(output.read_bytes(),before);self.assertEqual(legacy.read_bytes(),before)
   self.readmit(case['input']['path'],legacy,case['isa'],f'legacy-{i}-recapture-required',False)
 def test_noalias_free_imports_keep_legacy_canonical_shape(self):
  baseline=os.environ.get('OCORE_METADATA_BASELINE_OCOREC')
  if not baseline:self.skipTest('retained pre-change compiler not selected')
  for isa,(triple,layout) in PROFILES.items():
   ll=self.out/f'{isa}-no-alias.ll';ll.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\ndefine i64 @plain(i64 %x) {{ %r = add i64 %x, 7\n ret i64 %r }}\n')
   old=self.out/f'{isa}-plain-legacy.json'
   self.command([baseline,ll,'--input-kind','llvm-ir','--emit','mir','--target',isa+'-unknown-none','--llvm-library',self.lib,'--llvm-sha256',self.libpin['sha256'],'-o',old],isa+'-plain-legacy')
   _,new,raw=self.import_(ll,isa,isa+'-plain-new')
   self.assertEqual(old.read_bytes(),new.read_bytes())
   data=json.loads(new.read_text());self.assertNotIn('noalias_metadata_graph_source',data['provenance']);self.assertEqual(data['noalias_metadata']['attachments'],[])
   diag=json.loads(raw.read_text());self.assertIsNone(diag['graph_source']);self.assertEqual(diag['alias_nodes'],[])
 def test_existing_unsupported_semantics_and_scope_dominance_stay_failclosed(self):
  unsupported = {
   'dominated-same-scope': BODY.replace('metadata !6)', 'metadata !5)'),
   'unknown-metadata': 'define i64 @unknown(i64 %x) { %r = add i64 %x, 1, !unqualified.source.metadata !0\n ret i64 %r }\n!0 = !{i64 7}\n',
   'inline-asm': 'define void @barrier() { call void asm sideeffect "", ""()\n ret void }\n',
   'strict-real-fp': 'define double @real_fp(double %x) #0 { %r = fadd double %x, 1.000000e+00\n ret double %r }\nattributes #0 = { strictfp }\n',
  }
  for isa,(triple,layout) in PROFILES.items():
   for label,body in unsupported.items():
    ll=self.out/f'unsupported-{isa}-{label}.ll';ll.write_text(f'target triple = "{triple}"\ntarget datalayout = "{layout}"\n'+body)
    bc=ll.with_suffix('.bc');self.command([self.sdk/'llvm-as',ll,'-o',bc],f'serialize-unsupported-{isa}-{label}')
    for fmt,path in [('ll',ll),('bc',bc)]:
     with self.subTest(isa=isa,case=label,format=fmt):
      q,out,raw=self.import_(path,isa,f'unsupported-{isa}-{label}-{fmt}',False)
      self.assertNotEqual(q.returncode,0);self.assertFalse(out.exists())
      self.assertTrue(raw.exists())
      # The worker completes traversal of this LLVM-valid fixture, then the
      # independent NativeVerifier rejects the dominating redeclaration.
      # Raw diagnostics deliberately do not claim owned verification.
      self.assertEqual(json.loads(raw.read_text())['import_complete'], label == 'dominated-same-scope')
      if label == 'dominated-same-scope': self.assertIn(b'dominates another declaration', q.stderr)
 def test_private_parser_library_collision_is_rejected_before_loading(self):
  ll,_,_=self.fixture();fake=self.out/'must-not-replace-parser';fake.write_bytes(b'private fake readable parser bytes');before=pin(fake)
  paths=[fake,self.out/'parser-symlink'];paths[1].symlink_to(fake)
  for i,path in enumerate(paths):
   output=self.out/f'collision-{i}.json'
   q=self.command([self.core,ll,'--input-kind','llvm-ir','--llvm-library',fake,'--llvm-sha256',before['sha256'],'--llvm-metadata-diagnostics',path,'-o',output],f'collision-{i}',False)
   self.assertEqual(q.returncode,2);self.assertFalse(output.exists());self.assertEqual(pin(fake),before)
  q=self.command(['/usr/bin/python3',ROOT/'scripts/ocore_llvm_import.py',ll,'--llvm-library',fake,'--llvm-sha256',before['sha256'],'--metadata-diagnostics',fake,'-o',self.out/'worker-collision.json'],'worker-collision',False)
  self.assertNotEqual(q.returncode,0);self.assertIn(b'"stage": "command"',q.stderr);self.assertEqual(pin(fake),before)
  rustup=self.out/'fake-rustup';selected=rustup/'toolchains/1.97.1-fixture/lib/libLLVM.so.22.1-rust-1.97.1-stable';selected.parent.mkdir(parents=True);selected.write_bytes(fake.read_bytes());original=pin(selected)
  q=self.command(['/usr/bin/python3',ROOT/'scripts/ocore_llvm_import.py',ll,'--metadata-diagnostics',selected,'-o',self.out/'discovery-collision.json'],'discovered-collision',False,dict(self.env,RUSTUP_HOME=str(rustup)))
  self.assertNotEqual(q.returncode,0);self.assertIn(b'"stage": "command"',q.stderr);self.assertEqual(pin(selected),original)
if __name__=='__main__':unittest.main()
