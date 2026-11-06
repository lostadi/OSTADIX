# Authored INERT bytes; no actual rustc/LLVM/source-production evidence.
# Real ELF/ar bytes use the real registered payload extractor and full owning
# Rust event verifier. No compiler, LLVM parser, subprocess or native invocation.
import copy,hashlib,json,struct,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
WORKER=ROOT/'scripts/ocore_runtime_capture.py'
ASSET_PINS={'worker': ('scripts/ocore_runtime_capture.py', 167292, '03956b10d66ec5877c9f23c67bfdfb16648d28b74f9ac3c2a30720cd64784ff8'), 'payload': ('tools/ocore-runtime/rust/payload_inventory.py', 43028, '0190404305ffa887b60d5f23e9af64029c1fe770ce6c705d19a65ee3a89d6767'), 'registry': ('scripts/ocore_producer_registry.json', 1138, '62d74350f9b97db882f96ccb04fb985ff519e45d648b2f977664c2e631ff4052')}
def checked(path,pin):
 raw=path.read_bytes()
 if (len(raw),hashlib.sha256(raw).hexdigest())!=(pin['bytes'],pin['sha256']):raise AssertionError('fixture source pin differs '+str(path))
 return raw
def asset_artifact(role):
 relative,size,digest=ASSET_PINS[role]
 return {'path':str((ROOT/relative).resolve()),'bytes':size,'sha256':digest}
def checked_assets():
 return {role:checked(ROOT/relative,{'bytes':size,'sha256':digest})
         for role,(relative,size,digest) in ASSET_PINS.items()}
def worker():
 assets=checked_assets()
 ns={'__name__':'rust_native_byte_fixture_worker','__file__':str(WORKER)}
 exec(compile(assets['worker'],str(WORKER),'exec'),ns)
 return ns,assets
def elf(payload):
 names=b'\0.shstrtab\0.llvmbc\0';nameoff=64;dataoff=nameoff+len(names);shoff=(dataoff+len(payload)+7)&~7
 header=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+b'\0'*9,1,243,1,0,0,shoff,5,64,0,0,64,3,1)
 sections=bytes(64)+struct.pack('<IIQQQQIIQQ',1,3,0,0,nameoff,len(names),0,0,1,0)+struct.pack('<IIQQQQIIQQ',11,1,0,0,dataoff,len(payload),0,0,1,0)
 return header+names+payload+bytes(shoff-dataoff-len(payload))+sections
def ar(members):
 result=b'!<arch>\n'
 for name,raw in members:
  header=(name+'/').encode().ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'100644'.ljust(8)+str(len(raw)).encode().ljust(10)+bytes([96,10])
  if len(header)!=60:raise AssertionError('authored archive header differs')
  result+=header+raw+(b'\n' if len(raw)&1 else b'')
 return result
class Fixture:
 def __init__(self,archive=False,duplicate=False):
  self.w,self.assets=worker();self.root=Path(tempfile.mkdtemp(prefix='ostadix-rust-native-byte-DATA-'));self.capture=self.root/'capture';self.capture.mkdir()
  (self.root/'main.rs').write_text('pub fn fixture()->u32{7}\n');self.frontend=self.root/'not-executed-rustc';self.frontend.write_bytes(b'canned inert frontend; NOT EXECUTED\n')
  payload=ROOT/'tools/ocore-runtime/rust/payload_inventory.py';snapshot=self.capture/'rust-payload-extractor.py';snapshot.write_bytes(self.assets['payload'])
  fi=self.w['file_info'];self.worker_pin=asset_artifact('worker')
  self.session={'recipe':{'toolchain':{'rust_capture_policy':'rust-embedded-bc-v1'}},'capture_worker':{'artifact':self.worker_pin,'rust_payload_extractor':{'schema':'ocore-rust-payload-extractor-worker-v1','source':asset_artifact('payload'),'artifact':fi(snapshot)}}}
  self.extractor=self.w['rust_payload_extractor'](self.session,self.capture)
  self.registry=json.loads(self.assets['registry'])
  self.bitcodes=[b'BC\xc0\xde'+b'canned-not-semantic-llvm-A']
  if archive:self.bitcodes.append(b'BC\xc0\xde'+b'canned-not-semantic-llvm-B')
  self.objects=[elf(bc) for bc in self.bitcodes];self.output=self.root/('whole.rlib' if archive else 'own.o')
  self.output.write_bytes(ar([('a.o',self.objects[0]),('a.o' if duplicate else 'cold.o',self.objects[1])]) if archive else self.objects[0])
  self.depfile=self.root/'fixture.d';self.depfile.write_bytes(b'fixture.o: main.rs\n')
  source=fi(self.root/'main.rs');frontend={**fi(self.frontend),'invoked_path':str(self.frontend),'version':'canned inert frontend; NOT EXECUTED'}
  argv=[str(self.root/'main.rs'),'--crate-name','fixture','--crate-type','lib','--emit=obj','-C','opt-level=1']
  executed,changes=self.w['rust_instrumentation'](argv,True)
  self.event={'id':'authored-native-action','kind':'rustc','driver_kind':'rustc','producer':'rustc-llvm-v1','state':'finished','exit_code':0,'capture_errors':[],'cargo_parent_invocation_id':None,'cwd':str(self.root),'argv':argv,'expanded_argv':list(argv),'executed_argv':executed,'rust_response_files':[],'response_files':[],'compiler':str(self.frontend),'frontend':frontend,'capture_worker':self.worker_pin,'sources':[source],'outputs':[fi(self.output),fi(self.depfile)],'saved_cgus':[],'units':[],'rust_cgu_gaps':[],'rust_native_resources':[],'started_ns':1,'finished_ns':2,'rust_capture':{'policy':'rust-embedded-bc-v1','applied':True,'transformations':changes,'original_command_executed':executed==argv,'frontend_replay_used':False,'post_lto_equivalence_verified':False,'argfile_gap':None}}
  for index,(obj,bc) in enumerate(zip(self.objects,self.bitcodes)):
   # Exact actual API: an artifact DICT, never a Path.
   extracted=self.extractor['extract_embedded_bitcode'](fi(self.output),index if archive else None)
   if archive:
    objpath=self.capture/('saved-'+str(index)+'.o');objpath.write_bytes(obj);object_pin=fi(objpath)
   else:
    # Native standalone ownership includes original output PATH identity.
    object_pin=fi(self.output)
   bcpath=self.capture/('saved-'+str(index)+'.bc');bcpath.write_bytes(bc)
   record={'schema':'ocore-rust-native-bitcode-edge-v1','compiler_invocation_id':self.event['id'],'cargo_parent_invocation_id':None,'object':object_pin,'bitcode':fi(bcpath),'edge':extracted['edge']}
   if archive:record['container']={'artifact':fi(self.output),'member':extracted['member']}
   self.event['saved_cgus'].append(record)
   self.event['units'].append({'id':self.event['id']+':'+str(index),'kind':'rustc','source':source,'dependencies':[source],'saved_cgu_index':index,'capture_policy':'rust-embedded-bc-v1','ir':{**fi(bcpath),'format':'llvm-bitcode','target_triple':'riscv64-unknown-linux-gnu','data_layout':'canned metadata; NO LLVM PARSE'},'source_production_ownership_verified':False,'native_machine_equivalence_verified':False,'post_lto_equivalence_verified':False})
  evidence=self.w['rust_output_evidence'](self.event,self.extractor)
  if evidence['gaps']:raise AssertionError('authored positive fixture gaps '+repr(evidence['gaps']))
  self.event['rust_native_resources']=evidence['resources']
  self.w['verify_rust_capture_event'](self.event,self.session,self.capture)
  self.context=self.w['RustNativeLinkageContext'](self.session,self.capture,self.registry,self.worker_pin)
 def proof(self):return self.w['native_source_output'](self.event,self.event['outputs'][0],None,self.context)
 def report(self,events=None):return self.w['linkage_evidence'](events or [self.event],{'roots':[self.event['outputs'][0]],'contributing_invocation_ids':[self.event['id']]},self.context)
 def members(self):return self.extractor['archive_members'](self.output.read_bytes())
class RustNativeByteEdgeDataTests(unittest.TestCase):
 def refused(self,f,reason):
  p=f.proof();self.assertFalse(p['native_embedded_bitcode_edge_verified']);self.assertIn(reason,p['reason']);return p
 def test_standalone_real_byte_edge_without_source_or_replay_claim(self):
  f=Fixture();p=f.proof();self.assertTrue(p['native_embedded_bitcode_edge_verified']);self.assertEqual(len(p['native_embedded_bitcode_edges']),1);self.assertEqual(f.event['saved_cgus'][0]['object'],f.event['outputs'][0])
  for key in ('native_source_owned','llvm_replay_owned','source_production_ownership_verified','native_machine_equivalence_verified','post_lto_equivalence_verified'):self.assertIs(p[key],False)
 def test_archive_all_members_and_stable_name_selector_inputs(self):
  f=Fixture(archive=True);p=f.proof();self.assertTrue(p['native_embedded_bitcode_edge_verified']);edges=p['native_embedded_bitcode_edges'];self.assertEqual(len(edges),2)
  self.assertNotEqual(edges[0]['selector_input']['member_name_bytes'],edges[1]['selector_input']['member_name_bytes'])
  for edge in edges:self.assertEqual(set(edge['selector_input']),{'profile','container','member_name_bytes'});self.assertEqual(edge['selector_input']['container'],str(f.output))
 def test_ordinary_evidence_reaches_actual_linkage_report(self):
  f=Fixture();r=f.report();self.assertTrue(r['provider_ownership'][0]['native_embedded_bitcode_edge_verified']);self.assertTrue(r['rust_native_embedded_bitcode_evidence']['postguards_passed']);self.assertFalse(r['source_provider_ownership_complete']);self.assertFalse(r['llvm_replay_ownership_complete'])
 def test_archive_member_evidence_reaches_actual_linkage_report(self):
  f=Fixture(archive=True);r=f.report();self.assertEqual(len(r['archive_member_ownership']),2);self.assertTrue(all(p['native_embedded_bitcode_edge_verified'] for p in r['archive_member_ownership']));self.assertFalse(r['native_source_ownership_complete'])
 def test_duplicate_physical_member_names_are_ambiguous_selectors(self):
  f=Fixture(archive=True,duplicate=True);members=f.members();self.assertEqual(len(members),2);self.assertNotEqual(members[0]['header_offset'],members[1]['header_offset']);self.refused(f,'ambiguous stable native output selector')
 def test_cold_second_edge_omission_fails_whole_action_floor(self):
  f=Fixture(archive=True);self.assertEqual(len(f.event['saved_cgus']),2);f.event['saved_cgus'].pop();f.event['units'].pop();self.assertEqual(len(f.members()),2);self.refused(f,'Rust saved CGU inventory differs from all original embedded object/member edges')
 def test_record_parent_mutation_reaches_real_payload_verifier(self):
  f=Fixture();f.event['saved_cgus'][0]['compiler_invocation_id']='different-action';self.assertNotEqual(f.event['saved_cgus'][0]['compiler_invocation_id'],f.event['id']);self.refused(f,'cgu_parent_mismatch: saved CGU record does not belong to this original compiler journal')
 def test_embedded_range_mutation_reaches_real_payload_verifier(self):
  f=Fixture();edge=f.event['saved_cgus'][0]['edge'];before=edge['object_offset'];edge['object_offset']+=1;self.assertNotEqual(edge['object_offset'],before);self.refused(f,'embedded_edge_mismatch: embedded section identity/range/hash differs')
 def test_cold_original_resource_byte_mutation_is_detected(self):
  f=Fixture();old=f.event['outputs'][1]['sha256'];f.depfile.write_bytes(b'changed cold original dependency resource\n');self.assertNotEqual(hashlib.sha256(f.depfile.read_bytes()).hexdigest(),old);self.refused(f,'Rust original producer output changed')
 def test_cached_positive_is_invalidated_when_actual_postguard_fails(self):
  f=Fixture();self.assertTrue(f.proof()['native_embedded_bitcode_edge_verified']);actual=f.context.postguard;reached=[]
  def mutate_then_verify():
   reached.append(True);f.depfile.write_bytes(b'changed after initial proof\n');actual()
  f.context.postguard=mutate_then_verify;r=f.report();self.assertEqual(reached,[True]);self.assertFalse(r['provider_ownership'][0]['native_embedded_bitcode_edge_verified']);self.assertFalse(r['rust_native_embedded_bitcode_evidence']['postguards_passed']);self.assertTrue(any('Rust native byte-edge postguard: Rust original producer output changed' in s for s in r['issues']))
 def test_cargo_parent_some_stays_explicitly_unsupported(self):
  f=Fixture();f.event['cargo_parent_invocation_id']='unadmitted-observer-action'
  for record in f.event['saved_cgus']:record['cargo_parent_invocation_id']=f.event['cargo_parent_invocation_id']
  self.refused(f,'Cargo parent semantic context unsupported')
 def test_fabricated_replay_cannot_replace_native_byte_edge(self):
  f=Fixture();f.event['replay_argv']=['fabricated'];self.refused(f,'embedded Rust capture cannot substitute a frontend replay')
 def test_wrong_registered_producer_id_refuses(self):
  f=Fixture();f.event['producer']='clang-llvm-v1';self.refused(f,'registered Rust embedded producer differs')
 def test_two_causal_producing_actions_never_choose_one_passing_owner(self):
  f=Fixture();second=copy.deepcopy(f.event);second['id']='second-native-action'
  for record in second['saved_cgus']:record['compiler_invocation_id']=second['id']
  for index,unit in enumerate(second['units']):unit['id']=second['id']+':'+str(index)
  r=f.report([f.event,second]);p=r['provider_ownership'][0];self.assertEqual(len(p['candidate_outputs']),2);self.assertFalse(p['native_embedded_bitcode_edge_verified']);self.assertIn('ambiguous',p['rust_byte_edge_reason'])
 def test_exact_instrumented_arguments_are_retained_without_equivalence(self):
  f=Fixture();p=f.proof();self.assertTrue(p['native_embedded_bitcode_edge_verified']);row=p['native_embedded_bitcode_edges'][0];self.assertEqual(row['original_argv'],f.event['argv']);self.assertEqual(row['executed_argv'],f.event['executed_argv']);self.assertNotEqual(row['original_argv'],row['executed_argv']);self.assertIs(row['rust_capture']['original_command_executed'],False);self.assertIs(row['source_production_ownership_verified'],False)
if __name__=='__main__':unittest.main()
