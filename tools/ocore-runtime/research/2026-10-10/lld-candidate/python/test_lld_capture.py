"""Authored source-packet protocol QA; no upstream source build or link run."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import lld_capture as D
HELPER=Path.home()/'.cache/ostadix-research/rust-producer-capture-integration-8a5nodnt/private-stage/tools/ocore-runtime/rust/payload_inventory.py'
HELPER_SHA='0190404305ffa887b60d5f23e9af64029c1fe770ce6c705d19a65ee3a89d6767'
def b(x):return list(x.encode() if isinstance(x,str) else x)
def archive(parts):
    result=bytearray(b'!<arch>\n')
    for name,data in parts:
        header=(name+'/').encode().ljust(16,b' ')+b'0'.ljust(12,b' ')+b'0'.ljust(6,b' ')+b'0'.ljust(6,b' ')+b'644'.ljust(8,b' ')+str(len(data)).encode().ljust(10,b' ')+b'`\n'
        result.extend(header);result.extend(data)
        if len(data)&1:result.extend(b'\n')
    return bytes(result)
class Fixture:
    def __init__(self,path,seed=None,object_bytes=b'\x7fELForiginal-object'):
        self.path=Path(path);self.root=self.path/'packets';self.root.mkdir();(self.root/'blobs').mkdir()
        self.events=[];self.obj=object_bytes
        self.image=self.artifact('lld-image',b'synthetic-unbuilt-LLD-image')
        self.patch=self.artifact('patch',b'synthetic source patch only')
        self.sources=self.json('sources.json',{'synthetic':True})
        self.reg=self.json('registration.json',{'schema':'ocore-lld-hook-registration-v1','source_revision':D.REVISION,'source_patch':self.patch,'linker_image':self.image,'hook_source_manifest':self.sources,'scope':'authored-protocol-fixture-not-built'})
        self.seed=seed or self.json('rust-spawn.pending.json',{'schema':'ocore-rust-native-link-spawn-v1','observation':'original_driver_spawn_prepared'})
        self.context=self.json('context.json',{'schema':'ocore-lld-link-context-v1','packet_directory':str(self.root),'invocation_id':'authored-one','rust_spawn_seed':self.seed,'linker_registration':self.reg,'driver_trace_seed':None})
        self.add('session',source_revision=D.REVISION,context=self.blob(Path(self.context['path']).read_bytes()),pid=70,cwd=b(str(self.path)),executable_locator=b(self.image['path']),executable=self.blob(Path(self.image['path']).read_bytes()),incoming_argv=[b('ld.lld'),b('@original.rsp')],process_argv=[b('ld.lld'),b('@original.rsp')],process_argv_snapshot=self.blob(b'ld.lld\0@original.rsp\0'))
        self.add('read',role='response',locator=b('original.rsp'),buffer=self.blob(b'--start-group original.a --end-group\n'))
        self.add('arguments',phase='response_expanded',argv=[b('--start-group'),b('original.a'),b('--end-group')])
        self.add('arguments',phase='plugin_options_normalized',argv=[b('--start-group'),b('original.a'),b('--end-group')])
        self.add('argument',option_id=1,index=0,spelling=b('--start-group'),rendered=b('--start-group'),values=[])
        self.data=archive([('same-name.o',self.obj),('same-name.o',b'cold-unused-original-member')])
        self.read=self.add('read',role='read_file',locator=b('original.a'),buffer=self.blob(self.data))
        self.input=self.add('input',locator=b('original.a'),buffer=self.blob(self.data),read_event=self.read,script_operand_id=0,with_l_option=False,whole_archive=False,start_lib=False,in_group=True,group_id=0,static=True,as_needed=False)
        self.member=self.add('archive_member',input_id=self.input,physical_index=0,header_offset=8,data_offset=68,raw_name=b('same-name.o/'),name=b('same-name.o'),thin=False,archive=self.blob(self.data),buffer=self.blob(self.obj),member_locator=b('original.a(same-name.o)'))
        second=8+60+len(self.obj)+(len(self.obj)&1)
        self.unselected_member=self.add('archive_member',input_id=self.input,physical_index=1,header_offset=second,data_offset=second+60,raw_name=b('same-name.o/'),name=b('same-name.o'),thin=False,archive=self.blob(self.data),buffer=self.blob(b'cold-unused-original-member'),member_locator=b('original.a(same-name.o)'))
        self.file=self.add('file',input_id=self.input,member_id=self.member,kind=0,group_id=0,lazy=True,buffer=self.blob(self.obj),source_range={'offset':0,'bytes':len(self.obj)})
        self.add('extract',file_id=self.file,symbol=b('required_symbol'))
        self.add('selected',file_id=self.file)
        self.finish=self.add('finish',prior_event_count=len(self.events),capture_write_failed=False,source_return_success=True,source_error_count=0,output_locator=b('original-output'),output=self.blob(b'original-final-native-bytes'),emachine=62,elf_kind=3,configuration_read=True,shared=False,relocatable=False,symbols=[{'name':b('required_symbol'),'kind':1,'file_id':self.file,'binding':1,'type':2,'visibility':0,'version_id':1,'used':True,'preemptible':False}],providers=[],versions=[])
    def artifact(self,name,data):
        p=self.path/name;p.write_bytes(data);return D.info(p)
    def json(self,name,value):return self.artifact(name,(json.dumps(value,indent=2)+'\n').encode())
    def blob(self,data):
        sha=hashlib.sha256(data).hexdigest();p=self.root/'blobs'/sha;p.write_bytes(data);return D.info(p)
    def add(self,event_kind,**payload):
        n=len(self.events)+1;self.events.append({'schema':'ocore-lld-elf-event-v1','sequence':n,'kind':event_kind,'payload':payload});return n
    def prune_blobs(self):
        live={x["sha256"] for e in self.events for x in e["payload"].values() if isinstance(x,dict) and "sha256" in x}
        for p in (self.root/"blobs").iterdir():
            if p.name not in live:p.unlink()
    def write(self):
        for p in self.root.glob('event-*'):p.unlink()
        for e in self.events:(self.root/f"event-{e['sequence']:016}.json").write_text(json.dumps(e,indent=2)+'\n')
        return D.manifest(self.root,self.path/'manifest.json')
    def decode(self,**kw):
        return D.decode(self.write(),self.context,self.reg,trusted_registration_sha256=self.reg['sha256'],archive_helper=D.info(HELPER),trusted_archive_helper_sha256=HELPER_SHA,**kw)
    def p(self,n):return self.events[n-1]['payload']
class ProtocolTests(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.f=Fixture(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def reject(self,kind,**kw):
        with self.assertRaises(D.LinkEvidenceError) as caught:self.f.decode(**kw)
        self.assertEqual(caught.exception.kind,kind,str(caught.exception))
    def test_actual_member_occurrence_not_basename(self):
        v=self.f.decode(observed_linker_status=0)
        self.assertEqual([x['file_id'] for x in v['selected_input_occurrences']],[self.f.file])
        self.assertEqual(len(v['ordered_input_occurrences']),1)
        self.assertFalse(any(v[k] for k in D.FLAGS))
        self.assertFalse(v['selected_input_occurrences'][0]['source_production_owned'])
    def test_duplicated_archive_header_rejects(self):
        self.f.p(self.f.unselected_member).update(copy.deepcopy(self.f.p(self.f.member)));self.f.prune_blobs();self.reject('archive')
    def test_wrong_physical_index_rejects(self):self.f.p(self.f.member)['physical_index']=1;self.reject('archive')
    def test_wrong_header_offset_rejects(self):self.f.p(self.f.member)['header_offset']=9;self.reject('archive')
    def test_wrong_data_offset_rejects(self):self.f.p(self.f.member)['data_offset']=69;self.reject('archive')
    def test_wrong_member_name_rejects(self):self.f.p(self.f.member)['name']=b('other.o');self.reject('archive')
    def test_member_bytes_changed_rejects(self):self.f.p(self.f.member)['buffer']=self.f.blob(b'wrong');self.reject('archive')
    def test_member_raw_name_rejects(self):self.f.p(self.f.member)['raw_name']=b('different.o/');self.reject('archive')
    def test_detached_input_read_rejects(self):self.f.p(self.f.input)['read_event']=2;self.reject('input')
    def test_forward_source_reference_rejects(self):self.f.p(self.f.file)['member_id']=self.f.finish;self.reject('reference')
    def test_original_derived_buffer_slice_accepted(self):
        self.f.p(self.f.file)['buffer']=self.f.blob(self.f.obj[4:]);self.f.p(self.f.file)['source_range']={'offset':4,'bytes':len(self.f.obj)-4}
        self.f.decode()
    def test_derived_buffer_slice_detached_rejects(self):self.f.p(self.f.file)['source_range']['offset']=1;self.reject('source_range')
    def test_missing_actual_extract_rejects(self):
        self.f.events[self.f.file]['kind']='gap';self.f.events[self.f.file]['payload']={'kind':'intentional_missing_extraction','reason':'authored control'};self.reject('selection')
    def test_nonlazy_extract_rejects(self):self.f.p(self.f.file)['lazy']=False;self.reject('extraction')
    def test_wrong_final_symbol_owner_rejects(self):self.f.p(self.f.finish)['symbols'][0]['file_id']=self.f.input;self.reject('reference')
    def test_original_failure_status_remains_failure(self):
        self.f.p(self.f.finish).update(source_return_success=False,source_error_count=1,output=None)
        # Remove unused former output snapshot: legitimate native failed packet.
        live={x['sha256'] for e in self.f.events for x in e['payload'].values() if isinstance(x,dict) and 'sha256' in x}
        for p in (self.f.root/'blobs').iterdir():
            if p.name not in live:p.unlink()
        v=self.f.decode(observed_linker_status=1);self.assertFalse(v['source_return_success'])
    def test_external_waited_status_mismatch_rejects(self):self.reject('status',observed_linker_status=1)
    def test_source_capture_write_failure_rejects(self):self.f.p(self.f.finish)['capture_write_failed']=True;self.reject('lifecycle')
    def test_source_count_hole_rejects(self):self.f.p(self.f.finish)['prior_event_count']-=1;self.reject('lifecycle')
    def test_strict_unknown_event_field_rejects(self):self.f.p(self.f.member)['fake_owned']=True;self.reject('wire_fields')
    def test_duplicate_json_keys_reject(self):
        m=self.f.write();p=self.f.root/'event-0000000000000001.json';p.write_bytes(b'{"schema":1,"schema":2}')
        m=D.manifest(self.f.root,self.f.path/'manifest.json')
        with self.assertRaisesRegex(D.LinkEvidenceError,'duplicate_json_key'):D.decode(m,self.f.context,self.f.reg,trusted_registration_sha256=self.f.reg['sha256'],archive_helper=D.info(HELPER),trusted_archive_helper_sha256=HELPER_SHA)
    def test_drop_manifest_resource_rejects(self):
        m=self.f.write();v=D.record(m);v['files'].pop();self.f.json('manifest.json',v)
        with self.assertRaisesRegex(D.LinkEvidenceError,'manifest'):D.decode(D.info(self.f.path/'manifest.json'),self.f.context,self.f.reg,trusted_registration_sha256=self.f.reg['sha256'],archive_helper=D.info(HELPER),trusted_archive_helper_sha256=HELPER_SHA)
    def test_actual_process_image_differs_rejects(self):self.f.p(1)['executable']=self.f.blob(b'other image');self.f.prune_blobs();self.reject('linker_image')
    def test_ordinary_provider_retains_dependencies(self):
        # Source-authored provider final symbol read, not execution.
        self.f.p(self.f.finish)['providers']=[{'file_id':self.f.file,'soname':b('provider.so'),'needed':True,'dt_needed':[b('transitive.so')]}]
        v=self.f.decode();self.assertEqual(v['final_dynamic_providers'][0]['dt_needed'],[b('transitive.so')])
        self.assertTrue(any(g['kind']=='dynamic_loader_provider_transitive_dependencies_unresolved' for g in v['gaps']))
    def test_caller_cannot_skip_producer_readmission(self):self.reject('producer_trust',producer_observation={'producer_units':[]})
    def test_real_v3_packets_join_compatibility_no_replay(self):
        root=Path.home()/'.cache/ostadix-research/rust-producer-capture-integration-8a5nodnt'
        original=D.record(D.info(root/'implementation-evidence/cli-direct-final-observation.json'))
        attempt=D.record(original['native_attempts'][0]['record'])
        reg=D.record(D.info(root/'implementation-evidence/registration.json'))
        helper_path=root/'private-stage/tools/ocore-runtime/rust/producer_capture.py'
        namespace={'__name__':'lld_test_original_producer_readmission','__file__':str(helper_path)}
        expected='1242605d37ee8bd6a6c88703ae9742508a4be4bdeccb3821e901921433967986'
        self.assertEqual(D.info(helper_path)['sha256'],expected)
        exec(compile(helper_path.read_bytes(),str(helper_path),'exec'),namespace)
        unit=original['producer_units'][0];obj=D.checked(unit['retained_object'])
        with tempfile.TemporaryDirectory() as tmp:
            fixture=Fixture(tmp,seed=attempt['spawn_seed'],object_bytes=obj)
            v=fixture.decode(producer_observation=original,producer_readmission=lambda value:namespace['verify_observation'](value,reg,compiler=reg['compiler']))
        self.assertEqual(len(v['producer_joins']),1);self.assertTrue(v['producer_joins'][0]['unique_original_producer'])
        self.assertFalse(v['producer_joins'][0]['source_production_ownership_complete'])
        self.assertFalse(any(v[k] for k in D.FLAGS))
    def test_process_argv_snapshot_exact_bytes(self):
        self.f.p(1)['process_argv']=[b('different-program')];self.reject('process_argv')
    def test_source_script_resource_and_operand_retained(self):
        script=self.f.blob(b'INPUT(original.a)\n')
        before=self.f.events.pop();self.f.add('read',role='read_file',locator=b('original.ld'),buffer=script)
        rid=len(self.f.events)
        self.f.add('script',role='linker_script',locator=b('original.ld'),buffer=script,read_event=rid)
        self.f.add('script_operand',parent_operand_id=0,operand=b('original.a'),source=script,source_locator=b('original.ld'))
        before['sequence']=len(self.f.events)+1;before['payload']['prior_event_count']=len(self.f.events);self.f.events.append(before);self.f.finish=before['sequence']
        self.f.decode()
    def test_unretained_script_operand_rejects(self):
        before=self.f.events.pop();self.f.add('script_operand',parent_operand_id=0,operand=b('original.a'),source=self.f.blob(b'unread-source'),source_locator=b('unread.ld'))
        before['sequence']=len(self.f.events)+1;before['payload']['prior_event_count']=len(self.f.events);self.f.events.append(before);self.reject('script')
    def test_original_lto_ir_and_object_cache_gap(self):
        before=self.f.events.pop()
        self.f.add('lto_ir',task=0,phase='original_pre_codegen_module',module_id=b('original-module'),triple=b('x86_64-original'),data_layout=b('e-p:64:64'),bitcode=self.f.blob(b'BC\xc0\xdeoriginal-source-issued-module'))
        self.f.add('lto_object',task=0,cache_hit=True,buffer=self.f.blob(b'original-cached-native-object'),locator=b('original-lto.o'))
        before['sequence']=len(self.f.events)+1;before['payload']['prior_event_count']=len(self.f.events);self.f.events.append(before)
        v=self.f.decode();self.assertEqual(len(v['original_lto_pre_codegen_modules']),1);self.assertTrue(any(g['kind']=='cached_lto_phase_unqualified' for g in v['gaps']))
    def test_dropped_lto_native_ir_no_false_equivalence(self):
        before=self.f.events.pop();self.f.add('lto_object',task=0,cache_hit=False,buffer=self.f.blob(b'original-native-only'),locator=b('actual-lto.o'))
        before['sequence']=len(self.f.events)+1;before['payload']['prior_event_count']=len(self.f.events);self.f.events.append(before)
        v=self.f.decode();self.assertFalse(v['lto_machine_equivalence_verified']);self.assertEqual(v['original_lto_pre_codegen_modules'],[])
    def test_worker_integration_missing_hook_is_gap_not_linker_replacement(self):
        import link_integration as I
        native=self.f.json('complete-attempt.json',{'spawn_seed':self.f.seed})
        original={'native_attempts':[{'record':native,'observed_result':{'exit_code':1}}],'producer_units':[]}
        root=self.f.path/'empty-owned-link-root';root.mkdir()
        finalized=I.finalize_root(root,self.f.path/'root-manifest.json')
        value=I.collect(finalized,original,producer_readmission=lambda v:v,registration=self.f.reg,trusted_registration_sha256=self.f.reg['sha256'],archive_helper=D.info(HELPER),trusted_archive_helper_sha256=HELPER_SHA,packet_manifests={})
        self.assertEqual(value['linked_input_candidates'],[]);self.assertEqual(value['gaps'][0]['original_observed_result'],{'exit_code':1});self.assertFalse(value['rustc_outputs_modified']);self.assertFalse(value['saved_cgus_modified'])
    def test_worker_original_root_manifest_drop_rejects(self):
        import link_integration as I
        root=self.f.path/'owned-link-root';root.mkdir();(root/'original-resource').write_bytes(b'original')
        manifest=I.finalize_root(root,self.f.path/'root-manifest.json');v=D.record(manifest);v['files']=[];(self.f.path/'root-manifest.json').write_text(json.dumps(v))
        with self.assertRaisesRegex(D.LinkEvidenceError,'root_manifest'):I.collect(D.info(self.f.path/'root-manifest.json'),{'native_attempts':[]},producer_readmission=lambda v:v,registration=self.f.reg,trusted_registration_sha256=self.f.reg['sha256'],archive_helper=D.info(HELPER),trusted_archive_helper_sha256=HELPER_SHA,packet_manifests={})
    def test_unobserved_native_descendants_cannot_become_complete(self):
        v=self.f.decode();self.assertFalse(v['driver_trace_packet_bound']);self.assertFalse(v['actual_driver_descendants_verified'])
    def test_trust_registry_mismatch_rejects(self):
        with self.assertRaisesRegex(D.LinkEvidenceError,'registration_trust'):D.decode(self.f.write(),self.f.context,self.f.reg,trusted_registration_sha256='0'*64,archive_helper=D.info(HELPER),trusted_archive_helper_sha256=HELPER_SHA)

class StageBarrierTests(unittest.TestCase):
    def test_source_registration_is_not_a_version_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(tmp);v=D.record(f.reg);v['source_revision']='other-source'
            changed=f.json('wrong-registration.json',v)
            with self.assertRaisesRegex(D.LinkEvidenceError,'registration'):D.decode(f.write(),f.context,changed,trusted_registration_sha256=changed['sha256'],archive_helper=D.info(HELPER),trusted_archive_helper_sha256=HELPER_SHA)
    def test_dynamic_provider_sources_not_admitted_by_link_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            v=Fixture(tmp).decode(observed_linker_status=0)
        self.assertFalse(v['source_hook_build_and_execution_qualified'])
        self.assertFalse(v['selected_provider_source_closure_complete'])
        self.assertFalse(v['ordered_full_program_dependency_closure_complete'])

class DescendantProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.f=Fixture(self.temp.name)
        f=self.f
        trace_seed=f.json('trace-seed.json',{'schema':'authored-tracer-seed','invocation':'authored-one'})
        ctx=D.record(f.context);ctx['driver_trace_seed']=trace_seed;f.context=f.json('context.json',ctx);f.p(1)['context']=f.blob(Path(f.context['path']).read_bytes());f.prune_blobs()
        worker=f.artifact('trace-worker.py',b'authored-tracer-protocol-not-executed')
        driver=f.artifact('original-selected-cc',b'authored driver image')
        attempt=f.json('actual-spawn-complete.json',{'spawn_seed':f.seed})
        command={'program_bytes':b('/original/cc'),'argv_bytes':[b('-o'),b('original-output')],'cwd_bytes':b(str(f.path))}
        self.original={'producer_units':[],'native_output_scopes':[{'output_scope_id':'authored-output','record':attempt,'output_at_scope_close':{'retained':f.p(f.finish)['output']}}],'native_attempts':[{'record':attempt,'output_scope_id':'authored-output','child_pid':60,'executed_command':command,'observed_result':{'exit_code':0}}]}
        self.trace={'schema':'ocore-native-driver-trace-v1','worker':worker,'seed':trace_seed,'rust_spawn_seed':f.seed,'nodes':[
          {'id':'original-cc','parent':None,'pid':60,'generation':1,'executable':driver,'argv':[command['program_bytes'],*command['argv_bytes']],'cwd':command['cwd_bytes'],'observed_status':0},
          {'id':'actual-lld','parent':'original-cc','pid':70,'generation':2,'executable':f.image,'argv':f.p(1)['process_argv'],'cwd':f.p(1)['cwd'],'observed_status':0}]}
    def tearDown(self):self.temp.cleanup()
    def run_decode(self):
        trace=self.f.json('driver-trace.json',self.trace)
        return self.f.decode(producer_observation=self.original,producer_readmission=lambda value:value,driver_trace=trace,trusted_trace_worker_sha256=self.trace['worker']['sha256'])
    def test_authored_driver_packet_binding_does_not_claim_execution(self):
        value=self.run_decode();self.assertTrue(value['driver_trace_packet_bound']);self.assertFalse(value['actual_driver_descendants_verified'])
    def test_wrong_actual_ancestor_rejects(self):
        self.trace['nodes'][0]['pid']=61
        with self.assertRaisesRegex(D.LinkEvidenceError,'ancestry'):self.run_decode()
    def test_changed_original_selected_driver_argv_rejects(self):
        self.trace['nodes'][0]['argv'][0]=b('/other/clang')
        with self.assertRaisesRegex(D.LinkEvidenceError,'selected driver command differs'):self.run_decode()
    def test_changed_lld_image_rejects(self):
        self.trace['nodes'][1]['executable']=self.f.artifact('other-lld',b'different linker')
        with self.assertRaisesRegex(D.LinkEvidenceError,'source session absent'):self.run_decode()
    def test_changed_lld_waited_status_rejects(self):
        self.trace['nodes'][1]['observed_status']=1
        with self.assertRaisesRegex(D.LinkEvidenceError,'waited status differs'):self.run_decode()
    def test_context_from_another_original_attempt_rejects(self):
        self.trace['rust_spawn_seed']=self.f.json('other-spawn.json',{'other':'pending'})
        with self.assertRaisesRegex(D.LinkEvidenceError,'detached original driver ancestry'):self.run_decode()
    def test_parent_generation_not_observed_rejects(self):
        self.trace['nodes'][1]['parent']='missing-native-parent'
        with self.assertRaisesRegex(D.LinkEvidenceError,'parent not observed'):self.run_decode()
if __name__=='__main__':unittest.main()
