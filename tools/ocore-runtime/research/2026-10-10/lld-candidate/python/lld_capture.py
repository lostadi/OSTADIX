#!/usr/bin/env python3
"""Strict source-issued LLD occurrence decoder, never whole-program admission.

External trusted registries choose code/image/source bindings. A packet's own
registered=True, successful link, path, timestamp or basename is never authority.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re

REVISION = 'dcc3606807c989700e0ac1cac18c31741bcd40d9'
FLAGS = {key: False for key in ('actual_driver_descendants_verified',
    'source_production_inventory_complete', 'selected_provider_source_closure_complete',
    'ordered_full_program_dependency_closure_complete', 'lto_machine_equivalence_verified',
    'ocore_lowering_complete', 'whole_original_compiler_ocore_lowered', 'runtime_complete')}
class LinkEvidenceError(ValueError):
    def __init__(self, kind, reason):
        self.kind = kind
        super().__init__(f'{kind}: {reason}')
def require(test, kind, reason):
    if not test: raise LinkEvidenceError(kind, reason)
def exact(value, fields, where):
    require(isinstance(value, dict) and set(value) == set(fields.split()), 'wire_fields', where)
def integer(value, where, minimum=0):
    require(type(value) is int and value >= minimum, 'integer', where)
    return value
def boolean(value, where):
    require(type(value) is bool, 'boolean', where)
def raw(value):
    require(isinstance(value, list) and all(type(x) is int and 0 <= x <= 255 for x in value), 'raw_bytes', 'not exact byte array')
    return bytes(value)
def argv(value):
    require(isinstance(value, list), 'argv', 'not array')
    for word in value:
        if word is not None: raw(word)
def info(path):
    p=Path(path).absolute(); data=p.read_bytes()
    return {'path':str(p), 'sha256':hashlib.sha256(data).hexdigest(), 'bytes':len(data)}
def checked(ref):
    require(isinstance(ref, dict) and set(ref) in ({'path','sha256','bytes'},{'path','path_bytes','sha256','bytes'}), 'artifact', 'fields differ')
    integer(ref['bytes'],'artifact bytes')
    require(isinstance(ref['sha256'],str) and re.fullmatch('[0-9a-f]{64}',ref['sha256']), 'artifact', 'hash invalid')
    require(isinstance(ref['path'],str) and Path(ref['path']).is_absolute(), 'artifact', 'locator not absolute')
    if 'path_bytes' in ref:
        locator=raw(ref['path_bytes'])
        require(b'\0' not in locator and locator.decode('utf-8','replace')==ref['path'], 'artifact', 'raw/display path differ')
        path=Path(os.fsdecode(locator))
    else: path=Path(ref['path'])
    data=path.read_bytes()
    require(len(data)==ref['bytes'] and hashlib.sha256(data).hexdigest()==ref['sha256'], 'artifact_changed',str(path))
    return data

def json_bytes(data):
    def unique(pairs):
        value={}
        for key, child in pairs:
            require(key not in value, 'duplicate_json_key',key);value[key]=child
        return value
    return json.loads(data,object_pairs_hook=unique)
def record(ref):
    value=json_bytes(checked(ref));require(isinstance(value,dict),'wire','not object');return value

def same_ref(a,b):
    if not same_bytes(a,b):return False
    ar=raw(a['path_bytes']) if 'path_bytes' in a else os.fsencode(a['path'])
    br=raw(b['path_bytes']) if 'path_bytes' in b else os.fsencode(b['path'])
    return ar==br

def same_bytes(a,b):
    return a is not None and b is not None and (a['bytes'],a['sha256'])==(b['bytes'],b['sha256'])

def manifest(root, output):
    """Finalizer must be hashed in the original capture journal, after wait."""
    root=Path(root).absolute(); out=Path(output).absolute()
    require(root not in out.parents,'manifest','manifest must be outside packet root')
    files=[]
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(),'packet_symlink',str(path))
        if path.is_file(): files.append({'relative':str(path.relative_to(root)),'artifact':info(path)})
    value={'schema':'ocore-lld-elf-packet-manifest-v1','root':str(root),'files':files}
    out.write_text(json.dumps(value,indent=2)+'\n');return info(out)

PAYLOAD_FIELDS={
 'session':'source_revision context pid cwd executable_locator executable incoming_argv process_argv process_argv_snapshot',
 'read':'role locator buffer', 'arguments':'phase argv',
 'argument':'option_id index spelling rendered values',
 'script':'role locator read_event buffer',
 'script_include':'parent child operand parent_locator child_locator',
 'script_operand':'parent_operand_id operand source source_locator',
 'input':'locator buffer read_event script_operand_id with_l_option whole_archive start_lib in_group group_id static as_needed',
 'archive_member':'input_id physical_index header_offset data_offset raw_name name thin archive buffer member_locator',
 'file':'input_id member_id kind group_id lazy buffer source_range',
 'unbound_file':'kind locator buffer', 'extract':'file_id symbol', 'selected':'file_id',
 'lto_ir':'task phase module_id triple data_layout bitcode',
 'lto_object':'task cache_hit buffer locator',
 'gap':'kind reason',
 'finish':'prior_event_count capture_write_failed source_return_success source_error_count output_locator output emachine elf_kind configuration_read shared relocatable symbols providers versions'}

def validate_payload(kind,p):
    require(kind in PAYLOAD_FIELDS,'unknown_event',kind);exact(p,PAYLOAD_FIELDS[kind],kind)
    for field in ('pid','option_id','index','read_event','group_id','input_id','member_id','kind','file_id','physical_index','header_offset','data_offset','task','prior_event_count','source_error_count','emachine','elf_kind','script_operand_id','parent_operand_id'):
        if field in p and not (kind=='gap' and field=='kind'): integer(p[field],kind+'.'+field)
    for field in ('with_l_option','whole_archive','start_lib','in_group','static','as_needed','thin','lazy','cache_hit','capture_write_failed','source_return_success','configuration_read','shared','relocatable'):
        if field in p:boolean(p[field],field)
    for field in ('cwd','executable_locator','locator','spelling','rendered','raw_name','name','member_locator','symbol','module_id','triple','data_layout','output_locator','operand','source_locator','parent_locator','child_locator'):
        if field in p:raw(p[field])
    for field in ('incoming_argv','argv','process_argv'):
        if field in p and p[field] is not None:argv(p[field])
    if 'values' in p:
        require(isinstance(p['values'],list),'wire','values not array')
        for x in p['values']:raw(x)
    for field in ('buffer','archive','bitcode','context','executable','output','process_argv_snapshot','parent','child','source'):
        if field in p and p[field] is not None:checked(p[field])
    if kind in ('file','unbound_file'):require(p['kind']<=4,'file','original InputFile kind invalid')
    if 'source_range' in p and p['source_range'] is not None:
        exact(p['source_range'],'offset bytes','source_range')
        integer(p['source_range']['offset'],'offset');integer(p['source_range']['bytes'],'bytes')
    if kind=='gap':
        require(all(isinstance(p[x],str) for x in ('kind','reason')),'wire','gap not text')
    if kind=='finish':
        require(p['emachine']<=65535 and p['elf_kind']<=4,'target','original target enum invalid')
        for field in ('symbols','providers','versions'):
            require(isinstance(p[field],list),'wire',field)
        for s in p['symbols']:
            exact(s,'name kind file_id binding type visibility version_id used preemptible','symbol');raw(s['name'])
            for f in ('kind','file_id','binding','type','visibility','version_id'):integer(s[f],f)
            require(s['kind']<=5 and s['binding']<=15 and s['type']<=15 and s['visibility']<=3 and s['version_id']<=65535,'symbol','original symbol enum/bit fields invalid')
            boolean(s['used'],'used');boolean(s['preemptible'],'preemptible')
        for s in p['providers']:
            exact(s,'file_id soname needed dt_needed','provider');integer(s['file_id'],'file_id');raw(s['soname']);boolean(s['needed'],'needed')
            require(isinstance(s['dt_needed'],list),'wire','dt_needed')
            for n in s['dt_needed']:raw(n)
        for v in p['versions']:
            exact(v,'id name local global','version');integer(v['id'],'id');raw(v['name'])
            for f in ('local','global'):
                require(isinstance(v[f],list),'wire','version patterns')
                for n in v[f]:
                    exact(n,'name extern_cpp wildcard','version pattern');raw(n['name']);boolean(n['extern_cpp'],'extern_cpp');boolean(n['wildcard'],'wildcard')

def load_helper(ref,expected_sha):
    require(ref['sha256']==expected_sha,'helper_trust','archive helper differs from registry')
    namespace={'__name__':'ocore_lld_member_readmission','__file__':ref['path']}
    exec(compile(checked(ref),ref['path'],'exec'),namespace)
    return namespace

def decode(manifest_ref,context_ref,registration_ref,*,trusted_registration_sha256,
           archive_helper, trusted_archive_helper_sha256, producer_observation=None,
           producer_readmission=None, driver_trace=None, trusted_trace_worker_sha256=None,
           observed_linker_status=None):
    """Decode link occurrences; a successful return never fills remaining edges."""
    require(registration_ref['sha256']==trusted_registration_sha256,'registration_trust','caller registry differs')
    reg=record(registration_ref)
    exact(reg,'schema source_revision source_patch linker_image hook_source_manifest scope','registration')
    require(reg['schema']=='ocore-lld-hook-registration-v1' and reg['source_revision']==REVISION,'registration','wrong source profile')
    for f in ('source_patch','linker_image','hook_source_manifest'):checked(reg[f])
    ctx=record(context_ref)
    exact(ctx,'schema packet_directory invocation_id rust_spawn_seed linker_registration driver_trace_seed','context')
    require(ctx['schema']=='ocore-lld-link-context-v1' and same_ref(ctx['linker_registration'],registration_ref),'context','unregistered context')
    require(isinstance(ctx['invocation_id'],str) and ctx['invocation_id'],'context','missing unique invocation')
    seed=record(ctx['rust_spawn_seed'])
    require(seed.get('schema')=='ocore-rust-native-link-spawn-v1' and seed.get('observation')=='original_driver_spawn_prepared','rust_seed','not original pending spawn')
    if ctx['driver_trace_seed'] is not None:checked(ctx['driver_trace_seed'])
    helper=load_helper(archive_helper,trusted_archive_helper_sha256)
    packet=record(manifest_ref)
    exact(packet,'schema root files','manifest')
    require(packet['schema']=='ocore-lld-elf-packet-manifest-v1' and packet['root']==ctx['packet_directory'],'manifest','wrong packet root')
    root=Path(packet['root']);require(root.is_absolute(),'manifest','root not absolute')
    require(isinstance(packet['files'],list),'manifest','files not array')
    files={};refs={}
    for item in packet['files']:
        exact(item,'relative artifact','manifest file')
        name=item['relative'];require(isinstance(name,str) and not Path(name).is_absolute() and '..' not in Path(name).parts,'manifest','unsafe relative locator')
        require(name not in files,'manifest','duplicate occurrence')
        require(Path(item['artifact']['path'])==root/name,'manifest','detached file')
        files[name]=checked(item['artifact']);refs[name]=item['artifact']
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    require(actual==set(files),'manifest','dropped or added files')
    require(not any(p.is_symlink() for p in root.rglob('*')),'manifest','symlink packet')
    events=[];blobs=set()
    def check_snapshot(ref):
        if ref is None:return
        data=checked(ref);path=Path(ref['path'])
        require(root in path.parents and str(path.relative_to(root)) in files,'snapshot','not original finalized snapshot')
        relative=str(path.relative_to(root));require(relative=='blobs/'+ref['sha256'],'snapshot','not hash locator')
        require(files[relative]==data,'snapshot','snapshot bytes differ');blobs.add(relative)
    for name in sorted(files):
        if name.startswith('blobs/'):continue
        require(re.fullmatch(r'event-[0-9]{16}\.json',name),'manifest','unknown packet file')
        e=json_bytes(files[name]);exact(e,'schema sequence kind payload','event')
        require(e['schema']=='ocore-lld-elf-event-v1','wire','schema differs')
        require(e['sequence']==len(events)+1 and name==f"event-{e['sequence']:016}.json",'sequence','missing/reordered/duplicated source event')
        validate_payload(e['kind'],e['payload'])
        for f in ('buffer','archive','bitcode','context','executable','output','process_argv_snapshot','parent','child','source'):
            if f in e['payload']:check_snapshot(e['payload'][f])
        e['artifact']=refs[name];events.append(e)
    require(set(files)=={str(Path(e['artifact']['path']).relative_to(root)) for e in events}|blobs,'manifest','unreferenced or dropped resource')
    require(events and events[0]['kind']=='session' and events[-1]['kind']=='finish','lifecycle','missing original session/finish')
    require(sum(e['kind']=='session' for e in events)==1 and sum(e['kind']=='finish' for e in events)==1,'lifecycle','duplicate session/finish')
    session=events[0]['payload'];finish=events[-1]['payload']
    require(session['source_revision']==REVISION,'source','revision differs')
    if session['process_argv_snapshot'] is not None:
        original_cmdline=checked(session['process_argv_snapshot'])
        require(original_cmdline.endswith(b'\0') and [list(x) for x in original_cmdline[:-1].split(b'\0')]==session['process_argv'],'process_argv','original process bytes differ')
    else:
        require(session['process_argv'] is None,'process_argv','no original process byte snapshot')
    require(same_bytes(session['context'],context_ref),'context','original context bytes differ')
    require(same_bytes(session['executable'],reg['linker_image']),'linker_image','actual process image differs')
    require(Path(os.fsdecode(raw(session['executable_locator']))).resolve()==Path(reg['linker_image']['path']).resolve(),'linker_image','actual image locator not registered selected artifact')
    require(finish['prior_event_count']==len(events)-1 and finish['capture_write_failed'] is False,'lifecycle','capture incomplete')
    require(finish['source_return_success']==(finish['source_error_count']==0),'lifecycle','original return/error count differ')
    if observed_linker_status is not None:
        integer(observed_linker_status,'status')
        require((observed_linker_status==0)==finish['source_return_success'],'status','original waited status/source return differ')
    gaps=[{'kind':key} for key in ('actual_driver_descendant_trace_unobserved',
        'provider_source_production_unresolved','linker_local_symbol_relocation_requirements_unqualified',
        'complete_original_platform_and_source_dependency_closure_unqualified')]
    byid={e['sequence']:e for e in events};inputs=[];selected=[];extractions=[];extract_records=[];bound={};member_headers={};lto_ir=[];lto_objects=[]
    def prior(number,kind,current):
        require(number in byid and number<current and byid[number]['kind'] in kind.split(),'reference','wrong/missing/forward event edge')
        return byid[number]['payload']
    for e in events:
        n,k,p=e['sequence'],e['kind'],e['payload']
        if k=='input':
            read=prior(p['read_event'],'read',n)
            require(read['role']=='read_file' and same_bytes(read['buffer'],p['buffer']),'input','detached original read')
            if p['script_operand_id']:prior(p['script_operand_id'],'script_operand',n)
            inputs.append({'occurrence_id':n,'source_record':e['artifact'],**p})
        elif k=='script_operand':
            original_sources=[x['payload']['buffer'] for x in events[:n-1] if x['kind'] in ('read','script')]
            require(any(same_bytes(source,p['source']) for source in original_sources),'script','operand source not retained by original parser')
            if p['parent_operand_id']:prior(p['parent_operand_id'],'script_operand',n)
        elif k=='script_include':
            original_reads=[x['payload']['buffer'] for x in events[:n-1] if x['kind']=='read']
            require(all(any(same_bytes(source,p[field]) for source in original_reads) for field in ('parent','child')),'script','include resources not original reads')
        elif k=='script':
            if p['read_event']:
                read=prior(p['read_event'],'read',n)
                require(same_bytes(read['buffer'],p['buffer']),'script','detached source read')
            require(p['role'] in ('linker_script','version_script','dynamic_list','defsym'),'script','role differs')
        elif k=='archive_member':
            inp=prior(p['input_id'],'input',n)
            require(same_bytes(inp['buffer'],p['archive']),'archive','container differs')
            key=(p['input_id'],p['header_offset']);require(key not in member_headers,'archive','duplicate member occurrence within input');member_headers[key]=n
            data=checked(p['archive']); obj=checked(p['buffer'])
            if p['thin']:
                require(data.startswith(b'!<thin>\n'),'archive','thin flag differs')
                gaps.append({'kind':'thin_archive_external_range_unqualified','member_record':e['artifact']})
            else:
                try:members=helper['archive_members'](data)
                except Exception as err:raise LinkEvidenceError('archive',str(err)) from err
                candidates=[x for x in members if x['header_offset']==p['header_offset']]
                require(len(candidates)==1,'archive','not a real original member header')
                m=candidates[0]
                require(m['physical_index']==p['physical_index'] and m['data_offset']==p['data_offset'] and m['name_bytes']==p['name'] and m['bytes']==len(obj) and m['sha256']==p['buffer']['sha256'],'archive','member identity/range/bytes differ')
                require(data[p['header_offset']:p['header_offset']+16].rstrip(b' ')==raw(p['raw_name']),'archive','raw member header differs')
        elif k=='file':
            source=prior(p['member_id'],'archive_member',n) if p['member_id'] else prior(p['input_id'],'input',n)
            if p['member_id']:require(source['input_id']==p['input_id'],'file','member belongs to different input occurrence')
            span=p['source_range'];require(span is not None,'source_range','original input buffer relationship absent')
            data=checked(source['buffer']);actual_buffer=checked(p['buffer'])
            require(span['bytes']==len(actual_buffer) and span['offset']<=len(data) and span['bytes']<=len(data)-span['offset'] and data[span['offset']:span['offset']+span['bytes']]==actual_buffer,'source_range','detached derived input buffer')
            bound[n]=p
        elif k=='unbound_file':
            gaps.append({'kind':'unbound_source_input_or_linker_internal','source_record':e['artifact']})
        elif k=='extract':
            f=prior(p['file_id'],'file unbound_file',n)
            if byid[p['file_id']]['kind']=='file':require(f['lazy'] is True,'extraction','nonlazy input extraction')
            require(p['file_id'] not in extractions,'extraction','same lazy occurrence extracted twice');extractions.append(p['file_id']);extract_records.append(e['artifact'])
        elif k=='selected':
            f=prior(p['file_id'],'file unbound_file',n)
            require(p['file_id'] not in [s['file_id'] for s in selected],'selection','same input selected twice')
            if byid[p['file_id']]['kind']=='file' and f['lazy']:require(p['file_id'] in extractions,'selection','lazy selection without original extract')
            selected.append({'file_id':p['file_id'],'selection_index':len(selected),'source_record':e['artifact'], 'file_record':byid[p['file_id']]['artifact'], 'buffer':f['buffer'],'source_production_owned':False})
        elif k=='lto_object':
            lto_objects.append({'source_record':e['artifact'],**p})
            gaps.append({'kind':'cached_lto_phase_unqualified' if p['cache_hit'] else 'lto_native_codegen_semantics_unqualified','source_record':e['artifact']})
        elif k=='lto_ir':
            lto_ir.append({'source_record':e['artifact'],**p})
            require(p['phase']=='original_pre_codegen_module','lto','phase differs')
            require(checked(p['bitcode']).startswith((b'BC\xc0\xde',b'\xde\xc0\x17\x0b')),'lto','not original bitcode bytes')
        elif k=='arguments':require(p['phase'] in ('response_expanded','plugin_options_normalized'),'arguments','phase differs')
        elif k=='gap':gaps.append({'kind':p['kind'],'source_record':e['artifact'],'reason':p['reason']})
    for s in finish['symbols']:
        if s['file_id']:prior(s['file_id'],'file unbound_file lto_object',events[-1]['sequence'])
    for s in finish['providers']:
        prior(s['file_id'],'file unbound_file',events[-1]['sequence'])
        gaps.append({'kind':'dynamic_loader_provider_transitive_dependencies_unresolved','provider':s})
    # Join exact source-issued bytes; no path/stage/CGU-name inference. Both the
    # original Rust object and original LLD read are retained independently.
    joins=[]; verified=None; matching_attempts=[]; output_association=None
    if producer_observation is not None:
        require(callable(producer_readmission),'producer_trust','independent Rust readmission required')
        verified=producer_readmission(producer_observation)
        require(verified==producer_observation,'producer_trust','readmission changed observation')
        matching_attempts=[a for a in verified.get('native_attempts',[]) if same_ref(record(a['record']).get('spawn_seed'),ctx['rust_spawn_seed'])]
        require(len(matching_attempts)==1,'producer_trust','LLD context not attached uniquely to verified original Rust spawn')
        scopes=[s for s in verified.get('native_output_scopes',[]) if s['output_scope_id']==matching_attempts[0]['output_scope_id']]
        require(len(scopes)==1,'output_scope','original attempted native output scope absent or ambiguous')
        scoped=scopes[0]['output_at_scope_close']
        scoped_ref=scoped['retained'] if scoped is not None else None
        output_association={'output_scope_id':scopes[0]['output_scope_id'],'source_record':scopes[0]['record'],
            'original_scope_output':scoped_ref,'lld_output':finish['output'],
            'same_original_output_bytes':same_bytes(scoped_ref,finish['output'])}
        if not output_association['same_original_output_bytes']:
            gaps.append({'kind':'lld_output_not_identical_to_original_rust_scope_close','association':output_association})
        for item in selected:
            candidates=[]
            for u in verified.get('producer_units',[]):
                obj=u.get('retained_object') or u.get('object')
                if same_bytes(obj,item['buffer']):candidates.append(u)
            joins.append({'file_id':item['file_id'],'candidates':candidates,
                'unique_original_producer':len(candidates)==1,'source_production_ownership_complete':False})
            if len(candidates)!=1:gaps.append({'kind':'selected_input_without_unique_original_rust_producer','file_id':item['file_id']})
    else:gaps.append({'kind':'original_rust_producer_packet_join_unobserved'})
    # Tracer is a separate independently pinned implementation. Source PID and
    # environment locators alone never establish a cc/collect2/ld descendant.
    trace_bound=False
    if driver_trace is not None:
        require(verified is not None and ctx['driver_trace_seed'] is not None,'trace_trust','original Rust readmission/trace seed absent')
        trace=record(driver_trace)
        exact(trace,'schema worker seed rust_spawn_seed nodes','driver trace')
        require(trace['schema']=='ocore-native-driver-trace-v1' and trace['worker']['sha256']==trusted_trace_worker_sha256,'trace_trust','unregistered tracer')
        checked(trace['worker']);require(trace['seed']==ctx['driver_trace_seed'] and trace['rust_spawn_seed']==ctx['rust_spawn_seed'],'trace_trust','detached original driver ancestry')
        require(isinstance(trace['nodes'],list),'trace','nodes not array')
        nodes={}
        for node in trace['nodes']:
            exact(node,'id parent pid generation executable argv cwd observed_status','trace node')
            require(isinstance(node['id'],str) and node['id'] not in nodes,'trace','duplicate process generation')
            integer(node['pid'],'pid',1);integer(node['generation'],'generation');checked(node['executable']);argv(node['argv']);raw(node['cwd'])
            if node['parent'] is not None:require(node['parent'] in nodes,'trace','parent not observed before child')
            if node['observed_status'] is not None:integer(node['observed_status'],'status')
            nodes[node['id']]=node
        matches=[x for x in nodes.values() if x['pid']==session['pid'] and same_bytes(x['executable'],session['executable']) and x['argv']==session['process_argv'] and x['cwd']==session['cwd']]
        require(len(matches)==1,'trace','source session absent/ambiguous in actual exec generations')
        target=matches[0]
        ancestry=[target]
        while target['parent'] is not None:
            target=nodes[target['parent']];ancestry.append(target)
        attempt=matching_attempts[0]
        roots=[x for x in ancestry if x['pid']==attempt['child_pid']]
        require(len(roots)==1,'trace','original Rust waited native child absent from ancestry')
        command=attempt['executed_command']
        require(roots[0]['argv']==[command['program_bytes'],*command['argv_bytes']] and roots[0]['cwd']==command['cwd_bytes'],'trace','original selected driver command differs')
        if matches[0]['observed_status'] is not None:
            require((matches[0]['observed_status']==0)==finish['source_return_success'],'trace','LLD waited status differs')
        trace_bound=True
        # This candidate reader only binds packets. Kernel ptrace source and
        # original waited process status still need their independent gate.
        gaps.append({'kind':'driver_trace_implementation_execution_gate_pending'})
    result={'schema':'ocore-lld-original-link-observation-v1','manifest':manifest_ref,'context':context_ref,
        'registration':registration_ref,'original_linker_source_revision':REVISION,
        'ordered_input_occurrences':inputs,'selected_input_occurrences':selected,
        'actual_archive_extractions':extract_records,
        'original_lto_pre_codegen_modules':lto_ir,'original_lto_native_objects':lto_objects,
        'final_symbol_resolution':finish['symbols'],'final_dynamic_providers':finish['providers'],
        'final_version_rules':finish['versions'],'registration_scope':reg['scope'],
        'source_hook_build_and_execution_qualified':False,
        'source_return_success':finish['source_return_success'],
        'observed_linker_status':observed_linker_status,'original_output':finish['output'],
        'producer_joins':joins,'original_output_association':output_association,'driver_trace_packet_bound':trace_bound,
        'original_source_event_count':len(events),'gaps':gaps,**FLAGS}
    return result
