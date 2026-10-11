"""Artifact-only prospective worker integration; it never invokes native tools.

Call after the original compiler status and its source packets are finalized.
The existing producer reader and trusted LLD decoder must independently re-admit
all inputs. These link candidates stay outside rustc outputs/saved_cgus.
"""
import json
from pathlib import Path
import lld_capture as D

def finalize_root(root,output):
    root=Path(root).absolute();output=Path(output).absolute()
    D.require(root not in output.parents,'root_manifest','must be outside original source hook root')
    rows=[]
    for path in sorted(root.rglob('*')):
        D.require(not path.is_symlink(),'root_manifest','symlink source hook tree')
        if path.is_file():rows.append({'relative':str(path.relative_to(root)),'artifact':D.info(path)})
    output.write_text(json.dumps({'schema':'ocore-lld-original-root-manifest-v1','root':str(root),'files':rows},indent=2)+'\n')
    return D.info(output)

def collect(root_manifest,producer_observation,*,producer_readmission,registration,
            trusted_registration_sha256,archive_helper,trusted_archive_helper_sha256,
            packet_manifests,driver_traces=None,trusted_trace_worker_sha256=None):
    """Capture-journal-owned root+packet manifests are mandatory caller inputs."""
    D.require(callable(producer_readmission),'producer_trust','readmission required')
    original=producer_readmission(producer_observation)
    D.require(original==producer_observation,'producer_trust','producer observation changed')
    root=D.record(root_manifest);D.exact(root,'schema root files','root manifest')
    D.require(root['schema']=='ocore-lld-original-root-manifest-v1','root_manifest','schema differs')
    owned=Path(root['root']);D.require(owned.is_absolute(),'root_manifest','relative root')
    files={}
    for row in root['files']:
        D.exact(row,'relative artifact','root member');name=row['relative']
        D.require(isinstance(name,str) and not Path(name).is_absolute() and '..' not in Path(name).parts and name not in files,'root_manifest','duplicate/unsafe occurrence')
        D.require(Path(row['artifact']['path'])==owned/name,'root_manifest','detached root member')
        D.checked(row['artifact']);files[name]=row['artifact']
    D.require({str(p.relative_to(owned)) for p in owned.rglob('*') if p.is_file()}==set(files),'root_manifest','added/dropped original source packets')
    D.require(not any(p.is_symlink() for p in owned.rglob('*')),'root_manifest','symlink tree')
    contexts=[]
    for row in files.values():
        if not row['path'].endswith('.context.json'):continue
        ctx=D.record(row)
        D.require(Path(ctx['packet_directory']).parent==owned,'root_manifest','context packet directory not invocation owned')
        contexts.append(row)
    observations=[];gaps=[];seen=[]
    for context in contexts:
        ctx=D.record(context);root_path=ctx['packet_directory']
        D.require(root_path not in seen,'context','multiple context refs own same packet directory');seen.append(root_path)
        if root_path not in packet_manifests:
            gaps.append({'kind':'original_lld_packet_manifest_missing','context':context});continue
        try:
            observation=D.decode(packet_manifests[root_path],context,registration,
                trusted_registration_sha256=trusted_registration_sha256,
                archive_helper=archive_helper,trusted_archive_helper_sha256=trusted_archive_helper_sha256,
                producer_observation=original,producer_readmission=producer_readmission,
                driver_trace=(driver_traces or {}).get(root_path),
                trusted_trace_worker_sha256=trusted_trace_worker_sha256)
        except (D.LinkEvidenceError,OSError,ValueError) as err:
            gaps.append({'kind':'original_lld_packet_readmission_failed','context':context,'reason':str(err)})
        else:observations.append(observation)
    # Retain EVERY original attempt, including native failures and non-LLD
    # selected drivers. Missing hooks never select another linker or erase it.
    for attempt in original['native_attempts']:
        pending=D.record(attempt['record'])['spawn_seed']
        matches=[x for x in observations if D.same_ref(D.record(x['context'])['rust_spawn_seed'],pending)]
        if not matches:gaps.append({'kind':'selected_native_attempt_has_no_registered_lld_source_receipt','attempt_record':attempt['record'],'original_observed_result':attempt['observed_result']})
    D.require(set(packet_manifests)<=set(seen),'context','unowned packet manifest supplied')
    return {'schema':'ocore-rust-original-link-capture-v1','root_manifest':root_manifest,
        'original_producer_observation':producer_observation,'original_link_observations':observations,
        'linked_input_candidates':[{'link_context':x['context'],'input':i} for x in observations for i in x['selected_input_occurrences']],
        'gaps':gaps,'rustc_outputs_modified':False,'saved_cgus_modified':False,
        'original_program_replayed':False,**D.FLAGS}
