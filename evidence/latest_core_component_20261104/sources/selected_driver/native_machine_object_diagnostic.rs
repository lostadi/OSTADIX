//! Unqualified diagnostic assembly of complete typed machine units.
//! This never constructs a NativeModule, AdmittedCapture or complete artifact.
//! Configured original assembly is retained but is NEVER the assembler input.
use std::fs::{self,OpenOptions};
use std::io::{self,Write};
use std::path::{Path,PathBuf};
use std::process::{Command,Output,Stdio};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use super::{driver_error,monotonic_nonce,object_assembler_command,selected_object_assembler};
use super::super::{common::{Diagnostic,Target},native_machine_emit::{plan_unit,MachineAssemblyPlan},native_machine_ir::{ArtifactIdentity,MachineProfile},native_machine_unit::{MachineUnit,UnitSelection}};

fn identity(bytes:&[u8])->ArtifactIdentity{ArtifactIdentity{bytes:bytes.len()as u64,sha256:hex::encode(Sha256::digest(bytes))}}
fn error(text:impl Into<String>)->Diagnostic{driver_error(format!("typed-machine diagnostic: {}",text.into()))}
struct PreparedInputs<'a>{plan:MachineAssemblyPlan,unit_json:Vec<u8>,profile:MachineProfile,inventory:&'a[u8],configured:&'a[u8]}
// The production entry computes a new plan. This checked continuation also
// prevents any future cached plan from silently crossing to a different unit.
fn with_checked_plan<'a,T>(unit:&MachineUnit,plan:MachineAssemblyPlan,inventory:&'a[u8],configured:&'a[u8],target:Target,dispatch:impl FnOnce(PreparedInputs<'a>)->Result<T,Diagnostic>)->Result<T,Diagnostic>{
    if plan.assembler_target()!=target.triple(){return Err(error("requested assembler target differs from regenerated machine plan"));}
    plan.check_typed_unit(unit).map_err(error)?;
    let floor=identity(inventory);if plan.inventory!=floor||unit.selected_inventory!=floor{return Err(error("selected whole-unit inventory buffer differs from regenerated machine plan"));}
    let original=identity(configured);if plan.configured_assembly!=original||unit.source.decoded_assembly!=original{return Err(error("configured assembly buffer differs from regenerated machine plan"));}
    let unit_json=serde_json::to_vec(unit).map_err(|e|error(format!("retain typed unit: {e}")))?;
    if identity(&unit_json)!=plan.typed_unit_identity().encoded_unit{return Err(error("retained compact typed unit differs from plan encoding identity"));}
    dispatch(PreparedInputs{plan,unit_json,profile:unit.profile.clone(),inventory,configured})
}
fn assembler_command(prepared:&PreparedInputs<'_>,target:Target,clang:&Path,input:&Path,output:&Path)->Result<Command,Diagnostic>{
    if prepared.plan.assembler_target()!=target.triple(){return Err(error("requested assembler target differs from regenerated machine plan"));}
    let mut command=object_assembler_command(clang,target,Some(prepared.plan.assembler_abi()),true);
    command.arg(input).arg("-o").arg(output);Ok(command)
}
struct Observation{known:bool,exit:Option<i32>,success:bool,status:Option<String>,invocation_error:Option<String>,stdout:Option<Vec<u8>>,stderr:Option<Vec<u8>>,object:Option<Vec<u8>>,object_error:Option<String>}
fn observe_output(result:io::Result<Output>,read_object:impl FnOnce()->io::Result<Vec<u8>>)->Observation{
    match result{
        Err(e)=>Observation{known:false,exit:None,success:false,status:None,invocation_error:Some(format!("{}; kind={:?}; os={:?}",e,e.kind(),e.raw_os_error())),stdout:None,stderr:None,object:None,object_error:None},
        Ok(output)=>{let(object,object_error)=if output.status.success(){match read_object(){Ok(bytes)=>(Some(bytes),None),Err(e)=>(None,Some(e.to_string()))}}else{(None,Some("object not consumed after assembler nonzero or signal".into()))};Observation{known:true,exit:output.status.code(),success:output.status.success(),status:Some(output.status.to_string()),invocation_error:None,stdout:Some(output.stdout),stderr:Some(output.stderr),object,object_error}}
    }
}
impl Observation{
    fn metadata(&self)->Value{json!({"attempted":true,"completion_known":self.known,"exit_code":self.exit,"exit_success":self.success,"status":self.status,"launch_or_output_error":self.invocation_error,"stdout":self.stdout.as_deref().map(identity),"stderr":self.stderr.as_deref().map(identity),"raw_object":self.object.as_deref().map(identity),"object_read_error":self.object_error,"unknown_outputs_consumed":false,"descendant_quiescence_qualified":false})}
}
fn retain_new(path:&Path,bytes:&[u8])->Result<(),Diagnostic>{
    let mut file=OpenOptions::new().write(true).create_new(true).open(path).map_err(|e|error(format!("create {}: {e}",path.display())))?;
    file.write_all(bytes).and_then(|_|file.sync_all()).map_err(|e|error(format!("retain {}: {e}",path.display())))
}
fn retain_json(path:&Path,value:&Value)->Result<(),Diagnostic>{let bytes=serde_json::to_vec_pretty(value).map_err(|e|error(format!("encode diagnostic evidence: {e}")))?;retain_new(path,&bytes)}
fn observe_inputs(directory:&Path,inputs:&[(&str,&[u8])],phase:&str)->Result<(bool,Value),Diagnostic>{
    let mut exact=true;let mut rows=Vec::new();for(name,expected)in inputs{
        let path=directory.join(name);match fs::read(&path){
            Ok(actual)=>{let matches=actual.as_slice()==*expected;exact&=matches;let retained=if matches{None}else{let p=directory.join(format!("{phase}-{name}.observed"));retain_new(&p,&actual)?;Some(p)};rows.push(json!({"path":path,"expected":identity(expected),"observed":identity(&actual),"exact":matches,"mismatch_path":retained}));},
            Err(e)=>{exact=false;rows.push(json!({"path":path,"expected":identity(expected),"observed":null,"exact":false,"read_error":e.to_string()}));}
        }
    }Ok((exact,Value::Array(rows)))
}
/// An owned diagnostic observation, including captured raw buffers. Saved
/// evidence can be incomplete; inspect publication errors and status. No ELF is admitted.
pub struct MachineObjectDiagnostic{directory:PathBuf,receipt:Value,object:Option<Vec<u8>>,stdout:Option<Vec<u8>>,stderr:Option<Vec<u8>>}
impl MachineObjectDiagnostic{
    pub fn evidence_directory(&self)->&Path{&self.directory}
    pub fn receipt(&self)->&Value{&self.receipt}
    /// Raw observation only, never validated ELF or an admitted executable.
    pub fn raw_object(&self)->Option<&[u8]>{self.object.as_deref()}
    pub fn raw_stdout(&self)->Option<&[u8]>{self.stdout.as_deref()}
    pub fn raw_stderr(&self)->Option<&[u8]>{self.stderr.as_deref()}
    pub fn admitted(&self)->bool{false}
}
/// Recompute a whole-unit static plan and invoke the compiler-owned assembler
/// selection policy. This is a diagnostic raw-object boundary, not a source,
/// platform, ELF-format, provider, link or execution qualification boundary.
/// All current native selection is RV64 LP64/LP64D supported-subset only;
/// x86/AArch64 lifter DATA controls do not implement native machine emission.
pub fn diagnose_machine_unit_object(unit:&MachineUnit,selection:&UnitSelection,inventory:&[u8],configured:&[u8],target:Target,evidence_root:&Path)->Result<MachineObjectDiagnostic,Diagnostic>{
    let plan=plan_unit(unit,selection,inventory,configured,target).map_err(|failure|error(format!("whole-unit plan refused: {}",serde_json::to_string(&failure).unwrap_or_else(|e|format!("failure report serialization error: {e}; {failure:?}")))))?;
    with_checked_plan(unit,plan,inventory,configured,target,|prepared|run(prepared,target,evidence_root))
}
fn run(prepared:PreparedInputs<'_>,target:Target,evidence_root:&Path)->Result<MachineObjectDiagnostic,Diagnostic>{
    let root=evidence_root.canonicalize().map_err(|e|error(format!("resolve existing evidence root: {e}")))?;
    let directory=root.join(format!("machine-object-{}-{}",std::process::id(),monotonic_nonce()));
    let mut builder=fs::DirBuilder::new();#[cfg(unix)]{use std::os::unix::fs::DirBuilderExt;builder.mode(0o700);}builder.create(&directory).map_err(|e|error(format!("create exclusive diagnostic attempt: {e}")))?;
    let assembly=prepared.plan.assembly().as_bytes();
    let inputs=[("unit.machine.json",prepared.unit_json.as_slice()),("unit.inventory.json",prepared.inventory),("configured.s",prepared.configured),("selected.s",assembly)];
    for(name,bytes)in &inputs{retain_new(&directory.join(name),bytes)?;}
    let (before_exact,before)=observe_inputs(&directory,&inputs,"before")?;
    let (invoked,resolved,assembler_sha)=selected_object_assembler()?;
    let environment=(std::env::var_os("PATH"),std::env::var_os("LD_LIBRARY_PATH"));
    let output_path=directory.join("raw.o");let mut command=assembler_command(&prepared,target,&invoked,&directory.join("selected.s"),&output_path)?;command.current_dir(&directory);
    let argv=std::iter::once(command.get_program()).chain(command.get_args()).map(|a|a.to_str().map(str::to_owned).ok_or_else(||error("assembler argv is not lossless UTF-8"))).collect::<Result<Vec<_>,_>>()?;
    let invocation=json!({"format":"ocore-typed-machine-object-invocation-v1","source_unit_id":prepared.plan.source_unit_id,"target":target.name(),"assembler_target":target.triple(),"source_machine_profile":prepared.profile,"assembler_abi":prepared.plan.assembler_abi(),"typed_unit":prepared.plan.typed_unit_identity(),"inventory":identity(prepared.inventory),"configured":identity(prepared.configured),"selected_assembly":identity(assembly),"assembler_policy":"ocore-driver-which-clang-v1","assembler_invoked":invoked,"assembler_resolved":resolved,"assembler_sha256":assembler_sha,"argv":argv,"cwd":directory,"PATH":environment.0,"LD_LIBRARY_PATH":environment.1,"environment_observation_scope":"PATH and LD_LIBRARY_PATH only; other inherited environment unqualified","inputs_before":before,"input_file_guard_scope":"full-byte before/after observations, not sealed-file or TOCTOU proof","object_path":output_path,"original_source_semantic_admission":"UNMET","object_format_inventory":"UNMET_NOT_RUN","native_execution_qualified":false});
    retain_json(&directory.join("invocation.json"),&invocation)?;
    if !before_exact{let receipt=json!({"format":"ocore-typed-machine-object-diagnostic-v1","status":"not_launched_input_drift","attempted":false,"invocation":"invocation.json","object_format_inventory":"UNMET_NOT_RUN","original_source_semantic_admission":"UNMET","qualified":false});retain_json(&directory.join("receipt.json"),&receipt)?;return Ok(MachineObjectDiagnostic{directory,receipt,object:None,stdout:None,stderr:None});}
    let observed=observe_output(command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).output(),||fs::read(&output_path));
    // Command::output Err may follow an attempted launch or output capture.
    // It is not silently relabelled not-dispatched, known, or spawn_failed.
    let mut output_publication_errors:Vec<String>=Vec::new();
    if let Some(stdout)=&observed.stdout{if let Err(e)=retain_new(&directory.join("stdout"),stdout){output_publication_errors.push(e.to_string());}}
    if let Some(stderr)=&observed.stderr{if let Err(e)=retain_new(&directory.join("stderr"),stderr){output_publication_errors.push(e.to_string());}}
    let command_record=json!({"command_observation":observed.metadata(),"output_publication_errors":output_publication_errors});
    if let Err(e)=retain_json(&directory.join("command-observation.json"),&command_record){output_publication_errors.push(e.to_string());}
    let (stable,after,assembler_after)=if observed.known{
        let(exact,after)=match observe_inputs(&directory,&inputs,"after"){Ok(value)=>value,Err(e)=>(false,json!({"observation_error":e.to_string()}))};
        let after_tool=selected_object_assembler();let stable=after_tool.as_ref().is_ok_and(|v|v==&(invoked.clone(),resolved.clone(),assembler_sha.clone()))&&environment==(std::env::var_os("PATH"),std::env::var_os("LD_LIBRARY_PATH"));
        let tool=match after_tool{Ok((a,b,c))=>json!({"invoked":a,"resolved":b,"sha256":c}),Err(e)=>json!({"error":e.to_string()})};(exact&&stable,after,tool)
    }else{(false,Value::Null,Value::Null)};
    let status=if !observed.known{"completion_UNKNOWN"}else if !output_publication_errors.is_empty(){"output_publication_failed"}else if !observed.success{"assembler_nonzero_or_signal"}else if !stable{"input_or_tool_drift"}else if observed.object.is_none(){"assembler_zero_object_missing"}else{"raw_object_retained_format_validation_UNMET"};
    let mut receipt=json!({"format":"ocore-typed-machine-object-diagnostic-v1","status":status,"invocation":"invocation.json","command_observation":observed.metadata(),"output_publication_errors":output_publication_errors,"inputs_after":after,"assembler_after":assembler_after,"input_and_selected_tool_observations_stable":stable,"selector_scope":"RV64 LP64/LP64D static supported subset; complete unsupported records refuse before dispatch","original_source_semantic_admission":"UNMET","object_format_inventory":"UNMET_NOT_RUN","generated_relocation_inventory":"UNMET_NOT_RUN","provider_closure":"UNMET","final_link_and_artifact":"UNMET","CFI_stack_restore_and_provider_realization":"UNMET","assembler_execution_byte_custody_qualified":false,"assembler_library_and_environment_closure_qualified":false,"descendant_quiescence_qualified":false,"native_decoder_CPU_and_all_ISA_execution_qualified":false,"qualified":false});
    publish_diagnostic_receipt(&directory,&mut receipt);Ok(retained_diagnostic(directory,receipt,observed))
}
#[cfg(test)]
#[path="native_machine_object_diagnostic_tests.rs"]
mod tests;


// Explicit selected-operation source identity and invocation contract.
// These are requests and source-stability observations, not exec/admission proof.
use std::ffi::{OsStr, OsString};
use std::io::{Read as SelectedRead, Seek as SelectedSeek, SeekFrom as SelectedSeekFrom};

pub const SELECTED_MACHINE_ASSEMBLER_PROFILE: &str =
    "ocore-clang-rv64gc-static-map-env-v1";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
struct SelectedMachineFileStat {
    dev:u64, ino:u64, bytes:u64, mode:u32, nlink:u64, uid:u32, gid:u32,
    mtime:i64, mtime_ns:i64, ctime:i64, ctime_ns:i64,
}
fn selected_file_stat(m:&fs::Metadata)->Result<SelectedMachineFileStat,Diagnostic>{
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        Ok(SelectedMachineFileStat{dev:m.dev(),ino:m.ino(),bytes:m.len(),
            mode:m.mode(),nlink:m.nlink(),uid:m.uid(),gid:m.gid(),
            mtime:m.mtime(),mtime_ns:m.mtime_nsec(),ctime:m.ctime(),ctime_ns:m.ctime_nsec()})
    }
    #[cfg(not(unix))] { let _=m;Err(error("selected assembler operation requires the Unix byte/identity profile")) }
}
fn selected_os_bytes(value:&OsStr)->Result<Vec<u8>,Diagnostic>{
    #[cfg(unix)] { use std::os::unix::ffi::OsStrExt;Ok(value.as_bytes().to_vec()) }
    #[cfg(not(unix))] { let _=value;Err(error("selected assembler operation requires the Unix byte codec")) }
}
fn selected_os_record(value:&OsStr)->Result<Value,Diagnostic>{
    Ok(json!({"encoding":"unix-os-bytes-v1","bytes":selected_os_bytes(value)?}))
}

/// Held source image selection only. No Deserialize or public field constructor.
/// This does not establish the actual executed child image, libraries or helpers.
pub struct MachineAssemblerImageSelection {
    invoked:PathBuf, resolved:PathBuf, identity:ArtifactIdentity,
    stat:SelectedMachineFileStat, file:std::sync::Mutex<fs::File>,
}
impl MachineAssemblerImageSelection {
    pub fn select(invoked:&Path,expected_resolved:&Path,expected:&ArtifactIdentity)->Result<Self,Diagnostic>{
        if !invoked.is_absolute()||!expected_resolved.is_absolute(){
            return Err(error("selected assembler paths must be explicitly absolute"));
        }
        let resolved=invoked.canonicalize().map_err(|e|error(format!("resolve explicit assembler: {e}")))?;
        if resolved!=expected_resolved{
            return Err(error("selected assembler canonical path differs from held request"));
        }
        let named=fs::symlink_metadata(&resolved).map_err(|e|error(format!("stat explicit assembler: {e}")))?;
        if !named.is_file(){return Err(error("selected assembler source image is not a regular file"));}
        let stat=selected_file_stat(&named)?;
        if stat.mode&0o111==0{return Err(error("selected assembler source image lacks executable mode"));}
        let mut file=fs::File::open(&resolved).map_err(|e|error(format!("open explicit assembler: {e}")))?;
        if selected_file_stat(&file.metadata().map_err(|e|error(e.to_string()))?)?!=stat{
            return Err(error("selected assembler named/held identity differs"));
        }
        let mut raw=Vec::new();
        file.read_to_end(&mut raw).map_err(|e|error(format!("read explicit assembler: {e}")))?;
        if identity(&raw)!=*expected{return Err(error("selected assembler bytes differ from held request"));}
        let selected=Self{invoked:invoked.to_path_buf(),resolved,identity:expected.clone(),
            stat,file:std::sync::Mutex::new(file)};
        selected.check()?;
        Ok(selected)
    }
    pub fn invoked(&self)->&Path{&self.invoked}
    pub fn resolved(&self)->&Path{&self.resolved}
    pub fn identity(&self)->&ArtifactIdentity{&self.identity}
    fn check(&self)->Result<(),Diagnostic>{
        if self.invoked.canonicalize().map_err(|e|error(format!("resolve selected assembler again: {e}")))?!=self.resolved{
            return Err(error("selected assembler alias target changed"));
        }
        let named=fs::symlink_metadata(&self.resolved).map_err(|e|error(format!("stat selected assembler again: {e}")))?;
        if !named.is_file()||selected_file_stat(&named)?!=self.stat{
            return Err(error("selected assembler named physical identity changed"));
        }
        let mut file=self.file.lock().map_err(|_|error("selected assembler held-file lock poisoned"))?;
        if selected_file_stat(&file.metadata().map_err(|e|error(e.to_string()))?)?!=self.stat{
            return Err(error("selected assembler held physical identity changed"));
        }
        file.seek(SelectedSeekFrom::Start(0)).map_err(|e|error(e.to_string()))?;
        let mut raw=Vec::new();file.read_to_end(&mut raw).map_err(|e|error(e.to_string()))?;
        if identity(&raw)!=self.identity
            ||selected_file_stat(&file.metadata().map_err(|e|error(e.to_string()))?)?!=self.stat
            ||selected_file_stat(&fs::symlink_metadata(&self.resolved).map_err(|e|error(e.to_string()))?)?!=self.stat{
            return Err(error("selected assembler source bytes/identity changed"));
        }
        Ok(())
    }
    fn observation(&self)->Result<Value,Diagnostic>{
        Ok(json!({"invoked":selected_os_record(self.invoked.as_os_str())?,
            "resolved":selected_os_record(self.resolved.as_os_str())?,
            "identity":self.identity,"physical":self.stat,
            "scope":"same-held source bytes and named identity; no atomic exec or child-image proof",
            "execution_custody_qualified":false}))
    }
}

/// Complete explicit environment mapping, with requested sequence retained.
/// Command's actual configured sequence is retained separately. No original
/// raw-environ-order or source/platform admission is inferred from this request.
pub struct MachineAssemblerOperationRequest<'a> {
    pub image:&'a MachineAssemblerImageSelection,
    pub cwd:&'a Path,
    pub environment:&'a [(OsString,OsString)],
    pub command_profile:&'a str,
    pub expected_assembler_target:&'a str,
    pub expected_assembler_abi:&'a str,
    pub expected_machine_profile:&'a MachineProfile,
}
fn selected_environment(entries:&[(OsString,OsString)])->Result<Value,Diagnostic>{
    let mut seen=std::collections::BTreeSet::new();let mut rows=Vec::new();
    for(key,value)in entries{
        let key_bytes=selected_os_bytes(key)?;let value_bytes=selected_os_bytes(value)?;
        if key_bytes.is_empty()||key_bytes.contains(&0)||key_bytes.contains(&b'='){
            return Err(error("selected environment key is empty or contains NUL or '='"));
        }
        if value_bytes.contains(&0){return Err(error("selected environment value contains NUL"));}
        if !seen.insert(key_bytes.clone()){return Err(error("selected environment contains a duplicate key"));}
        rows.push(json!({"key":{"encoding":"unix-os-bytes-v1","bytes":key_bytes},
            "value":{"encoding":"unix-os-bytes-v1","bytes":value_bytes}}));
    }
    Ok(Value::Array(rows))
}
struct SelectedOperationCwd {
    requested:PathBuf, resolved:PathBuf, dev:u64, ino:u64, mode:u32, uid:u32, gid:u32,
}
impl SelectedOperationCwd {
    fn select(path:&Path)->Result<Self,Diagnostic>{
        if !path.is_absolute(){return Err(error("selected assembler cwd must be explicitly absolute"));}
        let resolved=path.canonicalize().map_err(|e|error(format!("resolve explicit assembler cwd: {e}")))?;
        let named=fs::symlink_metadata(&resolved).map_err(|e|error(e.to_string()))?;
        if !named.is_dir(){return Err(error("selected assembler cwd is not a directory"));}
        let stat=selected_file_stat(&named)?;
        Ok(Self{requested:path.to_path_buf(),resolved,dev:stat.dev,ino:stat.ino,
            mode:stat.mode,uid:stat.uid,gid:stat.gid})
    }
    fn check(&self)->Result<(),Diagnostic>{
        if self.requested.canonicalize().map_err(|e|error(e.to_string()))?!=self.resolved{
            return Err(error("selected assembler cwd alias target changed"));
        }
        let named=fs::symlink_metadata(&self.resolved).map_err(|e|error(e.to_string()))?;
        let s=selected_file_stat(&named)?;
        if !named.is_dir()||(s.dev,s.ino,s.mode,s.uid,s.gid)!=(self.dev,self.ino,self.mode,self.uid,self.gid){
            return Err(error("selected assembler cwd physical identity changed"));
        }
        Ok(())
    }
    fn observation(&self)->Result<Value,Diagnostic>{
        Ok(json!({"requested":selected_os_record(self.requested.as_os_str())?,
            "resolved":selected_os_record(self.resolved.as_os_str())?,
            "dev":self.dev,"ino":self.ino,"mode":self.mode,"uid":self.uid,"gid":self.gid,
            "scope":"named directory identity; contents and chdir-to-held-dir are unqualified"}))
    }
}
struct SelectedOperationContext {
    cwd:SelectedOperationCwd, requested_environment:Value, image:Value, cwd_before:Value,
}
fn with_selected_operation<'a,T>(
    prepared:PreparedInputs<'a>,target:Target,operation:&MachineAssemblerOperationRequest<'_>,
    dispatch:impl FnOnce(PreparedInputs<'a>,SelectedOperationContext)->Result<T,Diagnostic>,
)->Result<T,Diagnostic>{
    if operation.command_profile!=SELECTED_MACHINE_ASSEMBLER_PROFILE{
        return Err(error("selected assembler command profile is unsupported"));
    }
    if prepared.plan.assembler_target()!="riscv64-unknown-none-elf"
        ||operation.expected_assembler_target!=prepared.plan.assembler_target()
        ||operation.expected_assembler_target!=target.triple(){
        return Err(error("selected assembler target differs from regenerated plan"));
    }
    if operation.expected_assembler_abi!=prepared.plan.assembler_abi(){
        return Err(error("selected assembler ABI differs from regenerated plan"));
    }
    if operation.expected_machine_profile!=&prepared.profile{
        return Err(error("selected assembler machine profile differs from regenerated plan"));
    }
    let requested_environment=selected_environment(operation.environment)?;
    operation.image.check()?;
    let cwd=SelectedOperationCwd::select(operation.cwd)?;cwd.check()?;
    let image=operation.image.observation()?;let cwd_before=cwd.observation()?;
    dispatch(prepared,SelectedOperationContext{cwd,requested_environment,image,cwd_before})
}


/// Execute an explicitly selected assembler operation over regenerated typed
/// assembly. Requests and source-file checks do not confer artifact admission.
pub fn diagnose_machine_unit_object_selected(
    unit:&MachineUnit,selection:&UnitSelection,inventory:&[u8],configured:&[u8],
    target:Target,evidence_root:&Path,operation:&MachineAssemblerOperationRequest<'_>,
)->Result<MachineObjectDiagnostic,Diagnostic>{
    let plan=plan_unit(unit,selection,inventory,configured,target)
        .map_err(|failure|error(format!("whole-unit plan refused: {failure:?}")))?;
    with_checked_plan(unit,plan,inventory,configured,target,|prepared|
        with_selected_operation(prepared,target,operation,|prepared,context|
            run_selected(prepared,target,evidence_root,operation,context)))
}
fn selected_command(
    prepared:&PreparedInputs<'_>,target:Target,operation:&MachineAssemblerOperationRequest<'_>,
    input:&Path,output:&Path,
)->Result<(Command,Value),Diagnostic>{
    // Preserve the selected invoked spelling, including its argv[0] semantics.
    // A canonical source pin is not independently observed child exec identity.
    let mut command=assembler_command(prepared,target,operation.image.invoked(),input,output)?;
    command.current_dir(operation.cwd).env_clear();
    for(key,value)in operation.environment{command.env(key,value);}
    let actual=command.get_envs().map(|(key,value)|
        value.map(|value|(key.to_os_string(),value.to_os_string()))
            .ok_or_else(||error("selected command unexpectedly removes an environment key")))
        .collect::<Result<Vec<_>,_>>()?;
    let to_map=|rows:&[(OsString,OsString)]|->Result<std::collections::BTreeMap<Vec<u8>,Vec<u8>>,Diagnostic>{
        rows.iter().map(|(key,value)|Ok((selected_os_bytes(key.as_os_str())?,
            selected_os_bytes(value.as_os_str())?))).collect()
    };
    // Duplicate/NUL rejection is performed before this map equality; maps do
    // not establish original raw environ ordering or inherited library closure.
    selected_environment(operation.environment)?;
    let actual_environment=selected_environment(&actual)?;
    if to_map(operation.environment)?!=to_map(&actual)?{
        return Err(error("configured command environment differs from explicit request"));
    }
    let argv=std::iter::once(command.get_program()).chain(command.get_args())
        .map(selected_os_record).collect::<Result<Vec<_>,_>>()?;
    let configuration=json!({"argv":argv,
        "cwd":selected_os_record(operation.cwd.as_os_str())?,
        "complete_environment_mapping":actual_environment,
        "ambient_environment_cleared":true,
        "environment_scope":"explicit Unix byte mapping; raw environ order and child library closure unqualified"});
    Ok((command,configuration))
}
fn selected_observe_inputs(
    directory:&Path,inputs:&[(&str,&[u8])],phase:&str,
)->Result<(bool,Value),Diagnostic>{
    let mut exact=true;let mut rows=Vec::new();
    for(name,expected)in inputs{
        let path=directory.join(name);
        match fs::read(&path){
            Ok(actual)=>{
                let matches=actual.as_slice()==*expected;exact&=matches;
                let retained=if matches{Value::Null}else{
                    let observed=directory.join(format!("{phase}-{name}.observed"));
                    retain_new(&observed,&actual)?;selected_os_record(observed.as_os_str())?
                };
                rows.push(json!({"path":selected_os_record(path.as_os_str())?,
                    "expected":identity(expected),"observed":identity(&actual),
                    "exact":matches,"mismatch_path":retained}));
            },
            Err(e)=>{exact=false;rows.push(json!({"path":selected_os_record(path.as_os_str())?,
                "expected":identity(expected),"observed":null,"exact":false,"read_error":e.to_string()}));},
        }
    }
    Ok((exact,Value::Array(rows)))
}
// Publication is deliberately separate from the owned operation observation.
// Even a final receipt create/write/sync error must not erase a known status,
// or reclassify Command::output Err as not dispatched.
fn publish_diagnostic_receipt_with(
    receipt:&mut Value,publish:impl FnOnce(&Value)->Result<(),Diagnostic>,
){
    if let Err(publication)=publish(receipt){
        let text=publication.to_string();
        if !receipt["output_publication_errors"].is_array(){receipt["output_publication_errors"]=json!([]);}
        if let Some(errors)=receipt["output_publication_errors"].as_array_mut(){errors.push(json!(text.clone()));}
        receipt["receipt_publication_error"]=json!(text);
        receipt["status"]=json!(match(
            receipt["command_observation"]["attempted"].as_bool(),
            receipt["command_observation"]["completion_known"].as_bool(),
        ){
            (Some(true),Some(false))=>"completion_UNKNOWN",
            (Some(true),Some(true))=>"output_publication_failed",
            _=>"receipt_publication_failed_before_launch",
        });
    }
}
fn publish_diagnostic_receipt(directory:&Path,receipt:&mut Value){
    publish_diagnostic_receipt_with(receipt,|value|retain_json(&directory.join("receipt.json"),value));
}
fn run_selected(
    prepared:PreparedInputs<'_>,target:Target,evidence_root:&Path,
    operation:&MachineAssemblerOperationRequest<'_>,context:SelectedOperationContext,
)->Result<MachineObjectDiagnostic,Diagnostic>{
    let root=evidence_root.canonicalize().map_err(|e|error(format!("resolve existing evidence root: {e}")))?;
    let directory=root.join(format!("machine-object-selected-{}-{}",std::process::id(),monotonic_nonce()));
    let mut builder=fs::DirBuilder::new();
    #[cfg(unix)]{use std::os::unix::fs::DirBuilderExt;builder.mode(0o700);}
    builder.create(&directory).map_err(|e|error(format!("create exclusive diagnostic attempt: {e}")))?;
    let assembly=prepared.plan.assembly().as_bytes();
    let inputs=[("unit.machine.json",prepared.unit_json.as_slice()),
        ("unit.inventory.json",prepared.inventory),("configured.s",prepared.configured),("selected.s",assembly)];
    for(name,bytes)in &inputs{retain_new(&directory.join(name),bytes)?;}
    let(before_exact,before)=selected_observe_inputs(&directory,&inputs,"before")?;
    let output_path=directory.join("raw.o");
    let(mut command,configuration)=selected_command(&prepared,target,operation,&directory.join("selected.s"),&output_path)?;
    operation.image.check()?;context.cwd.check()?;
    let invocation=json!({"format":"ocore-selected-typed-machine-object-invocation-v1",
        "source_unit_id":prepared.plan.source_unit_id,"target":target.name(),
        "assembler_target":target.triple(),"source_machine_profile":prepared.profile,
        "assembler_abi":prepared.plan.assembler_abi(),"typed_unit":prepared.plan.typed_unit_identity(),
        "inventory":identity(prepared.inventory),"configured":identity(prepared.configured),
        "selected_assembly":identity(assembly),"assembler_policy":operation.command_profile,
        "selected_image":context.image,"selected_cwd":context.cwd_before,
        "requested_environment":context.requested_environment,"command_configuration":configuration,
        "inputs_before":before,"object_path":selected_os_record(output_path.as_os_str())?,
        "original_source_semantic_admission":"UNMET","object_format_inventory":"UNMET_NOT_RUN",
        "requested_tool_source_identity_only":true,"native_execution_qualified":false});
    retain_json(&directory.join("invocation.json"),&invocation)?;
    if !before_exact{
        let mut receipt=json!({"format":"ocore-typed-machine-object-diagnostic-v1",
            "status":"not_launched_input_drift","command_observation":{"attempted":false,
            "completion_known":true,"exit_code":null,"exit_success":false,"unknown_outputs_consumed":false},
            "output_publication_errors":[],"invocation":"invocation.json",
            "input_and_selected_tool_observations_stable":false,"qualified":false});
        publish_diagnostic_receipt(&directory,&mut receipt);
        return Ok(MachineObjectDiagnostic{directory,receipt,object:None,stdout:None,stderr:None});
    }
    // From this boundary onward every result retains the original operation
    // observation in memory, regardless of later publication or guard failures.
    let observed=observe_output(command.stdin(Stdio::null()).stdout(Stdio::piped())
        .stderr(Stdio::piped()).output(),||fs::read(&output_path));
    let command_observation=observed.metadata();
    let mut output_publication_errors:Vec<String>=Vec::new();
    if let Some(bytes)=&observed.stdout{
        if let Err(e)=retain_new(&directory.join("stdout"),bytes){output_publication_errors.push(e.to_string());}
    }
    if let Some(bytes)=&observed.stderr{
        if let Err(e)=retain_new(&directory.join("stderr"),bytes){output_publication_errors.push(e.to_string());}
    }
    let command_record=json!({"command_observation":command_observation,
        "output_publication_errors":output_publication_errors});
    if let Err(e)=retain_json(&directory.join("command-observation.json"),&command_record){
        output_publication_errors.push(e.to_string());
    }
    let(stable,after,selected_after)=if observed.known{
        let(exact,after)=match selected_observe_inputs(&directory,&inputs,"after"){
            Ok(value)=>value,Err(e)=>(false,json!({"observation_error":e.to_string()})),
        };
        let image_check=operation.image.check();let cwd_check=context.cwd.check();
        let stable=exact&&image_check.is_ok()&&cwd_check.is_ok();
        let selected_after=json!({"image_check_passed":image_check.is_ok(),
            "image_check_error":image_check.err().map(|e|e.to_string()),
            "cwd_check_passed":cwd_check.is_ok(),"cwd_check_error":cwd_check.err().map(|e|e.to_string()),
            "scope":"requested image and named cwd source checks; child exec image/libraries unqualified"});
        (stable,after,selected_after)
    }else{(false,Value::Null,Value::Null)};
    let status=if !observed.known{"completion_UNKNOWN"}
        else if !output_publication_errors.is_empty(){"output_publication_failed"}
        else if !observed.success{"assembler_nonzero_or_signal"}
        else if !stable{"input_or_tool_drift"}
        else if observed.object.is_none(){"assembler_zero_object_missing"}
        else{"raw_object_retained_format_validation_UNMET"};
    let mut receipt=json!({"format":"ocore-typed-machine-object-diagnostic-v1","status":status,
        "invocation":"invocation.json","command_observation":observed.metadata(),
        "output_publication_errors":output_publication_errors,"inputs_after":after,
        "assembler_after":selected_after,"input_and_selected_tool_observations_stable":stable,
        "selected_operation_profile":operation.command_profile,
        "selector_scope":"RV64 LP64/LP64D static supported subset; whole-unit unsupported records refuse",
        "original_source_semantic_admission":"UNMET","object_format_inventory":"UNMET_NOT_RUN",
        "generated_relocation_inventory":"UNMET_NOT_RUN","provider_closure":"UNMET",
        "final_link_and_artifact":"UNMET","CFI_stack_restore_and_provider_realization":"UNMET",
        "assembler_execution_byte_custody_qualified":false,
        "assembler_library_and_environment_closure_qualified":false,"descendant_quiescence_qualified":false,
        "native_decoder_CPU_and_all_ISA_execution_qualified":false,"qualified":false});
    publish_diagnostic_receipt(&directory,&mut receipt);
    Ok(retained_diagnostic(directory,receipt,observed))
}

fn retained_diagnostic(directory:PathBuf,receipt:Value,observed:Observation)->MachineObjectDiagnostic{
    MachineObjectDiagnostic{directory,receipt,object:observed.object,stdout:observed.stdout,stderr:observed.stderr}
}
