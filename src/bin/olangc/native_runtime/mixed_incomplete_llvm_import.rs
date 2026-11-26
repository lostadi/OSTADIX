//! Incomplete-capture structural diagnostics. No complete-capture lineage or native admission.
use super::*;
use super::super::{MixedDiagnosticSession,MixedDiagnosticInputResult};
struct DiagnosticModule { module: Arc<NativeModule>, mir_sha256: String }
struct DiagnosticUnit {
    record: Value,
    snapshot: Option<DiagnosticModule>,
    original_representation: Option<String>,
    phases: UnitPhases,
}
pub(crate) struct MixedIncompleteImportedCohort {
    session: MixedDiagnosticSession,
    units: Vec<DiagnosticUnit>,
    executor: Executor,
    guards: Vec<ObservedFile>,
    observed_custody_failure: OnceLock<String>,
    custody_issues: Vec<String>,
    classification_issues: Vec<String>,
    issues: Vec<String>,
    native_tools: Vec<Value>,
    host: Value,
    dependencies: Vec<PathBuf>,
    output: PathBuf,
    // Set only after this operation actually creates its fresh private directory.
    output_created: bool,
    summary_write_error: Option<String>,
    started: bool,
}
fn original_diagnostic_target(unit: &Value) -> Result<&Value> {
    let object = unit.as_object().context("incomplete raw unit is not an object")?;
    let configured = object.get("representation").and_then(Value::as_str)
        == Some("configured-assembly") || object.contains_key("configured_assembly");
    let payload = object.get(if configured { "configured_assembly" } else { "ir" });
    Ok(payload.and_then(Value::as_object)
        .and_then(|payload| payload.get("target_triple")).unwrap_or(&Value::Null))
}
impl MixedIncompleteImportedCohort {
    pub(crate) fn pending_process_count(&self) -> usize {
        self.executor.pending.iter().filter(|attempt|attempt.terminal.is_none()).count()
    }
    pub(crate) fn check_custody(&self) -> Result<()> {
        if let Some(error)=self.observed_custody_failure.get() {
            bail!("mixed import permanently refused after observed custody failure: {error}");
        }
        if self.executor.unknown || !self.executor.pending.is_empty() {
            bail!("mixed import has historical UNKNOWN; owned handles and observations retained");
        }
        if !self.custody_issues.is_empty() || !self.executor.custody_issues.is_empty() {
            bail!("mixed import custody failed; private module views withheld");
        }
        let observed=(|| -> Result<()> {
            self.session.check_custody()?;
            for guard in self.guards.iter().chain(self.executor.guards.iter()) { guard.check()?; }
            Ok(())
        })();
        if let Err(error)=&observed {
            let _=self.observed_custody_failure.set(format!("{error:#}"));
        }
        observed
    }
    pub(crate) fn wait_pending_original(&mut self) -> Value {
        let mut wait_errors = Vec::new();
        for (pending_index, attempt) in self.executor.pending.iter_mut().enumerate() {
            if attempt.terminal.is_some() {
                continue;
            }
            let mut count = 0_u64;
            let mut first_error: Option<String> = None;
            let mut last_error: Option<String> = None;
            loop {
                match attempt.child.wait() {
                    Ok(_) => break,
                    Err(error) => {
                        let message = error.to_string();
                        if first_error.is_none() {
                            first_error = Some(message.clone());
                        }
                        last_error = Some(message);
                        count = count.saturating_add(1);
                        std::thread::sleep(std::time::Duration::from_millis(250));
                    }
                }
            }
            if count != 0 {
                wait_errors.push(json!({
                    "pending_index": pending_index,
                    "state": "original_child_blocking_wait_errors",
                    "wait_error_count": count,
                    "first_error": first_error,
                    "last_error": last_error,
                    "historical_unknown_cleared": false,
                    "import_resumed": false
                }));
            }
        }
        // Child::wait caches the known terminal status. Reuse the existing
        // observer's exact guards, terminal record, file reads and publication.
        let terminal_observation = self.observe_pending();
        json!({
            "schema": "ocore-runtime-mixed-original-child-wait-v1",
            "terminal_observation": terminal_observation,
            "bounded_wait_error_accounting": wait_errors,
            "historical_unknown_cleared": false,
            "import_resumed": false,
            "descendant_quiescence_qualified": false
        })
    }

    pub(crate) fn observe_pending(&mut self) -> Value {
        let stage=&self.session;
        let guards=&self.guards;
        let latch=&self.observed_custody_failure;
        let custody=&mut self.custody_issues;
        let Executor {host,pending,guards:command_guards,terminal_observations,
            unknown_without_handle,..}=&mut self.executor;
        let mut latest=Vec::new();
        for attempt in pending.iter_mut() {
            if attempt.terminal.is_some() { continue; }
            attempt.observation_count+=1;
            let mut row=json!({"schema":"ocore-mixed-original-child-observation-v1",
                "command_index":attempt.command_index,"pid":attempt.pid,
                "original_start_ticks":attempt.start_ticks,"observation":attempt.observation_count,
                "deadline":null,"signals_sent":[],"historical_unknown_qualification_refusal":true,
                "descendant_quiescence_qualified":false});
            let mut identity_conflict=false;
            match process_start(attempt.pid) {
                Ok(now)=>{
                    row["current_start_ticks"]=json!(now);
                    if attempt.start_ticks.is_some_and(|original|original!=now) {
                        identity_conflict=true;
                        row["state"]=json!("original_process_identity_conflict_unknown");
                        let message=format!("pending command {} process start differs",attempt.command_index);
                        let _=latch.set(message.clone());custody.push(message);
                    }
                }
                Err(error)=>row["process_metadata_error"]=json!(error.to_string()),
            }
            if !identity_conflict {
                match attempt.child.try_wait() {
                    Ok(None)=>row["state"]=json!("still_running_unknown"),
                    Err(error)=>{
                        row["state"]=json!("original_child_try_wait_error_unknown");
                        row["failure"]=json!(error.to_string());
                    }
                    Ok(Some(status))=>{
                        let terminal=KnownTerminal::observed(&status);
                        // Retain known terminal facts before any postguard/publication I/O.
                        attempt.terminal=Some(terminal.clone());
                        row["state"]=json!("original_child_known_reaped_after_unknown");
                        row["terminal"]=json!(terminal);
                        let post=(|| -> Result<Value> {
                            stage.check_custody()?;
                            for guard in guards.iter().chain(command_guards.iter()) {guard.check()?;}
                            let known=KnownReaped(&status);
                            let files=known_terminal_files(
                                (*host).context("pending original native host missing")?,
                                &attempt.program,&attempt.stdout,&attempt.stderr,&known)?;
                            let evidence=json!({"native_program_after":{"file":files.program.value(),
                                "elf":files.program_elf},"stdout":files.stdout.value(),
                                "stderr":files.stderr.value(),
                                "scope":"known direct-child terminal and observed raw file pins only"});
                            attempt.observed_guards.extend([files.program,files.stdout,files.stderr]);
                            Ok(evidence)
                        })();
                        match post {
                            Ok(evidence)=>{row["postguard"]="passed".into();row["raw_evidence"]=evidence;}
                            Err(error)=>{
                                let message=format!("pending command {} terminal postguard: {error:#}",attempt.command_index);
                                let _=latch.set(message.clone());custody.push(message.clone());
                                row["postguard"]="known_failed".into();row["postguard_failure"]=json!(message);
                            }
                        }
                    }
                }
            }
            let path=attempt.directory.join(format!(
                "{}.pending-observation-{:06}.json",attempt.label,attempt.observation_count));
            let publication=(|| -> Result<Value> {
                let raw=serde_json::to_vec_pretty(&row)?;
                write_new(&path,&raw)?;
                let pin=ObservedFile::read(&path)?;
                if pin.sha256!=digest(&raw) {bail!("pending observation readback pin differs");}
                Ok(pin.value())
            })();
            match publication {
                Ok(pin)=>row["publication"]=pin,
                Err(error)=>row["publication_error"]=json!(format!("{error:#}")),
            }
            terminal_observations.push(row.clone());latest.push(row);
        }
        json!({"schema":"ocore-mixed-pending-observation-result-v1","observations":latest,
            "unknown_without_owned_handle":unknown_without_handle,
            "historical_unknown_qualification_refusal":true,
            "automatic_reimport":false,"automatic_continuation":false,
            "native_module_minted":false,"full_session_quiescence_qualified":false})
    }

    pub(crate) fn with_diagnostic_module<T>(
        &self, occurrence: usize, use_module: impl FnOnce(&NativeModule) -> Result<T>,
    ) -> Result<T> {
        self.check_custody()?;
        let snapshot = self.units.get(occurrence)
            .and_then(|unit|unit.snapshot.as_ref())
            .context("mixed unit has no independently verified structural module")?;
        if snapshot.mir_sha256 != self.units[occurrence].record["module"]["sha256"] {
            let _=self.observed_custody_failure.set("mixed retained snapshot diagnostic binding differs".into());
            let _=self.observed_custody_failure.set(
                "retained mixed module snapshot binding differs".into());
            bail!("mixed retained snapshot diagnostic binding differs");
        }
        let result = use_module(&snapshot.module);
        self.check_custody()?;
        result
    }
    pub(crate) fn summary(&self) -> Value {
        let safe=self.check_custody().is_ok() && self.classification_issues.is_empty();
        let llvm=self.units.iter().filter(|unit|unit.original_representation.as_deref()==Some("llvm")).collect::<Vec<_>>();
        let positive=safe && !llvm.is_empty();
        let observed=|unit: &&DiagnosticUnit|unit.record["input_disposition"]=="observed";
        let structural=positive && llvm.iter().all(|unit|observed(unit) && matches!(&unit.phases.structural_verification.state,PhaseState::Passed));
        let inventory=positive && llvm.iter().all(|unit|observed(unit) && matches!(&unit.phases.source_native_inventory.state,PhaseState::Passed));
        let all=positive && llvm.iter().all(|unit|observed(unit) && unit.phases.all_passed());
        let rows=self.units.iter().map(|unit|json!({"original_representation":unit.original_representation,
            "record":unit.record,"phases":unit.phases,"diagnostic_module_retained":unit.snapshot.is_some()})).collect::<Vec<_>>();
        json!({"schema":"ocore-runtime-incomplete-llvm-import-cohort-v1",
            "scope":"actual original-occurrence structural LLVM diagnostics from incomplete capture; no complete lineage",
            "input_session":self.session.summary(),"units":rows,"original_llvm_count":llvm.len(),
            "original_member_count":self.units.len(),"structural_llvm_cohort_complete":structural,
            "source_native_inventory_cohort_complete":inventory,"all_required_llvm_phases_complete":all,
            "commands":self.executor.commands,"terminal_observations":self.executor.terminal_observations,
            "unknown_without_handle":self.executor.unknown_without_handle,"historical_process_unknown":self.executor.unknown,
            "pending_original_children":self.pending_process_count(),"native_tools":self.native_tools,"host":self.host,
            "issues":self.issues,"custody_issues":self.custody_issues,"classification_issues":self.classification_issues,
            "first_permanent_custody_refusal":self.observed_custody_failure.get(),"summary_write_error":self.summary_write_error,
            "source_capture_complete":false,"unit_lowering_complete":false,"artifact_complete":false,"runtime_complete":false,
            "native_execution_qualified":false,"native_order_meaning_checked":false,"abi_complete":false,
            "provider_closure_complete":false,"source_function_authority":false,"generated_application_inclusion_qualified":false})
    }
    pub(crate) fn run_import(&mut self,target:&str,options:NativeImportOptions<'_>,compiler:&provider_group::Pin,
        python:&provider_group::Pin,library:&provider_group::Pin) {
        if self.started {self.issues.push("incomplete diagnostic import already entered; no redispatch".into());return;}
        self.started=true;
        if let Err(error)=self.run_body(target,options,compiler,python,library) {
            self.issues.push(format!("incomplete diagnostic operation: {error:#}"));
        }
        let saved=(|| -> Result<()> {
            if !self.output_created {bail!("exclusive incomplete diagnostic output absent; no publication");}
            write_new(&self.output.join("incomplete-llvm-import.json"),&serde_json::to_vec_pretty(&self.summary())?)
        })();
        if let Err(error)=saved {self.summary_write_error=Some(error.to_string());}
    }
    fn run_body(&mut self,target:&str,import_options:NativeImportOptions<'_>,compiler:&provider_group::Pin,
        python:&provider_group::Pin,library:&provider_group::Pin)->Result<()> {
    let NativeImportOptions {
        llvm_library,
        llvm_sha256,
        tls_profile,
        atomic_profile,
        wide_volatile_profile,
        linux_syscall_profile,
        dependencies: dependency_paths,
    } = import_options;
    let expected_tls_profile = match tls_profile {
        None => None,
        Some("linux-elf-static-nonpreemptive-v1") => {
            Some(TlsProfile::LinuxElfStaticNonpreemptiveV1)
        }
        Some(_) => bail!("unsupported native TLS realization profile"),
    };
    let expected_atomic_profile = match atomic_profile {
        None => None,
        Some("coherent-ram-v1") => Some(AtomicProfile::CoherentRamV1),
        Some(_) => bail!("unsupported native atomic realization profile"),
    };
    let expected_wide_volatile_profile = match wide_volatile_profile {
        None => None,
        Some("ordinary-ram-split-v1") => Some(WideVolatileProfile::OrdinaryRamSplitV1),
        Some(_) => bail!("unsupported native wide volatile realization profile"),
    };
    let expected_linux_syscall_profile = match linux_syscall_profile {
        None => None,
        Some("linux-user-raw-v1") => {
            Some(o_lang::ocore::native_ir::LinuxSyscallProfile::LinuxUserRawV1)
        }
        Some(_) => bail!("unsupported native Linux syscall realization profile"),
    };
        self.dependencies = dependency_paths.to_vec();
        let arch = architecture(target)?;
        let selected_library = llvm_library.context("mixed import requires explicit selected LLVM library")?;
        let selected_sha = llvm_sha256.context("mixed import requires explicit selected LLVM library SHA")?;
        if selected_library != library.path.as_path() || selected_sha != library.sha256.as_str() {
            bail!("mixed import and independent inventory LLVM selections differ");
        }

        self.session.check_custody()?;
        if self.units.len()!=self.session.member_count() {bail!("incomplete original occurrence coverage differs");}
        for (ordinal,unit) in self.units.iter().enumerate() {
            if unit.record["member_index"]!=json!(ordinal) || !matches!(unit.original_representation.as_deref(),Some("llvm"|"configured-assembly"|"unsupported")) {
                self.classification_issues.push(format!("incomplete original occurrence {ordinal} index/tag invalid"));
            }
        }
        if !self.classification_issues.is_empty() {bail!("incomplete original membership is not dense and classified");}
        let (host, host_value) = NativeHost::observe()?;
        self.host = host_value;
        self.executor.host = Some(host);
        for (role,pin,is_library) in [("compiler",compiler,false),("inventory_python",python,false),
                                     ("llvm_library",library,true)] {
            let (file,elf) = host.pin(pin,is_library)?;
            self.native_tools.push(json!({"role":role,"file":file.value(),"elf":elf}));
            self.guards.push(file);
        }
        let shared_tool_guard_count = self.guards.len();
        if !self.output.is_absolute() { bail!("mixed import output must be absolute"); }
        fs::create_dir(&self.output).context("mixed import output must be a new directory")?;
        self.output = self.output.canonicalize()?;
        self.output_created = true;

        let mut module_target:Option<Value>=None;
        for ordinal in 0..self.units.len() {
            if self.units[ordinal].original_representation.as_deref()!=Some("llvm") {continue;}
            if self.executor.halted {
                self.units[ordinal].record["status"]=json!("unattempted_after_dispatch_halt");
                self.units[ordinal].phases.block_unattempted("global process/custody halt; no new dispatch");continue;
            }
            if let Err(error)=self.session.check_custody().and_then(|()| {
                for guard in &self.guards[..shared_tool_guard_count] {guard.check()?;} Ok(())
            }) {
                let message=format!("before incomplete occurrence {ordinal}: {error:#}");
                let _=self.observed_custody_failure.set(message.clone());self.custody_issues.push(message);
                self.executor.halted=true;self.units[ordinal].record["status"]=json!("unattempted_custody_failure");continue;
            }
            let expected=self.session.capture()["units"].get(ordinal).and_then(|unit|original_diagnostic_target(unit).ok())
                .and_then(Value::as_str).map(str::to_owned);
            let Some(expected)=expected else {
                self.units[ordinal].record["status"]=json!("refused_missing_original_target");
                self.units[ordinal].record["input_disposition"]=json!("refused");continue;
            };
            let unit_guard_start=self.guards.len();let command_guard_start=self.executor.guards.len();
            let command_start=self.executor.commands.len();let mut candidate_target=module_target.clone();
            let mut record=self.units[ordinal].record.clone();let mut phases=self.units[ordinal].phases.clone();
            let session=&self.session;let output=&self.output;let executor=&mut self.executor;
            let guards=&mut self.guards;let custody_issues=&mut self.custody_issues;
            let checked=session.with_llvm_input(ordinal,&expected,|input| {
                let index=input.index();let unit=input.original_unit();let held_path=input.path();let held_bytes=input.bytes();
                let mut snapshot:Option<DiagnosticModule>=None;let mut inventory_passed=false;
                let mut active=Some(PhaseKind::Import);phases.import.begin();
                let result=held_llvm_phases(unit, held_path, held_bytes, arch, ordinal, index, output, host, compiler, python, library,
                    selected_library, selected_sha, tls_profile, atomic_profile, wide_volatile_profile, linux_syscall_profile,
                    &expected_tls_profile, &expected_atomic_profile, &expected_wide_volatile_profile, &expected_linux_syscall_profile,
                    shared_tool_guard_count, executor, guards, custody_issues, &mut record, &mut phases, &mut active,
                    &mut candidate_target, &mut inventory_passed, &mut snapshot,
                    ||session.check_custody(),|module,raw|Ok(DiagnosticModule{module,mir_sha256:digest(raw)}));
            record["command_indices"] = json!((command_start..executor.commands.len()).collect::<Vec<_>>());
            record["independent_inventory_passed"] = json!(inventory_passed);
            match result {
                Ok(())=>record["status"]=json!(if phases.all_passed() {
                    "all_required_llvm_phases_passed"
                } else {"known_auxiliary_failure_with_independent_inventory_result"}),
                Err(error)=>{
                    if let Some(phase)=active {
                        phases.get_mut(phase).fail(&format!("{error:#}"),executor.unknown);
                        record["failed_phase"]=json!(phase.name());
                    } else {record["failed_phase"]=json!("global_custody_boundary");}
                    phases.block_unattempted("preceding phase/global process boundary did not complete");
                    record["status"]=json!(if executor.unknown {"phase_unknown"} else {"phase_known_failed"});
                    record["failure"]=json!(format!("{error:#}"));
                }
            }

                Ok(snapshot)
            });
            let mut snapshot=None;
            match checked {
                Ok(MixedDiagnosticInputResult::Refused{index,reasons})=>{
                    record["input_disposition"]=json!("refused");record["status"]=json!("input_refused_before_or_after_phases");
                    record["input_refusal_reasons"]=json!(reasons);
                    if index!=ordinal {self.classification_issues.push("diagnostic refusal index differs".into());self.executor.halted=true;}
                }
                Ok(MixedDiagnosticInputResult::Observed{index,result})=>{
                    if index!=ordinal {self.classification_issues.push("diagnostic observed index differs".into());self.executor.halted=true;}
                    match result {Ok(value)=>{snapshot=value;record["input_disposition"]=json!("observed");}
                        Err(error)=>{record["input_disposition"]=json!("operation-error");record["callback_error"]=json!(error);}}
                }
                Err(error)=>{
                    let message=format!("incomplete input shared postguard: {error:#}");
                    let _=self.observed_custody_failure.set(message.clone());self.custody_issues.push(message);
                    self.executor.halted=true;record["input_disposition"]=json!("shared-custody-failed");
                }
            }
            if self.executor.unknown || self.executor.halted {snapshot=None;}
            if snapshot.is_some() {module_target=candidate_target;}
            let original_representation=self.units[ordinal].original_representation.clone();
            self.units[ordinal]=DiagnosticUnit{record,snapshot,original_representation,phases};
            // Never read any generated output after an unknown constructor/wait.
            if !self.executor.unknown {
                let post = self.session.check_custody().and_then(|()| {
                    for guard in &self.guards[..shared_tool_guard_count] { guard.check()?; }
                    for guard in self.guards[unit_guard_start..].iter()
                        .chain(self.executor.guards[command_guard_start..].iter()) {
                        guard.check()?;
                    }
                    Ok(())
                });
                if let Err(error) = post {
                    self.custody_issues.push(format!("after occurrence {ordinal}: {error:#}"));
                    self.executor.halted = true;
                }
            }
        }
        // Observe every retained output before returning any private success view.
        // A failed observation remains a permanent refusal even if bytes later revert.
        if !self.executor.unknown {
            if let Err(error) = self.check_custody() {
                self.custody_issues.push(format!("final cohort guard: {error:#}"));
                self.executor.halted = true;
            }
        }
        Ok(())
    }
}

// No child dispatch occurs here. The normal caller installs this owner before run_import.
pub(crate) fn prepare_diagnostic_session(session:MixedDiagnosticSession,output:&Path)->MixedIncompleteImportedCohort {
    let units=session.original_units().enumerate().map(|(ordinal,unit)| {
        let representation=unit.outcome()["representation"].as_str().map(str::to_owned);
        let status=match representation.as_deref(){Some("llvm")=>"unattempted",Some("configured-assembly")=>"pending-assembly",_=>"unsupported"};
        DiagnosticUnit{record:json!({"occurrence":ordinal,"member_index":unit.index(),"id":unit.raw()["id"],
            "representation":representation,"status":status,"input_disposition":"unattempted","command_indices":[]}),
            snapshot:None,original_representation:representation,phases:UnitPhases::unattempted("original incomplete occurrence not yet consumed")}
    }).collect();
    MixedIncompleteImportedCohort{session,units,executor:Executor::new(),guards:Vec::new(),
        observed_custody_failure:OnceLock::new(),custody_issues:Vec::new(),classification_issues:Vec::new(),issues:Vec::new(),
        native_tools:Vec::new(),host:Value::Null,dependencies:Vec::new(),output:output.to_owned(),output_created:false,
        summary_write_error:None,started:false}
}
