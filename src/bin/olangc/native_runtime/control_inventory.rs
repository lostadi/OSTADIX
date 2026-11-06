//! Verified-MIR control requirements only. Existing closure guards remain authoritative.
//! Raw effects, ordinary ABI plans and missing provider/boundary evidence are
//! separate. No symbol spelling or inferred call-graph fixed point grants admission.
use super::*;
use o_lang::ocore::{native_abi, native_ir::{ControlEffects, Function, Operand, Operation, SourceAbiWitness, Terminator}, Target};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Requirements {
    schema: &'static str,
    unit_id: String,
    /// Hash of the exact input file, including its original JSON representation.
    module_file_sha256: String,
    input_sha256: String,
    source_target: Value,
    has_nonlocal_effects: bool,
    functions: Vec<FunctionRequirements>,
    /// Only raw/effective returns_twice bindings, not a complete save/resume
    /// provider census. All ordinary callees remain dependencies; restore
    /// semantics are never inferred from a symbol name or noreturn.
    returns_twice_provider_requirements: Vec<ProviderRequirement>,
    function_count: usize,
    call_site_count: usize,
    unresolved_call_site_count: usize,
    unmet: Vec<UnmetRequirement>,
    provider_qualified: bool,
    library_exposure_admitted: bool,
    rust_ovalue_boundary_qualified: bool,
    frame_or_assembly_proof_included: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct FunctionRequirements {
    function_index: usize,
    symbol: String,
    definition_present: bool,
    linkage: String,
    raw_declaration_effects: ControlEffects,
    canonical_signature: Value,
    source_abi: Option<SourceAbiWitness>,
    nonlocal_entry_abi_plan: Option<AbiObservation>,
    referenced_symbols: BTreeSet<String>,
    block_address_dependencies: BTreeSet<(String, usize)>,
    direct_call_dependencies: BTreeSet<String>,
    source_call_target_constraints: Value,
    call_sites: Vec<CallRequirements>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct SiteIdentity {
    caller_function_index: usize,
    block: usize,
    /// None means the block terminator; kind distinguishes invoke from call.
    instruction: Option<usize>,
    kind: SiteKind,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum SiteKind { Call, Invoke }

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Callee {
    DirectFunction { symbol: String, function_index: usize, definition_present: bool },
    DirectAliasUnresolved { symbol: String },
    NamedSymbolUnresolved { symbol: String },
    NonDirectUnresolved,
}
impl Callee {
    fn direct_symbol(&self) -> Option<&str> {
        match self {
            Self::DirectFunction { symbol, .. } | Self::DirectAliasUnresolved { symbol }
            | Self::NamedSymbolUnresolved { symbol } => Some(symbol),
            Self::NonDirectUnresolved => None,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CallRequirements {
    site: SiteIdentity,
    callee: Callee,
    original_callee_operand: Value,
    original_arguments: Value,
    canonical_signature: Value,
    /// Invoke has no raw ControlEffects field in the current MIR schema.
    raw_site_effects: Option<ControlEffects>,
    raw_direct_declaration_effects: Option<ControlEffects>,
    /// Exactly the existing local declaration/site OR, never inter-module proof.
    same_module_effective_returns_twice: bool,
    nonlocal_call_abi_plan: Option<AbiObservation>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum AbiObservation {
    Planned { canonical_transport: Value },
    Unsupported { reason: String },
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderRequirement {
    function_index: usize,
    symbol: String,
    original_definition_present: bool,
    raw_declaration_effects: ControlEffects,
    canonical_signature: Value,
    effective_local_sites: Vec<SiteIdentity>,
    status: RequirementStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequirementStatus { Unmet }
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Obligation {
    OriginalProviderImplementationAndRecursiveClosure,
    OriginalJumpBufferAndSavedStateAbi,
    SignalTlsUnwindAndTargetFeatureCompatibility,
    LiveNativeFramesAndRustOValueGraphBoundary,
    CrossModuleControlAndProviderCompatibility,
}
#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnmetRequirement { obligation: Obligation, status: RequirementStatus }

fn target(module: &NativeModule) -> Result<Target> {
    let arch = module.target.triple.split('-').next().unwrap_or_default();
    Target::parse(&format!("{arch}-unknown-none")).context("control inventory ABI target is unsupported")
}

fn abi_observation(module: &NativeModule, caller: &Function, call: Option<&Signature>) -> AbiObservation {
    let planned = (|| -> Result<Value> {
        let target = target(module)?;
        let plan = if let Some(signature) = call {
            // Effective returns_twice calls are already verified fixed-argument C
            // calls. Do not fabricate variadic actual-argument types or attributes.
            if signature.variadic { bail!("nonlocal variadic call ABI is unsupported"); }
            native_abi::plan_call_from(module, target, caller, signature,
                &signature.params, &signature.param_attributes)?
        } else { native_abi::plan_function(module, target, caller)? };
        // Existing helper replaces every ABI-plan TypeId with the canonical
        // source type contract; it does not introduce another ABI classifier.
        fast_float_plan_contract(module, &plan)
    })();
    match planned {
        Ok(canonical_transport) => AbiObservation::Planned { canonical_transport },
        Err(error) => AbiObservation::Unsupported { reason: error.to_string() },
    }
}

fn call_requirements(module: &NativeModule, caller: &Function, site: SiteIdentity,
    callee: &Operand, signature: &Signature, args: &[Operand], raw: Option<ControlEffects>) -> Result<CallRequirements> {
    let declaration = match callee {
        Operand::Symbol { name, .. } => module.functions.iter().enumerate().find(|(_, f)| f.name == *name),
        _ => None,
    };
    let classified = if let Some((function_index, function)) = declaration {
        Callee::DirectFunction { symbol: function.name.clone(), function_index,
            definition_present: function.entry.is_some() }
    } else if let Operand::Symbol { name, .. } = callee {
        if module.aliases.iter().any(|alias| alias.name == *name) {
            Callee::DirectAliasUnresolved { symbol: name.clone() }
        } else { Callee::NamedSymbolUnresolved { symbol: name.clone() } }
    } else { Callee::NonDirectUnresolved };
    let effective = module.effective_returns_twice(callee, raw.unwrap_or_default());
    Ok(CallRequirements {
        site, callee: classified,
        original_callee_operand: serde_json::to_value(callee)?,
        original_arguments: serde_json::to_value(args)?,
        canonical_signature: signature_contract(module, signature, &mut BTreeSet::new())?,
        raw_site_effects: raw,
        raw_direct_declaration_effects: declaration.map(|(_, f)| f.control_effects),
        same_module_effective_returns_twice: effective,
        nonlocal_call_abi_plan: effective.then(|| abi_observation(module, caller, Some(signature))),
    })
}

pub(super) fn collect(unit_id: &str, exact_native_ir: &[u8]) -> Result<Requirements> {
    // Parse and structurally verify the exact file buffer. Neither an external
    // report nor an independently serialized module can replace this binding.
    let module = NativeModule::from_json(exact_native_ir)
        .map_err(|error| anyhow::anyhow!("control inventory verified MIR: {}", error.message))?;
    let mut functions = Vec::new();
    let mut provider_sites = BTreeMap::<usize, Vec<SiteIdentity>>::new();
    let mut call_site_count = 0;
    let mut unresolved_call_site_count = 0;
    for (function_index, function) in module.functions.iter().enumerate() {
        let mut call_sites = Vec::new();
        for block in &function.blocks {
            for (instruction, value) in block.instructions.iter().enumerate() {
                if let Operation::Call { callee, signature, args, control_effects } = &value.operation {
                    call_sites.push(call_requirements(&module, function,
                        SiteIdentity { caller_function_index: function_index, block: block.id,
                            instruction: Some(instruction), kind: SiteKind::Call },
                        callee, signature, args, Some(*control_effects))?);
                }
            }
            if let Terminator::Invoke { callee, signature, args, .. } = &block.terminator {
                call_sites.push(call_requirements(&module, function,
                    SiteIdentity { caller_function_index: function_index, block: block.id,
                        instruction: None, kind: SiteKind::Invoke },
                    callee, signature, args, None)?);
            }
        }
        let mut direct_call_dependencies = BTreeSet::new();
        for call in &call_sites {
            call_site_count += 1;
            if let Some(name) = call.callee.direct_symbol() { direct_call_dependencies.insert(name.to_owned()); }
            match &call.callee {
                Callee::DirectFunction { function_index, .. } if call.same_module_effective_returns_twice => {
                    provider_sites.entry(*function_index).or_default().push(call.site.clone());
                }
                Callee::DirectFunction { .. } => {},
                _ => unresolved_call_site_count += 1,
            }
        }
        let exposed = function.control_effects.returns_twice
            || call_sites.iter().any(|call| call.same_module_effective_returns_twice);
        let (referenced_symbols, block_address_dependencies) = function_dependencies(function);
        functions.push(FunctionRequirements {
            function_index, symbol: function.name.clone(), definition_present: function.entry.is_some(),
            linkage: function.linkage.clone(), raw_declaration_effects: function.control_effects,
            canonical_signature: signature_contract(&module, &function.signature, &mut BTreeSet::new())?,
            source_abi: function.source_abi.clone(),
            nonlocal_entry_abi_plan: exposed.then(|| abi_observation(&module, function, None)),
            referenced_symbols, block_address_dependencies, direct_call_dependencies,
            source_call_target_constraints: serde_json::to_value(&function.call_target_constraints)?, call_sites,
        });
    }
    let mut returns_twice_provider_requirements = Vec::new();
    for (function_index, function) in module.functions.iter().enumerate() {
        if function.control_effects.returns_twice || provider_sites.contains_key(&function_index) {
            returns_twice_provider_requirements.push(ProviderRequirement {
                function_index, symbol: function.name.clone(), original_definition_present: function.entry.is_some(),
                raw_declaration_effects: function.control_effects,
                canonical_signature: signature_contract(&module, &function.signature, &mut BTreeSet::new())?,
                effective_local_sites: provider_sites.remove(&function_index).unwrap_or_default(),
                status: RequirementStatus::Unmet,
            });
        }
    }
    let has_nonlocal_effects = module.has_nonlocal_control_effects();
    let unmet = if has_nonlocal_effects {
        [Obligation::OriginalProviderImplementationAndRecursiveClosure,
         Obligation::OriginalJumpBufferAndSavedStateAbi,
         Obligation::SignalTlsUnwindAndTargetFeatureCompatibility,
         Obligation::LiveNativeFramesAndRustOValueGraphBoundary,
         Obligation::CrossModuleControlAndProviderCompatibility]
            .into_iter().map(|obligation| UnmetRequirement { obligation, status: RequirementStatus::Unmet }).collect()
    } else { Vec::new() };
    Ok(Requirements { schema: "ocore-native-control-requirements-v1", unit_id: unit_id.into(),
        module_file_sha256: digest(exact_native_ir), input_sha256: module.provenance.input_sha256.clone(),
        source_target: serde_json::to_value(&module.target)?, has_nonlocal_effects,
        function_count: functions.len(), functions, returns_twice_provider_requirements, call_site_count,
        unresolved_call_site_count, unmet, provider_qualified: false, library_exposure_admitted: false,
        rust_ovalue_boundary_qualified: false, frame_or_assembly_proof_included: false })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(declaration: bool, site: bool, indirect: bool, cold: bool) -> Vec<u8> {
        let signature = json!({"params":[],"result":0,"abi":"c","variadic":false});
        let mut functions = vec![json!({"name":"caller","linkage":"external",
            "signature":{"params":if indirect {vec![1]} else {vec![]},"result":0,"abi":"c","variadic":false},
            "params":if indirect {vec![json!({"id":0,"ty":1})]} else {vec![]},"entry":0,
            "blocks":[{"id":0,"instructions":[{"result":{"id":1,"ty":0},"operation":{
                "op":"call","callee":if indirect {json!({"kind":"value","id":0})}
                    else {json!({"kind":"symbol","ty":1,"name":"original_checkpoint"})},
                "signature":signature,"args":[],"control_effects":{"returns_twice":site}}}],
                "terminator":{"op":"return","value":{"kind":"value","id":1}}}]}),
            json!({"name":"original_checkpoint","linkage":"external","signature":signature,
                "control_effects":{"returns_twice":declaration},"params":[],"entry":null,"blocks":[]})];
        if cold { functions.push(json!({"name":"cold_checkpoint","linkage":"external","signature":signature,
            "control_effects":{"returns_twice":true},"params":[],"entry":null,"blocks":[]})); }
        serde_json::to_vec(&json!({"format":"ocore-native-module-v1","name":"control-source",
            "target":{"triple":"x86_64-unknown-linux-gnu","data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1","types":[{"kind":"int","bits":64},{"kind":"pointer","address_space":0}],
            "globals":[],"functions":functions,"provenance":{"input_sha256":"a".repeat(64),
                "frontend":"test-original","frontend_version":"1","importer":"test","importer_version":"1",
                "source_function_count":functions.len(),"source_global_count":0,"refinements":[]}})).unwrap()
    }
    #[test]
    fn cold_declarations_and_complete_function_membership_are_retained() {
        let report = collect("unit", &fixture(false, false, false, true)).unwrap();
        assert_eq!((report.function_count, report.call_site_count), (3, 1));
        assert_eq!(report.functions.iter().map(|f| f.symbol.as_str()).collect::<BTreeSet<_>>(),
            BTreeSet::from(["caller", "original_checkpoint", "cold_checkpoint"]));
        let cold = report.returns_twice_provider_requirements.iter().find(|p| p.symbol == "cold_checkpoint").unwrap();
        assert!(cold.raw_declaration_effects.returns_twice);
        assert!(cold.effective_local_sites.is_empty());
        assert!(!cold.original_definition_present);
        assert!(!report.provider_qualified && !report.library_exposure_admitted);
    }
    #[test]
    fn site_only_effects_do_not_promote_raw_declaration_effects() {
        let report = collect("unit", &fixture(false, true, false, false)).unwrap();
        let call = &report.functions[0].call_sites[0];
        assert!(call.raw_site_effects.unwrap().returns_twice);
        assert!(!call.raw_direct_declaration_effects.unwrap().returns_twice);
        assert!(call.same_module_effective_returns_twice);
        assert!(!report.returns_twice_provider_requirements[0].raw_declaration_effects.returns_twice);
        assert_eq!(report.returns_twice_provider_requirements[0].effective_local_sites.len(), 1);
    }
    #[test]
    fn declaration_effects_do_not_rewrite_raw_site_effects() {
        let report = collect("unit", &fixture(true, false, false, false)).unwrap();
        let call = &report.functions[0].call_sites[0];
        assert!(!call.raw_site_effects.unwrap().returns_twice);
        assert!(call.raw_direct_declaration_effects.unwrap().returns_twice);
        assert!(call.same_module_effective_returns_twice);
        assert!(call.nonlocal_call_abi_plan.is_some());
    }
    #[test]
    fn direct_dependencies_remain_requirements_without_provider_inference() {
        let report = collect("unit", &fixture(true, true, false, false)).unwrap();
        assert_eq!(report.functions[0].direct_call_dependencies, BTreeSet::from(["original_checkpoint".into()]));
        assert!(matches!(report.functions[0].call_sites[0].callee,
            Callee::DirectFunction { definition_present: false, .. }));
        assert_eq!(report.unmet.len(), 5);
        assert!(!report.rust_ovalue_boundary_qualified && !report.frame_or_assembly_proof_included);
    }
    #[test]
    fn ordinary_indirect_call_is_retained_as_unresolved_without_name_inference() {
        let report = collect("unit", &fixture(false, false, true, false)).unwrap();
        assert_eq!(report.unresolved_call_site_count, 1);
        assert!(matches!(report.functions[0].call_sites[0].callee, Callee::NonDirectUnresolved));
        assert!(report.functions[0].direct_call_dependencies.is_empty());
        assert!(report.returns_twice_provider_requirements.is_empty());
    }
    #[test]
    fn exact_file_digest_is_distinct_from_equivalent_json_representation() {
        let raw = fixture(true, true, false, false);
        let first = collect("unit", &raw).unwrap();
        let mut spaced = raw.clone(); spaced.push(b'\n');
        let second = collect("unit", &spaced).unwrap();
        assert_eq!(first.module_file_sha256, digest(&raw));
        assert_ne!(first.module_file_sha256, second.module_file_sha256);
        assert_eq!(first.input_sha256, "a".repeat(64));
        assert_eq!(first.source_target, second.source_target);
        assert!(collect("unit", b"{}").is_err());
    }
    #[test]
    fn canonical_signatures_ignore_module_local_type_id_reordering() {
        let mut value: Value = serde_json::from_slice(&fixture(false, true, false, false)).unwrap();
        let original = collect("unit", &serde_json::to_vec(&value).unwrap()).unwrap();
        value["types"].as_array_mut().unwrap().reverse();
        for function in value["functions"].as_array_mut().unwrap() {
            function["signature"]["result"] = json!(1);
            if let Some(blocks) = function["blocks"].as_array_mut() {
                for block in blocks {
                    for instruction in block["instructions"].as_array_mut().unwrap() {
                        instruction["result"]["ty"] = json!(1);
                        instruction["operation"]["callee"]["ty"] = json!(0);
                        instruction["operation"]["signature"]["result"] = json!(1);
                    }
                }
            }
        }
        let reordered = collect("unit", &serde_json::to_vec(&value).unwrap()).unwrap();
        for (first, second) in original.functions.iter().zip(&reordered.functions) {
            assert_eq!(first.canonical_signature, second.canonical_signature);
        }
    }
    #[test]
    fn diagnostic_inventory_does_not_relax_symbol_or_embedded_module_guards() {
        let raw = fixture(true, true, false, false);
        let report = collect("unit", &raw).unwrap();
        let module = NativeModule::from_json(&raw).unwrap();
        assert!(!report.provider_qualified && !report.library_exposure_admitted);
        assert!(super::super::symbols("unit", &module).unwrap_err().to_string().contains("returns_twice symbol closure"));
        let embedded = super::super::artifact::EmbeddedModule { component: "component".into(),
            unit_id: "unit".into(), sha256: digest(&raw), native_ir: String::from_utf8(raw).unwrap() };
        assert!(embedded.verify().unwrap_err().to_string().contains("returns_twice module-set admission"));
    }

    #[test]
    fn invoke_terminator_identity_and_absent_raw_site_effects_are_retained() {
        // Ordinary verified Itanium Invoke, not an unsupported returns_twice/EH
        // combination. Its result exists only on the normal successor edge.
        let raw = br#"{
            "format":"ocore-native-module-v1","name":"invoke-control-inventory",
            "target":{"triple":"x86_64-unknown-linux-gnu","data_layout":"e-p:64:64-i32:32-i64:64","pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"int","bits":32},{"kind":"pointer","address_space":0},
                {"kind":"struct","fields":[2,1],"packed":false},{"kind":"int","bits":64}],
            "globals":[],
            "functions":[
                {"name":"invoke_caller","linkage":"external",
                    "signature":{"params":[],"result":4,"abi":"c","variadic":false},"params":[],"entry":10,
                    "exception_handling":{"model":"itanium_dwarf_v1","personality":{"kind":"symbol","ty":2,"name":"source_personality"}},
                    "blocks":[
                        {"id":10,"instructions":[],"terminator":{"op":"invoke",
                            "callee":{"kind":"symbol","ty":2,"name":"may_throw"},
                            "signature":{"params":[],"result":4,"abi":"c","variadic":false},
                            "args":[],"result":{"id":0,"ty":4},"normal":20,"unwind":30}},
                        {"id":20,"instructions":[],"terminator":{"op":"return","value":{"kind":"value","id":0}}},
                        {"id":30,"instructions":[{"result":{"id":1,"ty":3},
                            "operation":{"op":"landing_pad","cleanup":true,"clauses":[]}}],
                            "terminator":{"op":"resume","value":{"kind":"value","id":1}}}]},
                {"name":"source_personality","linkage":"external",
                    "signature":{"params":[],"result":1,"abi":"c","variadic":true},"params":[],"entry":null,"blocks":[]},
                {"name":"may_throw","linkage":"external",
                    "signature":{"params":[],"result":4,"abi":"c","variadic":false},"params":[],"entry":null,"blocks":[]}],
            "provenance":{"input_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "frontend":"authored-structural-test","frontend_version":"1","importer":"test","importer_version":"1",
                "source_function_count":3,"source_global_count":0,"refinements":[]}
        }"#;
        let verified = NativeModule::from_json(raw).expect("Invoke fixture must pass structural verification first");
        assert!(matches!(&verified.functions[0].blocks[0].terminator, Terminator::Invoke { result: Some(_), .. }));
        let report = collect("invoke-unit", raw).unwrap();
        assert_eq!((report.function_count, report.call_site_count, report.unresolved_call_site_count), (3, 1, 0));
        let caller = &report.functions[0];
        let call = &caller.call_sites[0];
        assert!(matches!(&call.site.kind, SiteKind::Invoke));
        assert_eq!((call.site.caller_function_index, call.site.block, call.site.instruction), (0, 10, None));
        assert!(call.raw_site_effects.is_none());
        assert!(!call.raw_direct_declaration_effects.unwrap().returns_twice);
        assert!(!call.same_module_effective_returns_twice);
        assert!(call.nonlocal_call_abi_plan.is_none());
        assert_eq!(call.original_callee_operand["name"], "may_throw");
        assert_eq!(caller.direct_call_dependencies, BTreeSet::from(["may_throw".into()]));
        assert!(caller.referenced_symbols.contains("source_personality"));
        assert!(report.returns_twice_provider_requirements.is_empty());
        assert!(!report.provider_qualified && !report.library_exposure_admitted);
    }

    #[test]
    fn verified_function_alias_call_stays_an_unresolved_alias_edge() {
        let mut value: Value = serde_json::from_slice(&fixture(false, false, false, false)).unwrap();
        let signature = value["functions"][1]["signature"].clone();
        value["types"].as_array_mut().unwrap().push(json!({"kind":"function","signature":signature}));
        // A valid alias must target an actual included emitted definition.
        value["functions"][1]["entry"] = json!(10);
        value["functions"][1]["blocks"] = json!([{"id":10,"instructions":[],
            "terminator":{"op":"return","value":{"kind":"int","ty":0,"bits":"17"}}}]);
        value["aliases"] = json!([{"name":"checkpoint_alias","ty":2,
            "aliasee":"original_checkpoint","linkage":"external"}]);
        value["provenance"]["source_alias_count"] = json!(1);
        value["functions"][0]["blocks"][0]["instructions"][0]["operation"]["callee"]["name"] = json!("checkpoint_alias");
        let raw = serde_json::to_vec(&value).unwrap();
        let verified = NativeModule::from_json(&raw).expect("alias fixture must pass structural verification first");
        assert_eq!(verified.aliases.len(), 1);
        assert!(verified.functions[1].entry.is_some());
        let report = collect("alias-unit", &raw).unwrap();
        let caller = &report.functions[0];
        let call = &caller.call_sites[0];
        assert!(matches!(&call.callee, Callee::DirectAliasUnresolved { symbol } if symbol == "checkpoint_alias"));
        assert_eq!(report.unresolved_call_site_count, 1);
        assert_eq!(caller.direct_call_dependencies, BTreeSet::from(["checkpoint_alias".into()]));
        assert_eq!(call.original_callee_operand["name"], "checkpoint_alias");
        assert!(call.raw_direct_declaration_effects.is_none());
        assert!(!call.raw_site_effects.unwrap().returns_twice);
        assert!(!call.same_module_effective_returns_twice);
        assert!(report.returns_twice_provider_requirements.is_empty());
        assert!(!report.provider_qualified && !report.library_exposure_admitted);
    }

    #[test]
    fn unsupported_shared_entry_abi_plan_is_retained_after_verified_input() {
        let mut value: Value = serde_json::from_slice(&fixture(true, true, false, false)).unwrap();
        value["types"].as_array_mut().unwrap().extend([
            json!({"kind":"float","bits":64}),
            json!({"kind":"struct","fields":[2],"packed":false}),
        ]);
        value["functions"][0]["signature"]["params"] = json!([3]);
        value["functions"][0]["params"] = json!([{"id":0,"ty":3}]);
        let raw = serde_json::to_vec(&value).unwrap();
        let verified = NativeModule::from_json(&raw).expect("unsupported-ABI fixture must pass structural verification first");
        // This exact shared planner failure is the intended oracle; no malformed
        // module, target mismatch or variadic precondition can satisfy the test.
        let error = native_abi::plan_function(&verified, Target::X86_64UnknownNone,
            &verified.functions[0]).expect_err("by-value floating aggregate transport is not implemented");
        let expected = error.to_string();
        assert!(expected.contains("floating-point aggregate ABI/HFA requires explicit lowering"), "{expected}");
        let report = collect("unsupported-abi-unit", &raw).unwrap();
        let observation = report.functions[0].nonlocal_entry_abi_plan.as_ref().unwrap();
        match observation {
            AbiObservation::Unsupported { reason } => assert_eq!(reason, &expected),
            other => panic!("required unsupported shared-plan observation was lost: {other:?}"),
        }
        assert_eq!((report.function_count, report.call_site_count), (2, 1));
        assert!(report.functions[0].call_sites[0].same_module_effective_returns_twice);
        assert_eq!(report.returns_twice_provider_requirements.len(), 1);
        assert_eq!(report.unmet.len(), 5);
        assert!(!report.provider_qualified && !report.library_exposure_admitted && !report.rust_ovalue_boundary_qualified);
    }

}
