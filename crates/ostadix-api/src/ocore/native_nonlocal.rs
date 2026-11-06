//! Computed native continuation/frame witnesses, not jump-provider admission.
//!
//! A standalone fixed-frame object may retain a returns_twice continuation.
//! This does not admit an original save/resume provider, signal/TLS/unwind
//! implementation, dynamic-library entry, or a jump across Rust/OValue frames.
//! Reports describe the exact nonoptimizing emitter and are checked by complete
//! canonical re-emission; accepting a report is not a proof of all codegen.
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use super::native_ir::{error_diagnostic, ControlEffects, NativeModule, Signature, ValueId};
use super::{Diagnostic, Target};

pub const FORMAT: &str = "ocore-native-nonlocal-frame-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeNonlocalReport {
    pub format: String,
    pub target: String,
    pub source_target: JsonValue,
    pub module_sha256: String,
    pub input_sha256: String,
    pub assembly_sha256: String,
    pub assembly_bytes: usize,
    pub has_nonlocal_effects: bool,
    pub functions: Vec<FunctionFrameProof>,
    pub original_provider_obligations: Vec<OriginalProviderObligation>,
    pub provider_qualified: bool,
    pub library_exposure_admitted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FunctionFrameProof {
    pub function_index: usize,
    pub function: String,
    pub declaration_effects: ControlEffects,
    pub signature: Signature,
    pub source_abi: JsonValue,
    /// Exact shared planner output, not a separately implemented C ABI map.
    pub entry_abi_plan: JsonValue,
    pub frame_pointer: String,
    pub stack_pointer: String,
    pub entry_sp_from_fp: i64,
    pub incoming_stack_base: i64,
    pub fixed_frame_bytes: i64,
    pub steady_sp_from_fp: i64,
    pub stack_alignment: u64,
    pub saved_frame_registers: Vec<SavedFrameRegister>,
    /// Every actual emitter storage region; padding is not invented storage.
    pub regions: Vec<FrameRegion>,
    pub call_sites: Vec<NonlocalCallSiteProof>,
    pub state_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SavedFrameRegister {
    pub register: String,
    pub offset_from_fp: i64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrameRegion {
    pub role: String,
    pub value: Option<ValueId>,
    pub ty: Option<usize>,
    pub offset_from_fp: i64,
    pub bytes: u64,
    pub alignment: u64,
    pub chunks: Vec<SpillChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpillChunk {
    pub leaf: usize,
    /// Logical bit offset within the typed leaf, independent of its packed
    /// memory extent. Fixed vectors may span more than 65,535 value bits.
    pub bit_offset: u64,
    pub value_bits: u16,
    pub offset_from_fp: i64,
    pub storage_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NonlocalCallSiteProof {
    pub block: usize,
    pub instruction: usize,
    pub callee: String,
    pub callee_function_index: usize,
    pub declaration_effects: ControlEffects,
    pub call_effects: ControlEffects,
    pub signature: Signature,
    pub arguments: JsonValue,
    pub result: JsonValue,
    pub abi_plan: JsonValue,
    pub outgoing_stack_bytes: i64,
    /// SP saved by the original provider must resume at this exact value.
    pub continuation_sp_from_fp: i64,
    pub call_assembly_start: usize,
    pub call_assembly_end: usize,
    pub resume_label: String,
    pub resume_assembly_start: usize,
    pub resume_assembly_end: usize,
    pub result_capture_after_resume: bool,
    pub stack_restore_after_resume: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginalProviderObligation {
    pub function_index: usize,
    pub symbol: String,
    pub original_definition_present: bool,
    pub declaration_effects: ControlEffects,
    pub signature: Signature,
    pub source_abi: JsonValue,
    pub effective_sites: Vec<ProviderSite>,
    pub required_context: Vec<String>,
    pub provider_qualified: bool,
    pub library_exposure_admitted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSite {
    pub caller_function_index: usize,
    pub block: usize,
    pub instruction: usize,
}

pub(crate) fn snapshot<T: Serialize>(value: &T) -> Result<JsonValue, Diagnostic> {
    serde_json::to_value(value)
        .map_err(|error| error_diagnostic(format!("nonlocal report serialization: {error}")))
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

impl FunctionFrameProof {
    /// Check physical containment, alignment and non-reuse of the actual
    /// emitter's regions. The caller also binds every SSA chunk and fixed
    /// allocation to these regions while constructing this witness.
    pub(crate) fn validate_regions(&self) -> Result<(), Diagnostic> {
        let fail = || error_diagnostic("nonlocal frame storage containment/alignment/non-reuse proof failed");
        if self.fixed_frame_bytes < 0 || self.fixed_frame_bytes % 16 != 0
            || self.steady_sp_from_fp != -self.fixed_frame_bytes
            || self.stack_alignment != 16 {
            return Err(fail());
        }
        let mut spans = Vec::new();
        for region in &self.regions {
            let size = i64::try_from(region.bytes).map_err(|_| fail())?;
            let end = region.offset_from_fp.checked_add(size).ok_or_else(fail)?;
            if region.alignment == 0 || !region.alignment.is_power_of_two()
                || region.alignment > 16
                || region.offset_from_fp < -self.fixed_frame_bytes || end > 0
                || region.offset_from_fp.rem_euclid(region.alignment as i64) != 0 {
                return Err(fail());
            }
            if size > 0 { spans.push((region.offset_from_fp, end)); }
            let mut chunks = Vec::new();
            for chunk in &region.chunks {
                let chunk_end = chunk.offset_from_fp.checked_add(8).ok_or_else(fail)?;
                if chunk.storage_bytes != 8 || !(1..=64).contains(&chunk.value_bits)
                    || chunk.offset_from_fp < region.offset_from_fp || chunk_end > end
                    || chunk.offset_from_fp % 8 != 0 {
                    return Err(fail());
                }
                chunks.push((chunk.offset_from_fp, chunk_end));
            }
            chunks.sort_unstable();
            if chunks.windows(2).any(|p| p[0].1 > p[1].0) { return Err(fail()); }
        }
        spans.sort_unstable();
        if spans.windows(2).any(|p| p[0].1 > p[1].0) { return Err(fail()); }
        Ok(())
    }
}

impl NativeNonlocalReport {
    pub(crate) fn from_emission(module: &NativeModule, target: Target, assembly: &str,
        functions: Vec<FunctionFrameProof>) -> Result<Self, Diagnostic> {
        let mut obligations = Vec::new();
        for (index, function) in module.functions.iter().enumerate() {
            let effective_sites: Vec<_> = functions.iter().flat_map(|caller| {
                caller.call_sites.iter().filter(move |site| site.callee_function_index == index)
                    .map(move |site| ProviderSite { caller_function_index: caller.function_index,
                        block: site.block, instruction: site.instruction })
            }).collect();
            // Preserve cold declarations; site-only effects do not get promoted
            // into invented declaration attributes or omitted provider duties.
            if !function.control_effects.returns_twice && effective_sites.is_empty() { continue; }
            let mut required_context = vec![
                "original save/resume implementation and recursive provider closure are not admitted".into(),
                "resume the exact call continuation with its saved FP/SP and ABI return locations".into(),
                "preserve the selected original ABI callee-saved state and original jump-buffer layout".into(),
                "preserve original signal-mask, thread/TLS, unwind and target-feature contracts where applicable".into(),
                "only live original C frames; Rust/OValue/graph callback crossings remain forbidden".into(),
            ];
            required_context.push(match target {
                Target::X86_64UnknownNone => "x86-64 original provider must account for RBX/RBP/R12-R15, pointer guards and any enabled shadow-stack/CET contract",
                Target::Aarch64UnknownNone => "AArch64 original provider must account for X19-X30, SP, preserved SIMD state and any enabled PAC/GCS/SME contract",
                Target::Riscv64UnknownNone if module.target.abi.as_deref() == Some("lp64d") => "RV64 LP64D original provider must account for RA, SP, S0-S11 and FS0-FS11 with the original FLEN/ABI contract",
                Target::Riscv64UnknownNone => "RV64 LP64 original provider must account for RA, SP and S0-S11; hard-float provider compatibility is not inferred",
            }.into());
            obligations.push(OriginalProviderObligation { function_index: index,
                symbol: function.name.clone(), original_definition_present: function.entry.is_some(),
                declaration_effects: function.control_effects, signature: function.signature.clone(),
                source_abi: snapshot(&function.source_abi)?, effective_sites, required_context,
                provider_qualified: false, library_exposure_admitted: false });
        }
        Ok(Self { format: FORMAT.into(), target: target.name().into(), source_target: snapshot(&module.target)?,
            module_sha256: digest(&serde_json::to_vec(module).map_err(|e| error_diagnostic(e.to_string()))?),
            input_sha256: module.provenance.input_sha256.clone(), assembly_sha256: digest(assembly.as_bytes()),
            assembly_bytes: assembly.len(), has_nonlocal_effects: module.has_nonlocal_control_effects(),
            functions, original_provider_obligations: obligations, provider_qualified: false,
            library_exposure_admitted: false })
    }

    pub fn to_json(&self) -> Result<Vec<u8>, Diagnostic> {
        serde_json::to_vec_pretty(self)
            .map_err(|error| error_diagnostic(format!("nonlocal report: {error}")))
    }
}

/// Strictly decode and recompute every physical frame/site and exact assembly.
/// No report field, claimed digest, provider flag or mutated resume label grants
/// admission on its own. This remains descriptive compiler evidence only.
pub fn verify_report_json(report_json: &[u8], module: &NativeModule, target: Target,
    assembly: &str) -> Result<NativeNonlocalReport, Diagnostic> {
    let report: NativeNonlocalReport = serde_json::from_slice(report_json)
        .map_err(|error| error_diagnostic(format!("invalid nonlocal report: {error}")))?;
    let (expected_assembly, expected) = super::native_codegen::emit_with_nonlocal_report(module, target)?;
    if expected_assembly != assembly || report != expected {
        return Err(error_diagnostic("nonlocal report or assembly differs from canonical computed emission"));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::native_codegen::{emit, emit_with_map, emit_with_nonlocal_report,
        emit_with_map_and_nonlocal_report};
    use serde_json::json;

    fn fixture(target: Target, abi: Option<&str>, declaration: bool, site: bool) -> NativeModule {
        let triple = match target {
            Target::X86_64UnknownNone => "x86_64-unknown-linux-gnu",
            Target::Aarch64UnknownNone => "aarch64-unknown-linux-gnu",
            Target::Riscv64UnknownNone => "riscv64-unknown-linux-gnu",
        };
        let signature = json!({"params":[3,2,2,2,2,2,2,2,2,2],"result":1,"abi":"c","variadic":false});
        let declaration_params: Vec<_> = (0..10).map(|id|
            json!({"id":id,"ty":if id==0 {3} else {2}})).collect();
        let mut args = vec![json!({"kind":"value","id":2})];
        args.extend((1..=9).map(|n| json!({"kind":"int","ty":2,"bits":n.to_string()})));
        serde_json::from_value(json!({
            "format":"ocore-native-module-v1","name":"nonlocal-physical-frame",
            "target":{"triple":triple,"abi":abi,"data_layout":"e-p:64:64-i64:64-i128:128-n32:64-S128",
                "pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"int","bits":32},{"kind":"int","bits":64},
                {"kind":"pointer","address_space":0},{"kind":"int","bits":128}],
            "globals":[],"functions":[
                {"name":"original_checkpoint","linkage":"external","control_effects":{"returns_twice":declaration},
                    "signature":signature.clone(),"params":declaration_params.clone(),"entry":null,"blocks":[]},
                {"name":"original_cold_checkpoint","linkage":"external","control_effects":{"returns_twice":true},
                    "signature":signature.clone(),"params":declaration_params.clone(),"entry":null,"blocks":[]},
                {"name":"caller","linkage":"external",
                    "signature":{"params":[3,4],"result":1,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":3},{"id":1,"ty":4}],"entry":0,
                    "blocks":[{"id":0,"instructions":[
                        {"result":{"id":2,"ty":3},"operation":{"op":"alloca","size":32,"alignment":16}},
                        {"result":{"id":3,"ty":4},"operation":{"op":"binary","kind":"add",
                            "lhs":{"kind":"value","id":1},"rhs":{"kind":"int","ty":4,"bits":"1"},"flags":[]}},
                        {"result":null,"operation":{"op":"store","pointer":{"kind":"value","id":2},
                            "value":{"kind":"int","ty":1,"bits":"17"},"alignment":4,"volatile":true}},
                        {"result":{"id":4,"ty":1},"operation":{"op":"call","callee":{"kind":"symbol","ty":3,"name":"original_checkpoint"},
                            "signature":signature,"args":args,"control_effects":{"returns_twice":site}}},
                        {"result":{"id":5,"ty":1},"operation":{"op":"load","pointer":{"kind":"value","id":2},"alignment":4,"volatile":true}},
                        {"result":{"id":6,"ty":1},"operation":{"op":"binary","kind":"add",
                            "lhs":{"kind":"value","id":4},"rhs":{"kind":"value","id":5},"flags":[]}}
                    ],"terminator":{"op":"jump","target":7}},
                    {"id":7,"instructions":[{"result":{"id":7,"ty":1},"operation":{"op":"phi",
                        "incoming":[{"block":0,"value":{"kind":"value","id":6}}]}}],
                        "terminator":{"op":"return","value":{"kind":"value","id":7}}}]
                }],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"unit-test","frontend_version":"1",
                "importer":"unit-test","importer_version":"1","source_function_count":3,"source_global_count":0,"refinements":[]}
        })).unwrap()
    }

    fn profiles() -> [(Target, Option<&'static str>); 4] {
        [(Target::X86_64UnknownNone,None),(Target::Aarch64UnknownNone,None),
            (Target::Riscv64UnknownNone,Some("lp64")),(Target::Riscv64UnknownNone,Some("lp64d"))]
    }

    #[test]
    fn computed_frames_bind_actual_spills_allocas_phi_abi_and_resume_on_four_profiles() {
        for (target, abi) in profiles() {
            let m = fixture(target, abi, true, true);
            let (assembly, map, report) = emit_with_map_and_nonlocal_report(&m, target).unwrap();
            assert_eq!(emit(&m,target).unwrap(),assembly);
            assert_eq!(emit_with_map(&m,target).unwrap().0,assembly);
            assert_eq!(report.functions.len(),1);
            assert!(!report.provider_qualified && !report.library_exposure_admitted);
            let frame = &report.functions[0];
            assert_eq!(frame.function,"caller");
            frame.validate_regions().unwrap();
            assert!(frame.regions.iter().any(|r| r.role=="fixed_original_alloca" && r.bytes==32 && r.alignment==16));
            assert!(frame.regions.iter().any(|r| r.role=="phi_parallel_copy" && r.bytes==8));
            assert_eq!(frame.regions.iter().find(|r| r.value==Some(1) && r.role=="ssa_spill").unwrap().chunks.len(),2);
            let site = &frame.call_sites[0];
            assert_eq!((site.block,site.instruction),(0,3));
            assert!(site.outgoing_stack_bytes>0);
            assert_eq!(site.continuation_sp_from_fp,-frame.fixed_frame_bytes-site.outgoing_stack_bytes);
            assert_eq!(site.call_assembly_end,site.resume_assembly_start);
            assert_eq!(&assembly[site.resume_assembly_start..site.resume_assembly_end],format!("{}:\n",site.resume_label));
            assert_eq!(&assembly[site.call_assembly_start..site.call_assembly_end],format!("  {} original_checkpoint\n",if target==Target::Aarch64UnknownNone {"bl"} else {"call"}));
            assert!(site.result_capture_after_resume && site.stack_restore_after_resume);
            assert!(map.sites.iter().any(|s| s.function=="caller" && s.block==Some(0) && s.instruction==Some(3)
                && s.assembly_start<=site.call_assembly_start && s.assembly_end>site.resume_assembly_end));
            let verified=verify_report_json(&report.to_json().unwrap(),&m,target,&assembly).unwrap();
            assert_eq!(verified,report);
            assert_eq!(report.original_provider_obligations.len(),2);
            assert!(report.original_provider_obligations.iter().all(|p| !p.provider_qualified && !p.library_exposure_admitted));
            let cold=report.original_provider_obligations.iter().find(|p| p.symbol=="original_cold_checkpoint").unwrap();
            assert!(cold.effective_sites.is_empty());
        }
    }

    #[test]
    fn declaration_and_site_only_effects_do_not_invent_each_others_raw_attributes() {
        for (declaration,site) in [(true,false),(false,true),(true,true)] {
            let m=fixture(Target::Riscv64UnknownNone,Some("lp64d"),declaration,site);
            let (_,report)=emit_with_nonlocal_report(&m,Target::Riscv64UnknownNone).unwrap();
            let proof=&report.functions[0].call_sites[0];
            assert_eq!(proof.declaration_effects.returns_twice,declaration);
            assert_eq!(proof.call_effects.returns_twice,site);
            assert_eq!(report.original_provider_obligations[0].declaration_effects.returns_twice,declaration);
            assert_eq!(report.original_provider_obligations[0].effective_sites.len(),1);
        }
    }

    #[test]
    fn cold_declarations_remain_unqualified_without_invented_native_calls() {
        let m=fixture(Target::Riscv64UnknownNone,Some("lp64d"),false,false);
        let (assembly,report)=emit_with_nonlocal_report(&m,Target::Riscv64UnknownNone).unwrap();
        assert!(report.has_nonlocal_effects);
        assert!(report.functions.is_empty());
        assert_eq!(report.original_provider_obligations.len(),1);
        assert_eq!(report.original_provider_obligations[0].symbol,"original_cold_checkpoint");
        assert!(report.original_provider_obligations[0].effective_sites.is_empty());
        assert!(!assembly.contains("_nonlocal_b"));
    }

    #[test]
    fn canonical_report_rejects_forged_frames_sites_targets_effects_and_qualification() {
        let target=Target::Riscv64UnknownNone;
        let m=fixture(target,Some("lp64d"),true,true);
        let (assembly,report)=emit_with_nonlocal_report(&m,target).unwrap();
        let baseline=serde_json::to_value(&report).unwrap();
        for mutation in 0..12 {
            let mut v=baseline.clone();
            match mutation {
                0=>v["provider_qualified"]=json!(true),
                1=>v["library_exposure_admitted"]=json!(true),
                2=>v["functions"][0]["call_sites"][0]["resume_label"]=json!("invented"),
                3=>v["functions"][0]["call_sites"][0]["continuation_sp_from_fp"]=json!(0),
                4=>v["functions"][0]["call_sites"][0]["call_effects"]["returns_twice"]=json!(false),
                5=>v["functions"][0]["regions"][0]["offset_from_fp"]=json!(0),
                6=>v["functions"][0]["entry_abi_plan"]["stack_bytes"]=json!(999),
                7=>v["source_target"]["abi"]=json!("lp64"),
                8=>v["original_provider_obligations"]=json!([]),
                9=>v["assembly_sha256"]=json!("0".repeat(64)),
                10=>v["target"]=json!("x86_64-unknown-none"),
                _=>v["invented_authority"]=json!(true),
            }
            assert!(verify_report_json(&serde_json::to_vec(&v).unwrap(),&m,target,&assembly).is_err(),"mutation {mutation}");
        }
        let changed=assembly.replace("original_checkpoint\n","original_cold_checkpoint\n");
        assert_ne!(changed,assembly);
        assert!(verify_report_json(&report.to_json().unwrap(),&m,target,&changed).is_err());
    }

    #[test]
    fn physical_region_check_rejects_overlap_escape_and_misalignment() {
        let m=fixture(Target::Riscv64UnknownNone,Some("lp64d"),true,true);
        let (_,r)=emit_with_nonlocal_report(&m,Target::Riscv64UnknownNone).unwrap();
        let original=&r.functions[0];
        for kind in 0..4 {
            let mut p=original.clone();
            match kind {
                0=>p.regions.push(p.regions[0].clone()),
                1=>p.regions[0].offset_from_fp=0,
                2=>p.regions[0].offset_from_fp-=1,
                _=>p.steady_sp_from_fp+=16,
            }
            assert!(p.validate_regions().is_err());
        }
    }

    #[test]
    fn unsupported_nonlocal_overalignment_or_nonentry_alloca_is_not_admitted_by_frame_report() {
        use super::super::native_ir::{Instruction, Operation, Value};
        let target=Target::Riscv64UnknownNone;
        // These are authored test controls, not edited original-engine inputs.
        // Independently prove each mutant has valid SSA/types/dominance when
        // only its nonlocal effects are absent. A second unrelated verifier
        // defect must not stand in for the nonlocal fixed-frame policy.
        let prove_otherwise_well_typed = |module: &NativeModule| {
            let mut ordinary = module.clone();
            for function in &mut ordinary.functions {
                function.control_effects = ControlEffects::default();
                for instruction in function.blocks.iter_mut().flat_map(|block| &mut block.instructions) {
                    if let Operation::Call { control_effects, .. } = &mut instruction.operation {
                        *control_effects = ControlEffects::default();
                    }
                }
            }
            super::super::native_verify::verify(&ordinary).unwrap();
        };
        let expected = "returns_twice exposure requires ordinary C with fixed entry allocas and no EH/dynamic-stack combination";
        let mut aligned=fixture(target,Some("lp64d"),true,true);
        aligned.functions[2].blocks[0].instructions[0].operation=Operation::Alloca {size:32,alignment:32};
        prove_otherwise_well_typed(&aligned);
        let error=emit_with_nonlocal_report(&aligned,target).unwrap_err();
        assert!(error.message.contains(expected), "{}", error.message);

        let mut nonentry=fixture(target,Some("lp64d"),true,true);
        // Keep the original entry allocation (id2) and every use unchanged.
        // This fresh otherwise unused id8 is after the existing block7 PHI,
        // so it neither breaks dominance nor moves a PHI behind an instruction.
        assert!(!nonentry.functions[2].params.iter().any(|value| value.id==8));
        assert!(!nonentry.functions[2].blocks.iter().flat_map(|block| &block.instructions)
            .any(|instruction| instruction.result.is_some_and(|value| value.id==8)));
        nonentry.functions[2].blocks[1].instructions.push(Instruction {
            result: Some(Value { id:8, ty:3 }),
            operation: Operation::Alloca { size:8, alignment:8 },
        });
        assert!(matches!(nonentry.functions[2].blocks[0].instructions[0].operation,
            Operation::Alloca {size:32,alignment:16}));
        prove_otherwise_well_typed(&nonentry);
        let error=emit_with_nonlocal_report(&nonentry,target).unwrap_err();
        assert!(error.message.contains(expected), "{}", error.message);
    }
}
