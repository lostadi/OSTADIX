//! Actual whole-unit configured-source readmission/planning, NOT admission.
//!
//! The registered capture verifier currently covers LLVM evidence only. This
//! separate representation cannot become AdmittedCapture, UnitLineage or
//! NativeModule. Caller-selected floors and CIE facts are held BEFORE current
//! observations arrive; packaged copies never select their own coverage floor.
//! The optional borrowed original-function bridge checks source-CFI consistency
//! only. Its object owners and function/body relations are held before resolution;
//! it neither establishes same-produced source/object authority nor admits a producer.
use o_lang::ocore::{
    Target,
    native_machine_asm_unit::ConstructedUnit,
    native_machine_asm_unit_artifact::{readmit_configured_unit, ArtifactError, RequiredFloors},
    native_machine_emit::{plan_unit, plan_unit_with_initial_cies, MachineAssemblyPlan, UnitEmissionFailure},
    native_machine_ir::{ArtifactIdentity, CfiPolicy, DirectTailTarget, SelectedInstructionInventory},
    native_machine_unit::{BodyId, RecordEffect, SelectedUnitInventory, UNIT_INVENTORY_FORMAT_V3},
    native_machine_verify::{CfiInitialCie, CfiSourceProgram, CfiSourceProgramWithInitialCie},
};
use std::collections::{BTreeMap, BTreeSet};
use super::super::exception_inventory::{
    cie_raw_decoder::fde_function::CheckedObjectFunctions,
    cie_source_adapter::{
        verify_source_cfi_from_checked_original_function,
        verify_source_cfi_from_checked_original_function_with_tail_targets,
        OriginalFdeSelection, OriginalFunctionSelection,
    },
};

fn identity(raw: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity { bytes: raw.len() as u64, sha256: super::digest(raw) }
}
fn nonempty(value: &str) -> bool { !value.is_empty() && !value.contains('\0') }
fn valid_identity(value: &ArtifactIdentity) -> bool {
    value.sha256.len() == 64 && value.sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Caller-held whole-output key; never an action-local ordinal/CGU index.
/// Key equality establishes consistency, not authentic fresh-selector authority.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WholeOutputSelector { action: String, output: String }
impl WholeOutputSelector {
    pub(crate) fn new(action: String, output: String) -> Result<Self, String> {
        if !nonempty(&action) || !nonempty(&output) { return Err("empty or NUL-containing whole-output selector".into()); }
        Ok(Self { action, output })
    }
    pub(crate) fn action(&self) -> &str { &self.action }
    pub(crate) fn output(&self) -> &str { &self.output }
}

/// Caller-held relation between an actual selected body and an immutable object.
/// Construction holds inputs only; it does not validate a source/object relation.
/// No Deserialize or bytes-to-success-only convenience conversion is provided.
pub(crate) struct RequiredOriginalFunctionCfi<'f> {
    body: BodyId,
    object_functions: &'f CheckedObjectFunctions,
    selected: OriginalFunctionSelection,
}
impl<'f> RequiredOriginalFunctionCfi<'f> {
    pub(crate) fn new(body: BodyId, object_functions: &'f CheckedObjectFunctions,
        selected: OriginalFunctionSelection) -> Self {
        Self { body, object_functions, selected }
    }
    pub(crate) fn body(&self) -> BodyId { self.body }
    pub(crate) fn object_functions(&self) -> &CheckedObjectFunctions { self.object_functions }
    pub(crate) fn selection(&self) -> &OriginalFunctionSelection { &self.selected }
}

/// One row per actual constructed body, in the constructed unit's order.
/// A relation index refers to the original held vector, never a fresh selector.
pub(crate) enum ConfiguredOriginalFunctionCfiBodyResult {
    NotRequired { body_index: usize, body: BodyId },
    Refused { body_index: usize, body: BodyId, relation_index: Option<usize>, reasons: Vec<String> },
    Verified {
        body_index: usize,
        body: BodyId,
        relation_index: usize,
        selected_fde: OriginalFdeSelection,
        program: CfiSourceProgram,
        source_object_association_verified: bool,
        native_unwind_verified: bool,
    },
}

/// This report owns each successfully checked initial CIE exactly once.
/// The planner borrows this map only after complete coverage succeeds. On a
/// refusal the map may be partial; every body outcome and held owner remains.
pub(crate) struct ConfiguredOriginalFunctionCfiReport {
    selector: WholeOutputSelector,
    bodies: Vec<ConfiguredOriginalFunctionCfiBodyResult>,
    coverage_errors: Vec<String>,
    initial_cies: BTreeMap<BodyId, CfiInitialCie>,
}
impl ConfiguredOriginalFunctionCfiReport {
    pub(crate) fn selector(&self) -> &WholeOutputSelector { &self.selector }
    pub(crate) fn bodies(&self) -> &[ConfiguredOriginalFunctionCfiBodyResult] { &self.bodies }
    pub(crate) fn coverage_errors(&self) -> &[String] { &self.coverage_errors }
    pub(crate) fn initial_cies(&self) -> &BTreeMap<BodyId, CfiInitialCie> { &self.initial_cies }
    pub(crate) fn complete(&self) -> bool {
        self.coverage_errors.is_empty()
            && self.bodies.iter().all(|row| !matches!(row, ConfiguredOriginalFunctionCfiBodyResult::Refused { .. }))
    }
}

fn checked_body_inventory(raw: &[u8]) -> Result<SelectedInstructionInventory, String> {
    let value = super::super::provider_order::checked_json(raw)
        .map_err(|error| format!("held body inventory JSON: {error}"))?;
    serde_json::from_value(value).map_err(|error| format!("held body inventory: {error}"))
}

/// Seal policy from the caller's prior raw V3 inventory, not a fresh body.
/// This index grants no producer authority. The actual constructor still verifies
/// the complete unit/callee before the returned owner can reach this CFI path.
fn checked_tail_targets(floors: &RequiredFloors<'_>)
    -> Result<BTreeMap<BodyId, Vec<DirectTailTarget>>, String> {
    if identity(floors.unit_inventory_json) != floors.unit_selection.inventory {
        return Err("held tail-policy inventory bytes differ from the external selection".into());
    }
    let value = super::super::provider_order::checked_json(floors.unit_inventory_json)
        .map_err(|error| format!("held tail-policy inventory JSON: {error}"))?;
    let floor: SelectedUnitInventory = serde_json::from_value(value)
        .map_err(|error| format!("held tail-policy inventory: {error}"))?;
    if floor.format != UNIT_INVENTORY_FORMAT_V3
        || floor.source != floors.unit_selection.source
        || floor.profile != floors.unit_selection.profile {
        return Err("held tail policy requires the externally selected V3 source/profile".into());
    }
    let mut bodies = BTreeSet::new();
    for body in &floor.bodies {
        if !bodies.insert(body.id) {
            return Err(format!("duplicate held tail-policy body: {:?}", body.id));
        }
    }
    let mut targets: BTreeMap<BodyId, Vec<DirectTailTarget>> = BTreeMap::new();
    let mut sources = BTreeSet::new();
    for record in floor.required.records {
        for effect in record.effects {
            if let RecordEffect::TailTransferSelection { target } = effect {
                if !bodies.contains(&target.caller_body) || !bodies.contains(&target.target_body) {
                    return Err("held tail policy has an orphan caller/callee body".into());
                }
                if !sources.insert(target.source_item) {
                    return Err(format!("duplicate held tail-policy source item: {:?}", target.source_item));
                }
                targets.entry(target.caller_body).or_default().push(target);
            }
        }
    }
    if targets.is_empty() {
        return Err("explicit V3 tail-policy selection is empty".into());
    }
    Ok(targets)
}

/// Readmission has already reconstructed these bodies from configured bytes and
/// independently held floors. No packaged/current CIE or object chooses policy.
fn verify_original_function_cfi(selector: &WholeOutputSelector, constructed: &ConstructedUnit,
    floors: &RequiredFloors<'_>, relations: &[RequiredOriginalFunctionCfi<'_>],
    target: Target, tail_targets: Option<&BTreeMap<BodyId, Vec<DirectTailTarget>>>) -> ConfiguredOriginalFunctionCfiReport {
    let mut report = ConfiguredOriginalFunctionCfiReport {
        selector: selector.clone(), bodies: Vec::with_capacity(constructed.unit.bodies.len()),
        coverage_errors: Vec::new(), initial_cies: BTreeMap::new(),
    };
    let mut body_rows = BTreeMap::<BodyId, Vec<usize>>::new();
    for (index, body) in constructed.unit.bodies.iter().enumerate() {
        body_rows.entry(body.id).or_default().push(index);
    }
    let mut floor_rows = BTreeMap::<BodyId, Vec<&[u8]>>::new();
    for floor in floors.body_floors {
        floor_rows.entry(floor.body).or_default().push(floor.inventory_json);
    }
    let mut relation_rows = BTreeMap::<BodyId, Vec<usize>>::new();
    for (index, relation) in relations.iter().enumerate() {
        relation_rows.entry(relation.body).or_default().push(index);
    }
    // Each index stores membership once. Duplicate groups are not copied into
    // every body or into serialized per-function/object evidence.
    for (body, rows) in &body_rows {
        if rows.len() != 1 {
            report.coverage_errors.push(format!("constructed body ID {body:?} occurs {} times", rows.len()));
        }
    }
    for (body, rows) in &floor_rows {
        if !body_rows.contains_key(body) {
            report.coverage_errors.push(format!("held body floor has no constructed body: {body:?}"));
        }
        if rows.len() != 1 {
            report.coverage_errors.push(format!("held body floor ID {body:?} occurs {} times", rows.len()));
        }
    }
    for (body, rows) in &relation_rows {
        if !body_rows.contains_key(body) {
            report.coverage_errors.push(format!("held original-function relation has no constructed body: {body:?}"));
        }
        if rows.len() != 1 {
            report.coverage_errors.push(format!("held original-function relation ID {body:?} occurs {} times", rows.len()));
        }
    }
    for (body_index, body) in constructed.unit.bodies.iter().enumerate() {
        let mut reasons = Vec::new();
        if body_rows.get(&body.id).is_none_or(|rows| rows.len() != 1) {
            reasons.push("constructed body ID is not unique".into());
        }
        let held_floor = match floor_rows.get(&body.id) {
            Some(rows) if rows.len() == 1 => Some(rows[0]),
            Some(_) => { reasons.push("held body floor is not unique".into()); None }
            None => { reasons.push("held body floor is missing".into()); None }
        };
        if held_floor.is_some_and(|raw| raw != body.selected_inventory_json.as_slice()) {
            reasons.push("constructed body's selected inventory bytes differ from its held floor".into());
        }
        let rows = relation_rows.get(&body.id).map(Vec::as_slice).unwrap_or(&[]);
        let relation_index = if rows.len() == 1 { Some(rows[0]) } else { None };
        match &body.contract.profile.cfi {
            CfiPolicy::NoCfiDeclared => {
                if !rows.is_empty() {
                    reasons.push("original-function CIE relation supplied for a body declaring no CFI".into());
                }
                if reasons.is_empty() {
                    report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::NotRequired { body_index, body: body.id });
                } else {
                    report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Refused { body_index, body: body.id, relation_index, reasons });
                }
                continue;
            }
            CfiPolicy::Required => {
                if rows.is_empty() {
                    reasons.push("required-CFI body has no held original-function relation".into());
                } else if rows.len() != 1 {
                    reasons.push("required-CFI body has ambiguous held original-function relations".into());
                }
            }
        }
        if !reasons.is_empty() {
            report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Refused { body_index, body: body.id, relation_index, reasons });
            continue;
        }
        let Some(relation_index) = relation_index else {
            report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Refused {
                body_index, body: body.id, relation_index: None,
                reasons: vec!["required original-function relation index is unavailable".into()],
            });
            continue;
        };
        let Some(raw) = held_floor else {
            report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Refused {
                body_index, body: body.id, relation_index: Some(relation_index),
                reasons: vec!["required held body inventory is unavailable".into()],
            });
            continue;
        };
        let inventory = match checked_body_inventory(raw) {
            Ok(inventory) => inventory,
            Err(reason) => {
                report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Refused {
                    body_index, body: body.id, relation_index: Some(relation_index), reasons: vec![reason],
                });
                continue;
            }
        };
        let relation = &relations[relation_index];
        // ConstructedUnit reached this call only after real complete-unit/callee
        // verification. Policy is held from the prior raw floor, not a fresh V4
        // terminal or a cached success flag. Ordinary bodies keep the old API.
        let checked = match tail_targets.and_then(|selected| selected.get(&body.id)) {
            Some(selected) => verify_source_cfi_from_checked_original_function_with_tail_targets(
                relation.object_functions, &relation.selected, &body.contract,
                &inventory, target, selected),
            None => verify_source_cfi_from_checked_original_function(relation.object_functions,
                &relation.selected, &body.contract, &inventory, target),
        };
        match checked {
            Err(error) => report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Refused {
                body_index, body: body.id, relation_index: Some(relation_index),
                reasons: vec![format!("checked original-function source-CFI verification: {error}")],
            }),
            Ok((selected_fde, checked)) => {
                let CfiSourceProgramWithInitialCie { program, initial_cie,
                    source_object_association_verified, native_unwind_verified } = checked;
                match report.initial_cies.entry(body.id) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(initial_cie);
                        report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Verified {
                            body_index, body: body.id, relation_index, selected_fde, program,
                            source_object_association_verified, native_unwind_verified,
                        });
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {
                        report.bodies.push(ConfiguredOriginalFunctionCfiBodyResult::Refused {
                            body_index, body: body.id, relation_index: Some(relation_index),
                            reasons: vec!["checked initial-CIE body ID would overwrite an earlier entry".into()],
                        });
                    }
                }
            }
        }
    }
    let expected: BTreeSet<_> = constructed.unit.bodies.iter()
        .filter(|body| matches!(&body.contract.profile.cfi, CfiPolicy::Required))
        .map(|body| body.id).collect();
    let actual: BTreeSet<_> = report.initial_cies.keys().copied().collect();
    if actual != expected {
        report.coverage_errors.push("checked initial-CIE keys differ from actual required-CFI body IDs".into());
    }
    report
}

/// Independent original selection, retained immutably through resolution.
/// Floors and explicit CIE facts cannot be replaced by current observations.
/// No Deserialize is provided for this borrowed input or its private owner.
pub(crate) struct RequiredConfiguredOutput<'f> {
    selector: WholeOutputSelector,
    source_unit_id: String,
    artifact: ArtifactIdentity,
    configured: ArtifactIdentity,
    floors: RequiredFloors<'f>,
    initial_cies: Option<&'f BTreeMap<BodyId, CfiInitialCie>>,
    original_functions: Option<Vec<RequiredOriginalFunctionCfi<'f>>>,
    tail_targets: Option<BTreeMap<BodyId, Vec<DirectTailTarget>>>,
}
impl<'f> RequiredConfiguredOutput<'f> {
    pub(crate) fn new(selector: WholeOutputSelector, source_unit_id: String,
        artifact: ArtifactIdentity, configured: ArtifactIdentity, floors: RequiredFloors<'f>,
        initial_cies: Option<&'f BTreeMap<BodyId, CfiInitialCie>>) -> Result<Self, String> {
        if !nonempty(&source_unit_id) || !valid_identity(&artifact) || !valid_identity(&configured) {
            return Err("invalid independently selected configured-output identity".into());
        }
        Ok(Self { selector, source_unit_id, artifact, configured, floors, initial_cies, original_functions: None, tail_targets: None })
    }
    /// Explicit opt-in borrowed-owner policy. The original constructor and its
    /// caller-selected map/None semantics are preserved without mixing policies.
    pub(crate) fn new_with_original_functions(selector: WholeOutputSelector, source_unit_id: String,
        artifact: ArtifactIdentity, configured: ArtifactIdentity, floors: RequiredFloors<'f>,
        original_functions: Vec<RequiredOriginalFunctionCfi<'f>>) -> Result<Self, String> {
        let mut required = Self::new(selector, source_unit_id, artifact, configured, floors, None)?;
        required.original_functions = Some(original_functions);
        Ok(required)
    }
    /// Explicit original-function CFI opt-in with prior held V3 tail policy.
    /// Existing constructors keep no-policy behavior. Current observations, CIEs,
    /// object names and freshly constructed terminals never choose the policy.
    pub(crate) fn new_with_original_functions_and_tail_targets(selector: WholeOutputSelector,
        source_unit_id: String, artifact: ArtifactIdentity, configured: ArtifactIdentity,
        floors: RequiredFloors<'f>, original_functions: Vec<RequiredOriginalFunctionCfi<'f>>)
        -> Result<Self, String> {
        let mut required = Self::new_with_original_functions(selector, source_unit_id,
            artifact, configured, floors, original_functions)?;
        required.tail_targets = Some(checked_tail_targets(&required.floors)?);
        Ok(required)
    }
    pub(crate) fn selector(&self) -> &WholeOutputSelector { &self.selector }
    pub(crate) fn original_function_cfi(&self) -> Option<&[RequiredOriginalFunctionCfi<'f>]> {
        self.original_functions.as_deref()
    }
}

/// Current bytes only. There is deliberately no current floor/CIE input.
pub(crate) struct ConfiguredOutputObservation<'b> {
    selector: WholeOutputSelector,
    artifact: &'b [u8],
    configured: &'b [u8],
}
impl<'b> ConfiguredOutputObservation<'b> {
    pub(crate) fn new(selector: WholeOutputSelector, artifact: &'b [u8], configured: &'b [u8]) -> Self {
        Self { selector, artifact, configured }
    }
}

/// Context from the actual compiled registry, not an evidence verifier or token.
#[derive(Debug)]
pub(crate) struct AssemblyProducerBoundary {
    registry: ArtifactIdentity,
    requested_producer: String,
    registered_entry: Option<serde_json::Value>,
}
impl AssemblyProducerBoundary {
    pub(crate) fn registry(&self) -> &ArtifactIdentity { &self.registry }
    pub(crate) fn requested_producer(&self) -> &str { &self.requested_producer }
    pub(crate) fn registered_entry(&self) -> Option<&serde_json::Value> { self.registered_entry.as_ref() }
    pub(crate) fn missing_contract(&self) -> &'static str {
        "genuine configured-assembly producer verification and stable original-to-fresh whole-output selector authority remain unavailable"
    }
    pub(crate) fn producer_evidence_verified(&self) -> bool { false }
}

pub(crate) struct ConfiguredAssemblyCommitment<'f> {
    action_selector: String,
    original_action: Vec<u8>,
    original_action_identity: ArtifactIdentity,
    required: Vec<RequiredConfiguredOutput<'f>>,
    occurrences: Vec<WholeOutputSelector>,
    occurrence_indices: Vec<usize>,
    boundary: AssemblyProducerBoundary,
    target: Target,
}
impl<'f> ConfiguredAssemblyCommitment<'f> {
    // source_action supplies the actual compiled registry, not caller JSON.
    pub(super) fn seal(registry: &[u8], producer: &str, action_selector: String,
        original_action: &[u8], required: Vec<RequiredConfiguredOutput<'f>>,
        occurrences: Vec<WholeOutputSelector>, target: Target) -> Result<Self, String> {
        if !nonempty(producer) || !nonempty(&action_selector) || original_action.is_empty() || required.is_empty() {
            return Err("configured handoff requires an original action and nonempty complete whole-output membership".into());
        }
        let value = super::super::provider_order::checked_json(registry).map_err(|e| format!("compiled producer registry: {e}"))?;
        if value["schema"] != "ocore-producer-registry-v1" { return Err("compiled registry schema differs".into()); }
        let entries = value["producers"].as_array().ok_or("compiled registry lacks producer entries")?;
        let mut ids = BTreeSet::new();
        let mut registered_entry = None;
        for entry in entries {
            let id = entry["id"].as_str().filter(|s| nonempty(s)).ok_or("compiled registry has an invalid producer ID")?;
            if !ids.insert(id) { return Err("compiled registry repeats a producer ID".into()); }
            if id == producer { registered_entry = Some(entry.clone()); }
        }
        let mut indices = BTreeMap::new();
        for (i, output) in required.iter().enumerate() {
            if output.selector.action != action_selector || indices.insert(output.selector.clone(), i).is_some() {
                return Err("whole-output selection repeats a key or selects another original action".into());
            }
        }
        let mut used = BTreeSet::new();
        let mut occurrence_indices = Vec::with_capacity(occurrences.len());
        for selector in &occurrences {
            let index = *indices.get(selector).ok_or("original occurrence is outside required whole-output membership")?;
            occurrence_indices.push(index);
            used.insert(index);
        }
        if used.len() != required.len() { return Err("original occurrence policy omits a required whole output".into()); }
        Ok(Self { action_selector, original_action: original_action.to_vec(), original_action_identity: identity(original_action),
            required, occurrences, occurrence_indices, target,
            boundary: AssemblyProducerBoundary { registry: identity(registry), requested_producer: producer.into(), registered_entry } })
    }

    /// Consume every selected unit through actual detached readmission and body
    /// selection. Observations may be permuted; sealed original occurrences and
    /// multiplicity remain unchanged. Failures do not silently select a subset.
    pub(crate) fn resolve(self, observed_original_action: &[u8], observations: Vec<ConfiguredOutputObservation<'_>>) -> UnadmittedConfiguredAction<'f> {
        let mut association_errors = Vec::new();
        if observed_original_action != self.original_action.as_slice() {
            association_errors.push("observed original action differs from its prior held bytes".into());
        }
        let required_keys: BTreeSet<_> = self.required.iter().map(|r| r.selector.clone()).collect();
        let mut current = BTreeMap::<WholeOutputSelector, Vec<ConfiguredOutputObservation<'_>>>::new();
        let mut observed = Vec::with_capacity(observations.len());
        for observation in observations {
            observed.push(ObservedWholeOutput { selector: observation.selector.clone(), artifact: identity(observation.artifact), configured: identity(observation.configured) });
            if !required_keys.contains(&observation.selector) {
                association_errors.push(format!("extra whole output: {:?}", observation.selector));
            }
            current.entry(observation.selector.clone()).or_default().push(observation);
        }
        let mut outputs = Vec::with_capacity(self.required.len());
        let mut original_function_cfi_reports = Vec::new();
        for required in &self.required {
            let Some(mut candidates) = current.remove(&required.selector) else {
                outputs.push(ConfiguredOutputResult::AssociationRefused { selector: required.selector.clone(), reason: "required whole output is missing".into() });
                continue;
            };
            if candidates.len() != 1 {
                outputs.push(ConfiguredOutputResult::AssociationRefused { selector: required.selector.clone(), reason: "whole-output key has multiple observations".into() });
                continue;
            }
            let observation = candidates.remove(0);
            if identity(observation.artifact) != required.artifact || identity(observation.configured) != required.configured {
                outputs.push(ConfiguredOutputResult::AssociationRefused { selector: required.selector.clone(), reason: "consumed artifact/configured bytes differ from prior selected identities".into() });
                continue;
            }
            // These are the held caller inputs. No bytes from packaged floors
            // or from the current observation select their own coverage.
            let floors = RequiredFloors {
                syntax_selection: required.floors.syntax_selection,
                syntax_inventory_json: required.floors.syntax_inventory_json,
                unit_selection: required.floors.unit_selection,
                unit_inventory_json: required.floors.unit_inventory_json,
                body_floors: required.floors.body_floors,
            };
            let constructed = match readmit_configured_unit(observation.artifact, floors, self.target) {
                Ok(unit) => unit,
                Err(error) => { outputs.push(ConfiguredOutputResult::ReadmissionRefused { selector: required.selector.clone(), error }); continue; }
            };
            if constructed.inputs.configured != required.configured
                || constructed.records.iter().any(|r| !r.represented)
                || constructed.bodies.iter().any(|b| !b.constructed) {
                outputs.push(ConfiguredOutputResult::ConstructionRefused { selector: required.selector.clone(), constructed, reason: "configured identity or complete record/body disposition differs".into() });
                continue;
            }
            let planned = if let Some(relations) = required.original_functions.as_deref() {
                let report = verify_original_function_cfi(&required.selector, &constructed,
                    &required.floors, relations, self.target, required.tail_targets.as_ref());
                let report_index = original_function_cfi_reports.len();
                if !report.complete() {
                    original_function_cfi_reports.push(report);
                    outputs.push(ConfiguredOutputResult::OriginalFunctionCfiRefused {
                        selector: required.selector.clone(), constructed, report_index,
                    });
                    continue;
                }
                // The checked tuple's initial CIE is owned once by this report.
                // No object reparse, default rule or fresh policy selection occurs.
                let planned = plan_unit_with_initial_cies(&constructed.unit,
                    required.floors.unit_selection, required.floors.unit_inventory_json,
                    observation.configured, self.target, &report.initial_cies);
                original_function_cfi_reports.push(report);
                planned
            } else {
                match required.initial_cies {
                    None => plan_unit(&constructed.unit, required.floors.unit_selection, required.floors.unit_inventory_json, observation.configured, self.target),
                    Some(initial) => plan_unit_with_initial_cies(&constructed.unit, required.floors.unit_selection, required.floors.unit_inventory_json, observation.configured, self.target, initial),
                }
            };
            match planned {
                Err(failure) => outputs.push(ConfiguredOutputResult::PlanningRefused { selector: required.selector.clone(), constructed, failure }),
                Ok(plan) => {
                    if plan.source_unit_id != required.source_unit_id {
                        outputs.push(ConfiguredOutputResult::ConstructionRefused { selector: required.selector.clone(), constructed, reason: "planned source unit differs from the selected whole output".into() });
                    } else {
                        outputs.push(ConfiguredOutputResult::Planned(PlannedConfiguredOutput { selector: required.selector.clone(), constructed, plan }));
                    }
                }
            }
        }
        UnadmittedConfiguredAction { commitment: self, observed, association_errors, outputs, original_function_cfi_reports }
    }
}

#[derive(Debug)]
pub(crate) struct ObservedWholeOutput {
    selector: WholeOutputSelector,
    artifact: ArtifactIdentity,
    configured: ArtifactIdentity,
}
impl ObservedWholeOutput {
    pub(crate) fn selector(&self) -> &WholeOutputSelector { &self.selector }
    pub(crate) fn artifact(&self) -> &ArtifactIdentity { &self.artifact }
    pub(crate) fn configured(&self) -> &ArtifactIdentity { &self.configured }
}
#[derive(Debug)]
pub(crate) struct PlannedConfiguredOutput {
    selector: WholeOutputSelector,
    constructed: ConstructedUnit,
    plan: MachineAssemblyPlan,
}
impl PlannedConfiguredOutput {
    pub(crate) fn selector(&self) -> &WholeOutputSelector { &self.selector }
    pub(crate) fn constructed(&self) -> &ConstructedUnit { &self.constructed }
    pub(crate) fn plan(&self) -> &MachineAssemblyPlan { &self.plan }
}
#[derive(Debug)]
pub(crate) enum ConfiguredOutputResult {
    AssociationRefused { selector: WholeOutputSelector, reason: String },
    ReadmissionRefused { selector: WholeOutputSelector, error: ArtifactError },
    ConstructionRefused { selector: WholeOutputSelector, constructed: ConstructedUnit, reason: String },
    OriginalFunctionCfiRefused { selector: WholeOutputSelector, constructed: ConstructedUnit, report_index: usize },
    PlanningRefused { selector: WholeOutputSelector, constructed: ConstructedUnit, failure: UnitEmissionFailure },
    Planned(PlannedConfiguredOutput),
}
/// Opaque immutable checked result with all original output/failure dispositions.
/// No Deserialize, admitted-capture conversion or executable publication exists.
pub(crate) struct UnadmittedConfiguredAction<'f> {
    commitment: ConfiguredAssemblyCommitment<'f>,
    observed: Vec<ObservedWholeOutput>,
    association_errors: Vec<String>,
    outputs: Vec<ConfiguredOutputResult>,
    original_function_cfi_reports: Vec<ConfiguredOriginalFunctionCfiReport>,
}
impl<'f> UnadmittedConfiguredAction<'f> {
    pub(crate) fn outputs(&self) -> &[ConfiguredOutputResult] { &self.outputs }
    /// Retains every original relation and immutable object owner even if fresh
    /// readmission, body verification or later whole-unit planning was refused.
    pub(crate) fn required_outputs(&self) -> &[RequiredConfiguredOutput<'f>] { &self.commitment.required }
    pub(crate) fn original_function_cfi_reports(&self) -> &[ConfiguredOriginalFunctionCfiReport] {
        &self.original_function_cfi_reports
    }
    pub(crate) fn observed_outputs(&self) -> &[ObservedWholeOutput] { &self.observed }
    pub(crate) fn association_errors(&self) -> &[String] { &self.association_errors }
    pub(crate) fn original_action_selector(&self) -> &str { &self.commitment.action_selector }
    pub(crate) fn original_action_identity(&self) -> &ArtifactIdentity { &self.commitment.original_action_identity }
    pub(crate) fn original_occurrences(&self) -> &[WholeOutputSelector] { &self.commitment.occurrences }
    pub(crate) fn original_occurrence_indices(&self) -> &[usize] { &self.commitment.occurrence_indices }
    pub(crate) fn producer_boundary(&self) -> &AssemblyProducerBoundary { &self.commitment.boundary }
    pub(crate) fn all_required_outputs_planned(&self) -> bool {
        self.association_errors.is_empty() && self.outputs.iter().all(|r| matches!(r, ConfiguredOutputResult::Planned(_)))
    }
    pub(crate) fn source_or_native_admission(&self) -> bool { false }
    pub(crate) fn native_unwind_verified(&self) -> bool { false }
    pub(crate) fn runtime_or_provider_qualified(&self) -> bool { false }
}
