//! Original identity-mapped source -> real source-derived held assembly floors.
//!
//! ABI/interfaces and explicit original object/function/scope selections are held
//! before fresh buffers. Existing syntax/declaration decoding runs before machine
//! construction. No semantic blocks, guessed ABI or CIE defaults are supplied.
//! Transformed `.S`, genuine producer/consumption authority, providers, final PCs,
//! unwind registration and native/runtime/ISA qualification remain UNMET.
use super::configured_assembly_consumer::{RequiredConfiguredOutput, RequiredOriginalFunctionCfi, WholeOutputSelector};
use super::super::exception_inventory::{
    cie_raw_decoder::fde_function::{inspect_elf64_le_rel, CheckedObjectFunctions, SymbolKey},
    cie_source_adapter::OriginalFunctionSelection,
};
use o_lang::ocore::{
    Target,
    native_machine_asm_reader::{self as asm, inventory::{select_identity_mapped_source, SelectedSyntaxFloor}},
    native_machine_asm_unit::{observe_source_declarations, BodyFloor, ObservedSourceDeclarations, SourceBodySelection},
    native_machine_asm_unit_artifact::RequiredFloors,
    native_machine_ir::{ArtifactIdentity, MachineInterface, MachineProfile, SelectedInstructionInventory, SourceWitness, INVENTORY_FORMAT},
    native_machine_unit::{self as unit, BodyId, SelectedUnitInventory, UnitSelection},
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
fn identity(raw: &[u8]) -> Result<ArtifactIdentity, String> {
    Ok(ArtifactIdentity { bytes: u64::try_from(raw.len()).map_err(|_| "input length exceeds u64")?, sha256: super::digest(raw) })
}
fn valid_identity(value: &ArtifactIdentity) -> bool {
    value.bytes > 0 && value.sha256.len() == 64 && value.sha256.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
/// Caller-held source/function relation and ABI; no deserializer or nm inference.
pub(crate) struct IdentityAssemblyFunctionPolicy {
    selected: OriginalFunctionSelection,
    interface: MachineInterface,
}
impl IdentityAssemblyFunctionPolicy {
    pub(crate) fn new(selected: OriginalFunctionSelection, interface: MachineInterface) -> Self { Self { selected, interface } }
    pub(crate) fn selection(&self) -> &OriginalFunctionSelection { &self.selected }
    pub(crate) fn interface(&self) -> &MachineInterface { &self.interface }
}
/// Own policy before observe receives fresh buffers. Holding never authenticates it.
pub(crate) struct IdentityAssemblyCommitment {
    source: SourceWitness, profile: MachineProfile, original_file: u64,
    original_object: ArtifactIdentity, target: Target, functions: Vec<IdentityAssemblyFunctionPolicy>,
}
#[derive(Debug, Serialize)]
pub(crate) struct IdentityAssemblyIssue {
    pub record: Option<u64>, pub function: Option<String>, pub stage: &'static str, pub reason: String,
}
struct OwnedBodyFloor { body: BodyId, policy_index: usize, raw: Vec<u8> }
/// Every raw buffer, checked object/function/FDE row, source record and refusal is
/// kept here even if no floor is prepared. No bytes-to-success-only conversion.
pub(crate) struct IdentityAssemblyObservation {
    policy: IdentityAssemblyCommitment,
    original_source: Vec<u8>, configured: Vec<u8>, original_object: Vec<u8>,
    checked_object: Option<CheckedObjectFunctions>, syntax: Option<SelectedSyntaxFloor>,
    parsed: Option<asm::ParsedAssembly>, source_bodies: Vec<SourceBodySelection>,
    declarations: Option<ObservedSourceDeclarations>, body_floors: Vec<OwnedBodyFloor>,
    unit_selection: Option<UnitSelection>, unit_floor: Option<Vec<u8>>, issues: Vec<IdentityAssemblyIssue>,
}
fn problem(record: Option<u64>, function: Option<&str>, stage: &'static str, reason: impl Into<String>) -> IdentityAssemblyIssue {
    IdentityAssemblyIssue { record, function: function.map(str::to_owned), stage, reason: reason.into() }
}
impl IdentityAssemblyCommitment {
    pub(crate) fn hold(source: SourceWitness, profile: MachineProfile, original_file: u64,
        original_object: ArtifactIdentity, target: Target, functions: Vec<IdentityAssemblyFunctionPolicy>) -> Self {
        Self { source, profile, original_file, original_object, target, functions }
    }
    pub(crate) fn observe(self, original_source: Vec<u8>, configured: Vec<u8>, original_object: Vec<u8>) -> IdentityAssemblyObservation {
        let mut result = IdentityAssemblyObservation { policy: self, original_source, configured, original_object,
            checked_object: None, syntax: None, parsed: None, source_bodies: Vec::new(), declarations: None,
            body_floors: Vec::new(), unit_selection: None, unit_floor: None, issues: Vec::new() };
        result.inspect(); result
    }
}
impl IdentityAssemblyObservation {
    pub(crate) fn issues(&self) -> &[IdentityAssemblyIssue] { &self.issues }
    pub(crate) fn original_source(&self) -> &[u8] { &self.original_source }
    pub(crate) fn configured_assembly(&self) -> &[u8] { &self.configured }
    pub(crate) fn original_object(&self) -> &[u8] { &self.original_object }
    pub(crate) fn checked_object(&self) -> Option<&CheckedObjectFunctions> { self.checked_object.as_ref() }
    pub(crate) fn parsed(&self) -> Option<&asm::ParsedAssembly> { self.parsed.as_ref() }
    pub(crate) fn source_bodies(&self) -> &[SourceBodySelection] { &self.source_bodies }
    pub(crate) fn declarations(&self) -> Option<&ObservedSourceDeclarations> { self.declarations.as_ref() }
    pub(crate) fn functions(&self) -> &[IdentityAssemblyFunctionPolicy] { &self.policy.functions }
    pub(crate) fn unit_inventory_json(&self) -> Option<&[u8]> { self.unit_floor.as_deref() }
    pub(crate) fn floors_complete(&self) -> bool {
        self.issues.is_empty() && self.checked_object.is_some() && self.syntax.is_some() && self.parsed.is_some()
            && self.unit_selection.is_some() && self.unit_floor.is_some() && !self.body_floors.is_empty()
            && self.body_floors.len() == self.policy.functions.len()
    }
    pub(crate) fn producer_evidence_verified(&self) -> bool { false }
    pub(crate) fn source_object_association_verified(&self) -> bool { false }
    pub(crate) fn native_unwind_verified(&self) -> bool { false }
    fn inspect(&mut self) {
        let mut policy_names = BTreeMap::<String, usize>::new();
        let mut policy_symbols = BTreeSet::<SymbolKey>::new();
        if self.policy.functions.is_empty() { self.issues.push(problem(None, None, "policy", "complete original function policy absent")); }
        if !valid_identity(&self.policy.original_object) { self.issues.push(problem(None, None, "policy", "invalid held original object pin")); }
        for (index, function) in self.policy.functions.iter().enumerate() {
            let selected = &function.selected; let scope = &selected.source_scope;
            if scope.symbol.is_empty() || scope.symbol.contains('\0') || !valid_identity(&scope.selected_inventory)
                || scope.source != self.policy.source || scope.profile != self.policy.profile
                || selected.object_identity != self.policy.original_object {
                self.issues.push(problem(None, Some(&scope.symbol), "policy", "held scope/profile/object differs from unit policy"));
            }
            if policy_names.contains_key(&scope.symbol) { self.issues.push(problem(None, Some(&scope.symbol), "policy", "duplicate held source function name")); }
            else { policy_names.insert(scope.symbol.clone(), index); }
            if !policy_symbols.insert(selected.function) { self.issues.push(problem(None, Some(&scope.symbol), "policy", "original object function selected more than once")); }
        }
        match identity(&self.original_object) {
            Ok(pin) if pin == self.policy.original_object => {}
            Ok(_) => self.issues.push(problem(None, None, "object", "consumed original object differs from held pin")),
            Err(reason) => self.issues.push(problem(None, None, "object", reason)),
        }
        match inspect_elf64_le_rel(&self.original_object) {
            Ok(object) => self.checked_object = Some(object),
            Err(error) => self.issues.push(problem(None, None, "object", error.to_string())),
        }
        match select_identity_mapped_source(&self.configured, &self.original_source, self.policy.original_file,
            &self.policy.source, &self.policy.profile, self.policy.target) {
            Ok(syntax) => { match syntax.read(self.policy.target) {
                Ok(parsed) => self.parsed = Some(parsed),
                Err(error) => self.issues.push(problem(None, None, "syntax", error.to_string())),
            } self.syntax = Some(syntax); }
            Err(error) => self.issues.push(problem(None, None, "origin", error.to_string())),
        }
        if let Some(object) = &self.checked_object {
            if let Err(error) = object.require_all_defined_functions_matched() { self.issues.push(problem(None, None, "object-functions", error.to_string())); }
            if let Err(error) = object.require_initial_rules_decoded() { self.issues.push(problem(None, None, "object-cfi", error.to_string())); }
            let mut rows = BTreeMap::<SymbolKey, Vec<_>>::new();
            for table in object.symbol_tables() {
                if let Some(error) = &table.error { self.issues.push(problem(None, None, "object-symbols", error.clone())); }
                for row in &table.symbols { rows.entry(row.key).or_default().push(row); }
            }
            let mut required = BTreeSet::new();
            for function in object.functions() {
                let Some(candidates) = rows.get(&function.symbol) else {
                    self.issues.push(problem(None, None, "object-functions", "function symbol row absent")); continue;
                };
                if candidates.len() != 1 { self.issues.push(problem(None, None, "object-functions", "function symbol row ambiguous")); continue; }
                let row = candidates[0];
                if row.section_index != 0 { required.insert(function.symbol); }
                if let Some(error) = &row.error { self.issues.push(problem(None, None, "object-symbols", error.clone())); }
            }
            if required != policy_symbols { self.issues.push(problem(None, None, "object-functions", "held keys differ from every defined original STT_FUNC")); }
            for function in &self.policy.functions {
                let selected = &function.selected; let name = selected.source_scope.symbol.as_str();
                match rows.get(&selected.function) {
                    Some(candidates) if candidates.len() == 1 && candidates[0].name_bytes.as_deref() == Some(name.as_bytes()) => {}
                    _ => self.issues.push(problem(None, Some(name), "object-functions", "held function name differs from exact original symbol bytes")),
                }
                if let Err(error) = object.selected_fde(&self.policy.original_object, selected.function) {
                    self.issues.push(problem(None, Some(name), "object-function-cfi", error.to_string()));
                }
            }
            for fde in object.fdes() {
                if fde.error.is_some() || fde.function.is_none_or(|function| !policy_symbols.contains(&function)) {
                    self.issues.push(problem(None, None, "object-fde", format!("unresolved/unselected original FDE {:?}: {:?}", fde.fde, fde.error)));
                }
            }
        }
        if let Some(parsed) = &self.parsed {
            let mut typed = BTreeSet::new();
            for record in &parsed.records {
                if let asm::Syntax::Directive(asm::Directive::SymbolType { name, kind: asm::SymbolType::Function }) = &record.syntax { typed.insert(name.clone()); }
            }
            let expected: BTreeSet<_> = policy_names.keys().cloned().collect();
            if typed != expected { self.issues.push(problem(None, None, "source-functions", "held names differ from every original function type directive")); }
            let mut active: Option<SourceBodySelection> = None; let mut seen = BTreeSet::new();
            for record in &parsed.records {
                if let asm::Syntax::Label(asm::Label::Named(name)) = &record.syntax {
                    if typed.contains(name) {
                        if active.is_some() { self.issues.push(problem(Some(record.required.id), Some(name), "source-functions", "new function precedes previous explicit size boundary")); }
                        else {
                            if !seen.insert(name.clone()) { self.issues.push(problem(Some(record.required.id), Some(name), "source-functions", "repeated original function label")); }
                            match u64::try_from(self.source_bodies.len()) {
                                Ok(id) => active = Some(SourceBodySelection { id, symbol: name.clone(), record_ids: Vec::new() }),
                                Err(_) => self.issues.push(problem(Some(record.required.id), Some(name), "source-functions", "source function count exceeds u64")),
                            }
                        }
                    }
                }
                if let asm::Syntax::Directive(asm::Directive::Size { name, .. }) = &record.syntax {
                    if typed.contains(name) {
                        if active.as_ref().is_some_and(|body| &body.symbol == name) { if let Some(body) = active.take() { self.source_bodies.push(body); } }
                        else { self.issues.push(problem(Some(record.required.id), Some(name), "source-functions", "function size lacks matching active label")); }
                        continue;
                    }
                }
                if let Some(body) = active.as_mut() { body.record_ids.push(record.required.id); }
                else if matches!(&record.syntax, asm::Syntax::Instruction { .. }) { self.issues.push(problem(Some(record.required.id), None, "source-functions", "original instruction outside explicit function boundaries")); }
            }
            if let Some(body) = active {
                self.issues.push(problem(body.record_ids.last().copied(), Some(&body.symbol), "source-functions", "function lacks explicit matching size boundary")); self.source_bodies.push(body);
            }
            if seen != expected { self.issues.push(problem(None, None, "source-functions", "original labels do not cover exact held function membership")); }
            let observed = observe_source_declarations(parsed, &self.source_bodies);
            for issue in &observed.issues { self.issues.push(problem(issue.record, None, issue.stage, issue.reason.clone())); }
            if let Some(declarations) = &observed.declarations {
                let mut kinds = BTreeMap::new();
                for symbol in &declarations.symbols {
                    if kinds.contains_key(&symbol.id) { self.issues.push(problem(None, None, "source-functions", "duplicate decoded symbol ID")); }
                    else { kinds.insert(symbol.id, symbol.kind); }
                }
                for body in &observed.bodies {
                    if body.symbol.and_then(|symbol| kinds.get(&symbol)) != Some(&unit::SymbolKind::Function) {
                        self.issues.push(problem(None, Some(&body.source_symbol), "source-functions", "decoded body symbol is not an original function declaration"));
                    }
                }
            }
            self.declarations = Some(observed);
        }
        if self.issues.is_empty() { self.prepare_floors(&policy_names); }
    }
    fn prepare_floors(&mut self, policy_names: &BTreeMap<String, usize>) {
        let Some(observed) = self.declarations.as_mut() else { return; };
        let mut required_bodies = Vec::with_capacity(observed.bodies.len());
        for body in &mut observed.bodies {
            let Some(&policy_index) = policy_names.get(&body.source_symbol) else { self.issues.push(problem(None, Some(&body.source_symbol), "floor", "source body policy absent")); continue; };
            let Some(symbol) = body.symbol else { self.issues.push(problem(None, Some(&body.source_symbol), "floor", "source body symbol absent")); continue; };
            let policy = &self.policy.functions[policy_index];
            let inventory = SelectedInstructionInventory { format: INVENTORY_FORMAT.into(),
                identity: policy.selected.source_scope.selected_inventory.clone(), source: self.policy.source.clone(),
                symbol: body.source_symbol.clone(), profile: self.policy.profile.clone(), interface: policy.interface.clone(),
                items: std::mem::take(&mut body.items) };
            let raw = serde_json::to_vec(&inventory); body.items = inventory.items;
            match raw {
                Ok(raw) => match identity(&raw) {
                    Ok(pin) => {
                        required_bodies.push(unit::RequiredBody { id: body.id, symbol, inventory: pin,
                            machine_inventory_claim: policy.selected.source_scope.selected_inventory.clone(), record_ids: body.record_ids.clone() });
                        self.body_floors.push(OwnedBodyFloor { body: body.id, policy_index, raw });
                    }
                    Err(reason) => self.issues.push(problem(None, Some(&body.source_symbol), "floor", reason)),
                },
                Err(error) => self.issues.push(problem(None, Some(&body.source_symbol), "floor", error.to_string())),
            }
        }
        if !self.issues.is_empty() || required_bodies.len() != self.policy.functions.len() { return; }
        let Some(required) = observed.declarations.take() else { self.issues.push(problem(None, None, "floor", "complete original declarations absent")); return; };
        let floor = SelectedUnitInventory { format: unit::inventory_format_for_declarations(&required).into(), source: self.policy.source.clone(),
            profile: self.policy.profile.clone(), required, bodies: required_bodies };
        let raw = serde_json::to_vec(&floor); observed.declarations = Some(floor.required);
        match raw {
            Ok(raw) => match identity(&raw) {
                Ok(pin) => { self.unit_selection = Some(UnitSelection { source: self.policy.source.clone(), profile: self.policy.profile.clone(), inventory: pin }); self.unit_floor = Some(raw); }
                Err(reason) => self.issues.push(problem(None, None, "floor", reason)),
            },
            Err(error) => self.issues.push(problem(None, None, "floor", error.to_string())),
        }
    }
    /// Caller keeps this small borrowed view alive; all large buffers stay owned once.
    pub(crate) fn body_floor_views(&self) -> Vec<BodyFloor<'_>> {
        self.body_floors.iter().map(|floor| BodyFloor { body: floor.body, inventory_json: &floor.raw }).collect()
    }
    /// Real consumer handoff, still UNADMITTED. The caller must hold artifact pin
    /// before fresh results; no packaged artifact or new construction selects it.
    pub(crate) fn required_output<'a>(&'a self, selector: WholeOutputSelector, artifact: ArtifactIdentity,
        body_floors: &'a [BodyFloor<'a>]) -> Result<RequiredConfiguredOutput<'a>, String> {
        if !self.floors_complete() { return Err("original identity floors incomplete; retained outcomes remain owned".into()); }
        if body_floors.len() != self.body_floors.len() || body_floors.iter().zip(&self.body_floors)
            .any(|(view, owned)| view.body != owned.body || view.inventory_json != owned.raw.as_slice()) { return Err("body views differ from held source observation".into()); }
        let syntax = self.syntax.as_ref().ok_or("held syntax floor absent")?;
        let object = self.checked_object.as_ref().ok_or("held original function owner absent")?;
        let unit_selection = self.unit_selection.as_ref().ok_or("held unit selection absent")?;
        let unit_floor = self.unit_floor.as_deref().ok_or("held unit floor absent")?;
        let mut functions = Vec::with_capacity(self.body_floors.len());
        for body in &self.body_floors {
            let held = &self.policy.functions[body.policy_index].selected;
            let selected = OriginalFunctionSelection { source_scope: held.source_scope.clone(), object_identity: held.object_identity.clone(), function: held.function };
            functions.push(RequiredOriginalFunctionCfi::new(body.body, object, selected));
        }
        RequiredConfiguredOutput::new_with_original_functions(selector, self.policy.source.unit_id.clone(), artifact,
            self.policy.source.decoded_assembly.clone(), RequiredFloors { syntax_selection: syntax.selection(),
                syntax_inventory_json: syntax.inventory_json(), unit_selection, unit_inventory_json: unit_floor, body_floors }, functions)
    }
}
