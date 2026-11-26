//! Compiler-owned fixed-C declaration -> prior-selected identity-assembly policy.
//!
//! The complete original function mapping, LLVM declaration occurrences, target,
//! source ABI, memory and PC-entry contracts are held before fresh source/object
//! buffers. No raw JSON, name discovery, STT_FUNC observation or fresh result can
//! construct those prior choices. This callable producer path remains UNADMITTED:
//! source/producer attribution, original order meaning, ABI execution, providers,
//! native unwind/runtime/ISA qualification and normal capture wiring are UNMET.
//!
//! This first slice supports external fixed-C declarations of scalar i64/AS0
//! pointers and void results in full64 GP registers only. It deliberately refuses
//! stack/hidden storage, aggregates, FP, extensions, boxing, variadic, EH,
//! returns_twice, managed/intrinsic and non-leaf preservation requirements.
use super::{IdentityAssemblyCommitment, IdentityAssemblyFunctionPolicy,
    IdentityAssemblyObservation, UnitLineage};
use super::super::exception_inventory::cie_source_adapter::OriginalFunctionSelection;
use o_lang::ocore::{
    Target,
    native_abi::{AbiClass, AbiContext, AbiLocation, AbiPart, Extension, MachineAbi},
    native_ir::{Function, NativeModule, SourceAbiWitness, TargetLayout, Type},
    native_machine_ir::{
        Architecture, ArtifactIdentity, ByteOrder, EntryInterface, EntryPolicy,
        ExitInterface, ExitKind, MachineInterface, MachineProfile, MemoryInterface,
        PhysicalRegister, RegisterView, SourceWitness, StateFeature,
    },
    native_verify::{type_layouts, value_leaf_layouts},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// An explicit occurrence in the caller-held complete lineage cohort, not an
/// automatically selected first/last function with the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct SelectedLineageDeclaration {
    lineage: usize,
    function: usize,
}
impl SelectedLineageDeclaration {
    pub(crate) fn new(lineage: usize, function: usize) -> Self { Self { lineage, function } }
}

/// Original source/STT_FUNC relation is independently selected, not inferred by
/// this factory. SourceAbiWitness equality binds raw source attrs only; it does
/// not qualify unimplemented target features or source consumption.
pub(crate) struct IdentityAssemblyAbiFunction {
    selected: OriginalFunctionSelection,
    declarations: Vec<SelectedLineageDeclaration>,
    expected_source_abi: Option<SourceAbiWitness>,
    memory: MemoryInterface,
    entry_context: Vec<RegisterView>,
}
impl IdentityAssemblyAbiFunction {
    pub(crate) fn hold(
        selected: OriginalFunctionSelection,
        declarations: Vec<SelectedLineageDeclaration>,
        expected_source_abi: Option<SourceAbiWitness>,
        memory: MemoryInterface,
        entry_context: Vec<RegisterView>,
    ) -> Self {
        Self { selected, declarations, expected_source_abi, memory, entry_context }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct IdentityAssemblyAbiFunctionOutcome {
    pub(crate) index: usize,
    pub(crate) symbol: String,
    pub(crate) declarations: Vec<SelectedLineageDeclaration>,
    pub(crate) issues: Vec<String>,
}

/// Holds the prior complete cohort and choices, before receiving fresh buffers.
/// The lineages remain borrowed so their immutable snapshots and original guards
/// cannot be replaced or mutated during preparation/observation.
pub(crate) struct IdentityAssemblyAbiCommitment<'a> {
    lineages: Vec<&'a UnitLineage>,
    source: SourceWitness,
    profile: MachineProfile,
    original_file: u64,
    original_object: ArtifactIdentity,
    target: Target,
    expected_target: TargetLayout,
    functions: Vec<IdentityAssemblyAbiFunction>,
}
pub(crate) struct IdentityAssemblyAbiPreparation<'a> {
    held: IdentityAssemblyAbiCommitment<'a>,
    policies: Vec<IdentityAssemblyFunctionPolicy>,
    outcomes: Vec<IdentityAssemblyAbiFunctionOutcome>,
    issues: Vec<String>,
}
struct UnconsumedFreshInputs {
    original_source: Vec<u8>,
    configured: Vec<u8>,
    original_object: Vec<u8>,
}
/// Every refused outcome and all fresh buffers survive even when producer entry
/// is withheld. A producer observation, when present, is the existing explicitly
/// unadmitted type; this owner cannot construct AdmittedCapture.
pub(crate) struct IdentityAssemblyAbiObservation {
    observation: Option<IdentityAssemblyObservation>,
    unconsumed: Option<UnconsumedFreshInputs>,
    outcomes: Vec<IdentityAssemblyAbiFunctionOutcome>,
    issues: Vec<String>,
}
impl IdentityAssemblyAbiObservation {
    pub(crate) fn function_outcomes(&self) -> &[IdentityAssemblyAbiFunctionOutcome] { &self.outcomes }
    pub(crate) fn issues(&self) -> &[String] { &self.issues }
    pub(crate) fn producer_observation(&self) -> Option<&IdentityAssemblyObservation> {
        // A failed final custody guard retains diagnostics but withholds floors.
        if self.issues.is_empty() && self.outcomes.iter().all(|row| row.issues.is_empty()) {
            self.observation.as_ref()
        } else { None }
    }
    pub(crate) fn unconsumed_fresh_inputs(&self) -> Option<(&[u8], &[u8], &[u8])> {
        self.unconsumed.as_ref().map(|raw|
            (raw.original_source.as_slice(), raw.configured.as_slice(), raw.original_object.as_slice()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scalar64 { Integer, Pointer }
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeclarationShape {
    params: Vec<Scalar64>,
    result: Option<Scalar64>,
    source_abi: Value,
}
#[derive(Clone)]
struct PlannedDeclaration {
    shape: DeclarationShape,
    arguments: Vec<RegisterView>,
    results: Vec<RegisterView>,
}
fn scalar(module: &NativeModule, ty: usize) -> Result<Scalar64, String> {
    match module.types.get(ty) {
        Some(Type::Int { bits: 64 }) => Ok(Scalar64::Integer),
        Some(Type::Pointer { address_space: 0 }) => Ok(Scalar64::Pointer),
        _ => Err("fixed-C assembly policy requires original scalar i64/AS0 pointer types".into()),
    }
}
fn gp(register: &'static str, result: bool) -> Result<RegisterView, String> {
    let index = match register {
        "a0" => 10, "a1" => 11,
        "a2" if !result => 12, "a3" if !result => 13,
        "a4" if !result => 14, "a5" if !result => 15,
        "a6" if !result => 16, "a7" if !result => 17,
        _ => return Err("ABI planner selected an unsupported original GP location".into()),
    };
    Ok(RegisterView { register: PhysicalRegister::RiscvGpr { index }, low_bit: 0, bits: 64 })
}
fn part(part: &AbiPart, param: Option<usize>, ty: usize, result: bool) -> Result<RegisterView, String> {
    if part.param != param || part.ty != ty || part.leaf != 0 || part.offset != 0
        || part.bit_offset != 0 || part.value_bits != 64 || part.location_bits != 64
        || part.class != AbiClass::General || part.extension != Extension::None || part.nan_box {
        return Err("ABI part requires unsupported split/extension/boxing/non-full64 transport".into());
    }
    match part.location {
        AbiLocation::Register(name) => gp(name, result),
        _ => Err("stack or hidden-result ABI transfer is not implemented by this factory".into()),
    }
}
fn plan_declaration(module: &NativeModule, context: &AbiContext<'_>, function: &Function)
    -> Result<PlannedDeclaration, String>
{
    let signature = &function.signature;
    if function.entry.is_some() || !function.blocks.is_empty() || function.linkage != "external" {
        return Err("selected LLVM occurrence is not an original external declaration".into());
    }
    if signature.abi != "c" || signature.variadic || signature.return_storage.is_some()
        || function.control_effects.returns_twice || function.exception_handling.is_some()
        || function.managed_method.is_some() || function.intrinsic.is_some() {
        return Err("unsupported original call/control/storage/managed/intrinsic contract".into());
    }
    if signature.param_attributes.iter().any(|attrs| !attrs.is_empty())
        || !signature.result_attributes.is_empty() {
        return Err("original parameter/result attributes need an explicit assembly interface witness".into());
    }
    let params = signature.params.iter().map(|ty| scalar(module, *ty)).collect::<Result<Vec<_>, _>>()?;
    let result = match module.types.get(signature.result) {
        Some(Type::Void) => None,
        _ => Some(scalar(module, signature.result)?),
    };
    // plan_function, not plan(signature): retain the actual per-function source
    // ABI witness and all independent native planner/profile validation.
    let plan = context.plan_function(function).map_err(|error| error.message)?;
    if plan.storage.is_some() || plan.stack_bytes != 0 || plan.stack_alignment != 16
        || plan.variadic.is_some() || plan.args.len() != signature.params.len()
        || plan.results.len() != (if result.is_some() { 1 } else { 0 }) {
        return Err("original ABI needs stack/storage/variadic/split-result support".into());
    }
    let mut arguments = Vec::with_capacity(plan.args.len());
    let mut used = BTreeSet::new();
    for (index, item) in plan.args.iter().enumerate() {
        let view = part(item, Some(index), signature.params[index], false)?;
        if !used.insert(view) { return Err("ABI arguments overlap physical registers".into()); }
        arguments.push(view);
    }
    let results = plan.results.iter().map(|item| part(item, None, signature.result, true))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PlannedDeclaration {
        shape: DeclarationShape {
            params, result,
            source_abi: serde_json::to_value(&function.source_abi).map_err(|error| error.to_string())?,
        },
        arguments, results,
    })
}
fn interface(plan: &PlannedDeclaration, function: &IdentityAssemblyAbiFunction, abi: MachineAbi)
    -> Result<MachineInterface, String>
{
    // These exact full readonly views are required by the existing RV selector.
    // They do not permit save/restore prologues or derive original CFI rules.
    let mut initialized = Vec::new();
    let mut preserved = Vec::new();
    for index in [1, 2, 3, 4, 8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27] {
        let view = RegisterView { register: PhysicalRegister::RiscvGpr { index }, low_bit: 0, bits: 64 };
        initialized.push(view); preserved.push(view);
    }
    if abi == MachineAbi::RiscvLp64d {
        for index in [8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27] {
            let view = RegisterView { register: PhysicalRegister::RiscvFpr { index }, low_bit: 0, bits: 64 };
            initialized.push(view); preserved.push(view);
        }
    }
    initialized.extend_from_slice(&plan.arguments);
    // Signature classification cannot invent PC/memory semantics. Only an
    // independently held exact full PC availability view is accepted here;
    // all other additional entry-state contracts need their own adapter.
    let mut pc = false;
    for view in &function.entry_context {
        if view.register != PhysicalRegister::RiscvPc || view.low_bit != 0 || view.bits != 64 || pc {
            return Err("unsupported or duplicate prior machine-entry context".into());
        }
        pc = true; initialized.push(*view);
    }
    Ok(MachineInterface {
        entry: EntryInterface { policy: EntryPolicy::NoImplicitFrameOrScratch,
            initialized, memory: function.memory },
        exits: vec![ExitInterface { id: 0, kind: ExitKind::OrdinaryReturn,
            outputs: plan.results.clone(), preserved }],
    })
}
fn guard(lineage: &UnitLineage) -> Result<(), String> {
    let snapshot = lineage.verified_module.as_ref().ok_or("lineage has no privately retained verified module")?;
    let mir = lineage.imported_mir.as_ref().ok_or("lineage has no verified MIR identity")?;
    if lineage.verification.is_none() || snapshot.mir_sha256 != mir.sha256 {
        return Err("private parsed snapshot differs from verified lineage identity".into());
    }
    for pin in &lineage.guards { pin.check().map_err(|error| error.to_string())?; }
    Ok(())
}
impl<'a> IdentityAssemblyAbiCommitment<'a> {
    pub(crate) fn hold(
        lineages: Vec<&'a UnitLineage>,
        source: SourceWitness,
        profile: MachineProfile,
        original_file: u64,
        original_object: ArtifactIdentity,
        target: Target,
        expected_target: TargetLayout,
        functions: Vec<IdentityAssemblyAbiFunction>,
    ) -> Self {
        Self { lineages, source, profile, original_file, original_object, target, expected_target, functions }
    }

    pub(crate) fn prepare(self) -> IdentityAssemblyAbiPreparation<'a> {
        let mut issues = Vec::new();
        let mut outcomes = self.functions.iter().enumerate().map(|(index, function)|
            IdentityAssemblyAbiFunctionOutcome { index, symbol: function.selected.source_scope.symbol.clone(),
                declarations: function.declarations.clone(), issues: Vec::new() }).collect::<Vec<_>>();
        if self.lineages.is_empty() { issues.push("complete verified LLVM lineage cohort is absent".into()); }
        if self.functions.is_empty() { issues.push("complete prior original function membership is absent".into()); }
        if self.target != Target::Riscv64UnknownNone || self.profile.architecture != Architecture::Rv64
            || !matches!(self.profile.abi, MachineAbi::RiscvLp64 | MachineAbi::RiscvLp64d)
            || self.profile.address_bits != 64 || self.profile.byte_order != ByteOrder::Little
            || self.profile.entry_stack_alignment != 16 || self.profile.entry_stack_remainder != 0
            || self.profile.features.iter().any(|feature| feature != &StateFeature::UserRegisterBits)
            || MachineAbi::from_frontend(self.target, self.expected_target.abi.as_deref()) != Some(self.profile.abi) {
            issues.push("held target/profile is outside the explicit RV64 fixed-C leaf slice".into());
        }
        let expected_target = serde_json::to_value(&self.expected_target);
        let mut by_name = BTreeMap::<String, Vec<SelectedLineageDeclaration>>::new();
        let mut results = BTreeMap::<SelectedLineageDeclaration, Result<PlannedDeclaration, String>>::new();
        for (lineage_index, lineage) in self.lineages.iter().enumerate() {
            if let Err(error) = guard(lineage) { issues.push(format!("lineage {lineage_index}: {error}")); }
            let Some(snapshot) = lineage.verified_module.as_ref() else { continue; };
            let module = &snapshot.module;
            let target_matches = match (&expected_target, serde_json::to_value(&module.target)) {
                (Ok(expected), Ok(actual)) => expected == &actual,
                _ => false,
            };
            if !target_matches {
                issues.push(format!("lineage {lineage_index}: full original TargetLayout differs from held expectation"));
            }
            for (function_index, function) in module.functions.iter().enumerate() {
                by_name.entry(function.name.clone()).or_default()
                    .push(SelectedLineageDeclaration { lineage: lineage_index, function: function_index });
            }
            let selected = self.functions.iter().flat_map(|function| &function.declarations)
                .filter(|selected| selected.lineage == lineage_index).map(|selected| selected.function)
                .collect::<BTreeSet<_>>();
            let roots = selected.iter().filter_map(|index| module.functions.get(*index))
                .flat_map(|function| function.signature.params.iter().copied()
                    .chain(std::iter::once(function.signature.result))).collect::<Vec<_>>();
            // One actual cache/context per held module for every requested function.
            let planned = (|| {
                let layouts = type_layouts(module).map_err(|error| error.message)?;
                let leaves = value_leaf_layouts(module, &roots).map_err(|error| error.message)?;
                let context = AbiContext::new(module, self.target, &leaves, &layouts).map_err(|error| error.message)?;
                Ok::<_, String>(selected.iter().map(|index| {
                    let value = module.functions.get(*index).ok_or_else(|| "selected function occurrence is absent".into())
                        .and_then(|function| plan_declaration(module, &context, function));
                    (*index, value)
                }).collect::<Vec<_>>())
            })();
            match planned {
                Ok(rows) => for (function, value) in rows {
                    results.insert(SelectedLineageDeclaration { lineage: lineage_index, function }, value);
                },
                Err(error) => for function in selected {
                    results.insert(SelectedLineageDeclaration { lineage: lineage_index, function }, Err(error.clone()));
                },
            }
        }
        let mut names = BTreeMap::<String, usize>::new();
        let mut keys = BTreeMap::new();
        for function in &self.functions {
            *names.entry(function.selected.source_scope.symbol.clone()).or_default() += 1;
            *keys.entry(function.selected.function).or_insert(0usize) += 1;
        }
        let mut policies = Vec::new();
        for (index, function) in self.functions.iter().enumerate() {
            let outcome = &mut outcomes[index];
            let scope = &function.selected.source_scope;
            if scope.source != self.source || scope.profile != self.profile
                || function.selected.object_identity != self.original_object {
                outcome.issues.push("prior source/profile/object function mapping differs from held unit commitment".into());
            }
            if names.get(&scope.symbol) != Some(&1) || keys.get(&function.selected.function) != Some(&1) {
                outcome.issues.push("duplicate prior original function name or STT_FUNC key".into());
            }
            let expected = by_name.get(&scope.symbol).cloned().unwrap_or_default();
            let mut actual = function.declarations.clone();
            actual.sort();
            let mut complete = expected;
            complete.sort();
            if actual.is_empty() || actual.windows(2).any(|pair| pair[0] == pair[1]) || actual != complete {
                outcome.issues.push("selected declaration occurrences do not cover exact complete matching lineage membership".into());
            }
            let source_abi = serde_json::to_value(&function.expected_source_abi);
            let mut first: Option<&PlannedDeclaration> = None;
            for selected in &function.declarations {
                match results.get(selected) {
                    Some(Ok(plan)) => {
                        let name_matches = self.lineages.get(selected.lineage)
                            .and_then(|lineage| lineage.verified_module.as_ref())
                            .and_then(|snapshot| snapshot.module.functions.get(selected.function))
                            .is_some_and(|declaration| declaration.name == scope.symbol);
                        if !name_matches {
                            outcome.issues.push("selected LLVM declaration differs from prior original function mapping".into());
                        }
                        if source_abi.as_ref().ok() != Some(&plan.shape.source_abi) {
                            outcome.issues.push("original per-function SourceAbiWitness differs from held expectation".into());
                        }
                        if let Some(previous) = first {
                            if previous.shape != plan.shape || previous.arguments != plan.arguments || previous.results != plan.results {
                                outcome.issues.push("conflicting original declarations or ABI plans across held modules".into());
                            }
                        } else { first = Some(plan); }
                    },
                    Some(Err(error)) => outcome.issues.push(format!("declaration {selected:?}: {error}")),
                    None => outcome.issues.push(format!("selected declaration {selected:?} has no held checked module")),
                }
            }
            if outcome.issues.is_empty() {
                match first.ok_or_else(|| "original function has no justified declaration".to_owned())
                    .and_then(|plan| interface(plan, function, self.profile.abi)) {
                    Ok(interface) => policies.push(IdentityAssemblyFunctionPolicy::new(function.selected.clone(), interface)),
                    Err(error) => outcome.issues.push(error),
                }
            }
        }
        for (index, lineage) in self.lineages.iter().enumerate() {
            if let Err(error) = guard(lineage) { issues.push(format!("lineage {index} final preparation guard: {error}")); }
        }
        IdentityAssemblyAbiPreparation { held: self, policies, outcomes, issues }
    }
}
impl<'a> IdentityAssemblyAbiPreparation<'a> {
    pub(crate) fn function_outcomes(&self) -> &[IdentityAssemblyAbiFunctionOutcome] { &self.outcomes }
    pub(crate) fn issues(&self) -> &[String] { &self.issues }
    /// Real positive producer call: fresh buffers are received only AFTER prior
    /// declaration/policy preparation. No LLVM replay or NativeModule coercion.
    pub(crate) fn observe(self, original_source: Vec<u8>, configured: Vec<u8>,
        original_object: Vec<u8>) -> IdentityAssemblyAbiObservation
    {
        let mut issues = self.issues;
        for (index, lineage) in self.held.lineages.iter().enumerate() {
            if let Err(error) = guard(lineage) { issues.push(format!("lineage {index} before source observation: {error}")); }
        }
        let complete = issues.is_empty() && !self.outcomes.is_empty()
            && self.outcomes.iter().all(|outcome| outcome.issues.is_empty())
            && self.policies.len() == self.held.functions.len();
        let (observation, unconsumed) = if complete {
            let held = &self.held;
            let observation = IdentityAssemblyCommitment::hold(
                held.source.clone(), held.profile.clone(), held.original_file,
                held.original_object.clone(), held.target, self.policies,
            ).observe(original_source, configured, original_object);
            (Some(observation), None)
        } else {
            (None, Some(UnconsumedFreshInputs { original_source, configured, original_object }))
        };
        for (index, lineage) in self.held.lineages.iter().enumerate() {
            if let Err(error) = guard(lineage) { issues.push(format!("lineage {index} after source observation: {error}")); }
        }
        IdentityAssemblyAbiObservation { observation, unconsumed, outcomes: self.outcomes, issues }
    }
}
