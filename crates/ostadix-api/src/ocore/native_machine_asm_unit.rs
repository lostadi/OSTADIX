//! Current-e704 integration of the previously evidence-only typed constructor.
//! All current-source verification and admission boundaries remain unchanged.
//! Pure configured-source to typed whole-unit construction.
//!
//! All floors are separately selected inputs. No source authenticity, producer
//! authority, provider resolution, native admission or semantic qualification is
//! created here. Unknown records remain in the complete diagnostic outcome.
//! No supplied semantic blocks, executable bytes, filesystem or process API.
use super::common::Target;
use super::native_machine_asm_reader as asm;
use super::native_machine_ir::*;
use super::native_machine_lift::{integer_expression, BlockLifter, LiftFlow, LiftIds};
use super::native_machine_lift_dispatch::lift_instruction;
use super::native_machine_unit as unit;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

pub struct BodyFloor<'a> {
    pub body: unit::BodyId,
    pub inventory_json: &'a [u8],
}
pub struct ConstructInput<'a> {
    pub configured_assembly: &'a [u8],
    pub syntax_selection: &'a asm::ReadSelection,
    pub syntax_inventory_json: &'a [u8],
    pub unit_selection: &'a unit::UnitSelection,
    pub unit_inventory_json: &'a [u8],
    pub body_floors: &'a [BodyFloor<'a>],
    pub target: Target,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConstructionIssue {
    pub record: Option<SourceItemId>,
    pub body: Option<unit::BodyId>,
    pub stage: &'static str,
    pub reason: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsumedInputs {
    pub configured: ArtifactIdentity,
    pub syntax_floor: ArtifactIdentity,
    pub selected_syntax_floor: ArtifactIdentity,
    pub unit_floor: ArtifactIdentity,
    pub selected_unit_floor: ArtifactIdentity,
    pub body_floors: Vec<(unit::BodyId, ArtifactIdentity)>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordDisposition {
    pub id: SourceItemId,
    pub kind: asm::SyntaxKind,
    pub span: SourceSpan,
    pub origins: Vec<OriginalSpan>,
    pub body: Option<unit::BodyId>,
    pub represented: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BodyDisposition {
    pub id: unit::BodyId,
    pub required_records: Vec<SourceItemId>,
    pub constructed: bool,
}
#[derive(Debug)]
pub struct ConstructionFailure {
    pub configured_identity: ArtifactIdentity,
    pub inputs: ConsumedInputs,
    pub parsed: Option<asm::ParsedAssembly>,
    pub records: Vec<RecordDisposition>,
    pub bodies: Vec<BodyDisposition>,
    pub issues: Vec<ConstructionIssue>,
}
pub struct ConstructedUnit {
    pub inputs: ConsumedInputs,
    pub parsed: asm::ParsedAssembly,
    pub unit: unit::MachineUnit,
    pub report: unit::UnitReport,
    pub records: Vec<RecordDisposition>,
    pub bodies: Vec<BodyDisposition>,
}
impl std::fmt::Debug for ConstructedUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConstructedUnit")
            .field("records", &self.records.len())
            .field("bodies", &self.bodies.len())
            .finish_non_exhaustive()
    }
}
type Check<T> = std::result::Result<T, String>;
fn artifact(raw: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        bytes: raw.len() as u64,
        sha256: hex::encode(Sha256::digest(raw)),
    }
}
fn require(ok: bool, why: &str) -> Check<()> {
    if ok {
        Ok(())
    } else {
        Err(why.into())
    }
}
fn issue(
    record: Option<u64>,
    body: Option<u64>,
    stage: &'static str,
    reason: impl Into<String>,
) -> ConstructionIssue {
    ConstructionIssue {
        record,
        body,
        stage,
        reason: reason.into(),
    }
}
fn unit_kind(k: asm::SyntaxKind) -> Option<unit::UnitRecordKind> {
    Some(match k {
        asm::SyntaxKind::Instruction => unit::UnitRecordKind::Instruction,
        asm::SyntaxKind::Label => unit::UnitRecordKind::Label,
        asm::SyntaxKind::Cfi => unit::UnitRecordKind::Cfi,
        asm::SyntaxKind::Alignment => unit::UnitRecordKind::Alignment,
        asm::SyntaxKind::Symbol => unit::UnitRecordKind::Symbol,
        asm::SyntaxKind::Data => unit::UnitRecordKind::Data,
        asm::SyntaxKind::Relocation => unit::UnitRecordKind::Relocation,
        asm::SyntaxKind::Section => unit::UnitRecordKind::Section,
        asm::SyntaxKind::Debug => unit::UnitRecordKind::Debug,
        asm::SyntaxKind::Preprocessor => unit::UnitRecordKind::Preprocessor,
        asm::SyntaxKind::Macro | asm::SyntaxKind::UnknownDirective => return None,
    })
}
fn item_kind(k: asm::SyntaxKind) -> Option<SourceItemKind> {
    Some(match k {
        asm::SyntaxKind::Instruction => SourceItemKind::Instruction,
        asm::SyntaxKind::Label => SourceItemKind::Label,
        asm::SyntaxKind::Cfi => SourceItemKind::CfiDirective,
        asm::SyntaxKind::Alignment => SourceItemKind::AlignmentDirective,
        asm::SyntaxKind::Symbol => SourceItemKind::SymbolDirective,
        asm::SyntaxKind::Data => SourceItemKind::DataDirective,
        asm::SyntaxKind::Relocation => SourceItemKind::RelocationDirective,
        _ => return None,
    })
}
fn dispositions(
    parsed: &asm::ParsedAssembly,
    owners: &BTreeMap<u64, u64>,
    issues: &[ConstructionIssue],
) -> Vec<RecordDisposition> {
    parsed
        .records
        .iter()
        .map(|r| RecordDisposition {
            id: r.required.id,
            kind: r.required.kind,
            span: r.required.span,
            origins: r.required.origins.clone(),
            body: owners.get(&r.required.id).copied(),
            represented: !issues.iter().any(|e| {
                e.record == Some(r.required.id)
                    || (e.record.is_none() && e.body.is_none())
                    || (e.body.is_some() && e.body == owners.get(&r.required.id).copied())
            }),
        })
        .collect()
}
fn with_parsed(
    mut failure: Box<ConstructionFailure>,
    parsed: asm::ParsedAssembly,
) -> Box<ConstructionFailure> {
    let owners = failure
        .bodies
        .iter()
        .flat_map(|b| b.required_records.iter().map(move |&r| (r, b.id)))
        .collect();
    failure.records = dispositions(&parsed, &owners, &failure.issues);
    failure.parsed = Some(parsed);
    failure
}
fn unsigned(e: &asm::Expression) -> Check<u64> {
    u64::try_from(integer_expression(e).map_err(|e| e.reason)?)
        .map_err(|_| "expected nonnegative u64 expression".into())
}
fn linear(e: &asm::Expression) -> Check<(asm::ExprAtom, i64)> {
    let mut addend = 0i128;
    let base = match &e.first {
        asm::ExprAtom::Integer(n) => {
            addend = *n;
            None
        }
        x => Some(x.clone()),
    };
    let mut symbol = base;
    for (op, a) in &e.rest {
        match a {
            asm::ExprAtom::Integer(n) => {
                addend = match op {
                    asm::AddSub::Add => addend.checked_add(*n),
                    asm::AddSub::Subtract => addend.checked_sub(*n),
                }
                .ok_or("linear addend overflow")?
            }
            x if symbol.is_none() && *op == asm::AddSub::Add => symbol = Some(x.clone()),
            _ => {
                return Err(
                    "expression needs a separately supported symbolic algebra/layout form".into(),
                )
            }
        }
    }
    Ok((
        symbol.ok_or("expression has no selected symbolic base")?,
        i64::try_from(addend).map_err(|_| "symbolic addend exceeds i64")?,
    ))
}

/// Stable IDs come only from the selected floor; payloads below are decoded from
/// source. Declaration vector order follows that selected namespace, while
/// record/effect and initializer order follows the consumed source.
/// Original-source record membership, selected before fresh machine construction.
/// No ABI, semantic blocks or producer authority are supplied by this type.
#[derive(Debug, Clone)]
pub struct SourceBodySelection {
    pub id: unit::BodyId,
    pub symbol: String,
    pub record_ids: Vec<SourceItemId>,
}
#[derive(Debug)]
pub struct ObservedSourceBody {
    pub id: unit::BodyId,
    pub symbol: Option<unit::SymbolId>,
    pub source_symbol: String,
    pub record_ids: Vec<SourceItemId>,
    pub items: Vec<SourceItem>,
}
/// All issues remain available. The caller retains the original ParsedAssembly.
/// A declaration value is provisional whenever issues is nonempty.
#[derive(Debug)]
pub struct ObservedSourceDeclarations {
    pub declarations: Option<unit::UnitDeclarations>,
    pub bodies: Vec<ObservedSourceBody>,
    pub issues: Vec<ConstructionIssue>,
}
fn observed_symbol(name: unit::SymbolName, names: &mut BTreeMap<unit::SymbolName, u64>,
    symbols: &mut Vec<unit::UnitSymbol>) -> Check<()> {
    if names.contains_key(&name) { return Ok(()); }
    let id = u64::try_from(symbols.len()).map_err(|_| "source symbol count exceeds u64")?;
    names.insert(name.clone(), id);
    // Namespace only; the existing decoder supplies every returned source fact.
    // This seed is never serialized or exposed as a coverage/semantic floor.
    symbols.push(unit::UnitSymbol { id, name, binding: unit::SymbolBinding::Global,
        visibility: unit::SymbolVisibility::Default, kind: unit::SymbolKind::NoType,
        size: unit::SymbolSize::Unspecified, definition: unit::SymbolDefinition::Undefined });
    Ok(())
}
fn observed_named(name: &str, names: &mut BTreeMap<unit::SymbolName, u64>,
    symbols: &mut Vec<unit::UnitSymbol>) -> Check<()> {
    observed_symbol(unit::SymbolName::Named { value: name.into() }, names, symbols)
}
fn observed_expression(value: &asm::Expression, names: &mut BTreeMap<unit::SymbolName, u64>,
    symbols: &mut Vec<unit::UnitSymbol>) -> Check<()> {
    for atom in std::iter::once(&value.first).chain(value.rest.iter().map(|(_, atom)| atom)) {
        if let asm::ExprAtom::Symbol(name) | asm::ExprAtom::Relocation { symbol: name, .. } = atom {
            observed_named(name, names, symbols)?;
        }
    }
    Ok(())
}
#[derive(Debug)]
struct InstructionReference {
    symbol: unit::SymbolName,
    operand: u64,
    atom: u64,
}
fn record_mnemonic<'a>(parsed: &'a asm::ParsedAssembly,
    record: &asm::ParsedRecord) -> Option<&'a str> {
    let start = usize::try_from(record.required.span.start).ok()?;
    let end = usize::try_from(record.required.span.end).ok()?;
    std::str::from_utf8(parsed.original.get(start..end)?).ok()?
        .split_ascii_whitespace().next()
}
// Lexical opcodes distinguish calls from jumps. JAL additionally requires the
// exact supported spelling and canonical zero-register destination.
fn local_control_operand(opcode: asm::Opcode, operands: &[asm::Operand],
    mnemonic: Option<&str>) -> Option<usize> {
    use asm::{Aarch64Opcode as A, RiscvOpcode as R, X86Opcode as X};
    let candidate = match opcode {
        asm::Opcode::X86 { operation: X::Jump | X::ConditionalJump(_), .. }
            if operands.len() == 1 && matches!(operands.first(), Some(asm::Operand::Expression(_))) => Some(0),
        asm::Opcode::Aarch64(A::Branch | A::ConditionalBranch(_))
            if operands.len() == 1 => Some(0),
        asm::Opcode::Aarch64(A::CompareBranchZero | A::CompareBranchNonzero)
            if operands.len() == 2 => Some(1),
        asm::Opcode::Aarch64(A::TestBranchZero | A::TestBranchNonzero)
            if operands.len() == 3 => Some(2),
        asm::Opcode::Riscv(R::Jump) if operands.len() == 1 => Some(0),
        asm::Opcode::Riscv(R::BranchEqual | R::BranchNotEqual)
            if operands.len() == 3 => Some(2),
        asm::Opcode::Riscv(R::BranchZero | R::BranchNonzero)
            if operands.len() == 2 => Some(1),
        asm::Opcode::Riscv(R::JumpAndLink)
            if mnemonic == Some("jal") && operands.len() == 2
                && matches!(&operands[0], asm::Operand::Register(view)
                    if view.low_bit == 0 && view.bits == 64
                        && matches!(view.register,
                            super::native_machine_ir::PhysicalRegister::RiscvGpr { index: 0 })) => Some(1),
        _ => None,
    };
    candidate.filter(|&index| matches!(operands.get(index),
        Some(asm::Operand::Expression(_)) | Some(asm::Operand::Immediate(_))))
}
fn operand_expressions<'a>(operand: &'a asm::Operand,
    output: &mut Vec<&'a asm::Expression>) {
    match operand {
        asm::Operand::Immediate(value) | asm::Operand::Expression(value) => output.push(value),
        asm::Operand::Address(asm::Address::X86 { displacement, .. }) => { output.push(displacement); }
        asm::Operand::Address(asm::Address::Aarch64 { offset, .. }) => {
            if let Some(value) = offset { output.push(value); }
        }
        asm::Operand::Address(asm::Address::Riscv { displacement, .. }) => output.push(displacement),
        asm::Operand::Indirect(inner) => operand_expressions(inner, output),
        asm::Operand::Register(_)
        | asm::Operand::ZeroRegister { .. }
        | asm::Operand::String(_)
        | asm::Operand::Shift { .. } => {}
    }
}
/// One immutable source pass shared by observation and fixed reconstruction.
/// Numeric labels use consumed reader order/links, never SourceItemId order.
/// Only an exact unique intrabody no-link control target is exempt; every other
/// symbolic operand/atom occurrence retains a separate whole-unit reference.
fn instruction_reference_rows(parsed: &asm::ParsedAssembly,
    owners: &BTreeMap<u64, u64>) -> (BTreeMap<u64, Vec<InstructionReference>>, Vec<ConstructionIssue>) {
    let mut rows = BTreeMap::<u64, Vec<InstructionReference>>::new();
    let mut issues = Vec::new();
    let mut named = BTreeMap::<&str, Vec<usize>>::new();
    for (index, record) in parsed.records.iter().enumerate() {
        if let asm::Syntax::Label(asm::Label::Named(name)) = &record.syntax {
            named.entry(name.as_str()).or_default().push(index);
        }
    }
    // At most two directions per (record, number). Conflicts are retained rather
    // than overwriting an observed definition; raw LabelUse rows stay with parsed.
    let mut numeric = BTreeMap::<(usize, u64), Vec<(&asm::LabelUse, bool)>>::new();
    for usage in &parsed.label_uses {
        let bucket = numeric.entry((usage.record, usage.number)).or_default();
        if let Some((held, conflict)) = bucket.iter_mut()
            .find(|(held, _)| held.direction == usage.direction) {
            if held.definition != usage.definition { *conflict = true; }
        } else { bucket.push((usage, false)); }
    }
    for (index, record) in parsed.records.iter().enumerate() {
        let asm::Syntax::Instruction { opcode, operands } = &record.syntax else { continue; };
        let id = record.required.id;
        let owner = owners.get(&id).copied();
        let control = local_control_operand(*opcode, operands, record_mnemonic(parsed, record));
        for (operand_index, operand) in operands.iter().enumerate() {
            let mut expressions = Vec::new();
            operand_expressions(operand, &mut expressions);
            let sole_expression = expressions.len() == 1;
            for expression in expressions {
                let plain_control = control == Some(operand_index) && sole_expression
                    && expression.rest.is_empty();
                for (atom_index, atom) in std::iter::once(&expression.first)
                    .chain(expression.rest.iter().map(|(_, value)| value)).enumerate() {
                    let symbol = match atom {
                        asm::ExprAtom::Symbol(name) => {
                            let definitions = named.get(name.as_str());
                            if definitions.is_some_and(|values| values.len() > 1) {
                                issues.push(issue(Some(id), owner, "instruction-reference",
                                    format!("instruction symbol has multiple original definitions: {name}")));
                            }
                            let local = plain_control && owner.is_some()
                                && definitions.is_some_and(|values| values.len() == 1
                                    && owners.get(&parsed.records[values[0]].required.id).copied() == owner);
                            if local { continue; }
                            unit::SymbolName::Named { value: name.clone() }
                        }
                        asm::ExprAtom::Relocation { symbol, .. } =>
                            unit::SymbolName::Named { value: symbol.clone() },
                        asm::ExprAtom::NumericLabel { number, direction } => {
                            let resolution = numeric.get(&(index, *number)).and_then(|bucket|
                                bucket.iter().find(|(usage, _)| usage.direction == *direction));
                            let Some((usage, conflict)) = resolution else {
                                issues.push(issue(Some(id), owner, "instruction-reference",
                                    "numeric instruction reference has no consumed reader resolution"));
                                continue;
                            };
                            if *conflict {
                                issues.push(issue(Some(id), owner, "instruction-reference",
                                    "numeric instruction reference has conflicting reader resolutions"));
                                continue;
                            }
                            let Some(definition) = usage.definition else {
                                issues.push(issue(Some(id), owner, "instruction-reference",
                                    "numeric instruction reference has no original definition"));
                                continue;
                            };
                            let Some(definition_record) = parsed.records.get(definition) else {
                                issues.push(issue(Some(id), owner, "instruction-reference",
                                    "numeric instruction definition exceeds original record inventory"));
                                continue;
                            };
                            if !matches!(&definition_record.syntax,
                                asm::Syntax::Label(asm::Label::Numeric(actual)) if actual == number) {
                                issues.push(issue(Some(id), owner, "instruction-reference",
                                    "numeric reader resolution does not name its original numeric label"));
                                continue;
                            }
                            if plain_control && owner.is_some()
                                && owners.get(&definition_record.required.id).copied() == owner { continue; }
                            unit::SymbolName::NumericLocal {
                                number: *number, definition_record: definition_record.required.id,
                            }
                        }
                        asm::ExprAtom::Integer(_) | asm::ExprAtom::CurrentLocation => continue,
                    };
                    let (Ok(operand), Ok(atom)) =
                        (u64::try_from(operand_index), u64::try_from(atom_index)) else {
                        issues.push(issue(Some(id), owner, "instruction-reference",
                            "instruction operand/atom index exceeds u64"));
                        continue;
                    };
                    rows.entry(id).or_default().push(InstructionReference { symbol, operand, atom });
                }
            }
        }
    }
    (rows, issues)
}

/// Real declaration decoding before any build_body/lifter invocation. Every
/// source record is attempted. Storage/alignment IDs are allocated where the
/// existing decoder actually emits those rows, so no padding semantics are copied.
/// Exact local control labels stay in body items; other symbolic operand
/// occurrences are also decoded into the whole-unit dependency namespace.
/// ABI/interfaces and original function boundaries remain independently selected.
pub fn observe_source_declarations(parsed: &asm::ParsedAssembly,
    selected_bodies: &[SourceBodySelection]) -> ObservedSourceDeclarations {
    let mut issues = Vec::new();
    if !parsed.problems.is_empty() {
        issues.push(issue(None, None, "source-observation", "original syntax has retained parser problems"));
    }
    let mut body_ids = BTreeSet::new();
    let mut body_names = BTreeMap::<String, usize>::new();
    let mut owners = BTreeMap::<u64, usize>::new();
    for (index, body) in selected_bodies.iter().enumerate() {
        if !body_ids.insert(body.id) {
            issues.push(issue(None, Some(body.id), "source-observation", "duplicate selected source body ID"));
        }
        if body.symbol.is_empty() || body.symbol.contains('\0') || body_names.contains_key(&body.symbol) {
            issues.push(issue(None, Some(body.id), "source-observation", "invalid or duplicate selected source body name"));
        } else { body_names.insert(body.symbol.clone(), index); }
        if body.record_ids.is_empty() {
            issues.push(issue(None, Some(body.id), "source-observation", "empty selected source body membership"));
        }
        for &record in &body.record_ids {
            if owners.contains_key(&record) {
                issues.push(issue(Some(record), Some(body.id), "source-observation", "repeated/multiple source record ownership"));
            } else { owners.insert(record, index); }
        }
    }
    let mut sections = Vec::<unit::UnitSection>::new();
    let mut section_names = BTreeSet::<String>::new();
    let mut symbols = Vec::<unit::UnitSymbol>::new();
    let mut names = BTreeMap::<unit::SymbolName, u64>::new();
    let mut records = Vec::new();
    let mut actual: Vec<Vec<u64>> = (0..selected_bodies.len()).map(|_| Vec::new()).collect();
    let mut items: Vec<Vec<SourceItem>> = (0..selected_bodies.len()).map(|_| Vec::new()).collect();
    let mut record_rows = BTreeMap::new();
    for record in &parsed.records {
        let id = record.required.id;
        if record_rows.contains_key(&id) {
            issues.push(issue(Some(id), None, "source-observation", "duplicate parsed source record ID"));
        } else { record_rows.insert(id, record); }
        let owner = owners.get(&id).copied();
        if let Some(index) = owner {
            actual[index].push(id);
            if let Some(kind) = item_kind(record.required.kind) {
                items[index].push(SourceItem { id, kind, decoded_span: record.required.span,
                    origins: record.required.origins.clone() });
            } else {
                issues.push(issue(Some(id), Some(selected_bodies[index].id), "source-observation", "body record lacks an item representation"));
            }
        }
        let observed = (|| -> Check<()> {
            match &record.syntax {
                asm::Syntax::Label(asm::Label::Named(name)) => {
                    if owner.is_none() || body_names.contains_key(name) { observed_named(name, &mut names, &mut symbols)?; }
                }
                asm::Syntax::Label(asm::Label::Numeric(number)) if owner.is_none() => {
                    observed_symbol(unit::SymbolName::NumericLocal { number: *number, definition_record: id }, &mut names, &mut symbols)?;
                }
                asm::Syntax::Directive(directive) => match directive {
                    asm::Directive::Section { kind, name, .. } => {
                        let name = match kind {
                            asm::SectionKind::Text => Some(".text"), asm::SectionKind::Data => Some(".data"),
                            asm::SectionKind::Bss => Some(".bss"),
                            asm::SectionKind::Named | asm::SectionKind::Push => name.as_deref(),
                            asm::SectionKind::Pop | asm::SectionKind::Previous => None,
                        };
                        if let Some(name) = name {
                            if section_names.insert(name.into()) {
                                let id = u64::try_from(sections.len()).map_err(|_| "source section count exceeds u64")?;
                                sections.push(unit::UnitSection { id, name: name.into(), kind: unit::SectionKind::ProgramBits,
                                    flags: Vec::new(), alignment: 1, byte_size: None });
                            }
                        }
                    }
                    asm::Directive::Binding { names: selected, .. } => {
                        for name in selected { observed_named(name, &mut names, &mut symbols)?; }
                    }
                    asm::Directive::SymbolType { name, .. } => observed_named(name, &mut names, &mut symbols)?,
                    asm::Directive::Size { name, size } => {
                        observed_named(name, &mut names, &mut symbols)?; observed_expression(size, &mut names, &mut symbols)?;
                    }
                    asm::Directive::Assignment { name, value, .. } => {
                        observed_named(name, &mut names, &mut symbols)?; observed_expression(value, &mut names, &mut symbols)?;
                    }
                    asm::Directive::Integers { values, .. } => {
                        for value in values { observed_expression(value, &mut names, &mut symbols)?; }
                    }
                    _ => {}
                },
                _ => {}
            }
            Ok(())
        })();
        if let Err(reason) = observed {
            issues.push(issue(Some(id), owner.map(|index| selected_bodies[index].id), "source-observation", reason));
        }
        if let Some(kind) = unit_kind(record.required.kind) {
            records.push(unit::UnitRecord { id, kind, span: record.required.span,
                origins: record.required.origins.clone(), effects: Vec::new() });
        } else {
            issues.push(issue(Some(id), owner.map(|index| selected_bodies[index].id), "source-observation", "source record lacks whole-unit representation"));
        }
    }
    let instruction_owners: BTreeMap<_, _> = owners.iter()
        .map(|(&record, &index)| (record, selected_bodies[index].id)).collect();
    let (instruction_refs, reference_issues) = instruction_reference_rows(parsed, &instruction_owners);
    issues.extend(reference_issues);
    for (&record, references) in &instruction_refs {
        for reference in references {
            if !names.contains_key(&reference.symbol) {
                if let Err(reason) = observed_symbol(reference.symbol.clone(), &mut names, &mut symbols) {
                    issues.push(issue(Some(record), instruction_owners.get(&record).copied(),
                        "instruction-reference", reason));
                }
            }
        }
    }
    let mut bodies = Vec::with_capacity(selected_bodies.len());
    for (index, body) in selected_bodies.iter().enumerate() {
        if actual[index] != body.record_ids {
            issues.push(issue(None, Some(body.id), "source-observation", "source body membership/order differs or contains missing records"));
        }
        if !body.record_ids.first().and_then(|id| record_rows.get(id)).is_some_and(|record|
            matches!(&record.syntax, asm::Syntax::Label(asm::Label::Named(name)) if name == &body.symbol)) {
            issues.push(issue(body.record_ids.first().copied(), Some(body.id), "source-observation", "body must begin at exact named function label"));
        }
        let symbol = names.get(&unit::SymbolName::Named { value: body.symbol.clone() }).copied();
        if symbol.is_none() { issues.push(issue(None, Some(body.id), "source-observation", "selected body symbol absent")); }
        bodies.push(ObservedSourceBody { id: body.id, symbol, source_symbol: body.symbol.clone(),
            record_ids: std::mem::take(&mut actual[index]), items: std::mem::take(&mut items[index]) });
    }
    let seed = unit::UnitDeclarations { sections, symbols, records, initializers: Vec::new(),
        relocations: Vec::new(), alignments: Vec::new(), external_obligations: Vec::new() };
    let selected = bodies.iter().filter_map(|body| body.symbol.map(|symbol| (symbol, body.id)));
    let mut decoded = match Declarations::new_namespaces(&seed, parsed.profile.architecture, selected) {
        Ok(mut value) => { value.generated_ids = Some([0; 3]); Some(value) }
        Err(reason) => { issues.push(issue(None, None, "declarations", reason)); None }
    };
    if let Some(decoded) = decoded.as_mut() {
        for record in &parsed.records {
            let body = owners.get(&record.required.id).map(|&index| selected_bodies[index].id);
            if let Err(reason) = decoded.record(record, body, instruction_refs.get(&record.required.id).map(Vec::as_slice).unwrap_or(&[])) { issues.push(issue(Some(record.required.id), body, "declarations", reason)); }
        }
    }
    let declarations = decoded.and_then(|value| match value.finish() {
        Ok(value) => Some(value), Err(reason) => { issues.push(issue(None, None, "declarations", reason)); None }
    });
    ObservedSourceDeclarations { declarations, bodies, issues }
}

struct Declarations {
    expected: unit::UnitDeclarations,
    source_symbols: RefCell<BTreeSet<u64>>,
    architecture: Architecture,
    section_names: BTreeMap<String, u64>,
    names: BTreeMap<unit::SymbolName, u64>,
    body_symbols: BTreeMap<u64, u64>,
    source_records: BTreeMap<u64, unit::UnitRecord>,
    sections: BTreeMap<u64, unit::UnitSection>,
    symbols: BTreeMap<u64, unit::UnitSymbol>,
    offsets: BTreeMap<u64, Option<u64>>,
    current: Option<u64>,
    previous: Option<u64>,
    stack: Vec<Option<u64>>,
    bound: BTreeSet<u64>,
    initializers: Vec<unit::UnitInitializer>,
    relocations: Vec<unit::UnitRelocation>,
    alignments: Vec<unit::UnitAlignment>,
    records: Vec<unit::UnitRecord>,
    // None preserves the existing held-selector constructor.
    generated_ids: Option<[u64; 3]>,
}
impl Declarations {
    fn new(f: &unit::SelectedUnitInventory) -> Check<Self> {
        Self::new_namespaces(&f.required, f.profile.architecture,
            f.bodies.iter().map(|body| (body.symbol, body.id)))
    }
    fn new_namespaces(required: &unit::UnitDeclarations, architecture: Architecture,
        selected_bodies: impl IntoIterator<Item = (u64, u64)>) -> Check<Self> {
        let mut section_names = BTreeMap::new();
        let mut names = BTreeMap::new();
        let mut symbols = BTreeMap::new();
        let mut source_records = BTreeMap::new();
        let mut body_symbols = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for s in &required.sections {
            require(
                ids.insert(s.id) && section_names.insert(s.name.clone(), s.id).is_none(),
                "duplicate selected section selector",
            )?;
        }
        ids.clear();
        for s in &required.symbols {
            require(
                ids.insert(s.id) && names.insert(s.name.clone(), s.id).is_none(),
                "duplicate selected symbol selector",
            )?;
            symbols.insert(
                s.id,
                unit::UnitSymbol {
                    id: s.id,
                    name: s.name.clone(),
                    binding: unit::SymbolBinding::Global,
                    visibility: unit::SymbolVisibility::Default,
                    kind: unit::SymbolKind::NoType,
                    size: unit::SymbolSize::Unspecified,
                    definition: unit::SymbolDefinition::Undefined,
                },
            );
        }
        for r in &required.records {
            require(
                source_records.insert(r.id, r.clone()).is_none(),
                "duplicate selected unit record selector",
            )?;
        }
        for (symbol, body) in selected_bodies {
            require(
                body_symbols.insert(symbol, body).is_none(),
                "multiple selected bodies for one symbol",
            )?;
        }
        Ok(Self {
            expected: required.clone(),
            source_symbols: RefCell::new(BTreeSet::new()),
            architecture,
            section_names,
            names,
            body_symbols,
            source_records,
            sections: BTreeMap::new(),
            symbols,
            offsets: BTreeMap::new(),
            current: None,
            previous: None,
            stack: vec![],
            bound: BTreeSet::new(),
            initializers: vec![],
            relocations: vec![],
            alignments: vec![],
            records: vec![],
            generated_ids: None,
        })
    }
    fn symbol(&self, name: &str) -> Check<u64> {
        let id = self
            .names
            .get(&unit::SymbolName::Named { value: name.into() })
            .copied()
            .ok_or_else(|| {
                format!("source symbol lacks an independently selected symbol selector: {name}")
            })?;
        self.source_symbols.borrow_mut().insert(id);
        Ok(id)
    }
    fn section(&self) -> Check<u64> {
        self.current
            .ok_or_else(|| "record has no explicit selected section".into())
    }
    fn offset(&self) -> Check<u64> {
        self.offsets
            .get(&self.section()?)
            .copied()
            .flatten()
            .ok_or_else(|| "storage/label needs unresolved code-layout semantics".into())
    }
    fn selectors(&self, record: u64, kind: u8) -> Vec<u64> {
        self.source_records
            .get(&record)
            .into_iter()
            .flat_map(|r| &r.effects)
            .filter_map(|e| match (kind, e) {
                (0, unit::RecordEffect::Initialize { initializer }) => Some(*initializer),
                (1, unit::RecordEffect::Relocate { relocation }) => Some(*relocation),
                (2, unit::RecordEffect::Alignment { alignment }) => Some(*alignment),
                _ => None,
            })
            .collect()
    }
    fn emission_selectors(&mut self, record: u64, kind: u8, count: usize) -> Check<Vec<u64>> {
        let Some(counters) = self.generated_ids.as_mut() else {
            return Ok(self.selectors(record, kind));
        };
        let counter = counters.get_mut(usize::from(kind)).ok_or("invalid generated selector kind")?;
        let count = u64::try_from(count).map_err(|_| "declaration selector count exceeds u64")?;
        let start = *counter;
        let end = start.checked_add(count).ok_or("declaration selector space exhausted")?;
        *counter = end;
        Ok((start..end).collect())
    }
    fn select(
        &mut self,
        name: &str,
        flags: Option<&Vec<u8>>,
        kind: Option<asm::SectionType>,
    ) -> Check<u64> {
        let id = *self
            .section_names
            .get(name)
            .ok_or_else(|| format!("section lacks selected selector: {name}"))?;
        let default = match name {
            ".text" => (b"ax".to_vec(), unit::SectionKind::ProgramBits),
            ".data" => (b"aw".to_vec(), unit::SectionKind::ProgramBits),
            ".bss" => (b"aw".to_vec(), unit::SectionKind::NoBits),
            _ => {
                require(
                    self.sections.contains_key(&id) || (flags.is_some() && kind.is_some()),
                    "first named section requires explicit flags and section type",
                )?;
                (vec![], unit::SectionKind::ProgramBits)
            }
        };
        let converted = kind.map(|k| match k {
            asm::SectionType::Progbits => unit::SectionKind::ProgramBits,
            asm::SectionType::Nobits => unit::SectionKind::NoBits,
            asm::SectionType::Note => unit::SectionKind::Note,
        });
        if let Some(s) = self.sections.get(&id) {
            require(
                flags.is_none_or(|f| *f == s.flags) && converted.is_none_or(|k| k == s.kind),
                "section attributes changed incompatibly",
            )?;
        } else {
            self.sections.insert(
                id,
                unit::UnitSection {
                    id,
                    name: name.into(),
                    kind: converted.unwrap_or(default.1),
                    flags: flags.cloned().unwrap_or(default.0),
                    alignment: 1,
                    byte_size: Some(0),
                },
            );
            self.offsets.insert(id, Some(0));
        }
        if self.current != Some(id) {
            self.previous = self.current;
            self.current = Some(id);
        }
        Ok(id)
    }
    fn append_initializer(&mut self, id: u64, value: unit::InitializerValue) -> Check<()> {
        let section = self.section()?;
        let offset = self.offset()?;
        let bytes = match &value {
            unit::InitializerValue::Bytes { value } => value.len() as u64,
            unit::InitializerValue::RepeatByte { count, .. } => *count,
            unit::InitializerValue::ZeroFill { bytes } => *bytes,
            unit::InitializerValue::Relocation { bytes, .. } => u64::from(*bytes),
        };
        let next = offset.checked_add(bytes).ok_or("section extent overflow")?;
        self.initializers.push(unit::UnitInitializer {
            id,
            section,
            offset,
            value,
        });
        self.offsets.insert(section, Some(next));
        Ok(())
    }
    fn storage(&mut self, r: u64, values: Vec<Storage>) -> Check<Vec<unit::RecordEffect>> {
        let init_ids = self.emission_selectors(r, 0, values.len())?;
        let count = values.iter().filter(|value| matches!(value, Storage::Relocation { .. })).count();
        let rel_ids = self.emission_selectors(r, 1, count)?;
        require(
            init_ids.len() == values.len(),
            "selected initializer selector count differs from source",
        )?;
        let mut effects = vec![];
        let mut ri = 0;
        for (id, value) in init_ids.into_iter().zip(values) {
            let stored = match value {
                Storage::Value(v) => v,
                Storage::Relocation {
                    target,
                    kind,
                    addend,
                    bytes,
                } => {
                    let relocation = *rel_ids
                        .get(ri)
                        .ok_or("source relocation has no selected selector")?;
                    ri += 1;
                    self.relocations.push(unit::UnitRelocation {
                        id: relocation,
                        section: self.section()?,
                        offset: self.offset()?,
                        architecture: self.architecture()?,
                        bytes,
                        kind,
                        target,
                        addend,
                    });
                    effects.push(unit::RecordEffect::Initialize { initializer: id });
                    effects.push(unit::RecordEffect::Relocate { relocation });
                    self.append_initializer(
                        id,
                        unit::InitializerValue::Relocation { relocation, bytes },
                    )?;
                    continue;
                }
            };
            self.append_initializer(id, stored)?;
            effects.push(unit::RecordEffect::Initialize { initializer: id });
        }
        require(
            ri == rel_ids.len(),
            "selected relocation selector count differs from source",
        )?;
        Ok(effects)
    }
    fn architecture(&self) -> Check<Architecture> {
        // Derive target architecture from the joined actual machine profile.
        Ok(self.architecture)
    }
    fn decode_storage(&self, e: &asm::Expression, bytes: u8) -> Check<Storage> {
        if let Ok(n) = integer_expression(e) {
            let bits = u32::from(bytes) * 8;
            require(
                [1, 2, 4, 8, 16].contains(&bytes),
                "unsupported integer storage width",
            )?;
            if bits < 128 {
                require(
                    n >= -(1i128 << (bits - 1)) && (n < 0 || (n as u128) < (1u128 << bits)),
                    "integer storage value exceeds supported exact range",
                )?;
            }
            return Ok(Storage::Value(unit::InitializerValue::Bytes {
                value: (n as u128).to_le_bytes()[..usize::from(bytes)].to_vec(),
            }));
        }
        let (base, addend) = linear(e)?;
        let (name, kind) = match base {
            asm::ExprAtom::Symbol(name) => (name, unit::RelocationKind::Absolute),
            asm::ExprAtom::Relocation { kind, symbol } => (
                symbol,
                match kind {
                    asm::Relocation::GotPcRel => unit::RelocationKind::GotPcRelative,
                    asm::Relocation::GotPcRelX => unit::RelocationKind::GotPcRelativeRelaxed,
                    asm::Relocation::RexGotPcRelX => unit::RelocationKind::RexGotPcRelativeRelaxed,
                    asm::Relocation::Got => unit::RelocationKind::Got,
                    asm::Relocation::Plt => unit::RelocationKind::Plt,
                    asm::Relocation::TpOff => unit::RelocationKind::TlsTpOffset,
                    asm::Relocation::GpOff => unit::RelocationKind::GlobalPointerOffset,
                    asm::Relocation::PcRelHi => unit::RelocationKind::PcRelativeHigh,
                    asm::Relocation::PcRelLo => unit::RelocationKind::PcRelativeLow,
                    asm::Relocation::Hi => unit::RelocationKind::AbsoluteHigh,
                    asm::Relocation::Lo => unit::RelocationKind::AbsoluteLow,
                },
            ),
            _ => return Err(
                "data expression requires unimplemented location/numeric-label relocation binding"
                    .into(),
            ),
        };
        Ok(Storage::Relocation {
            target: self.symbol(&name)?,
            kind,
            addend,
            bytes,
        })
    }
    fn size(&self, e: &asm::Expression, record: u64) -> Check<unit::SymbolSize> {
        if let Ok(n) = unsigned(e) {
            return Ok(unit::SymbolSize::Bytes { bytes: n });
        }
        if e.first == asm::ExprAtom::CurrentLocation {
            if let Some((asm::AddSub::Subtract, asm::ExprAtom::Symbol(name))) = e.rest.first() {
                let tail = asm::Expression {
                    first: asm::ExprAtom::Integer(0),
                    rest: e.rest[1..].to_vec(),
                };
                let addend = i64::try_from(integer_expression(&tail).map_err(|e| e.reason)?)
                    .map_err(|_| "size addend exceeds i64")?;
                return Ok(unit::SymbolSize::Difference {
                    end: unit::SizeAnchor::CurrentLocation {
                        record,
                        section: self.section()?,
                    },
                    start: unit::SizeAnchor::Symbol {
                        symbol: self.symbol(name)?,
                    },
                    addend,
                });
            }
        }
        Err("symbol size needs an unimplemented layout expression".into())
    }
    fn record(&mut self, p: &asm::ParsedRecord, body: Option<u64>,
        instruction_refs: &[InstructionReference]) -> Check<()> {
        let id = p.required.id;
        let mut effects = vec![];
        match &p.syntax {
            asm::Syntax::Unsupported => {
                return Err(
                    if body.is_some() && p.required.kind == asm::SyntaxKind::Data {
                        "inline body data has no implemented machine directive semantics"
                    } else {
                        "parser retained unsupported source record"
                    }
                    .into(),
                )
            }
            asm::Syntax::Instruction { .. } => {
                require(
                    body.is_some(),
                    "instruction has no independently selected body owner",
                )?;
                let section = self.section()?;
                self.offsets.insert(section, None);
                for reference in instruction_refs {
                    let symbol = self.names.get(&reference.symbol).copied().ok_or_else(||
                        format!("instruction reference absent from selected unit namespace: {:?}", reference.symbol))?;
                    self.source_symbols.borrow_mut().insert(symbol);
                    effects.push(unit::RecordEffect::InstructionReference {
                        symbol, operand: reference.operand, atom: reference.atom,
                    });
                }
            }
            asm::Syntax::Label(label) => {
                let name = match label {
                    asm::Label::Named(n) => unit::SymbolName::Named { value: n.clone() },
                    asm::Label::Numeric(n) => unit::SymbolName::NumericLocal {
                        number: *n,
                        definition_record: id,
                    },
                };
                if let Some(&symbol) = self.names.get(&name) {
                    self.source_symbols.borrow_mut().insert(symbol);
                    let section = self.section()?;
                    let definition = if let Some(&b) = self.body_symbols.get(&symbol) {
                        unit::SymbolDefinition::Body { section, body: b }
                    } else {
                        unit::SymbolDefinition::InSection {
                            section,
                            offset: self.offset()?,
                        }
                    };
                    let s = self
                        .symbols
                        .get_mut(&symbol)
                        .ok_or("missing symbol namespace")?;
                    require(
                        s.definition == unit::SymbolDefinition::Undefined,
                        "duplicate source symbol definition",
                    )?;
                    s.definition = definition;
                    if !self.bound.contains(&symbol) {
                        s.binding = unit::SymbolBinding::Local;
                    }
                    effects.push(unit::RecordEffect::DefineSymbol { symbol });
                } else {
                    require(
                        body.is_some(),
                        "label outside a body lacks a selected symbol selector",
                    )?;
                }
            }
            asm::Syntax::PreprocessorMarker { line, path, flags } => {
                effects.push(unit::RecordEffect::PreprocessorMarker {
                    line: *line,
                    path: path.clone(),
                    flags: flags.clone(),
                })
            }
            asm::Syntax::Directive(d) => {
                match d {
                    asm::Directive::Section {
                        kind,
                        name,
                        flags,
                        section_type,
                        subsection,
                    } => {
                        require(
                            subsection.is_none_or(|n| n == 0),
                            "subsection reordering is not implemented",
                        )?;
                        let section = match kind {
                            asm::SectionKind::Text => self.select(".text", None, None)?,
                            asm::SectionKind::Data => self.select(".data", None, None)?,
                            asm::SectionKind::Bss => self.select(".bss", None, None)?,
                            asm::SectionKind::Named => self.select(
                                name.as_deref().ok_or("missing section name")?,
                                flags.as_ref(),
                                *section_type,
                            )?,
                            asm::SectionKind::Push => {
                                self.stack.push(self.current);
                                self.select(
                                    name.as_deref().ok_or("missing pushed section name")?,
                                    flags.as_ref(),
                                    *section_type,
                                )?
                            }
                            asm::SectionKind::Pop => {
                                let restored = self
                                    .stack
                                    .pop()
                                    .ok_or("section stack underflow")?
                                    .ok_or("section stack has no prior section")?;
                                self.previous = self.current;
                                self.current = Some(restored);
                                restored
                            }
                            asm::SectionKind::Previous => {
                                let previous = self.previous.ok_or("previous section is absent")?;
                                self.previous = self.current;
                                self.current = Some(previous);
                                previous
                            }
                        };
                        effects.push(unit::RecordEffect::SelectSection { section });
                    }
                    asm::Directive::Binding { kind, names } => {
                        for name in names {
                            let symbol = self.symbol(name)?;
                            let s = self.symbols.get_mut(&symbol).ok_or("missing symbol")?;
                            match kind {
                                asm::Binding::Global | asm::Binding::Weak | asm::Binding::Local => {
                                    let binding = match kind {
                                        asm::Binding::Global => unit::SymbolBinding::Global,
                                        asm::Binding::Weak => unit::SymbolBinding::Weak,
                                        _ => unit::SymbolBinding::Local,
                                    };
                                    s.binding = binding;
                                    self.bound.insert(symbol);
                                    effects.push(unit::RecordEffect::Binding { symbol, binding });
                                }
                                asm::Binding::Hidden | asm::Binding::Protected => {
                                    let visibility = if *kind == asm::Binding::Hidden {
                                        unit::SymbolVisibility::Hidden
                                    } else {
                                        unit::SymbolVisibility::Protected
                                    };
                                    s.visibility = visibility;
                                    effects.push(unit::RecordEffect::Visibility {
                                        symbol,
                                        visibility,
                                    });
                                }
                            }
                        }
                    }
                    asm::Directive::SymbolType { name, kind } => {
                        let symbol = self.symbol(name)?;
                        let kind = match kind {
                            asm::SymbolType::Function => unit::SymbolKind::Function,
                            asm::SymbolType::Object => unit::SymbolKind::Object,
                            asm::SymbolType::Notype => unit::SymbolKind::NoType,
                            asm::SymbolType::TlsObject => unit::SymbolKind::TlsObject,
                        };
                        self.symbols.get_mut(&symbol).ok_or("missing symbol")?.kind = kind;
                        effects.push(unit::RecordEffect::SymbolType { symbol, kind });
                    }
                    asm::Directive::Size { name, size } => {
                        let symbol = self.symbol(name)?;
                        let size = self.size(size, id)?;
                        self.symbols.get_mut(&symbol).ok_or("missing symbol")?.size = size;
                        effects.push(unit::RecordEffect::SymbolSize { symbol, size });
                    }
                    asm::Directive::Assignment { name, value, equ } => {
                        let symbol = self.symbol(name)?;
                        let (base, addend) = linear(value)?;
                        let asm::ExprAtom::Symbol(name) = base else {
                            return Err("absolute or non-symbol assignment needs a new typed representation".into());
                        };
                        let target = self.symbol(&name)?;
                        self.symbols
                            .get_mut(&symbol)
                            .ok_or("missing symbol")?
                            .definition = unit::SymbolDefinition::Alias { target, addend };
                        effects.push(unit::RecordEffect::Alias {
                            symbol,
                            target,
                            addend,
                            equ: *equ,
                        });
                    }
                    asm::Directive::Integers {
                        element_bytes,
                        values,
                    } => {
                        require(
                            body.is_none(),
                            "inline body data has no implemented machine directive semantics",
                        )?;
                        let values = values
                            .iter()
                            .map(|e| self.decode_storage(e, *element_bytes))
                            .collect::<Check<Vec<_>>>()?;
                        effects = self.storage(id, values)?;
                    }
                    asm::Directive::Space { count, fill } => {
                        require(
                            body.is_none(),
                            "inline body data has no implemented machine directive semantics",
                        )?;
                        let count = unsigned(count)?;
                        let byte = fill.as_ref().map(unsigned).transpose()?.unwrap_or(0);
                        let byte = u8::try_from(byte).map_err(|_| "space fill exceeds one byte")?;
                        let value =
                            if self.sections[&self.section()?].kind == unit::SectionKind::NoBits {
                                require(byte == 0, "nonzero fill cannot be represented by NOBITS")?;
                                unit::InitializerValue::ZeroFill { bytes: count }
                            } else {
                                unit::InitializerValue::RepeatByte { byte, count }
                            };
                        effects = self.storage(id, vec![Storage::Value(value)])?;
                    }
                    asm::Directive::Strings {
                        values,
                        nul_terminated,
                    } => {
                        require(
                            body.is_none(),
                            "inline body data has no implemented machine directive semantics",
                        )?;
                        let values = values
                            .iter()
                            .map(|v| {
                                let mut v = v.clone();
                                if *nul_terminated {
                                    v.push(0);
                                }
                                Storage::Value(unit::InitializerValue::Bytes { value: v })
                            })
                            .collect();
                        effects = self.storage(id, values)?;
                    }
                    asm::Directive::Alignment {
                        kind,
                        boundary,
                        fill,
                        maximum_skip,
                    } => {
                        let raw = unsigned(boundary)?;
                        let boundary=match kind {
                        asm::AlignmentKind::PowerOfTwo=>1u64.checked_shl(u32::try_from(raw).map_err(|_|"alignment exponent exceeds u32")?).ok_or("alignment exponent overflow")?,
                        asm::AlignmentKind::ByteAlign=>raw,
                        asm::AlignmentKind::Align=>return Err("target-dependent .align semantics need an explicit supported profile".into()),
                    };
                        require(
                            boundary.is_power_of_two(),
                            "alignment boundary is not a power of two",
                        )?;
                        let fill = fill
                            .as_ref()
                            .map(unsigned)
                            .transpose()?
                            .map(u8::try_from)
                            .transpose()
                            .map_err(|_| "alignment fill exceeds one byte")?;
                        let maximum_skip = maximum_skip.as_ref().map(unsigned).transpose()?;
                        let ids = self.emission_selectors(id, 2, 1)?;
                        require(
                            ids.len() == 1,
                            "alignment needs exactly one selected alignment selector",
                        )?;
                        let section = self.section()?;
                        let offset = self.offsets[&section];
                        let layout = offset.map(|offset| {
                            let padding = (boundary - offset % boundary) % boundary;
                            if maximum_skip.is_some_and(|n| padding > n) {
                                unit::AlignmentLayout::Skipped {
                                    offset,
                                    required_padding: padding,
                                }
                            } else {
                                unit::AlignmentLayout::Applied { offset, padding }
                            }
                        });
                        self.sections
                            .get_mut(&section)
                            .ok_or("missing section")?
                            .alignment = self.sections[&section].alignment.max(boundary);
                        self.alignments.push(unit::UnitAlignment {
                            id: ids[0],
                            section,
                            boundary,
                            fill,
                            maximum_skip,
                            layout,
                        });
                        effects.push(unit::RecordEffect::Alignment { alignment: ids[0] });
                        let padding = match layout {
                            Some(unit::AlignmentLayout::Applied { padding, .. }) => padding,
                            _ => 0,
                        };
                        let values = if padding == 0 {
                            vec![]
                        } else {
                            let byte = fill.unwrap_or(0);
                            let value = if self.sections[&section].kind == unit::SectionKind::NoBits
                            {
                                require(byte == 0, "nonzero alignment fill cannot be NOBITS")?;
                                unit::InitializerValue::ZeroFill { bytes: padding }
                            } else {
                                require(
                                    !self.sections[&section].flags.contains(&b'x')
                                        || fill.is_some(),
                                    "executable padding needs explicit byte-fill semantics",
                                )?;
                                unit::InitializerValue::RepeatByte {
                                    byte,
                                    count: padding,
                                }
                            };
                            vec![Storage::Value(value)]
                        };
                        effects.extend(self.storage(id, values)?);
                    }
                    asm::Directive::Cfi(_) => require(
                        body.is_some(),
                        "CFI has no independently selected body owner",
                    )?,
                    asm::Directive::File { number, path } => {
                        effects.push(unit::RecordEffect::File {
                            number: *number,
                            path: path.clone(),
                        })
                    }
                    asm::Directive::Location { file, line, column } => {
                        effects.push(unit::RecordEffect::Location {
                            file: *file,
                            line: *line,
                            column: *column,
                        })
                    }
                }
            }
        }
        if let Some(body) = body {
            effects.push(unit::RecordEffect::BodyItem { body });
        }
        let kind = unit_kind(p.required.kind)
            .ok_or("source record kind has no supported whole-unit representation")?;
        self.records.push(unit::UnitRecord {
            id,
            kind,
            span: p.required.span,
            origins: p.required.origins.clone(),
            effects,
        });
        Ok(())
    }
    fn finish(self) -> Check<unit::UnitDeclarations> {
        let mut declarations = self.finish_without_instruction_uses()?;
        let symbols: BTreeSet<_> = declarations.symbols.iter().map(|symbol| symbol.id).collect();
        let mut external = BTreeMap::<u64, BTreeSet<unit::ExternalUse>>::new();
        for obligation in std::mem::take(&mut declarations.external_obligations) {
            let uses: BTreeSet<_> = obligation.uses.iter().cloned().collect();
            require(uses.len() == obligation.uses.len()
                && external.insert(obligation.symbol, uses).is_none(),
                "duplicate decoded external obligation/use")?;
        }
        for record in &declarations.records {
            for effect in &record.effects {
                if let unit::RecordEffect::InstructionReference { symbol, operand, atom } = effect {
                    require(symbols.contains(symbol), "decoded instruction references missing symbol")?;
                    if let Some(uses) = external.get_mut(symbol) {
                        uses.insert(unit::ExternalUse::Instruction {
                            record: record.id, operand: *operand, atom: *atom,
                        });
                    }
                }
            }
        }
        declarations.external_obligations = external.into_iter().map(|(symbol, uses)|
            unit::ExternalObligation { symbol, uses: uses.into_iter().collect() }).collect();
        Ok(declarations)
    }
    fn finish_without_instruction_uses(mut self) -> Check<unit::UnitDeclarations> {
        require(
            self.symbols
                .keys()
                .all(|id| self.source_symbols.borrow().contains(id)),
            "selected symbol has no decoded source mention",
        )?;
        for s in self.sections.values_mut() {
            s.byte_size = self.offsets[&s.id];
        }
        let mut external = BTreeMap::<u64, BTreeSet<unit::ExternalUse>>::new();
        for s in self.symbols.values() {
            if s.definition == unit::SymbolDefinition::Undefined {
                external
                    .entry(s.id)
                    .or_default()
                    .insert(unit::ExternalUse::Declaration);
            }
        }
        for r in &self.relocations {
            if let Some(uses) = external.get_mut(&r.target) {
                uses.insert(unit::ExternalUse::Relocation { relocation: r.id });
            }
        }
        for s in self.symbols.values() {
            if let unit::SymbolDefinition::Alias { target, .. } = s.definition {
                if let Some(uses) = external.get_mut(&target) {
                    uses.insert(unit::ExternalUse::Alias { symbol: s.id });
                }
            }
            if let unit::SymbolSize::Difference { end, start, .. } = s.size {
                for a in [end, start] {
                    if let unit::SizeAnchor::Symbol { symbol } = a {
                        if let Some(uses) = external.get_mut(&symbol) {
                            uses.insert(unit::ExternalUse::Size { symbol: s.id });
                        }
                    }
                }
            }
        }
        let sections = self
            .expected
            .sections
            .iter()
            .map(|s| {
                self.sections
                    .get(&s.id)
                    .cloned()
                    .ok_or_else(|| "required section was never selected by source".into())
            })
            .collect::<Check<Vec<_>>>()?;
        let symbols = self
            .expected
            .symbols
            .iter()
            .map(|s| self.symbols[&s.id].clone())
            .collect();
        Ok(unit::UnitDeclarations {
            sections,
            symbols,
            initializers: self.initializers,
            relocations: self.relocations,
            alignments: self.alignments,
            records: self.records,
            external_obligations: external
                .into_iter()
                .map(|(symbol, uses)| unit::ExternalObligation {
                    symbol,
                    uses: uses.into_iter().collect(),
                })
                .collect(),
        })
    }
}
enum Storage {
    Value(unit::InitializerValue),
    Relocation {
        target: u64,
        kind: unit::RelocationKind,
        addend: i64,
        bytes: u8,
    },
}

fn cfi(p: &asm::ParsedRecord) -> Check<Option<DirectiveRecord>> {
    let directive = match &p.syntax {
        asm::Syntax::Directive(asm::Directive::Cfi(c)) => match c {
            asm::Cfi::Start { simple: false } => MachineDirective::CfiStart,
            asm::Cfi::End => MachineDirective::CfiEnd,
            asm::Cfi::DefCfa { register, offset } => MachineDirective::CfiDefCfa {
                register: *register,
                offset: *offset,
            },
            asm::Cfi::Offset {
                register,
                offset,
                relative: false,
            } => MachineDirective::CfiSaved {
                register: *register,
                offset: *offset,
            },
            asm::Cfi::Restore(register) => MachineDirective::CfiRestore {
                register: *register,
            },
            _ => {
                return Err(
                    "CFI form requires an unimplemented exact stateful representation".into(),
                )
            }
        },
        asm::Syntax::Directive(asm::Directive::Alignment { kind, boundary, .. }) => {
            let n = unsigned(boundary)?;
            let bytes = match kind {
                asm::AlignmentKind::ByteAlign => n,
                asm::AlignmentKind::PowerOfTwo => 1u64
                    .checked_shl(u32::try_from(n).map_err(|_| "alignment exponent exceeds u32")?)
                    .ok_or("alignment exponent overflow")?,
                _ => return Err("target-dependent body alignment is unsupported".into()),
            };
            MachineDirective::Alignment { bytes }
        }
        asm::Syntax::Directive(
            asm::Directive::SymbolType { name, .. }
            | asm::Directive::Size { name, .. }
            | asm::Directive::Assignment { name, .. },
        ) => MachineDirective::Symbol { name: name.clone() },
        asm::Syntax::Directive(asm::Directive::Binding { names, .. }) => {
            require(
                names.len() == 1,
                "body symbol directive needs one exact symbolic representation",
            )?;
            MachineDirective::Symbol {
                name: names[0].clone(),
            }
        }
        asm::Syntax::Directive(
            asm::Directive::Integers { .. }
            | asm::Directive::Space { .. }
            | asm::Directive::Strings { .. },
        ) => return Err("inline body data is unsupported by current body semantics".into()),
        _ => return Ok(None),
    };
    Ok(Some(DirectiveRecord {
        source_item: p.required.id,
        directive,
    }))
}
fn control_opcode(op: asm::Opcode) -> bool {
    match op {
        asm::Opcode::X86 { operation, .. } => matches!(
            operation,
            asm::X86Opcode::Call
                | asm::X86Opcode::Jump
                | asm::X86Opcode::Return
                | asm::X86Opcode::ConditionalJump(_)
        ),
        asm::Opcode::Aarch64(operation) => matches!(
            operation,
            asm::Aarch64Opcode::Branch
                | asm::Aarch64Opcode::BranchRegister
                | asm::Aarch64Opcode::BranchLinkRegister
                | asm::Aarch64Opcode::Return
                | asm::Aarch64Opcode::CompareBranchZero
                | asm::Aarch64Opcode::CompareBranchNonzero
                | asm::Aarch64Opcode::TestBranchZero
                | asm::Aarch64Opcode::TestBranchNonzero
                | asm::Aarch64Opcode::ConditionalBranch(_)
        ),
        asm::Opcode::Riscv(operation) => matches!(
            operation,
            asm::RiscvOpcode::Jump
                | asm::RiscvOpcode::JumpRegister
                | asm::RiscvOpcode::JumpAndLink
                | asm::RiscvOpcode::BranchEqual
                | asm::RiscvOpcode::BranchNotEqual
                | asm::RiscvOpcode::BranchZero
                | asm::RiscvOpcode::BranchNonzero
                | asm::RiscvOpcode::Return
        ),
    }
}
#[derive(Default)]
struct BlockPlan {
    label: Option<u64>,
    instructions: Vec<usize>,
}
fn branch_target(
    e: &asm::Expression,
    at: usize,
    parsed: &asm::ParsedAssembly,
    labels: &BTreeMap<u64, usize>,
    symbol: &str,
) -> Check<usize> {
    require(
        e.rest.is_empty(),
        "branch target offset/algebra needs exact layout binding",
    )?;
    let definition = match &e.first {
        asm::ExprAtom::Symbol(name) if name == symbol => return Ok(0),
        asm::ExprAtom::Symbol(name) => parsed
            .records
            .iter()
            .position(|r| matches!(&r.syntax,asm::Syntax::Label(asm::Label::Named(n))if n==name))
            .ok_or("branch source label absent")?,
        asm::ExprAtom::NumericLabel { number, direction } => parsed
            .label_uses
            .iter()
            .find(|u| u.record == at && u.number == *number && u.direction == *direction)
            .and_then(|u| u.definition)
            .ok_or("numeric branch label absent")?,
        _ => return Err("branch target requires a supported selected local label".into()),
    };
    labels
        .get(&parsed.records[definition].required.id)
        .copied()
        .ok_or_else(|| "branch leaves its independently selected body".into())
}
fn build_body(
    parsed: &asm::ParsedAssembly,
    required: &unit::RequiredBody,
    raw: &[u8],
    target: Target,
    held_tails: &[DirectTailTarget], parsed_by_id: &BTreeMap<SourceItemId, usize>,
) -> std::result::Result<unit::UnitBody, Vec<ConstructionIssue>> {
    let id = required.id;
    let mut issues = vec![];
    let error = |record, reason: String| issue(record, Some(id), "body", reason);
    let mut selected_tails_by_item = BTreeMap::new();
    for selected in held_tails {
        if selected_tails_by_item.contains_key(&selected.source_item) {
            return Err(vec![error(Some(selected.source_item), "duplicate selected tail occurrence".into())]);
        }
        selected_tails_by_item.insert(selected.source_item, selected);
    }
    if artifact(raw) != required.inventory {
        return Err(vec![error(
            None,
            "body raw inventory identity differs".into(),
        )]);
    }
    let inv: SelectedInstructionInventory = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(e) => return Err(vec![error(None, format!("body inventory JSON: {e}"))]),
    };
    if inv.format != INVENTORY_FORMAT
        || inv.identity != required.machine_inventory_claim
        || inv.source != parsed.source
        || inv.profile != parsed.profile
    {
        return Err(vec![error(
            None,
            "body floor source/profile/format/claim differs".into(),
        )]);
    }
    let required_ids: BTreeSet<_> = required.record_ids.iter().copied().collect();
    if required_ids.len() != required.record_ids.len()
        || inv.items.iter().map(|i| i.id).collect::<BTreeSet<_>>() != required_ids
        || inv.items.len() != required_ids.len()
    {
        return Err(vec![error(
            None,
            "body floor required record membership differs".into(),
        )]);
    }
    for i in &inv.items {
        let Some(p) = parsed.records.iter().find(|p| p.required.id == i.id) else {
            return Err(vec![error(
                Some(i.id),
                "body floor item absent from parsed source".into(),
            )]);
        };
        if item_kind(p.required.kind) != Some(i.kind)
            || p.required.span != i.decoded_span
            || p.required.origins != i.origins
        {
            return Err(vec![error(
                Some(i.id),
                "body floor source selector/span/origin/kind differs".into(),
            )]);
        }
    }
    if inv.interface.exits.len() != 1 || inv.interface.exits[0].kind != ExitKind::OrdinaryReturn {
        return Err(vec![error(
            None,
            "initial body profile requires exactly one selected OrdinaryReturn exit".into(),
        )]);
    }
    let exit = inv.interface.exits[0].id;
    let mut plans = vec![];
    let mut current = BlockPlan::default();
    let mut labels = BTreeMap::new();
    let mut directives = vec![];
    for (index, p) in parsed
        .records
        .iter()
        .enumerate()
        .filter(|(_, p)| required_ids.contains(&p.required.id))
    {
        match &p.syntax {
            asm::Syntax::Label(_) => {
                if !current.instructions.is_empty() {
                    plans.push(current);
                    current = BlockPlan::default();
                }
                if current.label.is_some() {
                    issues.push(error(Some(p.required.id),"adjacent label aliases need a representation preserving each selected label".into()));
                } else {
                    current.label = Some(p.required.id);
                    labels.insert(p.required.id, plans.len());
                }
            }
            asm::Syntax::Instruction { opcode, .. } => {
                current.instructions.push(index);
                if control_opcode(*opcode) {
                    plans.push(current);
                    current = BlockPlan::default();
                }
            }
            _ => match cfi(p) {
                Ok(Some(d)) => directives.push(d),
                Ok(None) => issues.push(error(
                    Some(p.required.id),
                    "body record has no typed directive representation".into(),
                )),
                Err(e) => issues.push(error(Some(p.required.id), e)),
            },
        }
    }
    if !current.instructions.is_empty() {
        plans.push(current);
    } else if let Some(label) = current.label {
        issues.push(error(
            Some(label),
            "trailing label has no representable executable block".into(),
        ));
    }
    if plans.is_empty() {
        issues.push(error(
            None,
            "body has no executable instruction block".into(),
        ));
    }
    let mut ids = LiftIds::new(0, plans.len());
    let mut blocks = vec![];
    for (bi, plan) in plans.iter().enumerate() {
        let mut instructions = vec![];
        let mut state = bi;
        let mut control = None;
        for (ordinal, &index) in plan.instructions.iter().enumerate() {
            let p = &parsed.records[index];
            let before = instructions.len();
            let previous_state = state;
            let mut b = BlockLifter::new(
                &parsed.profile,
                p.required.id,
                state,
                &mut ids,
                &mut instructions,
            );
            let lowered = lift_instruction(parsed, index, &mut b);
            match lowered {
                Err(e) => {
                    issues.push(error(Some(p.required.id), e.reason));
                    drop(b);
                    instructions.truncate(before);
                    state = previous_state;
                }
                Ok(flow) => {
                    let result = match &flow {
                        LiftFlow::ReturnTo { .. } => b
                            .return_control(&flow, exit)
                            .map(Some)
                            .map_err(|e| e.reason),
                        _ => Ok(None),
                    };
                    state = b.state();
                    drop(b);
                    if let Err(e) = result {
                        issues.push(error(Some(p.required.id), e));
                        continue;
                    }
                    if let Ok(Some(c)) = result {
                        control = Some(c);
                    }
                    match flow {
                        LiftFlow::Continue => {
                            // A synthetic constant is not an inventory-preserving nop.
                            let explicit_nop = matches!(
                                &p.syntax,
                                asm::Syntax::Instruction {
                                    opcode: asm::Opcode::X86 {
                                        operation: asm::X86Opcode::Nop,
                                        ..
                                    } | asm::Opcode::Aarch64(asm::Aarch64Opcode::Nop)
                                        | asm::Opcode::Riscv(asm::RiscvOpcode::Nop),
                                    ..
                                }
                            );
                            if instructions.len() == before || explicit_nop {
                                issues.push(error(Some(p.required.id),"zero-operation instruction needs an explicit inventory-preserving machine operation".into()));
                            }
                        }
                        LiftFlow::Jump(e) => {
                            match branch_target(&e, index, parsed, &labels, &inv.symbol) {
                                Ok(target) => {
                                    control = Some(MachineControl::Jump {
                                        edge: Edge {
                                            target,
                                            arguments: vec![],
                                        },
                                    })
                                }
                                Err(local_error) => {
                                    let is_local = match &e.first {
                                        asm::ExprAtom::Symbol(name) => labels.keys().any(|id|
                                            parsed_by_id.get(id).and_then(|index| parsed.records.get(*index))
                                                .is_some_and(|record| matches!(&record.syntax,
                                                    asm::Syntax::Label(asm::Label::Named(label)) if label == name))),
                                        _ => false,
                                    };
                                    match selected_tail_control(&e, p.required.id, required.id, &inv.symbol,
                                        is_local, &selected_tails_by_item) {
                                        Ok(selected) => control = Some(selected),
                                        Err(reason) => issues.push(error(Some(p.required.id),
                                            format!("{local_error}; direct tail: {reason}"))),
                                    }
                                }
                            }
                        }
                        LiftFlow::Branch { condition, target } => {
                            match branch_target(&target, index, parsed, &labels, &inv.symbol) {
                                Ok(target) if bi + 1 < plans.len() => {
                                    control = Some(MachineControl::Branch {
                                        condition: condition.id,
                                        on_true: Edge {
                                            target,
                                            arguments: vec![],
                                        },
                                        on_false: Edge {
                                            target: bi + 1,
                                            arguments: vec![],
                                        },
                                    })
                                }
                                Ok(_) => issues.push(error(
                                    Some(p.required.id),
                                    "conditional branch has no selected fallthrough block".into(),
                                )),
                                Err(e) => issues.push(error(Some(p.required.id), e)),
                            }
                        }
                        LiftFlow::ReturnTo { .. } => {}
                    }
                    if control.is_some() && ordinal + 1 != plan.instructions.len() {
                        issues.push(error(
                            Some(p.required.id),
                            "control transfer is not last in its planned block".into(),
                        ));
                    }
                }
            }
        }
        if let Some(&last) = plan.instructions.last() {
            let source_item = parsed.records[last].required.id;
            if control.is_none() && bi + 1 < plans.len() {
                control = Some(MachineControl::Jump {
                    edge: Edge {
                        target: bi + 1,
                        arguments: vec![],
                    },
                });
            }
            if let Some(control) = control {
                blocks.push(MachineBlock {
                    id: bi,
                    source_label: plan.label,
                    state_parameter: bi,
                    parameters: vec![],
                    instructions,
                    terminator: MachineTerminator {
                        source_item,
                        state,
                        control,
                    },
                });
            } else {
                issues.push(error(
                    Some(source_item),
                    "body falls off the selected end without a typed control transfer".into(),
                ));
            }
        }
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    let contract = MachineBodyContract {
        format: if blocks.iter().any(|block: &MachineBlock| matches!(&block.terminator.control,
            MachineControl::DirectTailTransfer { .. })) { DIRECT_TAIL_CONTROL_FORMAT } else { COMPUTED_CONTROL_FORMAT }.into(),
        selected_inventory: inv.identity.clone(),
        source: parsed.source.clone(),
        symbol: inv.symbol.clone(),
        profile: parsed.profile.clone(),
        interface: inv.interface.clone(),
        entry: 0,
        blocks,
        directives,
    };
    if let Err(e) = super::native_machine_verify::verify_with_tail_targets(&contract, &inv, target, held_tails) {
        return Err(vec![error(
            None,
            format!("existing body guard: {}", e.message),
        )]);
    }
    Ok(unit::UnitBody {
        id,
        symbol: required.symbol,
        contract,
        selected_inventory_json: raw.to_vec(),
    })
}

/// All successful construction is relative to independently selected floors.
/// This function performs no acquisition, external opening, execution or admission.
pub fn construct_configured_unit(
    input: ConstructInput<'_>,
) -> std::result::Result<ConstructedUnit, Box<ConstructionFailure>> {
    let consumed = ConsumedInputs {
        configured: artifact(input.configured_assembly),
        syntax_floor: artifact(input.syntax_inventory_json),
        selected_syntax_floor: input.syntax_selection.inventory.clone(),
        unit_floor: artifact(input.unit_inventory_json),
        selected_unit_floor: input.unit_selection.inventory.clone(),
        body_floors: input
            .body_floors
            .iter()
            .map(|b| (b.body, artifact(b.inventory_json)))
            .collect(),
    };
    let mut failure = Box::new(ConstructionFailure {
        configured_identity: artifact(input.configured_assembly),
        inputs: consumed.clone(),
        parsed: None,
        records: vec![],
        bodies: vec![],
        issues: vec![],
    });
    if artifact(input.syntax_inventory_json) != input.syntax_selection.inventory {
        failure.issues.push(issue(
            None,
            None,
            "input",
            "syntax floor raw identity differs",
        ));
        return Err(failure);
    }
    if artifact(input.unit_inventory_json) != input.unit_selection.inventory {
        failure.issues.push(issue(
            None,
            None,
            "input",
            "unit floor raw identity differs",
        ));
        return Err(failure);
    }
    let parsed = match asm::read_configured_assembly(
        input.configured_assembly,
        input.syntax_selection,
        input.syntax_inventory_json,
        input.target,
    ) {
        Ok(v) => v,
        Err(e) => {
            failure
                .issues
                .push(issue(None, None, "reader", e.to_string()));
            return Err(failure);
        }
    };
    let floor: unit::SelectedUnitInventory = match serde_json::from_slice(input.unit_inventory_json)
    {
        Ok(v) => v,
        Err(e) => {
            failure
                .issues
                .push(issue(None, None, "input", format!("unit floor JSON: {e}")));
            return Err(with_parsed(failure, parsed));
        }
    };
    let unit_format = match unit::unit_format_for_inventory(&floor.format) {
        Some(format) => format,
        None => {
            failure.issues.push(issue(None, None, "input", "unsupported selected unit inventory format"));
            return Err(with_parsed(failure, parsed));
        }
    };
    if floor.source != input.unit_selection.source
        || floor.profile != input.unit_selection.profile
        || parsed.source != floor.source
        || parsed.profile != floor.profile
    {
        failure.issues.push(issue(
            None,
            None,
            "input",
            "syntax/unit selected source/profile/format differs",
        ));
        return Err(with_parsed(failure, parsed));
    }
    let mut owners = BTreeMap::new();
    let mut body_ids = BTreeSet::new();
    for b in &floor.bodies {
        if !body_ids.insert(b.id) {
            failure.issues.push(issue(
                None,
                Some(b.id),
                "input",
                "duplicate required body selector",
            ));
        }
        for &record in &b.record_ids {
            if owners.insert(record, b.id).is_some() {
                failure.issues.push(issue(
                    Some(record),
                    Some(b.id),
                    "input",
                    "required source record has multiple body owners",
                ));
            }
        }
    }
    if parsed.records.len() != floor.required.records.len() {
        failure.issues.push(issue(
            None,
            None,
            "join",
            "syntax/unit complete record counts differ",
        ));
    }
    for (p, u) in parsed.records.iter().zip(&floor.required.records) {
        if p.required.id != u.id
            || unit_kind(p.required.kind) != Some(u.kind)
            || p.required.span != u.span
            || p.required.origins != u.origins
        {
            failure.issues.push(issue(
                Some(p.required.id),
                owners.get(&p.required.id).copied(),
                "join",
                "syntax/unit record selector/span/origin/kind differs",
            ));
        }
    }
    for p in &parsed.problems {
        let record = parsed.records[p.record].required.id;
        failure.issues.push(issue(
            Some(record),
            owners.get(&record).copied(),
            "reader",
            p.reason.clone(),
        ));
    }
    let mut supplied = BTreeMap::new();
    for b in input.body_floors {
        if supplied.insert(b.body, b.inventory_json).is_some() {
            failure.issues.push(issue(
                None,
                Some(b.body),
                "input",
                "duplicate supplied body floor",
            ));
        }
        if !body_ids.contains(&b.body) {
            failure.issues.push(issue(
                None,
                Some(b.body),
                "input",
                "unexpected supplied body floor",
            ));
        }
    }
    let (instruction_refs, reference_issues) = instruction_reference_rows(&parsed, &owners);
    failure.issues.extend(reference_issues);
    if !instruction_refs.is_empty() && (floor.format != unit::UNIT_INVENTORY_FORMAT_V2 && floor.format != unit::UNIT_INVENTORY_FORMAT_V3) {
        failure.issues.push(issue(None, None, "instruction-reference",
            "nonlocal instruction reference facts require V2 selected unit inventory"));
    }
    let selected_names: BTreeSet<_> = floor.required.symbols.iter().map(|symbol| &symbol.name).collect();
    for (&record, references) in &instruction_refs {
        for reference in references {
            if !selected_names.contains(&reference.symbol) {
                failure.issues.push(issue(Some(record), owners.get(&record).copied(), "instruction-reference",
                    format!("instruction reference absent from selected unit namespace: {:?}", reference.symbol)));
            }
        }
    }
    let mut declarations = match Declarations::new(&floor) {
        Ok(v) => Some(v),
        Err(e) => {
            failure.issues.push(issue(None, None, "declarations", e));
            None
        }
    };
    if let Some(d) = declarations.as_mut() {
        for p in &parsed.records {
            if let Err(e) = d.record(p, owners.get(&p.required.id).copied(), instruction_refs.get(&p.required.id).map(Vec::as_slice).unwrap_or(&[])) {
                failure.issues.push(issue(
                    Some(p.required.id),
                    owners.get(&p.required.id).copied(),
                    "declarations",
                    e,
                ));
            }
        }
    }
    let declarations = declarations.and_then(|d| match d.finish() {
        Ok(v) => Some(v),
        Err(e) => {
            failure.issues.push(issue(None, None, "declarations", e));
            None
        }
    });
    let mut bodies = vec![];
    let tail_targets_by_body = unit::selected_direct_tail_targets(&floor.required);
    let mut parsed_by_id = BTreeMap::new();
    for (index, record) in parsed.records.iter().enumerate() {
        if let std::collections::btree_map::Entry::Vacant(slot) = parsed_by_id.entry(record.required.id) {
            slot.insert(index);
        } else {
            failure.issues.push(issue(Some(record.required.id), None, "body", "duplicate original parsed record id"));
        }
    }
    for b in &floor.bodies {
        let constructed = match supplied.get(&b.id) {
            None => {
                failure.issues.push(issue(
                    None,
                    Some(b.id),
                    "input",
                    "missing required body floor",
                ));
                false
            }
            Some(raw) => match build_body(&parsed, b, raw, input.target,
                tail_targets_by_body.get(&b.id).map(Vec::as_slice).unwrap_or(&[]), &parsed_by_id) {
                Ok(v) => {
                    bodies.push(v);
                    true
                }
                Err(mut e) => {
                    failure.issues.append(&mut e);
                    false
                }
            },
        };
        failure.bodies.push(BodyDisposition {
            id: b.id,
            required_records: b.record_ids.clone(),
            constructed,
        });
    }
    failure.records = dispositions(&parsed, &owners, &failure.issues);
    if !failure.issues.is_empty() {
        return Err(with_parsed(failure, parsed));
    }
    let Some(mut declarations) = declarations else {
        failure.issues.push(issue(
            None,
            None,
            "declarations",
            "missing complete declarations",
        ));
        return Err(with_parsed(failure, parsed));
    };
    if let Err(reason) = append_constructed_tail_selections(&mut declarations, &bodies) {
        failure.issues.push(issue(None, None, "tail_selection", reason));
        failure.records = dispositions(&parsed, &owners, &failure.issues);
        return Err(with_parsed(failure, parsed));
    }
    let unit = unit::MachineUnit {
        format: unit_format.into(),
        selected_inventory: input.unit_selection.inventory.clone(),
        source: parsed.source.clone(),
        profile: parsed.profile.clone(),
        declarations,
        bodies,
    };
    let report = match unit::verify_unit(
        &unit,
        input.unit_selection,
        input.unit_inventory_json,
        input.configured_assembly,
        input.target,
    ) {
        Ok(v) => v,
        Err(e) => {
            failure
                .issues
                .push(issue(None, None, "unit", e.to_string()));
            return Err(with_parsed(failure, parsed));
        }
    };
    let ConstructionFailure {
        records, bodies, ..
    } = *failure;
    Ok(ConstructedUnit {
        inputs: consumed,
        parsed,
        unit,
        report,
        records,
        bodies,
    })
}

#[cfg(test)]
#[path = "native_machine_asm_unit_tests.rs"]
pub(crate) mod tests;

/// Source reconstruction artifacts relative to independently supplied floors.
pub use super::native_machine_asm_unit_artifact as artifact;

fn selected_tail_control(
    expression: &asm::Expression,
    source_item: SourceItemId,
    caller_body: unit::BodyId,
    caller_symbol: &str,
    local_label: bool,
    held: &BTreeMap<SourceItemId, &DirectTailTarget>,
) -> Check<MachineControl> {
    require(!local_label, "failed/ambiguous intrafunction label is not a function-tail target")?;
    require(expression.rest.is_empty(), "tail target algebra/offset requires another realization")?;
    let asm::ExprAtom::Symbol(name) = &expression.first else {
        return Err("tail target must be a naked named function, not relocation/numeric/address/indirect syntax".into());
    };
    let selected = *held.get(&source_item).ok_or("nonlocal jump lacks prior selected target/interface")?;
    require(selected.caller_body == caller_body && selected.caller_symbol == caller_symbol
        && selected.target_name == *name && selected.atom == 0,
        "tail source/caller/function differs from held target relation")?;
    Ok(MachineControl::DirectTailTransfer { target: selected.clone() })
}
fn append_constructed_tail_selections(
    declarations: &mut unit::UnitDeclarations,
    bodies: &[unit::UnitBody],
) -> Check<()> {
    let mut positions = BTreeMap::new();
    for (index, record) in declarations.records.iter().enumerate() {
        require(!positions.contains_key(&record.id), "duplicate declaration record id")?;
        positions.insert(record.id, index);
    }
    let mut used = BTreeSet::new();
    for body in bodies {
        for block in &body.contract.blocks {
            if let MachineControl::DirectTailTransfer { target } = &block.terminator.control {
                require(used.insert(target.source_item), "duplicate constructed tail source")?;
                let index = *positions.get(&target.source_item).ok_or("constructed tail source record absent")?;
                declarations.records[index].effects.push(unit::RecordEffect::TailTransferSelection { target: target.clone() });
            }
        }
    }
    Ok(())
}
