//! Whole-unit static assembly planning. Not a source-origin or provider admission.
//! Plans are privately constructed only after the full unit and every record pass.
use super::{
    common::Target, native_machine_emit_rv64, native_machine_ir::*, native_machine_unit::*,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Serialize)]
pub struct RecordDisposition {
    pub record: SourceItemId,
    pub selected: bool,
    pub refusals: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct UnitEmissionFailure {
    pub structural_failure: Option<String>,
    pub records: Vec<RecordDisposition>,
    pub unit_refusals: Vec<String>,
    pub body_refusals: BTreeMap<BodyId, String>,
}
/// Typed consistency encoding, not raw source/JSON identity or admission.
/// This version preserves derived serde field/tag order, vector order, and the
/// exact embedded raw inventory byte vectors. It is not an RFC canonical JSON.
pub const TYPED_UNIT_ENCODING: &str = "ocore-machine-typed-unit-compact-serde-json-v1";
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TypedUnitByteIdentity {
    pub encoding: &'static str,
    pub encoded_unit: ArtifactIdentity,
}
struct TypedIdentityWriter {
    bytes: u64,
    hasher: Sha256,
}
impl std::io::Write for TypedIdentityWriter {
    fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
        let count = u64::try_from(chunk.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "typed unit encoding length exceeds u64",
            )
        })?;
        self.bytes = self.bytes.checked_add(count).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "typed unit encoding extent overflow",
            )
        })?;
        self.hasher.update(chunk);
        Ok(chunk.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn typed_unit_identity(unit: &MachineUnit) -> std::result::Result<TypedUnitByteIdentity, String> {
    let mut writer = TypedIdentityWriter {
        bytes: 0,
        hasher: Sha256::new(),
    };
    serde_json::to_writer(&mut writer, unit)
        .map_err(|e| format!("typed unit encoding failed: {e}"))?;
    Ok(TypedUnitByteIdentity {
        encoding: TYPED_UNIT_ENCODING,
        encoded_unit: ArtifactIdentity {
            bytes: writer.bytes,
            sha256: hex::encode(writer.hasher.finalize()),
        },
    })
}
#[derive(Debug)]
pub struct MachineAssemblyPlan {
    assembly: String,
    pub source_unit_id: String,
    pub inventory: ArtifactIdentity,
    pub configured_assembly: ArtifactIdentity,
    pub assembly_identity: ArtifactIdentity,
    pub selected_bodies: usize,
    pub selected_records: usize,
    abi: &'static str,
    target: Target,
    typed_unit: TypedUnitByteIdentity,
}
impl MachineAssemblyPlan {
    pub fn assembly(&self) -> &str {
        &self.assembly
    }
    pub fn assembler_target(&self) -> &'static str {
        self.target.triple()
    }
    pub fn assembler_abi(&self) -> &'static str {
        self.abi
    }
    pub fn source_or_native_admission(&self) -> bool {
        false
    }
    pub fn typed_unit_identity(&self) -> &TypedUnitByteIdentity {
        &self.typed_unit
    }
    /// Pure consistency only; this does not perform capture/source admission.
    pub fn check_typed_unit(&self, unit: &MachineUnit) -> std::result::Result<(), String> {
        let observed = typed_unit_identity(unit)?;
        if observed != self.typed_unit {
            return Err("typed unit encoding identity differs from selected assembly plan".into());
        }
        Ok(())
    }
}
fn identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphabetic()
                || b == b'_'
                || b == b'.'
                || b == b'$'
                || (i > 0 && b.is_ascii_digit())
        })
}
fn symbol_name(symbol: &UnitSymbol, prefix: &str) -> std::result::Result<String, String> {
    match &symbol.name {
        SymbolName::Named { value } if identifier(value) => Ok(value.clone()),
        SymbolName::NumericLocal {
            number,
            definition_record,
        } if symbol.binding == SymbolBinding::Local => Ok(format!(
            "{prefix}_source_{definition_record}_number_{number}_symbol_{}",
            symbol.id
        )),
        _ => Err("symbol requires an explicit lossless assembler-name realization".into()),
    }
}
fn section_name(section: &UnitSection) -> std::result::Result<String, String> {
    if !identifier(&section.name) || section.flags.iter().any(|b| !b"awx".contains(b)) {
        return Err("section name/flags need a richer assembler directive contract".into());
    }
    let flags =
        String::from_utf8(section.flags.clone()).map_err(|_| "section flags are not ASCII")?;
    Ok(format!(
        ".section {},\"{}\",@{}",
        section.name,
        flags,
        match section.kind {
            SectionKind::ProgramBits => "progbits",
            SectionKind::NoBits => "nobits",
            SectionKind::Note => "note",
        }
    ))
}
fn size_expression(
    size: &SymbolSize,
    names: &BTreeMap<SymbolId, String>,
) -> std::result::Result<Option<String>, String> {
    fn anchor(
        value: &SizeAnchor,
        names: &BTreeMap<SymbolId, String>,
    ) -> std::result::Result<String, String> {
        match value {
            SizeAnchor::Symbol { symbol } => names
                .get(symbol)
                .cloned()
                .ok_or_else(|| "size symbol absent".into()),
            SizeAnchor::CurrentLocation { .. } => {
                Err("source current-location size needs selected-layout record rebinding".into())
            }
        }
    }
    match size {
        SymbolSize::Unspecified => Ok(None),
        SymbolSize::Bytes { bytes } => Ok(Some(bytes.to_string())),
        SymbolSize::Difference { end, start, addend } => Ok(Some(format!(
            "({}-{}){:+}",
            anchor(end, names)?,
            anchor(start, names)?,
            addend
        ))),
    }
}
/// This API consumes the complete configured unit and independently selected
/// inventory bytes. It never opens old source paths or invokes an assembler.
/// The returned plan is not an AdmittedCapture and is not a complete artifact.
pub fn plan_unit(
    unit: &MachineUnit,
    selection: &UnitSelection,
    inventory_json: &[u8],
    configured_assembly: &[u8],
    target: Target,
) -> std::result::Result<MachineAssemblyPlan, UnitEmissionFailure> {
    let mut failure = UnitEmissionFailure {
        structural_failure: None,
        records: Vec::new(),
        unit_refusals: Vec::new(),
        body_refusals: BTreeMap::new(),
    };
    if let Err(e) = verify_unit(unit, selection, inventory_json, configured_assembly, target) {
        failure.structural_failure = Some(format!("{e:?}"));
        failure.records = unit
            .declarations
            .records
            .iter()
            .map(|record| RecordDisposition {
                record: record.id,
                selected: false,
                refusals: vec![
                    "whole-unit structural verification failed; record not selected".into(),
                ],
            })
            .collect();
        return Err(failure);
    }
    if unit.profile.architecture != Architecture::Rv64 {
        failure
            .unit_refusals
            .push("native unit selector currently realizes only explicit RV64 LP64/LP64D".into());
    }
    let sections: BTreeMap<_, _> = unit
        .declarations
        .sections
        .iter()
        .map(|s| (s.id, s))
        .collect();
    let symbols: BTreeMap<_, _> = unit
        .declarations
        .symbols
        .iter()
        .map(|s| (s.id, s))
        .collect();
    let initializers: BTreeMap<_, _> = unit
        .declarations
        .initializers
        .iter()
        .map(|s| (s.id, s))
        .collect();
    let alignments: BTreeMap<_, _> = unit
        .declarations
        .alignments
        .iter()
        .map(|s| (s.id, s))
        .collect();
    let mut prefix = String::from(".L__ocore_machine");
    while unit
        .declarations
        .symbols
        .iter()
        .any(|s| matches!(&s.name,SymbolName::Named{value}if value.starts_with(&prefix)))
    {
        prefix.push('_');
    }
    let mut names = BTreeMap::new();
    for s in &unit.declarations.symbols {
        match symbol_name(s, &prefix) {
            Ok(name) => {
                names.insert(s.id, name);
            }
            Err(e) => failure.unit_refusals.push(format!("symbol {}: {e}", s.id)),
        }
        if s.kind == SymbolKind::TlsObject {
            failure
                .unit_refusals
                .push(format!("symbol {} requires TLS realization", s.id));
        }
    }
    let mut output_names = BTreeMap::<String, SymbolId>::new();
    for (&id, name) in &names {
        if let Some(previous) = output_names.insert(name.clone(), id) {
            failure.unit_refusals.push(format!(
                "final assembler symbol name collision between {previous} and {id}: {name}"
            ));
        }
    }
    for s in &unit.declarations.sections {
        if let Err(e) = section_name(s) {
            failure.unit_refusals.push(format!("section {}: {e}", s.id));
        }
    }
    for s in &unit.declarations.symbols {
        if let Err(e) = size_expression(&s.size, &names) {
            failure.unit_refusals.push(format!("symbol {}: {e}", s.id));
        }
    }
    let mut bodies = BTreeMap::new();
    for body in &unit.bodies {
        let result = (|| {
            let inv: SelectedInstructionInventory =
                serde_json::from_slice(&body.selected_inventory_json)
                    .map_err(|e| format!("body inventory: {e}"))?;
            native_machine_emit_rv64::select_body(
                &body.contract,
                &inv,
                target,
                &format!("{prefix}_body_{}", body.id),
            )
        })();
        match result {
            Ok(plan) => {
                bodies.insert(body.id, plan);
            }
            Err(e) => {
                failure.body_refusals.insert(body.id, e);
            }
        }
    }
    // Entry placement requires executable program storage and RV64GC IALIGN=16.
    for symbol in &unit.declarations.symbols {
        if let SymbolDefinition::Body { section, body } = &symbol.definition {
            let reason=match sections.get(section){Some(s)if s.kind==SectionKind::ProgramBits&&s.flags.contains(&b'x')&&s.alignment>=2&&s.alignment.is_power_of_two()=>None,_=>Some("body requires executable ProgramBits with section alignment satisfying RV IALIGN=16")};
            if let Some(reason) = reason {
                failure
                    .body_refusals
                    .entry(*body)
                    .and_modify(|old| {
                        old.push_str("; ");
                        old.push_str(reason);
                    })
                    .or_insert_with(|| reason.into());
            }
        }
    }
    // Every record receives a disposition even when another body/record fails.
    for record in &unit.declarations.records {
        let mut refused = Vec::new();
        if matches!(record.kind, UnitRecordKind::Cfi | UnitRecordKind::Debug) {
            refused.push("CFI/debug directive realization is not implemented".into());
        }
        for effect in &record.effects {
            match effect {
                RecordEffect::File { .. } | RecordEffect::Location { .. } => {
                    refused.push("debug origin directive needs native encoding".into())
                }
                RecordEffect::Unrepresented { feature, reason } => {
                    refused.push(format!("unrepresented {feature}: {reason}"))
                }
                RecordEffect::Relocate { .. } => {
                    refused.push("relocation encoding/link semantics are not implemented".into())
                }
                RecordEffect::Initialize { initializer } => {
                    if let Some(value) = initializers.get(initializer) {
                        if matches!(value.value, InitializerValue::Relocation { .. }) {
                            refused.push("relocation initializer is not implemented".into());
                        }
                    }
                }
                RecordEffect::BodyItem { body } => {
                    if let Some(e) = failure.body_refusals.get(body) {
                        refused.push(format!("body {body}: {e}"));
                    }
                }
                RecordEffect::DefineSymbol { symbol } => {
                    if let Some(s) = symbols.get(symbol) {
                        if let SymbolDefinition::Body { body, .. } = &s.definition {
                            if let Some(e) = failure.body_refusals.get(body) {
                                refused.push(format!("body {body}: {e}"));
                            }
                        }
                    }
                }
                RecordEffect::SymbolSize { size, .. } => {
                    if let Err(e) = size_expression(size, &names) {
                        refused.push(e);
                    }
                }
                _ => {}
            }
        }
        failure.records.push(RecordDisposition {
            record: record.id,
            selected: refused.is_empty(),
            refusals: refused,
        });
    }
    if !unit.declarations.relocations.is_empty() {
        failure
            .unit_refusals
            .push("all declared relocations require a native encoding realization".into());
    }
    // Whole-body placement is supported only when no interior source layout
    // record is being moved across it. This is a layout condition, not a size cap.
    let required: SelectedUnitInventory = match serde_json::from_slice(inventory_json) {
        Ok(v) => v,
        Err(e) => {
            failure.unit_refusals.push(e.to_string());
            return Err(failure);
        }
    };
    let positions: BTreeMap<_, _> = unit
        .declarations
        .records
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id, i))
        .collect();
    for body in &required.bodies {
        let span: Vec<_> = body
            .record_ids
            .iter()
            .filter_map(|id| positions.get(id).copied())
            .collect();
        if let (Some(lo), Some(hi)) = (span.iter().min(), span.iter().max()) {
            for r in &unit.declarations.records[*lo..=*hi] {
                for effect in &r.effects {
                    let moves_layout = match effect {
                        RecordEffect::SelectSection { .. }
                        | RecordEffect::Initialize { .. }
                        | RecordEffect::Alignment { .. }
                        | RecordEffect::Relocate { .. } => true,
                        RecordEffect::DefineSymbol { symbol } => {
                            !matches!(symbols.get(symbol).map(|s|&s.definition),Some(SymbolDefinition::Body{body:b,..})if *b==body.id)
                        }
                        RecordEffect::BodyItem { body: b } => *b != body.id,
                        _ => false,
                    };
                    if moves_layout {
                        failure.unit_refusals.push(format!("body {} interior record {} needs record-position native layout realization",body.id,r.id));
                    }
                }
            }
        }
    }
    if failure.structural_failure.is_some()
        || !failure.unit_refusals.is_empty()
        || !failure.body_refusals.is_empty()
        || failure.records.iter().any(|r| !r.selected)
    {
        return Err(failure);
    }
    let mut text = String::from(
        "# statically selected complete typed machine unit; source/admission unqualified\n",
    );
    let mut current = None;
    let mut offsets: BTreeMap<SectionId, u64> = sections.keys().map(|id| (*id, 0)).collect();
    let mut opened = BTreeSet::new();
    let mut emitted = BTreeSet::new();
    let mut rendering_record = None;
    let mut rendering_body = None;
    let render = (|| -> std::result::Result<(), String> {
        for record in &unit.declarations.records {
            rendering_record = Some(record.id);
            for effect in &record.effects {
                match effect {
                    RecordEffect::SelectSection { section } => {
                        let s = sections.get(section).ok_or("section absent")?;
                        text.push_str(&section_name(s)?);
                        text.push('\n');
                        if opened.insert(*section) {
                            text.push_str(&format!(".balign {}\n", s.alignment));
                        }
                        current = Some(*section);
                    }
                    RecordEffect::DefineSymbol { symbol } => {
                        let s = symbols.get(symbol).ok_or("symbol absent")?;
                        let section = current.ok_or("symbol has no selected section")?;
                        match &s.definition {
                            SymbolDefinition::Body {
                                section: expected,
                                body,
                            } => {
                                rendering_body = Some(*body);
                                if section != *expected {
                                    return Err("body section differs".into());
                                }
                                if !offsets[&section].is_multiple_of(2) {
                                    return Err(
                                        "body current byte offset violates RV IALIGN=16".into()
                                    );
                                }
                                if !emitted.insert(*body) {
                                    return Err("body would be emitted twice".into());
                                }
                                let b = bodies.get(body).ok_or("selected body absent")?;
                                text.push_str(&format!("{}:\n", names[symbol]));
                                text.push_str(&b.assembly());
                                *offsets.get_mut(&section).ok_or("section extent absent")? =
                                    offsets[&section]
                                        .checked_add(b.byte_size())
                                        .ok_or("section extent overflow")?;
                                rendering_body = None;
                            }
                            SymbolDefinition::InSection {
                                section: expected,
                                offset,
                            } => {
                                if section != *expected || offsets[&section] != *offset {
                                    return Err(format!("symbol {symbol} source offset lacks selected-layout correspondence"));
                                }
                                text.push_str(&format!("{}:\n", names[symbol]));
                            }
                            _ => {
                                return Err(
                                    "definition record requires an actual body/section symbol"
                                        .into(),
                                )
                            }
                        }
                    }
                    RecordEffect::Binding { symbol, binding } => {
                        let directive = match binding {
                            SymbolBinding::Global => Some(".globl"),
                            SymbolBinding::Weak => Some(".weak"),
                            SymbolBinding::Local => Some(".local"),
                        };
                        if let Some(d) = directive {
                            text.push_str(&format!("{d} {}\n", names[symbol]));
                        }
                    }
                    RecordEffect::Visibility { symbol, visibility } => {
                        if *visibility != SymbolVisibility::Default {
                            text.push_str(&format!(
                                "{} {}\n",
                                if *visibility == SymbolVisibility::Hidden {
                                    ".hidden"
                                } else {
                                    ".protected"
                                },
                                names[symbol]
                            ));
                        }
                    }
                    RecordEffect::SymbolType { symbol, kind } => text.push_str(&format!(
                        ".type {}, @{}\n",
                        names[symbol],
                        match kind {
                            SymbolKind::Function => "function",
                            SymbolKind::Object => "object",
                            SymbolKind::NoType => "notype",
                            SymbolKind::TlsObject => return Err("TLS is not selected".into()),
                        }
                    )),
                    RecordEffect::SymbolSize { symbol, size } => {
                        if let Some(e) = size_expression(size, &names)? {
                            text.push_str(&format!(".size {}, {e}\n", names[symbol]));
                        }
                    }
                    RecordEffect::Alias {
                        symbol,
                        target,
                        addend,
                        equ,
                    } => text.push_str(&format!(
                        "{} {}, {}{:+}\n",
                        if *equ { ".equ" } else { ".set" },
                        names[symbol],
                        names[target],
                        addend
                    )),
                    RecordEffect::Initialize { initializer } => {
                        let init = initializers.get(initializer).ok_or("initializer absent")?;
                        let section = current.ok_or("initializer has no section")?;
                        if section != init.section || offsets[&section] != init.offset {
                            return Err(
                                "initializer offset lacks selected-layout correspondence".into()
                            );
                        }
                        let bytes = match &init.value {
                            InitializerValue::Bytes { value } => {
                                for chunk in value.chunks(32) {
                                    text.push_str(".byte ");
                                    text.push_str(
                                        &chunk
                                            .iter()
                                            .map(u8::to_string)
                                            .collect::<Vec<_>>()
                                            .join(","),
                                    );
                                    text.push('\n');
                                }
                                value.len() as u64
                            }
                            InitializerValue::RepeatByte { byte, count } => {
                                text.push_str(&format!(".fill {count}, 1, {byte}\n"));
                                *count
                            }
                            InitializerValue::ZeroFill { bytes } => {
                                text.push_str(&format!(".zero {bytes}\n"));
                                *bytes
                            }
                            InitializerValue::Relocation { .. } => {
                                return Err("relocation initializer is not selected".into())
                            }
                        };
                        *offsets.get_mut(&section).ok_or("section absent")? = offsets[&section]
                            .checked_add(bytes)
                            .ok_or("data extent overflow")?;
                    }
                    RecordEffect::Alignment { alignment } => {
                        let a = alignments.get(alignment).ok_or("alignment absent")?;
                        let section = current.ok_or("alignment has no section")?;
                        if section != a.section {
                            return Err("alignment section differs".into());
                        }
                        let before = offsets[&section];
                        let required = (a.boundary - before % a.boundary) % a.boundary;
                        let pad = if a.maximum_skip.is_some_and(|limit| required > limit) {
                            0
                        } else {
                            required
                        };
                        match &a.layout {
                            Some(AlignmentLayout::Applied { offset, padding })
                                if *offset == before && *padding == pad => {}
                            Some(AlignmentLayout::Skipped {
                                offset,
                                required_padding,
                            }) if *offset == before
                                && *required_padding == required
                                && pad == 0 => {}
                            _ => return Err("alignment layout is unresolved or differs".into()),
                        };
                        if pad > 0 && a.fill.is_none() && sections[&section].flags.contains(&b'x') {
                            return Err("executable default alignment padding needs an explicit NOP realization".into());
                        }
                        text.push_str(&format!(
                            ".balign {}, {}{}\n",
                            a.boundary,
                            a.fill.unwrap_or(0),
                            a.maximum_skip.map(|n| format!(", {n}")).unwrap_or_default()
                        ));
                        *offsets.get_mut(&section).ok_or("section absent")? =
                            before.checked_add(pad).ok_or("alignment extent overflow")?;
                    }
                    RecordEffect::BodyItem { .. } | RecordEffect::PreprocessorMarker { .. } => {}
                    RecordEffect::File { .. } | RecordEffect::Location { .. } => {
                        return Err("debug origin directive needs native encoding".into())
                    }
                    RecordEffect::Relocate { .. } | RecordEffect::Unrepresented { .. } => {
                        return Err("unselected record reached renderer".into())
                    }
                }
            }
        }
        rendering_record = None;
        for (id, section) in &sections {
            if let Some(size) = section.byte_size {
                if offsets[id] != size {
                    return Err(format!(
                        "section {id} byte extent differs from selected layout"
                    ));
                }
            }
        }
        if emitted.len() != unit.bodies.len() {
            return Err("not every required body was emitted".into());
        }
        Ok(())
    })();
    if let Err(reason) = render {
        if let Some(body) = rendering_body {
            failure
                .body_refusals
                .entry(body)
                .and_modify(|old| {
                    old.push_str("; ");
                    old.push_str(&reason);
                })
                .or_insert_with(|| reason.clone());
            for (record, row) in unit
                .declarations
                .records
                .iter()
                .zip(failure.records.iter_mut())
            {
                let owns=record.effects.iter().any(|effect|match effect{RecordEffect::BodyItem{body:id}=>*id==body,RecordEffect::DefineSymbol{symbol}=>matches!(symbols.get(symbol).map(|s|&s.definition),Some(SymbolDefinition::Body{body:id,..})if *id==body),_=>false});
                if owns {
                    row.selected = false;
                    row.refusals.push(format!("body {body}: {reason}"));
                }
            }
        }
        if let Some(id) = rendering_record {
            if let Some(row) = failure.records.iter_mut().find(|row| row.record == id) {
                row.selected = false;
                row.refusals.push(reason.clone());
            }
        }
        failure.unit_refusals.push(reason);
        return Err(failure);
    }
    let typed_unit = match typed_unit_identity(unit) {
        Ok(value) => value,
        Err(reason) => {
            failure.unit_refusals.push(reason.clone());
            for row in &mut failure.records {
                row.selected = false;
                row.refusals.push(reason.clone());
            }
            return Err(failure);
        }
    };
    let assembly_identity = identity(text.as_bytes());
    Ok(MachineAssemblyPlan {
        assembly: text,
        source_unit_id: unit.source.unit_id.clone(),
        inventory: identity(inventory_json),
        configured_assembly: identity(configured_assembly),
        assembly_identity,
        selected_bodies: unit.bodies.len(),
        selected_records: unit.declarations.records.len(),
        abi: if unit.profile.abi == MachineAbi::RiscvLp64d {
            "lp64d"
        } else {
            "lp64"
        },
        target,
        typed_unit,
    })
}
#[cfg(test)]
#[path = "native_machine_emit_tests.rs"]
mod tests;
