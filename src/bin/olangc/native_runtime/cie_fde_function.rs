//! Same-consumed ELF function/FDE association, not source or producer admission.
//!
//! This deliberately narrow profile interprets RV64 RELA PC-relative starts and
//! an unrelocated signed-four-byte range or zero-raw ADD32/SUB32 difference. It
//! never treats an unresolved zero field as an address. Final linked addresses,
//! CFI execution, source production, providers and unwind registration stay open.
use super::{
    checked_elf_sections, field, inspect_with_sections, section_data, EncodedPointer,
    EncodedValue, RawCieObject, RawFde, RawFrameSection, RawRecord, RawRelocation, Section,
};
use anyhow::{bail, Context, Result};
use o_lang::ocore::native_machine_ir::ArtifactIdentity;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct SymbolKey {
    pub symbol_table: usize,
    pub symbol_index: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct FdeKey {
    pub frame_section_index: usize,
    pub fde_section_offset: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct FunctionExtent {
    pub section_index: usize,
    pub start: u64,
    pub size: u64,
}
/// Shared complete relation membership, stored once even for ambiguous extents.
#[derive(Debug, Serialize)]
pub(crate) struct ExtentGroup {
    pub extent: FunctionExtent,
    pub functions: Vec<SymbolKey>,
    pub fdes: Vec<FdeKey>,
}
#[derive(Debug, Serialize)]
pub(crate) struct SymbolRow {
    pub key: SymbolKey,
    pub raw: Vec<u8>,
    pub name_offset: u32,
    pub name_bytes: Option<Vec<u8>>,
    pub kind: u8,
    pub binding: u8,
    pub other: u8,
    pub section_index: u16,
    pub value: u64,
    pub size: u64,
    pub error: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct SymbolTable {
    pub section_index: usize,
    pub header_bytes: Vec<u8>,
    pub raw_bytes: Vec<u8>,
    pub string_section_index: usize,
    pub string_bytes: Option<Vec<u8>>,
    pub symbols: Vec<SymbolRow>,
    pub error: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct FunctionAssociation {
    pub symbol: SymbolKey,
    pub extent: Option<FunctionExtent>,
    pub extent_group: Option<usize>,
    /// External declarations are retained, never invented local bodies.
    pub disposition: &'static str,
    pub error: Option<String>,
}
#[derive(Debug, Serialize)]
pub(crate) struct FdeAssociation {
    pub fde: FdeKey,
    pub extent: Option<FunctionExtent>,
    pub extent_group: Option<usize>,
    pub function: Option<SymbolKey>,
    /// Indices into the retained raw frame section's relocation array.
    pub relocation_rows: Vec<usize>,
    pub error: Option<String>,
}

/// Immutable, constructor-owned facts. Serialization is diagnostic only; no
/// deserializer, mutable getter, admitted-capture constructor or authority flag.
#[derive(Debug, Serialize)]
pub(crate) struct CheckedObjectFunctions {
    schema: &'static str,
    raw_object: RawCieObject,
    symbol_tables: Vec<SymbolTable>,
    functions: Vec<FunctionAssociation>,
    extent_groups: Vec<ExtentGroup>,
    fdes: Vec<FdeAssociation>,
    all_defined_functions_matched: bool,
    source_function_identity_verified: bool,
    final_linked_addresses_verified: bool,
    #[serde(skip)]
    function_index: BTreeMap<SymbolKey, usize>,
    #[serde(skip)]
    fde_index: BTreeMap<FdeKey, usize>,
    #[serde(skip)]
    symbol_error: Option<String>,
    #[serde(skip)]
    initial_rules_error: Option<String>,
    #[serde(skip)]
    complete_error: Option<String>,
}
impl CheckedObjectFunctions {
    pub(crate) fn raw_object(&self) -> &RawCieObject { &self.raw_object }
    pub(crate) fn symbol_tables(&self) -> &[SymbolTable] { &self.symbol_tables }
    pub(crate) fn functions(&self) -> &[FunctionAssociation] { &self.functions }
    pub(crate) fn extent_groups(&self) -> &[ExtentGroup] { &self.extent_groups }
    pub(crate) fn fdes(&self) -> &[FdeAssociation] { &self.fdes }
    pub(crate) fn require_initial_rules_decoded(&self) -> Result<()> {
        if let Some(error) = &self.initial_rules_error { bail!("{error}"); }
        Ok(())
    }
    /// Complete only for this symbolic association profile; providers and native
    /// execution are not implied. An external STT_FUNC declaration needs providers.
    pub(crate) fn require_all_defined_functions_matched(&self) -> Result<()> {
        if let Some(error) = &self.complete_error { bail!("{error}"); }
        Ok(())
    }
    /// `expected` and `symbol` must be held independently before fresh evidence.
    /// Comparing them establishes consistency, never authenticity of that choice.
    pub(crate) fn selected_fde(&self, expected: &ArtifactIdentity, symbol: SymbolKey) -> Result<FdeKey> {
        if expected.bytes != u64::try_from(self.raw_object.object_bytes).context("original object size exceeds identity representation")? || expected.sha256 != self.raw_object.object_sha256 {
            bail!("independently held original object pin differs");
        }
        if let Some(error) = &self.symbol_error { bail!("original symbol inventory incomplete: {error}"); }
        let index = *self.function_index.get(&symbol).context("selected STT_FUNC symbol absent")?;
        let function = self.functions.get(index).context("checked function index absent")?;
        if let Some(error) = &function.error { bail!("selected original function unresolved: {error}"); }
        if function.disposition != "associated" {
            bail!("selected symbol is not a uniquely associated defined function");
        }
        let group = self.extent_groups.get(function.extent_group.context("selected function extent group absent")?)
            .context("checked extent group absent")?;
        if Some(group.extent) != function.extent || group.functions.len() != 1
            || group.functions.first().copied() != Some(symbol) || group.fdes.len() != 1 {
            bail!("selected symbol is not a uniquely associated defined function");
        }
        let key = *group.fdes.first().context("selected function FDE absent")?;
        let fde = self.fdes.get(*self.fde_index.get(&key).context("checked FDE index absent")?)
            .context("checked FDE row absent")?;
        if fde.error.is_some() || fde.function != Some(symbol) {
            bail!("selected original function/FDE association differs");
        }
        Ok(key)
    }
}

fn symbol_tables(bytes: &[u8], sections: &[Section]) -> Result<Vec<SymbolTable>> {
    let headers = usize::try_from(u64::from_le_bytes(field(bytes, 40)?))?;
    let mut tables = Vec::new();
    for (index, section) in sections.iter().enumerate().filter(|(_, s)| matches!(s.kind, 2 | 11)) {
        let at = headers.checked_add(index.checked_mul(64).context("symbol header index overflow")?)
            .context("symbol header offset overflow")?;
        let end = at.checked_add(64).context("symbol header extent overflow")?;
        let mut table = SymbolTable {
            section_index: index,
            header_bytes: bytes.get(at..end).context("symbol header outside object")?.to_vec(),
            raw_bytes: section_data(bytes, section)?.to_vec(),
            string_section_index: section.link,
            string_bytes: None,
            symbols: Vec::new(),
            error: None,
        };
        let decoded = (|| -> Result<()> {
            if section.stride != 24 || section.size % 24 != 0 {
                bail!("ELF64 symbol-table stride/extent differs");
            }
            let strings = sections.get(section.link).filter(|s| s.kind == 3)
                .context("symbol table requires its actual string table")?;
            table.string_bytes = Some(section_data(bytes, strings)?.to_vec());
            let names = table.string_bytes.as_deref().context("symbol strings absent")?;
            for (symbol_index, raw) in table.raw_bytes.chunks_exact(24).enumerate() {
                let mut row = SymbolRow {
                    key: SymbolKey { symbol_table: index, symbol_index: u32::try_from(symbol_index)? },
                    raw: raw.to_vec(), name_offset: u32::from_le_bytes(raw[..4].try_into()?),
                    name_bytes: None, kind: raw[4] & 15, binding: raw[4] >> 4, other: raw[5],
                    section_index: u16::from_le_bytes(raw[6..8].try_into()?),
                    value: u64::from_le_bytes(raw[8..16].try_into()?),
                    size: u64::from_le_bytes(raw[16..24].try_into()?), error: None,
                };
                let name = (|| -> Result<Vec<u8>> {
                    let tail = names.get(usize::try_from(row.name_offset)?..)
                        .context("symbol name outside retained strings")?;
                    let end = tail.iter().position(|b| *b == 0).context("unterminated symbol name")?;
                    Ok(tail[..end].to_vec())
                })();
                match name { Ok(name) => row.name_bytes = Some(name), Err(error) => row.error = Some(format!("{error:#}")) }
                table.symbols.push(row);
            }
            Ok(())
        })();
        if let Err(error) = decoded { table.error = Some(format!("{error:#}")); }
        tables.push(table);
    }
    Ok(tables)
}
fn code_section(sections: &[Section], index: u16) -> Result<&Section> {
    if index == 0 || index >= 0xff00 { bail!("symbol has no ordinary defined code section"); }
    sections.get(usize::from(index))
        .filter(|s| s.kind == 1 && s.flags & 4 != 0 && s.flags & 0x800 == 0)
        .context("symbol section is not uncompressed executable PROGBITS")
}
fn function_extent(row: &SymbolRow, sections: &[Section]) -> Result<FunctionExtent> {
    if let Some(error) = &row.error { bail!("{error}"); }
    let section = code_section(sections, row.section_index)?;
    if row.size == 0 { bail!("STT_FUNC size is zero; no extent inferred from neighbors"); }
    let end = row.value.checked_add(row.size).context("STT_FUNC range overflow")?;
    if end > section.size { bail!("STT_FUNC range outside its code section"); }
    Ok(FunctionExtent { section_index: usize::from(row.section_index), start: row.value, size: row.size })
}
fn symbol_location(relocation: &RawRelocation, symbols: &BTreeMap<SymbolKey, &SymbolRow>, sections: &[Section]) -> Result<(usize, u64)> {
    let addend = relocation.addend.context("FDE association requires explicit-addend RELA")?;
    let key = SymbolKey { symbol_table: relocation.symbol_table, symbol_index: relocation.symbol_index };
    let row = symbols.get(&key).context("FDE relocation symbol absent from complete inventory")?;
    if row.raw != relocation.symbol_raw { bail!("FDE relocation symbol bytes differ from same-object row"); }
    if let Some(error) = &row.error { bail!("FDE relocation symbol invalid: {error}"); }
    if !matches!(row.kind, 0 | 2 | 3) { bail!("unsupported FDE code-reference symbol type"); }
    let section = code_section(sections, row.section_index)?;
    // Same equation as exception_inventory::relocated_location: S + A, in an
    // actual object section. This is not the final linked PC-relative value.
    let offset = u64::try_from(i128::from(row.value) + i128::from(addend))?;
    if row.value > section.size || offset > section.size { bail!("FDE relocation symbol/addend escapes code section"); }
    Ok((usize::from(row.section_index), offset))
}
fn field_relocations<'a>(frame: &'a RawFrameSection, pointer: &EncodedPointer) -> Result<Vec<(usize, &'a RawRelocation)>> {
    let start = u64::try_from(pointer.range.section_offset)?;
    let end = start.checked_add(u64::try_from(pointer.range.bytes.len())?).context("FDE field extent overflow")?;
    let mut result = Vec::new();
    for (index, relocation) in frame.relocations.iter().enumerate() {
        // Only widths actually implemented by this RV64 profile. Unknown fixups
        // before the field end are conservatively unresolved, never harmless.
        let width = match relocation.kind { 2 => Some(8u64), 35 | 39 | 57 => Some(4u64), _ => None };
        let relocation_end = width.and_then(|width| relocation.offset.checked_add(width));
        if relocation.offset < end && relocation_end.is_none_or(|limit| limit > start) {
            if relocation.offset != start || width != Some(end - start) {
                bail!("unsupported or overlapping relocation on FDE address field");
            }
            result.push((index, relocation));
        }
    }
    Ok(result)
}
fn fde_extent(machine: u16, frame: &RawFrameSection, fde: &RawFde,
    symbols: &BTreeMap<SymbolKey, &SymbolRow>, sections: &[Section]) -> Result<(FunctionExtent, Vec<usize>)> {
    if let Some(error) = &fde.error { bail!("raw FDE incomplete: {error}"); }
    if machine != 243 { bail!("symbolic FDE/function association is unsupported for this ELF machine"); }
    let pc = fde.initial_location.as_ref().context("FDE initial location absent")?;
    if pc.encoding != 0x1b || pc.indirect || pc.application != 0x10 || pc.range.bytes.len() != 4 {
        bail!("RV64 FDE start requires direct pcrel sdata4 encoding");
    }
    let pc_relocations = field_relocations(frame, pc)?;
    if pc_relocations.len() != 1 || pc_relocations[0].1.kind != 57 {
        bail!("RV64 FDE start requires exactly one checked kind57 PC-relative relocation");
    }
    let (section, start) = symbol_location(pc_relocations[0].1, symbols, sections)?;
    let range = fde.address_range.as_ref().context("FDE address range absent")?;
    if range.encoding != 0x0b || range.indirect || range.application != 0 || range.range.bytes.len() != 4 {
        bail!("RV64 FDE range requires direct sdata4 encoding");
    }
    let range_relocations = field_relocations(frame, range)?;
    let size = if range_relocations.is_empty() {
        match range.value {
            EncodedValue::Signed(value) => u64::try_from(value)?,
            _ => bail!("FDE range encoding/value differs"),
        }
    } else {
        if range_relocations.len() != 2 || range_relocations[0].1.kind != 35 || range_relocations[1].1.kind != 39
            || range_relocations[0].0.checked_add(1) != Some(range_relocations[1].0)
            || range_relocations[0].1.relocation_section != range_relocations[1].1.relocation_section {
            bail!("FDE range relocation must be an adjacent ordered ADD32/SUB32 pair");
        }
        // Narrow exact counterpart of exception_inventory::owned_difference.
        // Nonzero initial fields require another explicitly implemented formula.
        if range.range.bytes.iter().any(|b| *b != 0) {
            bail!("nonzero raw ADD32/SUB32 FDE range is unsupported");
        }
        let (positive_section, positive) = symbol_location(range_relocations[0].1, symbols, sections)?;
        let (negative_section, negative) = symbol_location(range_relocations[1].1, symbols, sections)?;
        if positive_section != section || negative_section != section || negative != start || positive < start {
            bail!("FDE difference does not span the checked start in one code section");
        }
        positive.checked_sub(negative).context("FDE difference underflow")?
    };
    if size == 0 { bail!("FDE range is zero; unresolved fields do not establish an extent"); }
    if size > i32::MAX as u64 { bail!("FDE range exceeds positive sdata4 profile"); }
    let end = start.checked_add(size).context("FDE code range overflow")?;
    if end > sections.get(section).context("FDE code section absent")?.size { bail!("FDE range outside code section"); }
    let rows = pc_relocations.iter().chain(range_relocations.iter()).map(|(i, _)| *i).collect();
    Ok((FunctionExtent { section_index: section, start, size }, rows))
}

/// All rows/outcomes are retained, including external declarations, aliases,
/// partial overlaps, missing FDEs and unsupported fixups. No first-match selector.
pub(crate) fn inspect_elf64_le_rel(bytes: &[u8]) -> Result<CheckedObjectFunctions> {
    let (machine, sections) = checked_elf_sections(bytes)?;
    let raw_object = inspect_with_sections(bytes, machine, &sections)?;
    let symbol_tables = symbol_tables(bytes, &sections)?;
    let mut symbols = BTreeMap::new();
    let mut symbol_error = if symbol_tables.is_empty() { Some("no ELF symbol tables".into()) } else { None };
    for table in &symbol_tables {
        if symbol_error.is_none() { symbol_error = table.error.clone(); }
        for row in &table.symbols {
            if symbol_error.is_none() { symbol_error = row.error.clone(); }
            if symbols.insert(row.key, row).is_some() { bail!("duplicate checked symbol-table/index key"); }
        }
    }
    let mut functions = Vec::new();
    let mut function_index = BTreeMap::new();
    for row in symbols.values().filter(|row| row.kind == 2) {
        let mut function = FunctionAssociation { symbol: row.key, extent: None, extent_group: None, disposition: "unmet", error: None };
        if row.section_index == 0 {
            function.disposition = "external_declaration";
            function.error = row.error.clone();
        } else {
            match function_extent(row, &sections) {
                Ok(extent) => function.extent = Some(extent),
                Err(error) => function.error = Some(format!("{error:#}")),
            }
        }
        if function_index.insert(row.key, functions.len()).is_some() { bail!("duplicate checked function key"); }
        functions.push(function);
    }
    // Sorted sweep marks every overlapping/aliased extent, without quadratic
    // pair scans. All rows remain available for the diagnostic candidate list.
    let mut intervals: BTreeMap<usize, Vec<(u64, u64, usize)>> = BTreeMap::new();
    for (index, function) in functions.iter().enumerate() {
        if let Some(extent) = function.extent {
            intervals.entry(extent.section_index).or_default().push((extent.start, extent.start + extent.size, index));
        }
    }
    for rows in intervals.values_mut() {
        rows.sort_unstable();
        let mut maximum: Option<(u64, usize)> = None;
        for &(start, end, index) in rows.iter() {
            if let Some((previous_end, previous_index)) = maximum {
                if start < previous_end {
                    functions[index].error = Some("overlapping or aliased STT_FUNC extent".into());
                    functions[previous_index].error = Some("overlapping or aliased STT_FUNC extent".into());
                }
            }
            if maximum.is_none_or(|(previous_end, _)| end > previous_end) { maximum = Some((end, index)); }
        }
    }
    let mut fdes = Vec::new();
    let mut fde_index = BTreeMap::new();
    for frame in &raw_object.sections {
        for record in &frame.records {
            let RawRecord::Fde(raw_fde) = record else { continue; };
            let key = FdeKey { frame_section_index: frame.index, fde_section_offset: raw_fde.range.section_offset };
            let mut fde = FdeAssociation { fde: key, extent: None, extent_group: None, function: None, relocation_rows: Vec::new(), error: None };
            match fde_extent(machine, frame, raw_fde, &symbols, &sections) {
                Ok((extent, rows)) => { fde.extent = Some(extent); fde.relocation_rows = rows; }
                Err(error) => fde.error = Some(format!("{error:#}")),
            }
            if fde_index.insert(key, fdes.len()).is_some() { bail!("duplicate checked FDE key"); }
            fdes.push(fde);
        }
    }
    // One shared group owns each full relation. N aliases and M duplicate FDEs
    // retain N+M memberships, never N*M copies in individual outcome records.
    let mut grouped: BTreeMap<FunctionExtent, (Vec<usize>, Vec<usize>)> = BTreeMap::new();
    for (index, function) in functions.iter().enumerate() {
        if let Some(extent) = function.extent { grouped.entry(extent).or_default().0.push(index); }
    }
    for (index, fde) in fdes.iter().enumerate() {
        if let Some(extent) = fde.extent { grouped.entry(extent).or_default().1.push(index); }
    }
    let mut extent_groups = Vec::new();
    for (extent, (function_rows, fde_rows)) in grouped {
        let group_index = extent_groups.len();
        let group = ExtentGroup {
            extent,
            functions: function_rows.iter().map(|index| functions[*index].symbol).collect(),
            fdes: fde_rows.iter().map(|index| fdes[*index].fde).collect(),
        };
        for &index in &function_rows {
            let function = &mut functions[index];
            function.extent_group = Some(group_index);
            if function.error.is_none() {
                if fde_rows.is_empty() { function.error = Some("defined function has no exact FDE extent".into()); }
                else if fde_rows.len() != 1 { function.error = Some("defined function has multiple exact FDEs".into()); }
                else { function.disposition = "associated"; }
            }
        }
        for &index in &fde_rows {
            let fde = &mut fdes[index];
            fde.extent_group = Some(group_index);
            if function_rows.len() != 1 { fde.error = Some("FDE has no unique exact STT_FUNC extent".into()); }
            else {
                let function = &functions[function_rows[0]];
                if let Some(error) = &function.error { fde.error = Some(format!("matching function unresolved: {error}")); }
                else { fde.function = Some(function.symbol); }
            }
        }
        extent_groups.push(group);
    }
    let initial_rules_error = raw_object.require_initial_rules_decoded().err().map(|e| format!("{e:#}"));
    let complete_error = symbol_error.clone()
        .or_else(|| initial_rules_error.clone())
        .or_else(|| if functions.iter().all(|f| f.extent.is_none()) { Some("no defined function extents".into()) } else { None })
        .or_else(|| functions.iter().find_map(|f| f.error.clone()))
        .or_else(|| if fdes.is_empty() { Some("no FDE outcomes".into()) } else { None })
        .or_else(|| fdes.iter().find_map(|f| f.error.clone()));
    Ok(CheckedObjectFunctions {
        schema: "ocore-original-elf-function-fde-association-v2", raw_object, symbol_tables, functions, fdes, extent_groups,
        all_defined_functions_matched: complete_error.is_none(), source_function_identity_verified: false,
        final_linked_addresses_verified: false, function_index, fde_index, symbol_error, initial_rules_error, complete_error,
    })
}

#[cfg(test)]
#[path = "cie_fde_function_tests.rs"]
mod tests;
