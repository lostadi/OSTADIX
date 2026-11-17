//! Checked raw .eh_frame facts from actual ELF64 LE ET_REL bytes.
//! This is not object admission, producer custody, FDE-PC verification or unwind execution.
use super::{section_data, section_names, Reader, Section};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RawSpan {
    pub section_offset: usize,
    pub object_offset: u64,
    pub bytes: Vec<u8>,
}
fn span(data: &[u8], section: &Section, start: usize, end: usize) -> Result<RawSpan> {
    let bytes = data
        .get(start..end)
        .context("raw CFI span outside section")?;
    Ok(RawSpan {
        section_offset: start,
        object_offset: section
            .offset
            .checked_add(u64::try_from(start)?)
            .context("raw CFI object offset overflow")?,
        bytes: bytes.to_vec(),
    })
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub(crate) enum RegisterRule {
    Undefined,
    SameValue,
    CfaOffset(i64),
    CfaValueOffset(i64),
    Register(u64),
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CfaRule {
    pub register: u64,
    pub offset: i64,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct InitialInstruction {
    pub program_offset: usize,
    pub raw: Vec<u8>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct InitialRules {
    pub machine: u16,
    pub cfa: Option<CfaRule>,
    /// Absence means unspecified. It never creates Undefined or SameValue.
    pub registers: BTreeMap<u64, RegisterRule>,
    pub instructions: Vec<InitialInstruction>,
}
impl InitialRules {
    pub(crate) fn require_cfa(&self) -> Result<&CfaRule> {
        self.cfa.as_ref().context("CIE initial CFA is unspecified")
    }
    /// Future FDE restore consumers must use this exact initial table.
    pub(crate) fn restore_rule(&self, register: u64) -> Result<RegisterRule> {
        register_domain(self.machine, register)?;
        self.registers
            .get(&register)
            .cloned()
            .context("CIE initial register rule is unspecified; restore cannot guess a default")
    }
}
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub(crate) enum EncodedValue {
    Unsigned(u64),
    Signed(i64),
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct EncodedPointer {
    pub encoding: u8,
    pub indirect: bool,
    pub application: u8,
    pub range: RawSpan,
    pub value: EncodedValue,
    pub resolved_address: Option<u64>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CieHeader {
    pub version: u8,
    pub augmentation: String,
    pub code_alignment: u64,
    pub data_alignment: i64,
    pub return_column: u64,
    /// CIE versions 1/3 inherit address width from the checked ELF64 class.
    pub address_size_from_elf_class: u8,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RawCie {
    pub range: RawSpan,
    pub header: Option<CieHeader>,
    pub augmentation_data: Option<RawSpan>,
    pub fde_encoding: Option<u8>,
    pub lsda_encoding: Option<u8>,
    pub personality: Option<EncodedPointer>,
    pub signal_frame: bool,
    pub initial_instructions: Option<RawSpan>,
    pub initial_rules: Option<InitialRules>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RawFde {
    pub range: RawSpan,
    pub cie_section_offset: Option<usize>,
    pub initial_location: Option<EncodedPointer>,
    pub address_range: Option<EncodedPointer>,
    pub augmentation_data: Option<RawSpan>,
    pub lsda: Option<EncodedPointer>,
    pub instructions: Option<RawSpan>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "record", content = "facts", rename_all = "snake_case")]
pub(crate) enum RawRecord {
    Cie(RawCie),
    Fde(RawFde),
    Rejected { range: RawSpan, error: String },
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RawRelocation {
    pub relocation_section: usize,
    pub target_section: usize,
    pub symbol_table: usize,
    pub symbol_index: u32,
    pub offset: u64,
    pub kind: u32,
    pub addend: Option<i64>,
    pub raw: Vec<u8>,
    pub symbol_raw: Vec<u8>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RawFrameSection {
    pub index: usize,
    pub file_offset: u64,
    pub header_bytes: Vec<u8>,
    pub flags: u64,
    pub alignment: u64,
    pub raw_bytes: Vec<u8>,
    pub records: Vec<RawRecord>,
    pub relocations: Vec<RawRelocation>,
    pub trailing_zero_terminator: Vec<u8>,
}
#[derive(Debug, Clone, Serialize)]
pub(crate) struct RawCieObject {
    pub schema: &'static str,
    pub object_bytes: usize,
    pub object_sha256: String,
    pub elf_header: Vec<u8>,
    pub machine: u16,
    pub elf_flags: u32,
    pub sections: Vec<RawFrameSection>,
    pub fde_pc_verified: bool,
    pub fde_rules_executed: bool,
    pub object_provenance_verified: bool,
    pub source_profile_admitted: bool,
    pub unwind_execution_verified: bool,
}
impl RawCieObject {
    /// Complete raw initial-rule decoding is not any of the separate authority gates above.
    pub(crate) fn require_initial_rules_decoded(&self) -> Result<()> {
        let mut cies = 0usize;
        let mut fdes = 0usize;
        for section in &self.sections {
            for record in &section.records {
                match record {
                    RawRecord::Cie(cie) => {
                        cies += 1;
                        if let Some(error) = &cie.error {
                            bail!("raw CIE rejected: {error}");
                        }
                        if cie.initial_rules.is_none() {
                            bail!("raw CIE initial rules absent");
                        }
                    }
                    RawRecord::Fde(fde) => {
                        fdes += 1;
                        if let Some(error) = &fde.error {
                            bail!("raw FDE geometry rejected: {error}");
                        }
                    }
                    RawRecord::Rejected { error, .. } => {
                        bail!("raw frame record rejected: {error}")
                    }
                }
            }
        }
        if cies == 0 || fdes == 0 {
            bail!("raw frame object lacks a nonempty CIE/FDE inventory");
        }
        Ok(())
    }
}
fn register_domain(machine: u16, register: u64) -> Result<()> {
    // Same explicit subset as configured-assembly cfi_register; no 32-bit target inference.
    let supported = match machine {
        62 => register <= 32,
        183 => register <= 31 || (64..=95).contains(&register),
        243 => register <= 63,
        _ => false,
    };
    if !supported {
        bail!("unsupported DWARF register {register} for ELF machine {machine}");
    }
    Ok(())
}
fn scaled_unsigned(value: u64, factor: i64) -> Result<i64> {
    i64::try_from(
        i128::from(value)
            .checked_mul(i128::from(factor))
            .context("CFI offset multiplication overflow")?,
    )
    .context("CFI signed offset exceeds i64")
}
fn scaled_signed(value: i64, factor: i64) -> Result<i64> {
    i64::try_from(
        i128::from(value)
            .checked_mul(i128::from(factor))
            .context("CFI offset multiplication overflow")?,
    )
    .context("CFI signed offset exceeds i64")
}
fn read_register(reader: &mut Reader<'_>, machine: u16) -> Result<u64> {
    let register = reader.uleb()?;
    register_domain(machine, register)?;
    Ok(register)
}
fn initial_program(program: &[u8], machine: u16, data_alignment: i64) -> Result<InitialRules> {
    let mut reader = Reader::new(program, 0, program.len())?;
    let mut rules = InitialRules {
        machine,
        cfa: None,
        registers: BTreeMap::new(),
        instructions: Vec::new(),
    };
    let mut remembered = Vec::new();
    while reader.cursor < reader.end {
        let start = reader.cursor;
        let opcode = reader.byte()?;
        match opcode {
            0x00 => {}
            0x80..=0xbf => {
                let register = u64::from(opcode & 63);
                register_domain(machine, register)?;
                let offset = scaled_unsigned(reader.uleb()?, data_alignment)?;
                rules
                    .registers
                    .insert(register, RegisterRule::CfaOffset(offset));
            }
            0xc0..=0xff => bail!("CIE initial restore has no independent initial-CIE rule context"),
            0x05 | 0x11 | 0x14 | 0x15 => {
                let register = read_register(&mut reader, machine)?;
                let offset = if matches!(opcode, 0x11 | 0x15) {
                    scaled_signed(reader.sleb()?, data_alignment)?
                } else {
                    scaled_unsigned(reader.uleb()?, data_alignment)?
                };
                rules.registers.insert(
                    register,
                    if matches!(opcode, 0x14 | 0x15) {
                        RegisterRule::CfaValueOffset(offset)
                    } else {
                        RegisterRule::CfaOffset(offset)
                    },
                );
            }
            0x06 => {
                read_register(&mut reader, machine)?;
                bail!("CIE initial restore has no independent initial-CIE rule context");
            }
            0x07 | 0x08 => {
                let register = read_register(&mut reader, machine)?;
                rules.registers.insert(
                    register,
                    if opcode == 0x07 {
                        RegisterRule::Undefined
                    } else {
                        RegisterRule::SameValue
                    },
                );
            }
            0x09 => {
                let register = read_register(&mut reader, machine)?;
                let source = read_register(&mut reader, machine)?;
                rules
                    .registers
                    .insert(register, RegisterRule::Register(source));
            }
            0x0a => remembered.push((rules.cfa.clone(), rules.registers.clone())),
            0x0b => {
                let (cfa, registers) = remembered
                    .pop()
                    .context("CIE restore_state stack underflow")?;
                rules.cfa = cfa;
                rules.registers = registers;
            }
            0x0c | 0x12 => {
                let register = read_register(&mut reader, machine)?;
                let offset = if opcode == 0x12 {
                    scaled_signed(reader.sleb()?, data_alignment)?
                } else {
                    i64::try_from(reader.uleb()?).context("CFA offset exceeds i64")?
                };
                rules.cfa = Some(CfaRule { register, offset });
            }
            0x0d => {
                let register = read_register(&mut reader, machine)?;
                rules
                    .cfa
                    .as_mut()
                    .context("CFA register update precedes an explicit CFA")?
                    .register = register;
            }
            0x0e | 0x13 => {
                let offset = if opcode == 0x13 {
                    scaled_signed(reader.sleb()?, data_alignment)?
                } else {
                    i64::try_from(reader.uleb()?).context("CFA offset exceeds i64")?
                };
                rules
                    .cfa
                    .as_mut()
                    .context("CFA offset update precedes an explicit CFA")?
                    .offset = offset;
            }
            // Location programs and expression/target extensions need their own checked semantics.
            _ => bail!("unsupported CIE initial opcode 0x{opcode:02x} at program offset {start}"),
        }
        rules.instructions.push(InitialInstruction {
            program_offset: start,
            raw: program[start..reader.cursor].to_vec(),
        });
    }
    if !remembered.is_empty() {
        bail!("CIE initial remembered-state stack remains open");
    }
    Ok(rules)
}
fn encoded_pointer(
    reader: &mut Reader<'_>,
    data: &[u8],
    section: &Section,
    encoding: u8,
) -> Result<EncodedPointer> {
    if encoding == 0xff {
        bail!("omitted pointer has no encoded field");
    }
    let application = encoding & 0x70;
    if !matches!(application, 0 | 0x10 | 0x20 | 0x30 | 0x40) {
        bail!("unsupported EH pointer application 0x{application:02x}");
    }
    let start = reader.cursor;
    let value = match encoding & 15 {
        0 => EncodedValue::Unsigned(reader.u64()?),
        1 => EncodedValue::Unsigned(reader.uleb()?),
        2 => EncodedValue::Unsigned(u64::from(u16::from_le_bytes(reader.take(2)?.try_into()?))),
        3 => EncodedValue::Unsigned(u64::from(reader.u32()?)),
        4 => EncodedValue::Unsigned(reader.u64()?),
        9 => EncodedValue::Signed(reader.sleb()?),
        10 => EncodedValue::Signed(i64::from(i16::from_le_bytes(reader.take(2)?.try_into()?))),
        11 => EncodedValue::Signed(i64::from(i32::from_le_bytes(reader.take(4)?.try_into()?))),
        12 => EncodedValue::Signed(i64::from_le_bytes(reader.take(8)?.try_into()?)),
        format => bail!("unsupported EH pointer format 0x{format:02x}"),
    };
    Ok(EncodedPointer {
        encoding,
        indirect: encoding & 0x80 != 0,
        application,
        range: span(data, section, start, reader.cursor)?,
        value,
        resolved_address: None,
    })
}
fn cie_record(
    data: &[u8],
    section: &Section,
    start: usize,
    end: usize,
    machine: u16,
) -> Result<RawCie> {
    let mut cie = RawCie {
        range: span(data, section, start, end)?,
        header: None,
        augmentation_data: None,
        fde_encoding: None,
        lsda_encoding: None,
        personality: None,
        signal_frame: false,
        initial_instructions: None,
        initial_rules: None,
        error: None,
    };
    let decoded = (|| -> Result<()> {
        let mut reader = Reader::new(data, start + 8, end)?;
        let version = reader.byte()?;
        if !matches!(version, 1 | 3) {
            bail!("unsupported raw CIE version {version}");
        }
        let augmentation = reader.string()?;
        let code_alignment = reader.uleb()?;
        let data_alignment = reader.sleb()?;
        let return_column = if version == 1 {
            u64::from(reader.byte()?)
        } else {
            reader.uleb()?
        };
        cie.header = Some(CieHeader {
            version,
            augmentation: augmentation.clone(),
            code_alignment,
            data_alignment,
            return_column,
            address_size_from_elf_class: 8,
        });
        if code_alignment == 0 {
            bail!("CIE code alignment is zero");
        }
        register_domain(machine, return_column)?;
        if augmentation.is_empty() {
            cie.initial_instructions = Some(span(data, section, reader.cursor, end)?);
        } else {
            if !augmentation.starts_with('z') {
                bail!("unsupported non-z CIE augmentation");
            }
            let size = usize::try_from(reader.uleb()?)?;
            let aug_end = reader
                .cursor
                .checked_add(size)
                .context("CIE augmentation length overflow")?;
            if aug_end > end {
                bail!("CIE augmentation exceeds its record");
            }
            cie.augmentation_data = Some(span(data, section, reader.cursor, aug_end)?);
            cie.initial_instructions = Some(span(data, section, aug_end, end)?);
            let mut aug = Reader::new(data, reader.cursor, aug_end)?;
            let mut seen = BTreeSet::new();
            for kind in augmentation[1..].bytes() {
                if !seen.insert(kind) {
                    bail!("duplicate raw CIE augmentation byte");
                }
                match kind {
                    b'R' => cie.fde_encoding = Some(aug.byte()?),
                    b'L' => cie.lsda_encoding = Some(aug.byte()?),
                    b'P' => {
                        let encoding = aug.byte()?;
                        cie.personality = Some(encoded_pointer(&mut aug, data, section, encoding)?);
                    }
                    b'S' => cie.signal_frame = true,
                    _ => bail!("unsupported raw CIE augmentation byte 0x{kind:02x}"),
                }
            }
            if aug.cursor != aug.end {
                bail!("unclaimed raw CIE augmentation bytes");
            }
        }
        let program = cie
            .initial_instructions
            .as_ref()
            .context("CIE initial bytes absent")?;
        cie.initial_rules = Some(initial_program(&program.bytes, machine, data_alignment)?);
        Ok(())
    })();
    if let Err(error) = decoded {
        cie.error = Some(format!("{error:#}"));
    }
    Ok(cie)
}
fn fde_record(
    data: &[u8],
    section: &Section,
    start: usize,
    end: usize,
    id: usize,
    cie: Option<&RawCie>,
) -> Result<RawFde> {
    let mut fde = RawFde {
        range: span(data, section, start, end)?,
        cie_section_offset: None,
        initial_location: None,
        address_range: None,
        augmentation_data: None,
        lsda: None,
        instructions: None,
        error: None,
    };
    let decoded = (|| -> Result<()> {
        let cie_offset = start
            .checked_add(4)
            .and_then(|offset| offset.checked_sub(id))
            .context("FDE CIE backreference outside section")?;
        fde.cie_section_offset = Some(cie_offset);
        let cie = cie.context("FDE backreference does not name a preceding CIE")?;
        let header = cie
            .header
            .as_ref()
            .context("FDE references an undecoded CIE header")?;
        if cie.error.is_some() {
            bail!("FDE references an incomplete CIE");
        }
        let encoding = cie
            .fde_encoding
            .context("FDE encoding absent; no implicit address encoding invented")?;
        let mut reader = Reader::new(data, start + 8, end)?;
        fde.initial_location = Some(encoded_pointer(&mut reader, data, section, encoding)?);
        // The range uses only the format bits, never the PC-relative application.
        let range = encoded_pointer(&mut reader, data, section, encoding & 15)?;
        if matches!(&range.value, EncodedValue::Signed(value) if *value < 0) {
            bail!("negative raw FDE address range");
        }
        fde.address_range = Some(range);
        if header.augmentation.starts_with('z') {
            let size = usize::try_from(reader.uleb()?)?;
            let aug_end = reader
                .cursor
                .checked_add(size)
                .context("FDE augmentation length overflow")?;
            if aug_end > end {
                bail!("FDE augmentation exceeds its record");
            }
            fde.augmentation_data = Some(span(data, section, reader.cursor, aug_end)?);
            let mut aug = Reader::new(data, reader.cursor, aug_end)?;
            if let Some(encoding) = cie.lsda_encoding {
                if encoding != 0xff {
                    fde.lsda = Some(encoded_pointer(&mut aug, data, section, encoding)?);
                }
            }
            if aug.cursor != aug.end {
                bail!("unclaimed raw FDE augmentation bytes");
            }
            reader.cursor = aug_end;
        }
        fde.instructions = Some(span(data, section, reader.cursor, end)?);
        Ok(())
    })();
    if let Err(error) = decoded {
        fde.error = Some(format!("{error:#}"));
    }
    Ok(fde)
}
fn raw_relocations(
    bytes: &[u8],
    sections: &[Section],
    target: usize,
) -> Result<Vec<RawRelocation>> {
    let mut result = Vec::new();
    for (index, section) in sections
        .iter()
        .enumerate()
        .filter(|(_, section)| matches!(section.kind, 4 | 9) && section.info == target)
    {
        let stride = if section.kind == 4 { 24 } else { 16 };
        if section.stride != stride as u64 || section.size % stride as u64 != 0 {
            bail!("raw ELF relocation stride/extent differs");
        }
        let symbols = sections
            .get(section.link)
            .context("raw relocation symbol table missing")?;
        if !matches!(symbols.kind, 2 | 11) || symbols.stride != 24 || symbols.size % 24 != 0 {
            bail!("raw relocation symbol-table geometry differs");
        }
        let symbol_data = section_data(bytes, symbols)?;
        for entry in section_data(bytes, section)?.chunks_exact(stride) {
            let offset = u64::from_le_bytes(entry[..8].try_into()?);
            if offset >= sections[target].size {
                bail!("raw relocation offset outside target section");
            }
            let info = u64::from_le_bytes(entry[8..16].try_into()?);
            let symbol_index = u32::try_from(info >> 32)?;
            let symbol_offset = usize::try_from(symbol_index)?
                .checked_mul(24)
                .context("raw symbol offset overflow")?;
            let symbol_end = symbol_offset
                .checked_add(24)
                .context("raw symbol extent overflow")?;
            let symbol_raw = symbol_data
                .get(symbol_offset..symbol_end)
                .context("raw relocation symbol outside table")?;
            result.push(RawRelocation {
                relocation_section: index,
                target_section: target,
                symbol_table: section.link,
                symbol_index,
                offset,
                kind: info as u32,
                addend: if stride == 24 {
                    Some(i64::from_le_bytes(entry[16..24].try_into()?))
                } else {
                    None
                },
                raw: entry.to_vec(),
                symbol_raw: symbol_raw.to_vec(),
            });
        }
    }
    Ok(result)
}
fn relocation_width(machine: u16, kind: u32) -> Option<usize> {
    match (machine, kind) {
        (62, 1) | (183, 257) | (243, 2) => Some(8),
        (62, 2) | (183, 261) | (243, 57) => Some(4),
        _ => None,
    }
}
fn protect_initial_rules(section: &mut RawFrameSection, machine: u16) {
    for record in &mut section.records {
        if let RawRecord::Fde(fde) = record {
            // Length and CIE backreference determine which record supplies
            // the initial rules. Unresolved fixups cannot authenticate those
            // raw-byte geometry/association facts. The initial-PC field begins
            // at +8 and remains outside this narrow header protection.
            let start = fde.range.section_offset;
            let end = start + 8;
            for relocation in &section.relocations {
                let Ok(offset) = usize::try_from(relocation.offset) else {
                    fde.error = Some("FDE relocation offset exceeds addressable section".into());
                    fde.cie_section_offset = None;
                    continue;
                };
                let relocation_end = relocation_width(machine, relocation.kind)
                    .and_then(|width| offset.checked_add(width));
                if offset < end && relocation_end.is_none_or(|limit| limit > start) {
                    fde.error = Some(format!(
                        "unresolved relocation kind {} overlaps FDE length/CIE backreference",
                        relocation.kind
                    ));
                    fde.cie_section_offset = None;
                }
            }
        }
        let RawRecord::Cie(cie) = record else {
            continue;
        };
        for relocation in &section.relocations {
            let Ok(offset) = usize::try_from(relocation.offset) else {
                cie.error = Some("CIE relocation offset exceeds addressable section".into());
                cie.initial_rules = None;
                continue;
            };
            let start = cie.range.section_offset;
            let end = start + cie.range.bytes.len();
            // A fixup may straddle the record start. Unknown widths are never assumed harmless.
            let width = relocation_width(machine, relocation.kind);
            let relocation_end = width.and_then(|size| offset.checked_add(size));
            let intersects = offset < end && relocation_end.is_none_or(|limit| limit > start);
            if !intersects {
                continue;
            }
            let allowed = relocation.addend.is_some()
                && relocation_end.is_some_and(|limit| {
                    cie.personality.as_ref().is_some_and(|pointer| {
                        offset >= pointer.range.section_offset
                            && limit <= pointer.range.section_offset + pointer.range.bytes.len()
                    })
                });
            if !allowed {
                cie.error = Some(format!(
                    "unresolved relocation kind {} overlaps CIE header/initial rules",
                    relocation.kind
                ));
                cie.initial_rules = None;
            }
        }
    }
}
fn frame_section(
    bytes: &[u8],
    section: &Section,
    index: usize,
    machine: u16,
    sections: &[Section],
) -> Result<RawFrameSection> {
    let data = section_data(bytes, section)?;
    let header_start = usize::try_from(u64::from_le_bytes(field(bytes, 40)?))?
        .checked_add(
            index
                .checked_mul(64)
                .context("raw section header index overflow")?,
        )
        .context("raw section header offset overflow")?;
    let header_end = header_start
        .checked_add(64)
        .context("raw section header extent overflow")?;
    let mut result = RawFrameSection {
        index,
        file_offset: section.offset,
        header_bytes: bytes
            .get(header_start..header_end)
            .context("raw section header absent")?
            .to_vec(),
        flags: section.flags,
        alignment: section.alignment,
        raw_bytes: data.to_vec(),
        records: Vec::new(),
        relocations: raw_relocations(bytes, sections, index)?,
        trailing_zero_terminator: Vec::new(),
    };
    let mut cursor = 0usize;
    let mut cies = BTreeMap::new();
    while cursor < data.len() {
        let start = cursor;
        let decoded = (|| -> Result<(usize, u32)> {
            let mut reader = Reader::new(data, start, data.len())?;
            let length = reader.u32()?;
            if length == 0 {
                return Ok((reader.cursor, 0));
            }
            if length == u32::MAX {
                bail!("DWARF64 frame lengths are explicitly unsupported");
            }
            if length < 4 {
                bail!("raw frame record shorter than CIE/FDE identifier");
            }
            let end = reader
                .cursor
                .checked_add(usize::try_from(length)?)
                .context("raw frame extent overflow")?;
            Reader::new(data, reader.cursor, end)?;
            Ok((end, reader.u32()?))
        })();
        let (end, id) = match decoded {
            Ok(value) => value,
            Err(error) => {
                result.records.push(RawRecord::Rejected {
                    range: span(data, section, start, data.len())?,
                    error: format!("{error:#}"),
                });
                break;
            }
        };
        if end == start + 4 {
            result.trailing_zero_terminator = data[start..].to_vec();
            if data[end..].iter().any(|byte| *byte != 0) {
                result.records.push(RawRecord::Rejected {
                    range: span(data, section, start, data.len())?,
                    error: "nonzero bytes after raw frame terminator".into(),
                });
            }
            break;
        }
        if id == 0 {
            let cie = cie_record(data, section, start, end, machine)?;
            cies.insert(start, result.records.len());
            result.records.push(RawRecord::Cie(cie));
        } else {
            let cie_offset = start
                .checked_add(4)
                .and_then(|offset| offset.checked_sub(id as usize));
            let cie = cie_offset
                .and_then(|offset| cies.get(&offset))
                .and_then(|&position| match &result.records[position] {
                    RawRecord::Cie(cie) => Some(cie),
                    _ => None,
                });
            let fde = fde_record(data, section, start, end, id as usize, cie)?;
            result.records.push(RawRecord::Fde(fde));
        }
        cursor = end;
    }
    protect_initial_rules(&mut result, machine);
    Ok(result)
}
fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).context("raw ELF field overflow")?;
    Ok(bytes
        .get(offset..end)
        .context("truncated raw ELF field")?
        .try_into()?)
}
/// Diagnostic entrypoint: preserves rejected frame records and exact raw bytes.
/// Structural ELF/container errors return Err; the caller retains its actual object buffer.
pub(crate) fn inspect_elf64_le_rel(bytes: &[u8]) -> Result<RawCieObject> {
    if !bytes.starts_with(b"\x7fELF\x02\x01\x01") || bytes.len() < 64 {
        bail!("raw CIE input must be an actual ELF64 little-endian object");
    }
    let machine = u16::from_le_bytes(field(bytes, 18)?);
    if !matches!(machine, 62 | 183 | 243)
        || u16::from_le_bytes(field(bytes, 16)?) != 1
        || u32::from_le_bytes(field(bytes, 20)?) != 1
        || u16::from_le_bytes(field(bytes, 52)?) != 64
        || u16::from_le_bytes(field(bytes, 58)?) != 64
    {
        bail!("unsupported raw ELF machine/type/header profile");
    }
    let shoff = usize::try_from(u64::from_le_bytes(field(bytes, 40)?))?;
    let count = usize::from(u16::from_le_bytes(field(bytes, 60)?));
    let shstr = usize::from(u16::from_le_bytes(field(bytes, 62)?));
    if count == 0 || shstr == 0 || shstr >= count {
        bail!("extended/missing raw ELF section inventory unsupported");
    }
    let mut sections = Vec::new();
    for index in 0..count {
        let at = shoff
            .checked_add(
                index
                    .checked_mul(64)
                    .context("raw ELF section index overflow")?,
            )
            .context("raw ELF section header overflow")?;
        let header_end = at
            .checked_add(64)
            .context("raw ELF section header overflow")?;
        bytes
            .get(at..header_end)
            .context("truncated raw ELF section header")?;
        let kind = u32::from_le_bytes(field(bytes, at + 4)?);
        let offset = u64::from_le_bytes(field(bytes, at + 24)?);
        let size = u64::from_le_bytes(field(bytes, at + 32)?);
        if kind != 8
            && offset
                .checked_add(size)
                .context("raw ELF section extent overflow")?
                > bytes.len() as u64
        {
            bail!("raw ELF section outside object");
        }
        let alignment = u64::from_le_bytes(field(bytes, at + 48)?);
        if alignment > 1 && !alignment.is_power_of_two() {
            bail!("raw ELF section alignment is not a power of two");
        }
        sections.push(Section {
            kind,
            flags: u64::from_le_bytes(field(bytes, at + 8)?),
            offset,
            size,
            link: usize::try_from(u32::from_le_bytes(field(bytes, at + 40)?))?,
            info: usize::try_from(u32::from_le_bytes(field(bytes, at + 44)?))?,
            alignment,
            stride: u64::from_le_bytes(field(bytes, at + 56)?),
        });
    }
    let names = section_names(bytes, &sections)?;
    let mut frames = Vec::new();
    for (index, section) in sections
        .iter()
        .enumerate()
        .filter(|(index, _)| names[*index] == ".eh_frame")
    {
        if !(section.kind == 1 || machine == 62 && section.kind == 0x7000_0001)
            || section.flags & 0x800 != 0
        {
            bail!("unsupported compressed or non-byte raw .eh_frame section");
        }
        frames.push(frame_section(bytes, section, index, machine, &sections)?);
    }
    if frames.is_empty() {
        bail!("raw object has no .eh_frame inventory");
    }
    Ok(RawCieObject {
        schema: "ocore-raw-elf64-cie-initial-rules-v1",
        object_bytes: bytes.len(),
        object_sha256: hex::encode(Sha256::digest(bytes)),
        elf_header: bytes[..64].to_vec(),
        machine,
        elf_flags: u32::from_le_bytes(field(bytes, 48)?),
        sections: frames,
        fde_pc_verified: false,
        fde_rules_executed: false,
        object_provenance_verified: false,
        source_profile_admitted: false,
        unwind_execution_verified: false,
    })
}
/// Strict raw-decoding entrypoint; callers requiring diagnostics first retain inspect_elf64_le_rel().
pub(crate) fn decode_elf64_le_rel(bytes: &[u8]) -> Result<RawCieObject> {
    let object = inspect_elf64_le_rel(bytes)?;
    object.require_initial_rules_decoded()?;
    Ok(object)
}

#[cfg(test)]
#[path = "cie_raw_decoder_tests.rs"]
mod tests;
