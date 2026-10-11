//! Admission of the owned static Itanium tables, including derived COMDAT data.
//!
//! This decoder binds CIE/FDE ownership, full-width personality/LSDA/typeinfo
//! references, call regions and ordered actions to the verified source module.
//! It does not establish execution of CFI instructions, a provider closure, or
//! the platform's discovery/registration of unwind tables.

use super::*;
use o_lang::ocore::native_ir::{ExceptionClause, Function, Operand, Operation, Terminator};

pub(super) struct Inspection {
    pub sections: Vec<(usize, String)>,
    pub receipt: Value,
}

struct Relocation<'a> {
    kind: u32,
    addend: i64,
    symbol: &'a ObjectSymbol,
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], start: usize, end: usize) -> Result<Self> {
        if start > end || end > bytes.len() {
            bail!("ELF exception table range is outside its section");
        }
        Ok(Self {
            bytes,
            cursor: start,
            end,
        })
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.cursor.checked_add(size).context("EH field overflow")?;
        if end > self.end {
            bail!("truncated ELF exception table");
        }
        let data = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(data)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn uleb(&mut self) -> Result<u64> {
        let mut result = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.byte()?;
            let payload = u64::from(byte & 127);
            if shift == 63 && payload > 1 {
                bail!("EH ULEB overflows u64");
            }
            result |= payload << shift;
            if byte & 128 == 0 {
                return Ok(result);
            }
        }
        bail!("unterminated EH ULEB")
    }
    fn sleb(&mut self) -> Result<i64> {
        let mut result = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.byte()?;
            let payload = u64::from(byte & 127);
            if shift == 63 && !matches!(payload, 0 | 127) {
                bail!("EH SLEB overflows i64");
            }
            result |= payload << shift;
            if byte & 128 == 0 {
                let bits = shift + 7;
                if bits < 64 && byte & 64 != 0 {
                    result |= u64::MAX << bits;
                }
                return Ok(result as i64);
            }
        }
        bail!("unterminated EH SLEB")
    }
    fn string(&mut self) -> Result<String> {
        let start = self.cursor;
        while self.byte()? != 0 {}
        Ok(std::str::from_utf8(&self.bytes[start..self.cursor - 1])?.into())
    }
}

fn section_data<'a>(bytes: &'a [u8], section: &Section) -> Result<&'a [u8]> {
    let start = usize::try_from(section.offset)?;
    let end = start
        .checked_add(usize::try_from(section.size)?)
        .context("EH section overflow")?;
    bytes.get(start..end).context("EH section outside object")
}

fn section_names(bytes: &[u8], sections: &[Section]) -> Result<Vec<String>> {
    let index = usize::from(u16::from_le_bytes(
        bytes
            .get(62..64)
            .context("truncated ELF header")?
            .try_into()?,
    ));
    let table = sections
        .get(index)
        .filter(|section| index != 0 && section.kind == 3)
        .context("EH object requires an ordinary section-name table")?;
    let names = section_data(bytes, table)?;
    let headers = u64::from_le_bytes(bytes[40..48].try_into()?);
    (0..sections.len())
        .map(|index| {
            let offset = usize::try_from(headers)?
                .checked_add(
                    index
                        .checked_mul(64)
                        .context("EH section-header overflow")?,
                )
                .context("EH section-header overflow")?;
            let name = u32::from_le_bytes(
                bytes
                    .get(offset..offset + 4)
                    .context("truncated section header")?
                    .try_into()?,
            );
            let tail = names
                .get(usize::try_from(name)?..)
                .context("EH section name outside strings")?;
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .context("unterminated EH section name")?;
            Ok(std::str::from_utf8(&tail[..end])?.into())
        })
        .collect()
}

fn relocations<'a>(
    bytes: &[u8],
    sections: &[Section],
    symbols: &'a BTreeMap<usize, Vec<ObjectSymbol>>,
    inspected_sections: &BTreeSet<usize>,
) -> Result<BTreeMap<usize, BTreeMap<usize, Relocation<'a>>>> {
    let mut result: BTreeMap<usize, BTreeMap<usize, Relocation<'a>>> = BTreeMap::new();
    for section in sections.iter().filter(|section| {
        matches!(section.kind, 4 | 9) && inspected_sections.contains(&section.info)
    }) {
        if section.kind != 4 {
            bail!("EH profile requires explicit-addend ELF relocations");
        }
        let data = section_data(bytes, section)?;
        let table = symbols
            .get(&section.link)
            .context("EH relocation symbol table missing")?;
        for entry in data.chunks_exact(24) {
            let offset = usize::try_from(u64::from_le_bytes(entry[0..8].try_into()?))?;
            let info = u64::from_le_bytes(entry[8..16].try_into()?);
            let symbol = table
                .get(usize::try_from(info >> 32)?)
                .context("EH relocation symbol missing")?;
            let relocation = Relocation {
                kind: info as u32,
                addend: i64::from_le_bytes(entry[16..24].try_into()?),
                symbol,
            };
            if result
                .entry(section.info)
                .or_default()
                .insert(offset, relocation)
                .is_some()
            {
                bail!("duplicate relocation in owned EH object");
            }
        }
    }
    Ok(result)
}

fn absolute_kind(arch: &str) -> u32 {
    match arch {
        "x86_64" => 1,
        "aarch64" => 257,
        "riscv64" => 2,
        _ => unreachable!(),
    }
}
fn pcrel_kind(arch: &str) -> u32 {
    match arch {
        "x86_64" => 2,
        "aarch64" => 261,
        "riscv64" => 57,
        _ => unreachable!(),
    }
}

fn named(operand: &Operand) -> Result<Option<&str>> {
    match operand {
        Operand::Null { .. } => Ok(None),
        Operand::PointerBits { bits, .. } if bits.bytes().all(|byte| byte == b'0') => Ok(None),
        Operand::Symbol { name, .. }
        | Operand::SymbolOffset {
            name, addend: 0, ..
        } => Ok(Some(name)),
        _ => bail!("EH object has an unsupported verified symbol contract"),
    }
}

fn reference_matches(
    relocation: &Relocation<'_>,
    name: &str,
    definitions: &BTreeMap<String, Definition>,
) -> bool {
    reference_matches_adjusted(relocation, name, definitions, 0)
}

fn reference_matches_adjusted(
    relocation: &Relocation<'_>,
    name: &str,
    definitions: &BTreeMap<String, Definition>,
    adjustment: i64,
) -> bool {
    if relocation.symbol.name == name && relocation.addend == adjustment {
        return definitions.get(name).map_or_else(
            || {
                relocation.symbol.section == 0
                    && relocation.symbol.binding == 1
                    && relocation.symbol.value == 0
                    && relocation.symbol.size == 0
            },
            |definition| {
                relocation.symbol.section == definition.section
                    && relocation.symbol.value == definition.value
                    && relocation.symbol.kind == definition.kind
                    && relocation.symbol.binding == definition.binding
                    && relocation.symbol.visibility == definition.visibility
                    && relocation.symbol.size == definition.size
            },
        );
    }
    definitions.get(name).is_some_and(|definition| {
        definition.binding == 0
            && relocation.symbol.kind == 3
            && relocation.symbol.binding == 0
            && relocation.symbol.section == definition.section
            && relocation.symbol.value == 0
            && relocation.symbol.size == 0
            && relocation.symbol.visibility == 0
            && relocation.addend as u64 == definition.value.wrapping_add(adjustment as u64)
    })
}

fn relocated_location(relocation: &Relocation<'_>) -> Result<(usize, usize)> {
    if relocation.symbol.section == 0 {
        bail!("EH table reference has no owned object section");
    }
    let offset = i128::from(relocation.symbol.value) + i128::from(relocation.addend);
    Ok((relocation.symbol.section, usize::try_from(offset)?))
}

fn local_call_target(bytes: &[u8], address: usize, arch: &str) -> Option<i128> {
    let displacement = match arch {
        "x86_64" if bytes.len() == 5 && bytes[0] == 0xe8 => {
            i128::from(i32::from_le_bytes(bytes[1..5].try_into().ok()?)) + 5
        }
        "aarch64" if bytes.len() == 4 => {
            let instruction = u32::from_le_bytes(bytes.try_into().ok()?);
            if instruction & 0xfc00_0000 != 0x9400_0000 {
                return None;
            }
            i128::from(((instruction as i32) << 6) >> 4)
        }
        "riscv64" if bytes.len() == 8 => {
            let high = u32::from_le_bytes(bytes[..4].try_into().ok()?);
            let low = u32::from_le_bytes(bytes[4..].try_into().ok()?);
            if high & 0xfff != 0x97 || low & 0x000f_ffff != 0x80e7 {
                return None;
            }
            i128::from((high & 0xffff_f000) as i32) + i128::from((low as i32) >> 20)
        }
        _ => return None,
    };
    Some(address as i128 + displacement)
}

struct Cie<'a> {
    personality: Option<(usize, &'a Relocation<'a>)>,
    lsda_encoding: u8,
    augmentation: bool,
}
struct Frame {
    function: String,
    table_section: usize,
    table_offset: usize,
}

fn frames<'a>(
    data: &[u8],
    relocation_map: &'a BTreeMap<usize, Relocation<'a>>,
    arch: &str,
    module: &NativeModule,
    definitions: &BTreeMap<String, Definition>,
    used: &mut BTreeSet<usize>,
) -> Result<Vec<Frame>> {
    let mut reader = Reader::new(data, 0, data.len())?;
    let mut cies = BTreeMap::new();
    let mut referenced_cies = BTreeSet::new();
    let mut found = BTreeSet::new();
    let mut result = Vec::new();
    while reader.cursor < reader.end {
        let start = reader.cursor;
        let length = usize::try_from(reader.u32()?)?;
        if length == 0 {
            if data[reader.cursor..].iter().any(|byte| *byte != 0) {
                bail!("extra bytes after EH frame terminator");
            }
            break;
        }
        if length < 4 || length == u32::MAX as usize {
            bail!("unsupported owned EH frame format");
        }
        let end = reader
            .cursor
            .checked_add(length)
            .context("EH frame length overflow")?;
        let mut record = Reader::new(data, reader.cursor, end)?;
        let id_offset = record.cursor;
        let id = usize::try_from(record.u32()?)?;
        reader.cursor = end;
        if id == 0 {
            let version = record.byte()?;
            if !matches!(version, 1 | 3) {
                bail!("owned EH CIE version unsupported by pinned reader");
            }
            let augmentation = record.string()?;
            let data_factor = if arch == "aarch64" { -4 } else { -8 };
            if record.uleb()? != 1 || record.sleb()? != data_factor {
                bail!("owned CIE alignment differs from LP64 code profile");
            }
            let register = if version == 1 {
                u64::from(record.byte()?)
            } else {
                record.uleb()?
            };
            let expected = match arch {
                "x86_64" => 16,
                "aarch64" => 30,
                "riscv64" => 1,
                _ => unreachable!(),
            };
            if register != expected {
                bail!("owned CIE return register differs from selected ISA");
            }
            let mut personality = None;
            let mut lsda_encoding = 255;
            if !augmentation.starts_with('z') {
                bail!("unsupported owned CIE augmentation");
            }
            let size = usize::try_from(record.uleb()?)?;
            let aug_end = record
                .cursor
                .checked_add(size)
                .context("CIE augmentation overflow")?;
            let mut aug = Reader::new(data, record.cursor, aug_end)?;
            let mut seen = BTreeSet::new();
            for kind in augmentation[1..].bytes() {
                if !seen.insert(kind) {
                    bail!("duplicate owned CIE augmentation");
                }
                match kind {
                    b'P' => {
                        if aug.byte()? != 0 {
                            bail!("owned personality requires full-width absolute encoding");
                        }
                        let offset = aug.cursor;
                        if aug.u64()? != 0 {
                            bail!("personality pointer slot is not a pure relocation");
                        }
                        let relocation = relocation_map
                            .get(&offset)
                            .context("owned CIE personality relocation missing")?;
                        if relocation.kind != absolute_kind(arch) {
                            bail!("owned CIE personality relocation is not ABS64");
                        }
                        personality = Some((offset, relocation));
                    }
                    b'L' => {
                        lsda_encoding = aug.byte()?;
                        if lsda_encoding != 0 {
                            bail!("owned LSDA requires full-width absolute encoding");
                        }
                    }
                    b'R' => {
                        if aug.byte()? != 0x1b {
                            bail!("unsupported owned FDE code-address encoding");
                        }
                    }
                    _ => bail!("unsupported owned CIE augmentation character"),
                }
            }
            if aug.cursor != aug.end
                || aug_end > record.end
                || !seen.contains(&b'R')
                || seen.contains(&b'P') != seen.contains(&b'L')
            {
                bail!("owned CIE augmentation geometry differs from code profile");
            }
            cies.insert(
                start,
                Cie {
                    personality,
                    lsda_encoding,
                    augmentation: true,
                },
            );
        } else {
            let cie_start = id_offset
                .checked_sub(id)
                .context("owned FDE refers outside CIE inventory")?;
            let cie = cies.get(&cie_start).context("owned FDE CIE missing")?;
            referenced_cies.insert(cie_start);
            let address = record.cursor;
            if record.u32()? != 0 {
                bail!("owned FDE code address slot is not a pure relocation");
            }
            let extent = u64::from(record.u32()?);
            let relocation = relocation_map
                .get(&address)
                .context("owned FDE code relocation missing")?;
            if relocation.kind != pcrel_kind(arch) {
                bail!("owned FDE code relocation differs from selected ISA");
            }
            used.insert(address);
            let (section, value) = relocated_location(relocation)?;
            let function = module
                .functions
                .iter()
                .filter(|function| function.entry.is_some())
                .find(|function| {
                    definitions.get(&function.name).is_some_and(|definition| {
                        definition.section == section && definition.value == value as u64
                    })
                })
                .context("owned FDE has no exact original function start")?;
            if extent != definitions[&function.name].size || !found.insert(function.name.clone()) {
                bail!("owned FDE extent/inventory differs from source function");
            }
            if !cie.augmentation {
                bail!("missing owned FDE augmentation contract");
            }
            let aug_size = usize::try_from(record.uleb()?)?;
            let aug_end = record
                .cursor
                .checked_add(aug_size)
                .context("FDE augmentation overflow")?;
            if aug_end > record.end {
                bail!("truncated owned FDE augmentation");
            }
            if let Some(eh) = &function.exception_handling {
                let (personality_offset, personality) = cie
                    .personality
                    .context("source EH function has no personality CIE")?;
                let name =
                    named(&eh.personality)?.context("source EH personality cannot be null")?;
                if !reference_matches(personality, name, definitions)
                    || cie.lsda_encoding != 0
                    || aug_size != 8
                {
                    bail!("owned FDE personality/LSDA differs from original source contract");
                }
                used.insert(personality_offset);
                let offset = record.cursor;
                if record.u64()? != 0 {
                    bail!("owned FDE LSDA slot is not a pure relocation");
                }
                let table = relocation_map
                    .get(&offset)
                    .context("owned FDE LSDA relocation missing")?;
                if table.kind != absolute_kind(arch) {
                    bail!("owned FDE LSDA relocation is not ABS64");
                }
                used.insert(offset);
                let (table_section, table_offset) = relocated_location(table)?;
                result.push(Frame {
                    function: function.name.clone(),
                    table_section,
                    table_offset,
                });
            } else if cie.personality.is_some() || cie.lsda_encoding != 255 || aug_size != 0 {
                bail!("ELF added exception metadata to a source function without it");
            }
        }
    }
    if found.len()
        != module
            .functions
            .iter()
            .filter(|function| function.entry.is_some())
            .count()
    {
        bail!("owned FDE inventory omitted original function definitions");
    }
    if referenced_cies.len() != cies.len() {
        bail!("ELF introduces a CIE without an original function owner");
    }
    if relocation_map.keys().any(|offset| !used.contains(offset)) {
        bail!("ELF introduces an unowned CFI relocation");
    }
    Ok(result)
}

fn encode_uleb(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 127) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 128;
        }
        bytes.push(byte);
        if value == 0 {
            return bytes;
        }
    }
}

#[derive(Default)]
struct SourceTables<'a> {
    types: Vec<Option<&'a str>>,
    filters: Vec<u8>,
    actions: BTreeMap<usize, Vec<i64>>,
}

impl<'a> SourceTables<'a> {
    fn index(&mut self, operand: &'a Operand) -> Result<i64> {
        let name = named(operand)?;
        if let Some(index) = self.types.iter().position(|candidate| *candidate == name) {
            return Ok(i64::try_from(index + 1)?);
        }
        self.types.push(name);
        Ok(i64::try_from(self.types.len())?)
    }
    fn new(function: &'a Function) -> Result<Self> {
        let mut table = Self::default();
        for block in &function.blocks {
            for instruction in &block.instructions {
                match &instruction.operation {
                    Operation::LandingPad { cleanup, clauses } => {
                        let mut actions = Vec::new();
                        for clause in clauses {
                            match clause {
                                ExceptionClause::Catch { typeinfo } => {
                                    actions.push(table.index(typeinfo)?)
                                }
                                ExceptionClause::Filter { typeinfos } => {
                                    actions.push(-i64::try_from(table.filters.len() + 1)?);
                                    for typeinfo in typeinfos {
                                        let index = table.index(typeinfo)?;
                                        table.filters.extend(encode_uleb(index as u64));
                                    }
                                    table.filters.push(0);
                                }
                            }
                        }
                        if *cleanup {
                            actions.push(0);
                        }
                        table.actions.insert(block.id, actions);
                    }
                    Operation::EhTypeId { typeinfo } => {
                        table.index(typeinfo)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(table)
    }
}

struct TableContext<'a> {
    function: &'a Function,
    arch: &'a str,
    definitions: &'a BTreeMap<String, Definition>,
    code: &'a [u8],
    code_relocations: &'a BTreeMap<usize, Relocation<'a>>,
}

fn table(
    data: &[u8],
    start: usize,
    end: usize,
    relocations: &BTreeMap<usize, Relocation<'_>>,
    context: TableContext<'_>,
) -> Result<Value> {
    let TableContext {
        function,
        arch,
        definitions,
        code,
        code_relocations,
    } = context;
    let extent = definitions[&function.name].size;
    let expected = SourceTables::new(function)?;
    let mut header = Reader::new(data, start, end)?;
    if !start.is_multiple_of(8) || header.byte()? != 255 {
        bail!("owned LSDA start/LPStart differs from static code profile");
    }
    let encoding = header.byte()?;
    let type_base = if encoding == 0 {
        let offset = usize::try_from(header.uleb()?)?;
        Some(
            header
                .cursor
                .checked_add(offset)
                .context("LSDA type-base overflow")?,
        )
    } else if encoding == 255 && expected.types.is_empty() && expected.filters.is_empty() {
        None
    } else {
        bail!("owned LSDA type encoding differs from full-width source profile");
    };
    if header.byte()? != 1 {
        bail!("owned LSDA call sites require unsigned function-relative LEBs");
    }
    let size = usize::try_from(header.uleb()?)?;
    let actions_start = header
        .cursor
        .checked_add(size)
        .context("LSDA call-table overflow")?;
    let type_start = match type_base {
        Some(base) => base
            .checked_sub(
                expected
                    .types
                    .len()
                    .checked_mul(8)
                    .context("TT size overflow")?,
            )
            .context("LSDA type-table underflow")?,
        None => end,
    };
    if type_start < actions_start || type_base.is_some_and(|base| base > end) {
        bail!("owned LSDA table regions overlap or escape");
    }
    let mut calls = Reader::new(data, header.cursor, actions_start)?;
    let mut expected_calls = Vec::new();
    for block in &function.blocks {
        for instruction in &block.instructions {
            if let Operation::Call { callee, .. } = &instruction.operation {
                let direct = match callee {
                    Operand::Symbol { name, .. } => Some(name.as_str()),
                    _ => None,
                };
                expected_calls.push((direct, None));
            }
        }
        match &block.terminator {
            Terminator::Invoke { callee, unwind, .. } => {
                let direct = match callee {
                    Operand::Symbol { name, .. } => Some(name.as_str()),
                    _ => None,
                };
                expected_calls.push((direct, Some(*unwind)));
            }
            Terminator::Resume { .. } => expected_calls.push((Some("_Unwind_Resume"), None)),
            _ => {}
        }
    }
    let mut previous_end = 0u64;
    let mut records: BTreeMap<usize, usize> = BTreeMap::new();
    let mut observations = Vec::new();
    let mut landing_targets = BTreeSet::new();
    for (callee, unwind) in &expected_calls {
        let offset = calls.uleb()?;
        let length = calls.uleb()?;
        let landing = calls.uleb()?;
        let action = calls.uleb()?;
        let call_end = offset
            .checked_add(length)
            .context("LSDA call range overflow")?;
        if length == 0
            || offset < previous_end
            || call_end > extent
            || landing >= extent
            || (landing != 0) != unwind.is_some()
        {
            bail!("owned LSDA call/landing range differs from original CFG");
        }
        previous_end = call_end;
        let definition = &definitions[&function.name];
        let code_start = usize::try_from(
            definition
                .value
                .checked_add(offset)
                .context("EH call address overflow")?,
        )?;
        let code_end = usize::try_from(
            definition
                .value
                .checked_add(call_end)
                .context("EH call address overflow")?,
        )?;
        let call_bytes = code
            .get(code_start..code_end)
            .context("EH call region escapes owned code")?;
        if let Some(callee) = callee {
            let (relocation_offset, expected_kind, expected_addend, expected_size) = match arch {
                "x86_64" => (code_start + 1, 4, -4, 5),
                "aarch64" => (code_start, 283, 0, 4),
                "riscv64" => (code_start, 19, 0, 8),
                _ => unreachable!(),
            };
            if let Some(relocation) = code_relocations.get(&relocation_offset) {
                let kind = relocation.kind == expected_kind
                    || (arch == "x86_64" && relocation.kind == 2)
                    || (arch == "riscv64" && relocation.kind == 18);
                let identity =
                    reference_matches_adjusted(relocation, callee, definitions, expected_addend);
                let instruction = match arch {
                    "x86_64" => call_bytes == [0xe8, 0, 0, 0, 0],
                    "aarch64" => call_bytes == 0x9400_0000u32.to_le_bytes(),
                    "riscv64" => call_bytes == [0x97, 0, 0, 0, 0xe7, 0x80, 0, 0],
                    _ => false,
                };
                if !instruction
                    || !kind
                    || call_bytes.len() != expected_size
                    || !identity
                    || code_relocations.range(code_start..code_end).count() != 1
                {
                    bail!("LSDA direct call relocation differs from original source callee");
                }
            } else if code_relocations
                .range(code_start..code_end)
                .next()
                .is_some()
                || !definitions.get(*callee).is_some_and(|target| {
                    target.binding == 0
                        && target.section == definition.section
                        && local_call_target(call_bytes, code_start, arch)
                            == Some(i128::from(target.value))
                })
            {
                bail!("LSDA direct call has no exact relocation or resolved local source target");
            }
        } else if code_relocations
            .range(code_start..code_end)
            .next()
            .is_some()
            || !match arch {
                "x86_64" => call_bytes == [0xff, 0xd0],
                "aarch64" => call_bytes == 0xd63f0120u32.to_le_bytes(), // blr x9.
                "riscv64" => {
                    call_bytes == [0x82, 0x92] || call_bytes == 0x000280e7u32.to_le_bytes()
                } // [c.]jalr t0.
                _ => false,
            }
        {
            bail!("LSDA indirect call region differs from owned instruction profile");
        }
        let expected_actions = unwind.and_then(|block| expected.actions.get(&block));
        if let Some(expected_actions) = expected_actions {
            if !landing_targets.insert(landing) {
                bail!("owned invokes must retain distinct unwind edge entries");
            }
            if expected_actions.as_slice() == [0] {
                if action != 0 {
                    bail!("owned cleanup-only call site acquired a catch/filter action");
                }
            } else {
                if action == 0 {
                    bail!("owned catch/filter call site lost its action chain");
                }
                let mut cursor = actions_start
                    .checked_add(usize::try_from(action - 1)?)
                    .context("LSDA action overflow")?;
                let mut selectors = Vec::new();
                let mut visited = BTreeSet::new();
                loop {
                    if !visited.insert(cursor) {
                        bail!("cycle in owned LSDA action chain");
                    }
                    let mut record = Reader::new(data, cursor, type_start)?;
                    let selector = record.sleb()?;
                    let displacement_base = record.cursor;
                    let displacement = record.sleb()?;
                    if let Some(end) = records.insert(cursor, record.cursor) {
                        if end != record.cursor {
                            bail!("inconsistent owned action record extent");
                        }
                    }
                    selectors.push(selector);
                    if selectors.len() > expected_actions.len() {
                        bail!("extra action in owned LSDA chain");
                    }
                    if displacement == 0 {
                        break;
                    }
                    let next = i128::try_from(displacement_base)? + i128::from(displacement);
                    cursor = usize::try_from(next)?;
                    if cursor < actions_start {
                        bail!("LSDA action displacement escapes action table");
                    }
                }
                if &selectors != expected_actions {
                    bail!("owned LSDA action/filter ordering differs from original clauses");
                }
            }
        } else if action != 0 {
            bail!("ordinary source call acquired an exception handler");
        }
        observations.push(json!({"start":offset,"bytes":length,"landing":landing,"action":action}));
    }
    if calls.cursor != calls.end {
        bail!("owned LSDA has extra source call regions");
    }
    let mut records_end = actions_start;
    for (&start, &end) in &records {
        if start != records_end {
            bail!("owned action records overlap or contain unclaimed bytes");
        }
        records_end = end;
    }
    let payload_end = if let Some(type_base) = type_base {
        if !type_start.is_multiple_of(8)
            || type_start
                .checked_sub(records_end)
                .is_none_or(|padding| padding > 7)
            || data[records_end..type_start].iter().any(|byte| *byte != 0)
        {
            bail!("owned LSDA action/type-table padding differs from code profile");
        }
        let mut expected_relocations = BTreeSet::new();
        for (index, name) in expected.types.iter().enumerate() {
            let offset = type_base - (index + 1) * 8;
            if data
                .get(offset..offset + 8)
                .context("truncated LSDA type entry")?
                .iter()
                .any(|byte| *byte != 0)
            {
                bail!("owned LSDA type entry must be a pure relocation or literal null");
            }
            if let Some(name) = name {
                let relocation = relocations
                    .get(&offset)
                    .context("owned LSDA typeinfo relocation missing")?;
                if relocation.kind != absolute_kind(arch)
                    || !reference_matches(relocation, name, definitions)
                {
                    bail!("owned LSDA typeinfo relocation differs from source identity/ABS64");
                }
                expected_relocations.insert(offset);
            } else if relocations.contains_key(&offset) {
                bail!("null catch-all became a relocated pointer");
            }
        }
        let filter_end = type_base
            .checked_add(expected.filters.len())
            .context("LSDA filter range overflow")?;
        if data
            .get(type_base..filter_end)
            .context("truncated LSDA filter table")?
            != expected.filters
        {
            bail!("owned LSDA filter bytes differ from ordered original type list");
        }
        if relocations
            .range(start..end)
            .any(|(offset, _)| !expected_relocations.contains(offset))
        {
            bail!("ELF introduces an unowned exception-table relocation");
        }
        filter_end
    } else {
        if relocations.range(start..end).next().is_some() {
            bail!("cleanup-only LSDA acquired a relocation");
        }
        records_end
    };
    if payload_end > end
        || end - payload_end > 7
        || data[payload_end..end].iter().any(|byte| *byte != 0)
    {
        bail!("unclaimed bytes after owned LSDA payload");
    }
    Ok(
        json!({"function":function.name,"call_sites":observations,"type_entries":expected.types.len(),
        "filter_bytes":expected.filters.len(),"action_records":records.len(),"bytes":payload_end-start}),
    )
}

pub(super) fn inspect(
    bytes: &[u8],
    arch: &str,
    module: &NativeModule,
    sections: &[Section],
    definitions: &BTreeMap<String, Definition>,
    symbols: &BTreeMap<usize, Vec<ObjectSymbol>>,
) -> Result<Inspection> {
    if !module
        .functions
        .iter()
        .any(|function| function.exception_handling.is_some())
    {
        return Ok(Inspection {
            sections: Vec::new(),
            receipt: json!({"functions":[],"scope":"no_source_exception_functions"}),
        });
    }
    let names = section_names(bytes, sections)?;
    let mut unwind = names
        .iter()
        .enumerate()
        .filter(|(_, name)| name.as_str() == ".eh_frame");
    let (frame_index, _) = unwind
        .next()
        .context("source EH module has no owned .eh_frame")?;
    if unwind.next().is_some() {
        bail!("duplicate owned .eh_frame section");
    }
    let frame_section = &sections[frame_index];
    if !(frame_section.kind == 1 || arch == "x86_64" && frame_section.kind == 0x7000_0001)
        || frame_section.flags != 2
        || frame_section.alignment < 8
    {
        bail!("owned EH frame storage differs from static ELF profile");
    }
    // This decoder owns one relocation per EH/code field. Ordinary global
    // initializers have a separate, exact decoder: RV symbol differences use
    // ADD32 and SUB32 at the same offset and must not be mistaken for duplicate
    // frame or call fixups. Keep strict uniqueness in every section consumed
    // below, including the complete code section of each exception function.
    let mut inspected_sections = BTreeSet::from([frame_index]);
    inspected_sections.extend(
        names
            .iter()
            .enumerate()
            .filter(|(_, name)| name.starts_with(".gcc_except_table"))
            .map(|(index, _)| index),
    );
    for function in module
        .functions
        .iter()
        .filter(|function| function.exception_handling.is_some() && function.entry.is_some())
    {
        inspected_sections.insert(
            definitions
                .get(&function.name)
                .context("source exception function has no ELF definition")?
                .section,
        );
    }
    let relocation_maps = relocations(bytes, sections, symbols, &inspected_sections)?;
    let empty = BTreeMap::new();
    let frame_relocations = relocation_maps.get(&frame_index).unwrap_or(&empty);
    let mut used = BTreeSet::new();
    let frames = frames(
        section_data(bytes, frame_section)?,
        frame_relocations,
        arch,
        module,
        definitions,
        &mut used,
    )?;
    let mut by_section: BTreeMap<usize, Vec<Frame>> = BTreeMap::new();
    for frame in frames {
        by_section
            .entry(frame.table_section)
            .or_default()
            .push(frame);
    }
    let mut observations = Vec::new();
    let mut owned = Vec::new();
    for (&index, frames) in &mut by_section {
        let section = sections.get(index).context("owned LSDA section missing")?;
        if section.kind != 1
            || section.flags & !0x200 != 2
            || section.alignment < 8
            || !names[index].starts_with(".gcc_except_table")
        {
            bail!("owned LSDA storage differs from allocated immutable ELF profile");
        }
        let data = section_data(bytes, section)?;
        frames.sort_by_key(|frame| frame.table_offset);
        if frames.first().is_none_or(|frame| frame.table_offset != 0) {
            bail!("unowned prefix in exception-table section");
        }
        let relocations = relocation_maps.get(&index).unwrap_or(&empty);
        for (position, frame) in frames.iter().enumerate() {
            let end = frames
                .get(position + 1)
                .map_or(data.len(), |next| next.table_offset);
            let function = module
                .functions
                .iter()
                .find(|function| function.name == frame.function)
                .unwrap();
            let definition = &definitions[&function.name];
            let code = section_data(bytes, &sections[definition.section])?;
            let code_relocations = relocation_maps.get(&definition.section).unwrap_or(&empty);
            observations.push(table(
                data,
                frame.table_offset,
                end,
                relocations,
                TableContext {
                    function,
                    arch,
                    definitions,
                    code,
                    code_relocations,
                },
            )?);
            owned.push((index, function.name.clone()));
        }
    }
    if names.iter().enumerate().any(|(index, name)| {
        name.starts_with(".gcc_except_table") && !by_section.contains_key(&index)
    }) {
        bail!("ELF introduces an exception table without an original function owner");
    }
    Ok(Inspection {
        sections: owned,
        receipt: json!({"functions":observations,
        "scope":"source_owned_static_itanium_cie_fde_lsda_and_relocations",
        "cfi_instructions":"structural_only","provider_closure_complete":false,"platform_execution_qualified":false}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use o_lang::ocore::driver::Target;

    fn module(triple: &str, group: Option<&str>, selection: &str) -> NativeModule {
        serde_json::from_value(json!({
            "format":"ocore-native-module-v1","name":"owned-eh-artifact-fixture",
            "target":{"triple":triple,"data_layout":"e-p:64:64-i64:64","pointer_bits":64,"little_endian":true},
            "semantics":"llvm_defined_behavior_v1",
            "types":[{"kind":"void"},{"kind":"int","bits":64},{"kind":"pointer","address_space":0},
                {"kind":"int","bits":32},{"kind":"struct","fields":[2,3],"packed":false}],
            "globals":[],"aliases":[],
            "comdats":group.map(|name| vec![json!({"name":name,"selection":selection})]).unwrap_or_default(),
            "functions":[
                {"name":"source_cleanup","linkage":if group.is_some(){"linkonce_odr"}else{"external"},"comdat":group,
                "signature":{"params":[1],"result":1,"abi":"c","variadic":false},"params":[{"id":0,"ty":1}],"entry":0,
                "exception_handling":{"model":"itanium_dwarf_v1","personality":{"kind":"symbol","ty":2,"name":"personality"}},
                "blocks":[
                    {"id":0,"instructions":[],"terminator":{"op":"invoke","callee":{"kind":"symbol","ty":2,"name":"may_throw"},
                        "signature":{"params":[1],"result":1,"abi":"c","variadic":false},"args":[{"kind":"value","id":0}],
                        "result":{"id":1,"ty":1},"normal":1,"unwind":2}},
                    {"id":1,"instructions":[],"terminator":{"op":"return","value":{"kind":"value","id":1}}},
                    {"id":2,"instructions":[{"result":{"id":2,"ty":4},"operation":{"op":"landing_pad","cleanup":true,"clauses":[]}}],
                        "terminator":{"op":"resume","value":{"kind":"value","id":2}}}]},
                {"name":"may_throw","linkage":"external","signature":{"params":[1],"result":1,"abi":"c","variadic":false},
                    "params":[{"id":0,"ty":1}],"entry":null,"blocks":[]},
                {"name":"personality","linkage":"external","signature":{"params":[],"result":3,"abi":"c","variadic":true},
                    "params":[],"entry":null,"blocks":[]}],
            "provenance":{"input_sha256":"0".repeat(64),"frontend":"authored-native-test","frontend_version":"1", "importer":"none","importer_version":"none",
                "source_function_count":3,"source_global_count":0,"referenced_comdat_count":usize::from(group.is_some()),"refinements":[]}
        })).unwrap()
    }

    #[test]
    fn owned_exception_tables_admit_only_their_derived_whole_group_members_on_each_isa() {
        let directory = std::env::temp_dir().join(format!(
            "ostadix-owned-exception-inventory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let clang = which::which("clang")
            .expect("LLVM clang is required for owned exception object qualification");
        for (arch, triple, target) in [
            ("x86_64", "x86_64-unknown-none", Target::X86_64UnknownNone),
            (
                "aarch64",
                "aarch64-unknown-none",
                Target::Aarch64UnknownNone,
            ),
            (
                "riscv64",
                "riscv64-unknown-none",
                Target::Riscv64UnknownNone,
            ),
        ] {
            for variant in ["cleanup", "typed", "local_call", "relative_initializer"] {
                for selection in ["ungrouped", "any", "no_deduplicate"] {
                    let group = (selection != "ungrouped").then_some("source_cleanup");
                    let mut module = module(triple, group, selection);
                    if matches!(variant, "typed" | "relative_initializer") {
                        for (name, linkage) in [
                            ("source_type_local", "internal"),
                            ("source_type_exported", "external"),
                        ] {
                            module.globals.push(serde_json::from_value(json!({"name":name,"ty":1,"linkage":linkage,"alignment":8,
                            "constant":true,"thread_local":false,"initializer":{"bytes":[0,0,0,0,0,0,0,0],"relocations":[]}})).unwrap());
                        }
                        let info = |name: &str| Operand::Symbol {
                            ty: 2,
                            name: name.into(),
                        };
                        module.functions[0].blocks[2].instructions[0].operation =
                            Operation::LandingPad {
                                cleanup: true,
                                clauses: vec![
                                    ExceptionClause::Catch {
                                        typeinfo: info("source_type_local"),
                                    },
                                    ExceptionClause::Filter {
                                        typeinfos: vec![
                                            info("source_type_exported"),
                                            info("source_type_local"),
                                            info("source_type_exported"),
                                        ],
                                    },
                                    ExceptionClause::Catch {
                                        typeinfo: Operand::Null { ty: 2 },
                                    },
                                    ExceptionClause::Filter { typeinfos: vec![] },
                                ],
                            };
                        module.provenance.source_global_count = module.globals.len();
                    }
                    if variant == "local_call" {
                        module.functions[1].linkage = "internal".into();
                        module.functions[1].entry = Some(0);
                        module.functions[1].blocks = vec![o_lang::ocore::native_ir::Block {
                            id: 0,
                            instructions: vec![],
                            terminator: Terminator::Return {
                                value: Some(Operand::Value { id: 0 }),
                            },
                        }];
                    }
                    if variant == "relative_initializer" {
                        module.globals.push(
                            serde_json::from_value(json!({
                                "name":"relative_table","ty":1,"linkage":"private","alignment":4,
                                "constant":true,"thread_local":false,
                                "initializer":{"bytes":[0,0,0,0,0,0,0,0],"relocations":[
                                    {"offset":0,"width":32,"symbol":"source_cleanup","addend":-3,
                                        "relative_to":"relative_table"}]}
                            }))
                            .unwrap(),
                        );
                        module.provenance.source_global_count = module.globals.len();
                    }
                    let assembly = o_lang::ocore::native_codegen::emit(&module, target).unwrap();
                    let source = directory.join(format!("{arch}-{selection}-{variant}.s"));
                    let object = source.with_extension("o");
                    fs::write(&source, &assembly).unwrap();
                    let result = Command::new(&clang)
                        .args(["-target", triple, "-c", "-x", "assembler"])
                        .arg(&source)
                        .arg("-o")
                        .arg(&object)
                        .output()
                        .unwrap();
                    assert!(
                        result.status.success(),
                        "{}",
                        String::from_utf8_lossy(&result.stderr)
                    );
                    let inventory =
                        object_inventory(&fs::read(&object).unwrap(), arch, &module).unwrap();
                    assert_eq!(
                        inventory["exception_tables"]["functions"][0]["function"],
                        "source_cleanup"
                    );
                    assert_eq!(
                        inventory["exception_tables"]["functions"][0]["call_sites"]
                            .as_array()
                            .unwrap()
                            .len(),
                        2
                    );
                    if group.is_some() {
                        let groups = inventory["section_groups"].as_array().unwrap();
                        assert_eq!(groups.len(), 1);
                        assert!(groups[0]["members"].as_array().unwrap().len() >= 3);
                    }
                    if variant == "relative_initializer" {
                        assert_eq!(
                            inventory["initializer_checks"]["relative32_initializers"],
                            1
                        );
                        assert_eq!(
                            inventory["initializer_checks"]["relocation_records"],
                            if arch == "riscv64" { 2 } else { 1 }
                        );
                        // An allowed data pair must not weaken the decoder for
                        // duplicate frame or call relocations. Independently
                        // append a duplicate raw RELA entry in each EH section.
                        let original = fs::read(&object).unwrap();
                        let headers = usize::try_from(u64::from_le_bytes(
                            original[40..48].try_into().unwrap(),
                        ))
                        .unwrap();
                        let count =
                            usize::from(u16::from_le_bytes(original[60..62].try_into().unwrap()));
                        let strings_index =
                            usize::from(u16::from_le_bytes(original[62..64].try_into().unwrap()));
                        let strings_header = headers + 64 * strings_index;
                        let strings_offset = usize::try_from(u64::from_le_bytes(
                            original[strings_header + 24..strings_header + 32]
                                .try_into()
                                .unwrap(),
                        ))
                        .unwrap();
                        let mut duplicate_checks = BTreeSet::new();
                        for index in 0..count {
                            let header = headers + 64 * index;
                            if u32::from_le_bytes(
                                original[header + 4..header + 8].try_into().unwrap(),
                            ) != 4
                            {
                                continue;
                            }
                            let target = usize::try_from(u32::from_le_bytes(
                                original[header + 44..header + 48].try_into().unwrap(),
                            ))
                            .unwrap();
                            let target_header = headers + 64 * target;
                            let flags = u64::from_le_bytes(
                                original[target_header + 8..target_header + 16]
                                    .try_into()
                                    .unwrap(),
                            );
                            let name_offset = strings_offset
                                + usize::try_from(u32::from_le_bytes(
                                    original[target_header..target_header + 4]
                                        .try_into()
                                        .unwrap(),
                                ))
                                .unwrap();
                            let name_tail = &original[name_offset..];
                            let name_end = name_tail.iter().position(|byte| *byte == 0).unwrap();
                            let name = std::str::from_utf8(&name_tail[..name_end]).unwrap();
                            if flags & 4 == 0
                                && name != ".eh_frame"
                                && !name.starts_with(".gcc_except_table")
                            {
                                continue;
                            }
                            let offset = usize::try_from(u64::from_le_bytes(
                                original[header + 24..header + 32].try_into().unwrap(),
                            ))
                            .unwrap();
                            let size = usize::try_from(u64::from_le_bytes(
                                original[header + 32..header + 40].try_into().unwrap(),
                            ))
                            .unwrap();
                            if size == 0 {
                                continue;
                            }
                            let mut mutant = original.clone();
                            let mut payload = original[offset..offset + size].to_vec();
                            payload.extend_from_slice(&original[offset..offset + 24]);
                            let new_offset = mutant.len();
                            mutant.extend_from_slice(&payload);
                            mutant[header + 24..header + 32]
                                .copy_from_slice(&(new_offset as u64).to_le_bytes());
                            mutant[header + 32..header + 40]
                                .copy_from_slice(&(payload.len() as u64).to_le_bytes());
                            assert!(
                                object_inventory(&mutant, arch, &module)
                                    .unwrap_err()
                                    .to_string()
                                    .contains("duplicate relocation in owned EH object"),
                                "duplicate EH/code fixup escaped {arch}/{selection}/{index}"
                            );
                            duplicate_checks.insert(if flags & 4 != 0 {
                                "code"
                            } else if name == ".eh_frame" {
                                "frame"
                            } else {
                                "lsda"
                            });
                        }
                        assert_eq!(duplicate_checks, BTreeSet::from(["code", "frame", "lsda"]));
                    }
                    // Preserve the relocation and interval while converting CALL
                    // into JMP/B or discarding RV's return-address destination.
                    let mut mutant = fs::read(&object).unwrap();
                    let headers =
                        usize::try_from(u64::from_le_bytes(mutant[40..48].try_into().unwrap()))
                            .unwrap();
                    let count = usize::from(u16::from_le_bytes(mutant[60..62].try_into().unwrap()));
                    let mut file_code = None;
                    for index in 0..count {
                        let header = headers + 64 * index;
                        if u32::from_le_bytes(mutant[header + 4..header + 8].try_into().unwrap())
                            != 2
                        {
                            continue;
                        }
                        let offset = usize::try_from(u64::from_le_bytes(
                            mutant[header + 24..header + 32].try_into().unwrap(),
                        ))
                        .unwrap();
                        let size = usize::try_from(u64::from_le_bytes(
                            mutant[header + 32..header + 40].try_into().unwrap(),
                        ))
                        .unwrap();
                        let names_section = usize::try_from(u32::from_le_bytes(
                            mutant[header + 40..header + 44].try_into().unwrap(),
                        ))
                        .unwrap();
                        let names_header = headers + 64 * names_section;
                        let names_offset = usize::try_from(u64::from_le_bytes(
                            mutant[names_header + 24..names_header + 32]
                                .try_into()
                                .unwrap(),
                        ))
                        .unwrap();
                        for at in (offset..offset + size).step_by(24) {
                            let name_offset = names_offset
                                + usize::try_from(u32::from_le_bytes(
                                    mutant[at..at + 4].try_into().unwrap(),
                                ))
                                .unwrap();
                            let name_end = mutant[name_offset..]
                                .iter()
                                .position(|byte| *byte == 0)
                                .unwrap()
                                + name_offset;
                            if &mutant[name_offset..name_end] != b"source_cleanup" {
                                continue;
                            }
                            let code_section = usize::from(u16::from_le_bytes(
                                mutant[at + 6..at + 8].try_into().unwrap(),
                            ));
                            let code_header = headers + 64 * code_section;
                            let code_offset = usize::try_from(u64::from_le_bytes(
                                mutant[code_header + 24..code_header + 32]
                                    .try_into()
                                    .unwrap(),
                            ))
                            .unwrap();
                            let symbol_value = usize::try_from(u64::from_le_bytes(
                                mutant[at + 8..at + 16].try_into().unwrap(),
                            ))
                            .unwrap();
                            file_code = Some(code_offset + symbol_value);
                        }
                    }
                    let start = file_code.unwrap()
                        + usize::try_from(
                            inventory["exception_tables"]["functions"][0]["call_sites"][0]["start"]
                                .as_u64()
                                .unwrap(),
                        )
                        .unwrap();
                    match arch {
                        "x86_64" => mutant[start] = 0xe9,
                        "aarch64" => mutant[start + 3] &= 0x7f,
                        "riscv64" => mutant[start + 4] &= 0x7f,
                        _ => unreachable!(),
                    }
                    assert!(
                        object_inventory(&mutant, arch, &module).is_err(),
                        "call-to-jump corruption escaped {arch}/{variant}/{selection}"
                    );
                    // An unrelated immutable PROGBITS member is never legitimized
                    // merely because the real source group also contains an LSDA.
                    if let Some(group) = group {
                        let extra = format!(
                        "{assembly}\n.section .extra.unowned,\"aG\",@progbits,{group}{}\n.quad 0\n",
                        if selection == "any" { ",comdat" } else { "" }
                    );
                        let mutant = source.with_extension("extra.s");
                        let mutant_object = source.with_extension("extra.o");
                        fs::write(&mutant, extra).unwrap();
                        let result = Command::new(&clang)
                            .args(["-target", triple, "-c", "-x", "assembler"])
                            .arg(&mutant)
                            .arg("-o")
                            .arg(&mutant_object)
                            .output()
                            .unwrap();
                        assert!(
                            result.status.success(),
                            "{}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        assert!(
                            object_inventory(&fs::read(mutant_object).unwrap(), arch, &module)
                                .unwrap_err()
                                .to_string()
                                .contains("whole-group members differ")
                        );
                    }
                }
            }
        }
        eprintln!(
            "owned EH object/group qualification: {}",
            directory.display()
        );
    }
}
