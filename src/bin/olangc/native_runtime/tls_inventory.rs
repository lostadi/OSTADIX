//! Exact admission of source-owned local-exec TLS address sequences.
//! TLS storage, symbol binding and initializer bytes are checked by the parent.
//! This gate does not qualify a loader, PT_TLS, thread creation or provider code.

use super::{Definition, ObjectSymbol, Section};
use anyhow::{bail, Context, Result};
use o_lang::ocore::native_ir::{NativeModule, Operation, TlsProfile};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone)]
struct Fixup<'a> {
    offset: u64,
    kind: u32,
    addend: i64,
    symbol: &'a ObjectSymbol,
}

fn code_fixup_width(arch: &str, kind: u32) -> Option<u64> {
    // Exact write footprints used by this static native code profile. An
    // unfamiliar kind cannot be assigned an invented width for TLS protection.
    match (arch, kind) {
        ("x86_64", 1) | ("aarch64", 257) | ("riscv64", 2 | 18 | 19) => Some(8),
        ("x86_64", 2 | 4 | 10 | 11 | 23)
        | ("aarch64", 275 | 277 | 282 | 283 | 549 | 551)
        | ("riscv64", 16 | 17 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 30 | 32) => Some(4),
        _ => None,
    }
}

fn data<'a>(bytes: &'a [u8], section: &Section) -> Result<&'a [u8]> {
    let end = section
        .offset
        .checked_add(section.size)
        .context("TLS section overflow")?;
    bytes
        .get(usize::try_from(section.offset)?..usize::try_from(end)?)
        .context("truncated TLS code/relocation section")
}

fn word(code: &[u8], offset: u64) -> Result<u32> {
    let start = usize::try_from(offset)?;
    Ok(u32::from_le_bytes(
        code.get(start..start.checked_add(4).context("TLS opcode overflow")?)
            .context("TLS opcode outside function")?
            .try_into()?,
    ))
}

pub(super) fn inspect(
    bytes: &[u8],
    arch: &str,
    module: &NativeModule,
    sections: &[Section],
    definitions: &BTreeMap<String, Definition>,
    symbols: &BTreeMap<usize, Vec<ObjectSymbol>>,
) -> Result<Value> {
    let tls: BTreeMap<_, _> = module
        .globals
        .iter()
        .filter(|global| global.thread_local)
        .map(|global| (global.name.as_str(), global))
        .collect();
    let mut storage = Vec::new();
    for (index, section) in sections
        .iter()
        .enumerate()
        .filter(|(_, section)| section.flags & 0x400 != 0)
    {
        if module.target.tls_profile != Some(TlsProfile::LinuxElfStaticNonpreemptiveV1)
            || !matches!(section.kind, 1 | 8)
            || section.flags & !0x200 != 0x403
            || section.stride != 0
        {
            bail!("ELF introduces TLS storage outside the explicit source profile");
        }
        let mut owners: Vec<_> = module
            .globals
            .iter()
            .filter(|global| {
                global.thread_local
                    && global.initializer.is_some()
                    && definitions
                        .get(&global.name)
                        .is_some_and(|definition| definition.section == index)
            })
            .collect();
        if owners.is_empty() {
            bail!("ELF introduces a TLS section without original source-owned storage");
        }
        // Stable sorting preserves original emission order for zero-sized
        // objects that have equal offsets. Distinct nonempty definitions may
        // not overlap or invent extra TLS template bytes.
        owners.sort_by_key(|global| definitions[&global.name].value);
        let mut cursor = 0u64;
        for global in owners {
            let definition = &definitions[&global.name];
            let alignment = if global.alignment == 0 {
                o_lang::ocore::native_verify::type_alignment(module, global.ty)?
            } else {
                global.alignment
            };
            let expected = cursor
                .checked_add(alignment - 1)
                .context("TLS padding extent overflow")?
                & !(alignment - 1);
            if definition.value != expected {
                bail!("ELF TLS storage placement differs from original source and canonical alignment");
            }
            if section.kind == 1
                && data(bytes, section)?[usize::try_from(cursor)?..usize::try_from(expected)?]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                bail!("ELF TLS alignment padding contains invented template bytes");
            }
            cursor = definition
                .value
                .checked_add(definition.size)
                .context("TLS source extent overflow")?;
            storage.push(json!({"global":global.name,"section":index,"offset":definition.value,"bytes":definition.size}));
        }
        if cursor != section.size {
            bail!("ELF TLS template has bytes outside original source storage");
        }
    }
    let owned_kind = |kind| match arch {
        "x86_64" => kind == 23,
        "aarch64" => matches!(kind, 549 | 551),
        "riscv64" => matches!(kind, 29 | 30 | 32),
        _ => false,
    };
    let mut fixups: BTreeMap<usize, Vec<Fixup<'_>>> = BTreeMap::new();
    let mut all_code_fixups: BTreeMap<usize, Vec<(u64, u32)>> = BTreeMap::new();
    for section in sections
        .iter()
        .filter(|section| matches!(section.kind, 4 | 9))
    {
        let table = symbols
            .get(&section.link)
            .context("TLS relocation symbol table missing")?;
        let target = sections
            .get(section.info)
            .context("TLS relocation section target missing")?;
        let stride = if section.kind == 4 { 24 } else { 16 };
        for entry in data(bytes, section)?.chunks_exact(stride) {
            let info = u64::from_le_bytes(entry[8..16].try_into()?);
            let symbol = table
                .get(usize::try_from(info >> 32)?)
                .context("TLS fixup symbol missing")?;
            let kind = info as u32;
            if target.flags & 6 == 6 {
                all_code_fixups
                    .entry(section.info)
                    .or_default()
                    .push((u64::from_le_bytes(entry[0..8].try_into()?), kind));
            }
            if !owned_kind(kind) && symbol.kind != 6 {
                continue;
            }
            if section.kind != 4
                || target.kind != 1
                || target.flags & 6 != 6
                || !owned_kind(kind)
                || symbol.kind != 6
                || !tls.contains_key(symbol.name.as_str())
            {
                bail!("ELF TLS fixup differs from the owned local-exec code profile");
            }
            let global = tls[symbol.name.as_str()];
            let exact = if let Some(definition) = definitions.get(&symbol.name) {
                symbol.kind == definition.kind
                    && symbol.binding == definition.binding
                    && symbol.visibility == definition.visibility
                    && symbol.section == definition.section
                    && symbol.value == definition.value
                    && symbol.size == definition.size
            } else {
                symbol.section == 0
                    && symbol.binding == 1
                    && symbol.value == 0
                    && symbol.size == 0
                    && symbol.visibility == super::visibility_bits(global.visibility)
            };
            if !exact {
                bail!("ELF TLS fixup does not identify its exact source storage");
            }
            let addend = i64::from_le_bytes(entry[16..24].try_into()?);
            if addend != 0 {
                bail!("ELF TLS address fixup has an invented offset");
            }
            fixups.entry(section.info).or_default().push(Fixup {
                offset: u64::from_le_bytes(entry[0..8].try_into()?),
                kind,
                addend,
                symbol,
            });
        }
    }
    for values in fixups.values_mut() {
        values.sort_by_key(|record| record.offset);
    }
    let mut observations = Vec::new();
    let mut consumed = 0;
    for function in module
        .functions
        .iter()
        .filter(|function| function.entry.is_some())
    {
        let definition = &definitions[&function.name];
        let end = definition
            .value
            .checked_add(definition.size)
            .context("TLS function extent overflow")?;
        let records: Vec<_> = fixups
            .get(&definition.section)
            .into_iter()
            .flatten()
            .filter(|record| definition.value <= record.offset && record.offset < end)
            .collect();
        let globals: Vec<_> = function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| {
                if let Operation::ThreadLocalAddress { global } = &instruction.operation {
                    Some(global.as_str())
                } else {
                    None
                }
            })
            .collect();
        let width = match arch {
            "x86_64" => 1,
            "aarch64" => 2,
            "riscv64" => 3,
            _ => unreachable!(),
        };
        if records.len()
            != globals
                .len()
                .checked_mul(width)
                .context("TLS source count overflow")?
        {
            bail!(
                "ELF TLS address inventory differs from whole source function: {}",
                function.name
            );
        }
        let section_code = data(bytes, &sections[definition.section])?;
        let code = section_code
            .get(usize::try_from(definition.value)?..usize::try_from(end)?)
            .context("TLS function code extent missing")?;
        for (global, sequence) in globals.iter().zip(records.chunks_exact(width)) {
            if sequence
                .iter()
                .any(|record| record.symbol.name != *global || record.addend != 0)
            {
                bail!("ELF TLS sequence targets a different original global");
            }
            let offset = sequence[0].offset - definition.value;
            let start = if arch == "x86_64" {
                sequence[0]
                    .offset
                    .checked_sub(12)
                    .context("TLS x86 sequence has no TP prefix")?
            } else if arch == "aarch64" {
                sequence[0]
                    .offset
                    .checked_sub(4)
                    .context("TLS ARM sequence has no TP prefix")?
            } else {
                sequence[0].offset
            };
            let end = start
                .checked_add(if arch == "x86_64" { 16 } else { 12 })
                .context("TLS sequence extent overflow")?;
            let mut writes = 0;
            for &(offset, kind) in all_code_fixups
                .get(&definition.section)
                .into_iter()
                .flatten()
            {
                let bytes = code_fixup_width(arch, kind)
                    .context("unknown code relocation write footprint in a source TLS section")?;
                let write_end = offset
                    .checked_add(bytes)
                    .context("TLS code relocation write extent overflow")?;
                if write_end > sections[definition.section].size {
                    bail!("ELF code relocation write exceeds its TLS code section");
                }
                if offset < end && write_end > start {
                    writes += 1;
                }
            }
            if writes != sequence.len() {
                bail!("ELF extra code relocation overwrites a source-owned TLS sequence");
            }
            let valid = match arch {
                "x86_64" => {
                    let start = offset
                        .checked_sub(12)
                        .context("TLS x86 sequence has no TP prefix")?;
                    let begin = usize::try_from(start)?;
                    code.get(begin..begin.checked_add(16).context("TLS sequence overflow")?)
                        == Some(&[
                            0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80, 0, 0, 0, 0,
                        ])
                        && sequence[0].kind == 23
                }
                "aarch64" => {
                    sequence[0].kind == 549
                        && sequence[1].kind == 551
                        && sequence[1].offset == sequence[0].offset + 4
                        && word(
                            code,
                            offset
                                .checked_sub(4)
                                .context("TLS ARM sequence has no TP prefix")?,
                        )? == 0xd53b_d049
                        && word(code, offset)? == 0x9140_0129
                        && word(code, offset + 4)? == 0x9100_0129
                }
                "riscv64" => {
                    sequence[0].kind == 29
                        && sequence[1].kind == 32
                        && sequence[2].kind == 30
                        && sequence[1].offset == sequence[0].offset + 4
                        && sequence[2].offset == sequence[0].offset + 8
                        && word(code, offset)? == 0x0000_02b7
                        && word(code, offset + 4)? == 0x0042_82b3
                        && word(code, offset + 8)? == 0x0002_8293
                }
                _ => unreachable!(),
            };
            if !valid {
                bail!("ELF TLS TP/offset instruction sequence differs from own lowering");
            }
            consumed += sequence.len();
            observations.push(json!({"function":function.name,"global":global,"source_model":tls[global].tls_model,
                "access":"local_exec","relocation_records":sequence.len()}));
        }
    }
    if consumed != fixups.values().map(Vec::len).sum::<usize>() {
        bail!("ELF TLS fixups occur outside source-owned address operations");
    }
    Ok(
        json!({"addresses":observations,"storage":storage,"profile":module.target.tls_profile,
        "scope":"exact_source_owned_local_exec_symbols_addends_and_opcodes",
        "tls_platform_execution_qualified":false,"provider_closure_complete":false}),
    )
}
