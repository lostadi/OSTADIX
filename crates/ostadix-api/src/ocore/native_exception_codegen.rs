//! Itanium LSDA construction for owned, statically linked ELF code.
//!
//! Type entries use full-width absolute pointers, independently of instruction
//! reach. The final link must resolve their original symbols; this profile does
//! not claim dynamic interposition or runtime publication of exception tables.

use std::collections::BTreeMap;
use std::fmt::Write;

use super::native_ir::*;
use super::Diagnostic;

#[derive(Debug)]
pub(crate) struct CallSite {
    pub start: String,
    pub end: String,
    pub landing: Option<String>,
    pub action: u64,
}

#[derive(Debug)]
pub(crate) struct ExceptionTables<'a> {
    typeinfos: Vec<&'a Operand>,
    type_indices: BTreeMap<String, i64>,
    actions: Vec<u8>,
    filters: Vec<u8>,
    landing_actions: BTreeMap<BlockId, u64>,
}

fn typeinfo_key(operand: &Operand) -> Result<String, Diagnostic> {
    match operand {
        Operand::Null { .. } => Ok("null".into()),
        Operand::PointerBits { bits, .. } if bits.bytes().all(|byte| byte == b'0') => {
            Ok("null".into())
        }
        Operand::Symbol { name, .. }
        | Operand::SymbolOffset {
            name, addend: 0, ..
        } => Ok(format!("symbol:{name}")),
        _ => Err(error_diagnostic(
            "EH typeinfo needs a supported static symbol or null catch-all",
        )),
    }
}

fn sleb(mut value: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        let finished = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if !finished {
            byte |= 0x80;
        }
        bytes.push(byte);
        if finished {
            return bytes;
        }
    }
}

fn uleb(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return bytes;
        }
    }
}

impl<'a> ExceptionTables<'a> {
    pub fn new(function: &'a Function) -> Result<Self, Diagnostic> {
        let mut tables = Self {
            typeinfos: Vec::new(),
            type_indices: BTreeMap::new(),
            actions: Vec::new(),
            filters: Vec::new(),
            landing_actions: BTreeMap::new(),
        };
        for block in &function.blocks {
            for instruction in &block.instructions {
                match &instruction.operation {
                    Operation::LandingPad { cleanup, clauses } => {
                        let mut selectors = Vec::new();
                        for clause in clauses {
                            match clause {
                                ExceptionClause::Catch { typeinfo } => {
                                    selectors.push(tables.insert_typeinfo(typeinfo)?);
                                }
                                ExceptionClause::Filter { typeinfos } => {
                                    // Filter selectors encode BYTE offsets, not
                                    // ordinals: ULEB type indices have variable width.
                                    let offset =
                                        i64::try_from(tables.filters.len()).map_err(|_| {
                                            error_diagnostic("EH filter offset overflow")
                                        })?;
                                    selectors.push(
                                        offset
                                            .checked_add(1)
                                            .and_then(i64::checked_neg)
                                            .ok_or_else(|| {
                                                error_diagnostic("EH filter selector overflow")
                                            })?,
                                    );
                                    for typeinfo in typeinfos {
                                        let index = tables.insert_typeinfo(typeinfo)?;
                                        tables.filters.extend(uleb(index as u64));
                                    }
                                    tables.filters.push(0);
                                }
                            }
                        }
                        if *cleanup {
                            selectors.push(0);
                        }
                        let action = if selectors.as_slice() == [0] {
                            // Action zero with a landing address is cleanup.
                            0
                        } else {
                            tables.append_action_chain(&selectors)?
                        };
                        tables.landing_actions.insert(block.id, action);
                    }
                    Operation::EhTypeId { typeinfo } => {
                        tables.insert_typeinfo(typeinfo)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(tables)
    }

    fn insert_typeinfo(&mut self, operand: &'a Operand) -> Result<i64, Diagnostic> {
        let key = typeinfo_key(operand)?;
        if let Some(index) = self.type_indices.get(&key) {
            return Ok(*index);
        }
        let index = i64::try_from(self.typeinfos.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| error_diagnostic("EH type index overflow"))?;
        i32::try_from(index)
            .map_err(|_| error_diagnostic("EH selector exceeds positive i32 range"))?;
        self.typeinfos.push(operand);
        self.type_indices.insert(key, index);
        Ok(index)
    }

    fn append_action_chain(&mut self, selectors: &[i64]) -> Result<u64, Diagnostic> {
        let mut next = None;
        // Records point backward to already-sized records. The displacement
        // base is the ADDRESS of the second SLEB field, not its end.
        for selector in selectors.iter().rev() {
            let start = i64::try_from(self.actions.len())
                .map_err(|_| error_diagnostic("EH action offset overflow"))?;
            let first = sleb(*selector);
            let displacement_base = start
                .checked_add(first.len() as i64)
                .ok_or_else(|| error_diagnostic("EH action displacement overflow"))?;
            let displacement = next
                .map_or(Some(0), |offset: i64| offset.checked_sub(displacement_base))
                .ok_or_else(|| error_diagnostic("EH action displacement overflow"))?;
            self.actions.extend(first);
            self.actions.extend(sleb(displacement));
            next = Some(start);
        }
        next.and_then(|offset| offset.checked_add(1))
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or_else(|| error_diagnostic("EH landing pad has no action or cleanup"))
    }

    pub fn type_id(&self, operand: &Operand) -> Result<i64, Diagnostic> {
        self.type_indices
            .get(&typeinfo_key(operand)?)
            .copied()
            .ok_or_else(|| error_diagnostic("EH typeid missing from its function table"))
    }

    pub fn action(&self, block: BlockId) -> Result<u64, Diagnostic> {
        self.landing_actions
            .get(&block)
            .copied()
            .ok_or_else(|| error_diagnostic("invoke unwind target has no landing pad"))
    }

    pub fn emit(&self, out: &mut String, function: &str, label: &str, calls: &[CallSite]) {
        let reference_end = format!("{label}_type_reference_end");
        let types_end = format!("{label}_types_end");
        let calls_begin = format!("{label}_calls_begin");
        let actions_begin = format!("{label}_actions_begin");
        writeln!(out, ".balign 8\n{label}:\n  .byte 255").unwrap(); // omit LPStart
        if self.typeinfos.is_empty() && self.filters.is_empty() {
            out.push_str("  .byte 255\n"); // omit TType
        } else {
            // Fixed-width absolute pointers accommodate all three 64-bit ISAs
            // without a hidden signed-32-bit code/data-distance restriction.
            writeln!(
                out,
                "  .byte 0\n  .uleb128 {types_end}-{reference_end}\n{reference_end}:"
            )
            .unwrap();
        }
        writeln!(
            out,
            "  .byte 1\n  .uleb128 {actions_begin}-{calls_begin}\n{calls_begin}:"
        )
        .unwrap();
        for call in calls {
            writeln!(
                out,
                "  .uleb128 {}-{function}\n  .uleb128 {}-{}",
                call.start, call.end, call.start
            )
            .unwrap();
            if let Some(landing) = &call.landing {
                writeln!(out, "  .uleb128 {landing}-{function}").unwrap();
            } else {
                out.push_str("  .uleb128 0\n");
            }
            writeln!(out, "  .uleb128 {}", call.action).unwrap();
        }
        writeln!(out, "{actions_begin}:").unwrap();
        for byte in &self.actions {
            writeln!(out, "  .byte {byte}").unwrap();
        }
        if !self.typeinfos.is_empty() || !self.filters.is_empty() {
            out.push_str("  .balign 8\n");
            for operand in self.typeinfos.iter().rev() {
                match operand {
                    Operand::Symbol { name, .. }
                    | Operand::SymbolOffset {
                        name, addend: 0, ..
                    } => {
                        writeln!(out, "  .quad {name}").unwrap();
                    }
                    _ => out.push_str("  .quad 0\n"), // verified null catch-all
                }
            }
            writeln!(out, "{types_end}:").unwrap();
            for byte in &self.filters {
                writeln!(out, "  .byte {byte}").unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(name: &str) -> Operand {
        Operand::Symbol {
            ty: 0,
            name: name.into(),
        }
    }

    fn function(clauses: Vec<ExceptionClause>, cleanup: bool) -> Function {
        Function {
            name: "owned".into(),
            linkage: "external".into(),
            visibility: Visibility::Default,
            comdat: None,
            alignment: 0,
            signature: Signature {
                params: vec![],
                result: 0,
                abi: "c".into(),
                variadic: false,
                param_attributes: vec![],
                result_attributes: vec![],
                return_storage: None,
            },
            params: vec![],
            entry: Some(0),
            blocks: vec![Block {
                id: 0,
                instructions: vec![Instruction {
                    result: Some(Value { id: 0, ty: 1 }),
                    operation: Operation::LandingPad { cleanup, clauses },
                }],
                terminator: Terminator::Unreachable,
            }],
            managed_method: None,
            intrinsic: None,
            exception_handling: None,
        }
    }

    // Decode the standard action representation independently of its reverse
    // construction, including the second-field displacement base.
    fn read_sleb(bytes: &[u8], cursor: &mut usize) -> i64 {
        let mut result = 0u64;
        let mut shift = 0;
        loop {
            let byte = bytes[*cursor];
            *cursor += 1;
            result |= u64::from(byte & 127) << shift;
            shift += 7;
            if byte & 128 == 0 {
                if shift < 64 && byte & 64 != 0 {
                    result |= u64::MAX << shift;
                }
                return result as i64;
            }
        }
    }

    fn decode_chain(tables: &ExceptionTables<'_>, block: BlockId) -> Vec<i64> {
        let mut cursor = (tables.action(block).unwrap() - 1) as usize;
        let mut selectors = Vec::new();
        loop {
            selectors.push(read_sleb(&tables.actions, &mut cursor));
            let displacement_base = cursor;
            let displacement = read_sleb(&tables.actions, &mut cursor);
            if displacement == 0 {
                return selectors;
            }
            cursor = (displacement_base as i64 + displacement) as usize;
            assert!(selectors.len() <= tables.actions.len());
        }
    }

    #[test]
    fn distinguishes_cleanup_catch_all_and_empty_filter() {
        let cleanup = function(vec![], true);
        let tables = ExceptionTables::new(&cleanup).unwrap();
        assert_eq!(tables.action(0).unwrap(), 0);
        assert!(tables.actions.is_empty());
        let catch = function(
            vec![ExceptionClause::Catch {
                typeinfo: Operand::Null { ty: 0 },
            }],
            true,
        );
        let tables = ExceptionTables::new(&catch).unwrap();
        assert_eq!(decode_chain(&tables, 0), [1, 0]);
        assert_eq!(tables.type_id(&Operand::Null { ty: 0 }).unwrap(), 1);
        let filter = function(vec![ExceptionClause::Filter { typeinfos: vec![] }], false);
        let tables = ExceptionTables::new(&filter).unwrap();
        assert_eq!(decode_chain(&tables, 0), [-1]);
        assert_eq!(tables.filters, [0]);
        assert!(tables.typeinfos.is_empty());
    }

    #[test]
    fn preserves_order_duplicates_and_multibyte_filter_offsets() {
        let mut clauses: Vec<_> = (0..130)
            .map(|index| ExceptionClause::Catch {
                typeinfo: symbol(&format!("T{index}")),
            })
            .collect();
        clauses.push(ExceptionClause::Filter {
            typeinfos: vec![symbol("T128"), symbol("T0"), symbol("T0")],
        });
        clauses.push(ExceptionClause::Filter { typeinfos: vec![] });
        let mut function = function(clauses, true);
        function.blocks[0].instructions.push(Instruction {
            result: Some(Value { id: 1, ty: 0 }),
            operation: Operation::EhTypeId {
                typeinfo: Operand::Null { ty: 0 },
            },
        });
        let tables = ExceptionTables::new(&function).unwrap();
        let mut expected: Vec<_> = (1..=130).collect();
        expected.extend([-1, -6, 0]);
        assert_eq!(decode_chain(&tables, 0), expected);
        assert_eq!(tables.filters, [129, 1, 1, 1, 0, 0]);
        assert_eq!(tables.type_id(&symbol("T128")).unwrap(), 129);
        assert_eq!(tables.type_id(&Operand::Null { ty: 0 }).unwrap(), 131);
        let mut assembly = String::new();
        tables.emit(&mut assembly, "owned", "LSDA", &[]);
        assert_eq!(assembly.matches(".quad ").count(), 131);
        assert!(assembly.contains("  .quad 0\n  .quad T129\n"));
        assert!(!assembly.contains("T128-."));
    }
}
