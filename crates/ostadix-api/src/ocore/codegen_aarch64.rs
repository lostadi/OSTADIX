//! AArch64 freestanding assembly generation from typed SSA MIR.
//!
//! This is a stack-spilling integer/aggregate backend. It uses AAPCS64
//! integer/pointer registers, spills every local and SSA value to the stack,
//! and rejects target features whose semantics are not implemented instead of
//! selecting an approximately equivalent instruction.
//!
//! x9--x17 are emitter scratch registers; x28 owns the aligned spill frame.
//! Explicit assembly operands are staged together so they may safely use these
//! registers. Phi edge copies are simultaneous, including cyclic copies.

use std::fmt::Write as _;

use super::ast::{Abi, BinaryOp, UnaryOp};
use super::hir::*;
use super::mir::*;
use super::{Diagnostic, Span};

pub fn emit_assembly(hir: &HirProgram, mir: &MirProgram) -> Result<String, Diagnostic> {
    emit_assembly_with_function_sections(hir, mir, false)
}

pub(crate) fn emit_assembly_with_function_sections(
    hir: &HirProgram,
    mir: &MirProgram,
    function_sections: bool,
) -> Result<String, Diagnostic> {
    let mut out = String::new();
    out.push_str(".file \"ocore\"\n");
    emit_statics(hir, &mut out)?;
    for function in &mir.functions {
        FunctionCodegen::new(hir, function)?.emit(&mut out, function_sections)?;
    }
    out.push_str(".section .note.GNU-stack,\"\",@progbits\n");
    Ok(out)
}

fn emit_statics(hir: &HirProgram, out: &mut String) -> Result<(), Diagnostic> {
    for static_ in &hir.statics {
        let section = static_.attrs.link_section.as_deref().unwrap_or({
            if static_.mutable {
                ".data"
            } else {
                ".rodata"
            }
        });
        writeln!(out, ".section {section}").unwrap();
        let align = static_
            .attrs
            .align
            .unwrap_or_else(|| hir.types.layout(static_.ty).align);
        writeln!(out, ".balign {align}").unwrap();
        if static_.attrs.export || static_.public {
            writeln!(out, ".globl {}", static_.symbol).unwrap();
        } else {
            writeln!(out, ".local {}", static_.symbol).unwrap();
        }
        writeln!(out, ".type {}, @object", static_.symbol).unwrap();
        writeln!(out, "{}:", static_.symbol).unwrap();
        emit_const(hir, static_.ty, &static_.init, out)?;
        writeln!(out, ".size {}, .-{}", static_.symbol, static_.symbol).unwrap();
    }
    Ok(())
}

fn emit_const(
    hir: &HirProgram,
    ty: TypeId,
    value: &HirConstValue,
    out: &mut String,
) -> Result<(), Diagnostic> {
    match (value, &hir.types.types[ty]) {
        (HirConstValue::Function(id), Type::Function { abi, .. }) => {
            if matches!(abi, Abi::SysV64 | Abi::Interrupt) {
                return Err(codegen_error(
                    "function-pointer constant uses an unsupported AArch64 ABI",
                ));
            }
            let target = hir
                .functions
                .get(*id)
                .ok_or_else(|| codegen_error("invalid function-pointer constant"))?;
            writeln!(out, ".xword {}", target.symbol).unwrap();
        }
        (HirConstValue::Integer(value), Type::Int { .. } | Type::Usize | Type::Isize) => {
            emit_integer(hir.types.layout(ty).size, *value, out)?;
        }
        (HirConstValue::Bool(value), Type::Bool) => {
            emit_integer(hir.types.layout(ty).size, u64::from(*value), out)?;
        }
        (HirConstValue::Bytes(bytes), Type::Array { element, len })
            if bytes.len() as u64 == *len
                && matches!(
                    hir.types.types[*element],
                    Type::Int {
                        signed: false,
                        bits: 8
                    }
                ) =>
        {
            if bytes.is_empty() {
                out.push_str(".zero 0\n");
            } else {
                out.push_str(".byte ");
                for (index, byte) in bytes.iter().enumerate() {
                    if index != 0 {
                        out.push_str(", ");
                    }
                    write!(out, "{byte}").unwrap();
                }
                out.push('\n');
            }
        }
        (HirConstValue::Array(values), Type::Array { element, len })
            if values.len() as u64 == *len =>
        {
            for value in values {
                emit_const(hir, *element, value, out)?;
            }
        }
        (HirConstValue::Repeat(value, count), Type::Array { element, len }) if count == len => {
            for _ in 0..*count {
                emit_const(hir, *element, value, out)?;
            }
        }
        (HirConstValue::Struct(id, values), Type::Struct(expected))
            if id == expected && values.len() == hir.types.structs[*id].fields.len() =>
        {
            let def = &hir.types.structs[*id];
            let mut cursor = 0u64;
            for (field, value) in def.fields.iter().zip(values) {
                if field.offset > cursor {
                    writeln!(out, ".zero {}", field.offset - cursor).unwrap();
                }
                emit_const(hir, field.ty, value, out)?;
                cursor = field.offset + hir.types.layout(field.ty).size;
            }
            if def.layout.size > cursor {
                writeln!(out, ".zero {}", def.layout.size - cursor).unwrap();
            }
        }
        (HirConstValue::Enum(id, variant, payload), Type::Enum(expected))
            if id == expected
                && hir.types.enums[*id]
                    .variants
                    .get(*variant)
                    .is_some_and(|definition| definition.payload.len() == payload.len()) =>
        {
            let def = &hir.types.enums[*id];
            emit_integer(def.tag_size, *variant as u64, out)?;
            if def.payload_offset > def.tag_size {
                writeln!(out, ".zero {}", def.payload_offset - def.tag_size).unwrap();
            }
            let variant_def = &def.variants[*variant];
            let mut cursor = 0u64;
            for (payload_ty, value) in variant_def.payload.iter().zip(payload) {
                let layout = hir.types.layout(*payload_ty);
                let next = align_up(cursor, layout.align);
                if next > cursor {
                    writeln!(out, ".zero {}", next - cursor).unwrap();
                }
                emit_const(hir, *payload_ty, value, out)?;
                cursor = next + layout.size;
            }
            let used = def.payload_offset + cursor;
            if def.layout.size > used {
                writeln!(out, ".zero {}", def.layout.size - used).unwrap();
            }
        }
        (HirConstValue::Zero, _) => {
            writeln!(out, ".zero {}", hir.types.layout(ty).size).unwrap();
        }
        _ => return Err(codegen_error("constant/type mismatch during data emission")),
    }
    Ok(())
}

fn emit_integer(size: u64, value: u64, out: &mut String) -> Result<(), Diagnostic> {
    match size {
        1 => writeln!(out, ".byte {}", value & u8::MAX as u64).unwrap(),
        2 => writeln!(out, ".hword {}", value & u16::MAX as u64).unwrap(),
        4 => writeln!(out, ".word {}", value & u32::MAX as u64).unwrap(),
        8 => writeln!(out, ".xword {value}").unwrap(),
        _ => return Err(codegen_error(format!("cannot emit {size}-byte scalar"))),
    }
    Ok(())
}

struct FrameLayout {
    locals: Vec<u64>,
    values: Vec<u64>,
    phi_temps: Vec<u64>,
    callee_saves: Vec<(u8, u64)>,
    align: u64,
    size: u64,
}

impl FrameLayout {
    fn new(types: &TypeContext, function: &MirFunction) -> Result<Self, Diagnostic> {
        let mut cursor = 0u64;
        let mut alignment = 16;
        let mut locals = Vec::new();
        for ty in &function.local_types {
            let layout = types.layout(*ty);
            alignment = alignment.max(layout.align);
            cursor = checked_align_up(cursor, layout.align.max(1))?;
            locals.push(cursor);
            cursor = cursor
                .checked_add(layout.size.max(1))
                .ok_or_else(|| codegen_error("AArch64 frame size overflow"))?;
        }
        let mut values = Vec::new();
        for _ in &function.values {
            cursor = checked_align_up(cursor, 8)?;
            values.push(cursor);
            cursor = cursor
                .checked_add(8)
                .ok_or_else(|| codegen_error("AArch64 frame size overflow"))?;
        }
        let phi_count = function
            .blocks
            .iter()
            .map(|block| {
                block
                    .instructions
                    .iter()
                    .filter(|instruction| matches!(instruction, Instruction::Phi { .. }))
                    .count()
            })
            .max()
            .unwrap_or(0);
        let mut phi_temps = Vec::new();
        for _ in 0..phi_count {
            cursor = checked_align_up(cursor, 8)?;
            phi_temps.push(cursor);
            cursor = cursor
                .checked_add(8)
                .ok_or_else(|| codegen_error("AArch64 frame size overflow"))?;
        }
        // An unsafe template may name callee-saved registers without operands.
        // Preserve them conservatively whenever the function contains assembly.
        let has_asm = function.blocks.iter().any(|block| {
            block
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Instruction::Asm { .. }))
        });
        let mut callee_saves = Vec::new();
        if has_asm {
            for register in 19..=27 {
                cursor = checked_align_up(cursor, 8)?;
                callee_saves.push((register, cursor));
                cursor = cursor
                    .checked_add(8)
                    .ok_or_else(|| codegen_error("AArch64 frame size overflow"))?;
            }
        }
        Ok(Self {
            locals,
            values,
            phi_temps,
            callee_saves,
            align: alignment,
            size: checked_align_up(cursor, 16)?,
        })
    }
}

struct FunctionCodegen<'a> {
    hir: &'a HirProgram,
    mir: &'a MirFunction,
    source: &'a HirFunction,
    frame: FrameLayout,
    label_prefix: String,
}

impl<'a> FunctionCodegen<'a> {
    fn new(hir: &'a HirProgram, mir: &'a MirFunction) -> Result<Self, Diagnostic> {
        let source = &hir.functions[mir.source];
        Ok(Self {
            hir,
            mir,
            source,
            frame: FrameLayout::new(&hir.types, mir)?,
            label_prefix: format!(".L_ocore_aarch64_{}", mir.source),
        })
    }

    fn emit(&self, out: &mut String, function_sections: bool) -> Result<(), Diagnostic> {
        if self.source.attrs.interrupt || self.source.abi == Abi::Interrupt {
            return Err(codegen_error(
                "interrupt ABI functions are not implemented by the AArch64 backend",
            ));
        }
        if self.source.abi == Abi::SysV64 {
            return Err(codegen_error(
                "extern \"sysv64\" is the AMD64 System V ABI and is unsupported on AArch64; use extern \"ocore\" for the compiler-versioned native ABI",
            ));
        }

        let default_section =
            function_sections.then(|| format!(".text.ocore_fn.{}", self.source.symbol));
        let section = self
            .source
            .attrs
            .link_section
            .as_deref()
            .or(default_section.as_deref())
            .unwrap_or(".text");
        writeln!(out, ".section {section},\"ax\",@progbits").unwrap();
        let align = self.source.attrs.align.unwrap_or(16);
        writeln!(out, ".balign {align}").unwrap();
        if self.source.attrs.export || self.source.public {
            writeln!(out, ".globl {}", self.source.symbol).unwrap();
        } else {
            writeln!(out, ".local {}", self.source.symbol).unwrap();
        }
        writeln!(out, ".type {}, @function", self.source.symbol).unwrap();
        writeln!(out, "{}:", self.source.symbol).unwrap();
        if self.source.attrs.naked {
            self.emit_naked(out)?;
            writeln!(
                out,
                ".size {}, .-{}",
                self.source.symbol, self.source.symbol
            )
            .unwrap();
            return Ok(());
        }
        out.push_str("  stp x29, x30, [sp, #-16]!\n  mov x29, sp\n");
        out.push_str("  stp x28, xzr, [sp, #-16]!\n");
        self.reserve_stack(out);
        out.push_str("  mov x28, sp\n");
        for (register, offset) in &self.frame.callee_saves {
            emit_frame_address("x15", *offset, out);
            writeln!(out, "  str x{register}, [x15]").unwrap();
        }
        self.store_parameters(out)?;
        writeln!(out, "  b {}_bb{}", self.label_prefix, self.mir.entry).unwrap();

        for (block_id, block) in self.mir.blocks.iter().enumerate() {
            writeln!(out, "{}_bb{}:", self.label_prefix, block_id).unwrap();
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                if !matches!(instruction, Instruction::Phi { .. }) {
                    self.emit_instruction(block_id, instruction_index, instruction, out)?;
                }
            }
            self.emit_terminator(block_id, &block.terminator, out)?;
        }
        writeln!(
            out,
            ".size {}, .-{}",
            self.source.symbol, self.source.symbol
        )
        .unwrap();
        Ok(())
    }

    fn reserve_stack(&self, out: &mut String) {
        emit_stack_adjust("sub", self.frame.size, out);
        if self.frame.align > 16 {
            emit_u64("x16", self.frame.align - 1, out);
            out.push_str("  mov x17, sp\n  bic x17, x17, x16\n  mov sp, x17\n");
        }
    }

    fn emit_naked(&self, out: &mut String) -> Result<(), Diagnostic> {
        for block in &self.mir.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::Asm {
                        template, operands, ..
                    } if operands.is_empty() => {
                        for line in template.lines() {
                            writeln!(out, "  {line}").unwrap();
                        }
                    }
                    Instruction::Const { .. } => {}
                    _ => {
                        return Err(codegen_error(
                            "@naked function bodies may contain only operand-free asm!",
                        ))
                    }
                }
            }
        }
        Ok(())
    }

    fn store_parameters(&self, out: &mut String) -> Result<(), Diagnostic> {
        for (index, local) in self.source.params.iter().enumerate() {
            let ty = self.source.locals[*local].ty;
            self.require_scalar_type(ty, "function parameter")?;
            if self.hir.types.is_float(ty) {
                return Err(codegen_error(
                    "floating-point parameters are not implemented by the AArch64 backend",
                ));
            }
            if index < 8 {
                self.store_reg_to_frame(&format!("x{index}"), self.frame.locals[*local], ty, out)?;
            } else {
                let offset = 16 + (index as u64 - 8) * 8;
                emit_address_offset("x10", "x29", offset, out);
                self.load_memory("x9", "x10", ty, out)?;
                self.store_reg_to_frame("x9", self.frame.locals[*local], ty, out)?;
            }
        }
        Ok(())
    }

    fn emit_instruction(
        &self,
        block_id: BlockId,
        instruction_index: usize,
        instruction: &Instruction,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        match instruction {
            Instruction::Const { dst, value } => {
                if self.hir.types.is_float(self.mir.values[*dst]) {
                    return Err(codegen_error(
                        "floating-point constant escaped O-core type checking",
                    ));
                }
                emit_u64("x9", *value, out);
                self.normalize_scalar("x9", self.mir.values[*dst], out)?;
                self.store_value(*dst, "x9", out);
            }
            Instruction::FunctionAddress { dst, function } => {
                self.validate_function_address(*dst, *function)?;
                emit_symbol_address("x9", &self.hir.functions[*function].symbol, out);
                self.store_value(*dst, "x9", out);
            }
            Instruction::AddressOf { dst, place } => {
                let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[*dst]]
                else {
                    return Err(codegen_error("address result is not a pointer"));
                };
                if pointee != place.ty {
                    return Err(codegen_error("address result pointee type mismatch"));
                }
                self.place_address(place, "x10", out)?;
                self.store_value(*dst, "x10", out);
            }
            Instruction::Load {
                dst,
                place,
                volatile,
            } => {
                self.require_same_type(self.mir.values[*dst], place.ty, "load result")?;
                self.require_scalar_type(place.ty, "load")?;
                self.place_address(place, "x10", out)?;
                if *volatile {
                    self.guard_volatile_alignment("x10", place, out);
                    self.load_memory("x9", "x10", place.ty, out)?;
                } else {
                    self.load_place_memory("x9", "x10", place, out)?;
                }
                self.store_value(*dst, "x9", out);
            }
            Instruction::Store {
                place,
                value,
                volatile,
            } => {
                self.require_same_type(self.mir.values[*value], place.ty, "store value")?;
                self.require_scalar_type(place.ty, "store")?;
                self.load_value(*value, "x9", out);
                self.place_address(place, "x10", out)?;
                if *volatile {
                    self.guard_volatile_alignment("x10", place, out);
                    self.store_memory("x9", "x10", place.ty, out)?;
                } else {
                    self.store_place_memory("x9", "x10", place, out)?;
                }
            }
            Instruction::Copy {
                destination,
                source,
                size,
            } => {
                if destination.ty != source.ty
                    || *size != self.hir.types.layout(destination.ty).size
                {
                    return Err(codegen_error("aggregate copy type or size mismatch"));
                }
                if *size != 0 {
                    let label = format!(
                        "{}_bb{}_copy{}",
                        self.label_prefix, block_id, instruction_index
                    );
                    self.place_address(destination, "x10", out)?;
                    self.place_address(source, "x11", out)?;
                    emit_u64("x12", *size, out);
                    // Aggregate assignment snapshots its source even when two
                    // unsafe pointer places overlap: choose memmove direction.
                    out.push_str("  cmp x10, x11\n");
                    writeln!(out, "  b.eq {label}_done\n  b.lo {label}_forward").unwrap();
                    out.push_str("  add x10, x10, x12\n  add x11, x11, x12\n");
                    writeln!(out, "{label}_backward:").unwrap();
                    out.push_str(
                        "  ldrb w13, [x11, #-1]!\n  strb w13, [x10, #-1]!\n  subs x12, x12, #1\n",
                    );
                    writeln!(
                        out,
                        "  b.ne {label}_backward\n  b {label}_done\n{label}_forward:"
                    )
                    .unwrap();
                    out.push_str(
                        "  ldrb w13, [x11], #1\n  strb w13, [x10], #1\n  subs x12, x12, #1\n",
                    );
                    writeln!(out, "  b.ne {label}_forward\n{label}_done:").unwrap();
                }
            }
            Instruction::Unary { dst, op, operand } => {
                self.validate_unary(*dst, *op, *operand)?;
                self.load_value(*operand, "x9", out);
                match op {
                    UnaryOp::Neg => out.push_str("  neg x9, x9\n"),
                    UnaryOp::Not => out.push_str("  eor x9, x9, #1\n"),
                    UnaryOp::BitNot => out.push_str("  mvn x9, x9\n"),
                    UnaryOp::Deref | UnaryOp::AddressOf { .. } => {
                        return Err(codegen_error("place unary operation escaped MIR lowering"));
                    }
                }
                self.normalize_scalar("x9", self.mir.values[*dst], out)?;
                self.store_value(*dst, "x9", out);
            }
            Instruction::Binary { dst, op, lhs, rhs } => {
                self.emit_binary(*dst, *op, *lhs, *rhs, out)?;
            }
            Instruction::Cast {
                dst,
                value,
                from,
                to,
            } => {
                self.require_same_type(self.mir.values[*value], *from, "cast source")?;
                self.require_same_type(self.mir.values[*dst], *to, "cast result")?;
                self.require_scalar_type(*from, "cast source")?;
                self.require_scalar_type(*to, "cast result")?;
                if self.hir.types.is_float(*from) || self.hir.types.is_float(*to) {
                    return Err(codegen_error(
                        "floating-point cast escaped O-core type checking",
                    ));
                }
                self.load_value(*value, "x9", out);
                self.normalize_scalar("x9", *from, out)?;
                self.normalize_scalar("x9", *to, out)?;
                self.store_value(*dst, "x9", out);
            }
            Instruction::Call {
                dst,
                function,
                args,
            } => self.emit_call(*dst, *function, args, out)?,
            Instruction::CallIndirect { dst, callee, args } => {
                self.emit_indirect_call(*dst, *callee, args, out)?;
            }
            Instruction::Intrinsic {
                dst,
                intrinsic,
                args,
            } => self.emit_intrinsic(*dst, *intrinsic, args, block_id, instruction_index, out)?,
            Instruction::Phi { .. } => unreachable!(),
            Instruction::Asm {
                template,
                operands,
                options,
            } => self.emit_asm(template, operands, options, out)?,
        }
        Ok(())
    }

    fn validate_function_address(
        &self,
        dst: ValueId,
        function: FunctionId,
    ) -> Result<(), Diagnostic> {
        let target = &self.hir.functions[function];
        if target.abi == Abi::SysV64 {
            return Err(codegen_error(
                "cannot take an AMD64 sysv64 function address on AArch64",
            ));
        }
        let expected_params = target
            .params
            .iter()
            .map(|local| target.locals[*local].ty)
            .collect::<Vec<_>>();
        match &self.hir.types.types[self.mir.values[dst]] {
            Type::Function {
                params,
                result,
                abi,
            } if params == &expected_params && *result == target.result && *abi == target.abi => {
                Ok(())
            }
            _ => Err(codegen_error("function address type mismatch")),
        }
    }

    fn validate_unary(
        &self,
        dst: ValueId,
        op: UnaryOp,
        operand: ValueId,
    ) -> Result<(), Diagnostic> {
        let operand_ty = self.mir.values[operand];
        let dst_ty = self.mir.values[dst];
        match op {
            UnaryOp::Neg | UnaryOp::BitNot => {
                self.require_integer_type(operand_ty, "unary operand")?;
                self.require_same_type(dst_ty, operand_ty, "unary result")
            }
            UnaryOp::Not => {
                let bool_ty = self.hir.types.primitive("bool").unwrap();
                self.require_same_type(operand_ty, bool_ty, "logical-not operand")?;
                self.require_same_type(dst_ty, bool_ty, "logical-not result")
            }
            UnaryOp::Deref | UnaryOp::AddressOf { .. } => {
                Err(codegen_error("place unary operation escaped MIR lowering"))
            }
        }
    }

    fn validate_binary(
        &self,
        dst: ValueId,
        op: BinaryOp,
        lhs: ValueId,
        rhs: ValueId,
    ) -> Result<(), Diagnostic> {
        let lhs_ty = self.mir.values[lhs];
        let rhs_ty = self.mir.values[rhs];
        let dst_ty = self.mir.values[dst];
        if self.hir.types.is_float(lhs_ty) || self.hir.types.is_float(rhs_ty) {
            return Err(codegen_error(
                "floating-point binary operation escaped O-core type checking",
            ));
        }
        match op {
            BinaryOp::Add | BinaryOp::Sub
                if matches!(self.hir.types.types[lhs_ty], Type::Pointer { .. }) =>
            {
                self.require_integer_type(rhs_ty, "pointer offset")?;
                self.require_same_type(dst_ty, lhs_ty, "pointer arithmetic result")
            }
            BinaryOp::ShiftLeft | BinaryOp::ShiftRight => {
                self.require_integer_type(lhs_ty, "shifted value")?;
                self.require_integer_type(rhs_ty, "shift count")?;
                self.require_same_type(dst_ty, lhs_ty, "shift result")
            }
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Rem
            | BinaryOp::BitAnd
            | BinaryOp::BitOr
            | BinaryOp::BitXor => {
                self.require_integer_type(lhs_ty, "binary left operand")?;
                self.require_same_type(rhs_ty, lhs_ty, "binary right operand")?;
                self.require_same_type(dst_ty, lhs_ty, "binary result")
            }
            BinaryOp::Eq
            | BinaryOp::NotEq
            | BinaryOp::Less
            | BinaryOp::LessEq
            | BinaryOp::Greater
            | BinaryOp::GreaterEq => {
                self.require_scalar_type(lhs_ty, "comparison operand")?;
                self.require_same_type(rhs_ty, lhs_ty, "comparison right operand")?;
                let bool_ty = self.hir.types.primitive("bool").unwrap();
                self.require_same_type(dst_ty, bool_ty, "comparison result")
            }
            BinaryOp::LogicalAnd | BinaryOp::LogicalOr => Err(codegen_error(
                "logical operator escaped short-circuit lowering",
            )),
        }
    }

    fn emit_binary(
        &self,
        dst: ValueId,
        op: BinaryOp,
        lhs: ValueId,
        rhs: ValueId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_binary(dst, op, lhs, rhs)?;
        self.load_value(lhs, "x9", out);
        self.load_value(rhs, "x10", out);
        let signed = is_signed(&self.hir.types.types[self.mir.values[lhs]]);
        match op {
            BinaryOp::Add | BinaryOp::Sub => {
                if let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[lhs]] {
                    let scale = self.hir.types.layout(pointee).size;
                    if scale != 1 {
                        emit_u64("x11", scale, out);
                        out.push_str("  mul x10, x10, x11\n");
                    }
                }
                writeln!(
                    out,
                    "  {} x9, x9, x10",
                    if op == BinaryOp::Add { "add" } else { "sub" }
                )
                .unwrap();
            }
            BinaryOp::Mul => out.push_str("  mul x9, x9, x10\n"),
            BinaryOp::Div | BinaryOp::Rem => {
                // Unlike AMD64 div/idiv, AArch64 returns zero for a zero
                // divisor and does not trap on signed MIN / -1 overflow.
                // Preserve the existing O-core fail-closed arithmetic
                // behavior explicitly before selecting sdiv/udiv.
                out.push_str("  cbnz x10, 1f\n  brk #0\n1:\n");
                if signed && self.hir.types.layout(self.mir.values[lhs]).size == 8 {
                    emit_u64("x11", 0x8000_0000_0000_0000, out);
                    out.push_str(
                        "  cmp x9, x11\n  b.ne 2f\n  cmn x10, #1\n  b.ne 2f\n  brk #0\n2:\n",
                    );
                }
                writeln!(
                    out,
                    "  {} x11, x9, x10",
                    if signed { "sdiv" } else { "udiv" }
                )
                .unwrap();
                if op == BinaryOp::Rem {
                    out.push_str("  msub x9, x11, x10, x9\n");
                } else {
                    out.push_str("  mov x9, x11\n");
                }
            }
            BinaryOp::BitAnd => out.push_str("  and x9, x9, x10\n"),
            BinaryOp::BitOr => out.push_str("  orr x9, x9, x10\n"),
            BinaryOp::BitXor => out.push_str("  eor x9, x9, x10\n"),
            BinaryOp::ShiftLeft => out.push_str("  lsl x9, x9, x10\n"),
            BinaryOp::ShiftRight => out.push_str(if signed {
                "  asr x9, x9, x10\n"
            } else {
                "  lsr x9, x9, x10\n"
            }),
            BinaryOp::Eq
            | BinaryOp::NotEq
            | BinaryOp::Less
            | BinaryOp::LessEq
            | BinaryOp::Greater
            | BinaryOp::GreaterEq => {
                out.push_str("  cmp x9, x10\n");
                let condition = match (op, signed) {
                    (BinaryOp::Eq, _) => "eq",
                    (BinaryOp::NotEq, _) => "ne",
                    (BinaryOp::Less, true) => "lt",
                    (BinaryOp::LessEq, true) => "le",
                    (BinaryOp::Greater, true) => "gt",
                    (BinaryOp::GreaterEq, true) => "ge",
                    (BinaryOp::Less, false) => "lo",
                    (BinaryOp::LessEq, false) => "ls",
                    (BinaryOp::Greater, false) => "hi",
                    (BinaryOp::GreaterEq, false) => "hs",
                    _ => unreachable!(),
                };
                writeln!(out, "  cset x9, {condition}").unwrap();
            }
            BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                return Err(codegen_error(
                    "logical operator escaped short-circuit lowering",
                ));
            }
        }
        self.normalize_scalar("x9", self.mir.values[dst], out)?;
        self.store_value(dst, "x9", out);
        Ok(())
    }

    fn validate_call(
        &self,
        dst: Option<ValueId>,
        function: FunctionId,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        let target = &self.hir.functions[function];
        if target.abi == Abi::SysV64 {
            return Err(codegen_error(
                "extern \"sysv64\" is the AMD64 System V ABI and cannot be called from AArch64",
            ));
        }
        if target.abi == Abi::Interrupt || target.attrs.interrupt {
            return Err(codegen_error(
                "interrupt handler reached AArch64 direct-call lowering",
            ));
        }
        let params = target
            .params
            .iter()
            .map(|local| target.locals[*local].ty)
            .collect::<Vec<_>>();
        self.validate_call_signature(dst, &params, target.result, args)
    }

    fn validate_call_signature(
        &self,
        dst: Option<ValueId>,
        params: &[TypeId],
        result: TypeId,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        if args.len() != params.len() {
            return Err(codegen_error("call argument count mismatch"));
        }
        for (arg, expected) in args.iter().zip(params.iter().copied()) {
            self.require_scalar_type(expected, "direct call argument")?;
            self.require_same_type(self.mir.values[*arg], expected, "direct call argument")?;
            if self.hir.types.is_float(expected) {
                return Err(codegen_error(
                    "floating-point calls are not implemented by the AArch64 backend",
                ));
            }
        }
        let no_result = matches!(self.hir.types.types[result], Type::Void | Type::Never);
        match (dst, no_result) {
            (None, true) => Ok(()),
            (Some(dst), false) => {
                self.require_scalar_type(result, "direct call result")?;
                self.require_same_type(self.mir.values[dst], result, "direct call result")?;
                if self.hir.types.is_float(result) {
                    return Err(codegen_error(
                        "floating-point calls are not implemented by the AArch64 backend",
                    ));
                }
                Ok(())
            }
            _ => Err(codegen_error("direct call result shape mismatch")),
        }
    }

    fn emit_call(
        &self,
        dst: Option<ValueId>,
        function: FunctionId,
        args: &[ValueId],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_call(dst, function, args)?;
        let stack_size = self.emit_call_arguments(args, out);
        writeln!(out, "  bl {}", self.hir.functions[function].symbol).unwrap();
        emit_stack_adjust("add", stack_size, out);
        if let Some(dst) = dst {
            self.normalize_call_result("x0", self.mir.values[dst], out)?;
            self.store_value(dst, "x0", out);
        }
        Ok(())
    }

    fn emit_call_arguments(&self, args: &[ValueId], out: &mut String) -> u64 {
        let stack_size = align_up(args.len().saturating_sub(8) as u64 * 8, 16);
        emit_stack_adjust("sub", stack_size, out);
        for (index, value) in args.iter().skip(8).enumerate() {
            self.load_value(*value, "x9", out);
            emit_address_offset("x10", "sp", index as u64 * 8, out);
            out.push_str("  str x9, [x10]\n");
        }
        for (index, value) in args.iter().take(8).enumerate() {
            self.load_value(*value, &format!("x{index}"), out);
        }
        stack_size
    }

    fn emit_indirect_call(
        &self,
        dst: Option<ValueId>,
        callee: ValueId,
        args: &[ValueId],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let Type::Function {
            params,
            result,
            abi,
        } = &self.hir.types.types[self.mir.values[callee]]
        else {
            return Err(codegen_error("indirect call requires a function value"));
        };
        if *abi == Abi::SysV64 {
            return Err(codegen_error(
                "AMD64 System V ABI cannot be called from AArch64",
            ));
        }
        if *abi == Abi::Interrupt {
            return Err(codegen_error(
                "interrupt handler reached AArch64 indirect-call lowering",
            ));
        }
        self.validate_call_signature(dst, params, *result, args)?;
        let stack_size = self.emit_call_arguments(args, out);
        self.load_value(callee, "x17", out);
        out.push_str("  blr x17\n");
        emit_stack_adjust("add", stack_size, out);
        if let Some(dst) = dst {
            self.normalize_call_result("x0", self.mir.values[dst], out)?;
            self.store_value(dst, "x0", out);
        }
        Ok(())
    }

    fn validate_intrinsic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        match intrinsic {
            Intrinsic::In8
            | Intrinsic::In16
            | Intrinsic::In32
            | Intrinsic::Out8
            | Intrinsic::Out16
            | Intrinsic::Out32 => {
                return Err(codegen_error(
                    "x86 port-I/O intrinsics are unsupported on AArch64",
                ));
            }
            Intrinsic::AtomicLoad
            | Intrinsic::AtomicStore
            | Intrinsic::AtomicExchange
            | Intrinsic::AtomicCompareExchange
            | Intrinsic::AtomicFetchAdd => {
                return self.validate_atomic(dst, intrinsic, args);
            }
            Intrinsic::InvalidatePage => {
                return Err(codegen_error(
                    "invalidate_page is not implemented by the AArch64 backend",
                ));
            }
            Intrinsic::VolatileLoad | Intrinsic::VolatileStore => {
                return Err(codegen_error(
                    "volatile intrinsic escaped MIR memory lowering",
                ));
            }
            _ => {}
        }

        let u64_ty = self.hir.types.primitive("u64").unwrap();
        let signature = match intrinsic {
            Intrinsic::EnableInterrupts | Intrinsic::DisableInterrupts | Intrinsic::Halt => {
                (Vec::new(), None)
            }
            Intrinsic::Syscall(count) if count <= 6 => {
                (vec![u64_ty; count as usize + 1], Some(u64_ty))
            }
            Intrinsic::Syscall(_) => {
                return Err(codegen_error(
                    "AArch64 syscall lowering supports syscall0 through syscall6",
                ));
            }
            _ => unreachable!(),
        };
        if args.len() != signature.0.len() {
            return Err(codegen_error("intrinsic argument count mismatch"));
        }
        for (arg, expected) in args.iter().zip(signature.0) {
            self.require_same_type(self.mir.values[*arg], expected, "intrinsic argument")?;
        }
        self.require_optional_result(dst, signature.1, "intrinsic result")
    }

    fn emit_intrinsic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
        block_id: BlockId,
        instruction_index: usize,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_intrinsic(dst, intrinsic, args)?;
        if matches!(
            intrinsic,
            Intrinsic::AtomicLoad
                | Intrinsic::AtomicStore
                | Intrinsic::AtomicExchange
                | Intrinsic::AtomicCompareExchange
                | Intrinsic::AtomicFetchAdd
        ) {
            return self.emit_atomic(dst, intrinsic, args, block_id, instruction_index, out);
        }
        match intrinsic {
            Intrinsic::EnableInterrupts => out.push_str("  msr daifclr, #2\n  isb\n"),
            Intrinsic::DisableInterrupts => out.push_str("  msr daifset, #2\n  isb\n"),
            Intrinsic::Halt => out.push_str("  wfi\n"),
            Intrinsic::Syscall(count) => {
                self.load_value(args[0], "x8", out);
                for (index, value) in args[1..].iter().take(count as usize).enumerate() {
                    self.load_value(*value, &format!("x{index}"), out);
                }
                out.push_str("  svc #0\n");
            }
            _ => unreachable!(),
        }
        if let Some(dst) = dst {
            self.normalize_scalar("x0", self.mir.values[dst], out)?;
            self.store_value(dst, "x0", out);
        }
        Ok(())
    }

    fn const_from_value(&self, value: ValueId) -> Option<u64> {
        self.mir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find_map(|instruction| {
                if let Instruction::Const {
                    dst,
                    value: constant,
                } = instruction
                {
                    (*dst == value).then_some(*constant)
                } else {
                    None
                }
            })
    }

    fn validate_atomic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        let (value_count, order_count) = match intrinsic {
            Intrinsic::AtomicLoad => (0, 1),
            Intrinsic::AtomicStore | Intrinsic::AtomicExchange | Intrinsic::AtomicFetchAdd => {
                (1, 1)
            }
            Intrinsic::AtomicCompareExchange => (2, 2),
            _ => unreachable!(),
        };
        if args.len() != 1 + value_count + order_count {
            return Err(codegen_error("atomic intrinsic argument count mismatch"));
        }
        let Type::Pointer { mutable, pointee } = self.hir.types.types[self.mir.values[args[0]]]
        else {
            return Err(codegen_error("atomic intrinsic requires a pointer"));
        };
        self.require_integer_type(pointee, "atomic pointee")?;
        if !matches!(self.hir.types.layout(pointee).size, 1 | 2 | 4 | 8) {
            return Err(codegen_error(
                "atomic pointee must be a 1/2/4/8-byte integer",
            ));
        }
        if !mutable && intrinsic != Intrinsic::AtomicLoad {
            return Err(codegen_error("mutating atomic intrinsic requires *mut"));
        }
        for value in &args[1..1 + value_count] {
            self.require_same_type(self.mir.values[*value], pointee, "atomic value")?;
        }
        let u8_ty = self.hir.types.primitive("u8").unwrap();
        let mut orders = Vec::new();
        for value in &args[1 + value_count..] {
            self.require_same_type(self.mir.values[*value], u8_ty, "atomic ordering")?;
            let order = self
                .const_from_value(*value)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| codegen_error("atomic ordering must be constant in MIR"))?;
            super::typeck::validate_memory_order(intrinsic, order).map_err(codegen_error)?;
            orders.push(order);
        }
        if intrinsic == Intrinsic::AtomicCompareExchange {
            let success = orders[0];
            let failure = orders[1];
            let allowed = match success {
                x if x == MemoryOrder::Relaxed as u8 => failure == MemoryOrder::Relaxed as u8,
                x if x == MemoryOrder::Acquire as u8 => {
                    matches!(failure, y if y == MemoryOrder::Relaxed as u8 || y == MemoryOrder::Acquire as u8)
                }
                x if x == MemoryOrder::Release as u8 => failure == MemoryOrder::Relaxed as u8,
                x if x == MemoryOrder::AcqRel as u8 => {
                    matches!(failure, y if y == MemoryOrder::Relaxed as u8 || y == MemoryOrder::Acquire as u8)
                }
                _ => {
                    matches!(failure, y if y == MemoryOrder::Relaxed as u8 || y == MemoryOrder::Acquire as u8 || y == MemoryOrder::SeqCst as u8)
                }
            };
            if !allowed {
                return Err(codegen_error(
                    "compare-exchange failure order must not release or exceed success order",
                ));
            }
        }
        self.require_optional_result(
            dst,
            (intrinsic != Intrinsic::AtomicStore).then_some(pointee),
            "atomic result",
        )
    }

    fn emit_atomic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
        block_id: BlockId,
        instruction_index: usize,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[args[0]]] else {
            unreachable!()
        };
        let size = self.hir.types.layout(pointee).size;
        let order_index = match intrinsic {
            Intrinsic::AtomicLoad => 1,
            Intrinsic::AtomicCompareExchange => 3,
            _ => 2,
        };
        let success = self.const_from_value(args[order_index]).unwrap();
        let failure = if intrinsic == Intrinsic::AtomicCompareExchange {
            self.const_from_value(args[order_index + 1]).unwrap()
        } else {
            MemoryOrder::Relaxed as u64
        };
        let sequential =
            success == MemoryOrder::SeqCst as u64 || failure == MemoryOrder::SeqCst as u64;
        let acquire = sequential
            || success == MemoryOrder::Acquire as u64
            || success == MemoryOrder::AcqRel as u64
            || failure == MemoryOrder::Acquire as u64;
        let release = sequential
            || success == MemoryOrder::Release as u64
            || success == MemoryOrder::AcqRel as u64;
        self.load_value(args[0], "x10", out);
        if size > 1 {
            writeln!(out, "  tst x10, #{}\n  b.eq 1f\n  brk #0\n1:", size - 1).unwrap();
        }
        if sequential {
            out.push_str("  dmb ish\n");
        }
        let suffix = match size {
            1 => "b",
            2 => "h",
            _ => "",
        };
        let result_reg = if size == 8 { "x9" } else { "w9" };
        let desired_reg = if size == 8 { "x12" } else { "w12" };
        match intrinsic {
            Intrinsic::AtomicLoad => {
                if acquire {
                    writeln!(out, "  ldar{suffix} {result_reg}, [x10]").unwrap();
                } else {
                    self.load_memory("x9", "x10", pointee, out)?;
                }
            }
            Intrinsic::AtomicStore => {
                self.load_value(args[1], "x12", out);
                if release {
                    writeln!(out, "  stlr{suffix} {desired_reg}, [x10]").unwrap();
                } else {
                    self.store_memory("x12", "x10", pointee, out)?;
                }
            }
            _ => {
                self.load_value(args[1], "x11", out);
                if intrinsic == Intrinsic::AtomicCompareExchange {
                    self.load_value(args[2], "x12", out);
                }
                let label = format!(
                    "{}_bb{}_atomic{}",
                    self.label_prefix, block_id, instruction_index
                );
                writeln!(out, "{label}_retry:").unwrap();
                writeln!(
                    out,
                    "  {}{suffix} {result_reg}, [x10]",
                    if acquire { "ldaxr" } else { "ldxr" }
                )
                .unwrap();
                if intrinsic == Intrinsic::AtomicCompareExchange {
                    self.normalize_scalar("x9", pointee, out)?;
                    out.push_str("  cmp x9, x11\n");
                    writeln!(out, "  b.ne {label}_mismatch").unwrap();
                } else if intrinsic == Intrinsic::AtomicFetchAdd {
                    out.push_str("  add x12, x9, x11\n");
                } else {
                    out.push_str("  mov x12, x11\n");
                }
                writeln!(
                    out,
                    "  {}{suffix} w13, {desired_reg}, [x10]",
                    if release { "stlxr" } else { "stxr" }
                )
                .unwrap();
                writeln!(out, "  cbnz w13, {label}_retry").unwrap();
                if intrinsic == Intrinsic::AtomicCompareExchange {
                    writeln!(
                        out,
                        "  b {label}_done\n{label}_mismatch:\n  clrex\n{label}_done:"
                    )
                    .unwrap();
                }
            }
        }
        if sequential {
            out.push_str("  dmb ish\n");
        }
        if let Some(dst) = dst {
            self.normalize_scalar("x9", pointee, out)?;
            self.store_value(dst, "x9", out);
        }
        Ok(())
    }

    fn emit_asm(
        &self,
        template: &str,
        operands: &[MirAsmOperand],
        options: &[String],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let mut used_registers = std::collections::HashSet::new();
        let mut outputs = Vec::new();
        let mut inputs = Vec::new();
        let mut seen_options = std::collections::HashSet::new();
        for option in options {
            if !matches!(
                option.as_str(),
                "nomem" | "readonly" | "nostack" | "preserves_flags"
            ) || !seen_options.insert(option.as_str())
            {
                return Err(codegen_error("invalid or repeated inline assembly option"));
            }
        }
        if seen_options.contains("nomem") && seen_options.contains("readonly") {
            return Err(codegen_error(
                "asm options nomem and readonly are redundant",
            ));
        }
        for (index, operand) in operands.iter().enumerate() {
            let (register, input, output) = match operand {
                MirAsmOperand::In { register, value } => (register, Some(*value), None),
                MirAsmOperand::Out { register, target } => (register, None, Some(target)),
                MirAsmOperand::InOut {
                    register,
                    input,
                    output,
                } => (register, Some(*input), Some(output)),
            };
            let (number, width) = asm_register(register)?;
            if !used_registers.insert(number) {
                return Err(codegen_error(
                    "inline assembly operands overlap the same physical register",
                ));
            }
            if let Some(value) = input {
                self.require_asm_type(self.mir.values[value], width)?;
                inputs.push((number, width, value, index as u64 * 8));
            }
            if let Some(target) = output {
                self.require_asm_type(target.ty, width)?;
                if let Some(value) = input {
                    self.require_same_type(
                        self.mir.values[value],
                        target.ty,
                        "assembly inout operand",
                    )?;
                }
                outputs.push((number, target, index as u64 * 8));
            }
        }
        // Capture every input before assigning explicit registers. Preserve the
        // compiler frame anchors even when the template uses x28/x29 itself.
        let context_offset = align_up(operands.len() as u64 * 8, 16);
        let size = context_offset + 16;
        emit_stack_adjust("sub", size, out);
        writeln!(out, "  stp x28, x29, [sp, #{context_offset}]").unwrap();
        for (_, _, value, offset) in &inputs {
            self.load_value(*value, "x9", out);
            writeln!(out, "  str x9, [sp, #{offset}]").unwrap();
        }
        for (register, width, _, offset) in &inputs {
            writeln!(
                out,
                "  ldr {}{register}, [sp, #{offset}]",
                if *width == 4 { "w" } else { "x" }
            )
            .unwrap();
        }
        for line in template.lines() {
            writeln!(out, "  {line}").unwrap();
        }
        for (register, _, offset) in &outputs {
            writeln!(out, "  str x{register}, [sp, #{offset}]").unwrap();
        }
        writeln!(out, "  ldp x28, x29, [sp, #{context_offset}]").unwrap();
        for (_, target, offset) in outputs {
            writeln!(out, "  ldr x9, [sp, #{offset}]").unwrap();
            self.normalize_scalar("x9", target.ty, out)?;
            self.place_address(target, "x10", out)?;
            self.store_place_memory("x9", "x10", target, out)?;
        }
        emit_stack_adjust("add", size, out);
        Ok(())
    }

    fn require_asm_type(&self, ty: TypeId, width: u64) -> Result<(), Diagnostic> {
        self.require_scalar_type(ty, "inline assembly operand")?;
        if self.hir.types.is_float(ty) || self.hir.types.layout(ty).size > width {
            return Err(codegen_error(
                "inline assembly register width does not hold non-floating scalar operand",
            ));
        }
        Ok(())
    }

    fn emit_terminator(
        &self,
        block_id: BlockId,
        terminator: &Terminator,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        match terminator {
            Terminator::Pending => return Err(codegen_error("MIR block has no terminator")),
            Terminator::Unreachable => out.push_str("  brk #0\n"),
            Terminator::Return(value) => {
                let no_result = matches!(
                    self.hir.types.types[self.source.result],
                    Type::Void | Type::Never
                );
                match (value, no_result) {
                    (Some(value), false) => {
                        self.require_scalar_type(self.source.result, "return value")?;
                        self.require_same_type(
                            self.mir.values[*value],
                            self.source.result,
                            "return value",
                        )?;
                        if self.hir.types.is_float(self.source.result) {
                            return Err(codegen_error(
                                "floating-point returns are not implemented by the AArch64 backend",
                            ));
                        }
                        self.load_value(*value, "x0", out);
                    }
                    (None, true) => {}
                    _ => return Err(codegen_error("return value shape mismatch")),
                }
                self.emit_epilogue(out);
            }
            Terminator::Jump(target) => {
                self.emit_phi_moves(block_id, *target, out)?;
                writeln!(out, "  b {}_bb{target}", self.label_prefix).unwrap();
            }
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => {
                let bool_ty = self.hir.types.primitive("bool").unwrap();
                self.require_same_type(self.mir.values[*condition], bool_ty, "branch condition")?;
                let then_edge = format!("{}_bb{}_then_edge", self.label_prefix, block_id);
                self.load_value(*condition, "x9", out);
                writeln!(out, "  cbnz x9, {then_edge}").unwrap();
                self.emit_phi_moves(block_id, *else_block, out)?;
                writeln!(out, "  b {}_bb{else_block}", self.label_prefix).unwrap();
                writeln!(out, "{then_edge}:").unwrap();
                self.emit_phi_moves(block_id, *then_block, out)?;
                writeln!(out, "  b {}_bb{then_block}", self.label_prefix).unwrap();
            }
        }
        Ok(())
    }

    fn emit_phi_moves(
        &self,
        from: BlockId,
        to: BlockId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let block = self
            .mir
            .blocks
            .get(to)
            .ok_or_else(|| codegen_error("phi successor block does not exist"))?;
        let mut copies = Vec::new();
        for instruction in &block.instructions {
            let Instruction::Phi { dst, incoming } = instruction else {
                continue;
            };
            if let Some((_, value)) = incoming.iter().find(|(block, _)| *block == from) {
                self.require_same_type(
                    self.mir.values[*value],
                    self.mir.values[*dst],
                    "phi incoming value",
                )?;
                self.require_scalar_type(self.mir.values[*dst], "phi result")?;
                copies.push((*dst, *value));
            } else {
                return Err(codegen_error("phi has no incoming value for predecessor"));
            }
        }
        // Read every source before writing any destination: a pair of loop
        // phis may swap values whose source/destination spill slots overlap.
        for (index, (_, value)) in copies.iter().enumerate() {
            self.load_value(*value, "x9", out);
            emit_frame_address("x15", self.frame.phi_temps[index], out);
            out.push_str("  str x9, [x15]\n");
        }
        for (index, (dst, _)) in copies.iter().enumerate() {
            emit_frame_address("x15", self.frame.phi_temps[index], out);
            out.push_str("  ldr x9, [x15]\n");
            self.store_value(*dst, "x9", out);
        }
        Ok(())
    }

    fn emit_epilogue(&self, out: &mut String) {
        for (register, offset) in &self.frame.callee_saves {
            emit_frame_address("x15", *offset, out);
            writeln!(out, "  ldr x{register}, [x15]").unwrap();
        }
        out.push_str(
            "  sub sp, x29, #16\n  ldp x28, xzr, [sp], #16\n  ldp x29, x30, [sp], #16\n  ret\n",
        );
    }

    fn place_address(
        &self,
        place: &Place,
        register: &str,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        match place.base {
            PlaceBase::Local(local) => {
                emit_frame_address(register, self.frame.locals[local], out);
            }
            PlaceBase::Static(static_id) => {
                emit_symbol_address(register, &self.hir.statics[static_id].symbol, out);
            }
            PlaceBase::Pointer(value) => {
                if !matches!(
                    self.hir.types.types[self.mir.values[value]],
                    Type::Pointer { .. }
                ) {
                    return Err(codegen_error("place base is not a pointer"));
                }
                self.load_value(value, register, out);
            }
        }
        for projection in &place.projections {
            match projection {
                Projection::Field { offset } => {
                    if *offset != 0 {
                        let scratch = scratch_other_than(register, "x16", "x14");
                        emit_u64(scratch, *offset, out);
                        writeln!(out, "  add {register}, {register}, {scratch}").unwrap();
                    }
                }
                Projection::Index {
                    index,
                    element_size,
                } => {
                    self.require_integer_type(self.mir.values[*index], "place index")?;
                    let index_register = scratch_other_than(register, "x17", "x13");
                    self.load_value(*index, index_register, out);
                    if *element_size != 1 {
                        let scale_register = if register != "x16" && index_register != "x16" {
                            "x16"
                        } else {
                            "x14"
                        };
                        emit_u64(scale_register, *element_size, out);
                        writeln!(
                            out,
                            "  mul {index_register}, {index_register}, {scale_register}"
                        )
                        .unwrap();
                    }
                    writeln!(out, "  add {register}, {register}, {index_register}").unwrap();
                }
            }
        }
        Ok(())
    }

    fn load_value(&self, value: ValueId, register: &str, out: &mut String) {
        let address = frame_address_scratch(register);
        emit_frame_address(address, self.frame.values[value], out);
        writeln!(out, "  ldr {register}, [{address}]").unwrap();
    }

    fn store_value(&self, value: ValueId, register: &str, out: &mut String) {
        let address = frame_address_scratch(register);
        emit_frame_address(address, self.frame.values[value], out);
        writeln!(out, "  str {register}, [{address}]").unwrap();
    }

    fn store_reg_to_frame(
        &self,
        register: &str,
        offset: u64,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let address = frame_address_scratch(register);
        emit_frame_address(address, offset, out);
        self.store_memory(register, address, ty, out)
    }

    fn place_alignment(&self, place: &Place) -> u64 {
        let mut align = match place.base {
            PlaceBase::Local(local) => self.hir.types.layout(self.mir.local_types[local]).align,
            PlaceBase::Static(id) => self.hir.statics[id]
                .attrs
                .align
                .unwrap_or_else(|| self.hir.types.layout(self.hir.statics[id].ty).align),
            // Raw pointers have no MIR alignment provenance. Ordinary memory
            // accesses must also work for pointers to packed fields when the
            // target enables strict alignment checks.
            PlaceBase::Pointer(_) => 1,
        };
        for projection in &place.projections {
            let offset = match projection {
                Projection::Field { offset } => *offset,
                Projection::Index { element_size, .. } => *element_size,
            };
            if offset != 0 {
                align = align.min(1u64 << offset.trailing_zeros());
            }
        }
        align
    }

    fn guard_volatile_alignment(&self, address: &str, place: &Place, out: &mut String) {
        let size = self.hir.types.layout(place.ty).size;
        if size > 1 && self.place_alignment(place) < size {
            // A device access must remain one access of its declared width.
            // Trap before touching misaligned memory rather than split it.
            writeln!(
                out,
                "  tst {address}, #{}\n  b.eq 1f\n  brk #0\n1:",
                size - 1
            )
            .unwrap();
        }
    }

    fn load_place_memory(
        &self,
        dst: &str,
        address: &str,
        place: &Place,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let size = self.hir.types.layout(place.ty).size;
        if self.place_alignment(place) >= size {
            return self.load_memory(dst, address, place.ty, out);
        }
        writeln!(out, "  mov {dst}, #0").unwrap();
        for index in 0..size {
            writeln!(
                out,
                "  ldrb w14, [{address}, #{index}]\n  orr {dst}, {dst}, x14, lsl #{}",
                index * 8
            )
            .unwrap();
        }
        self.normalize_scalar(dst, place.ty, out)
    }

    fn store_place_memory(
        &self,
        src: &str,
        address: &str,
        place: &Place,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let size = self.hir.types.layout(place.ty).size;
        if self.place_alignment(place) >= size {
            return self.store_memory(src, address, place.ty, out);
        }
        let wsrc = wreg(src)?;
        writeln!(out, "  strb {wsrc}, [{address}]").unwrap();
        for index in 1..size {
            writeln!(
                out,
                "  lsr x14, {src}, #{}\n  strb w14, [{address}, #{index}]",
                index * 8
            )
            .unwrap();
        }
        Ok(())
    }

    fn load_memory(
        &self,
        dst: &str,
        address: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let size = self.hir.types.layout(ty).size;
        let signed = is_signed(&self.hir.types.types[ty]);
        let wdst = wreg(dst)?;
        match (size, signed) {
            (1, false) => writeln!(out, "  ldrb {wdst}, [{address}]").unwrap(),
            (1, true) => writeln!(out, "  ldrsb {dst}, [{address}]").unwrap(),
            (2, false) => writeln!(out, "  ldrh {wdst}, [{address}]").unwrap(),
            (2, true) => writeln!(out, "  ldrsh {dst}, [{address}]").unwrap(),
            (4, false) => writeln!(out, "  ldr {wdst}, [{address}]").unwrap(),
            (4, true) => writeln!(out, "  ldrsw {dst}, [{address}]").unwrap(),
            (8, _) => writeln!(out, "  ldr {dst}, [{address}]").unwrap(),
            _ => return Err(codegen_error(format!("cannot scalar-load {size} bytes"))),
        }
        if matches!(self.hir.types.types[ty], Type::Bool) {
            self.normalize_scalar(dst, ty, out)?;
        }
        Ok(())
    }

    fn store_memory(
        &self,
        src: &str,
        address: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let size = self.hir.types.layout(ty).size;
        let wsrc = wreg(src)?;
        match size {
            1 => writeln!(out, "  strb {wsrc}, [{address}]").unwrap(),
            2 => writeln!(out, "  strh {wsrc}, [{address}]").unwrap(),
            4 => writeln!(out, "  str {wsrc}, [{address}]").unwrap(),
            8 => writeln!(out, "  str {src}, [{address}]").unwrap(),
            _ => return Err(codegen_error(format!("cannot scalar-store {size} bytes"))),
        }
        Ok(())
    }

    fn normalize_scalar(
        &self,
        register: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        if matches!(self.hir.types.types[ty], Type::Bool) {
            writeln!(out, "  cmp {register}, #0\n  cset {register}, ne").unwrap();
            return Ok(());
        }
        let size = self.hir.types.layout(ty).size;
        let signed = is_signed(&self.hir.types.types[ty]);
        let wregister = wreg(register)?;
        match (size, signed) {
            (1, false) => writeln!(out, "  uxtb {wregister}, {wregister}").unwrap(),
            (1, true) => writeln!(out, "  sxtb {register}, {wregister}").unwrap(),
            (2, false) => writeln!(out, "  uxth {wregister}, {wregister}").unwrap(),
            (2, true) => writeln!(out, "  sxth {register}, {wregister}").unwrap(),
            (4, false) => writeln!(out, "  mov {wregister}, {wregister}").unwrap(),
            (4, true) => writeln!(out, "  sxtw {register}, {wregister}").unwrap(),
            (8, _) | (0, _) => {}
            _ => {
                return Err(codegen_error(format!(
                    "cannot normalize {size}-byte scalar"
                )));
            }
        }
        Ok(())
    }

    fn normalize_call_result(
        &self,
        register: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        if matches!(self.hir.types.types[ty], Type::Bool) {
            // AAPCS64 leaves bits above the returned scalar width undefined.
            // Casts examine all source bits, but a boolean ABI result only
            // defines its low byte; discard the rest before canonicalizing.
            let wregister = wreg(register)?;
            writeln!(out, "  uxtb {wregister}, {wregister}").unwrap();
        }
        self.normalize_scalar(register, ty, out)
    }

    fn require_optional_result(
        &self,
        actual: Option<ValueId>,
        expected: Option<TypeId>,
        context: &str,
    ) -> Result<(), Diagnostic> {
        match (actual, expected) {
            (None, None) => Ok(()),
            (Some(value), Some(ty)) => self.require_same_type(self.mir.values[value], ty, context),
            _ => Err(codegen_error(format!("{context} shape mismatch"))),
        }
    }

    fn require_same_type(
        &self,
        actual: TypeId,
        expected: TypeId,
        context: &str,
    ) -> Result<(), Diagnostic> {
        if actual == expected {
            Ok(())
        } else {
            Err(codegen_error(format!("{context} type mismatch")))
        }
    }

    fn require_scalar_type(&self, ty: TypeId, context: &str) -> Result<(), Diagnostic> {
        if self.hir.types.is_scalar(ty) {
            Ok(())
        } else {
            Err(codegen_error(format!("{context} requires a scalar type")))
        }
    }

    fn require_integer_type(&self, ty: TypeId, context: &str) -> Result<(), Diagnostic> {
        if self.hir.types.is_integer(ty) {
            Ok(())
        } else {
            Err(codegen_error(format!("{context} requires an integer type")))
        }
    }
}

fn emit_u64(register: &str, value: u64, out: &mut String) {
    let low = value & 0xffff;
    writeln!(out, "  movz {register}, #0x{low:x}").unwrap();
    for shift in [16u32, 32, 48] {
        let part = (value >> shift) & 0xffff;
        if part != 0 {
            writeln!(out, "  movk {register}, #0x{part:x}, lsl #{shift}").unwrap();
        }
    }
}

fn emit_symbol_address(register: &str, symbol: &str, out: &mut String) {
    writeln!(out, "  adrp {register}, {symbol}").unwrap();
    writeln!(out, "  add {register}, {register}, :lo12:{symbol}").unwrap();
}

fn emit_frame_address(register: &str, offset: u64, out: &mut String) {
    emit_address_offset(register, "x28", offset, out);
}

fn emit_address_offset(register: &str, base: &str, offset: u64, out: &mut String) {
    if offset <= 4095 {
        writeln!(out, "  add {register}, {base}, #{offset}").unwrap();
    } else {
        let scratch = scratch_other_than(register, "x16", "x14");
        emit_u64(scratch, offset, out);
        writeln!(out, "  add {register}, {base}, {scratch}").unwrap();
    }
}

fn emit_stack_adjust(op: &str, size: u64, out: &mut String) {
    if size == 0 {
        return;
    }
    if size <= 4095 {
        writeln!(out, "  {op} sp, sp, #{size}").unwrap();
    } else if size & 4095 == 0 && size >> 12 <= 4095 {
        writeln!(out, "  {op} sp, sp, #{}, lsl #12", size >> 12).unwrap();
    } else {
        emit_u64("x16", size, out);
        writeln!(out, "  {op} sp, sp, x16").unwrap();
    }
}

fn checked_align_up(value: u64, alignment: u64) -> Result<u64, Diagnostic> {
    if !alignment.is_power_of_two() {
        return Err(codegen_error("frame alignment must be a power of two"));
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or_else(|| codegen_error("AArch64 frame size overflow"))
}

fn asm_register(register: &str) -> Result<(u8, u64), Diagnostic> {
    let register = register.to_ascii_lowercase();
    let (number, width) = if let Some(number) = register.strip_prefix('x') {
        (number, 8)
    } else if let Some(number) = register.strip_prefix('w') {
        (number, 4)
    } else {
        return Err(codegen_error(
            "inline assembly requires an explicit xN/wN register",
        ));
    };
    let number = number
        .parse::<u8>()
        .map_err(|_| codegen_error("invalid inline assembly register"))?;
    if number > 30 || number == 18 {
        return Err(codegen_error(
            "SP/zero/platform registers are not inline assembly operands",
        ));
    }
    Ok((number, width))
}

fn frame_address_scratch(register: &str) -> &'static str {
    scratch_other_than(register, "x15", "x14")
}

fn scratch_other_than(
    register: &str,
    preferred: &'static str,
    fallback: &'static str,
) -> &'static str {
    if register == preferred {
        fallback
    } else {
        preferred
    }
}

fn wreg(register: &str) -> Result<String, Diagnostic> {
    let Some(index) = register.strip_prefix('x') else {
        return Err(codegen_error(format!(
            "unsupported AArch64 register `{register}`"
        )));
    };
    let number = index
        .parse::<u8>()
        .map_err(|_| codegen_error(format!("unsupported AArch64 register `{register}`")))?;
    if number > 30 {
        return Err(codegen_error(format!(
            "unsupported AArch64 register `{register}`"
        )));
    }
    Ok(format!("w{number}"))
}

fn is_signed(ty: &Type) -> bool {
    matches!(ty, Type::Int { signed: true, .. } | Type::Isize)
}

fn codegen_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        file: "<aarch64-codegen>".into(),
        span: Span::default(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocore::{mir, parser, typeck};

    fn assembly(source: &str) -> Result<String, Diagnostic> {
        let ast = parser::parse("aarch64-test.oc", source)?;
        let hir = typeck::check(&[("aarch64-test.oc".into(), ast)])?;
        let mir = mir::lower(&hir)?;
        emit_assembly(&hir, &mir)
    }

    fn sectioned_assembly(source: &str) -> Result<String, Diagnostic> {
        let ast = parser::parse("aarch64-test.oc", source)?;
        let hir = typeck::check(&[("aarch64-test.oc".into(), ast)])?;
        let mir = mir::lower(&hir)?;
        emit_assembly_with_function_sections(&hir, &mir, true)
    }

    #[test]
    fn emits_aapcs64_scalar_memory_calls_and_control_flow() {
        let asm = assembly(
            r#"
module arm;
static mut TOTAL: u64 = 7;
fn add(left: u64, right: u64) -> u64 { return left + right; }
@export @no_mangle
unsafe fn exercise(pointer: *mut u64, left: u64, right: u64) -> u64 {
    let current: u64 = volatile_load(pointer);
    volatile_store(pointer, current + 1);
    if left < right {
        return add(current, left);
    }
    return current - right;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("exercise:"));
        assert!(asm.contains("bl _O_arm__add"));
        assert!(asm.contains("ldr x9, [x10]"));
        assert!(asm.contains("str x9, [x10]"));
        assert!(asm.contains("cset x9, lo"));
        assert!(asm.contains("cbnz x9"));
        assert!(asm.contains("stp x29, x30"));
    }

    #[test]
    fn emits_opt_in_function_sections() {
        let asm = sectioned_assembly(
            "module arm_sections; fn add(a: u64, b: u64) -> u64 { return a + b; }",
        )
        .unwrap();
        assert!(asm.contains(".section .text.ocore_fn._O_arm_sections__add"));
    }

    #[test]
    fn emits_syscall_interrupt_masks_and_halt() {
        let asm = assembly(
            r#"
module system;
@export @no_mangle
unsafe fn invoke(number: u64, value: u64) -> u64 {
    return syscall1(number, value);
}
@export @no_mangle
unsafe fn idle() -> never {
    disable_interrupts();
    enable_interrupts();
    loop { halt(); }
}
"#,
        )
        .unwrap();
        assert!(asm.contains("ldr x8"));
        assert!(asm.contains("ldr x0"));
        assert!(asm.contains("svc #0"));
        assert!(asm.contains("msr daifset, #2"));
        assert!(asm.contains("msr daifclr, #2"));
        assert!(asm.contains("wfi"));
    }

    #[test]
    fn rejects_unimplemented_target_features() {
        let port_error = assembly(
            r#"
module target_error;
unsafe fn read_port() -> u8 { return inb(0x3f8); }
"#,
        )
        .unwrap_err();
        assert!(port_error.message.contains("port-I/O"));

        let invalidate_error = assembly(
            r#"
module target_error;
unsafe fn invalidate(address: usize) -> void { invalidate_page(address); }
"#,
        )
        .unwrap_err();
        assert!(invalidate_error.message.contains("invalidate_page"));
    }

    #[test]
    fn emits_stack_arguments_and_indirect_calls() {
        let asm = assembly(
            r#"
module many;
fn many(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64) -> u64 {
    return a + b + c + d + e + f + g + h + i + j;
}
@export @no_mangle
unsafe fn exercise() -> u64 {
    let callback: fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 = many;
    let direct: u64 = many(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    return callback(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) - direct + 42;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("add x10, x29, #16"));
        assert!(asm.contains("add x10, x29, #24"));
        assert!(asm.contains("bl _O_many__many"));
        assert!(asm.contains("blr x17"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn assembles_large_aligned_frames_and_aggregate_places() {
        let asm = assembly(
            r#"
module aggregate;
@packed struct Packed { tag: u8, value: i64 }
@align(64) struct Aligned { value: u64 }
enum Optional { absent, present(u64) }
static ZEROES: [u8; 8193] = [0; 8193];
static mut ITEM: Packed = Packed { tag: 3, value: 0 };
@export @no_mangle
unsafe fn exercise() -> u64 {
    ITEM.value = -(17 as i64);
    let local: Aligned = Aligned { value: 42 };
    let address: usize = ((&local) as usize);
    let mut bytes: [u8; 8193] = ZEROES;
    bytes[8192] = 42;
    let first: Packed = ITEM;
    let mut second: Packed = Packed { tag: 0, value: 0 };
    second = first;
    let state: Optional = Optional::present(9);
    if (address & 63) != 0 { return 1; }
    if second.value != -(17 as i64) { return 2; }
    return bytes[8192] as u64;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("bic x17, x17, x16"));
        assert!(asm.contains("sub sp, sp, x16"));
        assert!(asm.contains("ldrsw") || asm.contains("ldr x9"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn stages_assembly_operands_and_preserves_frame_and_callee_registers() {
        let asm = assembly(
            r#"
module explicit_asm;
@export @no_mangle
unsafe fn exercise() -> u64 {
    let mut first: u64 = 0;
    let mut second: u64 = 0;
    asm!("add x17, x15, x16\nmov x28, #7\nmov x29, #8\nmov x19, #99\nmov x30, #9",
        in("x15") 17 as u64, in("x16") 25 as u64,
        out("x17") first, out("x28") second);
    if second != 7 { return 1; }
    return first;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("str x19, [x15]"));
        assert!(asm.contains("ldr x19, [x15]"));
        assert!(asm.contains("stp x28, x29, [sp"));
        assert!(asm.contains("ldp x28, x29, [sp"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);

        let error = assembly(
            r#"
module overlap;
unsafe fn invalid(value: u32) -> void {
    let mut output: u32 = 0;
    asm!("nop", in("x0") value, out("w0") output);
}
"#,
        )
        .unwrap_err();
        assert!(error.message.contains("overlap"));
    }

    #[test]
    fn overlapping_aggregate_assignments_preserve_source_snapshots() {
        let asm = assembly(
            r#"
module overlapping;
@export @no_mangle
unsafe fn exercise() -> u64 {
    let mut bytes: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let base: *mut u8 = &mut bytes[0];
    let source: *mut [u8; 8] = base as *mut [u8; 8];
    let destination: *mut [u8; 8] = (base + 2) as *mut [u8; 8];
    *destination = *source;
    if bytes[9] != 8 { return 1; }
    *source = *destination;
    if bytes[7] != 8 { return 2; }
    *source = *source;
    return (bytes[7] as u64) + 34;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("ldrb w13, [x11, #-1]!"));
        assert!(asm.contains("b.eq .L_ocore_aarch64_"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn packed_pointer_accesses_use_bytes_and_preserve_signed_values() {
        let asm = assembly(
            r#"
module packed_pointer;
@packed struct Packed { tag: u8, value: i64 }
@export @no_mangle
unsafe fn exercise() -> u64 {
    let mut packed: Packed = Packed { tag: 7, value: -19 };
    let pointer: *mut i64 = &mut packed.value;
    *pointer = -31;
    if *pointer != -31 || packed.tag != 7 { return 1; }
    return 42;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("ldrb w14, [x10, #7]"));
        assert!(asm.contains("strb w14, [x10, #7]"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn repeat_operands_evaluate_once_and_aggregate_temporaries_execute() {
        let asm = assembly(
            r#"
module repeat_effect;
struct Pair { first: u64, second: u64 }
static mut COUNT: u64 = 0;
unsafe fn step() -> u64 { COUNT += 1; return COUNT; }
@export @no_mangle
unsafe fn exercise() -> u64 {
    let values: [u64; 3] = [step(); 3];
    if COUNT != 1 || values[0] != 1 || values[2] != 1 { return 1; }
    let empty: [u64; 0] = [step(); 0];
    if COUNT != 2 { return 2; }
    let pairs: [Pair; 3] = [Pair { first: step(), second: 7 }; 3];
    if COUNT != 3 || pairs[0].first != 3 || pairs[2].first != 3 || pairs[2].second != 7 { return 3; }
    let nested: [[u64; 2]; 3] = [[step(); 2]; 3];
    if COUNT != 4 || nested[2][1] != 4 { return 4; }
    let empty_pairs: [Pair; 0] = [Pair { first: step(), second: 7 }; 0];
    if COUNT != 5 { return 5; }
    return 42;
}
"#,
        ).unwrap();
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn boolean_casts_and_assembly_outputs_are_canonical() {
        let asm = assembly(
            r#"
module boolean_casts;
@export @no_mangle
unsafe fn exercise() -> u64 {
    let zero: bool = 0 as bool;
    let two: bool = 2 as bool;
    let wide: bool = 256 as bool;
    let high: bool = 0x8000000000000000 as bool;
    if zero || !two || !wide || !high { return 1; }
    if (two as u64) != 1 || (wide as u64) != 1 { return 2; }
    let mut output: bool = false;
    asm!("mov x0, #256", out("x0") output);
    if !output || (output as u64) != 1 { return 3; }
    let mut byte: u8 = 2;
    let pointer: *mut bool = (&mut byte) as *mut bool;
    if !*pointer || (volatile_load(pointer) as u64) != 1 { return 4; }
    byte = 0;
    if *pointer || volatile_load(pointer) { return 5; }
    return 42;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("cmp x9, #0\n  cset x9, ne"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn boolean_abi_results_discard_undefined_upper_register_bits() {
        let asm = assembly(
            r#"
module boolean_results;
extern "C" fn foreign_false() -> bool;
extern "C" fn foreign_true() -> bool;
@export @no_mangle
unsafe fn exercise() -> u64 {
    if foreign_false() || !foreign_true() { return 1; }
    let mut callback: extern "C" fn() -> bool = foreign_false;
    if callback() { return 2; }
    callback = foreign_true;
    if !callback() { return 3; }
    return 42;
}
"#,
        )
        .unwrap();
        let asm = format!(
            "{asm}\n.text\nforeign_false:\nmov x0,#256\nret\nforeign_true:\nmov x0,#257\nret\n"
        );
        assert!(asm.contains("uxtb w0, w0\n  cmp x0, #0\n  cset x0, ne"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn negative_static_tables_emit_declared_widths_and_load_signed_minima() {
        let asm = assembly(
            r#"
module negative_statics;
static BYTE:i8=-128;
static HALF:i16=-32768;
static WORD:i32=-2147483648;
static DOUBLE:i64=-9223372036854775808;
static TABLE:[i8;3]=[-128,-1,127];
@export @no_mangle
fn exercise()->u64 {
    if BYTE != -128 || HALF != -32768 || WORD != -2147483648 { return 1; }
    if DOUBLE != -9223372036854775808 { return 2; }
    if TABLE[0] != -128 || TABLE[1] != -1 || TABLE[2] != 127 { return 3; }
    return 42;
}
"#,
        )
        .unwrap();
        assert!(asm.contains(".byte 128\n") && asm.contains(".byte 255\n"));
        assert!(asm.contains(".hword 32768\n") && asm.contains(".word 2147483648\n"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn misaligned_volatile_and_atomic_accesses_trap_before_memory_effects() {
        for access in [
            "volatile_load(pointer)",
            "atomic_load(pointer, relaxed)",
            "atomic_fetch_add(pointer, 1, relaxed)",
        ] {
            let source = format!(
                "module misaligned; @export @no_mangle unsafe fn exercise()->u64 {{ \
                 let mut bytes:[u8;16]=[0;16]; \
                 let pointer:*mut u64=(&mut bytes[1]) as *mut u64; return {access}; }}"
            );
            let asm = assembly(&source).unwrap();
            assert!(asm.contains("tst x10, #7\n  b.eq 1f\n  brk #0\n1:"));
            check_object_and_optional_execution(&asm, "bl exercise", -5);
        }
    }

    #[test]
    fn emits_operand_free_naked_assembly_without_generated_frame() {
        let asm = assembly(
            r#"
module entry;
@naked @export @no_mangle
unsafe fn entry() -> void { asm!("wfi\nb entry"); }
"#,
        )
        .unwrap();
        assert!(asm.contains("entry:\n  wfi\n  b entry\n"));
        assert!(!asm.contains("stp x29"));
        check_object_and_optional_execution(&asm, "mov x0, #42", 42);
    }

    #[test]
    fn emits_all_width_atomics_and_signed_results() {
        let asm = assembly(
            r#"
module atomics;
static mut BYTE: i8 = 0;
static mut HALF: u16 = 7;
static mut WORD: u32 = 9;
static mut DOUBLE: u64 = 11;
@export @no_mangle
unsafe fn exercise() -> u64 {
    atomic_store(&mut BYTE, -(3 as i8), relaxed);
    let old_byte: i8 = atomic_fetch_add(&mut BYTE, 1, acq_rel);
    if old_byte != -(3 as i8) { return 1; }
    if atomic_compare_exchange(&mut BYTE, -(2 as i8), 4, seq_cst, acquire) != -(2 as i8) { return 2; }
    if atomic_compare_exchange(&mut BYTE, -(2 as i8), 99, relaxed, relaxed) != 4 { return 3; }
    if atomic_exchange(&mut HALF, 8, release) != 7 { return 4; }
    if atomic_fetch_add(&mut WORD, 3, acquire) != 9 { return 5; }
    atomic_store(&mut DOUBLE, 42, seq_cst);
    return atomic_load(&DOUBLE, acquire);
}
"#,
        )
        .unwrap();
        assert!(asm.contains("ldaxrb w9"));
        assert!(asm.contains("stlxrb w13"));
        assert!(asm.contains("ldxrh w9"));
        assert!(asm.contains("stlxrh w13"));
        assert!(asm.contains("ldaxr w9"));
        assert!(asm.contains("stlr x12"));
        assert!(asm.contains("clrex"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn phi_edge_copies_preserve_cycles() {
        let ast = parser::parse(
            "phi.oc",
            r#"
module phis;
@export @no_mangle
fn exchange(a: u64, b: u64, count: u64) -> u64 { return a + b + count; }
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("phi.oc".into(), ast)]).unwrap();
        let mut mir = mir::lower(&hir).unwrap();
        let u64_ty = hir.types.primitive("u64").unwrap();
        let bool_ty = hir.types.primitive("bool").unwrap();
        let local = |id| Place {
            base: PlaceBase::Local(id),
            projections: Vec::new(),
            ty: u64_ty,
        };
        mir.functions[0].values = vec![u64_ty; 10];
        mir.functions[0].values[7] = bool_ty;
        mir.functions[0].blocks = vec![
            BasicBlock {
                instructions: vec![
                    Instruction::Load {
                        dst: 0,
                        place: local(0),
                        volatile: false,
                    },
                    Instruction::Load {
                        dst: 1,
                        place: local(1),
                        volatile: false,
                    },
                ],
                terminator: Terminator::Jump(1),
            },
            BasicBlock {
                instructions: vec![
                    Instruction::Phi {
                        dst: 3,
                        incoming: vec![(0, 0), (2, 4)],
                    },
                    Instruction::Phi {
                        dst: 4,
                        incoming: vec![(0, 1), (2, 3)],
                    },
                    Instruction::Load {
                        dst: 5,
                        place: local(2),
                        volatile: false,
                    },
                    Instruction::Const { dst: 6, value: 0 },
                    Instruction::Binary {
                        dst: 7,
                        op: BinaryOp::Eq,
                        lhs: 5,
                        rhs: 6,
                    },
                ],
                terminator: Terminator::Branch {
                    condition: 7,
                    then_block: 3,
                    else_block: 2,
                },
            },
            BasicBlock {
                instructions: vec![
                    Instruction::Const { dst: 8, value: 1 },
                    Instruction::Binary {
                        dst: 9,
                        op: BinaryOp::Sub,
                        lhs: 5,
                        rhs: 8,
                    },
                    Instruction::Store {
                        place: local(2),
                        value: 9,
                        volatile: false,
                    },
                ],
                terminator: Terminator::Jump(1),
            },
            BasicBlock {
                instructions: vec![],
                terminator: Terminator::Return(Some(3)),
            },
        ];
        let asm = emit_assembly(&hir, &mir).unwrap();
        check_object_and_optional_execution(
            &asm,
            "mov x0, #17\nmov x1, #25\nmov x2, #1\nbl exchange",
            25,
        );
    }

    /// Every corpus case is assembled when Clang is installed. Setting
    /// OCORE_TEST_QEMU_AARCH64 also makes these tests run the resulting static
    /// Linux ELF through the caller-selected user-mode emulator.
    fn check_object_and_optional_execution(asm: &str, entry: &str, expected: i32) {
        use std::{fs, process::Command};
        let clang = std::env::var_os("OCORE_CLANG").unwrap_or_else(|| "clang".into());
        if Command::new(&clang).arg("--version").output().is_err() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("test.s");
        let object = dir.path().join("test.o");
        fs::write(&source, asm).unwrap();
        let result = Command::new(&clang)
            .args(["--target=aarch64-unknown-none-elf", "-c"])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "assembly failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let Some(qemu) = std::env::var_os("OCORE_TEST_QEMU_AARCH64") else {
            return;
        };
        let start = format!("\n.text\n.globl _start\n_start:\n{entry}\nmov x8, #93\nsvc #0\n");
        fs::write(&source, format!("{asm}{start}")).unwrap();
        let executable = dir.path().join("test.elf");
        let result = Command::new(&clang)
            .args([
                "--target=aarch64-linux-gnu",
                "-fuse-ld=lld",
                "-nostdlib",
                "-static",
                "-Wl,--build-id=none",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "link failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result = Command::new(qemu)
            .current_dir(dir.path())
            .arg(executable)
            .output()
            .unwrap();
        if expected < 0 {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(
                    result.status.signal(),
                    Some(-expected),
                    "execution stderr: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            #[cfg(not(unix))]
            assert!(!result.status.success());
            return;
        }
        assert_eq!(
            result.status.code(),
            Some(expected),
            "execution stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn frame_size_overflow_is_rejected_without_wrapping() {
        assert!(checked_align_up(u64::MAX, 16).is_err());
        assert!(checked_align_up(9, 3).is_err());
        assert_eq!(checked_align_up(9, 8).unwrap(), 16);
    }

    #[test]
    fn rejects_width_and_platform_assembly_operands() {
        let error = assembly(
            r#"
module invalid_asm;
unsafe fn invalid(value: u64) -> void { asm!("nop", in("w0") value); }
"#,
        )
        .unwrap_err();
        assert!(error.message.contains("width"));
        assert!(asm_register("x18").is_err());
        assert!(asm_register("sp").is_err());
        assert!(asm_register("xzr").is_err());
        assert_eq!(asm_register("W27").unwrap(), (27, 4));
    }

    #[test]
    fn rejects_bypassed_atomic_order_contract() {
        let ast = parser::parse(
            "order.oc",
            r#"
module order;
unsafe fn atomic(pointer: *mut u64) -> u64 {
    return atomic_compare_exchange(pointer, 0, 1, acquire, relaxed);
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("order.oc".into(), ast)]).unwrap();
        let mut mir = mir::lower(&hir).unwrap();
        let args = mir.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find_map(|instruction| {
                if let Instruction::Intrinsic {
                    intrinsic: Intrinsic::AtomicCompareExchange,
                    args,
                    ..
                } = instruction
                {
                    Some(args.clone())
                } else {
                    None
                }
            })
            .unwrap();
        for instruction in mir.functions[0]
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instructions)
        {
            if let Instruction::Const { dst, value } = instruction {
                if *dst == args[4] {
                    *value = MemoryOrder::Release as u64;
                }
            }
        }
        let error = emit_assembly(&hir, &mir).unwrap_err();
        assert!(error.message.contains("failure order"));
    }

    #[test]
    fn emits_portable_c_scalar_calls() {
        let asm = assembly(
            r#"
module c_calls;
extern "C" fn foreign(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64) -> u64;
fn call(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64) -> u64 {
    return foreign(a, b, c, d, e, f, g, h, i);
}
"#,
        )
        .unwrap();
        assert!(asm.contains("bl foreign"));
        assert!(asm.contains("add x10, x29, #16"));
        check_object_and_optional_execution(
            &format!("{asm}\n.text\nforeign:\nmov x0, #0\nret\n"),
            "mov x0, #42",
            42,
        );
    }

    #[test]
    fn scalar_ninth_argument_can_be_narrow_and_signed() {
        let asm = assembly(
            r#"
module signed_stack;
fn ninth(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: i8) -> i8 {
    return i;
}
@export @no_mangle
fn exercise() -> u64 {
    let value: i8 = ninth(0, 0, 0, 0, 0, 0, 0, 0, -(17 as i8));
    if value == -(17 as i8) { return 42; }
    return 1;
}
"#,
        )
        .unwrap();
        assert!(asm.contains("ldrsb x9, [x10]"));
        check_object_and_optional_execution(&asm, "bl exercise", 42);
    }

    #[test]
    fn rejects_amd64_sysv64_calls_on_aarch64() {
        let error = assembly(
            r#"
module foreign_abi;
extern "sysv64" fn foreign(value: u64) -> u64;
fn invoke(value: u64) -> u64 { return foreign(value); }
"#,
        )
        .unwrap_err();
        assert!(error.message.contains("AMD64 System V ABI"));
    }

    #[test]
    fn division_traps_instead_of_using_aarch64_silent_error_results() {
        let asm = assembly(
            r#"
module arithmetic;
fn signed_div(left: i64, right: i64) -> i64 { return left / right; }
fn unsigned_rem(left: u64, right: u64) -> u64 { return left % right; }
"#,
        )
        .unwrap();
        assert_eq!(asm.matches("cbnz x10, 1f").count(), 2);
        assert!(asm.contains("cmn x10, #1"));
        assert!(asm.matches("brk #0").count() >= 3);
    }
}
