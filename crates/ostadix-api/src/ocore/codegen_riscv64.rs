//! RV64GC freestanding assembly generation from typed SSA MIR.
//!
//! Scalar arguments and results use the integer LP64 psABI. O-core keeps unsigned
//! narrow SSA values zero extended internally, and performs the psABI-required
//! 32-bit sign extension at call/return boundaries. Aggregate values stay in
//! memory and cross calls through pointers, as required by the current type checker.
//!
//! s0 records the incoming stack pointer and s1 addresses an aligned local frame.
//! All callee-saved integer registers are preserved, including those used by asm.
//! Atomic lowering deliberately provides stronger ordering than relaxed/acquire/
//! release requests. Subword RMW operations use a masked 32-bit LR/SC loop.
//! Supervisor intrinsics address sstatus/SFENCE.VMA; machine trap entry remains
//! explicit operand-free @naked assembly rather than an invented interrupt ABI.
//!
//! References: RISC-V ELF psABI (integer calling convention), and the RISC-V
//! Unprivileged/Privileged ISA specifications published by RISC-V International.

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
    out.push_str(".file \"ocore\"\n.option push\n.option norelax\n");
    emit_statics(hir, &mut out)?;
    for function in &mir.functions {
        FunctionCodegen::new(hir, function)?.emit(&mut out, function_sections)?;
    }
    out.push_str(".option pop\n.section .note.GNU-stack,\"\",@progbits\n");
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
                    "function-pointer constant uses an unsupported RISC-V ABI",
                ));
            }
            let target = hir
                .functions
                .get(*id)
                .ok_or_else(|| codegen_error("invalid function-pointer constant"))?;
            writeln!(out, ".quad {}", target.symbol).unwrap();
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
        1 => writeln!(out, ".byte {}", value as u8).unwrap(),
        2 => writeln!(out, ".2byte {}", value as u16).unwrap(),
        4 => writeln!(out, ".4byte {}", value as u32).unwrap(),
        8 => writeln!(out, ".8byte {value}").unwrap(),
        _ => return Err(codegen_error(format!("cannot emit {size}-byte scalar"))),
    }
    Ok(())
}

struct FrameLayout {
    locals: Vec<u64>,
    values: Vec<u64>,
    size: u64,
    align: u64,
}

impl FrameLayout {
    fn new(types: &TypeContext, function: &MirFunction) -> Result<Self, Diagnostic> {
        let mut cursor = 0u64;
        let mut align = 16u64;
        let mut locals = Vec::new();
        for ty in &function.local_types {
            let layout = types.layout(*ty);
            align = align.max(layout.align);
            // Slots extend downward from an aligned frame base: align their
            // beginning (the negative offset), rather than the prior cursor.
            cursor = checked_align_up(
                cursor
                    .checked_add(layout.size.max(1))
                    .ok_or_else(|| codegen_error("local frame size overflow"))?,
                layout.align.max(1),
            )?;
            locals.push(cursor);
        }
        let mut values = Vec::new();
        for _ in &function.values {
            cursor = checked_align_up(
                cursor
                    .checked_add(8)
                    .ok_or_else(|| codegen_error("SSA frame size overflow"))?,
                8,
            )?;
            values.push(cursor);
        }
        Ok(Self {
            locals,
            values,
            size: checked_align_up(cursor, align)?,
            align,
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
            label_prefix: format!(".L_ocore_riscv64_{}", mir.source),
        })
    }

    fn emit(&self, out: &mut String, function_sections: bool) -> Result<(), Diagnostic> {
        if self.source.attrs.interrupt || self.source.abi == Abi::Interrupt {
            return Err(codegen_error("RISC-V interrupt ABI requires an explicit trap-frame convention; use operand-free @naked assembly"));
        }
        self.require_native_abi(&self.source.abi)?;
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
        writeln!(out, ".balign {}", self.source.attrs.align.unwrap_or(16)).unwrap();
        writeln!(
            out,
            ".{} {}",
            if self.source.attrs.export || self.source.public {
                "globl"
            } else {
                "local"
            },
            self.source.symbol
        )
        .unwrap();
        writeln!(
            out,
            ".type {}, @function\n{}:",
            self.source.symbol, self.source.symbol
        )
        .unwrap();
        if self.source.attrs.naked {
            self.emit_naked(out)?;
        } else {
            out.push_str("  addi sp, sp, -112\n  sd ra, 104(sp)\n  sd s0, 96(sp)\n");
            for index in 1..=11 {
                writeln!(out, "  sd s{index}, {}(sp)", 96 - index * 8).unwrap();
            }
            out.push_str("  addi s0, sp, 112\n");
            if self.frame.align > 16 {
                emit_u64("t6", self.frame.align.wrapping_neg(), out);
                out.push_str("  and sp, sp, t6\n");
            }
            out.push_str("  mv s1, sp\n");
            self.reserve_stack(out);
            self.store_parameters(out)?;
            writeln!(out, "  j {}_bb{}", self.label_prefix, self.mir.entry).unwrap();
            for (block_id, block) in self.mir.blocks.iter().enumerate() {
                writeln!(out, "{}_bb{}:", self.label_prefix, block_id).unwrap();
                for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                    if !matches!(instruction, Instruction::Phi { .. }) {
                        self.emit_instruction(block_id, instruction_index, instruction, out)?;
                    }
                }
                self.emit_terminator(block_id, &block.terminator, out)?;
            }
        }
        writeln!(
            out,
            ".size {}, .-{}",
            self.source.symbol, self.source.symbol
        )
        .unwrap();
        Ok(())
    }

    fn require_native_abi(&self, abi: &Abi) -> Result<(), Diagnostic> {
        if *abi == Abi::SysV64 {
            return Err(codegen_error("extern \"sysv64\" is the AMD64 System V ABI and is unsupported on RISC-V; use extern \"C\" or extern \"ocore\""));
        }
        if *abi == Abi::Interrupt {
            return Err(codegen_error(
                "interrupt functions cannot be used as ordinary RISC-V calls",
            ));
        }
        Ok(())
    }

    fn emit_naked(&self, out: &mut String) -> Result<(), Diagnostic> {
        for block in &self.mir.blocks {
            for instruction in &block.instructions {
                match instruction {
                    Instruction::Asm {
                        template, operands, ..
                    } if operands.is_empty() => {
                        emit_asm_template(template, out)?;
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

    fn reserve_stack(&self, out: &mut String) {
        emit_stack_adjust(self.frame.size, false, out);
    }

    fn store_parameters(&self, out: &mut String) -> Result<(), Diagnostic> {
        for (index, local) in self.source.params.iter().enumerate() {
            let ty = self.source.locals[*local].ty;
            self.require_scalar_type(ty, "function parameter")?;
            let register = if index < 8 {
                format!("a{index}")
            } else {
                emit_base_offset("t5", "s0", (index - 8) as u64 * 8, out);
                out.push_str("  ld t0, 0(t5)\n");
                "t0".into()
            };
            self.store_reg_to_frame(&register, self.frame.locals[*local], ty, out)?;
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
                if !matches!(
                    self.hir.types.types[self.mir.values[*dst]],
                    Type::Void | Type::Never
                ) {
                    self.require_scalar_type(self.mir.values[*dst], "constant result")?;
                }
                emit_u64("t0", *value, out);
                self.normalize_scalar("t0", self.mir.values[*dst], out)?;
                self.store_value(*dst, "t0", out);
            }
            Instruction::FunctionAddress { dst, function } => {
                self.validate_function_address(*dst, *function)?;
                emit_symbol_address("t0", &self.hir.functions[*function].symbol, out);
                self.store_value(*dst, "t0", out);
            }
            Instruction::AddressOf { dst, place } => {
                let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[*dst]]
                else {
                    return Err(codegen_error("address result is not a pointer"));
                };
                if pointee != place.ty {
                    return Err(codegen_error("address result pointee type mismatch"));
                }
                self.place_address(place, "t1", out)?;
                self.store_value(*dst, "t1", out);
            }
            Instruction::Load {
                dst,
                place,
                volatile,
            } => {
                self.require_same_type(self.mir.values[*dst], place.ty, "load result")?;
                self.require_scalar_type(place.ty, "load")?;
                self.place_address(place, "t1", out)?;
                if *volatile {
                    self.guard_volatile_alignment("t1", place, out);
                    self.load_memory("t0", "t1", place.ty, out)?;
                } else {
                    self.load_place_memory("t0", "t1", place, out)?;
                }
                self.store_value(*dst, "t0", out);
            }
            Instruction::Store {
                place,
                value,
                volatile,
            } => {
                self.require_same_type(self.mir.values[*value], place.ty, "store value")?;
                self.require_scalar_type(place.ty, "store")?;
                self.load_value(*value, "t0", out);
                self.place_address(place, "t1", out)?;
                if *volatile {
                    self.guard_volatile_alignment("t1", place, out);
                    self.store_memory("t0", "t1", place.ty, out)?;
                } else {
                    self.store_place_memory("t0", "t1", place, out)?;
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
                    self.place_address(destination, "t1", out)?;
                    self.place_address(source, "t2", out)?;
                    emit_u64("t3", *size, out);
                    writeln!(out, "  bltu t1, t2, {label}_forward\n  add t4, t2, t3\n  bgeu t1, t4, {label}_forward\n  add t1, t1, t3\n  add t2, t2, t3\n{label}_backward:").unwrap();
                    out.push_str("  addi t1, t1, -1\n  addi t2, t2, -1\n  lbu t0, 0(t2)\n  sb t0, 0(t1)\n  addi t3, t3, -1\n");
                    writeln!(
                        out,
                        "  bnez t3, {label}_backward\n  j {label}_done\n{label}_forward:"
                    )
                    .unwrap();
                    out.push_str("  lbu t0, 0(t2)\n  sb t0, 0(t1)\n  addi t1, t1, 1\n  addi t2, t2, 1\n  addi t3, t3, -1\n");
                    writeln!(out, "  bnez t3, {label}_forward\n{label}_done:").unwrap();
                }
            }
            Instruction::Unary { dst, op, operand } => {
                self.validate_unary(*dst, *op, *operand)?;
                self.load_value(*operand, "t0", out);
                match op {
                    UnaryOp::Neg => out.push_str("  neg t0, t0\n"),
                    UnaryOp::Not => out.push_str("  xori t0, t0, 1\n"),
                    UnaryOp::BitNot => out.push_str("  not t0, t0\n"),
                    UnaryOp::Deref | UnaryOp::AddressOf { .. } => {
                        return Err(codegen_error("place unary operation escaped MIR lowering"));
                    }
                }
                self.normalize_scalar("t0", self.mir.values[*dst], out)?;
                self.store_value(*dst, "t0", out);
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
                self.load_value(*value, "t0", out);
                self.normalize_scalar("t0", *from, out)?;
                self.normalize_scalar("t0", *to, out)?;
                self.store_value(*dst, "t0", out);
            }
            Instruction::Call {
                dst,
                function,
                args,
            } => self.emit_call(*dst, *function, args, out)?,
            Instruction::Intrinsic {
                dst,
                intrinsic,
                args,
            } => self.emit_intrinsic(*dst, *intrinsic, args, out)?,
            Instruction::Phi { .. } => unreachable!(),
            Instruction::CallIndirect { dst, callee, args } => {
                self.emit_indirect_call(*dst, *callee, args, out)?;
            }
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
                "cannot take an AMD64 sysv64 function address on RISC-V RV64",
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
        self.load_value(lhs, "t0", out);
        self.load_value(rhs, "t1", out);
        let signed = is_signed(&self.hir.types.types[self.mir.values[lhs]]);
        match op {
            BinaryOp::Add | BinaryOp::Sub => {
                if let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[lhs]] {
                    let scale = self.hir.types.layout(pointee).size;
                    if scale != 1 {
                        emit_u64("t2", scale, out);
                        out.push_str("  mul t1, t1, t2\n");
                    }
                }
                writeln!(
                    out,
                    "  {} t0, t0, t1",
                    if op == BinaryOp::Add { "add" } else { "sub" }
                )
                .unwrap();
            }
            BinaryOp::Mul => out.push_str("  mul t0, t0, t1\n"),
            BinaryOp::Div | BinaryOp::Rem => {
                // RV64 DIV/REM have defined nontrapping error values; retain
                // O-core's existing arithmetic trap boundary explicitly.
                out.push_str("  bnez t1, 1f\n  unimp\n1:\n");
                if signed && self.hir.types.layout(self.mir.values[lhs]).size == 8 {
                    emit_u64("t2", 0x8000_0000_0000_0000, out);
                    out.push_str("  bne t0, t2, 2f\n  li t2, -1\n  bne t1, t2, 2f\n  unimp\n2:\n");
                }
                let instruction = match (op, signed) {
                    (BinaryOp::Div, true) => "div",
                    (BinaryOp::Div, false) => "divu",
                    (BinaryOp::Rem, true) => "rem",
                    (BinaryOp::Rem, false) => "remu",
                    _ => unreachable!(),
                };
                writeln!(out, "  {instruction} t0, t0, t1").unwrap();
            }
            BinaryOp::BitAnd => out.push_str("  and t0, t0, t1\n"),
            BinaryOp::BitOr => out.push_str("  or t0, t0, t1\n"),
            BinaryOp::BitXor => out.push_str("  xor t0, t0, t1\n"),
            BinaryOp::ShiftLeft => out.push_str("  sll t0, t0, t1\n"),
            BinaryOp::ShiftRight => out.push_str(if signed {
                "  sra t0, t0, t1\n"
            } else {
                "  srl t0, t0, t1\n"
            }),
            BinaryOp::Eq | BinaryOp::NotEq => {
                out.push_str("  xor t0, t0, t1\n");
                out.push_str(if op == BinaryOp::Eq {
                    "  seqz t0, t0\n"
                } else {
                    "  snez t0, t0\n"
                });
            }
            BinaryOp::Less | BinaryOp::Greater | BinaryOp::LessEq | BinaryOp::GreaterEq => {
                let (left, right) = if matches!(op, BinaryOp::Greater | BinaryOp::LessEq) {
                    ("t1", "t0")
                } else {
                    ("t0", "t1")
                };
                writeln!(
                    out,
                    "  {} t0, {left}, {right}",
                    if signed { "slt" } else { "sltu" }
                )
                .unwrap();
                if matches!(op, BinaryOp::LessEq | BinaryOp::GreaterEq) {
                    out.push_str("  xori t0, t0, 1\n");
                }
            }
            BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                return Err(codegen_error(
                    "logical operator escaped short-circuit lowering",
                ))
            }
        }
        self.normalize_scalar("t0", self.mir.values[dst], out)?;
        self.store_value(dst, "t0", out);
        Ok(())
    }

    fn validate_call(
        &self,
        dst: Option<ValueId>,
        function: FunctionId,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        let target = &self.hir.functions[function];
        self.require_native_abi(&target.abi)?;
        if target.attrs.interrupt {
            return Err(codegen_error(
                "interrupt handler reached ordinary RISC-V call lowering",
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
        for (value, expected) in args.iter().zip(params) {
            self.require_scalar_type(*expected, "call argument")?;
            self.require_same_type(self.mir.values[*value], *expected, "call argument")?;
        }
        let expected =
            (!matches!(self.hir.types.types[result], Type::Void | Type::Never)).then_some(result);
        if expected.is_some() {
            self.require_scalar_type(result, "call result")?;
        }
        self.require_optional_result(dst, expected, "call result")
    }

    fn setup_call_args(&self, args: &[ValueId], out: &mut String) -> Result<u64, Diagnostic> {
        let stack_size = align_up(args.len().saturating_sub(8) as u64 * 8, 16);
        emit_stack_adjust(stack_size, false, out);
        for (index, value) in args.iter().enumerate().skip(8) {
            self.load_value(*value, "t0", out);
            self.normalize_abi("t0", self.mir.values[*value], out)?;
            emit_base_offset("t5", "sp", (index - 8) as u64 * 8, out);
            out.push_str("  sd t0, 0(t5)\n");
        }
        for (index, value) in args.iter().take(8).enumerate() {
            let register = format!("a{index}");
            self.load_value(*value, &register, out);
            self.normalize_abi(&register, self.mir.values[*value], out)?;
        }
        Ok(stack_size)
    }

    fn finish_call(
        &self,
        dst: Option<ValueId>,
        stack_size: u64,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        emit_stack_adjust(stack_size, true, out);
        if let Some(dst) = dst {
            if matches!(self.hir.types.types[self.mir.values[dst]], Type::Bool) {
                // Consume the boolean's byte-width representation before
                // canonicalizing. This also tolerates unspecified upper return
                // bits from low-level foreign entry points across supported ISAs.
                out.push_str("  andi a0, a0, 255\n");
            }
            self.normalize_scalar("a0", self.mir.values[dst], out)?;
            self.store_value(dst, "a0", out);
        }
        Ok(())
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
            return Err(codegen_error("indirect callee is not a function pointer"));
        };
        self.require_native_abi(abi)?;
        self.validate_call_signature(dst, params, *result, args)?;
        let stack_size = self.setup_call_args(args, out)?;
        self.load_value(callee, "t0", out);
        out.push_str("  jalr ra, 0(t0)\n");
        self.finish_call(dst, stack_size, out)
    }

    fn emit_call(
        &self,
        dst: Option<ValueId>,
        function: FunctionId,
        args: &[ValueId],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_call(dst, function, args)?;
        let stack_size = self.setup_call_args(args, out)?;
        writeln!(out, "  call {}", self.hir.functions[function].symbol).unwrap();
        self.finish_call(dst, stack_size, out)
    }

    fn validate_intrinsic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        let u64_ty = self.hir.types.primitive("u64").unwrap();
        let u8_ty = self.hir.types.primitive("u8").unwrap();
        match intrinsic {
            Intrinsic::In8
            | Intrinsic::In16
            | Intrinsic::In32
            | Intrinsic::Out8
            | Intrinsic::Out16
            | Intrinsic::Out32 => {
                return Err(codegen_error(
                    "x86 port-I/O intrinsics are unsupported on RISC-V",
                ))
            }
            Intrinsic::VolatileLoad | Intrinsic::VolatileStore => {
                return Err(codegen_error(
                    "volatile intrinsic escaped MIR memory lowering",
                ))
            }
            Intrinsic::AtomicLoad
            | Intrinsic::AtomicStore
            | Intrinsic::AtomicExchange
            | Intrinsic::AtomicCompareExchange
            | Intrinsic::AtomicFetchAdd => {
                let (values, orders) = match intrinsic {
                    Intrinsic::AtomicLoad => (0, 1),
                    Intrinsic::AtomicCompareExchange => (2, 2),
                    _ => (1, 1),
                };
                if args.len() != 1 + values + orders {
                    return Err(codegen_error("atomic intrinsic argument count mismatch"));
                }
                let Type::Pointer { mutable, pointee } =
                    self.hir.types.types[self.mir.values[args[0]]]
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
                for value in &args[1..1 + values] {
                    self.require_same_type(self.mir.values[*value], pointee, "atomic value")?;
                }
                for value in &args[1 + values..] {
                    self.require_same_type(self.mir.values[*value], u8_ty, "atomic ordering")?;
                    let order = self
                        .const_from_value(*value)
                        .and_then(|order| u8::try_from(order).ok())
                        .ok_or_else(|| codegen_error("atomic ordering must be constant in MIR"))?;
                    super::typeck::validate_memory_order(intrinsic, order)
                        .map_err(codegen_error)?;
                }
                if intrinsic == Intrinsic::AtomicCompareExchange {
                    // Every order was checked above; validate their relationship
                    // again for callers that construct MIR directly.
                    let success = self.const_from_value(args[3]).unwrap() as u8;
                    let failure = self.const_from_value(args[4]).unwrap() as u8;
                    super::typeck::validate_compare_exchange_orders(success, failure)
                        .map_err(codegen_error)?;
                }
                return self.require_optional_result(
                    dst,
                    (intrinsic != Intrinsic::AtomicStore).then_some(pointee),
                    "atomic result",
                );
            }
            _ => {}
        }
        let (params, result) = match intrinsic {
            Intrinsic::EnableInterrupts | Intrinsic::DisableInterrupts | Intrinsic::Halt => {
                (vec![], None)
            }
            Intrinsic::InvalidatePage => (vec![self.hir.types.primitive("usize").unwrap()], None),
            Intrinsic::Syscall(count) if count <= 6 => {
                (vec![u64_ty; count as usize + 1], Some(u64_ty))
            }
            Intrinsic::Syscall(_) => {
                return Err(codegen_error(
                    "RISC-V syscall lowering supports syscall0 through syscall6",
                ))
            }
            _ => unreachable!(),
        };
        if args.len() != params.len() {
            return Err(codegen_error("intrinsic argument count mismatch"));
        }
        for (value, expected) in args.iter().zip(params) {
            self.require_same_type(self.mir.values[*value], expected, "intrinsic argument")?;
        }
        self.require_optional_result(dst, result, "intrinsic result")
    }

    fn const_from_value(&self, value: ValueId) -> Option<u64> {
        self.mir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find_map(|instruction| match instruction {
                Instruction::Const {
                    dst,
                    value: constant,
                } if *dst == value => Some(*constant),
                _ => None,
            })
    }

    fn emit_intrinsic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_intrinsic(dst, intrinsic, args)?;
        match intrinsic {
            Intrinsic::EnableInterrupts => out.push_str("  csrsi sstatus, 2\n"),
            Intrinsic::DisableInterrupts => out.push_str("  csrci sstatus, 2\n"),
            Intrinsic::Halt => out.push_str("  wfi\n"),
            Intrinsic::InvalidatePage => {
                self.load_value(args[0], "t0", out);
                out.push_str("  sfence.vma t0, zero\n");
            }
            Intrinsic::Syscall(count) => {
                self.load_value(args[0], "a7", out);
                for (index, value) in args[1..].iter().take(count as usize).enumerate() {
                    self.load_value(*value, &format!("a{index}"), out);
                }
                out.push_str("  ecall\n");
                if let Some(dst) = dst {
                    self.normalize_scalar("a0", self.mir.values[dst], out)?;
                    self.store_value(dst, "a0", out);
                }
            }
            Intrinsic::AtomicLoad
            | Intrinsic::AtomicStore
            | Intrinsic::AtomicExchange
            | Intrinsic::AtomicCompareExchange
            | Intrinsic::AtomicFetchAdd => self.emit_atomic(dst, intrinsic, args, out)?,
            _ => unreachable!(),
        }
        Ok(())
    }

    fn emit_atomic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[args[0]]] else {
            unreachable!()
        };
        let size = self.hir.types.layout(pointee).size;
        self.load_value(args[0], "t1", out);
        if size > 1 {
            writeln!(
                out,
                "  andi t0, t1, {}\n  beqz t0, 1f\n  unimp\n1:",
                size - 1
            )
            .unwrap();
        }
        out.push_str("  fence rw, rw\n");
        if intrinsic == Intrinsic::AtomicLoad {
            self.load_memory("t0", "t1", pointee, out)?;
        } else if intrinsic == Intrinsic::AtomicStore {
            self.load_value(args[1], "t0", out);
            self.store_memory("t0", "t1", pointee, out)?;
        } else {
            self.load_value(args[1], "t2", out);
            normalize_bits("t2", size, out);
            if intrinsic == Intrinsic::AtomicCompareExchange {
                self.load_value(args[2], "t3", out);
                normalize_bits("t3", size, out);
            }
            if size >= 4 && intrinsic != Intrinsic::AtomicCompareExchange {
                writeln!(
                    out,
                    "  {}.{}.aqrl t0, t2, (t1)",
                    if intrinsic == Intrinsic::AtomicExchange {
                        "amoswap"
                    } else {
                        "amoadd"
                    },
                    if size == 4 { "w" } else { "d" }
                )
                .unwrap();
            } else if size >= 4 {
                let width = if size == 4 { "w" } else { "d" };
                writeln!(out, "1:\n  lr.{width}.aq t0, (t1)").unwrap();
                normalize_bits("t0", size, out);
                writeln!(
                    out,
                    "  bne t0, t2, 2f\n  sc.{width}.rl t4, t3, (t1)\n  bnez t4, 1b\n2:"
                )
                .unwrap();
            } else {
                // A-extension only has word/doubleword RMWs. Update the selected
                // byte/halfword within a naturally aligned containing word;
                // failed reservations retry against a fresh neighbor snapshot.
                out.push_str("  andi t4, t1, 3\n  slli t4, t4, 3\n  andi t1, t1, -4\n");
                emit_u64("t5", (1u64 << (size * 8)) - 1, out);
                out.push_str("  sll t5, t5, t4\n1:\n  lr.w.aq t6, (t1)\n  srl t0, t6, t4\n");
                normalize_bits("t0", size, out);
                match intrinsic {
                    Intrinsic::AtomicCompareExchange => {
                        out.push_str("  bne t0, t2, 2f\n  mv a0, t3\n")
                    }
                    Intrinsic::AtomicFetchAdd => {
                        out.push_str("  add a0, t0, t2\n");
                        normalize_bits("a0", size, out);
                    }
                    Intrinsic::AtomicExchange => out.push_str("  mv a0, t2\n"),
                    _ => unreachable!(),
                }
                out.push_str("  sll a0, a0, t4\n  not a1, t5\n  and a1, t6, a1\n  or a1, a1, a0\n  sc.w.rl a2, a1, (t1)\n  bnez a2, 1b\n2:\n");
            }
        }
        out.push_str("  fence rw, rw\n");
        if let Some(dst) = dst {
            self.normalize_scalar("t0", pointee, out)?;
            self.store_value(dst, "t0", out);
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
            Terminator::Unreachable => out.push_str("  unimp\n"),
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
                                "floating-point returns are not implemented by the RISC-V RV64 backend",
                            ));
                        }
                        self.load_value(*value, "a0", out);
                        self.normalize_abi("a0", self.source.result, out)?;
                    }
                    (None, true) => {}
                    _ => return Err(codegen_error("return value shape mismatch")),
                }
                self.emit_epilogue(out);
            }
            Terminator::Jump(target) => {
                self.emit_phi_moves(block_id, *target, out)?;
                writeln!(out, "  j {}_bb{target}", self.label_prefix).unwrap();
            }
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => {
                let bool_ty = self.hir.types.primitive("bool").unwrap();
                self.require_same_type(self.mir.values[*condition], bool_ty, "branch condition")?;
                let then_edge = format!("{}_bb{}_then_edge", self.label_prefix, block_id);
                self.load_value(*condition, "t0", out);
                writeln!(out, "  bnez t0, {then_edge}").unwrap();
                self.emit_phi_moves(block_id, *else_block, out)?;
                writeln!(out, "  j {}_bb{else_block}", self.label_prefix).unwrap();
                writeln!(out, "{then_edge}:").unwrap();
                self.emit_phi_moves(block_id, *then_block, out)?;
                writeln!(out, "  j {}_bb{then_block}", self.label_prefix).unwrap();
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
        let mut moves = Vec::new();
        for instruction in &self.mir.blocks[to].instructions {
            let Instruction::Phi { dst, incoming } = instruction else {
                continue;
            };
            let Some((_, value)) = incoming.iter().find(|(block, _)| *block == from) else {
                return Err(codegen_error("phi is missing the incoming edge value"));
            };
            self.require_same_type(
                self.mir.values[*value],
                self.mir.values[*dst],
                "phi incoming value",
            )?;
            moves.push((*dst, *value));
        }
        let size = align_up(moves.len() as u64 * 8, 16);
        emit_stack_adjust(size, false, out);
        for (index, (_, value)) in moves.iter().enumerate() {
            self.load_value(*value, "t0", out);
            emit_base_offset("t5", "sp", index as u64 * 8, out);
            out.push_str("  sd t0, 0(t5)\n");
        }
        for (index, (dst, _)) in moves.iter().enumerate() {
            emit_base_offset("t5", "sp", index as u64 * 8, out);
            out.push_str("  ld t0, 0(t5)\n");
            self.store_value(*dst, "t0", out);
        }
        emit_stack_adjust(size, true, out);
        Ok(())
    }

    fn emit_epilogue(&self, out: &mut String) {
        out.push_str("  mv sp, s0\n  ld ra, -8(sp)\n");
        for index in 1..=11 {
            writeln!(out, "  ld s{index}, -{}(sp)", 16 + index * 8).unwrap();
        }
        out.push_str("  ld s0, -16(sp)\n  ret\n");
    }

    fn place_address(
        &self,
        place: &Place,
        register: &str,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        match place.base {
            PlaceBase::Local(local) => emit_frame_address(register, self.frame.locals[local], out),
            PlaceBase::Static(id) => {
                emit_symbol_address(register, &self.hir.statics[id].symbol, out)
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
                        emit_u64("t6", *offset, out);
                        writeln!(out, "  add {register}, {register}, t6").unwrap();
                    }
                }
                Projection::Index {
                    index,
                    element_size,
                } => {
                    self.require_integer_type(self.mir.values[*index], "place index")?;
                    self.load_value(*index, "t3", out);
                    if *element_size != 1 {
                        emit_u64("t4", *element_size, out);
                        out.push_str("  mul t3, t3, t4\n");
                    }
                    writeln!(out, "  add {register}, {register}, t3").unwrap();
                }
            }
        }
        Ok(())
    }

    fn load_value(&self, value: ValueId, register: &str, out: &mut String) {
        emit_frame_address("t5", self.frame.values[value], out);
        writeln!(out, "  ld {register}, 0(t5)").unwrap();
    }

    fn store_value(&self, value: ValueId, register: &str, out: &mut String) {
        emit_frame_address("t5", self.frame.values[value], out);
        writeln!(out, "  sd {register}, 0(t5)").unwrap();
    }

    fn store_reg_to_frame(
        &self,
        register: &str,
        offset: u64,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        emit_frame_address("t5", offset, out);
        self.store_memory(register, "t5", ty, out)
    }

    fn load_memory(
        &self,
        dst: &str,
        address: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let instruction = match (
            self.hir.types.layout(ty).size,
            is_signed(&self.hir.types.types[ty]),
        ) {
            (1, false) => "lbu",
            (1, true) => "lb",
            (2, false) => "lhu",
            (2, true) => "lh",
            (4, false) => "lwu",
            (4, true) => "lw",
            (8, _) => "ld",
            (size, _) => return Err(codegen_error(format!("cannot scalar-load {size} bytes"))),
        };
        writeln!(out, "  {instruction} {dst}, 0({address})").unwrap();
        if matches!(self.hir.types.types[ty], Type::Bool) {
            // O-core boolean memory is a byte: every nonzero byte is true,
            // while SSA booleans must be exactly zero or one for logical ops.
            writeln!(out, "  snez {dst}, {dst}").unwrap();
        }
        Ok(())
    }

    fn place_alignment(&self, place: &Place) -> u64 {
        let mut align = match place.base {
            PlaceBase::Local(local) => self.hir.types.layout(self.mir.local_types[local]).align,
            PlaceBase::Static(id) => self.hir.statics[id]
                .attrs
                .align
                .unwrap_or_else(|| self.hir.types.layout(self.hir.statics[id].ty).align),
            // MIR pointers carry their pointee type but no alignment provenance.
            // A pointer to a packed field is valid ordinary byte-addressed
            // memory, so avoid relying on optional unaligned RV64 accesses.
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
            // Volatile device accesses must retain their native width rather
            // than become several accesses. Unsupported alignment traps before
            // touching the device, independent of the execution environment.
            writeln!(
                out,
                "  andi t4, {address}, {}\n  beqz t4, 1f\n  unimp\n1:",
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
        writeln!(out, "  li {dst}, 0").unwrap();
        for index in 0..size {
            writeln!(out, "  lbu t4, {index}({address})").unwrap();
            if index != 0 {
                writeln!(out, "  slli t4, t4, {}", index * 8).unwrap();
            }
            writeln!(out, "  or {dst}, {dst}, t4").unwrap();
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
        for index in 0..size {
            if index == 0 {
                writeln!(out, "  sb {src}, 0({address})").unwrap();
            } else {
                writeln!(
                    out,
                    "  srli t4, {src}, {}\n  sb t4, {index}({address})",
                    index * 8
                )
                .unwrap();
            }
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
        let instruction = match self.hir.types.layout(ty).size {
            1 => "sb",
            2 => "sh",
            4 => "sw",
            8 => "sd",
            size => return Err(codegen_error(format!("cannot scalar-store {size} bytes"))),
        };
        writeln!(out, "  {instruction} {src}, 0({address})").unwrap();
        Ok(())
    }

    fn normalize_scalar(
        &self,
        register: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        // Effect-only and diverging MIR expressions have an unused Const0
        // placeholder, which occupies an SSA slot without a scalar language type.
        if matches!(self.hir.types.types[ty], Type::Void | Type::Never) {
            return Ok(());
        }
        let size = self.hir.types.layout(ty).size;
        if matches!(self.hir.types.types[ty], Type::Bool) {
            writeln!(out, "  snez {register}, {register}").unwrap();
        } else if matches!(size, 1 | 2 | 4) {
            let shift = 64 - size * 8;
            writeln!(out, "  slli {register}, {register}, {shift}").unwrap();
            writeln!(
                out,
                "  {} {register}, {register}, {shift}",
                if is_signed(&self.hir.types.types[ty]) {
                    "srai"
                } else {
                    "srli"
                }
            )
            .unwrap();
        } else if size != 8 {
            return Err(codegen_error(format!(
                "cannot normalize {size}-byte scalar"
            )));
        }
        Ok(())
    }

    fn normalize_abi(
        &self,
        register: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.normalize_scalar(register, ty, out)?;
        if self.hir.types.layout(ty).size == 4 {
            writeln!(out, "  addiw {register}, {register}, 0").unwrap();
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
        let mut registers = std::collections::HashSet::new();
        for operand in operands {
            let register = match operand {
                MirAsmOperand::In { register, .. }
                | MirAsmOperand::Out { register, .. }
                | MirAsmOperand::InOut { register, .. } => register,
            };
            let canonical = validate_register(register)?;
            if !registers.insert(canonical) {
                return Err(codegen_error(
                    "duplicate/aliased RISC-V inline assembly register",
                ));
            }
        }
        let size = align_up(operands.len() as u64 * 8, 16);
        emit_stack_adjust(size, false, out);
        for (index, operand) in operands.iter().enumerate() {
            let value = match operand {
                MirAsmOperand::In { value, .. } => Some(*value),
                MirAsmOperand::InOut { input, output, .. } => {
                    self.require_same_type(
                        self.mir.values[*input],
                        output.ty,
                        "assembly inout operand",
                    )?;
                    Some(*input)
                }
                MirAsmOperand::Out { .. } => None,
            };
            if let Some(value) = value {
                self.require_scalar_type(self.mir.values[value], "inline assembly operand")?;
                self.load_value(value, "t0", out);
                writeln!(out, "  sd t0, {}(sp)", index * 8).unwrap();
            }
        }
        for (index, operand) in operands.iter().enumerate() {
            if let MirAsmOperand::In { register, .. } | MirAsmOperand::InOut { register, .. } =
                operand
            {
                writeln!(out, "  ld {register}, {}(sp)", index * 8).unwrap();
            }
        }
        emit_asm_template(template, out)?;
        // Snapshot every output before any emitter address scratch can overwrite
        // another declared output, including t5/t6 aliases.
        for (index, operand) in operands.iter().enumerate() {
            if let MirAsmOperand::Out { register, .. } | MirAsmOperand::InOut { register, .. } =
                operand
            {
                writeln!(out, "  sd {register}, {}(sp)", index * 8).unwrap();
            }
        }
        for (index, operand) in operands.iter().enumerate() {
            let target = match operand {
                MirAsmOperand::Out { target, .. } => Some(target),
                MirAsmOperand::InOut { output, .. } => Some(output),
                _ => None,
            };
            if let Some(target) = target {
                self.require_scalar_type(target.ty, "inline assembly output")?;
                writeln!(out, "  ld t0, {}(sp)", index * 8).unwrap();
                self.normalize_scalar("t0", target.ty, out)?;
                self.place_address(target, "t1", out)?;
                self.store_place_memory("t0", "t1", target, out)?;
            }
        }
        emit_stack_adjust(size, true, out);
        Ok(())
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
        if self.hir.types.is_scalar(ty) && !self.hir.types.is_float(ty) {
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
    // GNU/LLVM LI expands to a full-width sequence; signed formatting preserves
    // all 64 bits, including addresses and values above i64::MAX.
    writeln!(out, "  li {register}, {}", value as i64).unwrap();
}

fn emit_symbol_address(register: &str, symbol: &str, out: &mut String) {
    writeln!(out, "  lla {register}, {symbol}").unwrap();
}

fn emit_frame_address(register: &str, offset: u64, out: &mut String) {
    if offset <= 2048 {
        writeln!(out, "  addi {register}, s1, -{offset}").unwrap();
    } else {
        emit_u64("t6", offset, out);
        writeln!(out, "  sub {register}, s1, t6").unwrap();
    }
}

fn emit_base_offset(register: &str, base: &str, offset: u64, out: &mut String) {
    if offset <= 2047 {
        writeln!(out, "  addi {register}, {base}, {offset}").unwrap();
    } else {
        emit_u64("t6", offset, out);
        writeln!(out, "  add {register}, {base}, t6").unwrap();
    }
}

fn emit_stack_adjust(size: u64, release: bool, out: &mut String) {
    if size == 0 {
        return;
    }
    if size <= if release { 2047 } else { 2048 } {
        writeln!(
            out,
            "  addi sp, sp, {}{size}",
            if release { "" } else { "-" }
        )
        .unwrap();
    } else {
        emit_u64("t6", size, out);
        writeln!(out, "  {} sp, sp, t6", if release { "add" } else { "sub" }).unwrap();
    }
}

fn normalize_bits(register: &str, size: u64, out: &mut String) {
    if size < 8 {
        let shift = 64 - size * 8;
        writeln!(
            out,
            "  slli {register}, {register}, {shift}\n  srli {register}, {register}, {shift}"
        )
        .unwrap();
    }
}

fn validate_register(register: &str) -> Result<u8, Diagnostic> {
    let number = match register {
        "ra" => 1,
        "t0" => 5,
        "t1" => 6,
        "t2" => 7,
        "a0" => 10,
        "a1" => 11,
        "a2" => 12,
        "a3" => 13,
        "a4" => 14,
        "a5" => 15,
        "a6" => 16,
        "a7" => 17,
        "s2" => 18,
        "s3" => 19,
        "s4" => 20,
        "s5" => 21,
        "s6" => 22,
        "s7" => 23,
        "s8" => 24,
        "s9" => 25,
        "s10" => 26,
        "s11" => 27,
        "t3" => 28,
        "t4" => 29,
        "t5" => 30,
        "t6" => 31,
        _ => register
            .strip_prefix('x')
            .and_then(|number| number.parse::<u8>().ok())
            .filter(|number| register == format!("x{number}"))
            .ok_or_else(|| {
                codegen_error(format!("unsupported RISC-V integer register `{register}`"))
            })?,
    };
    if !matches!(number, 1 | 5..=7 | 10..=31) {
        return Err(codegen_error(format!(
            "RISC-V register `{register}` is fixed or reserved by the frame ABI"
        )));
    }
    Ok(number)
}

fn emit_asm_template(template: &str, out: &mut String) -> Result<(), Diagnostic> {
    // Templates remain native assembler source; the target assembler validates
    // opcodes. Catch conventional foreign-register spellings early so asm-only
    // emission cannot present AMD64/AArch64 register-bound code as RV64 code.
    let tokens =
        template.split(|character: char| !character.is_ascii_alphanumeric() && character != '_');
    for token in tokens {
        let foreign = matches!(
            token,
            "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rsp" | "rbp" | "xzr" | "wzr" | "wsp"
        ) || token
            .strip_prefix('w')
            .is_some_and(|number| number.parse::<u8>().is_ok_and(|number| number <= 31));
        if foreign {
            return Err(codegen_error(format!(
                "foreign architecture register `{token}` in RISC-V assembly"
            )));
        }
    }
    for line in template.lines() {
        writeln!(out, "  {line}").unwrap();
    }
    Ok(())
}

fn is_signed(ty: &Type) -> bool {
    matches!(ty, Type::Int { signed: true, .. } | Type::Isize)
}

fn checked_align_up(value: u64, alignment: u64) -> Result<u64, Diagnostic> {
    if !alignment.is_power_of_two() {
        return Err(codegen_error("frame alignment must be a power of two"));
    }
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or_else(|| codegen_error("frame size overflow"))
}

fn codegen_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        file: "<riscv64-codegen>".into(),
        span: Span::default(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocore::{mir, parser, typeck};

    fn assembly(source: &str) -> Result<String, Diagnostic> {
        let ast = parser::parse("riscv64-test.oc", source)?;
        let hir = typeck::check(&[("riscv64-test.oc".into(), ast)])?;
        let mir = mir::lower(&hir)?;
        emit_assembly(&hir, &mir)
    }

    /// Compile every runtime corpus case with the real RV64GC assembler when
    /// Clang is available. OCORE_TEST_QEMU_RISCV64 enables execution of a static
    /// Linux ELF through the caller-selected emulator, without a guest libc.
    fn check_object_and_optional_execution(asm: &str, entry: &str, expected: i32) {
        use std::{fs, process::Command};
        let clang = std::env::var_os("OCORE_CLANG").unwrap_or_else(|| "clang".into());
        if Command::new(&clang).arg("--version").output().is_err() {
            eprintln!("Clang unavailable; RV64 object/runtime qualification skipped");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("test.s");
        let object = dir.path().join("test.o");
        fs::write(&source, asm).unwrap();
        let result = Command::new(&clang)
            .args([
                "--target=riscv64-unknown-none-elf",
                "-march=rv64gc",
                "-mabi=lp64",
                "-c",
            ])
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
        let bytes = fs::read(&object).unwrap();
        assert_eq!(&bytes[..5], b"\x7fELF\x02");
        assert_eq!(
            u16::from_le_bytes([bytes[18], bytes[19]]),
            243,
            "object must use EM_RISCV"
        );
        let Some(qemu) = std::env::var_os("OCORE_TEST_QEMU_RISCV64") else {
            return;
        };
        let start = format!("\n.text\n.globl _start\n_start:\n{entry}\nli a7, 93\necall\n");
        fs::write(&source, format!("{asm}{start}")).unwrap();
        let executable = dir.path().join("test.elf");
        let result = Command::new(&clang)
            .args([
                "--target=riscv64-linux-gnu",
                "-march=rv64gc",
                "-mabi=lp64",
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
        let result = Command::new(qemu).arg(executable).output().unwrap();
        assert_eq!(
            result.status.code(),
            Some(expected),
            "execution stderr: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn executes_narrow_unsigned_operations_and_xlen_shift_counts() {
        let asm = assembly(
            r#"
module widths;
@export @no_mangle
fn exercise() -> u64 {
    let high: u32 = 0x80000000;
    if high <= 1 { return 1; }
    if (high >> 31) != 1 { return 2; }
    if (255 as u8) + (1 as u8) != 0 { return 3; }
    if ((1 as u8) << (64 as usize)) != 1 { return 4; }
    if ((128 as i8) / -(1 as i8)) != (128 as i8) { return 5; }
    if ((128 as i8) % -(1 as i8)) != 0 { return 6; }
    if ((128 as i8) >> (7 as usize)) != -(1 as i8) { return 7; }
    if (high as u64) != 0x80000000 { return 8; }
    return 42;
}
"#,
        )
        .unwrap();
        check_object_and_optional_execution(&asm, "call exercise", 42);
    }

    #[test]
    fn executes_stack_arguments_and_indirect_calls() {
        let asm = assembly(
            r#"
module many;
fn sum(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64) -> u64 {
    return a + b + c + d + e + f + g + h + i + j;
}
@export @no_mangle
unsafe fn exercise() -> u64 {
    let callback: fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) -> u64 = sum;
    let direct: u64 = sum(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    return callback(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) - direct + 42;
}
"#,
        )
        .unwrap();
        check_object_and_optional_execution(&asm, "call exercise", 42);
    }

    #[test]
    fn executes_large_aligned_frames_and_unaligned_packed_places() {
        let asm = assembly(
            r#"
module places;
@packed struct Packed { tag: u8, value: i64 }
@align(64) struct Aligned { value: u64 }
@export @no_mangle
unsafe fn exercise() -> u64 {
    let mut bytes: [u8; 8193] = [0; 8193];
    let mut packed: Packed = Packed { tag: 1, value: -(9 as i64) };
    let aligned: Aligned = Aligned { value: 42 };
    bytes[8192] = 7;
    packed.value = packed.value + 1;
    let field: *mut i64 = &mut packed.value;
    *field = *field + 1;
    if packed.value != -(7 as i64) { return 1; }
    if bytes[8192] != 7 { return 2; }
    if (((&aligned) as usize) & 63) != 0 { return 3; }
    return aligned.value;
}
"#,
        )
        .unwrap();
        check_object_and_optional_execution(&asm, "call exercise", 42);
    }

    #[test]
    fn executes_all_width_atomics_and_signed_subword_results() {
        let asm = assembly(r#"
module atomics;
static mut BYTE: i8 = 0;
static mut HALF: u16 = 7;
static mut WORD: u32 = 9;
static mut DOUBLE: u64 = 11;
@export @no_mangle
unsafe fn exercise() -> u64 {
    atomic_store(&mut BYTE, -(3 as i8), relaxed);
    if atomic_fetch_add(&mut BYTE, 1, acq_rel) != -(3 as i8) { return 1; }
    if atomic_compare_exchange(&mut BYTE, -(2 as i8), 4, seq_cst, acquire) != -(2 as i8) { return 2; }
    if atomic_compare_exchange(&mut BYTE, -(2 as i8), 99, relaxed, relaxed) != 4 { return 3; }
    if atomic_exchange(&mut HALF, 8, release) != 7 { return 4; }
    if atomic_fetch_add(&mut WORD, 3, acquire) != 9 { return 5; }
    if atomic_compare_exchange(&mut WORD, 12, 0x80000000, acq_rel, acquire) != 12 { return 6; }
    if atomic_load(&WORD, acquire) != 0x80000000 { return 7; }
    atomic_store(&mut DOUBLE, 42, seq_cst);
    return atomic_load(&DOUBLE, acquire);
}
"#).unwrap();
        check_object_and_optional_execution(&asm, "call exercise", 42);
    }

    #[test]
    fn executes_inline_assembly_with_emitter_scratch_and_callee_saved_outputs() {
        let asm = assembly(
            r#"
module assembly;
@export @no_mangle
unsafe fn exercise() -> u64 {
    let mut left: u64 = 10;
    let mut right: u64 = 20;
    let mut extra: u64 = 0;
    asm!("add t5, t5, t6\nli t6, 7\nli s11, 5",
         inout("t5") left -> left, inout("t6") right -> right, out("s11") extra);
    return left + right + extra;
}
"#,
        )
        .unwrap();
        check_object_and_optional_execution(&asm, "call exercise", 42);
    }

    #[test]
    fn executes_boolean_memory_casts_and_foreign_return_boundaries() {
        let mut asm = assembly(
            r#"
module booleans;
extern "C" fn foreign_false() -> bool;
extern "C" fn foreign_true() -> bool;
@export @no_mangle
unsafe fn exercise() -> u64 {
    let mut byte: u8 = 2;
    let pointer: *mut bool = (&mut byte) as *mut bool;
    if !*pointer { return 1; }
    if !volatile_load(pointer) { return 2; }
    byte = 0;
    if *pointer { return 3; }
    if volatile_load(pointer) { return 4; }
    if 0 as bool { return 5; }
    if !(2 as bool) { return 6; }
    if !(256 as bool) { return 7; }
    if !(0x8000000000000000 as bool) { return 8; }
    let mut from_asm: bool = false;
    asm!("li t0, 256", out("t0") from_asm);
    if !from_asm { return 9; }
    if foreign_false() { return 10; }
    if !foreign_true() { return 11; }
    let false_callback: extern "C" fn() -> bool = foreign_false;
    let true_callback: extern "C" fn() -> bool = foreign_true;
    if false_callback() { return 12; }
    if !true_callback() { return 13; }
    return 42;
}
"#,
        )
        .unwrap();
        asm.push_str("\n.text\n.globl foreign_false\nforeign_false:\nli a0, 256\nret\n.globl foreign_true\nforeign_true:\nli a0, 257\nret\n");
        check_object_and_optional_execution(&asm, "call exercise", 42);
    }

    #[test]
    fn executes_phi_cycles_as_parallel_edge_copies() {
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
            "li a0, 17\nli a1, 25\nli a2, 1\ncall exchange",
            25,
        );
    }

    #[test]
    fn executes_overlapping_aggregate_copies_in_both_directions() {
        let asm = assembly(
            r#"
module copies;
@export @no_mangle
unsafe fn exercise() -> u64 {
    let mut bytes: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    let start: *mut u8 = &mut bytes[0];
    let source: *const [u8; 8] = start as *const [u8; 8];
    let destination: *mut [u8; 8] = (start + 1) as *mut [u8; 8];
    *destination = *source;
    if bytes[1] != 0 { return 1; }
    if bytes[8] != 7 { return 2; }
    let reverse_source: *const [u8; 8] = (start + 1) as *const [u8; 8];
    let reverse_destination: *mut [u8; 8] = start as *mut [u8; 8];
    *reverse_destination = *reverse_source;
    if bytes[0] != 0 { return 3; }
    if bytes[7] != 7 { return 4; }
    return 42;
}
"#,
        )
        .unwrap();
        check_object_and_optional_execution(&asm, "call exercise", 42);
    }

    #[test]
    fn rejects_target_bound_abi_registers_and_port_io() {
        let error = assembly(r#"module abi; extern "sysv64" fn foreign(value: u64) -> u64; fn invoke() -> u64 { return foreign(1); }"#).unwrap_err();
        assert!(error.message.contains("sysv64"));
        let error =
            assembly("module ports; unsafe fn load() -> u8 { return inb(0x3f8); }").unwrap_err();
        assert!(error.message.contains("port-I/O"));
        for register in [
            "zero", "sp", "gp", "tp", "s0", "s1", "x0", "x2", "x8", "x9", "x32",
        ] {
            assert!(
                validate_register(register).is_err(),
                "{register} must be reserved"
            );
        }
        assert_eq!(
            validate_register("t5").unwrap(),
            validate_register("x30").unwrap()
        );
        let error = assembly(r#"module asm_alias; unsafe fn invoke(value: u64) -> void { let mut output: u64 = 0; asm!("nop", in("t0") value, out("x5") output); }"#).unwrap_err();
        assert!(error.message.contains("aliased"));
        let error = assembly(
            r#"module wrong_isa; @naked @no_mangle unsafe fn entry() -> void { asm!("mov rax, 1"); }"#,
        )
        .unwrap_err();
        assert!(error.message.contains("foreign architecture"));
    }

    #[test]
    fn rejects_invalid_compare_exchange_order_relationship_in_raw_mir() {
        let ast = parser::parse("orders.oc", r#"module orders; unsafe fn replace(pointer: *mut u64) -> u64 { return atomic_compare_exchange(pointer, 0, 1, relaxed, relaxed); }"#).unwrap();
        let hir = typeck::check(&[("orders.oc".into(), ast)]).unwrap();
        let mut mir = mir::lower(&hir).unwrap();
        let failure = mir.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find_map(|instruction| match instruction {
                Instruction::Intrinsic {
                    intrinsic: Intrinsic::AtomicCompareExchange,
                    args,
                    ..
                } => Some(args[4]),
                _ => None,
            })
            .unwrap();
        let constant = mir.functions[0]
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instructions)
            .find_map(|instruction| match instruction {
                Instruction::Const { dst, value } if *dst == failure => Some(value),
                _ => None,
            })
            .unwrap();
        *constant = MemoryOrder::Acquire as u64;
        let error = emit_assembly(&hir, &mir).unwrap_err();
        assert!(error.message.contains("failure"));
    }

    #[test]
    fn frame_size_overflow_and_invalid_alignment_are_rejected() {
        assert!(checked_align_up(u64::MAX, 16).is_err());
        assert!(checked_align_up(9, 3).is_err());
        assert_eq!(checked_align_up(9, 8).unwrap(), 16);
    }
}
