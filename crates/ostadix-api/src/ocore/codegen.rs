//! x86_64 freestanding assembly generation from typed SSA MIR.

use std::collections::HashMap;
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
    out.push_str(".intel_syntax noprefix\n");
    out.push_str(".file \"ocore\"\n");
    emit_statics(hir, &mut out)?;
    for function in &mir.functions {
        FunctionCodegen::new(hir, function).emit(&mut out, function_sections)?;
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
        (HirConstValue::Function(id), Type::Function { .. }) => {
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
            for (ty, value) in variant_def.payload.iter().zip(payload) {
                let layout = hir.types.layout(*ty);
                let next = align_up(cursor, layout.align);
                if next > cursor {
                    writeln!(out, ".zero {}", next - cursor).unwrap();
                }
                emit_const(hir, *ty, value, out)?;
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
        2 => writeln!(out, ".word {}", value as u16).unwrap(),
        4 => writeln!(out, ".long {}", value as u32).unwrap(),
        8 => writeln!(out, ".quad {value}").unwrap(),
        _ => return Err(codegen_error(format!("cannot emit {size}-byte scalar"))),
    }
    Ok(())
}

struct FrameLayout {
    locals: Vec<u64>,
    values: Vec<u64>,
    size: u64,
    alignment: u64,
}

impl FrameLayout {
    fn new(types: &TypeContext, function: &MirFunction) -> Self {
        let mut cursor = 0u64;
        let mut alignment = 16;
        let mut locals = Vec::new();
        for ty in &function.local_types {
            let layout = types.layout(*ty);
            alignment = alignment.max(layout.align);
            // Locals grow down from the frame base, so their final address
            // (base - offset), rather than the preceding slot, is aligned.
            cursor = align_up(cursor + layout.size.max(1), layout.align.max(1));
            locals.push(cursor);
        }
        let mut values = Vec::new();
        for _ in &function.values {
            cursor = align_up(cursor, 8);
            cursor += 8;
            values.push(cursor);
        }
        Self {
            locals,
            values,
            size: align_up(cursor, 16),
            alignment,
        }
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
    fn new(hir: &'a HirProgram, mir: &'a MirFunction) -> Self {
        let source = &hir.functions[mir.source];
        Self {
            hir,
            mir,
            source,
            frame: FrameLayout::new(&hir.types, mir),
            label_prefix: format!(".L_ocore_{}", mir.source),
        }
    }

    fn emit(&self, out: &mut String, function_sections: bool) -> Result<(), Diagnostic> {
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

        if self.source.abi == Abi::Interrupt {
            self.emit_interrupt_prologue(out);
        } else {
            out.push_str("  push rbp\n  mov rbp, rsp\n");
        }
        if self.has_aligned_frame() {
            // Keep the entry frame pointer for incoming stack arguments and
            // restoration; r12 is callee-preserved and never an asm operand.
            out.push_str("  push r12\n");
            if self.frame.alignment <= i32::MAX as u64 {
                writeln!(out, "  and rsp, -{}", self.frame.alignment).unwrap();
            } else {
                writeln!(
                    out,
                    "  mov rax, {}",
                    0u64.wrapping_sub(self.frame.alignment)
                )
                .unwrap();
                out.push_str("  and rsp, rax\n");
            }
            out.push_str("  mov r12, rsp\n");
        }
        let stack_size = self.stack_size();
        if stack_size != 0 {
            writeln!(out, "  sub rsp, {stack_size}").unwrap();
        }
        self.store_parameters(out)?;
        writeln!(out, "  jmp {}_bb{}", self.label_prefix, self.mir.entry).unwrap();

        for (block_id, block) in self.mir.blocks.iter().enumerate() {
            writeln!(out, "{}_bb{}:", self.label_prefix, block_id).unwrap();
            for instruction in &block.instructions {
                if !matches!(instruction, Instruction::Phi { .. }) {
                    self.emit_instruction(instruction, out)?;
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

    fn emit_interrupt_prologue(&self, out: &mut String) {
        out.push_str(
            "  push rax\n  push rcx\n  push rdx\n  push rsi\n  push rdi\n  push r8\n  push r9\n  push r10\n  push r11\n  push rbp\n  mov rbp, rsp\n  cld\n",
        );
    }

    fn store_parameters(&self, out: &mut String) -> Result<(), Diagnostic> {
        let registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
        for (index, local) in self.source.params.iter().enumerate() {
            let ty = self.source.locals[*local].ty;
            if !self.hir.types.is_scalar(ty) {
                return Err(codegen_error("aggregate parameters are not implemented"));
            }
            if matches!(self.source.abi, Abi::SysV64 | Abi::C) && self.hir.types.is_float(ty) {
                return Err(codegen_error(
                    "floating-point parameter escaped sysv64 ABI checking",
                ));
            }
            let offset = self.frame.locals[*local];
            if index < registers.len() {
                self.store_reg_to_frame(registers[index], offset, ty, out)?;
            } else {
                let caller_offset = 16 + (index - registers.len()) as u64 * 8;
                writeln!(out, "  mov rax, qword ptr [rbp+{caller_offset}]").unwrap();
                self.store_reg_to_frame("rax", offset, ty, out)?;
            }
        }
        Ok(())
    }

    fn emit_instruction(
        &self,
        instruction: &Instruction,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        match instruction {
            Instruction::Const { dst, value } => {
                // MIR gives effect-only/never expressions an unused zero
                // placeholder so every ValueId still has a definition.
                if !matches!(
                    self.hir.types.types[self.mir.values[*dst]],
                    Type::Void | Type::Never
                ) {
                    self.require_scalar_type(self.mir.values[*dst], "constant result")?;
                }
                if self.hir.types.is_float(self.mir.values[*dst]) {
                    return Err(codegen_error(
                        "floating-point constant escaped O-core type checking",
                    ));
                }
                writeln!(out, "  mov rax, {value}").unwrap();
                self.normalize_scalar("rax", self.mir.values[*dst], out)?;
                self.store_value(*dst, "rax", out);
            }
            Instruction::FunctionAddress { dst, function } => {
                self.validate_function_address(*dst, *function)?;
                writeln!(
                    out,
                    "  lea rax, [rip+{}]",
                    self.hir.functions[*function].symbol
                )
                .unwrap();
                self.store_value(*dst, "rax", out);
            }
            Instruction::AddressOf { dst, place } => {
                let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[*dst]]
                else {
                    return Err(codegen_error("address result is not a pointer"));
                };
                if pointee != place.ty {
                    return Err(codegen_error("address result pointee type mismatch"));
                }
                self.place_address(place, "r11", out)?;
                self.store_value(*dst, "r11", out);
            }
            Instruction::Load {
                dst,
                place,
                volatile,
            } => {
                self.require_same_type(self.mir.values[*dst], place.ty, "load result")?;
                self.require_scalar_type(place.ty, "load")?;
                self.place_address(place, "r11", out)?;
                if *volatile {
                    self.emit_alignment_check("r11", place.ty, out);
                }
                self.load_memory("rax", "r11", place.ty, out)?;
                self.store_value(*dst, "rax", out);
            }
            Instruction::Store {
                place,
                value,
                volatile,
            } => {
                self.require_same_type(self.mir.values[*value], place.ty, "store value")?;
                self.require_scalar_type(place.ty, "store")?;
                self.load_value(*value, "rax", out);
                self.place_address(place, "r11", out)?;
                if *volatile {
                    self.emit_alignment_check("r11", place.ty, out);
                }
                self.store_memory("rax", "r11", place.ty, out)?;
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
                self.place_address(destination, "rdi", out)?;
                self.place_address(source, "rsi", out)?;
                if *size != 0 {
                    let label = format!("{}_copy_{}", self.label_prefix, out.len());
                    writeln!(
                        out,
                        "  mov rcx, {size}\n  cmp rdi, rsi\n  jbe {label}_forward"
                    )
                    .unwrap();
                    out.push_str("  lea rdi, [rdi+rcx-1]\n  lea rsi, [rsi+rcx-1]\n  std\n  rep movsb\n  cld\n");
                    writeln!(
                        out,
                        "  jmp {label}_done\n{label}_forward:\n  rep movsb\n{label}_done:"
                    )
                    .unwrap();
                }
            }
            Instruction::Unary { dst, op, operand } => {
                self.validate_unary(*dst, *op, *operand)?;
                self.load_value(*operand, "rax", out);
                match op {
                    UnaryOp::Neg => out.push_str("  neg rax\n"),
                    UnaryOp::Not => out.push_str("  xor rax, 1\n"),
                    UnaryOp::BitNot => out.push_str("  not rax\n"),
                    UnaryOp::Deref | UnaryOp::AddressOf { .. } => {
                        return Err(codegen_error("place unary operation escaped MIR lowering"))
                    }
                }
                self.normalize_scalar("rax", self.mir.values[*dst], out)?;
                self.store_value(*dst, "rax", out);
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
                self.load_value(*value, "rax", out);
                self.normalize_scalar("rax", *from, out)?;
                self.normalize_scalar("rax", *to, out)?;
                self.store_value(*dst, "rax", out);
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
            } => self.emit_intrinsic(*dst, *intrinsic, args, out)?,
            Instruction::Phi { .. } => unreachable!(),
            Instruction::Asm {
                template, operands, ..
            } => self.emit_asm(template, operands, out)?,
        }
        Ok(())
    }

    fn validate_function_address(
        &self,
        dst: ValueId,
        function: FunctionId,
    ) -> Result<(), Diagnostic> {
        let target = &self.hir.functions[function];
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

    fn validate_call(
        &self,
        dst: Option<ValueId>,
        function: FunctionId,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        let target = &self.hir.functions[function];
        let parameter_types = target
            .params
            .iter()
            .map(|local| target.locals[*local].ty)
            .collect::<Vec<_>>();
        self.validate_scalar_call(
            dst,
            args,
            &parameter_types,
            target.result,
            &target.abi,
            "direct call",
        )
    }

    fn validate_indirect_call(
        &self,
        dst: Option<ValueId>,
        callee: ValueId,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        let Type::Function {
            params,
            result,
            abi,
        } = &self.hir.types.types[self.mir.values[callee]]
        else {
            return Err(codegen_error("indirect call requires a function pointer"));
        };
        self.validate_scalar_call(dst, args, params, *result, abi, "indirect call")
    }

    fn validate_scalar_call(
        &self,
        dst: Option<ValueId>,
        args: &[ValueId],
        parameter_types: &[TypeId],
        result: TypeId,
        abi: &Abi,
        context: &str,
    ) -> Result<(), Diagnostic> {
        if *abi == Abi::Interrupt {
            return Err(codegen_error(
                "interrupt handler reached ordinary-call lowering",
            ));
        }
        if args.len() != parameter_types.len() {
            return Err(codegen_error(format!("{context} argument count mismatch")));
        }
        for (arg, expected) in args.iter().zip(parameter_types.iter().copied()) {
            self.require_scalar_type(expected, &format!("{context} argument"))?;
            self.require_same_type(
                self.mir.values[*arg],
                expected,
                &format!("{context} argument"),
            )?;
            if matches!(abi, Abi::SysV64 | Abi::C) && self.hir.types.is_float(expected) {
                return Err(codegen_error(
                    "floating-point argument escaped sysv64 ABI checking",
                ));
            }
        }
        let no_result = matches!(self.hir.types.types[result], Type::Void | Type::Never);
        match (dst, no_result) {
            (None, true) => Ok(()),
            (Some(dst), false) => {
                self.require_scalar_type(result, &format!("{context} result"))?;
                self.require_same_type(self.mir.values[dst], result, &format!("{context} result"))?;
                if matches!(abi, Abi::SysV64 | Abi::C) && self.hir.types.is_float(result) {
                    return Err(codegen_error(
                        "floating-point result escaped sysv64 ABI checking",
                    ));
                }
                Ok(())
            }
            _ => Err(codegen_error(format!("{context} result shape mismatch"))),
        }
    }

    fn validate_intrinsic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
    ) -> Result<(), Diagnostic> {
        let u8_ty = self.hir.types.primitive("u8").unwrap();
        let u16_ty = self.hir.types.primitive("u16").unwrap();
        let u32_ty = self.hir.types.primitive("u32").unwrap();
        let u64_ty = self.hir.types.primitive("u64").unwrap();
        let usize_ty = self.hir.types.primitive("usize").unwrap();
        let signature = match intrinsic {
            Intrinsic::In8 => Some((vec![u16_ty], Some(u8_ty))),
            Intrinsic::In16 => Some((vec![u16_ty], Some(u16_ty))),
            Intrinsic::In32 => Some((vec![u16_ty], Some(u32_ty))),
            Intrinsic::Out8 => Some((vec![u16_ty, u8_ty], None)),
            Intrinsic::Out16 => Some((vec![u16_ty, u16_ty], None)),
            Intrinsic::Out32 => Some((vec![u16_ty, u32_ty], None)),
            Intrinsic::EnableInterrupts | Intrinsic::DisableInterrupts | Intrinsic::Halt => {
                Some((vec![], None))
            }
            Intrinsic::InvalidatePage => Some((vec![usize_ty], None)),
            Intrinsic::Syscall(count) => Some((vec![u64_ty; count as usize + 1], Some(u64_ty))),
            Intrinsic::VolatileLoad | Intrinsic::VolatileStore => {
                return Err(codegen_error(
                    "volatile intrinsic escaped MIR memory lowering",
                ))
            }
            Intrinsic::AtomicLoad
            | Intrinsic::AtomicStore
            | Intrinsic::AtomicExchange
            | Intrinsic::AtomicCompareExchange
            | Intrinsic::AtomicFetchAdd => None,
        };
        if let Some((expected_args, expected_result)) = signature {
            if args.len() != expected_args.len() {
                return Err(codegen_error("intrinsic argument count mismatch"));
            }
            for (arg, expected) in args.iter().zip(expected_args) {
                self.require_same_type(self.mir.values[*arg], expected, "intrinsic argument")?;
            }
            return self.require_optional_result(dst, expected_result, "intrinsic result");
        }

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
        let pointer_ty = self.mir.values[args[0]];
        let Type::Pointer { mutable, pointee } = self.hir.types.types[pointer_ty] else {
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
        let mut orders = Vec::with_capacity(order_count);
        for order in &args[1 + value_count..] {
            self.require_same_type(self.mir.values[*order], u8_ty, "atomic ordering")?;
            let order = self
                .const_from_value(*order)
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| codegen_error("atomic ordering must be constant in MIR"))?;
            super::typeck::validate_memory_order(intrinsic, order).map_err(codegen_error)?;
            orders.push(order);
        }
        if intrinsic == Intrinsic::AtomicCompareExchange {
            super::typeck::validate_compare_exchange_orders(orders[0], orders[1])
                .map_err(codegen_error)?;
        }
        let result = (intrinsic != Intrinsic::AtomicStore).then_some(pointee);
        self.require_optional_result(dst, result, "atomic result")
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

    fn emit_binary(
        &self,
        dst: ValueId,
        op: BinaryOp,
        lhs: ValueId,
        rhs: ValueId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_binary(dst, op, lhs, rhs)?;
        self.load_value(lhs, "rax", out);
        self.load_value(rhs, "rcx", out);
        let signed = is_signed(&self.hir.types.types[self.mir.values[lhs]]);
        match op {
            BinaryOp::Add | BinaryOp::Sub => {
                if let Type::Pointer { pointee, .. } = self.hir.types.types[self.mir.values[lhs]] {
                    let scale = self.hir.types.layout(pointee).size;
                    if scale != 1 {
                        self.multiply_constant("rcx", "r11", scale, out);
                    }
                }
                writeln!(
                    out,
                    "  {} rax, rcx",
                    if op == BinaryOp::Add { "add" } else { "sub" }
                )
                .unwrap();
            }
            BinaryOp::Mul => out.push_str("  imul rax, rcx\n"),
            BinaryOp::Div | BinaryOp::Rem => {
                if signed {
                    out.push_str("  cqo\n  idiv rcx\n");
                } else {
                    out.push_str("  xor rdx, rdx\n  div rcx\n");
                }
                if op == BinaryOp::Rem {
                    out.push_str("  mov rax, rdx\n");
                }
            }
            BinaryOp::BitAnd => out.push_str("  and rax, rcx\n"),
            BinaryOp::BitOr => out.push_str("  or rax, rcx\n"),
            BinaryOp::BitXor => out.push_str("  xor rax, rcx\n"),
            BinaryOp::ShiftLeft => out.push_str("  shl rax, cl\n"),
            BinaryOp::ShiftRight => {
                out.push_str(if signed {
                    "  sar rax, cl\n"
                } else {
                    "  shr rax, cl\n"
                });
            }
            BinaryOp::Eq
            | BinaryOp::NotEq
            | BinaryOp::Less
            | BinaryOp::LessEq
            | BinaryOp::Greater
            | BinaryOp::GreaterEq => {
                out.push_str("  cmp rax, rcx\n");
                let cc = match (op, signed) {
                    (BinaryOp::Eq, _) => "e",
                    (BinaryOp::NotEq, _) => "ne",
                    (BinaryOp::Less, true) => "l",
                    (BinaryOp::LessEq, true) => "le",
                    (BinaryOp::Greater, true) => "g",
                    (BinaryOp::GreaterEq, true) => "ge",
                    (BinaryOp::Less, false) => "b",
                    (BinaryOp::LessEq, false) => "be",
                    (BinaryOp::Greater, false) => "a",
                    (BinaryOp::GreaterEq, false) => "ae",
                    _ => unreachable!(),
                };
                writeln!(out, "  set{cc} al\n  movzx rax, al").unwrap();
            }
            BinaryOp::LogicalAnd | BinaryOp::LogicalOr => {
                return Err(codegen_error(
                    "logical operator escaped short-circuit lowering",
                ))
            }
        }
        self.normalize_scalar("rax", self.mir.values[dst], out)?;
        self.store_value(dst, "rax", out);
        Ok(())
    }

    fn emit_call(
        &self,
        dst: Option<ValueId>,
        function: FunctionId,
        args: &[ValueId],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_call(dst, function, args)?;
        let stack_bytes = self.emit_call_arguments(args, out);
        writeln!(out, "  call {}", self.hir.functions[function].symbol).unwrap();
        self.prepare_foreign_boolean_result(dst, self.hir.functions[function].abi, out);
        self.finish_call(dst, stack_bytes, out)
    }

    fn emit_indirect_call(
        &self,
        dst: Option<ValueId>,
        callee: ValueId,
        args: &[ValueId],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        self.validate_indirect_call(dst, callee, args)?;
        let stack_bytes = self.emit_call_arguments(args, out);
        // Argument preparation can consume scratch registers. Load the callee
        // last, into a caller-saved register outside the integer argument set.
        self.load_value(callee, "r11", out);
        out.push_str("  call r11\n");
        let Type::Function { abi, .. } = self.hir.types.types[self.mir.values[callee]] else {
            unreachable!("validated function-pointer call")
        };
        self.prepare_foreign_boolean_result(dst, abi, out);
        self.finish_call(dst, stack_bytes, out)
    }

    fn prepare_foreign_boolean_result(&self, dst: Option<ValueId>, abi: Abi, out: &mut String) {
        if matches!(abi, Abi::C | Abi::SysV64)
            && dst
                .is_some_and(|dst| matches!(self.hir.types.types[self.mir.values[dst]], Type::Bool))
        {
            // INTEGER return bits outside the declared scalar width are
            // unspecified in the AMD64 ABI. A false AL with junk upper bits
            // must stay false before full-value Boolean normalization.
            out.push_str("  movzx rax, al\n");
        }
    }

    fn emit_call_arguments(&self, args: &[ValueId], out: &mut String) -> usize {
        let registers = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
        let stack_count = args.len().saturating_sub(registers.len());
        let pad = stack_count % 2;
        if pad != 0 {
            out.push_str("  sub rsp, 8\n");
        }
        for value in args.iter().skip(registers.len()).rev() {
            self.load_value(*value, "rax", out);
            out.push_str("  push rax\n");
        }
        for (value, register) in args.iter().zip(registers) {
            self.load_value(*value, register, out);
        }
        (stack_count + pad) * 8
    }

    fn finish_call(
        &self,
        dst: Option<ValueId>,
        stack_bytes: usize,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        if stack_bytes != 0 {
            writeln!(out, "  add rsp, {stack_bytes}").unwrap();
        }
        if let Some(dst) = dst {
            self.normalize_scalar("rax", self.mir.values[dst], out)?;
            self.store_value(dst, "rax", out);
        }
        Ok(())
    }

    fn emit_intrinsic(
        &self,
        dst: Option<ValueId>,
        intrinsic: Intrinsic,
        args: &[ValueId],
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
            self.load_value(args[0], "r11", out);
            let pointee = pointer_pointee(&self.hir.types, self.mir.values[args[0]])?;
            self.emit_alignment_check("r11", pointee, out);
        }
        match intrinsic {
            Intrinsic::In8 | Intrinsic::In16 | Intrinsic::In32 => {
                self.load_value(args[0], "rdx", out);
                out.push_str(match intrinsic {
                    Intrinsic::In8 => "  in al, dx\n  movzx rax, al\n",
                    Intrinsic::In16 => "  in ax, dx\n  movzx rax, ax\n",
                    _ => "  in eax, dx\n",
                });
            }
            Intrinsic::Out8 | Intrinsic::Out16 | Intrinsic::Out32 => {
                self.load_value(args[0], "rdx", out);
                self.load_value(args[1], "rax", out);
                out.push_str(match intrinsic {
                    Intrinsic::Out8 => "  out dx, al\n",
                    Intrinsic::Out16 => "  out dx, ax\n",
                    _ => "  out dx, eax\n",
                });
            }
            Intrinsic::EnableInterrupts => out.push_str("  sti\n"),
            Intrinsic::DisableInterrupts => out.push_str("  cli\n"),
            Intrinsic::Halt => out.push_str("  hlt\n"),
            Intrinsic::InvalidatePage => {
                self.load_value(args[0], "rax", out);
                out.push_str("  invlpg [rax]\n");
            }
            Intrinsic::Syscall(count) => {
                let regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"];
                self.load_value(args[0], "rax", out);
                for (value, reg) in args[1..].iter().zip(regs.iter().take(count as usize)) {
                    self.load_value(*value, reg, out);
                }
                out.push_str("  syscall\n");
            }
            Intrinsic::AtomicLoad => {
                let ty = self.mir.values[dst.unwrap()];
                self.load_memory("rax", "r11", ty, out)?;
            }
            Intrinsic::AtomicStore => {
                self.load_value(args[1], "rax", out);
                let pointee = pointer_pointee(&self.hir.types, self.mir.values[args[0]])?;
                let order = self.const_from_value(args[2]);
                if order == Some(MemoryOrder::SeqCst as u64) {
                    self.emit_xchg("rax", "r11", pointee, out)?;
                } else {
                    self.store_memory("rax", "r11", pointee, out)?;
                }
            }
            Intrinsic::AtomicExchange => {
                self.load_value(args[1], "rax", out);
                let ty = self.mir.values[dst.unwrap()];
                self.emit_xchg("rax", "r11", ty, out)?;
            }
            Intrinsic::AtomicFetchAdd => {
                self.load_value(args[1], "rax", out);
                let ty = self.mir.values[dst.unwrap()];
                let size = self.hir.types.layout(ty).size;
                writeln!(
                    out,
                    "  lock xadd {} ptr [r11], {}",
                    size_name(size)?,
                    subreg("rax", size)?
                )
                .unwrap();
            }
            Intrinsic::AtomicCompareExchange => {
                self.load_value(args[1], "rax", out);
                self.load_value(args[2], "rcx", out);
                let ty = self.mir.values[dst.unwrap()];
                let size = self.hir.types.layout(ty).size;
                writeln!(
                    out,
                    "  lock cmpxchg {} ptr [r11], {}",
                    size_name(size)?,
                    subreg("rcx", size)?
                )
                .unwrap();
            }
            Intrinsic::VolatileLoad | Intrinsic::VolatileStore => {
                return Err(codegen_error(
                    "volatile intrinsic escaped MIR memory lowering",
                ))
            }
        }
        if let Some(dst) = dst {
            self.store_value(dst, "rax", out);
        }
        Ok(())
    }

    fn emit_xchg(
        &self,
        reg: &str,
        address: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let size = self.hir.types.layout(ty).size;
        writeln!(
            out,
            "  xchg {} ptr [{address}], {}",
            size_name(size)?,
            subreg(reg, size)?
        )
        .unwrap();
        Ok(())
    }

    fn const_from_value(&self, value: ValueId) -> Option<u64> {
        self.mir
            .blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .find_map(|i| {
                if let Instruction::Const { dst, value: v } = i {
                    (*dst == value).then_some(*v)
                } else {
                    None
                }
            })
    }

    fn emit_asm(
        &self,
        template: &str,
        operands: &[MirAsmOperand],
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let mut outputs = Vec::new();
        for operand in operands {
            match operand {
                MirAsmOperand::In { register, value } => {
                    validate_register(register)?;
                    self.require_asm_value(self.mir.values[*value])?;
                    self.load_value(*value, register, out);
                }
                MirAsmOperand::Out { register, target } => {
                    validate_register(register)?;
                    self.require_asm_value(target.ty)?;
                    outputs.push((register.as_str(), target));
                }
                MirAsmOperand::InOut {
                    register,
                    input,
                    output,
                } => {
                    validate_register(register)?;
                    self.require_asm_value(self.mir.values[*input])?;
                    self.require_asm_value(output.ty)?;
                    self.require_same_type(
                        self.mir.values[*input],
                        output.ty,
                        "assembly inout operand",
                    )?;
                    self.load_value(*input, register, out);
                    outputs.push((register.as_str(), output));
                }
            }
        }
        for line in template.lines() {
            writeln!(out, "  {line}").unwrap();
        }
        // Output-place evaluation uses r10/r11 as scratch. Snapshot every
        // output before evaluating any destination so one address cannot
        // destroy another output register (including indexed destinations).
        for (register, _) in outputs.iter().rev() {
            writeln!(out, "  push {register}").unwrap();
        }
        for (_, target) in outputs {
            out.push_str("  pop rax\n");
            self.normalize_scalar("rax", target.ty, out)?;
            self.place_address(target, "r11", out)?;
            self.store_memory("rax", "r11", target.ty, out)?;
        }
        Ok(())
    }

    fn require_asm_value(&self, ty: TypeId) -> Result<(), Diagnostic> {
        self.require_scalar_type(ty, "inline assembly operand")?;
        if self.hir.types.is_float(ty) {
            return Err(codegen_error(
                "floating-point inline assembly operand escaped type checking",
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
            Terminator::Unreachable => out.push_str("  ud2\n"),
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
                        if matches!(self.source.abi, Abi::SysV64 | Abi::C)
                            && self.hir.types.is_float(self.source.result)
                        {
                            return Err(codegen_error(
                                "floating-point result escaped sysv64 ABI checking",
                            ));
                        }
                        self.load_value(*value, "rax", out);
                    }
                    (None, true) => {}
                    _ => return Err(codegen_error("return value shape mismatch")),
                }
                self.emit_epilogue(out);
            }
            Terminator::Jump(target) => {
                self.emit_phi_moves(block_id, *target, out)?;
                writeln!(out, "  jmp {}_bb{target}", self.label_prefix).unwrap();
            }
            Terminator::Branch {
                condition,
                then_block,
                else_block,
            } => {
                let bool_ty = self.hir.types.primitive("bool").unwrap();
                self.require_same_type(self.mir.values[*condition], bool_ty, "branch condition")?;
                let then_edge = format!("{}_bb{}_then_edge", self.label_prefix, block_id);
                self.load_value(*condition, "rax", out);
                out.push_str("  test rax, rax\n");
                writeln!(out, "  jne {then_edge}").unwrap();
                self.emit_phi_moves(block_id, *else_block, out)?;
                writeln!(out, "  jmp {}_bb{else_block}", self.label_prefix).unwrap();
                writeln!(out, "{then_edge}:").unwrap();
                self.emit_phi_moves(block_id, *then_block, out)?;
                writeln!(out, "  jmp {}_bb{then_block}", self.label_prefix).unwrap();
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
        let mut copies = Vec::new();
        for instruction in &self.mir.blocks[to].instructions {
            let Instruction::Phi { dst, incoming } = instruction else {
                continue;
            };
            let (_, value) = incoming
                .iter()
                .find(|(block, _)| *block == from)
                .ok_or_else(|| codegen_error("phi has no incoming value for control-flow edge"))?;
            self.require_same_type(
                self.mir.values[*value],
                self.mir.values[*dst],
                "phi incoming value",
            )?;
            self.require_scalar_type(self.mir.values[*dst], "phi result")?;
            if value != dst {
                copies.push((*dst, *value));
            }
        }
        // Phi assignments happen simultaneously. Snapshot sources before
        // replacing any destinations; this also handles loop-carried cycles.
        for (_, value) in &copies {
            self.load_value(*value, "rax", out);
            out.push_str("  push rax\n");
        }
        for (dst, _) in copies.into_iter().rev() {
            out.push_str("  pop rax\n");
            self.store_value(dst, "rax", out);
        }
        Ok(())
    }

    fn emit_epilogue(&self, out: &mut String) {
        if self.has_aligned_frame() {
            out.push_str("  lea rsp, [rbp-8]\n  pop r12\n");
        } else {
            let stack_size = self.stack_size();
            if stack_size != 0 {
                writeln!(out, "  add rsp, {stack_size}").unwrap();
            }
        }
        if self.source.abi == Abi::Interrupt {
            out.push_str(
                "  pop rbp\n  pop r11\n  pop r10\n  pop r9\n  pop r8\n  pop rdi\n  pop rsi\n  pop rdx\n  pop rcx\n  pop rax\n  iretq\n",
            );
        } else {
            out.push_str("  pop rbp\n  ret\n");
        }
    }

    fn stack_size(&self) -> u64 {
        // In 64-bit mode the hardware frame is RIP, CS, RFLAGS, RSP, and SS
        // (40 bytes), including same-privilege delivery. After saving nine
        // volatile registers plus RBP, the stack is eight bytes off the SysV
        // call boundary. Reserve one padding slot so interrupt handlers can
        // safely call ordinary O-core functions.
        self.frame.size
            + u64::from(self.source.abi == Abi::Interrupt && !self.has_aligned_frame()) * 8
    }

    fn has_aligned_frame(&self) -> bool {
        self.frame.alignment > 16
    }

    fn frame_base(&self) -> &'static str {
        if self.has_aligned_frame() {
            "r12"
        } else {
            "rbp"
        }
    }

    fn place_address(
        &self,
        place: &Place,
        register: &str,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        match place.base {
            PlaceBase::Local(local) => {
                writeln!(
                    out,
                    "  lea {register}, [{}-{}]",
                    self.frame_base(),
                    self.frame.locals[local]
                )
                .unwrap();
            }
            PlaceBase::Static(static_id) => {
                writeln!(
                    out,
                    "  lea {register}, [rip+{}]",
                    self.hir.statics[static_id].symbol
                )
                .unwrap();
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
                        if *offset <= i32::MAX as u64 {
                            writeln!(out, "  add {register}, {offset}").unwrap();
                        } else {
                            let scratch = if register == "r10" { "r11" } else { "r10" };
                            writeln!(
                                out,
                                "  mov {scratch}, {offset}\n  add {register}, {scratch}"
                            )
                            .unwrap();
                        }
                    }
                }
                Projection::Index {
                    index,
                    element_size,
                } => {
                    self.require_integer_type(self.mir.values[*index], "place index")?;
                    let scratch = if register == "r10" { "r11" } else { "r10" };
                    self.load_value(*index, scratch, out);
                    if *element_size != 1 {
                        self.multiply_constant(scratch, "rcx", *element_size, out);
                    }
                    writeln!(out, "  add {register}, {scratch}").unwrap();
                }
            }
        }
        Ok(())
    }

    fn multiply_constant(&self, register: &str, scratch: &str, value: u64, out: &mut String) {
        if value <= i32::MAX as u64 {
            writeln!(out, "  imul {register}, {value}").unwrap();
        } else {
            writeln!(
                out,
                "  mov {scratch}, {value}\n  imul {register}, {scratch}"
            )
            .unwrap();
        }
    }

    fn emit_alignment_check(&self, address: &str, ty: TypeId, out: &mut String) {
        let alignment = self.hir.types.layout(ty).size;
        if alignment > 1 {
            let label = format!("{}_aligned_{}", self.label_prefix, out.len());
            writeln!(
                out,
                "  test {address}, {}\n  jz {label}\n  ud2\n{label}:",
                alignment - 1
            )
            .unwrap();
        }
    }

    fn load_value(&self, value: ValueId, register: &str, out: &mut String) {
        writeln!(
            out,
            "  mov {register}, qword ptr [{}-{}]",
            self.frame_base(),
            self.frame.values[value]
        )
        .unwrap();
    }

    fn store_value(&self, value: ValueId, register: &str, out: &mut String) {
        writeln!(
            out,
            "  mov qword ptr [{}-{}], {register}",
            self.frame_base(),
            self.frame.values[value]
        )
        .unwrap();
    }

    fn store_reg_to_frame(
        &self,
        register: &str,
        offset: u64,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        let size = self.hir.types.layout(ty).size;
        writeln!(
            out,
            "  mov {} ptr [{}-{offset}], {}",
            size_name(size)?,
            self.frame_base(),
            subreg(register, size)?
        )
        .unwrap();
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
        match (size, signed) {
            (1, false) => writeln!(out, "  movzx {dst}, byte ptr [{address}]").unwrap(),
            (1, true) => writeln!(out, "  movsx {dst}, byte ptr [{address}]").unwrap(),
            (2, false) => writeln!(out, "  movzx {dst}, word ptr [{address}]").unwrap(),
            (2, true) => writeln!(out, "  movsx {dst}, word ptr [{address}]").unwrap(),
            (4, false) => {
                writeln!(out, "  mov {}, dword ptr [{address}]", subreg(dst, 4)?).unwrap()
            }
            (4, true) => writeln!(out, "  movsxd {dst}, dword ptr [{address}]").unwrap(),
            (8, _) => writeln!(out, "  mov {dst}, qword ptr [{address}]").unwrap(),
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
        writeln!(
            out,
            "  mov {} ptr [{address}], {}",
            size_name(size)?,
            subreg(src, size)?
        )
        .unwrap();
        Ok(())
    }

    fn normalize_scalar(
        &self,
        register: &str,
        ty: TypeId,
        out: &mut String,
    ) -> Result<(), Diagnostic> {
        if matches!(self.hir.types.types[ty], Type::Bool) {
            let byte = subreg(register, 1)?;
            writeln!(
                out,
                "  test {register}, {register}\n  setne {byte}\n  movzx {register}, {byte}"
            )
            .unwrap();
            return Ok(());
        }
        let size = self.hir.types.layout(ty).size;
        let signed = is_signed(&self.hir.types.types[ty]);
        match (size, signed) {
            (1, false) => writeln!(out, "  movzx {register}, {}", subreg(register, 1)?).unwrap(),
            (1, true) => writeln!(out, "  movsx {register}, {}", subreg(register, 1)?).unwrap(),
            (2, false) => writeln!(out, "  movzx {register}, {}", subreg(register, 2)?).unwrap(),
            (2, true) => writeln!(out, "  movsx {register}, {}", subreg(register, 2)?).unwrap(),
            (4, false) => {
                let r32 = subreg(register, 4)?;
                writeln!(out, "  mov {r32}, {r32}").unwrap();
            }
            (4, true) => writeln!(out, "  movsxd {register}, {}", subreg(register, 4)?).unwrap(),
            (8, _) | (0, _) => {}
            _ => {
                return Err(codegen_error(format!(
                    "cannot normalize {size}-byte scalar"
                )))
            }
        }
        Ok(())
    }
}

fn pointer_pointee(types: &TypeContext, ty: TypeId) -> Result<TypeId, Diagnostic> {
    match types.types[ty] {
        Type::Pointer { pointee, .. } => Ok(pointee),
        _ => Err(codegen_error("expected pointer type")),
    }
}

fn is_signed(ty: &Type) -> bool {
    matches!(ty, Type::Int { signed: true, .. } | Type::Isize)
}

fn size_name(size: u64) -> Result<&'static str, Diagnostic> {
    match size {
        1 => Ok("byte"),
        2 => Ok("word"),
        4 => Ok("dword"),
        8 => Ok("qword"),
        _ => Err(codegen_error(format!("unsupported scalar size {size}"))),
    }
}

fn subreg(register: &str, size: u64) -> Result<&'static str, Diagnostic> {
    let table: HashMap<&str, [&str; 4]> = HashMap::from([
        ("rax", ["al", "ax", "eax", "rax"]),
        ("rbx", ["bl", "bx", "ebx", "rbx"]),
        ("rcx", ["cl", "cx", "ecx", "rcx"]),
        ("rdx", ["dl", "dx", "edx", "rdx"]),
        ("rsi", ["sil", "si", "esi", "rsi"]),
        ("rdi", ["dil", "di", "edi", "rdi"]),
        ("r8", ["r8b", "r8w", "r8d", "r8"]),
        ("r9", ["r9b", "r9w", "r9d", "r9"]),
        ("r10", ["r10b", "r10w", "r10d", "r10"]),
        ("r11", ["r11b", "r11w", "r11d", "r11"]),
    ]);
    let index = match size {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => return Err(codegen_error(format!("unsupported register width {size}"))),
    };
    table
        .get(register)
        .map(|v| v[index])
        .ok_or_else(|| codegen_error(format!("unsupported register `{register}`")))
}

fn validate_register(register: &str) -> Result<(), Diagnostic> {
    const ALLOWED: &[&str] = &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];
    if ALLOWED.contains(&register) {
        Ok(())
    } else {
        Err(codegen_error(format!(
            "unsupported asm register `{register}`"
        )))
    }
}

fn codegen_error(message: impl Into<String>) -> Diagnostic {
    Diagnostic {
        file: "<x86_64-codegen>".into(),
        span: Span::default(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ocore::{mir, parser, typeck};

    fn compile_source(source: &str) -> (HirProgram, MirProgram) {
        let ast = parser::parse("native.oc", source).unwrap();
        let hir = typeck::check(&[("native.oc".into(), ast)]).unwrap();
        let mir = mir::lower(&hir).unwrap();
        (hir, mir)
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn execute_with_c(assembly: &str, harness: &str) {
        use std::process::Command;

        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("SKIP-OPTIONAL: native x86_64 execution requires clang");
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let assembly_path = directory.path().join("program.s");
        let harness_path = directory.path().join("harness.c");
        let executable = directory.path().join("program");
        std::fs::write(&assembly_path, assembly).unwrap();
        std::fs::write(&harness_path, harness).unwrap();
        let compile = Command::new("clang")
            .args(["-O2", "-fno-pie", "-no-pie"])
            .arg(&assembly_path)
            .arg(&harness_path)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let run = Command::new(&executable).output().unwrap();
        assert!(
            run.status.success(),
            "native execution returned {:?}: {}{}",
            run.status.code(),
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn executes_scalar_widths_asm_outputs_and_overaligned_stack_arguments() {
        let (hir, mir) = compile_source(
            r#"
module native_regressions;
@align(64) struct Aligned { value: u64 }
struct FarField { before: [u8; 2147483648], value: u8 }
@export @no_mangle fn bitnot_u8(value: u8) -> bool { return ~value == 255; }
@export @no_mangle fn negate_u8(value: u8) -> bool { return -value == 255; }
@export @no_mangle fn bitnot_divide(value: u8) -> u8 { return ~value / 2; }
@export @no_mangle unsafe fn scratch_outputs() -> u64 {
    let mut first: u64 = 0;
    let mut second: u64 = 0;
    asm!("mov r10, 11\nmov r11, 22", out("r10") first, out("r11") second, options(nostack));
    return first * 100 + second;
}
@export @no_mangle unsafe fn indexed_outputs() -> u64 {
    let mut values: [u64; 2] = [0; 2];
    let index: usize = 1;
    let mut first: u64 = 0;
    asm!("mov r11, 22\nmov r10, 11", out("r11") values[index], out("r10") first, options(nostack));
    return first * 100 + values[index];
}
@export @no_mangle unsafe fn aligned_stack(
    a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64
) -> u64 {
    let value: Aligned = Aligned { value: a + b + c + d + e + f + g + h + i };
    let address: usize = (&value) as usize;
    return value.value + (address & 63) as u64;
}
@export @no_mangle unsafe fn copy_eight(destination: *mut [u8; 8], source: *const [u8; 8]) {
    *destination = *source;
}
@export @no_mangle unsafe fn wide_pointer_offset(pointer: *const [u8; 2147483648]) -> usize {
    return (pointer + 1) as usize;
}
@export @no_mangle unsafe fn wide_field_offset(pointer: *const FarField) -> usize {
    return (&(*pointer).value) as usize;
}
@export @no_mangle unsafe fn wide_index_offset(pointer: *const [u8; 2147483648], index: usize) -> usize {
    return (&pointer[index]) as usize;
}
"#,
        );
        let assembly = emit_assembly(&hir, &mir).unwrap();
        assert!(assembly.contains("and rsp, -64"));
        assert!(assembly.contains("mov rax, qword ptr [rbp+32]"));
        execute_with_c(
            &assembly,
            r#"
#include <stdbool.h>
#include <stdint.h>
extern bool bitnot_u8(uint8_t);
extern bool negate_u8(uint8_t);
extern uint8_t bitnot_divide(uint8_t);
extern uint64_t scratch_outputs(void);
extern uint64_t indexed_outputs(void);
extern uint64_t aligned_stack(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
extern void copy_eight(void *, const void *);
extern uintptr_t wide_pointer_offset(const void *);
extern uintptr_t wide_field_offset(const void *);
extern uintptr_t wide_index_offset(const void *, uintptr_t);
int main(void) {
    if (!bitnot_u8(0) || !negate_u8(1) || bitnot_divide(0) != 127) return 1;
    if (scratch_outputs() != 1122 || indexed_outputs() != 1122) return 2;
    for (unsigned n = 0; n < 64; ++n) {
        if (aligned_stack(1,2,3,4,5,6,7,8,9) != 45) return 3;
    }
    uint8_t backward[9] = {0,1,2,3,4,5,6,7,8};
    uint8_t forward[9] = {0,1,2,3,4,5,6,7,8};
    copy_eight(backward + 1, backward);
    copy_eight(forward, forward + 1);
    for (unsigned n = 0; n < 8; ++n) {
        if (backward[n + 1] != n || forward[n] != n + 1) return 4;
    }
    copy_eight(backward, backward);
    unsigned long flags;
    __asm__ volatile("pushfq; popq %0" : "=r"(flags));
    if (flags & (1UL << 10)) return 5;
    register uint64_t sentinel __asm__("r12") = UINT64_C(0x123456789abcdef0);
    __asm__ volatile("" : "+r"(sentinel));
    if (aligned_stack(1,2,3,4,5,6,7,8,9) != 45) return 6;
    __asm__ volatile("" : "+r"(sentinel));
    if (sentinel != UINT64_C(0x123456789abcdef0)) return 7;
    const void *address = (const void *)(uintptr_t)UINT64_C(0x100000000);
    if (wide_pointer_offset(address) != UINT64_C(0x180000000)) return 8;
    if (wide_field_offset(address) != UINT64_C(0x180000000)) return 9;
    if (wide_index_offset(address, 2) != UINT64_C(0x200000000)) return 10;
    return 0;
}
"#,
        );
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn executes_direct_and_indirect_c_calls_with_stack_arguments() {
        let (hir, mir) = compile_source(
            r#"
module c_calls;
extern "C" fn c7(a: u64,b: u64,c: u64,d: u64,e: u64,f: u64,g: u64) -> u64;
extern "C" fn c8(a: u64,b: u64,c: u64,d: u64,e: u64,f: u64,g: u64,h: u64) -> u64;
extern "C" fn c9(a: u64,b: u64,c: u64,d: u64,e: u64,f: u64,g: u64,h: u64,i: u64) -> u64;
extern "C" fn align7(a: u64,b: u64,c: u64,d: u64,e: u64,f: u64,g: u64) -> u64;
extern "C" fn align8(a: u64,b: u64,c: u64,d: u64,e: u64,f: u64,g: u64,h: u64) -> u64;
extern "C" fn align9(a: u64,b: u64,c: u64,d: u64,e: u64,f: u64,g: u64,h: u64,i: u64) -> u64;
@export @no_mangle fn direct_calls() -> u64 {
    return c7(1,2,3,4,5,6,7) + c8(1,2,3,4,5,6,7,8) + c9(1,2,3,4,5,6,7,8,9);
}
@export @no_mangle fn call_alignment() -> u64 {
    return align7(1,2,3,4,5,6,7) + align8(1,2,3,4,5,6,7,8) + align9(1,2,3,4,5,6,7,8,9);
}
@export @no_mangle unsafe fn indirect_call(
    callback: extern "C" fn(u64,u64,u64,u64,u64,u64,u64,u64,u64) -> u64
) -> u64 { return callback(1,2,3,4,5,6,7,8,9); }
@export @no_mangle unsafe fn indirect_u32(callback: extern "C" fn(u32) -> u32, value: u32) -> bool {
    return callback(value) == value;
}
"#,
        );
        let mut assembly = emit_assembly(&hir, &mir).unwrap();
        assert!(assembly.contains("call r11"));
        for symbol in ["align7", "align8", "align9"] {
            writeln!(
                assembly,
                ".text\n.globl {symbol}\n{symbol}:\n  mov rax, rsp\n  and rax, 15\n  ret"
            )
            .unwrap();
        }
        execute_with_c(
            &assembly,
            r#"
#include <stdbool.h>
#include <stdint.h>
uint64_t c7(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g) {
    return a + 2*b + 3*c + 4*d + 5*e + 6*f + 7*g;
}
uint64_t c8(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,uint64_t h) {
    return c7(a,b,c,d,e,f,g) + 8*h;
}
uint64_t c9(uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f,uint64_t g,uint64_t h,uint64_t i) {
    return c8(a,b,c,d,e,f,g,h) + 9*i;
}
uint32_t identity32(uint32_t value) { return value; }
extern uint64_t direct_calls(void);
extern uint64_t call_alignment(void);
extern uint64_t indirect_call(uint64_t (*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t));
extern bool indirect_u32(uint32_t (*)(uint32_t), uint32_t);
int main(void) {
    if (direct_calls() != 629 || indirect_call(c9) != 285) return 1;
    if (call_alignment() != 24) return 2;
    if (!indirect_u32(identity32, UINT32_C(0xf1234567))) return 3;
    return 0;
}
"#,
        );
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn executes_parallel_phi_cycle() {
        let (hir, mut mir) =
            compile_source("module phis; @export @no_mangle fn phi_swap() -> u64 { return 0; }");
        let u64_ty = hir.types.primitive("u64").unwrap();
        let bool_ty = hir.types.primitive("bool").unwrap();
        mir.functions[0] = MirFunction {
            source: 0,
            local_types: vec![],
            values: vec![
                u64_ty, u64_ty, u64_ty, u64_ty, u64_ty, u64_ty, u64_ty, u64_ty, u64_ty, bool_ty,
                u64_ty, u64_ty, u64_ty,
            ],
            entry: 0,
            blocks: vec![
                BasicBlock {
                    instructions: vec![
                        Instruction::Const { dst: 0, value: 1 },
                        Instruction::Const { dst: 1, value: 2 },
                        Instruction::Const { dst: 2, value: 0 },
                        Instruction::Const { dst: 6, value: 1 },
                        Instruction::Const { dst: 8, value: 3 },
                        Instruction::Const { dst: 10, value: 10 },
                    ],
                    terminator: Terminator::Jump(1),
                },
                BasicBlock {
                    instructions: vec![
                        Instruction::Phi {
                            dst: 3,
                            incoming: vec![(0, 0), (1, 4)],
                        },
                        Instruction::Phi {
                            dst: 4,
                            incoming: vec![(0, 1), (1, 3)],
                        },
                        Instruction::Phi {
                            dst: 5,
                            incoming: vec![(0, 2), (1, 7)],
                        },
                        Instruction::Binary {
                            dst: 7,
                            op: BinaryOp::Add,
                            lhs: 5,
                            rhs: 6,
                        },
                        Instruction::Binary {
                            dst: 9,
                            op: BinaryOp::Less,
                            lhs: 7,
                            rhs: 8,
                        },
                    ],
                    terminator: Terminator::Branch {
                        condition: 9,
                        then_block: 1,
                        else_block: 2,
                    },
                },
                BasicBlock {
                    instructions: vec![
                        Instruction::Binary {
                            dst: 11,
                            op: BinaryOp::Mul,
                            lhs: 3,
                            rhs: 10,
                        },
                        Instruction::Binary {
                            dst: 12,
                            op: BinaryOp::Add,
                            lhs: 11,
                            rhs: 4,
                        },
                    ],
                    terminator: Terminator::Return(Some(12)),
                },
            ],
        };
        execute_with_c(
            &emit_assembly(&hir, &mir).unwrap(),
            r#"
#include <stdint.h>
extern uint64_t phi_swap(void);
int main(void) { return phi_swap() == 12 ? 0 : 1; }
"#,
        );
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn traps_before_misaligned_volatile_and_atomic_memory_access() {
        let (hir, mir) = compile_source(
            r#"
module alignment;
@export @no_mangle unsafe fn vload(pointer: *const u64) -> u64 { return volatile_load(pointer); }
@export @no_mangle unsafe fn vstore(pointer: *mut u64) { volatile_store(pointer, 1); }
@export @no_mangle unsafe fn aload(pointer: *const u16) -> u16 { return atomic_load(pointer, acquire); }
@export @no_mangle unsafe fn astore(pointer: *mut u16) { atomic_store(pointer, 1, seq_cst); }
@export @no_mangle unsafe fn exchange(pointer: *mut u32) -> u32 { return atomic_exchange(pointer, 1, acq_rel); }
@export @no_mangle unsafe fn add(pointer: *mut u64) -> u64 { return atomic_fetch_add(pointer, 1, relaxed); }
@export @no_mangle unsafe fn cas(pointer: *mut u64) -> u64 { return atomic_compare_exchange(pointer, 1, 2, seq_cst, acquire); }
"#,
        );
        execute_with_c(
            &emit_assembly(&hir, &mir).unwrap(),
            r#"
#include <stdint.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern uint64_t vload(const void *);
extern void vstore(void *);
extern uint16_t aload(const void *);
extern void astore(void *);
extern uint32_t exchange(void *);
extern uint64_t add(void *);
extern uint64_t cas(void *);
int main(void) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core)) return 20;
    for (unsigned test = 0; test < 7; ++test) {
        pid_t child = fork();
        if (child < 0) return 21;
        if (!child) {
            void *pointer = (void *)(uintptr_t)1;
            switch (test) {
                case 0: vload(pointer); break;
                case 1: vstore(pointer); break;
                case 2: aload(pointer); break;
                case 3: astore(pointer); break;
                case 4: exchange(pointer); break;
                case 5: add(pointer); break;
                case 6: cas(pointer); break;
            }
            _exit(100);
        }
        int status;
        if (waitpid(child, &status, 0) != child) return 22;
        if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGILL) return test + 1;
    }
    return 0;
}
"#,
        );
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fn canonicalizes_boolean_casts_memory_assembly_and_foreign_returns() {
        let (hir, mir) = compile_source(
            r#"
module booleans;
extern "C" fn foreign_bool(value: u64) -> bool;
@export @no_mangle fn bool_cast(value: u64) -> u64 { return (value as bool) as u64; }
@export @no_mangle fn bool_not(value: u64) -> u64 { return (!(value as bool)) as u64; }
@export @no_mangle unsafe fn bool_load(pointer: *const bool) -> u64 { return (*pointer) as u64; }
@export @no_mangle unsafe fn bool_asm() -> u64 {
    let mut value: bool = false;
    asm!("mov rax, 256", out("rax") value);
    return value as u64;
}
@export @no_mangle fn bool_direct(value: u64) -> u64 { return foreign_bool(value) as u64; }
@export @no_mangle unsafe fn bool_indirect(callback: extern "C" fn(u64) -> bool, value: u64) -> u64 {
    return callback(value) as u64;
}
"#,
        );
        execute_with_c(
            &emit_assembly(&hir, &mir).unwrap(),
            r#"
#include <stdbool.h>
#include <stdint.h>
__asm__(".text\n.globl foreign_bool\nforeign_bool:\nmovq %rdi, %rax\nret\n");
extern bool foreign_bool(uint64_t);
extern uint64_t bool_cast(uint64_t);
extern uint64_t bool_not(uint64_t);
extern uint64_t bool_load(const void *);
extern uint64_t bool_asm(void);
extern uint64_t bool_direct(uint64_t);
extern uint64_t bool_indirect(bool (*)(uint64_t), uint64_t);
int main(void) {
    const uint64_t values[] = {0,1,2,255,256,257,UINT64_MAX};
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        if (bool_cast(values[i]) != (values[i] != 0)) return 1;
        if (bool_not(values[i]) != (values[i] == 0)) return 2;
    }
    uint8_t memory = 2;
    if (bool_load(&memory) != 1 || bool_asm() != 1) return 3;
    if (bool_direct(256) != 0 || bool_direct(257) != 1) return 4;
    if (bool_indirect(foreign_bool, 256) != 0 || bool_indirect(foreign_bool, 257) != 1) return 5;
    return 0;
}
"#,
        );
    }

    #[test]
    fn emits_freestanding_x86_64_assembly() {
        let ast = parser::parse(
            "test.oc",
            r#"
module codegen;
@export @no_mangle
unsafe fn add_and_out(a: u64, b: u64) -> u64 {
    let value: u64 = a + b;
    unsafe { outb(0x3f8, value as u8); }
    return value;
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = mir::lower(&hir).unwrap();
        let asm = emit_assembly(&hir, &mir).unwrap();
        assert!(asm.contains("add_and_out:"));
        assert!(asm.contains("out dx, al"));
        assert!(asm.contains("ret"));
        let sectioned = emit_assembly_with_function_sections(&hir, &mir, true).unwrap();
        assert!(sectioned.contains(".section .text.ocore_fn.add_and_out"));
    }

    #[test]
    fn emits_struct_copy_and_enum_initialization() {
        let ast = parser::parse(
            "test.oc",
            r#"
module aggregates;
struct Pair { left: u64, right: u64 }
enum Maybe { none, some(u64) }
fn use_aggregates() -> u64 {
    let first: Pair = Pair { left: 10, right: 20 };
    let mut second: Pair = Pair { left: 0, right: 0 };
    second = first;
    let state: Maybe = Maybe::some(7);
    return second.right;
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = mir::lower(&hir).unwrap();
        let text = mir.to_text(&hir);
        assert!(text.contains("copy 16 bytes"));
        let asm = emit_assembly(&hir, &mir).unwrap();
        assert!(asm.contains("rep movsb"));
    }

    #[test]
    fn emits_shifts_with_independent_integer_count_types() {
        let ast = parser::parse(
            "test.oc",
            r#"
module shifts;
fn shift(value: u64, count: usize) -> u64 {
    return value >> count;
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = mir::lower(&hir).unwrap();
        let asm = emit_assembly(&hir, &mir).unwrap();
        assert!(asm.contains("shr rax, cl"));
    }

    #[test]
    fn rejects_float_mir_if_type_checking_is_bypassed() {
        let ast = parser::parse(
            "test.oc",
            r#"
module floats;
fn identity(value: f64) -> f64 { return value; }
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = mir::lower(&hir).unwrap();
        let float_value = 0;
        assert!(hir.types.is_float(mir.functions[0].values[float_value]));

        let mut binary_mir = mir.clone();
        let bool_ty = hir.types.primitive("bool").unwrap();
        let binary_dst = binary_mir.functions[0].values.len();
        binary_mir.functions[0].values.push(bool_ty);
        binary_mir.functions[0].blocks[0]
            .instructions
            .push(Instruction::Binary {
                dst: binary_dst,
                op: BinaryOp::Less,
                lhs: float_value,
                rhs: float_value,
            });
        let binary_error = emit_assembly(&hir, &binary_mir).unwrap_err();
        assert!(binary_error.message.contains("floating-point binary"));

        let mut cast_mir = mir;
        let u64_ty = hir.types.primitive("u64").unwrap();
        let cast_dst = cast_mir.functions[0].values.len();
        cast_mir.functions[0].values.push(u64_ty);
        cast_mir.functions[0].blocks[0]
            .instructions
            .push(Instruction::Cast {
                dst: cast_dst,
                value: float_value,
                from: hir.types.primitive("f64").unwrap(),
                to: u64_ty,
            });
        let cast_error = emit_assembly(&hir, &cast_mir).unwrap_err();
        assert!(cast_error.message.contains("floating-point cast"));
    }

    #[test]
    fn rejects_other_mir_type_contract_violations() {
        let ast = parser::parse(
            "test.oc",
            r#"
module guards;
fn choose(flag: bool, count: u64) -> u64 {
    if flag { return count + 1; }
    return count;
}
"#,
        )
        .unwrap();
        let hir = typeck::check(&[("test.oc".into(), ast)]).unwrap();
        let mir = mir::lower(&hir).unwrap();
        let bool_ty = hir.types.primitive("bool").unwrap();
        let u8_ty = hir.types.primitive("u8").unwrap();
        let u64_ty = hir.types.primitive("u64").unwrap();
        let bool_value = mir.functions[0]
            .values
            .iter()
            .position(|ty| *ty == bool_ty)
            .unwrap();
        let integer_value = mir.functions[0]
            .values
            .iter()
            .position(|ty| *ty == u64_ty)
            .unwrap();

        let mut unary_mir = mir.clone();
        let unary_dst = unary_mir.functions[0].values.len();
        unary_mir.functions[0].values.push(bool_ty);
        unary_mir.functions[0].blocks[0]
            .instructions
            .push(Instruction::Unary {
                dst: unary_dst,
                op: UnaryOp::Neg,
                operand: bool_value,
            });
        let unary_error = emit_assembly(&hir, &unary_mir).unwrap_err();
        assert!(unary_error.message.contains("requires an integer type"));

        let mut branch_mir = mir.clone();
        let branch = branch_mir.functions[0]
            .blocks
            .iter_mut()
            .find_map(|block| match &mut block.terminator {
                Terminator::Branch { condition, .. } => Some(condition),
                _ => None,
            })
            .unwrap();
        *branch = integer_value;
        let branch_error = emit_assembly(&hir, &branch_mir).unwrap_err();
        assert!(branch_error
            .message
            .contains("branch condition type mismatch"));

        let mut atomic_mir = mir;
        let order = atomic_mir.functions[0].values.len();
        atomic_mir.functions[0].values.push(u8_ty);
        let result = atomic_mir.functions[0].values.len();
        atomic_mir.functions[0].values.push(u64_ty);
        atomic_mir.functions[0].blocks[0]
            .instructions
            .push(Instruction::Const {
                dst: order,
                value: MemoryOrder::Relaxed as u64,
            });
        atomic_mir.functions[0].blocks[0]
            .instructions
            .push(Instruction::Intrinsic {
                dst: Some(result),
                intrinsic: Intrinsic::AtomicLoad,
                args: vec![integer_value, order],
            });
        let atomic_error = emit_assembly(&hir, &atomic_mir).unwrap_err();
        assert!(atomic_error.message.contains("requires a pointer"));

        let atomic_ast = parser::parse(
            "atomic.oc",
            r#"
module guards;
unsafe fn load(pointer: *const u64) -> u64 {
    return atomic_load(pointer, relaxed);
}
"#,
        )
        .unwrap();
        let atomic_hir = typeck::check(&[("atomic.oc".into(), atomic_ast)]).unwrap();
        let mut invalid_order_mir = mir::lower(&atomic_hir).unwrap();
        let order = invalid_order_mir.functions[0]
            .blocks
            .iter_mut()
            .flat_map(|block| &mut block.instructions)
            .find_map(|instruction| match instruction {
                Instruction::Const { value, .. } if *value == MemoryOrder::Relaxed as u64 => {
                    Some(value)
                }
                _ => None,
            })
            .unwrap();
        *order = 255;
        let order_error = emit_assembly(&atomic_hir, &invalid_order_mir).unwrap_err();
        assert!(order_error.message.contains("invalid memory ordering"));
    }
}
