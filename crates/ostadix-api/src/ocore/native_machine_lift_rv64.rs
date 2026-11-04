//! RV64 register/bit-vector semantics for the existing GNU-assembly reader.
//!
//! This emits machine IR, not executable assembly or supplied object code.
//! Calls, relocation addresses, platform state and return realization remain
//! separate obligations. An unsupported instruction refuses the whole lift.
use super::native_machine_asm_reader as syntax;
use super::native_machine_ir::{
    Architecture, BinaryKind, CompareKind, MachineAbi, PhysicalRegister,
    RegisterView, ReturnMechanism, Scalar, WriteMode,
};
use super::native_machine_lift::{
    integer_expression, BlockLifter, ExtensionKind, LiftError, LiftFlow,
};
use syntax::{Expression, Operand, RiscvOpcode};

type Result<T> = std::result::Result<T, LiftError>;

fn arity(operands: &[Operand], n: usize, b: &BlockLifter<'_>) -> Result<()> {
    if operands.len() != n { return Err(b.fail(format!("RV64 instruction requires {n} operands"))); }
    Ok(())
}
fn gpr(operand: &Operand, b: &BlockLifter<'_>) -> Result<RegisterView> {
    let view = match operand {
        Operand::ZeroRegister { bits: 64 } => RegisterView {
            register: PhysicalRegister::RiscvGpr { index: 0 }, low_bit: 0, bits: 64,
        },
        Operand::Register(view) => *view,
        _ => return Err(b.fail("RV64 operand requires a canonical 64-bit integer register")),
    };
    if !matches!(view.register, PhysicalRegister::RiscvGpr { index } if index < 32)
        || view.low_bit != 0 || view.bits != 64 {
        return Err(b.fail("RV64 operand requires a canonical 64-bit integer register"));
    }
    Ok(view)
}
fn fpr(operand: &Operand, b: &BlockLifter<'_>) -> Result<RegisterView> {
    let Operand::Register(view) = operand else {
        return Err(b.fail("RV64 operand requires a canonical 64-bit floating register"));
    };
    if !matches!(view.register, PhysicalRegister::RiscvFpr { index } if index < 32)
        || view.low_bit != 0 || view.bits != 64 {
        return Err(b.fail("RV64 operand requires a canonical 64-bit floating register"));
    }
    Ok(*view)
}
fn is_zero(view: RegisterView) -> bool {
    matches!(view.register, PhysicalRegister::RiscvGpr { index: 0 })
}
fn read(view: RegisterView, b: &mut BlockLifter<'_>) -> Result<Scalar> {
    if is_zero(view) { b.constant(64, 0) } else { b.read_register(view) }
}
fn write(view: RegisterView, value: Scalar, b: &mut BlockLifter<'_>) -> Result<()> {
    if is_zero(view) { return Ok(()); }
    b.write_register(view, value, WriteMode::WholeStorage)
}
fn integer(expression: &Expression, b: &BlockLifter<'_>) -> Result<i128> {
    integer_expression(expression).map_err(|e| b.fail(e.reason))
}
fn immediate(operand: &Operand, b: &BlockLifter<'_>) -> Result<i128> {
    match operand {
        Operand::Immediate(x) | Operand::Expression(x) => integer(x, b),
        _ => Err(b.fail("RV64 operand requires an integer immediate")),
    }
}
fn signed12(value: i128, b: &BlockLifter<'_>) -> Result<i128> {
    if !(-2048..=2047).contains(&value) {
        return Err(b.fail("RV64 immediate is outside the signed 12-bit encoding"));
    }
    Ok(value)
}
fn target(operand: &Operand, b: &BlockLifter<'_>) -> Result<Expression> {
    match operand {
        Operand::Immediate(x) | Operand::Expression(x) => Ok(x.clone()),
        _ => Err(b.fail("RV64 branch requires an original target expression")),
    }
}
fn address(operand: &Operand, b: &mut BlockLifter<'_>) -> Result<Scalar> {
    let Operand::Address(syntax::Address::Riscv { base, displacement }) = operand else {
        return Err(b.fail("RV64 memory operand requires base plus signed displacement"));
    };
    let base = gpr(&Operand::Register(*base), b)?;
    let offset = signed12(integer(displacement, b)?, b)?;
    let base = read(base, b)?;
    let offset = b.constant(64, offset as u128)?;
    b.binary(BinaryKind::WrappingAdd, base, offset)
}
fn narrow(value: Scalar, bits: u16, b: &mut BlockLifter<'_>) -> Result<Scalar> {
    if value.bits == bits { Ok(value) } else { b.cast(value, bits, ExtensionKind::Truncate) }
}
fn word_result(value: Scalar, b: &mut BlockLifter<'_>) -> Result<Scalar> {
    b.cast(value, 64, ExtensionKind::SignExtend)
}
fn logical_right(value: Scalar, amount: u16, b: &mut BlockLifter<'_>) -> Result<Scalar> {
    if amount == 0 { return Ok(value); }
    let shift = b.constant(value.bits, u128::from(amount))?;
    let rotated = b.binary(BinaryKind::RotateRightModuloWidth, value, shift)?;
    let mask = b.constant(value.bits, (1u128 << (value.bits - amount)) - 1)?;
    b.binary(BinaryKind::And, rotated, mask)
}
fn shift(value: Scalar, amount: u16, spelling: &str, b: &mut BlockLifter<'_>) -> Result<Scalar> {
    if amount == 0 { return Ok(value); }
    if spelling.starts_with("sll") {
        let mut result = value;
        for _ in 0..amount { result = b.binary(BinaryKind::WrappingAdd, result, result)?; }
        return Ok(result);
    }
    let logical = logical_right(value, amount, b)?;
    if spelling.starts_with("srl") { return Ok(logical); }
    let sign_mask = b.constant(value.bits, 1u128 << (value.bits - 1))?;
    let sign = b.binary(BinaryKind::And, value, sign_mask)?;
    let zero = b.constant(value.bits, 0)?;
    let nonnegative = b.compare(CompareKind::Equal, sign, zero)?;
    let one = b.constant(1, 1)?;
    let negative = b.binary(BinaryKind::Xor, nonnegative, one)?;
    let negative = b.cast(negative, value.bits, ExtensionKind::ZeroExtend)?;
    let fill = b.binary(BinaryKind::WrappingSub, zero, negative)?;
    let all = if value.bits == 128 { u128::MAX } else { (1u128 << value.bits) - 1 };
    let high_mask = all ^ ((1u128 << (value.bits - amount)) - 1);
    let high_mask = b.constant(value.bits, high_mask)?;
    let fill = b.binary(BinaryKind::And, fill, high_mask)?;
    b.binary(BinaryKind::Or, logical, fill)
}

/// Lift one already parsed original instruction. The owning frontend resolves
/// labels and verifies the complete source/instruction inventory separately.
fn rv_return(ra: RegisterView, b: &mut BlockLifter<'_>) -> Result<LiftFlow> {
    let base = read(ra, b)?;
    let offset = b.constant(64, 0)?;
    let sum = b.binary(BinaryKind::WrappingAdd, base, offset)?;
    let clear_low_bit = b.constant(64, u128::from(u64::MAX - 1))?;
    let target = b.binary(BinaryKind::And, sum, clear_low_bit)?;
    Ok(LiftFlow::ReturnTo { target, mechanism: ReturnMechanism::Rv64Jalr })
}

pub fn lower_rv64(operation: RiscvOpcode, spelling: &str, operands: &[Operand],
    b: &mut BlockLifter<'_>) -> Result<LiftFlow> {
    if b.profile().architecture != Architecture::Rv64
        || !matches!(b.profile().abi, MachineAbi::RiscvLp64 | MachineAbi::RiscvLp64d)
        || b.profile().address_bits != 64 {
        return Err(b.fail("RV64 lifter requires an actual RV64 LP64/LP64D profile"));
    }
    use RiscvOpcode::*;
    match operation {
        Move | LoadImmediate => {
            arity(operands, 2, b)?;
            let dst = gpr(&operands[0], b)?;
            let value = if operation == Move {
                if spelling != "mv" { return Err(b.fail("unsupported RV64 move spelling")); }
                let src = gpr(&operands[1], b)?; read(src, b)?
            } else {
                if spelling != "li" { return Err(b.fail("unsupported RV64 immediate spelling")); }
                let n = immediate(&operands[1], b)?;
                if n < i128::from(i64::MIN) || n > i128::from(u64::MAX) {
                    return Err(b.fail("RV64 li value does not fit one XLEN bit pattern"));
                }
                b.constant(64, n as u128)?
            };
            write(dst, value, b)?;
        }
        AddImmediate | Add | Subtract | And | Or | Xor => {
            arity(operands, 3, b)?;
            let (kind, word, immediate_rhs) = match (operation, spelling) {
                (AddImmediate, "addi") => (BinaryKind::WrappingAdd, false, true),
                (AddImmediate, "addiw") => (BinaryKind::WrappingAdd, true, true),
                (Add, "add") => (BinaryKind::WrappingAdd, false, false),
                (Add, "addw") => (BinaryKind::WrappingAdd, true, false),
                (Subtract, "sub") => (BinaryKind::WrappingSub, false, false),
                (Subtract, "subw") => (BinaryKind::WrappingSub, true, false),
                (And, "and") => (BinaryKind::And, false, false),
                (And, "andi") => (BinaryKind::And, false, true),
                (Or, "or") => (BinaryKind::Or, false, false),
                (Or, "ori") => (BinaryKind::Or, false, true),
                (Xor, "xor") => (BinaryKind::Xor, false, false),
                (Xor, "xori") => (BinaryKind::Xor, false, true),
                _ => return Err(b.fail("unsupported RV64 integer operation spelling")),
            };
            let dst = gpr(&operands[0], b)?;
            let lhs = gpr(&operands[1], b)?;
            let immediate = if immediate_rhs { Some(signed12(immediate(&operands[2], b)?, b)?) } else { None };
            let rhs = if immediate_rhs { None } else { Some(gpr(&operands[2], b)?) };
            let width = if word { 32 } else { 64 };
            let lhs = read(lhs, b)?; let lhs = narrow(lhs, width, b)?;
            let rhs = if let Some(n) = immediate { b.constant(width, n as u128)? }
                else { let value = read(rhs.unwrap(), b)?; narrow(value, width, b)? };
            let value = b.binary(kind, lhs, rhs)?;
            let value = if word { word_result(value, b)? } else { value };
            write(dst, value, b)?;
        }
        ShiftLeftImmediate | ShiftRightImmediate => {
            arity(operands, 3, b)?;
            let word = match (operation, spelling) {
                (ShiftLeftImmediate, "slli") | (ShiftRightImmediate, "srli" | "srai") => false,
                (ShiftLeftImmediate, "slliw") | (ShiftRightImmediate, "srliw" | "sraiw") => true,
                _ => return Err(b.fail("unsupported RV64 immediate shift spelling")),
            };
            let dst = gpr(&operands[0], b)?; let src = gpr(&operands[1], b)?;
            let amount = immediate(&operands[2], b)?;
            let width = if word { 32 } else { 64 };
            if amount < 0 || amount >= i128::from(width) {
                return Err(b.fail("RV64 shift immediate is outside the encoded operand width"));
            }
            let value = read(src, b)?; let value = narrow(value, width, b)?;
            let value = shift(value, amount as u16, spelling, b)?;
            let value = if word { word_result(value, b)? } else { value };
            write(dst, value, b)?;
        }
        LoadDouble | LoadWord | StoreDouble | StoreWord | LoadByteSigned | LoadByteUnsigned | LoadHalfSigned | LoadHalfUnsigned | StoreByte | StoreHalf | LoadFloatDouble | StoreFloatDouble => {
            arity(operands, 2, b)?;
            let (load, bits, floating, signed) = match (operation, spelling) {
                (LoadByteSigned, "lb") => (true, 8, false, true),
                (LoadByteUnsigned, "lbu") => (true, 8, false, false),
                (LoadHalfSigned, "lh") => (true, 16, false, true),
                (LoadHalfUnsigned, "lhu") => (true, 16, false, false),
                (StoreByte, "sb") => (false, 8, false, false),
                (StoreHalf, "sh") => (false, 16, false, false),
                (LoadDouble, "ld") => (true, 64, false, false),
                (LoadWord, "lw") => (true, 32, false, true),
                (LoadWord, "lwu") => (true, 32, false, false),
                (StoreDouble, "sd") => (false, 64, false, false),
                (StoreWord, "sw") => (false, 32, false, false),
                (LoadFloatDouble, "fld") => (true, 64, true, false),
                (StoreFloatDouble, "fsd") => (false, 64, true, false),
                _ => return Err(b.fail("unsupported RV64 memory operation spelling")),
            };
            if floating && b.profile().abi != MachineAbi::RiscvLp64d {
                return Err(b.fail("RV64 floating register memory transfer requires LP64D"));
            }
            let reg = if floating { fpr(&operands[0], b)? } else { gpr(&operands[0], b)? };
            let address = address(&operands[1], b)?;
            if load {
                let mut value = b.load(address, bits, 1)?;
                if bits < 64 { value = b.cast(value, 64, if signed { ExtensionKind::SignExtend } else { ExtensionKind::ZeroExtend })?; }
                if floating { b.write_register(reg, value, WriteMode::WholeStorage)?; }
                else { write(reg, value, b)?; }
            } else {
                let value = if floating { b.read_register(reg)? } else { read(reg, b)? };
                let value = narrow(value, bits, b)?;
                b.store(address, value, 1)?;
            }
        }
        BranchEqual | BranchNotEqual | BranchZero | BranchNonzero => {
            let zero = matches!(operation, BranchZero | BranchNonzero);
            arity(operands, if zero { 2 } else { 3 }, b)?;
            let lhs = gpr(&operands[0], b)?;
            let rhs = if zero { None } else { Some(gpr(&operands[1], b)?) };
            let destination = target(&operands[if zero { 1 } else { 2 }], b)?;
            let expected = match operation { BranchEqual => "beq", BranchNotEqual => "bne", BranchZero => "beqz", _ => "bnez" };
            if spelling != expected { return Err(b.fail("unsupported RV64 branch spelling")); }
            let lhs = read(lhs, b)?;
            let rhs = if let Some(v) = rhs { read(v, b)? } else { b.constant(64, 0)? };
            let mut condition = b.compare(CompareKind::Equal, lhs, rhs)?;
            if matches!(operation, BranchNotEqual | BranchNonzero) {
                let one = b.constant(1, 1)?; condition = b.binary(BinaryKind::Xor, condition, one)?;
            }
            return Ok(LiftFlow::Branch { condition, target: destination });
        }
        Jump => {
            arity(operands, 1, b)?;
            if spelling != "j" { return Err(b.fail("unsupported RV64 direct jump spelling")); }
            return Ok(LiftFlow::Jump(target(&operands[0], b)?));
        }
        JumpAndLink => {
            arity(operands, 2, b)?;
            let dst = gpr(&operands[0], b)?;
            if spelling != "jal" || !is_zero(dst) {
                return Err(b.fail("RV64 linked call requires an explicit call/PC/ABI realization"));
            }
            return Ok(LiftFlow::Jump(target(&operands[1], b)?));
        }
        JumpRegister => {
            let ra = if spelling == "jr" {
                arity(operands, 1, b)?; gpr(&operands[0], b)?
            } else if spelling == "jalr" {
                arity(operands, 3, b)?;
                let dst = gpr(&operands[0], b)?; let src = gpr(&operands[1], b)?;
                if !is_zero(dst) || immediate(&operands[2], b)? != 0 {
                    return Err(b.fail("RV64 indirect jump requires an explicit PC/ABI realization"));
                }
                src
            } else { return Err(b.fail("unsupported RV64 indirect jump spelling")); };
            if !matches!(ra.register, PhysicalRegister::RiscvGpr { index: 1 }) {
                return Err(b.fail("RV64 indirect jump requires an explicit PC/ABI realization"));
            }
            return rv_return(ra, b);
        }
        Return => {
            arity(operands, 0, b)?;
            if spelling != "ret" { return Err(b.fail("unsupported RV64 return spelling")); }
            return rv_return(RegisterView { register: PhysicalRegister::RiscvGpr { index: 1 }, low_bit: 0, bits: 64 }, b);
        }
        Nop => {
            arity(operands, 0, b)?;
            if spelling != "nop" { return Err(b.fail("unsupported RV64 nop spelling")); }
            b.constant(64, 0)?;
        }
    }
    Ok(LiftFlow::Continue)
}

#[cfg(test)]
#[path = "native_machine_lift_rv64_controls.rs"]
mod tests;
