//! GNU/AT&T x86-64 syntax -> explicit machine-state primitives.
//!
//! No assembly text, supplied object, host execution, or invented C prototype is
//! an output of this module. This is a bounded semantic subset, not an original
//! GNU-source coverage claim. The caller owns selected source spans, block-label
//! resolution, ABI entry/exit, CFI, relocation binding, and final verification.
//! Requires the v2 Cast and InvalidateRegister primitives; v1 consumers must fail.

use super::native_machine_asm_reader as syntax;
use super::native_machine_ir::{
    Architecture, BinaryKind, ByteOrder, CompareKind, MachineAbi, PhysicalRegister,
    RegisterView, Scalar, WriteMode, X86Gpr,
};
use super::native_machine_lift::{BlockLifter, ExtensionKind, LiftError, LiftFlow};
use syntax::{Address, Condition, ExprAtom, Expression, Operand, X86Opcode};

const CF: u16 = 0;
const PF: u16 = 2;
const AF: u16 = 4;
const ZF: u16 = 6;
const SF: u16 = 7;
const OF: u16 = 11;

#[derive(Clone, Copy)]
enum Place { Register(RegisterView), Memory(Scalar) }

fn mask(bits: u16) -> u128 { (1u128 << bits) - 1 }
fn flag(bit: u16) -> RegisterView {
    RegisterView { register: PhysicalRegister::X86Flags, low_bit: bit, bits: 1 }
}
fn rsp() -> RegisterView {
    RegisterView { register: PhysicalRegister::X86Gpr { name: X86Gpr::Rsp }, low_bit: 0, bits: 64 }
}
fn reject<T>(b: &BlockLifter, why: &str) -> Result<T, LiftError> { Err(b.fail(why)) }

fn gpr(v: RegisterView, b: &BlockLifter) -> Result<(), LiftError> {
    let PhysicalRegister::X86Gpr { name } = v.register else {
        return reject(b, "x86 scalar operand is not a GPR; PC/vector/flag operands require another semantic path");
    };
    if (v.low_bit == 0 && [8, 16, 32, 64].contains(&v.bits))
        || (v.low_bit == 8 && v.bits == 8
            && matches!(name, X86Gpr::Rax | X86Gpr::Rbx | X86Gpr::Rcx | X86Gpr::Rdx)) {
        Ok(())
    } else { reject(b, "illegal x86 GPR view") }
}

fn rex_register(v: RegisterView) -> bool {
    match v.register {
        PhysicalRegister::X86Gpr { name: X86Gpr::R8 | X86Gpr::R9 | X86Gpr::R10 | X86Gpr::R11 | X86Gpr::R12 | X86Gpr::R13 | X86Gpr::R14 | X86Gpr::R15 } => true,
        PhysicalRegister::X86Gpr { name: X86Gpr::Rsp | X86Gpr::Rbp | X86Gpr::Rsi | X86Gpr::Rdi } => v.bits == 8,
        _ => false,
    }
}
fn encoding_registers(o: &Operand) -> (bool, bool) {
    match o {
        Operand::Register(v) => (v.low_bit == 8 && v.bits == 8, rex_register(*v)),
        Operand::Address(Address::X86 { base, index, .. }) => {
            let rex = base.iter().chain(index.iter()).any(|v| rex_register(*v));
            (false, rex)
        }
        Operand::Indirect(inner) => encoding_registers(inner),
        _ => (false, false),
    }
}

fn fold_integer(e: &Expression, b: &BlockLifter) -> Result<i128, LiftError> {
    let ExprAtom::Integer(mut value) = e.first else {
        return reject(b, "symbol/current-location/relocation expression requires an authenticated address binding");
    };
    for (operation, atom) in &e.rest {
        let ExprAtom::Integer(rhs) = atom else {
            return reject(b, "symbolic expression requires an authenticated address binding");
        };
        value = match operation {
            syntax::AddSub::Add => value.checked_add(*rhs),
            syntax::AddSub::Subtract => value.checked_sub(*rhs),
        }.ok_or_else(|| b.fail("integer expression overflow"))?;
    }
    Ok(value)
}

fn constant_operand(e: &Expression, bits: u16, narrow_imm64: bool, b: &mut BlockLifter) -> Result<Scalar, LiftError> {
    let n = fold_integer(e, b)?;
    if narrow_imm64 && bits == 64 && !(i32::MIN as i128..=i32::MAX as i128).contains(&n) {
        return reject(b, "64-bit arithmetic/memory immediate is not an encodable sign-extended imm32");
    }
    if n < -(1i128 << (bits - 1)) || n > mask(bits) as i128 {
        return reject(b, "immediate exceeds selected operand width");
    }
    b.constant(bits, (n as u128) & mask(bits))
}

fn effective_address(o: &Operand, b: &mut BlockLifter) -> Result<Scalar, LiftError> {
    let (displacement, base, index, scale) = match o {
        Operand::Address(Address::X86 { segment: None, displacement, base, index, scale }) => (displacement, *base, *index, *scale),
        Operand::Address(Address::X86 { segment: Some(_), .. }) => return reject(b, "FS/GS address requires selected thread/TLS base semantics"),
        Operand::Expression(displacement) => (displacement, None, None, 1),
        _ => return reject(b, "expected x86 memory address"),
    };
    if ![1, 2, 4, 8].contains(&scale) || (index.is_none() && scale != 1) {
        return reject(b, "invalid x86 address scale");
    }
    let d = fold_integer(displacement, b)?;
    // Deliberately do not guess the encoding-specific moffs/addr32 exceptions.
    if !(i32::MIN as i128..=i32::MAX as i128).contains(&d) {
        return reject(b, "address displacement requires unsupported moffs/addr32 encoding semantics");
    }
    let mut address = b.constant(64, d as u128 & mask(64))?;
    if let Some(v) = base {
        if v.register == PhysicalRegister::X86Pc {
            return reject(b, "RIP-relative address requires selected instruction-location/symbol binding");
        }
        gpr(v, b)?;
        if v.bits != 64 || v.low_bit != 0 { return reject(b, "address base is not a 64-bit GPR"); }
        let x = b.read_register(v)?;
        address = b.binary(BinaryKind::WrappingAdd, address, x)?;
    }
    if let Some(v) = index {
        gpr(v, b)?;
        if v.bits != 64 || v.low_bit != 0 || v.register == rsp().register {
            return reject(b, "address index is not an encodable 64-bit GPR");
        }
        let mut x = b.read_register(v)?;
        for _ in 0..scale.trailing_zeros() { x = b.binary(BinaryKind::WrappingAdd, x, x)?; }
        address = b.binary(BinaryKind::WrappingAdd, address, x)?;
    }
    Ok(address)
}

fn place(o: &Operand, bits: u16, b: &mut BlockLifter) -> Result<Place, LiftError> {
    match o {
        Operand::Register(v) => {
            gpr(*v, b)?;
            if v.bits != bits { return reject(b, "register width differs from opcode width"); }
            Ok(Place::Register(*v))
        }
        Operand::Address(_) | Operand::Expression(_) => Ok(Place::Memory(effective_address(o, b)?)),
        _ => reject(b, "destination is not an encodable register or memory operand"),
    }
}
fn read_place(p: Place, bits: u16, b: &mut BlockLifter) -> Result<Scalar, LiftError> {
    match p { Place::Register(v) => b.read_register(v), Place::Memory(a) => b.load(a, bits, 1) }
}
fn write_place(p: Place, value: Scalar, b: &mut BlockLifter) -> Result<(), LiftError> {
    match p {
        Place::Memory(a) => b.store(a, value, 1),
        Place::Register(v) => {
            let mode = match v.bits { 64 => WriteMode::WholeStorage, 32 => WriteMode::ZeroExtendStorage, _ => WriteMode::PreserveOtherBits };
            b.write_register(v, value, mode)
        }
    }
}
fn source(o: &Operand, bits: u16, imm32: bool, b: &mut BlockLifter) -> Result<Scalar, LiftError> {
    match o {
        Operand::Immediate(e) => constant_operand(e, bits, imm32, b),
        _ => { let p = place(o, bits, b)?; read_place(p, bits, b) }
    }
}
fn memory_operand(o: &Operand) -> bool { matches!(o, Operand::Address(_) | Operand::Expression(_)) }

fn width(selected: Option<u16>, operands: &[Operand], b: &BlockLifter) -> Result<u16, LiftError> {
    let inferred = operands.iter().filter_map(|o| if let Operand::Register(v) = o { Some(v.bits) } else { None }).next();
    let n = selected.or(inferred).ok_or_else(|| b.fail("unsuffixed memory/immediate instruction has no unique operand width"))?;
    if ![8, 16, 32, 64].contains(&n) { return reject(b, "unsupported x86 scalar width"); }
    for o in operands { if let Operand::Register(v) = o { gpr(*v, b)?; if v.bits != n { return reject(b, "mixed register widths"); } } }
    Ok(n)
}

fn bit(value: Scalar, index: u16, b: &mut BlockLifter) -> Result<Scalar, LiftError> {
    let count = b.constant(value.bits, index as u128)?;
    let rotated = b.binary(BinaryKind::RotateRightModuloWidth, value, count)?;
    b.cast(rotated, 1, ExtensionKind::Truncate)
}
fn invert(value: Scalar, b: &mut BlockLifter) -> Result<Scalar, LiftError> {
    let ones = b.constant(value.bits, mask(value.bits))?;
    b.binary(BinaryKind::Xor, value, ones)
}
fn set_flag(position: u16, value: Scalar, b: &mut BlockLifter) -> Result<(), LiftError> {
    b.write_register(flag(position), value, WriteMode::PreserveOtherBits)
}
fn szp(value: Scalar, b: &mut BlockLifter) -> Result<(), LiftError> {
    let sign = bit(value, value.bits - 1, b)?;
    let zero = b.constant(value.bits, 0)?;
    let is_zero = b.compare(CompareKind::Equal, value, zero)?;
    let mut parity = bit(value, 0, b)?;
    for i in 1..8 { let x = bit(value, i, b)?; parity = b.binary(BinaryKind::Xor, parity, x)?; }
    let even = invert(parity, b)?;
    set_flag(SF, sign, b)?; set_flag(ZF, is_zero, b)?; set_flag(PF, even, b)
}
fn arithmetic_flags(lhs: Scalar, rhs: Scalar, result: Scalar, subtract: bool, b: &mut BlockLifter) -> Result<(), LiftError> {
    let carry = if subtract { b.compare(CompareKind::UnsignedLess, lhs, rhs)? } else { b.compare(CompareKind::UnsignedLess, result, lhs)? };
    let lr = b.binary(BinaryKind::Xor, lhs, rhs)?;
    let lo = b.binary(BinaryKind::Xor, lhs, result)?;
    let af_raw = b.binary(BinaryKind::Xor, lr, result)?;
    let auxiliary = bit(af_raw, 4, b)?;
    let signs = if subtract { lr } else { invert(lr, b)? };
    let overflow_raw = b.binary(BinaryKind::And, signs, lo)?;
    let overflow = bit(overflow_raw, lhs.bits - 1, b)?;
    set_flag(CF, carry, b)?; set_flag(AF, auxiliary, b)?; set_flag(OF, overflow, b)?;
    szp(result, b)
}
fn logical_flags(result: Scalar, b: &mut BlockLifter) -> Result<(), LiftError> {
    let zero = b.constant(1, 0)?;
    set_flag(CF, zero, b)?; set_flag(OF, zero, b)?;
    // Intel explicitly leaves AF undefined: it is neither retained nor cleared.
    // The v2 verifier removes these bits from initialized state; a later read
    // cannot acquire a fabricated deterministic AF value.
    b.invalidate_register(flag(AF))?;
    szp(result, b)
}

fn condition(c: Condition, b: &mut BlockLifter) -> Result<Scalar, LiftError> {
    use Condition::*;
    match c {
        Equal => b.read_register(flag(ZF)),
        NotEqual => { let x = b.read_register(flag(ZF))?; invert(x, b) }
        Below => b.read_register(flag(CF)),
        AboveEqual => { let x = b.read_register(flag(CF))?; invert(x, b) }
        BelowEqual | Above => {
            let carry = b.read_register(flag(CF))?; let zero = b.read_register(flag(ZF))?;
            let x = b.binary(BinaryKind::Or, carry, zero)?;
            if c == Above { invert(x, b) } else { Ok(x) }
        }
        Less | GreaterEqual | LessEqual | Greater => {
            let sign = b.read_register(flag(SF))?; let overflow = b.read_register(flag(OF))?;
            let mut x = b.binary(BinaryKind::Xor, sign, overflow)?;
            if matches!(c, LessEqual | Greater) { let zero = b.read_register(flag(ZF))?; x = b.binary(BinaryKind::Or, x, zero)?; }
            if matches!(c, GreaterEqual | Greater) { invert(x, b) } else { Ok(x) }
        }
        Overflow => b.read_register(flag(OF)),
        NoOverflow => { let x = b.read_register(flag(OF))?; invert(x, b) }
        Sign => b.read_register(flag(SF)),
        NoSign => { let x = b.read_register(flag(SF))?; invert(x, b) }
        Parity => b.read_register(flag(PF)),
        NoParity => { let x = b.read_register(flag(PF))?; invert(x, b) }
    }
}

fn direct_target(operands: &[Operand], b: &BlockLifter) -> Result<Expression, LiftError> {
    match operands {
        [Operand::Expression(e)] => Ok(e.clone()),
        _ => reject(b, "indirect branch requires selected target-set/ABI control semantics"),
    }
}

/// Lower ONE already parsed x86 instruction. `spelling` is the original
/// mnemonic (or full line starting with that mnemonic), retained for diagnostics.
/// The surrounding driver must discard the entire failed lift transaction.
pub fn lower_x86(operation: X86Opcode, selected_width: Option<u16>, spelling: &str, operands: &[Operand], b: &mut BlockLifter) -> Result<LiftFlow, LiftError> {
    let profile = b.profile();
    if profile.architecture != Architecture::X86_64 || profile.abi != MachineAbi::SysvAmd64
        || profile.address_bits != 64 || profile.byte_order != ByteOrder::Little {
        return reject(b, "x86-64 lowering requires the selected little-endian SysV AMD64 profile");
    }
    let mnemonic = spelling.split_whitespace().next().unwrap_or("");
    if mnemonic.is_empty() || mnemonic == "lock" || mnemonic.starts_with("rep") {
        return reject(b, "missing mnemonic or unsupported lock/repetition semantics");
    }
    let mut high = false; let mut rex = selected_width == Some(64);
    for o in operands { let (h, r) = encoding_registers(o); high |= h; rex |= r; }
    if high && rex { return reject(b, "AH/BH/CH/DH cannot be encoded with a required REX prefix"); }
    use X86Opcode::*;
    match operation {
        Nop => { if !operands.is_empty() || selected_width.is_some() { return reject(b, "unsupported operand/suffix on NOP"); } }
        Return => {
            if !operands.is_empty() || selected_width.is_some() { return reject(b, "RET immediate/far/width semantics are not admitted"); }
            return reject(b, "x86 RET stack/CET return protocol is not represented");
        }
        Jump => return Ok(LiftFlow::Jump(direct_target(operands, b)?)),
        ConditionalJump(c) => {
            let target = direct_target(operands, b)?;
            return Ok(LiftFlow::Branch { condition: condition(c, b)?, target });
        }
        Call => return reject(b, "CALL requires an authenticated callee ABI/prototype, clobbers, and return binding"),
        RotateLeft | RotateRight | ShiftLeft | ShiftRight | ShiftArithmeticRight => {
            return reject(b, "shift/rotate count and undefined-flag semantics are not implemented in this semantic subset");
        }
        Push => {
            if operands.len() != 1 { return reject(b, "PUSH requires exactly one operand"); }
            let n = selected_width.unwrap_or(64);
            if ![16, 64].contains(&n) { return reject(b, "PUSH only admits 16/64-bit long-mode operands"); }
            let value = source(&operands[0], n, true, b)?;
            let old_sp = b.read_register(rsp())?;
            let count = b.constant(64, (n / 8) as u128)?;
            let new_sp = b.binary(BinaryKind::WrappingSub, old_sp, count)?;
            // PUSH %rsp captures old %rsp; source address uses old %rsp too.
            b.write_register(rsp(), new_sp, WriteMode::WholeStorage)?;
            b.store(new_sp, value, 1)?;
        }
        Pop => {
            if operands.len() != 1 { return reject(b, "POP requires exactly one operand"); }
            let n = selected_width.unwrap_or(64);
            if ![16, 64].contains(&n) { return reject(b, "POP only admits 16/64-bit long-mode operands"); }
            let old_sp = b.read_register(rsp())?;
            let value = b.load(old_sp, n, 1)?;
            let count = b.constant(64, (n / 8) as u128)?;
            let new_sp = b.binary(BinaryKind::WrappingAdd, old_sp, count)?;
            b.write_register(rsp(), new_sp, WriteMode::WholeStorage)?;
            // A memory destination using %rsp is addressed AFTER increment.
            // POP %rsp writes the popped value AFTER that increment.
            let dst = place(&operands[0], n, b)?;
            write_place(dst, value, b)?;
        }
        Lea => {
            if operands.len() != 2 { return reject(b, "LEA requires source address and destination register"); }
            let n = width(selected_width, &operands[1..], b)?;
            if n == 8 || !matches!(operands[1], Operand::Register(_)) { return reject(b, "LEA requires 16/32/64-bit destination GPR"); }
            let address = effective_address(&operands[0], b)?;
            let value = if n == 64 { address } else { b.cast(address, n, ExtensionKind::Truncate)? };
            let dst = place(&operands[1], n, b)?;
            write_place(dst, value, b)?;
        }
        Move | Add | Subtract | Xor | And | Or | Compare | Test => {
            if operands.len() != 2 { return reject(b, "binary x86 instruction requires exactly two operands"); }
            if memory_operand(&operands[0]) && memory_operand(&operands[1]) { return reject(b, "x86 instruction cannot have two memory operands"); }
            let n = width(selected_width, operands, b)?;
            let dst = place(&operands[1], n, b)?;
            let immediate_is_32 = operation != Move || matches!(dst, Place::Memory(_));
            let rhs = source(&operands[0], n, immediate_is_32, b)?;
            if operation == Move { write_place(dst, rhs, b)?; }
            else {
                let lhs = read_place(dst, n, b)?;
                let kind = match operation { Add => BinaryKind::WrappingAdd, Subtract | Compare => BinaryKind::WrappingSub, Xor => BinaryKind::Xor, And | Test => BinaryKind::And, Or => BinaryKind::Or, _ => unreachable!() };
                let result = b.binary(kind, lhs, rhs)?;
                if !matches!(operation, Compare | Test) { write_place(dst, result, b)?; }
                if matches!(operation, Add | Subtract | Compare) { arithmetic_flags(lhs, rhs, result, operation != Add, b)?; }
                else { logical_flags(result, b)?; }
            }
        }
    }
    Ok(LiftFlow::Continue)
}

#[cfg(test)]
#[path = "native_machine_lift_x86_64_tests.rs"]
mod tests;
