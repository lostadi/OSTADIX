//! GNU AArch64 syntax to shared state-threaded machine primitives.
//! Entry initialization, whole-body rollback, ABI/LR continuation, CFI, symbolic
//! realization and native emission remain shared obligations; no C signature
//! is inferred. Authored source only, not original GNU/runtime qualification.
use super::native_machine_asm_reader as syntax;
use super::native_machine_ir::{
    BinaryKind, CompareKind, PhysicalRegister, RegisterView, ReturnMechanism, Scalar, WriteMode,
};
use super::native_machine_lift::{
    integer_expression, BlockLifter, ExtensionKind, LiftError, LiftFlow,
};
type R<T> = Result<T, LiftError>;
fn mask(bits: u16) -> u128 {
    (1u128 << bits) - 1
}
fn integer(b: &mut BlockLifter, bits: u16, n: i128) -> R<Scalar> {
    b.constant(bits, (n as u128) & mask(bits))
}
fn zero(b: &mut BlockLifter, bits: u16) -> R<Scalar> {
    b.constant(bits, 0)
}
fn expression_integer(b: &BlockLifter, e: &syntax::Expression) -> R<i128> {
    integer_expression(e).map_err(|e| b.fail(e.reason))
}
fn immediate(o: &syntax::Operand) -> bool {
    matches!(
        o,
        syntax::Operand::Immediate(_) | syntax::Operand::Expression(_)
    )
}
fn immediate_value(b: &BlockLifter, o: &syntax::Operand) -> R<i128> {
    match o {
        syntax::Operand::Immediate(e) | syntax::Operand::Expression(e) => expression_integer(b, e),
        _ => Err(b.fail("A64 immediate requires an integer expression")),
    }
}
fn zr(o: &syntax::Operand) -> bool {
    matches!(o, syntax::Operand::ZeroRegister { .. })
}
fn gpr_view(b: &BlockLifter, v: &RegisterView, allow_sp: bool) -> R<()> {
    let ok = match &v.register {
        PhysicalRegister::Aarch64Gpr { index } => *index < 31,
        PhysicalRegister::Aarch64Sp => allow_sp,
        _ => false,
    };
    if ok && v.low_bit == 0 && matches!(v.bits, 32 | 64) {
        Ok(())
    } else {
        Err(b.fail("A64 requires canonical W/X register; SP only in permitted roles"))
    }
}
fn width(b: &BlockLifter, o: &syntax::Operand, allow_sp: bool) -> R<u16> {
    match o {
        syntax::Operand::Register(v) => {
            gpr_view(b, v, allow_sp)?;
            Ok(v.bits)
        }
        syntax::Operand::ZeroRegister { bits } if matches!(*bits, 32 | 64) => Ok(*bits),
        _ => Err(b.fail("A64 operand has no independently declared W/X width")),
    }
}
fn register_input(b: &BlockLifter, o: &syntax::Operand, allow_sp: bool) -> R<()> {
    width(b, o, allow_sp).map(|_| ())
}
fn value(b: &mut BlockLifter, o: &syntax::Operand, bits: u16, allow_sp: bool) -> R<Scalar> {
    match o {
        syntax::Operand::Register(v) => {
            gpr_view(b, v, allow_sp)?;
            if v.bits != bits {
                return Err(b.fail("A64 register width mismatch"));
            }
            b.read_register(*v)
        }
        syntax::Operand::ZeroRegister { bits: n } if *n == bits => zero(b, bits),
        syntax::Operand::Immediate(e) | syntax::Operand::Expression(e) => {
            let n = expression_integer(b, e)?;
            integer(b, bits, n)
        }
        _ => Err(b.fail("A64 operand/shift/extension has no selected semantic lowering")),
    }
}
fn write(b: &mut BlockLifter, o: &syntax::Operand, x: Scalar, allow_sp: bool) -> R<()> {
    match o {
        syntax::Operand::ZeroRegister { bits } if *bits == x.bits => Ok(()),
        syntax::Operand::Register(v) => {
            gpr_view(b, v, allow_sp)?;
            if v.bits != x.bits {
                return Err(b.fail("A64 result width mismatch"));
            }
            if matches!(&v.register, PhysicalRegister::Aarch64Sp) && v.bits == 32 {
                let x = b.cast(x, 64, ExtensionKind::ZeroExtend)?;
                b.write_register(
                    RegisterView {
                        register: PhysicalRegister::Aarch64Sp,
                        low_bit: 0,
                        bits: 64,
                    },
                    x,
                    WriteMode::WholeStorage,
                )
            } else {
                b.write_register(
                    *v,
                    x,
                    if v.bits == 32 {
                        WriteMode::ZeroExtendStorage
                    } else {
                        WriteMode::WholeStorage
                    },
                )
            }
        }
        _ => Err(b.fail("A64 destination is not a selected register")),
    }
}
fn immediate_pattern(b: &BlockLifter, o: &syntax::Operand, bits: u16) -> R<u128> {
    let n = immediate_value(b, o)?;
    if n < -(1i128 << (bits - 1)) || n > mask(bits) as i128 {
        return Err(b.fail("A64 immediate does not fit selected width"));
    }
    Ok((n as u128) & mask(bits))
}
fn logical_immediate(n: u128, bits: u16) -> bool {
    for e in [2u16, 4, 8, 16, 32, 64] {
        if e > bits {
            continue;
        }
        for ones in 1..e {
            let run = (1u128 << ones) - 1;
            for r in 0..e {
                let element = if r == 0 {
                    run
                } else {
                    ((run >> r) | (run << (e - r))) & mask(e)
                };
                let mut repeated = 0;
                for p in (0..bits).step_by(e as usize) {
                    repeated |= element << p;
                }
                if repeated == n {
                    return true;
                }
            }
        }
    }
    false
}
fn move_wide_immediate(n: u128, bits: u16) -> bool {
    (0..bits).step_by(16).any(|shift| {
        let field = (0xffffu128 << shift) & mask(bits);
        n & !field == 0 || ((!n) & mask(bits)) & !field == 0
    })
}
fn add_immediate(b: &BlockLifter, o: &syntax::Operand) -> R<()> {
    let n = immediate_value(b, o)?;
    let failure = || b.fail("A64 ADD/SUB immediate needs more than one selected instruction");
    let magnitude = match n.checked_abs() {
        Some(x) => x,
        None => return Err(failure()),
    };
    if magnitude <= 4095 || (magnitude % 4096 == 0 && magnitude / 4096 <= 4095) {
        Ok(())
    } else {
        Err(failure())
    }
}
fn not_bool(b: &mut BlockLifter, x: Scalar) -> R<Scalar> {
    let one = b.constant(1, 1)?;
    b.binary(BinaryKind::Xor, x, one)
}
fn nonzero(b: &mut BlockLifter, x: Scalar) -> R<Scalar> {
    let z = zero(b, x.bits)?;
    let eq = b.compare(CompareKind::Equal, x, z)?;
    not_bool(b, eq)
}
fn sign(b: &mut BlockLifter, x: Scalar) -> R<Scalar> {
    let m = b.constant(x.bits, 1u128 << (x.bits - 1))?;
    let high = b.binary(BinaryKind::And, x, m)?;
    nonzero(b, high)
}
struct Flags {
    n: Scalar,
    z: Scalar,
    c: Scalar,
    v: Scalar,
}
fn nz(b: &mut BlockLifter, x: Scalar, c: Scalar, v: Scalar) -> R<Flags> {
    let n = sign(b, x)?;
    let z0 = zero(b, x.bits)?;
    let z = b.compare(CompareKind::Equal, x, z0)?;
    Ok(Flags { n, z, c, v })
}
fn read_flags(b: &mut BlockLifter) -> R<Flags> {
    let packed = b.read_register(RegisterView {
        register: PhysicalRegister::Aarch64Nzcv,
        low_bit: 0,
        bits: 4,
    })?;
    let mut bit = |n: u16| -> R<Scalar> {
        let m = b.constant(4, 1u128 << n)?;
        let x = b.binary(BinaryKind::And, packed, m)?;
        nonzero(b, x)
    };
    Ok(Flags {
        n: bit(3)?,
        z: bit(2)?,
        c: bit(1)?,
        v: bit(0)?,
    })
}
fn write_flags(b: &mut BlockLifter, flags: Flags) -> R<()> {
    let mut packed = b.constant(4, 0)?;
    for (x, shift) in [(flags.n, 3u16), (flags.z, 2), (flags.c, 1), (flags.v, 0)] {
        let mut part = b.cast(x, 4, ExtensionKind::ZeroExtend)?;
        if shift != 0 {
            let n = b.constant(4, (4 - shift) as u128)?;
            part = b.binary(BinaryKind::RotateRightModuloWidth, part, n)?;
        }
        packed = b.binary(BinaryKind::Or, packed, part)?;
    }
    // Shared v2 dispatches canonical flags to WriteFlags, not legacy WriteRegister.
    b.write_register(
        RegisterView {
            register: PhysicalRegister::Aarch64Nzcv,
            low_bit: 0,
            bits: 4,
        },
        packed,
        WriteMode::WholeStorage,
    )
}
fn arithmetic(
    b: &mut BlockLifter,
    x: Scalar,
    y: Scalar,
    subtract: bool,
    carry: Option<Scalar>,
) -> R<(Scalar, Flags)> {
    if x.bits != y.bits || !matches!(x.bits, 32 | 64) {
        return Err(b.fail("A64 arithmetic requires equal32/64-bit operands"));
    }
    let op = if subtract {
        BinaryKind::WrappingSub
    } else {
        BinaryKind::WrappingAdd
    };
    let first = b.binary(op, x, y)?;
    let first_carry = b.compare(
        CompareKind::UnsignedLess,
        if subtract { x } else { first },
        if subtract { y } else { x },
    )?;
    let (result, overflow_bit) = if let Some(cin) = carry {
        if cin.bits != 1 {
            return Err(b.fail("A64 carry input must be one bit"));
        }
        let adjust = if subtract { not_bool(b, cin)? } else { cin };
        let adjust = b.cast(adjust, x.bits, ExtensionKind::ZeroExtend)?;
        let op = if subtract {
            BinaryKind::WrappingSub
        } else {
            BinaryKind::WrappingAdd
        };
        let r = b.binary(op, first, adjust)?;
        let second = b.compare(
            CompareKind::UnsignedLess,
            if subtract { first } else { r },
            if subtract { adjust } else { first },
        )?;
        (r, b.binary(BinaryKind::Or, first_carry, second)?)
    } else {
        (first, first_carry)
    };
    let c = if subtract {
        not_bool(b, overflow_bit)?
    } else {
        overflow_bit
    };
    let sx = sign(b, x)?;
    let sy = sign(b, y)?;
    let sr = sign(b, result)?;
    let relation = b.binary(BinaryKind::Xor, sx, sy)?;
    let relation = if subtract {
        relation
    } else {
        not_bool(b, relation)?
    };
    let changed = b.binary(BinaryKind::Xor, sx, sr)?;
    let v = b.binary(BinaryKind::And, relation, changed)?;
    Ok((result, nz(b, result, c, v)?))
}
fn condition(b: &mut BlockLifter, c: &syntax::Condition) -> R<Scalar> {
    use syntax::Condition::*;
    if matches!(c, Parity | NoParity) {
        return Err(b.fail("A64 has no parity condition"));
    }
    let f = read_flags(b)?;
    match c {
        Equal => Ok(f.z),
        NotEqual => not_bool(b, f.z),
        Above => {
            let nz = not_bool(b, f.z)?;
            b.binary(BinaryKind::And, f.c, nz)
        }
        AboveEqual => Ok(f.c),
        Below => not_bool(b, f.c),
        BelowEqual => {
            let nc = not_bool(b, f.c)?;
            b.binary(BinaryKind::Or, nc, f.z)
        }
        Greater | GreaterEqual | Less | LessEqual => {
            let nv = b.binary(BinaryKind::Xor, f.n, f.v)?;
            match c {
                Less => Ok(nv),
                LessEqual => b.binary(BinaryKind::Or, nv, f.z),
                GreaterEqual => not_bool(b, nv),
                _ => {
                    let ge = not_bool(b, nv)?;
                    let nz = not_bool(b, f.z)?;
                    b.binary(BinaryKind::And, ge, nz)
                }
            }
        }
        Overflow => Ok(f.v),
        NoOverflow => not_bool(b, f.v),
        Sign => Ok(f.n),
        NoSign => not_bool(b, f.n),
        Parity | NoParity => unreachable!(),
    }
}
fn condition_spelling(c: &syntax::Condition, m: &str) -> bool {
    use syntax::Condition::*;
    match c {
        Equal => m == "b.eq",
        NotEqual => m == "b.ne",
        Above => m == "b.hi",
        AboveEqual => matches!(m, "b.hs" | "b.cs"),
        Below => matches!(m, "b.lo" | "b.cc"),
        BelowEqual => m == "b.ls",
        Greater => m == "b.gt",
        GreaterEqual => m == "b.ge",
        Less => m == "b.lt",
        LessEqual => m == "b.le",
        Overflow => m == "b.vs",
        NoOverflow => m == "b.vc",
        Sign => m == "b.mi",
        NoSign => m == "b.pl",
        Parity | NoParity => false,
    }
}
fn target(b: &BlockLifter, o: &syntax::Operand) -> R<syntax::Expression> {
    match o {
        syntax::Operand::Expression(e) | syntax::Operand::Immediate(e) => Ok(e.clone()),
        _ => Err(b.fail("A64 branch target is not a preserved expression")),
    }
}
fn alias(o: &syntax::Operand, base: &RegisterView) -> bool {
    matches!(o, syntax::Operand::Register(v) if v.register == base.register)
}
fn memory(
    b: &mut BlockLifter,
    operands: &[syntax::Operand],
    load: bool,
    pair: bool,
    m: &str,
) -> R<LiftFlow> {
    let count = if pair { 2 } else { 1 };
    if operands.len() != count + 1 && operands.len() != count + 2 {
        return Err(b.fail("A64 memory operand count differs"));
    }
    let bits = width(b, &operands[0], false)?;
    if pair && width(b, &operands[1], false)? != bits {
        return Err(b.fail("A64 pair register widths differ"));
    }
    let (base, offset, pre) = match &operands[count] {
        syntax::Operand::Address(syntax::Address::Aarch64 {
            base,
            offset,
            writeback,
        }) => (*base, offset.as_ref(), *writeback),
        _ => return Err(b.fail("A64 memory requires Aarch64 address")),
    };
    gpr_view(b, &base, true)?;
    if base.bits != 64 {
        return Err(b.fail("A64 memory base must be64 bits"));
    }
    let post = if operands.len() == count + 2 {
        if pre || offset.is_some() {
            return Err(b.fail("A64 conflicting pre/post-index form"));
        }
        Some(immediate_value(b, &operands[count + 1])?)
    } else {
        None
    };
    let wb = pre || post.is_some();
    if wb && operands[..count].iter().any(|r| alias(r, &base)) {
        return Err(b.fail("A64 writeback/data register overlap is constrained-unpredictable"));
    }
    if load && pair {
        let same = match (&operands[0], &operands[1]) {
            (syntax::Operand::Register(a), syntax::Operand::Register(c)) => {
                a.register == c.register
            }
            (syntax::Operand::ZeroRegister { .. }, syntax::Operand::ZeroRegister { .. }) => true,
            _ => false,
        };
        if same {
            return Err(b.fail("A64 load-pair destinations overlap"));
        }
    }
    let (access, signed) = match (load, pair, m) {
        (true, false, "ldr" | "ldur")
        | (false, false, "str" | "stur")
        | (true, true, "ldp")
        | (false, true, "stp") => (bits, false),
        (true, false, "ldrb" | "ldurb") | (false, false, "strb" | "sturb") => (8, false),
        (true, false, "ldrh" | "ldurh") | (false, false, "strh" | "sturh") => (16, false),
        (true, false, "ldrsb" | "ldursb") => (8, true),
        (true, false, "ldrsh" | "ldursh") => (16, true),
        (true, false, "ldrsw" | "ldursw") | (true, true, "ldpsw") if bits == 64 => (32, true),
        _ => return Err(b.fail("A64 acquire/release/non-temporal/vector memory is not realized")),
    };
    if access < 32 && !signed && bits != 32 {
        return Err(b.fail("A64 byte/halfword zero extension requires W register"));
    }
    let off = if let Some(e) = offset {
        expression_integer(b, e)?
    } else {
        0
    };
    let selected = post.unwrap_or(off);
    let stride = (access / 8) as i128;
    let unscaled = matches!(
        m,
        "ldur" | "stur" | "ldurb" | "sturb" | "ldurh" | "sturh" | "ldursb" | "ldursh" | "ldursw"
    );
    let signed9 = (-256..=255).contains(&selected);
    let encodable = if pair {
        selected % stride == 0 && (-64..=63).contains(&(selected / stride))
    } else if unscaled {
        !wb && signed9
    } else if wb {
        signed9
    } else {
        signed9 || (selected % stride == 0 && (0..=4095).contains(&(selected / stride)))
    };
    // GNU ldr/str may select an unscaled encoding: #1 and #-8 are valid
    // X-register offsets. They must not be used as unsupported mutants.
    if !encodable {
        return Err(b.fail("A64 memory offset has no selected instruction encoding"));
    }
    let initial = b.read_register(base)?;
    let delta = integer(b, 64, off)?;
    let address = b.binary(BinaryKind::WrappingAdd, initial, delta)?;
    let mut loaded = vec![];
    for (index, operand) in operands[..count].iter().enumerate() {
        let addr = if index == 0 {
            address
        } else {
            let n = b.constant(64, (access / 8) as u128)?;
            b.binary(BinaryKind::WrappingAdd, address, n)?
        };
        if load {
            let mut x = b.load(addr, access, 1)?;
            if access != bits {
                x = b.cast(
                    x,
                    bits,
                    if signed {
                        ExtensionKind::SignExtend
                    } else {
                        ExtensionKind::ZeroExtend
                    },
                )?;
            }
            loaded.push(x);
        } else {
            let mut x = value(b, operand, bits, false)?;
            if x.bits != access {
                x = b.cast(x, access, ExtensionKind::Truncate)?;
            }
            b.store(addr, x, 1)?;
        }
    }
    for (o, x) in operands[..count].iter().zip(loaded) {
        write(b, o, x, false)?;
    }
    if wb {
        let updated = if let Some(off) = post {
            let n = integer(b, 64, off)?;
            b.binary(BinaryKind::WrappingAdd, initial, n)?
        } else {
            address
        };
        b.write_register(base, updated, WriteMode::WholeStorage)?;
    }
    Ok(LiftFlow::Continue)
}
pub(super) fn lower_aarch64(
    operation: syntax::Aarch64Opcode,
    spelling: &str,
    operands: &[syntax::Operand],
    b: &mut BlockLifter,
) -> R<LiftFlow> {
    use syntax::Aarch64Opcode::*;
    let m = spelling.trim().to_ascii_lowercase();
    match operation {
        Nop if m == "nop" && operands.is_empty() => {
            b.constant(1, 0)?;
            Ok(LiftFlow::Continue)
        }
        Move if m == "mov" && operands.len() == 2 => {
            let bits = width(b, &operands[0], true)?;
            if immediate(&operands[1]) {
                if matches!(&operands[0], syntax::Operand::Register(v) if matches!(&v.register, PhysicalRegister::Aarch64Sp))
                {
                    return Err(b.fail("A64 MOV-immediate SP form is not selected"));
                }
                let n = immediate_pattern(b, &operands[1], bits)?;
                let wide = move_wide_immediate(n, bits);
                if !wide && (!logical_immediate(n, bits) || zr(&operands[0])) {
                    return Err(
                        b.fail("A64 MOV immediate needs more than one selected instruction")
                    );
                }
            } else {
                register_input(b, &operands[1], true)?;
                let has_sp = operands.iter().any(|o| matches!(o, syntax::Operand::Register(v) if matches!(&v.register, PhysicalRegister::Aarch64Sp)));
                if has_sp && operands.iter().any(zr) {
                    return Err(b.fail("A64 MOV cannot mix SP and zero register"));
                }
            }
            let x = value(b, &operands[1], bits, true)?;
            write(b, &operands[0], x, true)?;
            Ok(LiftFlow::Continue)
        }
        Add | Subtract => {
            let subtract = matches!(operation, Subtract);
            let valid = if subtract {
                matches!(m.as_str(), "sub" | "subs" | "sbc" | "sbcs")
            } else {
                matches!(m.as_str(), "add" | "adds" | "adc" | "adcs")
            };
            if !valid || operands.len() != 3 {
                return Err(b.fail("A64 arithmetic spelling/shift form is not selected"));
            }
            let flags = m.ends_with('s');
            let carry = m.starts_with("adc") || m.starts_with("sbc");
            let y_imm = immediate(&operands[2]);
            let allow_sp = !carry && y_imm;
            let bits = width(b, &operands[0], allow_sp && !flags)?;
            register_input(b, &operands[1], allow_sp)?;
            if carry && y_imm {
                return Err(b.fail("A64 ADC/SBC requires register operands"));
            }
            if y_imm {
                add_immediate(b, &operands[2])?;
                if zr(&operands[1]) || (!flags && zr(&operands[0])) {
                    return Err(b.fail("A64 immediate ADD/SUB register31 denotes SP"));
                }
            } else {
                register_input(b, &operands[2], false)?;
            }
            let x = value(b, &operands[1], bits, allow_sp)?;
            let y = value(b, &operands[2], bits, false)?;
            let cin = if carry { Some(read_flags(b)?.c) } else { None };
            let (x, f) = arithmetic(b, x, y, subtract, cin)?;
            write(b, &operands[0], x, allow_sp && !flags)?;
            if flags {
                write_flags(b, f)?;
            }
            Ok(LiftFlow::Continue)
        }
        Compare | Test => {
            if operands.len() != 2 {
                return Err(b.fail("A64 compare/test shift form is not selected"));
            }
            let valid = (matches!(operation, Test) && m == "tst")
                || (matches!(operation, Compare) && matches!(m.as_str(), "cmp" | "cmn"));
            if !valid {
                return Err(b.fail("A64 compare/test spelling differs"));
            }
            let y_imm = immediate(&operands[1]);
            let allow_sp = y_imm && m != "tst";
            let bits = width(b, &operands[0], allow_sp)?;
            if y_imm {
                if m == "tst" {
                    if !logical_immediate(immediate_pattern(b, &operands[1], bits)?, bits) {
                        return Err(b.fail("A64 logical immediate is not an encoded bitmask"));
                    }
                } else {
                    add_immediate(b, &operands[1])?;
                    if zr(&operands[0]) {
                        return Err(b.fail("A64 immediate compare register31 denotes SP"));
                    }
                }
            } else {
                register_input(b, &operands[1], false)?;
            }
            let x = value(b, &operands[0], bits, allow_sp)?;
            let y = value(b, &operands[1], bits, false)?;
            let f = if m == "tst" {
                let x = b.binary(BinaryKind::And, x, y)?;
                let c = zero(b, 1)?;
                let v = zero(b, 1)?;
                nz(b, x, c, v)?
            } else {
                arithmetic(b, x, y, m == "cmp", None)?.1
            };
            write_flags(b, f)?;
            Ok(LiftFlow::Continue)
        }
        And | Or | Xor => {
            if operands.len() != 3 {
                return Err(b.fail("A64 shifted logical form is not selected"));
            }
            let valid = match operation {
                And => m == "and" || m == "ands",
                Or => m == "orr",
                _ => m == "eor",
            };
            if !valid {
                return Err(b.fail("A64 logical spelling differs"));
            }
            let bits = width(b, &operands[0], false)?;
            register_input(b, &operands[1], false)?;
            if immediate(&operands[2]) {
                if !logical_immediate(immediate_pattern(b, &operands[2], bits)?, bits) {
                    return Err(b.fail("A64 logical immediate is not an encoded bitmask"));
                }
                if m != "ands" && zr(&operands[0]) {
                    return Err(b.fail("A64 logical-immediate register31 destination denotes SP"));
                }
            } else {
                register_input(b, &operands[2], false)?;
            }
            let x = value(b, &operands[1], bits, false)?;
            let y = value(b, &operands[2], bits, false)?;
            let kind = match operation {
                And => BinaryKind::And,
                Or => BinaryKind::Or,
                _ => BinaryKind::Xor,
            };
            let x = b.binary(kind, x, y)?;
            write(b, &operands[0], x, false)?;
            if m == "ands" {
                let c = zero(b, 1)?;
                let v = zero(b, 1)?;
                let f = nz(b, x, c, v)?;
                write_flags(b, f)?;
            }
            Ok(LiftFlow::Continue)
        }
        Load => memory(b, operands, true, false, &m),
        Store => memory(b, operands, false, false, &m),
        LoadPair => memory(b, operands, true, true, &m),
        StorePair => memory(b, operands, false, true, &m),
        Branch if m == "b" && operands.len() == 1 => Ok(LiftFlow::Jump(target(b, &operands[0])?)),
        ConditionalBranch(c) if operands.len() == 1 => {
            if matches!(c, syntax::Condition::Parity | syntax::Condition::NoParity) {
                return Err(b.fail("A64 has no parity condition"));
            }
            if !condition_spelling(&c, &m) {
                return Err(b.fail("A64 conditional branch spelling differs from typed condition"));
            }
            let destination = target(b, &operands[0])?;
            Ok(LiftFlow::Branch {
                condition: condition(b, &c)?,
                target: destination,
            })
        }
        CompareBranchZero | CompareBranchNonzero if operands.len() == 2 => {
            let nonzero_branch = matches!(operation, CompareBranchNonzero);
            let expected = if nonzero_branch { "cbnz" } else { "cbz" };
            if m != expected {
                return Err(b.fail("A64 compare-branch spelling differs"));
            }
            let bits = width(b, &operands[0], false)?;
            let x = value(b, &operands[0], bits, false)?;
            let z = zero(b, bits)?;
            let equal = b.compare(CompareKind::Equal, x, z)?;
            let c = if nonzero_branch {
                not_bool(b, equal)?
            } else {
                equal
            };
            Ok(LiftFlow::Branch {
                condition: c,
                target: target(b, &operands[1])?,
            })
        }
        TestBranchZero | TestBranchNonzero if operands.len() == 3 => {
            let nonzero_branch = matches!(operation, TestBranchNonzero);
            let expected = if nonzero_branch { "tbnz" } else { "tbz" };
            if m != expected {
                return Err(b.fail("A64 test-branch spelling differs"));
            }
            let bits = width(b, &operands[0], false)?;
            let bit = immediate_value(b, &operands[1])?;
            if bit < 0 || bit >= bits as i128 {
                return Err(b.fail("A64 TBZ/TBNZ bit outside register width"));
            }
            let x = value(b, &operands[0], bits, false)?;
            let m = b.constant(bits, 1u128 << bit as u32)?;
            let tested = b.binary(BinaryKind::And, x, m)?;
            let nz = nonzero(b, tested)?;
            let c = if nonzero_branch { nz } else { not_bool(b, nz)? };
            Ok(LiftFlow::Branch {
                condition: c,
                target: target(b, &operands[2])?,
            })
        }
        Return if m == "ret" => {
            if operands.is_empty()
                || (operands.len() == 1
                    && matches!(&operands[0], syntax::Operand::Register(v)
                if matches!(&v.register, PhysicalRegister::Aarch64Gpr { index: 30 }) && v.low_bit == 0 && v.bits == 64))
            {
                let target = b.read_register(RegisterView {
                    register: PhysicalRegister::Aarch64Gpr { index: 30 },
                    low_bit: 0,
                    bits: 64,
                })?;
                // RET branch class is retained; PAC/GCS/platform realization is not inferred.
                Ok(LiftFlow::ReturnTo {
                    target,
                    mechanism: ReturnMechanism::Aarch64Ret,
                })
            } else {
                Err(b.fail("A64 non-LR RET target lacks selected continuation realization"))
            }
        }
        BranchRegister | BranchLinkRegister => Err(b.fail(
            "A64 indirect branch/call requires admitted target/ABI continuation realization",
        )),
        _ => Err(b.fail(format!("A64 unsupported semantic operation/spelling: {m}"))),
    }
}
#[cfg(test)]
#[path = "native_machine_lift_aarch64_tests.rs"]
mod tests;
