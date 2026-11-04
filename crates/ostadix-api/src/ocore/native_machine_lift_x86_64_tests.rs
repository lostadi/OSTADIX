//! Authored DATA tests of the actual semantic expander and its emitted v2 graph.
//! The tiny primitive evaluator below is an oracle, NOT a shipped runtime for
//! unchanged machine/LLVM IR. No authentic GNU-source or executable-ABI claim.
use super::*;
use std::collections::BTreeMap;
use super::super::native_machine_ir::{
    CfiPolicy, MachineInstruction, MachineOperation, MachineProfile, StateFeature,
};
use super::super::native_machine_lift::LiftIds;

const FLAGS: u128 = (1 << CF) | (1 << PF) | (1 << AF) | (1 << ZF) | (1 << SF) | (1 << OF);

fn profile() -> MachineProfile {
    MachineProfile { architecture: Architecture::X86_64, abi: MachineAbi::SysvAmd64,
        address_bits: 64, byte_order: ByteOrder::Little,
        entry_stack_alignment: 16, entry_stack_remainder: 8,
        features: vec![StateFeature::UserRegisterBits], cfi: CfiPolicy::NoCfiDeclared }
}
fn reg(name: X86Gpr, bits: u16, low_bit: u16) -> Operand {
    Operand::Register(RegisterView { register: PhysicalRegister::X86Gpr { name }, low_bit, bits })
}
fn expr(n: i128) -> Expression { Expression { first: ExprAtom::Integer(n), rest: vec![] } }
fn imm(n: i128) -> Operand { Operand::Immediate(expr(n)) }
fn mem(d: i128, base: Option<X86Gpr>, index: Option<X86Gpr>, scale: u8) -> Operand {
    let view = |name| RegisterView { register: PhysicalRegister::X86Gpr { name }, low_bit: 0, bits: 64 };
    Operand::Address(Address::X86 { segment: None, displacement: expr(d), base: base.map(view), index: index.map(view), scale })
}
fn lift(op: X86Opcode, bits: Option<u16>, spelling: &str, operands: &[Operand]) -> Result<(LiftFlow, Vec<MachineInstruction>), LiftError> {
    let p = profile(); let mut ids = LiftIds::new(1, 1); let mut instructions = vec![];
    let flow = { let mut b = BlockLifter::new(&p, 1, 0, &mut ids, &mut instructions);
        lower_x86(op, bits, spelling, operands, &mut b)? };
    Ok((flow, instructions))
}

#[derive(Clone, Default)]
struct Model {
    registers: BTreeMap<PhysicalRegister, u128>,
    flags_valid: u128,
    values: BTreeMap<usize, (u16, u128)>,
    memory: BTreeMap<u64, u8>,
}
impl Model {
    fn initialized() -> Self {
        let mut s = Self { flags_valid: FLAGS, ..Self::default() };
        s.registers.insert(PhysicalRegister::X86Flags, 0); s
    }
    fn gpr(&mut self, name: X86Gpr, value: u128) { self.registers.insert(PhysicalRegister::X86Gpr { name }, value); }
    fn value(&self, id: usize) -> Result<(u16, u128), String> { self.values.get(&id).copied().ok_or_else(|| format!("undefined scalar {id}")) }
    fn register(&self, v: RegisterView) -> Result<u128, String> {
        let field = mask(v.bits) << v.low_bit;
        if v.register == PhysicalRegister::X86Flags && self.flags_valid & field != field { return Err("read of undefined x86 flag".into()); }
        self.registers.get(&v.register).map(|n| (n >> v.low_bit) & mask(v.bits)).ok_or_else(|| "uninitialized register".into())
    }
    fn write(&mut self, v: RegisterView, value: u128, mode: WriteMode) -> Result<(), String> {
        let field = mask(v.bits) << v.low_bit;
        let old = *self.registers.get(&v.register).unwrap_or(&0);
        let n = match mode { WriteMode::WholeStorage | WriteMode::ZeroExtendStorage => value & mask(v.bits),
            WriteMode::PreserveOtherBits => (old & !field) | ((value << v.low_bit) & field) };
        self.registers.insert(v.register, n);
        if v.register == PhysicalRegister::X86Flags { self.flags_valid |= field; }
        Ok(())
    }
    fn execute(&mut self, code: &[MachineInstruction]) -> Result<(), String> {
        for instruction in code {
            let result = match &instruction.operation {
                MachineOperation::Constant { little_endian } => {
                    let mut bytes = [0u8; 16];
                    if little_endian.len() > bytes.len() { return Err("oversized DATA scalar".into()); }
                    bytes[..little_endian.len()].copy_from_slice(little_endian); Some(u128::from_le_bytes(bytes))
                }
                MachineOperation::ReadRegister { view } | MachineOperation::ReadFlags { view } => Some(self.register(*view)?),
                MachineOperation::WriteRegister { view, value, mode } => { let (_, n) = self.value(*value)?; self.write(*view, n, *mode)?; None }
                MachineOperation::WriteFlags { view, value } => { let (_, n) = self.value(*value)?; self.write(*view, n, WriteMode::PreserveOtherBits)?; None }
                MachineOperation::InvalidateRegister { view } => {
                    if view.register != PhysicalRegister::X86Flags { return Err("oracle only implements x86 flag invalidation".into()); }
                    self.flags_valid &= !(mask(view.bits) << view.low_bit); None
                }
                MachineOperation::Cast { kind, value } => {
                    let (from, n) = self.value(*value)?;
                    let to = instruction.result.as_ref().ok_or("cast result absent")?.bits;
                    Some(match kind {
                        ExtensionKind::Truncate | ExtensionKind::ZeroExtend => n & mask(to),
                        ExtensionKind::SignExtend => if n & (1u128 << (from - 1)) == 0 { n } else { n | (mask(to) & !mask(from)) },
                    })
                }
                MachineOperation::Binary { kind, lhs, rhs } => {
                    let (bits, a) = self.value(*lhs)?; let (other, c) = self.value(*rhs)?;
                    if bits != other { return Err("binary width mismatch".into()); }
                    Some(match kind {
                        BinaryKind::WrappingAdd => a.wrapping_add(c) & mask(bits),
                        BinaryKind::WrappingSub => a.wrapping_sub(c) & mask(bits),
                        BinaryKind::And => a & c, BinaryKind::Or => a | c, BinaryKind::Xor => a ^ c,
                        BinaryKind::RotateRightModuloWidth => {
                            let n = c % bits as u128;
                            if n == 0 { a } else { ((a >> n) | (a << (bits as u128 - n))) & mask(bits) }
                        }
                    })
                }
                MachineOperation::Compare { kind, lhs, rhs } => {
                    let (_, a) = self.value(*lhs)?; let (_, c) = self.value(*rhs)?;
                    Some(match kind { CompareKind::Equal => (a == c) as u128, CompareKind::UnsignedLess => (a < c) as u128 })
                }
                MachineOperation::Load { address, .. } => {
                    let (_, a) = self.value(*address)?; let bits = instruction.result.as_ref().ok_or("load result absent")?.bits;
                    let mut n = 0; for i in 0..bits / 8 { n |= (*self.memory.get(&(a as u64 + i as u64)).ok_or("uninitialized DATA memory")? as u128) << (8 * i); } Some(n)
                }
                MachineOperation::Store { address, value, .. } => {
                    let (_, a) = self.value(*address)?; let (bits, n) = self.value(*value)?;
                    for i in 0..bits / 8 { self.memory.insert(a as u64 + i as u64, (n >> (8 * i)) as u8); } None
                }
            };
            match (instruction.result, result) {
                (Some(v), Some(n)) => { self.values.insert(v.id, (v.bits, n & mask(v.bits))); }
                (None, None) => (), _ => return Err("result shape mismatch".into()),
            }
        }
        Ok(())
    }
    fn flags(&self) -> u128 { self.registers[&PhysicalRegister::X86Flags] & FLAGS }
}

// Independent arithmetic oracle uses mathematical signed ranges and nibble
// carries/borrows, not the expander's XOR/sign-bit equations.
fn expected_arithmetic(a: u128, c: u128, bits: u16, sub: bool) -> (u128, u128) {
    let m = mask(bits); let a = a & m; let c = c & m;
    let r = if sub { a.wrapping_sub(c) & m } else { (a + c) & m };
    let signed = |n: u128| if n & (1 << (bits - 1)) == 0 { n as i128 } else { n as i128 - (1i128 << bits) };
    let math = if sub { signed(a) - signed(c) } else { signed(a) + signed(c) };
    let carry = if sub { a < c } else { a + c > m };
    let auxiliary = if sub { (a & 15) < (c & 15) } else { (a & 15) + (c & 15) > 15 };
    let overflow = math < -(1i128 << (bits - 1)) || math > (1i128 << (bits - 1)) - 1;
    let flags = ((carry as u128) << CF) | ((auxiliary as u128) << AF) | ((overflow as u128) << OF)
        | (((r == 0) as u128) << ZF) | (((r >> (bits - 1)) & 1) << SF)
        | ((((r as u8).count_ones() % 2 == 0) as u128) << PF);
    (r, flags)
}

#[test]
fn arithmetic_all_widths_matches_independent_signed_range_and_nibble_oracle() {
    for bits in [8, 16, 32, 64] {
        let m = mask(bits); let sign = 1u128 << (bits - 1);
        for (a, c) in [(0, 0), (m, 1), (sign - 1, 1), (sign, 1), (0, 1), (15, 1), (sign, sign), (m, m)] {
            for sub in [false, true] {
                let (r, flags) = expected_arithmetic(a, c, bits, sub);
                let (_, code) = lift(if sub { X86Opcode::Subtract } else { X86Opcode::Add }, Some(bits), if sub { "sub" } else { "add" }, &[reg(X86Gpr::Rbx, bits, 0), reg(X86Gpr::Rax, bits, 0)]).unwrap();
                let mut s = Model::initialized(); s.gpr(X86Gpr::Rax, a); s.gpr(X86Gpr::Rbx, c); s.execute(&code).unwrap();
                assert_eq!(s.register(match reg(X86Gpr::Rax, bits, 0) { Operand::Register(v) => v, _ => unreachable!() }).unwrap(), r);
                assert_eq!(s.flags(), flags, "bits={bits} a={a:x} b={c:x} subtract={sub}");
                assert_eq!(s.flags_valid & FLAGS, FLAGS);
            }
        }
    }
}

#[test]
fn partial_register_writes_preserve_upper_bits_and_eax_zero_extends() {
    let old = 0x8877_6655_4433_2211;
    for (bits, low, expected) in [(8, 0, 0x8877_6655_4433_22aa), (8, 8, 0x8877_6655_4433_aa11), (16, 0, 0x8877_6655_4433_00aa), (32, 0, 0xaa), (64, 0, 0xaa)] {
        let (_, code) = lift(X86Opcode::Move, Some(bits), "mov", &[imm(0xaa), reg(X86Gpr::Rax, bits, low)]).unwrap();
        let mut s = Model::initialized(); s.gpr(X86Gpr::Rax, old); s.execute(&code).unwrap();
        assert_eq!(s.registers[&PhysicalRegister::X86Gpr { name: X86Gpr::Rax }], expected);
    }
}

#[test]
fn mutated_eax_preserve_mode_is_detected_by_upper_half_oracle() {
    let (_, code) = lift(X86Opcode::Move, Some(32), "movl", &[imm(7), reg(X86Gpr::Rax, 32, 0)]).unwrap();
    let mut mutant = code.clone(); let mut reached = false;
    for i in &mut mutant { if let MachineOperation::WriteRegister { view, mode, .. } = &mut i.operation {
        if view.register == (PhysicalRegister::X86Gpr { name: X86Gpr::Rax }) { assert_eq!(*mode, WriteMode::ZeroExtendStorage); *mode = WriteMode::PreserveOtherBits; reached = true; }
    } }
    assert!(reached); let mut good = Model::initialized(); good.gpr(X86Gpr::Rax, u64::MAX as u128);
    let mut bad = good.clone(); good.execute(&code).unwrap(); bad.execute(&mutant).unwrap();
    assert_eq!(good.registers[&PhysicalRegister::X86Gpr { name: X86Gpr::Rax }], 7);
    assert_eq!(bad.registers[&PhysicalRegister::X86Gpr { name: X86Gpr::Rax }], 0xffff_ffff_0000_0007);
}

#[test]
fn logical_af_is_invalidated_and_missing_invalidation_mutation_is_visible() {
    let (_, code) = lift(X86Opcode::Xor, Some(64), "xorq", &[reg(X86Gpr::Rax, 64, 0), reg(X86Gpr::Rax, 64, 0)]).unwrap();
    let mut mutant = code.clone(); let before = mutant.len();
    mutant.retain(|i| !matches!(&i.operation, MachineOperation::InvalidateRegister { view } if *view == flag(AF)));
    assert_eq!(before - mutant.len(), 1);
    let mut good = Model::initialized(); good.gpr(X86Gpr::Rax, 123); good.registers.insert(PhysicalRegister::X86Flags, 1 << AF);
    let mut bad = good.clone(); good.execute(&code).unwrap(); bad.execute(&mutant).unwrap();
    assert_eq!(good.flags_valid & (1 << AF), 0); assert!(good.register(flag(AF)).unwrap_err().contains("undefined"));
    assert_ne!(bad.flags_valid & (1 << AF), 0); assert_eq!(bad.register(flag(AF)).unwrap(), 1);
    assert_eq!(good.flags() & !(1 << AF), (1 << ZF) | (1 << PF));
}

#[test]
fn compare_changes_flags_without_writing_destination() {
    let (_, code) = lift(X86Opcode::Compare, Some(64), "cmpq", &[reg(X86Gpr::Rbx, 64, 0), reg(X86Gpr::Rax, 64, 0)]).unwrap();
    assert!(!code.iter().any(|i| matches!(i.operation, MachineOperation::WriteRegister { .. })));
    let mut s = Model::initialized(); s.gpr(X86Gpr::Rax, 0); s.gpr(X86Gpr::Rbx, 1); s.execute(&code).unwrap();
    assert_eq!(s.registers[&PhysicalRegister::X86Gpr { name: X86Gpr::Rax }], 0);
    assert_eq!(s.flags(), expected_arithmetic(0, 1, 64, true).1);
}

#[test]
fn carry_output_removal_mutation_fails_intended_arithmetic_oracle() {
    let (_, code) = lift(X86Opcode::Add, Some(64), "addq", &[reg(X86Gpr::Rbx, 64, 0), reg(X86Gpr::Rax, 64, 0)]).unwrap();
    let mut mutant = code.clone(); let before = mutant.len();
    mutant.retain(|i| !matches!(&i.operation, MachineOperation::WriteFlags { view, .. } if *view == flag(CF)));
    assert_eq!(before - mutant.len(), 1);
    let mut good = Model::initialized(); good.gpr(X86Gpr::Rax, u64::MAX as u128); good.gpr(X86Gpr::Rbx, 1);
    let mut bad = good.clone(); good.execute(&code).unwrap(); bad.execute(&mutant).unwrap();
    assert_eq!(good.register(flag(CF)).unwrap(), 1); assert_eq!(bad.register(flag(CF)).unwrap(), 0);
}

#[test]
fn lea_scaled_address_uses_modular_arithmetic_without_memory_read() {
    let (_, code) = lift(X86Opcode::Lea, Some(32), "leal", &[mem(-8, Some(X86Gpr::Rbx), Some(X86Gpr::Rcx), 8), reg(X86Gpr::Rax, 32, 0)]).unwrap();
    assert!(!code.iter().any(|i| matches!(i.operation, MachineOperation::Load { .. } | MachineOperation::Store { .. })));
    let mut s = Model::initialized(); s.gpr(X86Gpr::Rax, u64::MAX as u128); s.gpr(X86Gpr::Rbx, 0x1_0000_0000); s.gpr(X86Gpr::Rcx, 3); s.execute(&code).unwrap();
    assert_eq!(s.registers[&PhysicalRegister::X86Gpr { name: X86Gpr::Rax }], 16);
}

#[test]
fn memory_add_reuses_original_effective_address_when_destination_register_aliases_base() {
    let (_, code) = lift(X86Opcode::Add, Some(64), "addq", &[mem(0, Some(X86Gpr::Rax), None, 1), reg(X86Gpr::Rax, 64, 0)]).unwrap();
    let mut s = Model::initialized(); s.gpr(X86Gpr::Rax, 0x100);
    for i in 0..8 { s.memory.insert(0x100 + i, if i == 0 { 5 } else { 0 }); }
    s.execute(&code).unwrap(); assert_eq!(s.registers[&PhysicalRegister::X86Gpr { name: X86Gpr::Rax }], 0x105);
}

#[test]
fn signed_and_unsigned_branch_conditions_read_actual_flag_bits() {
    for (c, flags, expected) in [(Condition::Less, 1 << SF, 1), (Condition::GreaterEqual, 1 << SF, 0),
        (Condition::Above, 1 << ZF, 0), (Condition::BelowEqual, 1 << CF, 1),
        (Condition::Greater, (1 << SF) | (1 << OF), 1), (Condition::NoParity, 1 << PF, 0)] {
        let target = Expression { first: ExprAtom::Symbol("label".into()), rest: vec![] };
        let (flow, code) = lift(X86Opcode::ConditionalJump(c), None, "jcc", &[Operand::Expression(target.clone())]).unwrap();
        let LiftFlow::Branch { condition, target: actual } = flow else { panic!("wrong control kind") };
        assert_eq!(actual, target); let mut s = Model::initialized(); s.registers.insert(PhysicalRegister::X86Flags, flags); s.execute(&code).unwrap();
        assert_eq!(s.values[&condition.id].1, expected);
    }
}

#[test]
fn high_byte_and_required_rex_is_rejected_before_emission() {
    let error = lift(X86Opcode::Move, Some(8), "movb", &[reg(X86Gpr::Rax, 8, 8), reg(X86Gpr::R8, 8, 0)]).unwrap_err();
    assert!(error.to_string().contains("REX"));
}

#[test]
fn tls_rip_and_got_require_real_selected_bindings() {
    let mut tls = mem(0, None, None, 1);
    if let Operand::Address(Address::X86 { segment, .. }) = &mut tls { *segment = Some(syntax::Segment::Fs); }
    let rip = Operand::Address(Address::X86 { segment: None, displacement: expr(0), base: Some(RegisterView { register: PhysicalRegister::X86Pc, low_bit: 0, bits: 64 }), index: None, scale: 1 });
    let got = Operand::Expression(Expression { first: ExprAtom::Relocation { kind: syntax::Relocation::GotPcRel, symbol: "object".into() }, rest: vec![] });
    for (operand, reason) in [(tls, "TLS"), (rip, "RIP"), (got, "binding")] {
        let error = lift(X86Opcode::Move, Some(64), "movq", &[operand, reg(X86Gpr::Rax, 64, 0)]).unwrap_err();
        assert!(error.to_string().contains(reason), "{error}");
    }
}

#[test]
fn memory_to_memory_and_unencodable_imm64_are_rejected() {
    let error = lift(X86Opcode::Move, Some(64), "movq", &[mem(0, Some(X86Gpr::Rax), None, 1), mem(0, Some(X86Gpr::Rbx), None, 1)]).unwrap_err();
    assert!(error.to_string().contains("two memory"));
    let error = lift(X86Opcode::Add, Some(64), "addq", &[imm(0x1_0000_0000), reg(X86Gpr::Rax, 64, 0)]).unwrap_err();
    assert!(error.to_string().contains("imm32"));
}

#[test]
fn call_and_indirect_control_do_not_fabricate_signatures_or_replay_pc() {
    let target = Operand::Expression(Expression { first: ExprAtom::Symbol("callee".into()), rest: vec![] });
    assert!(lift(X86Opcode::Call, None, "call", &[target]).unwrap_err().to_string().contains("ABI/prototype"));
    assert!(lift(X86Opcode::Jump, None, "jmp", &[Operand::Indirect(Box::new(reg(X86Gpr::Rax, 64, 0)))]).unwrap_err().to_string().contains("target-set"));
    let p = profile(); let mut ids = LiftIds::new(1,1); let mut code = vec![];
    let error = {
        let mut b = BlockLifter::new(&p,77,0,&mut ids,&mut code);
        let state_before = b.state();
        let error = lower_x86(X86Opcode::Return,None,"ret",&[],&mut b).unwrap_err();
        assert_eq!(b.state(),state_before); error
    };
    assert_eq!(error.source_item,77);
    assert_eq!(error.reason,"x86 RET stack/CET return protocol is not represented");
    assert!(code.is_empty());
    assert!(!code.iter().any(|i|matches!(&i.operation,MachineOperation::WriteRegister{view,..}
        if matches!(view.register,PhysicalRegister::X86Gpr{name:X86Gpr::Rsp}|PhysicalRegister::X86Pc))));
    assert!(lift(X86Opcode::Return, None, "ret", &[imm(8)]).unwrap_err().to_string().contains("RET immediate"));
}

#[test]
fn shifts_are_explicitly_unmet_instead_of_preserving_undefined_flags() {
    for op in [X86Opcode::ShiftLeft, X86Opcode::ShiftRight, X86Opcode::ShiftArithmeticRight, X86Opcode::RotateLeft, X86Opcode::RotateRight] {
        assert!(lift(op, Some(64), "shift", &[imm(1), reg(X86Gpr::Rax, 64, 0)]).unwrap_err().to_string().contains("not implemented"));
    }
}
