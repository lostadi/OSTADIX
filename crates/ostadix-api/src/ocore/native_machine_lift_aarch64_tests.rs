//! Authored typed operands, not original GNU fixtures or native-value execution.
use super::*;
use super::super::native_machine_ir::{Architecture, ByteOrder, CfiPolicy, MachineAbi, MachineInstruction, MachineOperation, MachineProfile, StateFeature};
use super::super::native_machine_lift::LiftIds;
fn profile() -> MachineProfile { MachineProfile { architecture: Architecture::Aarch64, abi: MachineAbi::Aapcs64,
    address_bits: 64, byte_order: ByteOrder::Little, entry_stack_alignment: 16, entry_stack_remainder: 0,
    features: vec![StateFeature::UserRegisterBits], cfi: CfiPolicy::NoCfiDeclared } }
fn reg(index: u8, bits: u16) -> syntax::Operand { syntax::Operand::Register(RegisterView { register: PhysicalRegister::Aarch64Gpr { index }, low_bit: 0, bits }) }
fn sp() -> RegisterView { RegisterView { register: PhysicalRegister::Aarch64Sp, low_bit: 0, bits: 64 } }
fn expr(n: i128) -> syntax::Expression { syntax::Expression { first: syntax::ExprAtom::Integer(n), rest: vec![] } }
fn imm(n: i128) -> syntax::Operand { syntax::Operand::Immediate(expr(n)) }
fn label() -> syntax::Operand { syntax::Operand::Expression(syntax::Expression { first: syntax::ExprAtom::Symbol("authored_cold_label".to_owned()), rest: vec![] }) }
fn address(base: u8, offset: i128, writeback: bool) -> syntax::Operand { syntax::Operand::Address(syntax::Address::Aarch64 {
    base: RegisterView { register: PhysicalRegister::Aarch64Gpr { index: base }, low_bit: 0, bits: 64 }, offset: Some(expr(offset)), writeback }) }
fn lifted(op: syntax::Aarch64Opcode, spelling: &str, args: &[syntax::Operand]) -> (R<LiftFlow>, Vec<MachineInstruction>, usize) {
    let p = profile(); let mut ids = LiftIds::new(1, 1); let mut out = vec![];
    let mut b = BlockLifter::new(&p, 1, 0, &mut ids, &mut out); let result = lower_aarch64(op, spelling, args, &mut b);
    let state = b.state(); drop(b); (result, out, state)
}
fn success(op: syntax::Aarch64Opcode, spelling: &str, args: &[syntax::Operand]) -> (LiftFlow, Vec<MachineInstruction>) {
    let (r, out, state) = lifted(op, spelling, args); let flow = r.unwrap_or_else(|e| panic!("positive authored form refused: {e}"));
    for (i, instruction) in out.iter().enumerate() { assert_eq!(instruction.source_item, 1);
        assert_eq!(instruction.state_in, if i == 0 { 0 } else { out[i - 1].state_out }); }
    assert_eq!(state, out.last().map_or(0, |i| i.state_out)); (flow, out)
}
fn refusal(op: syntax::Aarch64Opcode, spelling: &str, args: &[syntax::Operand], reason: &str) -> Vec<MachineInstruction> {
    let (r, out, _) = lifted(op, spelling, args); let e = match r { Err(e) => e, Ok(_) => panic!("mutant unexpectedly lowered") };
    assert_eq!(e.source_item, 1); assert!(e.reason.contains(reason), "expected {reason:?}, actual {:?}", e.reason); out
}
fn flag_read(o: &MachineInstruction) -> bool { matches!(&o.operation, MachineOperation::ReadFlags { view }
    if view.register == PhysicalRegister::Aarch64Nzcv && view.low_bit == 0 && view.bits == 4) }
fn flag_write(o: &MachineInstruction) -> bool { matches!(&o.operation, MachineOperation::WriteFlags { view, .. }
    if view.register == PhysicalRegister::Aarch64Nzcv && view.low_bit == 0 && view.bits == 4) }
fn depends_on(out: &[MachineInstruction], value: usize, ancestor: usize) -> bool {
    if value == ancestor { return true; }
    let instruction = out.iter().find(|i| i.result.as_ref().is_some_and(|r| r.id == value));
    match instruction.map(|i| &i.operation) {
        Some(MachineOperation::Binary { lhs, rhs, .. }) | Some(MachineOperation::Compare { lhs, rhs, .. }) => depends_on(out, *lhs, ancestor) || depends_on(out, *rhs, ancestor),
        Some(MachineOperation::Cast { value, .. }) => depends_on(out, *value, ancestor), _ => false }
}

#[test]
fn w_and_x_moves_keep_width_and_storage_write_modes() {
    for (bits, expected) in [(32, WriteMode::ZeroExtendStorage), (64, WriteMode::WholeStorage)] {
        let (_, out) = success(syntax::Aarch64Opcode::Move, "mov", &[reg(0, bits), reg(1, bits)]);
        assert!(out.iter().any(|i| matches!(&i.operation, MachineOperation::WriteRegister { view, mode, .. }
            if matches!(&view.register, PhysicalRegister::Aarch64Gpr { index: 0 }) && view.bits == bits && *mode == expected)));
        assert!(!out.iter().any(flag_read)); assert!(!out.iter().any(flag_write));
    }
}
#[test]
fn plain_add_preserves_flags_and_zr_discards_only_result() {
    let args = [reg(0, 64), reg(1, 64), reg(2, 64)]; let (_, baseline) = success(syntax::Aarch64Opcode::Add, "add", &args);
    assert!(!baseline.iter().any(flag_read)); assert!(!baseline.iter().any(flag_write));
    let mut changed = args; changed[0] = syntax::Operand::ZeroRegister { bits: 64 };
    let (_, out) = success(syntax::Aarch64Opcode::Add, "add", &changed);
    assert!(!out.iter().any(|i| matches!(&i.operation, MachineOperation::WriteRegister { .. })));
    assert!(out.iter().any(|i| matches!(&i.operation, MachineOperation::Binary { kind: BinaryKind::WrappingAdd, .. })));
}
#[test]
fn adds_subs_use_typed_compact_flags_not_legacy_flag_writes() {
    for (op, spelling) in [(syntax::Aarch64Opcode::Add, "adds"), (syntax::Aarch64Opcode::Subtract, "subs")] {
        let (_, out) = success(op, spelling, &[reg(0, 32), reg(1, 32), reg(2, 32)]);
        assert_eq!(out.iter().filter(|i| flag_write(i)).count(), 1); assert!(!out.iter().any(flag_read));
        assert!(!out.iter().any(|i| matches!(&i.operation, MachineOperation::WriteRegister { view, .. } if view.register == PhysicalRegister::Aarch64Nzcv)));
        let value = out.iter().find_map(|i| match &i.operation { MachineOperation::WriteFlags { value, .. } => Some(*value), _ => None }).unwrap();
        assert_eq!(out.iter().find_map(|i| i.result.as_ref().filter(|r| r.id == value).map(|r| r.bits)), Some(4));
    }
}
#[test]
fn adcs_sbcs_result_depends_on_selected_carry_input() {
    for (op, spelling) in [(syntax::Aarch64Opcode::Add, "adcs"), (syntax::Aarch64Opcode::Subtract, "sbcs")] {
        let (_, out) = success(op, spelling, &[reg(0, 64), reg(1, 64), reg(2, 64)]);
        assert_eq!(out.iter().filter(|i| flag_read(i)).count(), 1); assert_eq!(out.iter().filter(|i| flag_write(i)).count(), 1);
        let carry = out.iter().find(|i| flag_read(i)).unwrap().result.as_ref().unwrap().id;
        let result = out.iter().find_map(|i| match &i.operation { MachineOperation::WriteRegister { view, value, .. }
            if matches!(&view.register, PhysicalRegister::Aarch64Gpr { index: 0 }) => Some(*value), _ => None }).unwrap();
        assert!(depends_on(&out, result, carry));
    }
}
#[test]
fn arithmetic_register_role_mutants_reach_before_operations() {
    success(syntax::Aarch64Opcode::Add, "add", &[reg(0, 64), reg(1, 64), imm(1)]);
    assert!(refusal(syntax::Aarch64Opcode::Add, "add", &[reg(0, 64), imm(1), imm(1)], "no independently declared W/X width").is_empty());
    success(syntax::Aarch64Opcode::Add, "adc", &[reg(0, 64), reg(1, 64), reg(2, 64)]);
    assert!(refusal(syntax::Aarch64Opcode::Add, "adc", &[reg(0, 64), reg(1, 64), imm(1)], "ADC/SBC requires register operands").is_empty());
}
#[test]
fn gnu_add_immediate_shifted_and_negative_aliases_keep_exact_constants() {
    for n in [-4095 * 4096, -4096, -1, 0, 4095, 4096, 4095 * 4096] {
        for (op, spelling) in [(syntax::Aarch64Opcode::Add, "adds"), (syntax::Aarch64Opcode::Subtract, "subs")] {
            let (_, out) = success(op, spelling, &[reg(0, 64), reg(1, 64), imm(n)]);
            let expected = ((n as u128) & mask(64)).to_le_bytes()[..8].to_vec();
            assert!(out.iter().any(|i| matches!(&i.operation, MachineOperation::Constant { little_endian } if *little_endian == expected)));
        }
    }
    for n in [-4097, 4097, 4096 * 4096, i128::MIN] {
        assert!(refusal(syntax::Aarch64Opcode::Add, "add", &[reg(0, 64), reg(1, 64), imm(n)], "needs more than one selected instruction").is_empty());
    }
}
#[test]
fn logical_immediate_run_patterns_and_changed_mask_are_distinct() {
    for n in [0x00ff00ff, 0xf0f0f0f0, 0x80000001] { success(syntax::Aarch64Opcode::And, "and", &[reg(0, 32), reg(1, 32), imm(n)]); }
    for n in [0, 0xffff_ffff, 0x00ff01ff] { refusal(syntax::Aarch64Opcode::And, "and", &[reg(0, 32), reg(1, 32), imm(n)], "not an encoded bitmask"); }
}
#[test]
fn mov_immediate_requires_one_encoding_and_exact_width() {
    for n in [0, -1, 0x1234_0000_0000i128, 0xff00_ff00_ff00_ff00i128] { success(syntax::Aarch64Opcode::Move, "mov", &[reg(0, 64), imm(n)]); }
    refusal(syntax::Aarch64Opcode::Move, "mov", &[reg(0, 64), imm(0x1234_5678_9abc_def0)], "needs more than one selected instruction");
    refusal(syntax::Aarch64Opcode::Move, "mov", &[reg(0, 32), imm(0x1_0000_0000)], "does not fit selected width");
}
#[test]
fn branches_keep_boolean_width_and_original_symbol() {
    let (flow, out) = success(syntax::Aarch64Opcode::ConditionalBranch(syntax::Condition::Equal), "b.eq", &[label()]);
    assert_eq!(out.iter().filter(|i| flag_read(i)).count(), 1);
    match flow { LiftFlow::Branch { condition, target } => { assert_eq!(condition.bits, 1);
        assert!(matches!(target.first, syntax::ExprAtom::Symbol(ref s) if s == "authored_cold_label")); assert!(target.rest.is_empty()); }, _ => panic!("branch flow missing") }
    let (flow, out) = success(syntax::Aarch64Opcode::CompareBranchNonzero, "cbnz", &[reg(0, 32), label()]);
    assert!(!out.iter().any(flag_read)); assert!(!out.iter().any(flag_write));
    assert!(matches!(flow, LiftFlow::Branch { condition: Scalar { bits: 1, .. }, .. }));
    refusal(syntax::Aarch64Opcode::ConditionalBranch(syntax::Condition::Equal), "b.ne", &[label()], "spelling differs from typed condition");
}
#[test]
fn tbz_bit_bound_mutations_reach_width_guard() {
    success(syntax::Aarch64Opcode::TestBranchZero, "tbz", &[reg(0, 32), imm(31), label()]);
    success(syntax::Aarch64Opcode::TestBranchNonzero, "tbnz", &[reg(0, 64), imm(63), label()]);
    for n in [-1, 32] { assert!(refusal(syntax::Aarch64Opcode::TestBranchZero, "tbz", &[reg(0, 32), imm(n), label()], "bit outside register width").is_empty()); }
}
#[test]
fn byte_loads_distinguish_zero_and_sign_extension() {
    for (spelling, extension) in [("ldrb", ExtensionKind::ZeroExtend), ("ldrsb", ExtensionKind::SignExtend)] {
        let (_, out) = success(syntax::Aarch64Opcode::Load, spelling, &[reg(0, 32), address(1, 0, false)]);
        assert!(out.iter().any(|i| matches!(&i.operation, MachineOperation::Load { .. }) && i.result.as_ref().is_some_and(|r| r.bits == 8)));
        assert!(out.iter().any(|i| matches!(&i.operation, MachineOperation::Cast { kind, .. } if *kind == extension) && i.result.as_ref().is_some_and(|r| r.bits == 32)));
    }
}
#[test]
fn gnu_memory_signed9_aliases_scaled_limits_and_counterexamples() {
    for load in [true, false] {
        let opcode = || if load { syntax::Aarch64Opcode::Load } else { syntax::Aarch64Opcode::Store };
        let spelling = if load { "ldr" } else { "str" };
        for off in [-256, -8, 1, 255, 32760] { let (_, out) = success(opcode(), spelling, &[reg(0, 64), address(1, off, false)]);
            assert!(out.iter().any(|i| matches!(&i.operation, MachineOperation::Load { .. } | MachineOperation::Store { .. }))); }
        for off in [-257, 257, 32768] { assert!(refusal(opcode(), spelling, &[reg(0, 64), address(1, off, false)], "memory offset has no selected instruction encoding").is_empty()); }
    }
    for off in [-256, 255] { success(syntax::Aarch64Opcode::Load, "ldur", &[reg(0, 64), address(1, off, false)]); }
    refusal(syntax::Aarch64Opcode::Load, "ldur", &[reg(0, 64), address(1, 256, false)], "memory offset has no selected instruction encoding");
    success(syntax::Aarch64Opcode::LoadPair, "ldp", &[reg(0, 64), reg(2, 64), address(1, 504, false)]);
    for off in [508, 512, -520] { refusal(syntax::Aarch64Opcode::LoadPair, "ldp", &[reg(0, 64), reg(2, 64), address(1, off, false)], "memory offset has no selected instruction encoding"); }
}
#[test]
fn pair_and_writeback_overlap_are_not_normalized() {
    success(syntax::Aarch64Opcode::LoadPair, "ldp", &[reg(0, 64), reg(2, 64), address(1, 16, false)]);
    refusal(syntax::Aarch64Opcode::LoadPair, "ldp", &[reg(0, 64), reg(0, 64), address(1, 16, false)], "load-pair destinations overlap");
    refusal(syntax::Aarch64Opcode::LoadPair, "ldp", &[syntax::Operand::ZeroRegister { bits: 64 }, syntax::Operand::ZeroRegister { bits: 64 }, address(1, 16, false)], "load-pair destinations overlap");
    refusal(syntax::Aarch64Opcode::LoadPair, "ldp", &[reg(1, 64), reg(2, 64), address(1, 16, true)], "writeback/data register overlap");
}
#[test]
fn symbolic_refusal_is_attributed_to_actual_source_item() {
    success(syntax::Aarch64Opcode::Move, "mov", &[reg(0, 64), imm(1)]);
    let symbolic = syntax::Expression { first: syntax::ExprAtom::Relocation { kind: syntax::Relocation::Got, symbol: "authored_provider".to_owned() }, rest: vec![] };
    let expected = integer_expression(&symbolic).err().expect("GOT is not integer").reason;
    refusal(syntax::Aarch64Opcode::Move, "mov", &[reg(0, 64), syntax::Operand::Immediate(symbolic)], &expected);
}
#[test]
fn indirect_calls_and_non_lr_return_require_continuation_support() {
    success(syntax::Aarch64Opcode::Return, "ret", &[]); success(syntax::Aarch64Opcode::Return, "ret", &[reg(30, 64)]);
    refusal(syntax::Aarch64Opcode::Return, "ret", &[reg(29, 64)], "non-LR RET target lacks selected continuation realization");
    refusal(syntax::Aarch64Opcode::BranchLinkRegister, "blr", &[reg(0, 64)], "requires admitted target/ABI continuation realization");
    refusal(syntax::Aarch64Opcode::BranchRegister, "br", &[reg(0, 64)], "requires admitted target/ABI continuation realization");
}
#[test]
fn security_hint_and_parity_mutations_cannot_become_nop() {
    success(syntax::Aarch64Opcode::Nop, "nop", &[]);
    for spelling in ["bti", "paciasp", "autiasp"] { assert!(refusal(syntax::Aarch64Opcode::Nop, spelling, &[], "unsupported semantic operation/spelling").is_empty()); }
    success(syntax::Aarch64Opcode::ConditionalBranch(syntax::Condition::Equal), "b.eq", &[label()]);
    assert!(refusal(syntax::Aarch64Opcode::ConditionalBranch(syntax::Condition::Parity), "b.p", &[label()], "no parity condition").is_empty());
}
#[test]
fn sp_writeback_is_shared_failure_after_two_provisional_stores() {
    let p = profile(); let mut ids = LiftIds::new(1, 1); let mut out = vec![];
    let mut b = BlockLifter::new(&p, 1, 0, &mut ids, &mut out); let x = b.constant(64, 0).unwrap();
    let shared = b.write_register(sp(), x, WriteMode::WholeStorage).err().expect("SP realization unmet");
    assert_eq!(shared.reason, "SP/PC/zero writes require separate state realization"); drop(b);
    let actual = syntax::Operand::Address(syntax::Address::Aarch64 { base: sp(), offset: Some(expr(-16)), writeback: true });
    let out = refusal(syntax::Aarch64Opcode::StorePair, "stp", &[reg(0, 64), reg(1, 64), actual], &shared.reason);
    assert_eq!(out.iter().filter(|i| matches!(&i.operation, MachineOperation::Store { .. })).count(), 2);
    assert!(!out.iter().any(|i| matches!(&i.operation, MachineOperation::WriteRegister { view, .. } if view.register == PhysicalRegister::Aarch64Sp)));
    // The shared driver must discard this provisional graph on Err.
}
