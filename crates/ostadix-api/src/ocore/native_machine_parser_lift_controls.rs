// Included inside native_machine_asm_reader::tests. The floor is authored
// independently via that module's fixture; parsing consumes the actual text.
// These are parser/lifter DATA controls, not original-unit or native acceptance.
use super::super::native_machine_ir as lift_ir;
use super::super::native_machine_lift::{BlockLifter, LiftFlow, LiftIds};
use super::super::native_machine_lift_dispatch::lift_instruction;

fn lift_selected_record(parsed: &ParsedAssembly, index: usize) -> (LiftFlow, Vec<lift_ir::MachineInstruction>) {
    let mut instructions = Vec::new();
    let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[index].required.id, 0,
        &mut ids, &mut instructions);
    let flow = lift_instruction(parsed, index, &mut builder).unwrap();
    drop(builder);
    for (i, instruction) in instructions.iter().enumerate() {
        assert_eq!(instruction.source_item, parsed.records[index].required.id);
        assert_eq!(instruction.state_in, if i == 0 { 0 } else { instructions[i - 1].state_out });
    }
    (flow, instructions)
}

#[test]
fn parsed_rv_word_shift_aliases_keep_raw_spelling_and_word_extension() {
    let forms = ["addiw a0,a1,-1", "addw a0,a1,a2", "subw a0,a1,a2",
        "andi a0,a1,-1", "ori a0,a1,1", "xori a0,a1,1",
        "slliw a0,a1,0", "srliw a0,a1,31", "sraiw a0,a1,31", "srai a0,a1,63"];
    let text = forms.join("\n") + "\n";
    let floor: Vec<_> = forms.iter().map(|s| (*s, SyntaxKind::Instruction)).collect();
    let parsed = read(&text, Architecture::Rv64, &floor);
    assert!(parsed.syntax_supported, "{:?}", parsed.problems);
    assert_eq!(parsed.records.len(), forms.len());
    for (index, spelling) in forms.iter().enumerate() {
        let Syntax::Instruction { operands, .. } = &parsed.records[index].syntax else { panic!("typed instruction absent") };
        if index != 1 && index != 2 {
            assert!(matches!(&operands[2], Operand::Expression(Expression { first: ExprAtom::Integer(_), .. })));
        }
        let (flow, operations) = lift_selected_record(&parsed, index);
        assert_eq!(flow, LiftFlow::Continue);
        if spelling.starts_with("addiw") || spelling.starts_with("addw") || spelling.starts_with("subw")
            || spelling.starts_with("slliw") || spelling.starts_with("srliw") || spelling.starts_with("sraiw") {
            let truncation = operations.iter().position(|i| matches!(&i.operation,
                lift_ir::MachineOperation::Cast { kind: lift_ir::ExtensionKind::Truncate, .. }) && i.result.unwrap().bits == 32).unwrap();
            let extension = operations.iter().position(|i| matches!(&i.operation,
                lift_ir::MachineOperation::Cast { kind: lift_ir::ExtensionKind::SignExtend, .. }) && i.result.unwrap().bits == 64).unwrap();
            assert!(truncation < extension, "word operation must truncate before extending: {spelling}");
        }
    }
    assert!(!parsed.machine_body_admitted && !parsed.native_qualified && !parsed.runtime_qualified);
}

#[test]
fn parsed_rv_lw_and_lwu_reach_distinct_signed_and_unsigned_loads() {
    let text = "lw a0,0(a1)\nlwu a0,0(a1)\n";
    let parsed = read(text, Architecture::Rv64, &[("lw a0,0(a1)", SyntaxKind::Instruction),
        ("lwu a0,0(a1)", SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    for (index, expected) in [(0, lift_ir::ExtensionKind::SignExtend), (1, lift_ir::ExtensionKind::ZeroExtend)] {
        let (_, operations) = lift_selected_record(&parsed, index);
        assert!(operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::Load { .. }) && i.result.unwrap().bits == 32));
        assert!(operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::Cast { kind, .. } if *kind == expected)
            && i.result.unwrap().bits == 64));
    }
}

#[test]
fn parsed_rv_illegal_word_shift_reaches_encoded_width_rejection() {
    let text = "sraiw a0,a1,32\n";
    let parsed = read(text, Architecture::Rv64, &[(text.trim(), SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[0].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert_eq!(error.source_item, parsed.records[0].required.id);
    assert!(error.reason.contains("shift immediate is outside the encoded operand width"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_aarch64_add_and_adds_share_family_but_preserve_flag_effects() {
    let parsed = read("add x0,x1,x2\nadds x0,x1,x2\n", Architecture::Aarch64,
        &[("add x0,x1,x2", SyntaxKind::Instruction), ("adds x0,x1,x2", SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    for record in &parsed.records {
        assert!(matches!(record.syntax, Syntax::Instruction { opcode: Opcode::Aarch64(Aarch64Opcode::Add), .. }));
    }
    let (_, ordinary) = lift_selected_record(&parsed, 0);
    let (_, setting) = lift_selected_record(&parsed, 1);
    assert!(!ordinary.iter().any(|i| matches!(i.operation, lift_ir::MachineOperation::WriteFlags { .. })));
    assert_eq!(setting.iter().filter(|i| matches!(&i.operation, lift_ir::MachineOperation::WriteFlags { view, .. }
        if view.register == lift_ir::PhysicalRegister::Aarch64Nzcv && view.bits == 4)).count(), 1);
}

#[test]
fn parsed_aarch64_carry_aliases_read_flags_and_refuse_immediate_rhs() {
    for form in ["adc w0,w1,w2", "adcs w0,w1,w2", "sbc w0,w1,w2", "sbcs w0,w1,w2"] {
        let parsed = read(&(form.to_owned() + "\n"), Architecture::Aarch64, &[(form, SyntaxKind::Instruction)]);
        assert!(parsed.syntax_supported);
        let (_, operations) = lift_selected_record(&parsed, 0);
        assert_eq!(operations.iter().filter(|i| matches!(i.operation, lift_ir::MachineOperation::ReadFlags { .. })).count(), 1);
        assert!(!operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::ReadRegister { view }
            if view.register == lift_ir::PhysicalRegister::Aarch64Nzcv)));
    }
    let form = "adcs w0,w1,#1";
    let parsed = read(&(form.to_owned() + "\n"), Architecture::Aarch64, &[(form, SyntaxKind::Instruction)]);
    let Syntax::Instruction { operands, .. } = &parsed.records[0].syntax else { panic!("typed instruction absent") };
    assert!(matches!(operands[2], Operand::Immediate(_)));
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[0].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert!(error.reason.contains("ADC/SBC requires register operands"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_aarch64_unscaled_alias_keeps_address_and_access_width() {
    for (form, bits) in [("ldur x0,[x1,#-8]", 64), ("ldurb w0,[x1,#-1]", 8),
        ("ldursh x0,[x1,#-2]", 16), ("ldursw x0,[x1,#-4]", 32)] {
        let parsed = read(&(form.to_owned() + "\n"), Architecture::Aarch64, &[(form, SyntaxKind::Instruction)]);
        assert!(parsed.syntax_supported);
        let (_, operations) = lift_selected_record(&parsed, 0);
        assert_eq!(operations.iter().filter(|i| matches!(i.operation, lift_ir::MachineOperation::Load { .. })
            && i.result.unwrap().bits == bits).count(), 1);
    }
}

#[test]
fn parsed_x86_movl_preserves_actual_subregister_zero_extension() {
    let form = "movl %eax,%ecx";
    let parsed = read(&(form.to_owned() + "\n"), Architecture::X86_64, &[(form, SyntaxKind::Instruction)]);
    assert!(parsed.syntax_supported);
    let (_, operations) = lift_selected_record(&parsed, 0);
    assert!(operations.iter().any(|i| matches!(&i.operation, lift_ir::MachineOperation::WriteRegister { view, mode, .. }
        if view.bits == 32 && *mode == lift_ir::WriteMode::ZeroExtendStorage)));
}

#[test]
fn parsed_dispatch_refuses_wrong_selected_source_site_before_emission() {
    let parsed = read("addi a0,a1,1\n", Architecture::Rv64, &[("addi a0,a1,1", SyntaxKind::Instruction)]);
    let expected = parsed.records[0].required.id;
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, expected + 1, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert_eq!(error.source_item, expected + 1);
    assert!(error.reason.contains("semantic site differs"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_dispatch_refuses_changed_abi_profile_before_emission() {
    let parsed = read("addi a0,a1,1\n", Architecture::Rv64, &[("addi a0,a1,1", SyntaxKind::Instruction)]);
    let mut profile = parsed.profile.clone();
    profile.abi = MachineAbi::RiscvLp64;
    assert_ne!(profile, parsed.profile);
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&profile, parsed.records[0].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 0, &mut builder).unwrap_err();
    assert!(error.reason.contains("builder differs from selected assembly profile"));
    drop(builder); assert!(instructions.is_empty());
}

#[test]
fn parsed_supported_first_site_cannot_erase_unsupported_original_record() {
    let parsed = read("addi a0,a1,1\noriginal_unrealized_opcode a0\n", Architecture::Rv64,
        &[("addi a0,a1,1", SyntaxKind::Instruction), ("original_unrealized_opcode a0", SyntaxKind::Instruction)]);
    assert_eq!(parsed.records.len(), 2);
    assert!(!parsed.syntax_supported);
    assert_eq!(parsed.problems.len(), 1);
    assert_eq!(parsed.problems[0].record, 1);
    let (_, first) = lift_selected_record(&parsed, 0); assert!(!first.is_empty());
    let mut instructions = Vec::new(); let mut ids = LiftIds::new(1, 1);
    let mut builder = BlockLifter::new(&parsed.profile, parsed.records[1].required.id, 0, &mut ids, &mut instructions);
    let error = lift_instruction(&parsed, 1, &mut builder).unwrap_err();
    assert_eq!(error.source_item, parsed.records[1].required.id);
    assert!(error.reason.contains("no parsed instruction semantics"));
    drop(builder); assert!(instructions.is_empty());
    assert!(!parsed.machine_body_admitted && !parsed.original_unit_completeness_qualified
        && !parsed.provider_qualified && !parsed.native_qualified && !parsed.runtime_qualified);
}
