//! Authored fixture controls only; no original engine or native execution.
use super::super::{native_ir::ValueId, native_machine_emit_rv64::select_body};
use super::*;
fn reg(index: u8) -> RegisterView {
    RegisterView {
        register: PhysicalRegister::RiscvGpr { index },
        low_bit: 0,
        bits: 64,
    }
}
fn fixture(
    ops: Vec<(Option<(ValueId, u16)>, MachineOperation)>,
    target: ValueId,
) -> (MachineBodyContract, SelectedInstructionInventory) {
    let pin = ArtifactIdentity {
        bytes: 4096,
        sha256: "a".repeat(64),
    };
    let source = SourceWitness {
        format: SOURCE_FORMAT.into(),
        input_form: MachineInputForm::ConfiguredAssemblyText,
        unit_id: "unqualified-fixture".into(),
        files: vec![SourceFile {
            id: 1,
            logical_path: "fixture.S".into(),
            identity: pin.clone(),
        }],
        decoded_assembly: pin.clone(),
        build_configuration: pin.clone(),
        frontend_event: pin.clone(),
    };
    let profile = MachineProfile {
        architecture: Architecture::Rv64,
        abi: MachineAbi::RiscvLp64,
        address_bits: 64,
        byte_order: ByteOrder::Little,
        entry_stack_alignment: 16,
        entry_stack_remainder: 0,
        features: vec![StateFeature::UserRegisterBits],
        cfi: CfiPolicy::NoCfiDeclared,
    };
    let mut initialized: Vec<_> = (1..32).map(reg).collect();
    initialized.push(RegisterView {
        register: PhysicalRegister::RiscvPc,
        low_bit: 0,
        bits: 64,
    });
    let preserved = [1, 2, 3, 4, 8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27]
        .into_iter()
        .map(reg)
        .collect();
    let interface = MachineInterface {
        entry: EntryInterface {
            policy: EntryPolicy::NoImplicitFrameOrScratch,
            initialized,
            memory: MemoryInterface::OrderedProcessData,
        },
        exits: vec![ExitInterface {
            id: 0,
            kind: ExitKind::OrdinaryReturn,
            outputs: vec![reg(10)],
            preserved,
        }],
    };
    let count = ops.len();
    let instructions = ops
        .into_iter()
        .enumerate()
        .map(|(i, (result, operation))| MachineInstruction {
            source_item: (i + 1) as u64,
            state_in: i,
            state_out: i + 1,
            result: result.map(|(id, bits)| Scalar { id, bits }),
            operation,
        })
        .collect();
    let items = (1..=count + 1)
        .map(|id| SourceItem {
            id: id as u64,
            kind: SourceItemKind::Instruction,
            decoded_span: SourceSpan {
                start: (id * 8) as u64,
                end: (id * 8 + 4) as u64,
            },
            origins: vec![OriginalSpan {
                file: 1,
                span: SourceSpan {
                    start: (id * 8) as u64,
                    end: (id * 8 + 4) as u64,
                },
            }],
        })
        .collect();
    let inv = SelectedInstructionInventory {
        format: INVENTORY_FORMAT.into(),
        identity: pin.clone(),
        source: source.clone(),
        symbol: "fixture".into(),
        profile: profile.clone(),
        interface: interface.clone(),
        items,
    };
    let body = MachineBodyContract {
        format: COMPUTED_CONTROL_FORMAT.into(),
        selected_inventory: pin,
        source,
        symbol: "fixture".into(),
        profile,
        interface,
        entry: 0,
        blocks: vec![MachineBlock {
            id: 0,
            source_label: None,
            state_parameter: 0,
            parameters: vec![],
            instructions,
            terminator: MachineTerminator {
                source_item: (count + 1) as u64,
                state: count,
                control: MachineControl::ReturnTo {
                    exit: 0,
                    target,
                    mechanism: ReturnMechanism::Rv64Jalr,
                },
            },
        }],
        directives: vec![],
    };
    (body, inv)
}
fn ret() -> Vec<(Option<(ValueId, u16)>, MachineOperation)> {
    vec![
        (
            Some((100, 64)),
            MachineOperation::ReadRegister { view: reg(1) },
        ),
        (
            Some((101, 64)),
            MachineOperation::Constant {
                little_endian: 0u64.to_le_bytes().to_vec(),
            },
        ),
        (
            Some((102, 64)),
            MachineOperation::Binary {
                kind: BinaryKind::WrappingAdd,
                lhs: 100,
                rhs: 101,
            },
        ),
        (
            Some((103, 64)),
            MachineOperation::Constant {
                little_endian: (u64::MAX - 1).to_le_bytes().to_vec(),
            },
        ),
        (
            Some((104, 64)),
            MachineOperation::Binary {
                kind: BinaryKind::And,
                lhs: 102,
                rhs: 103,
            },
        ),
    ]
}
#[test]
fn explicit_return_selects_real_jalr() {
    let (b, i) = fixture(ret(), 104);
    let p = select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest").unwrap();
    assert!(p.assembly().contains("jalr x0, x1, 0"));
    assert_eq!(p.byte_size(), 4);
}
#[test]
fn changed_return_target_reaches_low_bit_rejection() {
    let (mut b, i) = fixture(ret(), 104);
    assert_eq!((0x1001u64.wrapping_add(0)) & !1, 0x1000);
    assert_ne!(0x1001u64, 0x1000);
    if let MachineControl::ReturnTo { target, .. } = &mut b.blocks[0].terminator.control {
        *target = 100;
    } else {
        panic!("mutation not reached")
    }
    assert!(matches!(
        b.blocks[0].terminator.control,
        MachineControl::ReturnTo { target: 100, .. }
    ));
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("exact JALR low-bit"));
}
#[test]
fn missing_ra_preservation_is_not_native_abi() {
    let (mut b, mut i) = fixture(ret(), 104);
    b.interface.exits[0]
        .preserved
        .retain(|v| v.register != reg(1).register);
    i.interface = b.interface.clone();
    assert!(!b.interface.exits[0].preserved.contains(&reg(1)));
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("leaf ABI"));
}
#[test]
fn unused_load_is_emitted_to_x0() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 64)),
            MachineOperation::Load {
                address: 1,
                alignment: 1,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    let p = select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest").unwrap();
    assert!(p.assembly().contains("ld x0, 0(x10)"));
    assert_eq!(p.instruction_count, 2);
}
#[test]
fn byte_load_keeps_exact_footprint() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 8)),
            MachineOperation::Load {
                address: 1,
                alignment: 1,
            },
        ),
        (
            Some((3, 64)),
            MachineOperation::Cast {
                kind: ExtensionKind::ZeroExtend,
                value: 2,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 3,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    let p = select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest").unwrap();
    assert!(p.assembly().contains("lbu x10, 0(x10)"));
    assert!(!p.assembly().contains("ld x10"));
}
#[test]
fn load_old_destination_read_reaches_refusal() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 64)),
            MachineOperation::Load {
                address: 1,
                alignment: 1,
            },
        ),
        (
            Some((3, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 2,
                mode: WriteMode::WholeStorage,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(11),
                value: 3,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    assert!(matches!(
        b.blocks[0].instructions[2].operation,
        MachineOperation::ReadRegister { .. }
    ));
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("old destination read"));
}
#[test]
fn old_scalar_after_write_requires_allocation() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 64)),
            MachineOperation::Constant {
                little_endian: 7u64.to_le_bytes().to_vec(),
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 2,
                mode: WriteMode::WholeStorage,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(11),
                value: 1,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("explicit allocation"));
}
#[test]
fn live_rotate_does_not_invent_zbb() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 64)),
            MachineOperation::Constant {
                little_endian: 3u64.to_le_bytes().to_vec(),
            },
        ),
        (
            Some((3, 64)),
            MachineOperation::Binary {
                kind: BinaryKind::RotateRightModuloWidth,
                lhs: 1,
                rhs: 2,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 3,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("Zbb/RORI"));
}
#[test]
fn balanced_constant_sequence_has_no_scratch() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::Constant {
                little_endian: 0x8000000000000801u64.to_le_bytes().to_vec(),
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 1,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    let code = select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap()
        .assembly();
    let materialized: Vec<_> = code
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("addi ") || line.starts_with("slli "))
        .collect();
    assert!(!materialized.is_empty());
    assert!(materialized
        .iter()
        .all(|line| line.starts_with("addi x10,") || line.starts_with("slli x10,")));
    assert!(materialized.iter().any(|line| line.contains("-2047")));
}

#[test]
fn captured_destination_before_load_is_not_clobbered() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 64)),
            MachineOperation::ReadRegister { view: reg(12) },
        ),
        (
            Some((3, 64)),
            MachineOperation::Load {
                address: 2,
                alignment: 1,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 3,
                mode: WriteMode::WholeStorage,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(11),
                value: 1,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    assert!(matches!(
        b.blocks[0].instructions[4].operation,
        MachineOperation::WriteRegister { value: 1, .. }
    ));
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("captured pre-load destination scalar"));
}
#[test]
fn aliased_load_base_reused_after_write_needs_allocation() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 64)),
            MachineOperation::Load {
                address: 1,
                alignment: 1,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 2,
                mode: WriteMode::WholeStorage,
            },
        ),
        (
            Some((3, 64)),
            MachineOperation::Load {
                address: 1,
                alignment: 1,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    assert!(matches!(
        b.blocks[0].instructions[3].operation,
        MachineOperation::Load { address: 1, .. }
    ));
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("captured pre-load destination scalar"));
}
#[test]
fn narrow_load_extra_consumer_is_not_silently_widened() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::ReadRegister { view: reg(10) },
        ),
        (
            Some((2, 8)),
            MachineOperation::Load {
                address: 1,
                alignment: 1,
            },
        ),
        (
            Some((3, 64)),
            MachineOperation::Cast {
                kind: ExtensionKind::ZeroExtend,
                value: 2,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 3,
                mode: WriteMode::WholeStorage,
            },
        ),
        (
            Some((4, 64)),
            MachineOperation::Cast {
                kind: ExtensionKind::SignExtend,
                value: 2,
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(11),
                value: 4,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (b, i) = fixture(ops, 104);
    assert_eq!(
        b.blocks[0]
            .instructions
            .iter()
            .filter(|i| matches!(i.operation, MachineOperation::Cast { value: 2, .. }))
            .count(),
        2
    );
    assert!(select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest")
        .unwrap_err()
        .contains("retention/fanout"));
}
fn item(id: u64) -> SourceItem {
    SourceItem {
        id,
        kind: SourceItemKind::Instruction,
        decoded_span: SourceSpan {
            start: id * 8,
            end: id * 8 + 4,
        },
        origins: vec![OriginalSpan {
            file: 1,
            span: SourceSpan {
                start: id * 8,
                end: id * 8 + 4,
            },
        }],
    }
}
#[test]
fn conditional_loop_and_cold_return_are_both_selected() {
    let (mut b, mut i) = fixture(ret(), 104);
    let mut exit = b.blocks.remove(0);
    exit.id = 1;
    exit.state_parameter = 100;
    for (n, op) in exit.instructions.iter_mut().enumerate() {
        op.source_item = (n + 5) as u64;
        op.state_in = 100 + n;
        op.state_out = 101 + n;
    }
    exit.terminator.source_item = 10;
    exit.terminator.state = 105;
    let head = MachineBlock {
        id: 0,
        source_label: None,
        state_parameter: 0,
        parameters: vec![],
        instructions: vec![
            MachineInstruction {
                source_item: 1,
                state_in: 0,
                state_out: 1,
                result: Some(Scalar { id: 1, bits: 64 }),
                operation: MachineOperation::ReadRegister { view: reg(10) },
            },
            MachineInstruction {
                source_item: 2,
                state_in: 1,
                state_out: 2,
                result: Some(Scalar { id: 2, bits: 64 }),
                operation: MachineOperation::ReadRegister { view: reg(11) },
            },
            MachineInstruction {
                source_item: 3,
                state_in: 2,
                state_out: 3,
                result: Some(Scalar { id: 3, bits: 1 }),
                operation: MachineOperation::Compare {
                    kind: CompareKind::Equal,
                    lhs: 1,
                    rhs: 2,
                },
            },
        ],
        terminator: MachineTerminator {
            source_item: 4,
            state: 3,
            control: MachineControl::Branch {
                condition: 3,
                on_true: Edge {
                    target: 1,
                    arguments: vec![],
                },
                on_false: Edge {
                    target: 0,
                    arguments: vec![],
                },
            },
        },
    };
    b.blocks = vec![head, exit];
    i.items = (1..=10).map(item).collect();
    let p = select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest").unwrap();
    let text = p.assembly();
    assert!(text.contains(".Ltest_0:") && text.contains(".Ltest_1:"));
    assert!(
        text.contains("beq x10, x11, .Ltest_1")
            && text.contains("jal x0, .Ltest_0")
            && text.contains("jalr x0, x1, 0")
    );
    assert_eq!(p.instruction_count, 3);
}
#[test]
fn unreachable_cold_block_is_not_omitted() {
    let (mut b, mut i) = fixture(ret(), 104);
    let cold = b.blocks[0].clone();
    b.entry = 1;
    b.blocks = vec![
        MachineBlock {
            id: 1,
            source_label: None,
            state_parameter: 100,
            parameters: vec![],
            instructions: vec![],
            terminator: MachineTerminator {
                source_item: 7,
                state: 100,
                control: MachineControl::Jump {
                    edge: Edge {
                        target: 1,
                        arguments: vec![],
                    },
                },
            },
        },
        cold,
    ];
    i.items.push(item(7));
    let p = select_body(&b, &i, Target::Riscv64UnknownNone, ".Ltest").unwrap();
    let text = p.assembly();
    assert!(text.find(".Ltest_1:").unwrap() < text.find(".Ltest_0:").unwrap());
    assert!(text.contains("jal x0, .Ltest_1") && text.contains("jalr x0, x1, 0"));
    assert_eq!(p.instruction_count, 2);
}
#[test]
fn no_exit_graph_cannot_write_ra_gp_or_tp() {
    let mut ops = vec![
        (
            Some((1, 64)),
            MachineOperation::Constant {
                little_endian: 7u64.to_le_bytes().to_vec(),
            },
        ),
        (
            None,
            MachineOperation::WriteRegister {
                view: reg(10),
                value: 1,
                mode: WriteMode::WholeStorage,
            },
        ),
    ];
    ops.extend(ret());
    let (mut baseline, inventory) = fixture(ops, 104);
    baseline.blocks[0].terminator.control = MachineControl::Jump {
        edge: Edge {
            target: 0,
            arguments: vec![],
        },
    };
    assert_eq!(baseline.interface.exits.len(), 1);
    assert_eq!(baseline.interface, inventory.interface);
    assert!(matches!(
        baseline.blocks[0].terminator.control,
        MachineControl::Jump {
            edge: Edge { target: 0, .. }
        }
    ));
    let structurally_valid = super::super::native_machine_verify::verify(
        &baseline,
        &inventory,
        Target::Riscv64UnknownNone,
    );
    assert!(
        structurally_valid.is_ok(),
        "no-write-to-protected loop baseline: {structurally_valid:?}"
    );
    let selected =
        select_body(&baseline, &inventory, Target::Riscv64UnknownNone, ".Ltest").unwrap();
    assert!(
        selected.assembly().contains("addi x10, x0, 7")
            && selected.assembly().contains("jal x0, .Ltest_0")
    );
    assert!(!selected.assembly().contains("jalr"));
    for index in [1, 3, 4] {
        let mut changed = baseline.clone();
        let instruction = &mut changed.blocks[0].instructions[1];
        assert!(
            matches!(instruction.operation,MachineOperation::WriteRegister{view,value:1,mode:WriteMode::WholeStorage}if view==reg(10))
        );
        if let MachineOperation::WriteRegister { view, .. } = &mut instruction.operation {
            *view = reg(index);
        } else {
            panic!("write mutation not reached")
        }
        assert!(
            matches!(instruction.operation,MachineOperation::WriteRegister{view,value:1,mode:WriteMode::WholeStorage}if view==reg(index))
        );
        assert_eq!(changed.interface, baseline.interface);
        assert_eq!(changed.source, baseline.source);
        assert_eq!(
            changed.blocks[0].instructions.len(),
            baseline.blocks[0].instructions.len()
        );
        let mut restored = changed.clone();
        if let MachineOperation::WriteRegister { view, .. } =
            &mut restored.blocks[0].instructions[1].operation
        {
            *view = reg(10);
        }
        assert_eq!(restored, baseline);
        let structural = super::super::native_machine_verify::verify(
            &changed,
            &inventory,
            Target::Riscv64UnknownNone,
        )
        .unwrap_err();
        assert!(
            format!("{structural:?}")
                .contains("write overlaps readonly exit-preserved register bits"),
            "wrong structural guard: {structural:?}"
        );
        let selected_error =
            select_body(&changed, &inventory, Target::Riscv64UnknownNone, ".Ltest").unwrap_err();
        assert!(
            selected_error.starts_with("machine structural verification:")
                && selected_error.contains("write overlaps readonly exit-preserved register bits"),
            "wrong native refusal: {selected_error}"
        );
    }
}

// Public whole-unit fixtures have actual complete configured source bytes,
// exact row origins, a separate inner claim and raw inventory identities.
// They are authored test inputs, never original-engine/source admission.
struct WholeFixture {
    unit: MachineUnit,
    selection: UnitSelection,
    inventory: Vec<u8>,
    assembly: Vec<u8>,
    label_record: u64,
    ret_record: u64,
    original_collision: Option<String>,
}
struct WholeOptions {
    kind: SectionKind,
    flags: Vec<u8>,
    alignment: u64,
    prefix_bytes: usize,
    skip_alignment: bool,
    numeric: bool,
    named_collision: bool,
}
impl Default for WholeOptions {
    fn default() -> Self {
        Self {
            kind: SectionKind::ProgramBits,
            flags: b"ax".to_vec(),
            alignment: 2,
            prefix_bytes: 0,
            skip_alignment: false,
            numeric: false,
            named_collision: false,
        }
    }
}
fn row(
    text: &mut String,
    records: &mut Vec<UnitRecord>,
    kind: UnitRecordKind,
    effects: Vec<RecordEffect>,
    line: String,
) -> u64 {
    let id = records.len() as u64 + 1;
    let start = text.len() as u64;
    text.push_str(&line);
    let span = SourceSpan {
        start,
        end: text.len() as u64,
    };
    records.push(UnitRecord {
        id,
        kind,
        span,
        origins: vec![OriginalSpan { file: 1, span }],
        effects,
    });
    id
}
fn whole_fixture(options: WholeOptions) -> WholeFixture {
    let mut text = String::new();
    let mut records = Vec::new();
    let mut initializers = Vec::new();
    let mut alignments = Vec::new();
    let mut symbols = vec![UnitSymbol {
        id: 0,
        name: SymbolName::Named { value: "f".into() },
        binding: SymbolBinding::Local,
        visibility: SymbolVisibility::Default,
        kind: SymbolKind::Function,
        size: SymbolSize::Unspecified,
        definition: SymbolDefinition::Body {
            section: 0,
            body: 0,
        },
    }];
    let section_kind = match &options.kind {
        SectionKind::ProgramBits => "progbits",
        SectionKind::NoBits => "nobits",
        SectionKind::Note => "note",
    };
    row(
        &mut text,
        &mut records,
        UnitRecordKind::Section,
        vec![RecordEffect::SelectSection { section: 0 }],
        format!(
            ".section .text,\"{}\",@{section_kind}\n",
            String::from_utf8(options.flags.clone()).unwrap()
        ),
    );
    row(
        &mut text,
        &mut records,
        UnitRecordKind::Symbol,
        vec![RecordEffect::SymbolType {
            symbol: 0,
            kind: SymbolKind::Function,
        }],
        ".type f,@function\n".into(),
    );
    let mut code_offset = options.prefix_bytes as u64;
    if options.prefix_bytes > 0 {
        initializers.push(UnitInitializer {
            id: 0,
            section: 0,
            offset: 0,
            value: InitializerValue::Bytes {
                value: vec![0; options.prefix_bytes],
            },
        });
        row(
            &mut text,
            &mut records,
            UnitRecordKind::Data,
            vec![RecordEffect::Initialize { initializer: 0 }],
            format!(".byte {}\n", vec!["0"; options.prefix_bytes].join(",")),
        );
    }
    if options.skip_alignment {
        let needed = (4 - code_offset % 4) % 4;
        let pad = if needed > 1 { 0 } else { needed };
        let id = records.len() as u64 + 1;
        alignments.push(UnitAlignment {
            id,
            section: 0,
            boundary: 4,
            fill: Some(0),
            maximum_skip: Some(1),
            layout: Some(if pad == 0 && needed > 1 {
                AlignmentLayout::Skipped {
                    offset: code_offset,
                    required_padding: needed,
                }
            } else {
                AlignmentLayout::Applied {
                    offset: code_offset,
                    padding: pad,
                }
            }),
        });
        row(
            &mut text,
            &mut records,
            UnitRecordKind::Alignment,
            vec![RecordEffect::Alignment { alignment: id }],
            ".balign 4,0,1\n".into(),
        );
        code_offset += pad;
    }
    let label_record = row(
        &mut text,
        &mut records,
        UnitRecordKind::Label,
        vec![
            RecordEffect::DefineSymbol { symbol: 0 },
            RecordEffect::BodyItem { body: 0 },
        ],
        "f:\n".into(),
    );
    let ret_record = row(
        &mut text,
        &mut records,
        UnitRecordKind::Instruction,
        vec![RecordEffect::BodyItem { body: 0 }],
        "ret\n".into(),
    );
    let mut original_collision = None;
    if options.numeric {
        let definition_record = records.len() as u64 + if options.named_collision { 2 } else { 1 };
        let native_offset = code_offset + 4;
        for (id, number) in [(1, 1), (2, 2)] {
            symbols.push(UnitSymbol {
                id,
                name: SymbolName::NumericLocal {
                    number,
                    definition_record,
                },
                binding: SymbolBinding::Local,
                visibility: SymbolVisibility::Default,
                kind: SymbolKind::NoType,
                size: SymbolSize::Unspecified,
                definition: SymbolDefinition::InSection {
                    section: 0,
                    offset: native_offset,
                },
            });
        }
        let mut effects = vec![
            RecordEffect::DefineSymbol { symbol: 1 },
            RecordEffect::DefineSymbol { symbol: 2 },
        ];
        let mut line = String::from("1: 2:");
        if options.named_collision {
            let name = format!(".L__ocore_machine_source_{definition_record}_number_1_symbol_1");
            symbols.push(UnitSymbol {
                id: 3,
                name: SymbolName::Named {
                    value: name.clone(),
                },
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                kind: SymbolKind::NoType,
                size: SymbolSize::Unspecified,
                definition: SymbolDefinition::InSection {
                    section: 0,
                    offset: native_offset,
                },
            });
            row(
                &mut text,
                &mut records,
                UnitRecordKind::Symbol,
                vec![RecordEffect::Binding {
                    symbol: 3,
                    binding: SymbolBinding::Global,
                }],
                format!(".globl {name}\n"),
            );
            effects.push(RecordEffect::DefineSymbol { symbol: 3 });
            line.push_str(&format!(" {name}:"));
            original_collision = Some(name);
        }
        line.push('\n');
        let actual = row(
            &mut text,
            &mut records,
            UnitRecordKind::Label,
            effects,
            line,
        );
        assert_eq!(actual, definition_record);
        for (id, target, name, raw) in [(4, 1, "alias_first", "1b"), (5, 2, "alias_second", "2b")] {
            symbols.push(UnitSymbol {
                id,
                name: SymbolName::Named { value: name.into() },
                binding: SymbolBinding::Local,
                visibility: SymbolVisibility::Default,
                kind: SymbolKind::NoType,
                size: SymbolSize::Unspecified,
                definition: SymbolDefinition::Alias { target, addend: 0 },
            });
            row(
                &mut text,
                &mut records,
                UnitRecordKind::Symbol,
                vec![RecordEffect::Alias {
                    symbol: id,
                    target,
                    addend: 0,
                    equ: true,
                }],
                format!(".equ {name}, {raw}\n"),
            );
        }
    }
    let assembly = text.into_bytes();
    let source = SourceWitness {
        format: SOURCE_FORMAT.into(),
        input_form: MachineInputForm::ConfiguredAssemblyText,
        unit_id: "authored-public-unit-fixture".into(),
        files: vec![SourceFile {
            id: 1,
            logical_path: "unit-fixture.S".into(),
            identity: identity(&assembly),
        }],
        decoded_assembly: identity(&assembly),
        build_configuration: identity(b"authored-test-configuration-not-source-admission"),
        frontend_event: identity(b"authored-typed-fixture-not-a-capture-event"),
    };
    let (mut body, mut inner) = fixture(ret(), 104);
    body.symbol = "f".into();
    body.source = source.clone();
    body.blocks[0].source_label = Some(label_record);
    for i in &mut body.blocks[0].instructions {
        i.source_item = ret_record;
    }
    body.blocks[0].terminator.source_item = ret_record;
    let claim = identity(b"independently-selected-inner-fixture-claim");
    body.selected_inventory = claim.clone();
    inner.identity = claim.clone();
    inner.source = source.clone();
    inner.symbol = "f".into();
    inner.items = [label_record, ret_record]
        .into_iter()
        .map(|id| {
            let r = records.iter().find(|r| r.id == id).unwrap();
            SourceItem {
                id,
                kind: if id == label_record {
                    SourceItemKind::Label
                } else {
                    SourceItemKind::Instruction
                },
                decoded_span: r.span,
                origins: r.origins.clone(),
            }
        })
        .collect();
    let profile = body.profile.clone();
    let raw_inner = serde_json::to_vec(&inner).unwrap();
    let declarations = UnitDeclarations {
        sections: vec![UnitSection {
            id: 0,
            name: ".text".into(),
            kind: options.kind,
            flags: options.flags,
            alignment: options.alignment,
            byte_size: None,
        }],
        symbols,
        initializers,
        relocations: vec![],
        alignments,
        records,
        external_obligations: vec![],
    };
    let required = SelectedUnitInventory {
        format: UNIT_INVENTORY_FORMAT.into(),
        source: source.clone(),
        profile: profile.clone(),
        required: declarations.clone(),
        bodies: vec![RequiredBody {
            id: 0,
            symbol: 0,
            inventory: identity(&raw_inner),
            machine_inventory_claim: claim,
            record_ids: vec![label_record, ret_record],
        }],
    };
    let inventory = serde_json::to_vec(&required).unwrap();
    let selection = UnitSelection {
        source: source.clone(),
        profile: profile.clone(),
        inventory: identity(&inventory),
    };
    let unit = MachineUnit {
        format: UNIT_FORMAT.into(),
        selected_inventory: identity(&inventory),
        source,
        profile,
        declarations,
        bodies: vec![UnitBody {
            id: 0,
            symbol: 0,
            contract: body,
            selected_inventory_json: raw_inner,
        }],
    };
    WholeFixture {
        unit,
        selection,
        inventory,
        assembly,
        label_record,
        ret_record,
        original_collision,
    }
}
fn checked_plan(f: &WholeFixture) -> MachineAssemblyPlan {
    let structural = verify_unit(
        &f.unit,
        &f.selection,
        &f.inventory,
        &f.assembly,
        Target::Riscv64UnknownNone,
    );
    assert!(
        structural.is_ok(),
        "positive whole-unit structural check: {structural:?}"
    );
    plan_unit(
        &f.unit,
        &f.selection,
        &f.inventory,
        &f.assembly,
        Target::Riscv64UnknownNone,
    )
    .unwrap()
}
fn reached_guard(f: &WholeFixture, text: &str) -> UnitEmissionFailure {
    let structural = verify_unit(
        &f.unit,
        &f.selection,
        &f.inventory,
        &f.assembly,
        Target::Riscv64UnknownNone,
    );
    assert!(
        structural.is_ok(),
        "mutation failed before native guard: {structural:?}"
    );
    let error = plan_unit(
        &f.unit,
        &f.selection,
        &f.inventory,
        &f.assembly,
        Target::Riscv64UnknownNone,
    )
    .unwrap_err();
    assert!(
        error.body_refusals.get(&0).unwrap().contains(text),
        "wrong guard: {error:?}"
    );
    for id in [f.label_record, f.ret_record] {
        let row = error.records.iter().find(|r| r.record == id).unwrap();
        assert!(
            !row.selected && row.refusals.iter().any(|r| r.contains(text)),
            "owning body row did not retain intended refusal: {row:?}"
        );
    }
    error
}
#[test]
fn plan_unit_accepts_complete_typed_leaf() {
    let f = whole_fixture(WholeOptions::default());
    assert_eq!(identity(&f.assembly), f.unit.source.decoded_assembly);
    let p = checked_plan(&f);
    assert_eq!(p.selected_bodies, 1);
    assert_eq!(p.selected_records, 4);
    assert!(p.assembly().contains("f:\n") && p.assembly().contains("jalr x0, x1, 0"));
    assert_eq!(p.assembly_identity, identity(p.assembly().as_bytes()));
    assert!(!p.source_or_native_admission());
}
#[test]
fn plan_unit_rejects_non_program_body_sections() {
    for kind in [SectionKind::NoBits, SectionKind::Note] {
        checked_plan(&whole_fixture(WholeOptions::default()));
        let f = whole_fixture(WholeOptions {
            kind,
            ..WholeOptions::default()
        });
        assert_eq!(f.unit.declarations.sections[0].kind, kind);
        reached_guard(&f, "executable ProgramBits");
    }
}
#[test]
fn plan_unit_rejects_non_executable_body_section() {
    checked_plan(&whole_fixture(WholeOptions::default()));
    let f = whole_fixture(WholeOptions {
        flags: b"a".to_vec(),
        ..WholeOptions::default()
    });
    assert!(!f.unit.declarations.sections[0].flags.contains(&b'x'));
    reached_guard(&f, "executable ProgramBits");
}
#[test]
fn plan_unit_rejects_section_alignment_one() {
    checked_plan(&whole_fixture(WholeOptions::default()));
    let f = whole_fixture(WholeOptions {
        alignment: 1,
        ..WholeOptions::default()
    });
    assert_eq!(f.unit.declarations.sections[0].alignment, 1);
    reached_guard(&f, "section alignment satisfying RV IALIGN=16");
}
#[test]
fn plan_unit_rejects_odd_body_offset_after_valid_skipped_alignment() {
    let good = whole_fixture(WholeOptions {
        prefix_bytes: 2,
        skip_alignment: true,
        alignment: 4,
        ..WholeOptions::default()
    });
    assert!(matches!(
        good.unit.declarations.alignments[0].layout,
        Some(AlignmentLayout::Skipped {
            offset: 2,
            required_padding: 2
        })
    ));
    checked_plan(&good);
    let bad = whole_fixture(WholeOptions {
        prefix_bytes: 1,
        skip_alignment: true,
        alignment: 4,
        ..WholeOptions::default()
    });
    assert!(
        matches!(&bad.unit.declarations.initializers[0].value,InitializerValue::Bytes{value}if value.len()==1)
    );
    assert!(matches!(
        bad.unit.declarations.alignments[0].layout,
        Some(AlignmentLayout::Skipped {
            offset: 1,
            required_padding: 3
        })
    ));
    reached_guard(&bad, "current byte offset violates RV IALIGN=16");
}
fn label_names(plan: &MachineAssemblyPlan) -> Vec<&str> {
    plan.assembly()
        .lines()
        .filter_map(|line| line.strip_suffix(':'))
        .collect()
}
#[test]
fn plan_unit_numeric_symbols_keep_distinct_alias_targets() {
    let f = whole_fixture(WholeOptions {
        numeric: true,
        ..WholeOptions::default()
    });
    let nums: Vec<_> = f
        .unit
        .declarations
        .symbols
        .iter()
        .filter_map(|s| {
            if let SymbolName::NumericLocal {
                number,
                definition_record,
            } = &s.name
            {
                Some((s.id, *number, *definition_record))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(nums.len(), 2);
    assert_ne!(nums[0].0, nums[1].0);
    assert_ne!(nums[0].1, nums[1].1);
    assert_eq!(nums[0].2, nums[1].2);
    let owned = f
        .unit
        .declarations
        .records
        .iter()
        .find(|r| r.id == nums[0].2)
        .unwrap();
    assert_eq!(
        owned
            .effects
            .iter()
            .filter(|e| matches!(e, RecordEffect::DefineSymbol { symbol: 1 | 2 }))
            .count(),
        2
    );
    let p = checked_plan(&f);
    let labels = label_names(&p);
    let first = labels
        .iter()
        .find(|n| n.contains("_number_1_symbol_1"))
        .unwrap();
    let second = labels
        .iter()
        .find(|n| n.contains("_number_2_symbol_2"))
        .unwrap();
    assert_ne!(first, second);
    assert!(p
        .assembly()
        .contains(&format!(".equ alias_first, {first}+0")));
    assert!(p
        .assembly()
        .contains(&format!(".equ alias_second, {second}+0")));
    assert_eq!(
        labels.len(),
        labels.iter().copied().collect::<BTreeSet<_>>().len()
    );
}
#[test]
fn plan_unit_original_global_name_cannot_collide_with_generated_symbols() {
    checked_plan(&whole_fixture(WholeOptions {
        numeric: true,
        ..WholeOptions::default()
    }));
    let f = whole_fixture(WholeOptions {
        numeric: true,
        named_collision: true,
        ..WholeOptions::default()
    });
    let original = f.original_collision.as_ref().unwrap();
    assert!(f
        .unit
        .declarations
        .symbols
        .iter()
        .any(|s| s.binding == SymbolBinding::Global
            && matches!(&s.name,SymbolName::Named{value}if value==original)));
    let p = checked_plan(&f);
    let labels = label_names(&p);
    assert_eq!(labels.iter().filter(|n| **n == original).count(), 1);
    assert_eq!(
        labels.len(),
        labels.iter().copied().collect::<BTreeSet<_>>().len()
    );
    let first = labels
        .iter()
        .find(|n| n.contains("_number_1_symbol_1") && **n != original)
        .unwrap();
    assert_ne!(*first, original);
    assert!(p.assembly().contains(&format!(".globl {original}\n")));
    assert!(p
        .assembly()
        .contains(&format!(".equ alias_first, {first}+0")));
}
#[test]
fn plan_unit_structural_failure_retains_every_record_as_unselected() {
    let mut f = whole_fixture(WholeOptions::default());
    checked_plan(&f);
    f.unit.format = "actual-invalid-format-mutation".into();
    assert_eq!(f.unit.format, "actual-invalid-format-mutation");
    let e = plan_unit(
        &f.unit,
        &f.selection,
        &f.inventory,
        &f.assembly,
        Target::Riscv64UnknownNone,
    )
    .unwrap_err();
    assert!(e.structural_failure.is_some());
    assert_eq!(e.records.len(), f.unit.declarations.records.len());
    assert!(e
        .records
        .iter()
        .all(|r| !r.selected && !r.refusals.is_empty()));
}

// Typed graph consistency only: these authored alternatives do not establish
// that a graph writing x10 implements the configured original ret instruction.
fn whole_output_variant(value: u64) -> WholeFixture {
    let mut f = whole_fixture(WholeOptions::default());
    let body = &mut f.unit.bodies[0].contract;
    assert!(body.interface.exits[0].outputs.contains(&reg(10)));
    assert!(!body.interface.exits[0].preserved.contains(&reg(10)));
    let block = &mut body.blocks[0];
    let mut instructions = vec![
        MachineInstruction {
            source_item: f.ret_record,
            state_in: 0,
            state_out: 1,
            result: Some(Scalar { id: 200, bits: 64 }),
            operation: MachineOperation::Constant {
                little_endian: value.to_le_bytes().to_vec(),
            },
        },
        MachineInstruction {
            source_item: f.ret_record,
            state_in: 1,
            state_out: 2,
            result: None,
            operation: MachineOperation::WriteRegister {
                view: reg(10),
                value: 200,
                mode: WriteMode::WholeStorage,
            },
        },
    ];
    for mut instruction in std::mem::take(&mut block.instructions) {
        instruction.state_in += 2;
        instruction.state_out += 2;
        instructions.push(instruction);
    }
    block.instructions = instructions;
    block.terminator.state += 2;
    f
}
#[test]
fn plan_typed_unit_identity_matches_compact_encoding() {
    let f = whole_fixture(WholeOptions::default());
    let p = checked_plan(&f);
    let buffered = serde_json::to_vec(&f.unit).unwrap();
    assert_eq!(p.typed_unit_identity().encoding, TYPED_UNIT_ENCODING);
    assert_eq!(p.typed_unit_identity().encoded_unit, identity(&buffered));
    assert!(p.check_typed_unit(&f.unit).is_ok());
    assert!(!p.source_or_native_admission());
}
#[test]
fn plan_typed_unit_identity_is_stable_for_unchanged_unit() {
    let f = whole_fixture(WholeOptions::default());
    let p = checked_plan(&f);
    let mut unchanged = whole_fixture(WholeOptions::default());
    unchanged.unit = f.unit.clone();
    let q = checked_plan(&unchanged);
    assert_eq!(p.typed_unit_identity(), q.typed_unit_identity());
    assert_eq!(p.assembly(), q.assembly());
    assert!(p.check_typed_unit(&unchanged.unit).is_ok());
    assert!(q.check_typed_unit(&f.unit).is_ok());
}
#[test]
fn plan_typed_unit_identity_binds_changed_body_with_same_floor() {
    let first = whole_output_variant(7);
    let p = checked_plan(&first);
    let mut changed = whole_output_variant(7);
    let instruction = changed.unit.bodies[0].contract.blocks[0]
        .instructions
        .iter_mut()
        .find(|i| i.result.as_ref().map(|r| r.id) == Some(200))
        .unwrap();
    assert!(
        matches!(&instruction.operation,MachineOperation::Constant{little_endian}if little_endian.as_slice()==7u64.to_le_bytes().as_slice())
    );
    instruction.operation = MachineOperation::Constant {
        little_endian: 9u64.to_le_bytes().to_vec(),
    };
    assert!(
        matches!(&instruction.operation,MachineOperation::Constant{little_endian}if little_endian.as_slice()==9u64.to_le_bytes().as_slice())
    );
    assert_eq!(first.inventory, changed.inventory);
    assert_eq!(first.assembly, changed.assembly);
    assert_eq!(
        first.unit.selected_inventory,
        changed.unit.selected_inventory
    );
    assert_eq!(
        first.unit.bodies[0].selected_inventory_json,
        changed.unit.bodies[0].selected_inventory_json
    );
    let q = checked_plan(&changed);
    assert!(p.assembly().contains("addi x10, x0, 7") && q.assembly().contains("addi x10, x0, 9"));
    assert_ne!(p.assembly(), q.assembly());
    assert_ne!(p.assembly_identity, q.assembly_identity);
    assert_ne!(p.typed_unit_identity(), q.typed_unit_identity());
    assert!(p.check_typed_unit(&first.unit).is_ok());
    assert!(q.check_typed_unit(&changed.unit).is_ok());
    assert!(p
        .check_typed_unit(&changed.unit)
        .unwrap_err()
        .contains("typed unit encoding identity differs"));
    assert!(q
        .check_typed_unit(&first.unit)
        .unwrap_err()
        .contains("typed unit encoding identity differs"));
    assert!(!p.source_or_native_admission() && !q.source_or_native_admission());
}
#[test]
fn plan_typed_unit_identity_is_distinct_from_raw_json_identity() {
    let f = whole_fixture(WholeOptions::default());
    let p = checked_plan(&f);
    let compact = serde_json::to_vec(&f.unit).unwrap();
    let pretty = serde_json::to_vec_pretty(&f.unit).unwrap();
    assert_ne!(compact, pretty);
    assert_ne!(identity(&compact), identity(&pretty));
    let parsed_compact: MachineUnit = serde_json::from_slice(&compact).unwrap();
    let parsed_pretty: MachineUnit = serde_json::from_slice(&pretty).unwrap();
    assert_eq!(parsed_compact, f.unit);
    assert_eq!(parsed_pretty, f.unit);
    assert!(p.check_typed_unit(&parsed_compact).is_ok());
    assert!(p.check_typed_unit(&parsed_pretty).is_ok());
    assert_eq!(p.typed_unit_identity().encoded_unit, identity(&compact));
    assert!(!p.source_or_native_admission());
}
