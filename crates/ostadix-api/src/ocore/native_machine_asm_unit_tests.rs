//! Authored source/body controls, not an upstream libc capture or ISA execution.
use super::*;
pub(crate) struct Fixture {
    pub raw: Vec<u8>,
    pub syntax_raw: Vec<u8>,
    pub unit_raw: Vec<u8>,
    pub body_raw: Vec<u8>,
    pub syntax: asm::ReadSelection,
    pub whole: unit::UnitSelection,
}
fn rv(index: u8) -> RegisterView {
    RegisterView {
        register: PhysicalRegister::RiscvGpr { index },
        low_bit: 0,
        bits: 64,
    }
}
pub(crate) fn fixture(body_lines: &[&str]) -> Fixture {
    let mut lines = vec![".text", ".globl f", ".type f,@function", "f:"];
    lines.extend_from_slice(body_lines);
    lines.push(".size f,.-f");
    let raw = (lines.join("\n") + "\n").into_bytes();
    let profile = MachineProfile {
        architecture: Architecture::Rv64,
        abi: MachineAbi::RiscvLp64d,
        address_bits: 64,
        byte_order: ByteOrder::Little,
        entry_stack_alignment: 16,
        entry_stack_remainder: 0,
        features: vec![StateFeature::UserRegisterBits],
        cfi: CfiPolicy::NoCfiDeclared,
    };
    let source = SourceWitness {
        format: SOURCE_FORMAT.into(),
        input_form: MachineInputForm::ConfiguredAssemblyText,
        unit_id: "synthetic-constructor-source-control".into(),
        files: vec![SourceFile {
            id: 0,
            logical_path: "authored.S".into(),
            identity: artifact(&raw),
        }],
        decoded_assembly: artifact(&raw),
        build_configuration: artifact(b"authored-rv64-lp64d"),
        frontend_event: artifact(b"authored-no-frontend-dispatch"),
    };
    let mut offset = 0u64;
    let records: Vec<_> = lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let span = SourceSpan {
                start: offset,
                end: offset + line.len() as u64,
            };
            offset = span.end + 1;
            let kind = if i == 0 {
                asm::SyntaxKind::Section
            } else if i == 1 || i == 2 || i == lines.len() - 1 {
                asm::SyntaxKind::Symbol
            } else if line.ends_with(':') {
                asm::SyntaxKind::Label
            } else if line.starts_with('.') {
                asm::SyntaxKind::Data
            } else {
                asm::SyntaxKind::Instruction
            };
            asm::RequiredRecord {
                id: i as u64,
                kind,
                span,
                origins: vec![OriginalSpan { file: 0, span }],
            }
        })
        .collect();
    let syntax_floor = asm::SyntaxInventory {
        format: asm::SYNTAX_INVENTORY_FORMAT.into(),
        source: source.clone(),
        profile: profile.clone(),
        records: records.clone(),
    };
    let syntax_raw = serde_json::to_vec(&syntax_floor).unwrap();
    let items = records[3..records.len() - 1]
        .iter()
        .map(|v| SourceItem {
            id: v.id,
            kind: item_kind(v.kind).unwrap(),
            decoded_span: v.span,
            origins: v.origins.clone(),
        })
        .collect();
    let legacy = artifact(b"authored-noncircular-body-claim");
    let body = SelectedInstructionInventory {
        format: INVENTORY_FORMAT.into(),
        identity: legacy.clone(),
        source: source.clone(),
        symbol: "f".into(),
        profile: profile.clone(),
        interface: MachineInterface {
            entry: EntryInterface {
                policy: EntryPolicy::NoImplicitFrameOrScratch,
                initialized: vec![
                    rv(10),
                    rv(1),
                    rv(2),
                    RegisterView {
                        register: PhysicalRegister::RiscvPc,
                        low_bit: 0,
                        bits: 64,
                    },
                ],
                memory: MemoryInterface::None,
            },
            exits: vec![ExitInterface {
                id: 0,
                kind: ExitKind::OrdinaryReturn,
                outputs: vec![rv(10)],
                preserved: vec![],
            }],
        },
        items,
    };
    let body_raw = serde_json::to_vec(&body).unwrap();
    let size = unit::SymbolSize::Difference {
        end: unit::SizeAnchor::CurrentLocation {
            record: (lines.len() - 1) as u64,
            section: 0,
        },
        start: unit::SizeAnchor::Symbol { symbol: 0 },
        addend: 0,
    };
    let required_records = records
        .iter()
        .map(|v| {
            let effects = match v.id {
                0 => vec![unit::RecordEffect::SelectSection { section: 0 }],
                1 => vec![unit::RecordEffect::Binding {
                    symbol: 0,
                    binding: unit::SymbolBinding::Global,
                }],
                2 => vec![unit::RecordEffect::SymbolType {
                    symbol: 0,
                    kind: unit::SymbolKind::Function,
                }],
                3 => vec![
                    unit::RecordEffect::DefineSymbol { symbol: 0 },
                    unit::RecordEffect::BodyItem { body: 0 },
                ],
                id if id == (lines.len() - 1) as u64 => {
                    vec![unit::RecordEffect::SymbolSize { symbol: 0, size }]
                }
                _ => vec![unit::RecordEffect::BodyItem { body: 0 }],
            };
            unit::UnitRecord {
                id: v.id,
                kind: unit_kind(v.kind).unwrap(),
                span: v.span,
                origins: v.origins.clone(),
                effects,
            }
        })
        .collect();
    let floor = unit::SelectedUnitInventory {
        format: unit::UNIT_INVENTORY_FORMAT.into(),
        source: source.clone(),
        profile: profile.clone(),
        required: unit::UnitDeclarations {
            sections: vec![unit::UnitSection {
                id: 0,
                name: ".text".into(),
                kind: unit::SectionKind::ProgramBits,
                flags: b"ax".to_vec(),
                alignment: 1,
                byte_size: None,
            }],
            symbols: vec![unit::UnitSymbol {
                id: 0,
                name: unit::SymbolName::Named { value: "f".into() },
                binding: unit::SymbolBinding::Global,
                visibility: unit::SymbolVisibility::Default,
                kind: unit::SymbolKind::Function,
                size,
                definition: unit::SymbolDefinition::Body {
                    section: 0,
                    body: 0,
                },
            }],
            initializers: vec![],
            relocations: vec![],
            alignments: vec![],
            records: required_records,
            external_obligations: vec![],
        },
        bodies: vec![unit::RequiredBody {
            id: 0,
            symbol: 0,
            inventory: artifact(&body_raw),
            machine_inventory_claim: legacy,
            record_ids: records[3..records.len() - 1].iter().map(|r| r.id).collect(),
        }],
    };
    let unit_raw = serde_json::to_vec(&floor).unwrap();
    Fixture {
        syntax: asm::ReadSelection {
            source: source.clone(),
            profile: profile.clone(),
            inventory: artifact(&syntax_raw),
        },
        whole: unit::UnitSelection {
            source,
            profile,
            inventory: artifact(&unit_raw),
        },
        raw,
        syntax_raw,
        unit_raw,
        body_raw,
    }
}
impl Fixture {
    fn construct(&self) -> Result<ConstructedUnit, Box<ConstructionFailure>> {
        self.with(&[BodyFloor {
            body: 0,
            inventory_json: &self.body_raw,
        }])
    }
    fn with(&self, floors: &[BodyFloor<'_>]) -> Result<ConstructedUnit, Box<ConstructionFailure>> {
        construct_configured_unit(ConstructInput {
            configured_assembly: &self.raw,
            syntax_selection: &self.syntax,
            syntax_inventory_json: &self.syntax_raw,
            unit_selection: &self.whole,
            unit_inventory_json: &self.unit_raw,
            body_floors: floors,
            target: Target::Riscv64UnknownNone,
        })
    }
}
#[test]
fn configured_source_constructs_real_register_state_ssa_without_admission() {
    let f = fixture(&["addi a0,a0,1", "ret"]);
    let built = f.construct().unwrap();
    assert_eq!(built.records.len(), 7);
    assert_eq!(built.report.checked_records, 7);
    assert!(built.records.iter().all(|r| r.represented));
    assert_eq!(built.bodies.len(), 1);
    assert!(built.bodies[0].constructed);
    assert!(built.unit.bodies[0]
        .contract
        .blocks
        .iter()
        .flat_map(|b| &b.instructions)
        .any(|i| matches!(
            i.operation,
            MachineOperation::Binary {
                kind: BinaryKind::WrappingAdd,
                ..
            }
        )));
    let report = serde_json::to_value(&built.report).unwrap();
    for name in [
        "source_custody_verified",
        "inventory_authority_verified",
        "original_unit_completeness_verified",
        "native_realization_verified",
        "provider_qualified",
        "runtime_qualified",
        "isa_equivalence_qualified",
        "ordinary_native_admission",
    ] {
        assert_eq!(
            report.get(name),
            Some(&serde_json::Value::Bool(false)),
            "{name}"
        );
    }
}
#[test]
fn configured_source_changed_instruction_refuses_original_selected_bytes() {
    let mut f = fixture(&["addi a0,a0,1", "ret"]);
    let i = f
        .raw
        .windows(12)
        .position(|v| v == b"addi a0,a0,1")
        .unwrap()
        + 11;
    f.raw[i] = b'2';
    assert_eq!(f.raw[i], b'2');
    let failure = f.construct().unwrap_err();
    assert!(
        failure
            .issues
            .iter()
            .any(|e| e.stage == "reader" && e.reason.contains("configured")),
        "{:?}",
        failure.issues
    );
}
#[test]
fn configured_source_missing_required_body_retains_all_records() {
    let f = fixture(&["addi a0,a0,1", "ret"]);
    let e = f.with(&[]).unwrap_err();
    assert_eq!(e.records.len(), 7);
    assert_eq!(e.bodies[0].id, 0);
    assert!(!e.bodies[0].constructed);
    assert!(e
        .issues
        .iter()
        .any(|i| i.body == Some(0) && i.reason == "missing required body floor"));
}
#[test]
fn configured_source_duplicate_floor_is_not_another_body_owner() {
    let f = fixture(&["addi a0,a0,1", "ret"]);
    let e = f
        .with(&[
            BodyFloor {
                body: 0,
                inventory_json: &f.body_raw,
            },
            BodyFloor {
                body: 0,
                inventory_json: &f.body_raw,
            },
        ])
        .unwrap_err();
    assert_eq!(e.records.len(), 7);
    assert!(e
        .issues
        .iter()
        .any(|i| i.body == Some(0) && i.reason == "duplicate supplied body floor"));
}
#[test]
fn configured_source_inline_data_retains_the_unsupported_record() {
    let f = fixture(&[".word 1", "ret"]);
    let e = f.construct().unwrap_err();
    assert_eq!(e.records.len(), 7);
    assert_eq!(e.records[4].kind, asm::SyntaxKind::Data);
    assert!(!e.records[4].represented);
    assert!(
        e.issues.iter().any(|i| i.record == Some(4)
            && i.reason == "inline body data has no implemented machine directive semantics"),
        "{:?}",
        e.issues
    );
}
#[test]
fn configured_source_floor_only_external_cannot_invent_source_declaration() {
    let mut f = fixture(&["addi a0,a0,1", "ret"]);
    let mut floor: unit::SelectedUnitInventory = serde_json::from_slice(&f.unit_raw).unwrap();
    floor.required.symbols.push(unit::UnitSymbol {
        id: 1,
        name: unit::SymbolName::Named {
            value: "not_in_source".into(),
        },
        binding: unit::SymbolBinding::Global,
        visibility: unit::SymbolVisibility::Default,
        kind: unit::SymbolKind::NoType,
        size: unit::SymbolSize::Unspecified,
        definition: unit::SymbolDefinition::Undefined,
    });
    floor
        .required
        .external_obligations
        .push(unit::ExternalObligation {
            symbol: 1,
            uses: vec![unit::ExternalUse::Declaration],
        });
    f.unit_raw = serde_json::to_vec(&floor).unwrap();
    f.whole.inventory = artifact(&f.unit_raw);
    assert!(!f.raw.windows(13).any(|v| v == b"not_in_source"));
    let e = f.construct().unwrap_err();
    assert_eq!(e.records.len(), 7);
    assert!(
        e.issues.iter().any(|i| i.stage == "declarations"
            && i.reason == "selected symbol has no decoded source mention"),
        "{:?}",
        e.issues
    );
}
#[test]
fn configured_source_trailing_zero_op_cannot_borrow_fallthrough_coverage() {
    let f = fixture(&["nop", "1:", "ret"]);
    let e = f.construct().unwrap_err();
    assert_eq!(e.records.len(), 8);
    let parsed = e.parsed.as_ref().unwrap();
    let p = &parsed.records[4];
    assert_eq!(
        &f.raw[p.required.span.start as usize..p.required.span.end as usize],
        b"nop"
    );
    assert!(e.issues.iter().any(|i|i.stage=="body"&&i.record==Some(4)&&i.reason=="zero-operation instruction needs an explicit inventory-preserving machine operation"),"{:?}",e.issues);
}

#[test]
fn configured_source_reachable_zero_op_cannot_hide_in_lifted_operations() {
    let f = fixture(&["nop", "addi a0,a0,1", "ret"]);
    let e = f.construct().unwrap_err();
    assert_eq!(e.records.len(), 8);
    assert_eq!(e.bodies.len(), 1);
    assert!(!e.bodies[0].constructed);
    let parsed = e.parsed.as_ref().unwrap();
    let p = &parsed.records[4];
    assert_eq!(
        &f.raw[p.required.span.start as usize..p.required.span.end as usize],
        b"nop"
    );
    assert!(!e.records[4].represented);
    assert!(
        e.issues.iter().any(|i| i.stage == "body"
            && i.record == Some(4)
            && i.reason == "zero-operation instruction needs an explicit inventory-preserving machine operation"),
        "{:?}",
        e.issues
    );
}
