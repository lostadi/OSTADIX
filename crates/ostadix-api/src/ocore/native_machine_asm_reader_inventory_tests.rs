use super::*;
use crate::ocore::native_machine_asm_reader::{Syntax, SyntaxKind};
use crate::ocore::native_machine_ir::{
    Architecture, ByteOrder, CfiPolicy, MachineAbi, MachineInputForm, SourceFile, StateFeature,
    SOURCE_FORMAT,
};

// Source-selection DATA fixtures, not original frontend/runtime qualification.
fn claims(bytes: &[u8], architecture: Architecture) -> (SourceWitness, MachineProfile, Target) {
    let (abi, target) = match architecture {
        Architecture::X86_64 => (MachineAbi::SysvAmd64, Target::X86_64UnknownNone),
        Architecture::Aarch64 => (MachineAbi::Aapcs64, Target::Aarch64UnknownNone),
        Architecture::Rv64 => (MachineAbi::RiscvLp64d, Target::Riscv64UnknownNone),
        _ => panic!("fixture has only the existing 64-bit target profiles"),
    };
    (
        SourceWitness {
            format: SOURCE_FORMAT.into(),
            input_form: MachineInputForm::ConfiguredAssemblyText,
            unit_id: "held-original-configured-source".into(),
            files: vec![SourceFile {
                id: 7,
                logical_path: "original/input.s".into(),
                identity: identity(bytes),
            }],
            decoded_assembly: identity(bytes),
            build_configuration: identity(b"selected-build-configuration"),
            frontend_event: identity(b"selected-original-event-not-an-execution-proof"),
        },
        MachineProfile {
            architecture,
            abi,
            address_bits: 64,
            byte_order: ByteOrder::Little,
            entry_stack_alignment: 16,
            entry_stack_remainder: 0,
            features: vec![StateFeature::UserRegisterBits],
            cfi: CfiPolicy::NoCfiDeclared,
        },
        target,
    )
}

fn floor(bytes: &[u8]) -> SelectedSyntaxFloor {
    let (source, profile, target) = claims(bytes, Architecture::X86_64);
    select_identity_mapped_source(bytes, bytes, 7, &source, &profile, target).unwrap()
}

#[test]
fn selected_syntax_factory_uses_actual_reader_on_all_existing_targets() {
    for architecture in [Architecture::X86_64, Architecture::Aarch64, Architecture::Rv64] {
        let bytes = b".text\nentry: ret\n";
        let (source, profile, target) = claims(bytes, architecture);
        let held = select_identity_mapped_source(bytes, bytes, 7, &source, &profile, target).unwrap();
        let parsed = held.read(target).unwrap();
        assert_eq!(parsed.original, bytes);
        assert_eq!(parsed.records.len(), 3);
        assert!(parsed.syntax_supported);
        assert_eq!(held.identity_origin_file(), 7);
        assert_eq!(parsed.selected_inventory, held.selection().inventory);
        assert!(!parsed.original_source_authenticated);
        assert!(!parsed.selected_floor_authority_authenticated);
        assert!(!parsed.original_unit_completeness_qualified);
        assert!(!parsed.instruction_semantics_lifted);
        assert!(!parsed.machine_body_admitted);
        assert!(!parsed.provider_qualified);
        assert!(!parsed.native_qualified);
        assert!(!parsed.runtime_qualified);
        assert!(!parsed.isa_equivalence_qualified);
    }
}

#[test]
fn selected_syntax_factory_retains_unsupported_include_incbin_macro_and_conditionals() {
    let bytes = b".text\nentry: ret\n.include \"missing.inc\"\n.incbin \"missing.bin\"\n.macro body\n.endm\n.if 1\n.endif\n";
    let held = floor(bytes);
    let parsed = held.read(Target::X86_64UnknownNone).unwrap();
    let inventory: SyntaxInventory = serde_json::from_slice(held.inventory_json()).unwrap();
    assert_eq!(inventory.records.len(), 9);
    assert_eq!(parsed.records.len(), inventory.records.len());
    assert!(!parsed.syntax_supported);
    assert!(parsed.problems.len() >= 6);
    assert!(parsed.records.iter().filter(|r| r.syntax == Syntax::Unsupported).count() >= 6);
    assert_eq!(inventory.records.iter().map(|r| r.id).collect::<Vec<_>>(), (0..9).collect::<Vec<_>>());
    for record in inventory.records {
        assert_eq!(record.origins, vec![OriginalSpan { file: 7, span: record.span }]);
    }
}

#[test]
fn selected_syntax_factory_preserves_complete_byte_coverage_and_inline_labels() {
    let bytes = b"/*original*/\nentry: movq %rax,%rbx; .ascii \"a;#b\" # tail\n";
    let held = floor(bytes);
    let parsed = held.read(Target::X86_64UnknownNone).unwrap();
    assert_eq!(parsed.records.len(), 3);
    assert!(parsed.syntax_supported);
    let mut end = 0;
    for coverage in parsed.coverage {
        let span = match coverage {
            super::super::Coverage::Trivia(span) | super::super::Coverage::Record { span, .. } => span,
        };
        assert_eq!(span.start, end);
        end = span.end;
    }
    assert_eq!(end, bytes.len() as u64);
    assert_eq!(held.configured_assembly(), bytes);
}

#[test]
fn selected_syntax_factory_held_floor_rejects_actual_changed_omitted_and_reordered_records() {
    let bytes = b".text\nentry:\nret\n";
    let held = floor(bytes);
    let selected_identity = held.selection().inventory.clone();
    for changed in [b".text\nentry:\nnop\n".as_slice(), b"entry:\nret\n", b".text\nret\nentry:\n"] {
        assert_ne!(changed, bytes);
        assert_ne!(identity(changed), held.selection().source.decoded_assembly);
        assert!(matches!(held.read_configured(changed, Target::X86_64UnknownNone),
            Err(ReadError::Identity(reason)) if reason.contains("configured input")));
    }
    assert_eq!(held.selection().inventory, selected_identity);
    assert!(held.read(Target::X86_64UnknownNone).unwrap().syntax_supported);
}

#[test]
fn selected_syntax_factory_original_floor_refuses_modified_inventory_bytes() {
    let held = floor(b".text\nentry:\nret\n");
    for change in 0..3 {
        let mut inventory: SyntaxInventory = serde_json::from_slice(held.inventory_json()).unwrap();
        match change {
            0 => { assert_eq!(inventory.records.remove(1).kind, SyntaxKind::Label); }
            1 => { inventory.records.swap(1, 2); assert_eq!(inventory.records[1].kind, SyntaxKind::Instruction); }
            _ => { inventory.records[2].kind = SyntaxKind::Label; assert_eq!(inventory.records[2].kind, SyntaxKind::Label); }
        }
        let mutated = serde_json::to_vec(&inventory).unwrap();
        assert_ne!(identity(&mutated), held.selection().inventory);
        assert!(matches!(read_configured_assembly(held.configured_assembly(), held.selection(), &mutated, Target::X86_64UnknownNone),
            Err(ReadError::Identity(reason)) if reason.contains("inventory bytes")));
        // Exercise the real reader's deeper count/span/kind guard too. This
        // intentionally edited selection is not produced by the factory.
        let mut edited_selection = held.selection().clone();
        edited_selection.inventory = identity(&mutated);
        assert!(matches!(read_configured_assembly(held.configured_assembly(), &edited_selection, &mutated, Target::X86_64UnknownNone),
            Err(ReadError::Inventory(_))));
    }
}

#[test]
fn selected_syntax_factory_checks_both_original_and_configured_byte_claims() {
    let bytes = b"ret\n";
    let (mut source, profile, target) = claims(bytes, Architecture::X86_64);
    assert!(matches!(select_identity_mapped_source(bytes, b"nop\n", 7, &source, &profile, target),
        Err(ReadError::Identity(reason)) if reason.contains("original file")));
    source.decoded_assembly = identity(b"nop\n");
    assert!(matches!(select_identity_mapped_source(bytes, bytes, 7, &source, &profile, target),
        Err(ReadError::Identity(reason)) if reason.contains("configured bytes")));
}

#[test]
fn selected_syntax_factory_does_not_forge_expanded_s_origins_from_cpp_markers() {
    let original = b"#define RETURN ret\nRETURN\n";
    let configured = b"# 1 \"input.S\"\nret\n";
    let (mut source, profile, target) = claims(original, Architecture::X86_64);
    source.files[0].logical_path = "original/input.S".into();
    source.decoded_assembly = identity(configured);
    assert_ne!(original.as_slice(), configured.as_slice());
    assert!(matches!(select_identity_mapped_source(configured, original, 7, &source, &profile, target),
        Err(ReadError::Inventory(reason)) if reason.contains("expansion mapping")));
    // A suffix alone does not invalidate a genuine byte-identity origin.
    source.decoded_assembly = identity(original);
    let held = select_identity_mapped_source(original, original, 7, &source, &profile, target).unwrap();
    let parsed = held.read(target).unwrap();
    assert_eq!(parsed.records.len(), 2);
    assert!(!parsed.syntax_supported);
    assert!(!parsed.original_source_authenticated);
}

#[test]
fn selected_syntax_factory_validates_versions_selected_file_and_profile() {
    let bytes = b"ret\n";
    let (source, profile, target) = claims(bytes, Architecture::X86_64);
    assert!(matches!(select_identity_mapped_source(bytes, bytes, 99, &source, &profile, target), Err(ReadError::Inventory(_))));
    for change in 0..5 {
        let mut source = source.clone();
        match change {
            0 => source.format = "unsupported-source-format".into(),
            1 => source.frontend_event.sha256 = "not-a-pin".into(),
            2 => source.build_configuration.sha256 = "not-a-pin".into(),
            3 => source.files.push(source.files[0].clone()),
            _ => source.files[0].logical_path = "../outside.s".into(),
        }
        assert!(select_identity_mapped_source(bytes, bytes, 7, &source, &profile, target).is_err());
    }
    assert!(matches!(select_identity_mapped_source(bytes, bytes, 7, &source, &profile, Target::Aarch64UnknownNone), Err(ReadError::Profile(_))));
}

#[test]
fn selected_syntax_factory_lexical_failure_never_yields_a_partial_floor() {
    for bytes in [b"ret /* truncated".as_slice(), b".ascii \"tail\n", b"movq (%rax,%rbx\n", b"ret\0\n", b"\xff"] {
        let (source, profile, target) = claims(bytes, Architecture::X86_64);
        assert!(matches!(select_identity_mapped_source(bytes, bytes, 7, &source, &profile, target), Err(ReadError::Lexical { .. })));
    }
    let bytes = b"/* trivia only */\n";
    let (source, profile, target) = claims(bytes, Architecture::X86_64);
    assert!(matches!(select_identity_mapped_source(bytes, bytes, 7, &source, &profile, target),
        Err(ReadError::Inventory(reason)) if reason.contains("empty")));
}
