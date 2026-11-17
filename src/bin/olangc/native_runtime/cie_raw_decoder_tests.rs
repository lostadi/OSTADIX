//! Authored raw-byte/source controls. These fixtures are not assembled objects,
//! producer evidence, reference execution or runtime qualification.
use super::*;

fn uleb(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 127) as u8;
        value >>= 7;
        if value != 0 { byte |= 128; }
        out.push(byte);
        if value == 0 { return out; }
    }
}
fn sleb(mut value: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        let done = value == 0 && byte & 64 == 0 || value == -1 && byte & 64 != 0;
        out.push(if done { byte } else { byte | 128 });
        if done { return out; }
    }
}
fn put16(bytes: &mut [u8], at: usize, value: u16) { bytes[at..at + 2].copy_from_slice(&value.to_le_bytes()); }
fn put32(bytes: &mut [u8], at: usize, value: u32) { bytes[at..at + 4].copy_from_slice(&value.to_le_bytes()); }
fn put64(bytes: &mut [u8], at: usize, value: u64) { bytes[at..at + 8].copy_from_slice(&value.to_le_bytes()); }
struct Fixture { bytes: Vec<u8>, frame: usize, headers: usize }
fn fixture(machine: u16, factor: i64, return_column: u8, program: &[u8], augmentation: &str, aug: &[u8]) -> Fixture {
    let mut cie = vec![0; 4]; // CIE identifier, not an FDE pointer.
    cie.push(1);
    cie.extend_from_slice(augmentation.as_bytes());
    cie.push(0);
    cie.extend(uleb(3)); // Deliberately not the owned-emitter code-alignment policy.
    cie.extend(sleb(factor));
    cie.push(return_column);
    if augmentation.starts_with('z') { cie.extend(uleb(aug.len() as u64)); cie.extend_from_slice(aug); }
    cie.extend_from_slice(program);
    while (cie.len() + 4) % 4 != 0 { cie.push(0); } // Explicit DW_CFA_nop padding.
    let mut frame = (cie.len() as u32).to_le_bytes().to_vec();
    frame.extend(cie);
    let fde_start = frame.len();
    let mut fde = ((fde_start + 4) as u32).to_le_bytes().to_vec();
    fde.extend(0i32.to_le_bytes()); // Unresolved PC-relative start, no owned-code claim.
    fde.extend(16i32.to_le_bytes());
    if augmentation.starts_with('z') { fde.push(0); }
    fde.push(0);
    while (fde.len() + 4) % 4 != 0 { fde.push(0); }
    frame.extend((fde.len() as u32).to_le_bytes());
    frame.extend(fde);
    let names = b"\0.shstrtab\0.eh_frame\0";
    let frame_at = (64 + names.len() + 7) & !7;
    let headers = (frame_at + frame.len() + 7) & !7;
    let mut bytes = vec![0; headers + 3 * 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 1); put16(&mut bytes, 18, machine); put32(&mut bytes, 20, 1);
    put64(&mut bytes, 40, headers as u64); put16(&mut bytes, 52, 64);
    put16(&mut bytes, 58, 64); put16(&mut bytes, 60, 3); put16(&mut bytes, 62, 1);
    bytes[64..64 + names.len()].copy_from_slice(names);
    bytes[frame_at..frame_at + frame.len()].copy_from_slice(&frame);
    put32(&mut bytes, headers + 64, 1); put32(&mut bytes, headers + 68, 3);
    put64(&mut bytes, headers + 88, 64); put64(&mut bytes, headers + 96, names.len() as u64);
    put64(&mut bytes, headers + 112, 1);
    put32(&mut bytes, headers + 128, 11); put32(&mut bytes, headers + 132, 1);
    put64(&mut bytes, headers + 136, 2); put64(&mut bytes, headers + 152, frame_at as u64);
    put64(&mut bytes, headers + 160, frame.len() as u64); put64(&mut bytes, headers + 176, 8);
    Fixture { bytes, frame: frame_at, headers }
}
fn simple(machine: u16, factor: i64, return_column: u8, program: &[u8]) -> Fixture {
    fixture(machine, factor, return_column, program, "zR", &[0x1b])
}
fn cie(object: &RawCieObject) -> &RawCie {
    object.sections[0].records.iter().find_map(|record| match record {
        RawRecord::Cie(cie) => Some(cie), _ => None,
    }).unwrap()
}
fn rejects_program(program: &[u8], expected: &str) {
    let f = simple(243, -8, 1, program);
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert!(cie(&raw).error.as_ref().unwrap().contains(expected), "{:?}", cie(&raw).error);
    assert!(cie(&raw).range.bytes.len() > program.len());
    assert!(decode_elf64_le_rel(&f.bytes).is_err());
}
#[test]
fn raw_initial_rules_decode_all_three_explicit_elf_register_domains() {
    for (machine, stack, return_column, factor) in [(62, 7, 16, -8), (183, 31, 30, -16), (243, 2, 1, -8)] {
        let program = [0x0c, stack, 24, 0x80 | return_column, 2];
        let f = simple(machine, factor, return_column, &program);
        let object = decode_elf64_le_rel(&f.bytes).unwrap();
        let c = cie(&object);
        let h = c.header.as_ref().unwrap();
        assert_eq!((h.code_alignment, h.data_alignment, h.return_column), (3, factor, u64::from(return_column)));
        let state = c.initial_rules.as_ref().unwrap();
        assert_eq!(state.require_cfa().unwrap(), &CfaRule { register: u64::from(stack), offset: 24 });
        assert_eq!(state.restore_rule(u64::from(return_column)).unwrap(), RegisterRule::CfaOffset(2 * factor));
        assert_eq!(c.initial_instructions.as_ref().unwrap().bytes[..program.len()], program);
        assert_eq!(object.object_sha256, hex::encode(Sha256::digest(&f.bytes)));
        assert!(!object.fde_pc_verified && !object.fde_rules_executed && !object.object_provenance_verified
            && !object.source_profile_admitted && !object.unwind_execution_verified);
    }
}
#[test]
fn signed_factored_offsets_and_cfa_updates_do_not_wrap_or_lose_sign() {
    let mut program = vec![0x12, 2]; program.extend(sleb(-2));
    program.extend([0x11, 1]); program.extend(sleb(3));
    program.extend([0x13]); program.extend(sleb(-4));
    let f = simple(243, -8, 1, &program);
    let object = decode_elf64_le_rel(&f.bytes).unwrap();
    let state = cie(&object).initial_rules.as_ref().unwrap();
    assert_eq!(state.require_cfa().unwrap().offset, 32);
    assert_eq!(state.restore_rule(1).unwrap(), RegisterRule::CfaOffset(-24));
}
#[test]
fn fde_restore_accessor_returns_exact_initial_rule_and_refuses_unspecified_defaults() {
    let f = simple(243, -8, 1, &[0x81, 2]);
    let object = decode_elf64_le_rel(&f.bytes).unwrap();
    let initial = cie(&object).initial_rules.as_ref().unwrap();
    let mut current = BTreeMap::from([(1, RegisterRule::SameValue)]);
    current.insert(1, initial.restore_rule(1).unwrap());
    assert_eq!(current[&1], RegisterRule::CfaOffset(-16));
    assert!(initial.restore_rule(2).unwrap_err().to_string().contains("unspecified"));
    assert!(initial.cfa.is_none());
    assert!(initial.require_cfa().is_err());
}
#[test]
fn only_explicit_undefined_same_value_and_register_rules_enter_the_initial_table() {
    let f = simple(243, -8, 1, &[0x07, 1, 0x08, 2, 0x09, 3, 4]);
    let object = decode_elf64_le_rel(&f.bytes).unwrap();
    let state = cie(&object).initial_rules.as_ref().unwrap();
    assert_eq!(state.restore_rule(1).unwrap(), RegisterRule::Undefined);
    assert_eq!(state.restore_rule(2).unwrap(), RegisterRule::SameValue);
    assert_eq!(state.restore_rule(3).unwrap(), RegisterRule::Register(4));
    assert!(state.restore_rule(5).is_err());
}
#[test]
fn remembered_state_restores_cfa_and_rules_without_erasing_instruction_trace() {
    let f = simple(243, -8, 1, &[0x0c, 2, 8, 0x81, 1, 0x0a, 0x0e, 32, 0x08, 1, 0x0b]);
    let object = decode_elf64_le_rel(&f.bytes).unwrap();
    let state = cie(&object).initial_rules.as_ref().unwrap();
    assert_eq!(state.require_cfa().unwrap().offset, 8);
    assert_eq!(state.restore_rule(1).unwrap(), RegisterRule::CfaOffset(-8));
    assert!(state.instructions.len() >= 6);
}
#[test]
fn cie_restore_cannot_refer_to_the_rule_it_is_currently_constructing() {
    rejects_program(&[0x81, 1, 0xc1], "no independent initial-CIE");
    rejects_program(&[0x06, 1], "no independent initial-CIE");
}
#[test]
fn remembered_state_underflow_and_open_stack_are_explicit_failures() {
    rejects_program(&[0x0b], "underflow");
    rejects_program(&[0x0a], "remains open");
}
#[test]
fn missing_cfa_dependencies_and_signed_offset_overflow_are_rejected() {
    rejects_program(&[0x0d, 2], "precedes an explicit CFA");
    rejects_program(&[0x0e, 8], "precedes an explicit CFA");
    let f = simple(243, i64::MIN, 1, &[0x81, 2]);
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert!(cie(&raw).error.as_ref().unwrap().contains("exceeds i64"));
    assert!(raw.require_initial_rules_decoded().is_err());
}
#[test]
fn unterminated_and_overflowing_leb_fields_fail_with_original_bytes_retained() {
    let mut program = vec![0x0c, 2]; program.extend([0xff; 11]);
    rejects_program(&program, "overflows u64");
    let mut f = simple(243, -8, 1, &[]);
    // The complete record is cut to a version plus unterminated augmentation string.
    put32(&mut f.bytes, f.frame, 6);
    f.bytes[f.frame + 8] = 1; f.bytes[f.frame + 9] = b'z';
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert!(raw.require_initial_rules_decoded().is_err());
}
#[test]
fn unsupported_expression_location_and_architecture_extensions_do_not_become_nops() {
    for opcode in [0x01, 0x02, 0x40, 0x0f, 0x10, 0x16, 0x2d, 0x2e] {
        rejects_program(&[opcode], "unsupported CIE initial opcode");
    }
}
#[test]
fn register_domains_reject_unknown_columns_without_inventing_32bit_support() {
    for (machine, return_column, unsupported) in [(62, 16, 33), (183, 30, 32), (243, 1, 64)] {
        let f = simple(machine, -8, return_column, &[0x0c, unsupported, 0]);
        let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
        assert!(cie(&raw).error.as_ref().unwrap().contains("unsupported DWARF register"));
    }
    let mut f = simple(243, -8, 1, &[0x0c, 2, 0]);
    f.bytes[4] = 1;
    assert!(inspect_elf64_le_rel(&f.bytes).is_err());
    f.bytes[4] = 2; put16(&mut f.bytes, 18, 40);
    assert!(inspect_elf64_le_rel(&f.bytes).is_err());
}
#[test]
fn augmentation_and_pointer_encodings_remain_raw_without_personality_policy_defaults() {
    let mut augmentation = vec![0x1b, 0]; augmentation.extend([0; 8]);
    let f = fixture(243, -7, 1, &[0x0c, 2, 0], "zRP", &augmentation);
    let object = decode_elf64_le_rel(&f.bytes).unwrap();
    let c = cie(&object);
    assert_eq!(c.augmentation_data.as_ref().unwrap().bytes, augmentation);
    assert_eq!(c.personality.as_ref().unwrap().encoding, 0);
    assert!(c.personality.as_ref().unwrap().resolved_address.is_none());
    assert_eq!(c.header.as_ref().unwrap().data_alignment, -7);
    let f = fixture(243, -8, 1, &[0x0c, 2, 0], "zRX", &[0x1b, 0xaa]);
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(cie(&raw).augmentation_data.as_ref().unwrap().bytes, [0x1b, 0xaa]);
    assert!(cie(&raw).error.as_ref().unwrap().contains("unsupported raw CIE augmentation"));
    assert!(raw.require_initial_rules_decoded().is_err());
}
#[test]
fn fde_range_format_is_signed_and_missing_or_unsupported_encodings_fail_closed() {
    let f = simple(243, -8, 1, &[0x0c, 2, 0]);
    let object = decode_elf64_le_rel(&f.bytes).unwrap();
    let fde = object.sections[0].records.iter().find_map(|r| match r { RawRecord::Fde(f) => Some(f), _ => None }).unwrap();
    assert_eq!(fde.initial_location.as_ref().unwrap().application, 0x10);
    assert_eq!(fde.address_range.as_ref().unwrap().encoding, 0x0b);
    assert!(fde.instructions.as_ref().unwrap().bytes.iter().all(|b| *b == 0));
    let f = fixture(243, -8, 1, &[0x0c, 2, 0], "", &[]);
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert!(raw.require_initial_rules_decoded().unwrap_err().to_string().contains("encoding absent"));
    let f = fixture(243, -8, 1, &[0x0c, 2, 0], "zR", &[0x50]);
    assert!(decode_elf64_le_rel(&f.bytes).is_err());
}
#[test]
fn record_bounds_dwarf64_and_section_truncation_do_not_panic_or_pass_zero_cases() {
    let mut f = simple(243, -8, 1, &[0x0c, 2, 0]);
    put32(&mut f.bytes, f.frame, u32::MAX);
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert!(matches!(&raw.sections[0].records[0], RawRecord::Rejected { error, .. } if error.contains("DWARF64")));
    assert!(raw.require_initial_rules_decoded().is_err());
    put32(&mut f.bytes, f.frame, 0x7fff_ffff);
    assert!(inspect_elf64_le_rel(&f.bytes).unwrap().require_initial_rules_decoded().is_err());
    f.bytes.truncate(63);
    assert!(inspect_elf64_le_rel(&f.bytes).is_err());
}
fn with_relocation(mut f: Fixture, offset: u64, kind: u32) -> Fixture {
    let old_headers = f.bytes[f.headers..f.headers + 192].to_vec();
    let symbol_at = (f.bytes.len() + 7) & !7;
    let rela_at = symbol_at + 24;
    let headers = rela_at + 24;
    f.bytes.resize(headers + 320, 0);
    f.bytes[headers..headers + 192].copy_from_slice(&old_headers);
    put64(&mut f.bytes, 40, headers as u64); put16(&mut f.bytes, 60, 5);
    put32(&mut f.bytes, headers + 196, 2); put64(&mut f.bytes, headers + 216, symbol_at as u64);
    put64(&mut f.bytes, headers + 224, 24); put64(&mut f.bytes, headers + 240, 8);
    put64(&mut f.bytes, headers + 248, 24);
    put32(&mut f.bytes, headers + 260, 4); put64(&mut f.bytes, headers + 280, rela_at as u64);
    put64(&mut f.bytes, headers + 288, 24); put32(&mut f.bytes, headers + 296, 3);
    put32(&mut f.bytes, headers + 300, 2); put64(&mut f.bytes, headers + 304, 8);
    put64(&mut f.bytes, headers + 312, 24);
    put64(&mut f.bytes, rela_at, offset); put64(&mut f.bytes, rela_at + 8, u64::from(kind));
    f.headers = headers;
    f
}
#[test]
fn relocation_overlapping_initial_rules_is_retained_and_blocks_a_decoded_baseline() {
    let f = simple(243, -8, 1, &[0x0c, 2, 0]);
    let initial = cie(&inspect_elf64_le_rel(&f.bytes).unwrap()).initial_instructions.as_ref().unwrap().section_offset;
    let f = with_relocation(f, initial as u64, 57);
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(raw.sections[0].relocations.len(), 1);
    assert_eq!(raw.sections[0].relocations[0].kind, 57);
    assert_eq!(raw.sections[0].relocations[0].raw.len(), 24);
    assert!(cie(&raw).error.as_ref().unwrap().contains("overlaps CIE header/initial rules"));
    assert!(cie(&raw).initial_rules.is_none());
    assert!(raw.require_initial_rules_decoded().is_err());
}
#[test]
fn raw_section_header_object_offsets_and_unresolved_fde_bytes_are_preserved() {
    let f = simple(243, -8, 1, &[0x0c, 2, 0]);
    let raw = decode_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(raw.sections[0].header_bytes, f.bytes[f.headers + 128..f.headers + 192]);
    let c = cie(&raw);
    assert_eq!(c.range.object_offset, f.frame as u64);
    assert_eq!(c.range.bytes, f.bytes[f.frame..f.frame + c.range.bytes.len()]);
    let encoded = serde_json::to_value(&raw).unwrap();
    for key in ["fde_pc_verified", "fde_rules_executed", "object_provenance_verified",
        "source_profile_admitted", "unwind_execution_verified"] {
        assert_eq!(encoded[key], false);
    }
}

#[test]
fn augmentation_lengths_cannot_borrow_bytes_from_the_next_record() {
    let mut f = simple(243, -8, 1, &[0x0c, 2, 0]);
    f.bytes[f.frame + 15] = 10;
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert!(cie(&raw).error.as_ref().unwrap().contains("CIE augmentation exceeds its record"));
    assert!(cie(&raw).augmentation_data.is_none());
    assert!(raw.require_initial_rules_decoded().is_err());
    let mut f = simple(243, -8, 1, &[0x0c, 2, 0]);
    let cie_length = u32::from_le_bytes(f.bytes[f.frame..f.frame + 4].try_into().unwrap()) as usize + 4;
    f.bytes[f.frame + cie_length + 16] = 8;
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    let fde = raw.sections[0].records.iter().find_map(|r| match r { RawRecord::Fde(f) => Some(f), _ => None }).unwrap();
    assert!(fde.error.as_ref().unwrap().contains("FDE augmentation exceeds its record"));
    assert!(fde.augmentation_data.is_none());
    assert!(raw.require_initial_rules_decoded().is_err());
}
#[test]
fn cie_version_three_is_explicit_and_unimplemented_versions_keep_the_raw_record() {
    let mut f = simple(243, -8, 1, &[0x0c, 2, 0]);
    f.bytes[f.frame + 8] = 3;
    assert_eq!(cie(&decode_elf64_le_rel(&f.bytes).unwrap()).header.as_ref().unwrap().version, 3);
    f.bytes[f.frame + 8] = 4;
    let raw = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert!(cie(&raw).error.as_ref().unwrap().contains("unsupported raw CIE version 4"));
    assert_eq!(cie(&raw).range.bytes[8], 4);
    assert!(raw.require_initial_rules_decoded().is_err());
}

// Additive source-only oracles: both production rejection branches below are real.
// These fixtures do not qualify object provenance, FDE-PC mapping or unwind execution.
#[test]
fn truncated_signed_leb_reaches_sleb_at_the_cie_program_boundary() {
    // Total CIE length is already aligned: the three program bytes have no nop padding.
    let mut f = simple(243, -8, 1, &[0x11, 1, 0x7f]);
    let original = f.bytes.clone();
    let baseline = decode_elf64_le_rel(&original).unwrap();
    let initial = cie(&baseline).initial_instructions.as_ref().unwrap().clone();
    assert_eq!(initial.bytes, [0x11, 1, 0x7f]);
    assert_eq!(initial.section_offset + initial.bytes.len(), cie(&baseline).range.bytes.len());
    assert_eq!(cie(&baseline).initial_rules.as_ref().unwrap().restore_rule(1).unwrap(),
        RegisterRule::CfaOffset(8));
    let operand_at = usize::try_from(initial.object_offset).unwrap() + 2;
    assert_eq!(original[operand_at], 0x7f);
    f.bytes[operand_at] = 0xff; // Signed offset now requires a byte outside this CIE program.
    let changed: Vec<_> = original.iter().zip(&f.bytes).enumerate()
        .filter_map(|(at, (before, after))| (before != after).then_some(at)).collect();
    assert_eq!(changed, [operand_at]);
    let diagnostic = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(diagnostic.object_sha256, hex::encode(Sha256::digest(&f.bytes)));
    assert_ne!(diagnostic.object_sha256, baseline.object_sha256);
    let c = cie(&diagnostic);
    assert_eq!(c.header.as_ref().unwrap().data_alignment, -8);
    assert_eq!(c.augmentation_data.as_ref().unwrap().bytes, [0x1b]);
    let consumed = c.initial_instructions.as_ref().unwrap();
    assert_eq!(consumed.bytes, [0x11, 1, 0xff]);
    assert_eq!(consumed.object_offset, initial.object_offset);
    assert_eq!(consumed.section_offset + consumed.bytes.len(), c.range.bytes.len());
    // Replay only this operand reader to witness the actual signed-reader boundary.
    // The ULEB register succeeds before sleb consumes 0xff and requests the missing byte.
    let mut operands = Reader::new(&consumed.bytes, 1, consumed.bytes.len()).unwrap();
    assert_eq!(read_register(&mut operands, 243).unwrap(), 1);
    assert_eq!(operands.cursor, 2);
    assert_eq!(operands.sleb().unwrap_err().to_string(), "truncated ELF exception table");
    assert_eq!(operands.cursor, consumed.bytes.len());
    assert_eq!(operands.end, consumed.bytes.len());
    assert!(c.initial_rules.is_none());
    assert_eq!(c.error.as_deref(), Some("truncated ELF exception table"));
    let expected = "raw CIE rejected: truncated ELF exception table";
    assert_eq!(diagnostic.require_initial_rules_decoded().unwrap_err().to_string(), expected);
    assert_eq!(decode_elf64_le_rel(&f.bytes).unwrap_err().to_string(), expected);
}

#[test]
fn negative_fde_range_reaches_signed_geometry_rejection_before_rule_admission() {
    let mut f = simple(243, -8, 1, &[0x0c, 2, 0]);
    let original = f.bytes.clone();
    let baseline = decode_elf64_le_rel(&original).unwrap();
    let before = baseline.sections[0].records.iter().find_map(|record| match record {
        RawRecord::Fde(fde) => Some(fde), _ => None,
    }).unwrap();
    let range = before.address_range.as_ref().unwrap();
    assert_eq!((range.encoding, range.application), (0x0b, 0));
    assert!(matches!(&range.value, EncodedValue::Signed(16)));
    assert_eq!(range.range.bytes, 16i32.to_le_bytes());
    let range_at = usize::try_from(range.range.object_offset).unwrap();
    assert_eq!(original[range_at..range_at + 4], 16i32.to_le_bytes());
    f.bytes[range_at..range_at + 4].copy_from_slice(&(-1i32).to_le_bytes());
    let changed: Vec<_> = original.iter().zip(&f.bytes).enumerate()
        .filter_map(|(at, (old, new))| (old != new).then_some(at)).collect();
    assert_eq!(changed, (range_at..range_at + 4).collect::<Vec<_>>());
    let diagnostic = inspect_elf64_le_rel(&f.bytes).unwrap();
    assert_eq!(diagnostic.object_sha256, hex::encode(Sha256::digest(&f.bytes)));
    assert_ne!(diagnostic.object_sha256, baseline.object_sha256);
    assert_eq!(diagnostic.sections[0].records.len(), baseline.sections[0].records.len());
    assert!(cie(&diagnostic).error.is_none());
    assert!(cie(&diagnostic).initial_rules.is_some());
    let after = diagnostic.sections[0].records.iter().find_map(|record| match record {
        RawRecord::Fde(fde) => Some(fde), _ => None,
    }).unwrap();
    assert_eq!(after.cie_section_offset, before.cie_section_offset);
    let pc = after.initial_location.as_ref().unwrap();
    assert_eq!((pc.encoding, pc.application), (0x1b, 0x10));
    assert!(matches!(&pc.value, EncodedValue::Signed(0)));
    assert_eq!(pc.range.bytes, before.initial_location.as_ref().unwrap().range.bytes);
    let within_record = range_at - usize::try_from(after.range.object_offset).unwrap();
    assert_eq!(after.range.bytes[within_record..within_record + 4], (-1i32).to_le_bytes());
    assert_eq!(after.error.as_deref(), Some("negative raw FDE address range"));
    assert!(after.address_range.is_none());
    assert!(after.instructions.is_none());
    let expected = "raw FDE geometry rejected: negative raw FDE address range";
    assert_eq!(diagnostic.require_initial_rules_decoded().unwrap_err().to_string(), expected);
    assert_eq!(decode_elf64_le_rel(&f.bytes).unwrap_err().to_string(), expected);
}
