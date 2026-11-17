//! Authored source-only artifact controls; no original capture or ISA execution.
use super::*;
use super::super::native_machine_asm_unit::tests::{fixture, Fixture};
use super::super::native_machine_ir::{BinaryKind, MachineOperation};

fn encode(f: &Fixture) -> Vec<u8> {
    encode_configured_unit(ConstructInput {
        configured_assembly: &f.raw,
        syntax_selection: &f.syntax,
        syntax_inventory_json: &f.syntax_raw,
        unit_selection: &f.whole,
        unit_inventory_json: &f.unit_raw,
        body_floors: &[BodyFloor { body: 0, inventory_json: &f.body_raw }],
        target: Target::Riscv64UnknownNone,
    }).unwrap()
}
fn read_with(f: &Fixture, raw: &[u8], target: Target) -> Result<ConstructedUnit, ArtifactError> {
    readmit_configured_unit(raw, RequiredFloors {
        syntax_selection: &f.syntax,
        syntax_inventory_json: &f.syntax_raw,
        unit_selection: &f.whole,
        unit_inventory_json: &f.unit_raw,
        body_floors: &[BodyFloor { body: 0, inventory_json: &f.body_raw }],
    }, target)
}
fn write(envelope: &Envelope) -> Vec<u8> {
    serde_json::to_vec(envelope).unwrap()
}
fn decoded(raw: &[u8]) -> Envelope {
    serde_json::from_slice(raw).unwrap()
}
fn baseline() -> (Fixture, Vec<u8>) {
    let f = fixture(&["addi a0,a0,1", "ret"]);
    let raw = encode(&f);
    let reconstructed = read_with(&f, &raw, Target::Riscv64UnknownNone).unwrap();
    assert_eq!(reconstructed.report.checked_records, 7);
    assert_eq!(reconstructed.report.checked_bodies, 1);
    (f, raw)
}
fn refused(error: ArtifactError, expected: &'static str) {
    match error {
        ArtifactError::Envelope(reason) => assert_eq!(reason, expected),
        other => panic!("expected envelope rejection {expected:?}, received {other:?}"),
    }
}
#[test]
fn configured_artifact_round_trip_reconstructs_real_lift_and_preserves_closed_authority() {
    let (f, raw) = baseline();
    assert_eq!(raw, encode(&f));
    let envelope = decoded(&raw);
    assert_eq!(envelope.format, FORMAT);
    assert_eq!(envelope.configured_assembly.bytes, f.raw);
    assert_eq!(envelope.syntax_inventory.identity, f.syntax.inventory);
    assert_eq!(envelope.unit_inventory.identity, f.whole.inventory);
    assert_eq!(envelope.body_inventories[0].body, 0);
    let reconstructed = read_with(&f, &raw, Target::Riscv64UnknownNone).unwrap();
    assert_eq!(envelope.typed_unit.bytes, serde_json::to_vec(&reconstructed.unit).unwrap());
    assert!(reconstructed.records.iter().all(|record| record.represented));
    assert!(reconstructed.unit.bodies[0].contract.blocks.iter().flat_map(|block| &block.instructions)
        .any(|instruction| matches!(instruction.operation, MachineOperation::Binary { kind: BinaryKind::WrappingAdd, .. })));
    let report = serde_json::to_value(&reconstructed.report).unwrap();
    for flag in ["source_custody_verified", "inventory_authority_verified", "original_unit_completeness_verified",
        "native_realization_verified", "provider_qualified", "runtime_qualified", "isa_equivalence_qualified", "ordinary_native_admission"] {
        assert_eq!(report[flag], false, "{flag}");
    }
}
#[test]
fn changed_source_with_recomputed_payload_hash_reaches_original_reader_guard() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    let old = envelope.configured_assembly.bytes.clone();
    let instruction = b"addi a0,a0,1";
    let at = old.windows(instruction.len()).position(|part| part == instruction).unwrap() + instruction.len() - 1;
    assert_eq!(old[at], b'1');
    envelope.configured_assembly.bytes[at] = b'2';
    envelope.configured_assembly = Blob::new(&envelope.configured_assembly.bytes);
    assert_eq!(envelope.configured_assembly.bytes[at], b'2');
    assert_eq!(old.iter().zip(&envelope.configured_assembly.bytes).filter(|(a,b)| a != b).count(), 1);
    let error = read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err();
    match error {
        ArtifactError::Construction(failure) => assert!(failure.issues.iter().any(|issue| issue.stage == "reader" && issue.reason.contains("configured"))),
        other => panic!("expected real reader guard, received {other:?}"),
    }
}
#[test]
fn changed_syntax_inventory_cannot_select_its_own_floor() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    let mut floor: super::super::native_machine_asm_reader::SyntaxInventory = serde_json::from_slice(&envelope.syntax_inventory.bytes).unwrap();
    assert_eq!(floor.records.len(), 7);
    floor.records.pop().unwrap();
    envelope.syntax_inventory = Blob::new(&serde_json::to_vec(&floor).unwrap());
    assert_ne!(envelope.syntax_inventory.identity, f.syntax.inventory);
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "syntax inventory differs from independent required floor");
}
#[test]
fn changed_unit_inventory_cannot_drop_a_required_body() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    let mut floor: super::super::native_machine_unit::SelectedUnitInventory = serde_json::from_slice(&envelope.unit_inventory.bytes).unwrap();
    assert_eq!(floor.bodies.len(), 1);
    floor.bodies.clear();
    envelope.unit_inventory = Blob::new(&serde_json::to_vec(&floor).unwrap());
    assert_ne!(envelope.unit_inventory.identity, f.whole.inventory);
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "unit inventory differs from independent required floor");
}
#[test]
fn forged_typed_unit_with_valid_own_hash_is_rejected_after_real_reconstruction() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    let mut typed: super::super::native_machine_unit::MachineUnit = serde_json::from_slice(&envelope.typed_unit.bytes).unwrap();
    assert_eq!(serde_json::to_vec(&typed).unwrap(), envelope.typed_unit.bytes);
    assert_eq!(typed.bodies[0].symbol, 0);
    typed.bodies[0].symbol = 99;
    envelope.typed_unit = Blob::new(&serde_json::to_vec(&typed).unwrap());
    envelope.typed_unit.check("fixture own hash must be valid").unwrap();
    assert_eq!(typed.bodies[0].symbol, 99);
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "typed unit differs from reconstructed source");
}
#[test]
fn changed_body_inventory_is_not_accepted_as_the_independent_floor() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    envelope.body_inventories[0].inventory.bytes.push(b' ');
    envelope.body_inventories[0].inventory = Blob::new(&envelope.body_inventories[0].inventory.bytes);
    assert_ne!(envelope.body_inventories[0].inventory.bytes, f.body_raw);
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "body inventory differs from independent required floor");
}
#[test]
fn changed_independent_body_floor_is_not_replaced_by_artifact_data() {
    let (f, raw) = baseline();
    let mut required_body = f.body_raw.clone();
    required_body.push(b' ');
    let error = readmit_configured_unit(&raw, RequiredFloors {
        syntax_selection: &f.syntax, syntax_inventory_json: &f.syntax_raw,
        unit_selection: &f.whole, unit_inventory_json: &f.unit_raw,
        body_floors: &[BodyFloor { body: 0, inventory_json: &required_body }],
    }, Target::Riscv64UnknownNone).unwrap_err();
    refused(error, "body inventory differs from independent required floor");
}
#[test]
fn missing_independent_body_floor_is_not_filled_from_the_artifact() {
    let (f, raw) = baseline();
    let error = readmit_configured_unit(&raw, RequiredFloors {
        syntax_selection: &f.syntax, syntax_inventory_json: &f.syntax_raw,
        unit_selection: &f.whole, unit_inventory_json: &f.unit_raw,
        body_floors: &[],
    }, Target::Riscv64UnknownNone).unwrap_err();
    refused(error, "body inventory scope differs from independent required floors");
}
#[test]
fn duplicate_independent_body_floor_is_rejected_before_selection_can_collapse() {
    let (f, raw) = baseline();
    let error = readmit_configured_unit(&raw, RequiredFloors {
        syntax_selection: &f.syntax, syntax_inventory_json: &f.syntax_raw,
        unit_selection: &f.whole, unit_inventory_json: &f.unit_raw,
        body_floors: &[BodyFloor { body: 0, inventory_json: &f.body_raw }, BodyFloor { body: 0, inventory_json: &f.body_raw }],
    }, Target::Riscv64UnknownNone).unwrap_err();
    refused(error, "duplicate independent required body floor");
}
#[test]
fn packaged_body_scope_cannot_replace_the_selected_body_id() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    assert_eq!(envelope.body_inventories[0].body, 0);
    envelope.body_inventories[0].body = 1;
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "body inventory scope differs from independent required floors");
}
#[test]
fn wrong_target_reaches_real_profile_guard_instead_of_retargeting_source() {
    let (f, raw) = baseline();
    let other = Target::from_architecture("x86_64").unwrap();
    assert_ne!(other, Target::Riscv64UnknownNone);
    match read_with(&f, &raw, other).unwrap_err() {
        ArtifactError::Construction(failure) => assert!(failure.issues.iter().any(|issue| issue.stage == "reader" && issue.reason.starts_with("Profile("))),
        other => panic!("expected real target/profile guard, received {other:?}"),
    }
}
#[test]
fn changed_profile_header_is_not_an_independent_profile_selection() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    envelope.profile.entry_stack_remainder = 1;
    assert_ne!(envelope.profile, f.syntax.profile);
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "profile differs from independent selection");
}
#[test]
fn unknown_artifact_version_is_rejected() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    envelope.format.push_str("-unknown");
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "unsupported configured-unit artifact format");
}
#[test]
fn caller_claimed_admission_field_is_not_an_artifact_capability() {
    let (f, raw) = baseline();
    let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    value["admitted_capture"] = true.into();
    let error = read_with(&f, &serde_json::to_vec(&value).unwrap(), Target::Riscv64UnknownNone).unwrap_err();
    match error {
        ArtifactError::Serialization(reason) => assert!(reason.contains("unknown field") && reason.contains("admitted_capture")),
        other => panic!("expected strict envelope field rejection, received {other:?}"),
    }
}
#[test]
fn payload_identity_mismatch_is_not_a_reconstructed_unit() {
    let (f, raw) = baseline();
    let mut envelope = decoded(&raw);
    envelope.typed_unit.identity.bytes += 1;
    refused(read_with(&f, &write(&envelope), Target::Riscv64UnknownNone).unwrap_err(), "typed-unit payload identity differs");
}
#[test]
fn failed_constructor_cannot_serialize_a_partial_source_artifact() {
    let (f, _) = baseline();
    let error = encode_configured_unit(ConstructInput {
        configured_assembly: &f.raw, syntax_selection: &f.syntax, syntax_inventory_json: &f.syntax_raw,
        unit_selection: &f.whole, unit_inventory_json: &f.unit_raw, body_floors: &[],
        target: Target::Riscv64UnknownNone,
    }).unwrap_err();
    match error {
        ArtifactError::Construction(failure) => {
            assert_eq!(failure.records.len(), 7);
            assert!(!failure.bodies[0].constructed);
            assert!(failure.issues.iter().any(|issue| issue.body == Some(0) && issue.reason == "missing required body floor"));
        }
        other => panic!("expected original constructor diagnostic, received {other:?}"),
    }
}
