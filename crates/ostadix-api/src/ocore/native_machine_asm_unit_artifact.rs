//! Source reconstruction artifacts relative to independently supplied inventories.
//!
//! This is neither AdmittedCapture nor the LLVM NativeModule artifact format.
//! Embedded inventory copies are data: readmission receives and uses the required
//! floors from its caller, reconstructs through the real parser/lifter/verifiers,
//! and compares the exact newly constructed typed unit. No capture, provider,
//! original-unit completeness, native realization or runtime authority is created.
use super::native_machine_asm_unit::{construct_configured_unit, BodyFloor, ConstructInput, ConstructedUnit, ConstructionFailure};
use super::common::Target;
use super::native_machine_asm_reader::ReadSelection;
use super::native_machine_ir::{ArtifactIdentity, MachineProfile, SourceWitness};
use super::native_machine_unit::{BodyId, UnitSelection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const FORMAT: &str = "ocore-configured-machine-unit-source-artifact-v1";

/// Required inputs are selected outside the artifact. No Deserialize exists for
/// this borrowed input: packaged claims cannot select their own coverage floor.
pub struct RequiredFloors<'a> {
    pub syntax_selection: &'a ReadSelection,
    pub syntax_inventory_json: &'a [u8],
    pub unit_selection: &'a UnitSelection,
    pub unit_inventory_json: &'a [u8],
    pub body_floors: &'a [BodyFloor<'a>],
}

#[derive(Debug)]
pub enum ArtifactError {
    Serialization(String),
    Envelope(&'static str),
    Construction(Box<ConstructionFailure>),
}
impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(reason) => write!(f, "configured-unit artifact JSON: {reason}"),
            Self::Envelope(reason) => write!(f, "configured-unit artifact: {reason}"),
            Self::Construction(failure) => write!(f, "configured-unit reconstruction: {:?}", failure.issues),
        }
    }
}
impl std::error::Error for ArtifactError {}

fn json_error(error: serde_json::Error) -> ArtifactError {
    ArtifactError::Serialization(error.to_string())
}
fn identity(raw: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity { bytes: raw.len() as u64, sha256: hex::encode(Sha256::digest(raw)) }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    identity: ArtifactIdentity,
    bytes: Vec<u8>,
}
impl Blob {
    fn new(raw: &[u8]) -> Self {
        Self { identity: identity(raw), bytes: raw.to_vec() }
    }
    fn check(&self, reason: &'static str) -> Result<(), ArtifactError> {
        if self.identity != identity(&self.bytes) {
            return Err(ArtifactError::Envelope(reason));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyInventory {
    body: BodyId,
    inventory: Blob,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    target: String,
    source: SourceWitness,
    profile: MachineProfile,
    configured_assembly: Blob,
    syntax_inventory: Blob,
    unit_inventory: Blob,
    body_inventories: Vec<BodyInventory>,
    typed_unit: Blob,
}

/// Construct and verify before producing an artifact. Constructor failure retains
/// its complete original record/body diagnostics; no partial unit is serialized.
pub fn encode_configured_unit(input: ConstructInput<'_>) -> Result<Vec<u8>, ArtifactError> {
    let configured_assembly = Blob::new(input.configured_assembly);
    let syntax_inventory = Blob::new(input.syntax_inventory_json);
    let unit_inventory = Blob::new(input.unit_inventory_json);
    let mut body_inventories: Vec<_> = input.body_floors.iter().map(|floor| BodyInventory {
        body: floor.body,
        inventory: Blob::new(floor.inventory_json),
    }).collect();
    let constructed = construct_configured_unit(input).map_err(ArtifactError::Construction)?;
    body_inventories.sort_by_key(|floor| floor.body);
    let typed_unit = Blob::new(&serde_json::to_vec(&constructed.unit).map_err(json_error)?);
    let envelope = Envelope {
        format: FORMAT.into(),
        target: constructed.report.target.into(),
        source: constructed.unit.source,
        profile: constructed.unit.profile,
        configured_assembly,
        syntax_inventory,
        unit_inventory,
        body_inventories,
        typed_unit,
    };
    serde_json::to_vec(&envelope).map_err(json_error)
}

/// Readmission is relative to caller-selected floors, not packaged authority.
/// The actual constructor reruns syntax, lifting, body guards and verify_unit.
/// The returned existing report retains all existing false qualification flags.
pub fn readmit_configured_unit(
    raw: &[u8],
    required: RequiredFloors<'_>,
    target: Target,
) -> Result<ConstructedUnit, ArtifactError> {
    let envelope: Envelope = serde_json::from_slice(raw).map_err(json_error)?;
    if envelope.format != FORMAT {
        return Err(ArtifactError::Envelope("unsupported configured-unit artifact format"));
    }
    if envelope.source != required.syntax_selection.source
        || envelope.source != required.unit_selection.source {
        return Err(ArtifactError::Envelope("source differs from independent selection"));
    }
    if envelope.profile != required.syntax_selection.profile
        || envelope.profile != required.unit_selection.profile {
        return Err(ArtifactError::Envelope("profile differs from independent selection"));
    }
    envelope.configured_assembly.check("configured payload identity differs")?;
    envelope.syntax_inventory.check("syntax payload identity differs")?;
    envelope.unit_inventory.check("unit inventory payload identity differs")?;
    envelope.typed_unit.check("typed-unit payload identity differs")?;
    if envelope.syntax_inventory.identity != required.syntax_selection.inventory
        || envelope.syntax_inventory.bytes.as_slice() != required.syntax_inventory_json {
        return Err(ArtifactError::Envelope("syntax inventory differs from independent required floor"));
    }
    if envelope.unit_inventory.identity != required.unit_selection.inventory
        || envelope.unit_inventory.bytes.as_slice() != required.unit_inventory_json {
        return Err(ArtifactError::Envelope("unit inventory differs from independent required floor"));
    }
    let mut required_bodies = BTreeMap::new();
    for floor in required.body_floors {
        if required_bodies.insert(floor.body, floor.inventory_json).is_some() {
            return Err(ArtifactError::Envelope("duplicate independent required body floor"));
        }
    }
    let mut previous = None;
    let mut packaged_bodies = BTreeMap::new();
    for floor in &envelope.body_inventories {
        if previous.is_some_and(|id| id >= floor.body) {
            return Err(ArtifactError::Envelope("packaged body inventory IDs are not unique and ordered"));
        }
        previous = Some(floor.body);
        floor.inventory.check("body inventory payload identity differs")?;
        packaged_bodies.insert(floor.body, floor.inventory.bytes.as_slice());
    }
    if required_bodies.keys().ne(packaged_bodies.keys()) {
        return Err(ArtifactError::Envelope("body inventory scope differs from independent required floors"));
    }
    if required_bodies != packaged_bodies {
        return Err(ArtifactError::Envelope("body inventory differs from independent required floor"));
    }
    // Only caller-supplied inventory bytes enter the real constructor. Packaged
    // copies above never become selections, and failed/extra bodies stay errors.
    let reconstructed = construct_configured_unit(ConstructInput {
        configured_assembly: &envelope.configured_assembly.bytes,
        syntax_selection: required.syntax_selection,
        syntax_inventory_json: required.syntax_inventory_json,
        unit_selection: required.unit_selection,
        unit_inventory_json: required.unit_inventory_json,
        body_floors: required.body_floors,
        target,
    }).map_err(ArtifactError::Construction)?;
    if envelope.target != reconstructed.report.target {
        return Err(ArtifactError::Envelope("target differs from reconstructed unit"));
    }
    let rebuilt = serde_json::to_vec(&reconstructed.unit).map_err(json_error)?;
    if envelope.typed_unit.bytes != rebuilt {
        return Err(ArtifactError::Envelope("typed unit differs from reconstructed source"));
    }
    Ok(reconstructed)
}

#[cfg(test)]
#[path = "native_machine_asm_unit_artifact_tests.rs"]
mod tests;
