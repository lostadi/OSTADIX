//! Exact original compound-source membership. This is not link-order authority.
use super::{provider_order, source_recipe};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

pub(super) const PLAN_V5: &str = "ocore-native-provider-plan-v5";
const POLICY_SCHEMA: &str = "ocore-original-provider-membership-v1";
const PACKAGE_SCHEMA: &str = "ocore-native-provider-membership-package-v1";

/// Original dependency label -> original member identity -> provider component.
pub(super) type CompoundBindings = BTreeMap<String, BTreeMap<String, String>>;

pub(super) struct Input<'a> {
    pub(super) name: &'a str,
    pub(super) recipe: &'a [u8],
    pub(super) dependencies: &'a BTreeMap<String, String>,
    pub(super) compound: &'a CompoundBindings,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    components: Vec<PolicyComponent>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyComponent {
    component: String,
    recipe: RecipePin,
    compound_dependencies: BTreeMap<String, CompoundPolicy>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipePin {
    bytes: u64,
    sha256: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompoundPolicy {
    declaration: Value,
    members: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    bytes: u64,
    mode: u32,
    nlink: u64,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}
fn identity(m: &Metadata) -> FileIdentity {
    FileIdentity {
        dev: m.dev(),
        ino: m.ino(),
        bytes: m.len(),
        mode: m.mode(),
        nlink: m.nlink(),
        uid: m.uid(),
        gid: m.gid(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
    }
}
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn sha_shape(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
}
fn valid_identity(s: &str) -> bool {
    !s.is_empty() && s.trim() == s && !s.chars().any(char::is_control)
}
fn object_source(value: &Value) -> bool {
    value.as_object().map(|x| !x.is_empty()).unwrap_or(false)
}
fn lexical_path(path: &Path) -> Result<()> {
    let normalized: std::path::PathBuf = path.components().collect();
    ensure!(
        path.is_absolute()
            && normalized.as_os_str() == path.as_os_str()
            && path
                .components()
                .all(|x| matches!(x, Component::RootDir | Component::Normal(_))),
        "membership policy path must be absolute and lexical-normal"
    );
    Ok(())
}
fn physical_path(path: &Path) -> Result<()> {
    lexical_path(path)?;
    ensure!(
        fs::canonicalize(path)?.as_os_str() == path.as_os_str(),
        "membership policy path must be physical/canonical"
    );
    Ok(())
}
fn check_pin(pin: &provider_order::OrderPin) -> Result<()> {
    ensure!(
        pin.bytes > 0 && sha_shape(&pin.sha256),
        "malformed membership policy pin"
    );
    physical_path(&pin.path)
}
/// Read only. Exact selected bytes come from this held regular FD; named and
/// physical identity are checked again after reading. No embedded path is opened.
fn read_policy(
    pin: &provider_order::OrderPin,
    expected: Option<&FileIdentity>,
) -> Result<(Vec<u8>, FileIdentity)> {
    check_pin(pin)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&pin.path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "membership policy must be a regular file"
    );
    let before = identity(&metadata);
    if let Some(old) = expected {
        ensure!(
            &before == old,
            "membership policy physical identity changed"
        );
    }
    ensure!(
        before.bytes == pin.bytes,
        "membership policy selected length differs"
    );
    let limit = pin
        .bytes
        .checked_add(1)
        .context("membership policy length overflow")?;
    let mut raw = Vec::new();
    (&mut file).take(limit).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 == pin.bytes && digest(&raw) == pin.sha256,
        "membership policy selected bytes/SHA differ"
    );
    ensure!(
        identity(&file.metadata()?) == before,
        "membership policy changed during held read"
    );
    physical_path(&pin.path)?;
    let named = fs::symlink_metadata(&pin.path)?;
    ensure!(
        named.is_file() && identity(&named) == before,
        "membership policy named identity changed"
    );
    drop(file);
    physical_path(&pin.path)?;
    ensure!(
        identity(&fs::symlink_metadata(&pin.path)?) == before,
        "membership policy named identity changed after close"
    );
    Ok((raw, before))
}

struct RecipeView {
    source: Value,
    declarations: BTreeMap<String, Value>,
}
fn validate(raw: &[u8], inputs: &[Input<'_>]) -> Result<()> {
    provider_order::check_json(raw).context("membership policy raw JSON must have unique keys")?;
    let policy: Policy = serde_json::from_slice(raw).context("membership policy schema invalid")?;
    ensure!(
        policy.schema == POLICY_SCHEMA,
        "unsupported membership policy schema"
    );
    ensure!(!inputs.is_empty(), "membership input components empty");
    let mut by_name = BTreeMap::new();
    let mut views = BTreeMap::new();
    let mut compounds = 0usize;
    for input in inputs {
        ensure!(
            valid_identity(input.name),
            "malformed membership component identity"
        );
        ensure!(
            by_name.insert(input.name, input).is_none(),
            "duplicate membership input component"
        );
        provider_order::check_json(input.recipe)
            .context("membership recipe raw JSON must have unique keys")?;
        let recipe: Value = serde_json::from_slice(input.recipe)?;
        ensure!(
            recipe["schema"] == source_recipe::RECIPE_FORMAT,
            "membership recipe schema differs"
        );
        let source = recipe
            .get("source")
            .context("membership recipe source absent")?;
        ensure!(
            object_source(source),
            "membership recipe source must be a nonempty object"
        );
        let dependencies = recipe
            .get("dependencies")
            .and_then(Value::as_array)
            .context("membership recipe dependencies must be an array")?;
        let mut declarations = BTreeMap::new();
        for declaration in dependencies {
            let name = declaration
                .as_object()
                .and_then(|x| x.get("name"))
                .and_then(Value::as_str)
                .context("membership dependency name must be a string")?;
            ensure!(
                valid_identity(name),
                "malformed membership dependency label"
            );
            ensure!(
                declarations
                    .insert(name.to_owned(), declaration.clone())
                    .is_none(),
                "duplicate membership recipe dependency label"
            );
        }
        for (label, provider) in input.dependencies {
            ensure!(
                valid_identity(label) && valid_identity(provider),
                "malformed legacy membership binding"
            );
            ensure!(
                !input.compound.contains_key(label),
                "legacy/compound dependency label overlap"
            );
        }
        let actual_labels: BTreeSet<&str> = input
            .dependencies
            .keys()
            .chain(input.compound.keys())
            .map(String::as_str)
            .collect();
        let declared_labels: BTreeSet<&str> = declarations.keys().map(String::as_str).collect();
        ensure!(
            actual_labels == declared_labels,
            "recipe dependency labels differ from legacy/compound bindings"
        );
        for (label, members) in input.compound {
            ensure!(valid_identity(label), "malformed compound dependency label");
            ensure!(!members.is_empty(), "compound member bindings empty");
            let declaration = &declarations[label];
            ensure!(
                declaration
                    .get("source_pin")
                    .map(Value::is_null)
                    .unwrap_or(true),
                "compound dependency retains non-null singular source_pin"
            );
            let mut providers = BTreeSet::new();
            for (member, provider) in members {
                ensure!(
                    valid_identity(member) && valid_identity(provider),
                    "malformed compound member identity"
                );
                ensure!(
                    providers.insert(provider),
                    "ambiguous compound members share one provider component"
                );
            }
            compounds = compounds
                .checked_add(1)
                .context("compound count overflow")?;
        }
        views.insert(
            input.name,
            RecipeView {
                source: source.clone(),
                declarations,
            },
        );
    }
    ensure!(
        compounds > 0,
        "membership V5 requires at least one compound dependency"
    );
    for input in inputs {
        for provider in input
            .dependencies
            .values()
            .chain(input.compound.values().flat_map(|x| x.values()))
        {
            ensure!(
                by_name.contains_key(provider.as_str()),
                "membership binding names unknown provider component"
            );
        }
    }
    let mut policies = BTreeMap::new();
    for component in &policy.components {
        ensure!(
            valid_identity(&component.component),
            "malformed policy component identity"
        );
        ensure!(
            policies
                .insert(component.component.as_str(), component)
                .is_none(),
            "duplicate membership policy component"
        );
    }
    ensure!(
        policies.keys().copied().collect::<BTreeSet<_>>() == by_name.keys().copied().collect(),
        "membership policy component set differs"
    );
    for (name, input) in by_name {
        let component = policies[name];
        ensure!(
            component.recipe.bytes == input.recipe.len() as u64
                && sha_shape(&component.recipe.sha256)
                && component.recipe.sha256 == digest(input.recipe),
            "membership policy recipe pin differs: {name}"
        );
        ensure!(
            component
                .compound_dependencies
                .keys()
                .collect::<BTreeSet<_>>()
                == input.compound.keys().collect(),
            "membership compound label set differs: {name}"
        );
        for (label, bindings) in input.compound {
            let expected = &component.compound_dependencies[label];
            ensure!(
                expected.declaration == views[name].declarations[label],
                "compound declaration differs: {name}/{label}"
            );
            ensure!(
                expected.members.keys().collect::<BTreeSet<_>>() == bindings.keys().collect(),
                "compound member set differs: {name}/{label}"
            );
            for (member, provider) in bindings {
                let source = &expected.members[member];
                ensure!(
                    object_source(source),
                    "policy member source must be a nonempty object"
                );
                ensure!(
                    source == &views[provider.as_str()].source,
                    "compound member source differs: {name}/{label}/{member}"
                );
            }
        }
    }
    Ok(())
}

/// Opaque selected capability. Never Deserialize and never construct from a package.
pub(super) struct SelectedMembership {
    pin: provider_order::OrderPin,
    raw: String,
    observed: FileIdentity,
}
impl SelectedMembership {
    pub(super) fn read(pin: &provider_order::OrderPin, inputs: &[Input<'_>]) -> Result<Self> {
        let (raw, observed) = read_policy(pin, None)?;
        validate(&raw, inputs)?;
        Ok(Self {
            pin: pin.clone(),
            raw: String::from_utf8(raw)?,
            observed,
        })
    }
    pub(super) fn check_unchanged(&self) -> Result<()> {
        let (raw, _) = read_policy(&self.pin, Some(&self.observed))?;
        ensure!(
            raw == self.raw.as_bytes(),
            "selected membership policy raw bytes changed"
        );
        Ok(())
    }
    pub(super) fn package(&self) -> PackagedMembership {
        PackagedMembership {
            schema: PACKAGE_SCHEMA.into(),
            policy_pin: self.pin.clone(),
            policy_raw: self.raw.clone(),
            policy_sha256: self.pin.sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PackagedMembership {
    schema: String,
    policy_pin: provider_order::OrderPin,
    policy_raw: String,
    policy_sha256: String,
}
impl PackagedMembership {
    /// Internal consistency only: this never opens policy_pin.path or any source path.
    pub(super) fn check(&self, inputs: &[Input<'_>]) -> Result<()> {
        ensure!(
            self.schema == PACKAGE_SCHEMA,
            "unsupported packaged membership schema"
        );
        lexical_path(&self.policy_pin.path)?;
        ensure!(
            self.policy_pin.bytes == self.policy_raw.len() as u64
                && sha_shape(&self.policy_sha256)
                && self.policy_pin.sha256 == self.policy_sha256
                && digest(self.policy_raw.as_bytes()) == self.policy_sha256,
            "packaged membership raw policy digest differs"
        );
        validate(self.policy_raw.as_bytes(), inputs)
    }
    pub(super) fn require_external(
        &self,
        selected: Option<&SelectedMembership>,
        inputs: &[Input<'_>],
    ) -> Result<()> {
        let selected = selected.context("separately selected membership policy required")?;
        ensure!(
            self.policy_pin == selected.pin
                && self.policy_raw == selected.raw
                && self.policy_sha256 == selected.pin.sha256,
            "external membership policy pin/raw differs"
        );
        selected.check_unchanged()?;
        self.check(inputs)
    }
}

#[cfg(test)]
#[path = "provider_membership_tests.rs"]
mod tests;
