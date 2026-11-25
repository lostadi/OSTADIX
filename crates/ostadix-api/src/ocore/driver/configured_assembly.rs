//! Reachable configured-source construction boundary. No assembler invocation,
//! NativeModule, producer authentication, native exposure or ISA qualification.
use crate::ocore::common::{Diagnostic, Span, Target};
use crate::ocore::{native_machine_asm_reader as syntax, native_machine_asm_unit as construction};
use crate::ocore::{native_machine_ir::*, native_machine_unit as unit};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

pub const SELECTION_FORMAT: &str = "ocore-configured-assembly-construction-selection-v1";
pub const OUTPUT_FORMAT: &str = "ocore-configured-machine-unit-construction-v1";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FloorFile {
    pub path: PathBuf,
    pub identity: ArtifactIdentity,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyFloorFile {
    pub body: unit::BodyId,
    pub path: PathBuf,
    pub identity: ArtifactIdentity,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblySelection {
    pub format: String,
    pub owner: PathBuf,
    pub source: SourceWitness,
    pub profile: MachineProfile,
    pub syntax_inventory: FloorFile,
    pub unit_inventory: FloorFile,
    pub body_inventories: Vec<BodyFloorFile>,
}

/// Explicit source-membership mode: the selected original bytes must be exactly
/// the configured bytes. This does not authenticate a producer or an ABI floor.
pub const IDENTITY_SELECTION_FORMAT: &str = "ocore-configured-assembly-identity-selection-v1";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityOriginalFile {
    pub file_id: u64,
    pub input: FloorFile,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAssemblySelection {
    pub format: String,
    pub owner: PathBuf,
    pub source: SourceWitness,
    pub profile: MachineProfile,
    pub original_file: IdentityOriginalFile,
    pub unit_inventory: FloorFile,
    pub body_inventories: Vec<BodyFloorFile>,
}
// Legacy descriptors keep their exact public type and JSON field set. The new
// mode has its own format and cannot deserialize an authoritative syntax floor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum AssemblyDescriptor {
    Supplied(AssemblySelection),
    Identity(IdentityAssemblySelection),
}
impl AssemblyDescriptor {
    fn check_format(&self) -> Result<(), String> {
        match self {
            Self::Supplied(v) if v.format == SELECTION_FORMAT => Ok(()),
            Self::Identity(v) if v.format == IDENTITY_SELECTION_FORMAT => Ok(()),
            Self::Supplied(_) => Err("unsupported configured assembly selection format".into()),
            Self::Identity(_) => {
                Err("unsupported identity-original configured assembly selection format".into())
            }
        }
    }
    fn owner(&self) -> &Path {
        match self {
            Self::Supplied(v) => &v.owner,
            Self::Identity(v) => &v.owner,
        }
    }
    fn source(&self) -> &SourceWitness {
        match self {
            Self::Supplied(v) => &v.source,
            Self::Identity(v) => &v.source,
        }
    }
    fn profile(&self) -> &MachineProfile {
        match self {
            Self::Supplied(v) => &v.profile,
            Self::Identity(v) => &v.profile,
        }
    }
    fn unit_inventory(&self) -> &FloorFile {
        match self {
            Self::Supplied(v) => &v.unit_inventory,
            Self::Identity(v) => &v.unit_inventory,
        }
    }
    fn body_inventories(&self) -> &[BodyFloorFile] {
        match self {
            Self::Supplied(v) => &v.body_inventories,
            Self::Identity(v) => &v.body_inventories,
        }
    }
}

fn identity(bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pin(value: &ArtifactIdentity) -> Result<(), String> {
    if value.bytes == 0 || !digest(&value.sha256) {
        Err("invalid nonempty lower-case SHA-256 identity".into())
    } else {
        Ok(())
    }
}
fn relative(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || !path.components().all(|c| matches!(c, Component::Normal(_)))
    {
        Err("floor path must be normal and relative under descriptor owner".into())
    } else {
        Ok(())
    }
}
fn selected_profile(p: &MachineProfile, target: Target) -> Result<(), String> {
    let ok = match target {
        Target::X86_64UnknownNone => {
            p.architecture == Architecture::X86_64
                && p.abi == MachineAbi::SysvAmd64
                && p.entry_stack_remainder == 8
        }
        Target::Aarch64UnknownNone => {
            p.architecture == Architecture::Aarch64
                && p.abi == MachineAbi::Aapcs64
                && p.entry_stack_remainder == 0
        }
        Target::Riscv64UnknownNone => {
            p.architecture == Architecture::Rv64
                && matches!(p.abi, MachineAbi::RiscvLp64 | MachineAbi::RiscvLp64d)
                && p.entry_stack_remainder == 0
        }
    };
    if !ok
        || p.address_bits != 64
        || p.byte_order != ByteOrder::Little
        || p.entry_stack_alignment != 16
    {
        Err(
            "independently selected CLI target disagrees with assembly architecture/ABI/layout"
                .into(),
        )
    } else {
        Ok(())
    }
}
fn membership(floor: &unit::SelectedUnitInventory, bodies: &[BodyFloorFile]) -> Result<(), String> {
    let required: BTreeSet<_> = floor.bodies.iter().map(|b| b.id).collect();
    let selected: BTreeSet<_> = bodies.iter().map(|b| b.body).collect();
    if required.len() != floor.bodies.len()
        || selected.len() != bodies.len()
        || required != selected
    {
        Err("duplicate, missing or extra required body selector before construction".into())
    } else {
        Ok(())
    }
}
/// Only --emit machine-unit calls this. The output is a versioned typed unit
/// with full record/body dispositions; self-described floors remain unadmitted.
pub fn construct_configured_assembly(
    configured: &Path,
    descriptor: &Path,
    sha: &str,
    target: Target,
    output: &Path,
) -> Result<(), Diagnostic> {
    #[cfg(unix)]
    let result = native::run(configured, descriptor, sha, target, output);
    #[cfg(not(unix))]
    let result: Result<(), String> = {
        let _ = (configured, descriptor, sha, target, output);
        Err(
            "configured source file custody requires the implemented Unix openat/nofollow boundary"
                .into(),
        )
    };
    result.map_err(|message| Diagnostic {
        file: "<configured-assembly>".into(),
        span: Span::default(),
        message,
    })
}

#[cfg(unix)]
mod native {
    use crate::ocore::driver::configured_assembly::*;
    use std::ffi::{CString, OsStr};
    use std::fs::{self, File, Metadata};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

    // The identity variant retains the opaque, source-derived floor until the
    // fresh constructor consumes it. No artifact can redefine its membership.
    enum HeldSyntaxFloor {
        Supplied {
            selection: syntax::ReadSelection,
            inventory_json: Vec<u8>,
        },
        Identity(syntax::inventory::SelectedSyntaxFloor),
    }
    impl HeldSyntaxFloor {
        fn selection(&self) -> &syntax::ReadSelection {
            match self {
                Self::Supplied { selection, .. } => selection,
                Self::Identity(floor) => floor.selection(),
            }
        }
        fn inventory_json(&self) -> &[u8] {
            match self {
                Self::Supplied { inventory_json, .. } => inventory_json,
                Self::Identity(floor) => floor.inventory_json(),
            }
        }
        fn origin(&self) -> serde_json::Value {
            match self {
                Self::Supplied { .. } => serde_json::json!({
                    "mode":"caller-selected-inventory",
                    "producer_attribution_proven":false,
                    "unit_or_abi_inventory_derived":false,
                }),
                Self::Identity(floor) => serde_json::json!({
                    "mode":"held-identity-original",
                    "identity_origin_file":floor.identity_origin_file(),
                    "producer_attribution_proven":false,
                    "unit_or_abi_inventory_derived":false,
                }),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct Native {
        dev: u64,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u64,
        size: u64,
        mtime: i64,
        mtime_ns: i64,
        ctime: i64,
        ctime_ns: i64,
    }
    impl Native {
        fn of(m: &Metadata) -> Self {
            Self {
                dev: m.dev(),
                ino: m.ino(),
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                nlink: m.nlink(),
                size: m.len(),
                mtime: m.mtime(),
                mtime_ns: m.mtime_nsec(),
                ctime: m.ctime(),
                ctime_ns: m.ctime_nsec(),
            }
        }
        fn core(&self, b: &Self) -> bool {
            (self.dev, self.ino, self.mode, self.uid, self.gid)
                == (b.dev, b.ino, b.mode, b.uid, b.gid)
        }
    }
    struct Directory {
        path: PathBuf,
        file: File,
        before: Option<Native>,
    }
    struct Input {
        path: PathBuf,
        file: File,
        before: Option<Native>,
        raw: Vec<u8>,
    }
    struct Held {
        dirs: Vec<Directory>,
        inputs: Vec<Input>,
    }
    fn err(e: impl std::fmt::Display) -> String {
        e.to_string()
    }
    fn absolute(path: &Path) -> Result<PathBuf, String> {
        let p = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().map_err(err)?.join(path)
        };
        if !p
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err("input path contains parent/dot/prefix components".into());
        }
        Ok(p)
    }
    fn openat(parent: &File, name: &OsStr, flags: i32, mode: u32) -> Result<File, String> {
        let c = CString::new(name.as_bytes()).map_err(err)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode,
            )
        };
        if fd < 0 {
            let os_error = std::io::Error::last_os_error();
            Err(format!(
                "nofollow openat {}: {}",
                name.to_string_lossy(),
                os_error
            ))
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    impl Held {
        fn new() -> Self {
            Self {
                dirs: vec![],
                inputs: vec![],
            }
        }
        fn directory(&mut self, path: &Path) -> Result<usize, String> {
            let path = absolute(path)?;
            if let Some(i) = self.dirs.iter().position(|d| d.path == path) {
                return Ok(i);
            }
            let file = File::open("/").map_err(err)?;
            self.dirs.push(Directory {
                path: PathBuf::from("/"),
                file,
                before: None,
            });
            let mut parent = self.dirs.len() - 1;
            self.dirs[parent].before =
                Some(Native::of(&self.dirs[parent].file.metadata().map_err(err)?));
            let mut current = PathBuf::from("/");
            for c in path.components() {
                if let Component::Normal(name) = c {
                    let file = openat(
                        &self.dirs[parent].file,
                        name,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                        0,
                    )?;
                    current.push(name);
                    self.dirs.push(Directory {
                        path: current.clone(),
                        file,
                        before: None,
                    });
                    parent = self.dirs.len() - 1;
                    let row = &mut self.dirs[parent];
                    let metadata = row.file.metadata().map_err(err)?;
                    row.before = Some(Native::of(&metadata));
                    let named = fs::symlink_metadata(&row.path).map_err(err)?;
                    if !metadata.is_dir()
                        || !named.is_dir()
                        || Native::of(&named) != *row.before.as_ref().unwrap()
                    {
                        return Err("physical directory held/named identity differs".into());
                    }
                }
            }
            Ok(parent)
        }
        fn input(
            &mut self,
            path: &Path,
            selected: Option<&ArtifactIdentity>,
        ) -> Result<usize, String> {
            let path = absolute(path)?;
            if self.inputs.iter().any(|r| r.path == path) {
                return Err("duplicate consumed input path".into());
            }
            let parent = self.directory(path.parent().ok_or("input has no parent")?)?;
            let file = openat(
                &self.dirs[parent].file,
                path.file_name().ok_or("missing basename")?,
                libc::O_RDONLY,
                0,
            )?;
            self.inputs.push(Input {
                path,
                file,
                before: None,
                raw: vec![],
            });
            let index = self.inputs.len() - 1;
            let metadata = self.inputs[index].file.metadata().map_err(err)?;
            let before = Native::of(&metadata);
            self.inputs[index].before = Some(before.clone());
            if !metadata.is_file() || before.nlink != 1 {
                return Err("input must be regular/single-link".into());
            }
            if self.inputs[..index]
                .iter()
                .filter_map(|r| r.before.as_ref())
                .any(|r| r.dev == before.dev && r.ino == before.ino)
            {
                return Err("duplicate consumed input inode".into());
            }
            let r = &mut self.inputs[index];
            r.file.read_to_end(&mut r.raw).map_err(err)?;
            Self::guard_input(r)?;
            if let Some(expected) = selected {
                pin(expected)?;
                if identity(&r.raw) != *expected {
                    return Err(format!("selected bytes differ: {}", r.path.display()));
                }
            }
            Ok(index)
        }
        fn guard_input(r: &mut Input) -> Result<(), String> {
            let before = r
                .before
                .as_ref()
                .ok_or("held input initialization incomplete")?;
            let held = Native::of(&r.file.metadata().map_err(err)?);
            let named = fs::symlink_metadata(&r.path).map_err(err)?;
            if !named.is_file() || &held != before || Native::of(&named) != *before {
                return Err(format!(
                    "input held/named native identity changed: {}",
                    r.path.display()
                ));
            }
            r.file.seek(SeekFrom::Start(0)).map_err(err)?;
            let mut raw = vec![];
            r.file.read_to_end(&mut raw).map_err(err)?;
            if raw != r.raw {
                return Err(format!("input bytes changed: {}", r.path.display()));
            }
            let held = Native::of(&r.file.metadata().map_err(err)?);
            let named = fs::symlink_metadata(&r.path).map_err(err)?;
            if !named.is_file() || &held != before || Native::of(&named) != *before {
                return Err(format!(
                    "input changed during full re-read: {}",
                    r.path.display()
                ));
            }
            Ok(())
        }
        fn guards(&mut self) -> Vec<String> {
            let mut failures = vec![];
            for r in &mut self.inputs {
                if let Err(e) = Self::guard_input(r) {
                    failures.push(e);
                }
            }
            for d in &self.dirs {
                let checked = (|| {
                    let b = d
                        .before
                        .as_ref()
                        .ok_or("held directory initialization incomplete")?;
                    let held = Native::of(&d.file.metadata().map_err(err)?);
                    let named = fs::symlink_metadata(&d.path).map_err(err)?;
                    if !named.is_dir() || !b.core(&held) || !b.core(&Native::of(&named)) {
                        return Err(format!(
                            "physical owner/ancestor changed: {}",
                            d.path.display()
                        ));
                    }
                    Ok(())
                })();
                if let Err(e) = checked {
                    failures.push(e);
                }
            }
            failures
        }
        fn closes(&mut self) -> Vec<String> {
            let mut failures = vec![];
            for r in self.inputs.drain(..) {
                let fd = r.file.into_raw_fd();
                if unsafe { libc::close(fd) } != 0 {
                    failures.push(format!(
                        "close {}: {}",
                        r.path.display(),
                        std::io::Error::last_os_error()
                    ));
                }
            }
            for r in self.dirs.drain(..) {
                let fd = r.file.into_raw_fd();
                if unsafe { libc::close(fd) } != 0 {
                    failures.push(format!(
                        "directory close {}: {}",
                        r.path.display(),
                        std::io::Error::last_os_error()
                    ));
                }
            }
            failures
        }
        fn output(&mut self, path: &Path, raw: Vec<u8>) -> Result<(), String> {
            if path == Path::new("-") {
                return Err("machine-unit output requires a new explicit artifact file".into());
            }
            let path = absolute(path)?;
            if self.inputs.iter().any(|i| i.path == path) {
                return Err("output aliases selected input".into());
            }
            let p = self.directory(path.parent().ok_or("output missing parent")?)?;
            let file = openat(
                &self.dirs[p].file,
                path.file_name().ok_or("output missing basename")?,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            self.inputs.push(Input {
                path,
                file,
                before: None,
                raw: vec![],
            });
            let i = self.inputs.len() - 1;
            let r = &mut self.inputs[i];
            r.file.write_all(&raw).map_err(err)?;
            r.file.sync_all().map_err(err)?;
            r.before = Some(Native::of(&r.file.metadata().map_err(err)?));
            r.raw = raw;
            Self::guard_input(r)?;
            self.dirs[p].file.sync_all().map_err(err)
        }
    }
    pub(in crate::ocore::driver::configured_assembly) fn run(
        configured: &Path,
        descriptor: &Path,
        sha: &str,
        target: Target,
        output: &Path,
    ) -> Result<(), String> {
        let mut held = Held::new();
        let body = (|| {
            if !digest(sha) {
                return Err("invalid descriptor SHA-256 selection".into());
            }
            let di = held.input(descriptor, None)?;
            if identity(&held.inputs[di].raw).sha256 != sha {
                return Err("descriptor SHA-256 differs".into());
            }
            let selected: AssemblyDescriptor = serde_json::from_slice(&held.inputs[di].raw)
                .map_err(|e| format!("selection JSON: {e}"))?;
            selected.check_format()?;
            let owner = absolute(selected.owner())?;
            if !selected.owner().is_absolute()
                || held.inputs[di].path.parent() != Some(owner.as_path())
            {
                return Err(
                    "descriptor must be directly under explicit absolute physical owner".into(),
                );
            }
            held.directory(&owner)?;
            selected_profile(selected.profile(), target)?;
            for a in [
                &selected.source().decoded_assembly,
                &selected.source().build_configuration,
                &selected.source().frontend_event,
            ] {
                pin(a)?;
            }
            for f in &selected.source().files {
                pin(&f.identity)?;
            }
            let ci = held.input(configured, Some(&selected.source().decoded_assembly))?;
            // Seal complete source membership before opening unit/body policy
            // files and before any fresh reader/construction result exists.
            let syntax_floor = match &selected {
                AssemblyDescriptor::Supplied(v) => {
                    relative(&v.syntax_inventory.path)?;
                    let si = held.input(
                        &owner.join(&v.syntax_inventory.path),
                        Some(&v.syntax_inventory.identity),
                    )?;
                    HeldSyntaxFloor::Supplied {
                        selection: syntax::ReadSelection {
                            source: v.source.clone(),
                            profile: v.profile.clone(),
                            inventory: v.syntax_inventory.identity.clone(),
                        },
                        inventory_json: held.inputs[si].raw.clone(),
                    }
                }
                AssemblyDescriptor::Identity(v) => {
                    relative(&v.original_file.input.path)?;
                    pin(&v.original_file.input.identity)?;
                    let original = owner.join(&v.original_file.input.path);
                    let oi = if original == held.inputs[ci].path {
                        // One physical file may satisfy two independently
                        // selected byte identities; do not reopen/alias it.
                        if identity(&held.inputs[ci].raw) != v.original_file.input.identity {
                            return Err("selected identity-original bytes differ".into());
                        }
                        ci
                    } else {
                        held.input(&original, Some(&v.original_file.input.identity))?
                    };
                    let floor = syntax::inventory::select_identity_mapped_source(
                        &held.inputs[ci].raw,
                        &held.inputs[oi].raw,
                        v.original_file.file_id,
                        &v.source,
                        &v.profile,
                        target,
                    )
                    .map_err(|e| format!("identity-original syntax selection: {e}"))?;
                    HeldSyntaxFloor::Identity(floor)
                }
            };
            relative(&selected.unit_inventory().path)?;
            let ui = held.input(
                &owner.join(&selected.unit_inventory().path),
                Some(&selected.unit_inventory().identity),
            )?;
            let floor: unit::SelectedUnitInventory =
                serde_json::from_slice(&held.inputs[ui].raw)
                    .map_err(|e| format!("unit floor JSON: {e}"))?;
            membership(&floor, selected.body_inventories())?;
            let mut indices = vec![];
            for b in selected.body_inventories() {
                relative(&b.path)?;
                let required = floor
                    .bodies
                    .iter()
                    .find(|r| r.id == b.body)
                    .ok_or("missing required body")?;
                if required.inventory != b.identity {
                    return Err("descriptor/body floor identity mismatch".into());
                }
                indices.push((b.body, held.input(&owner.join(&b.path), Some(&b.identity))?));
            }
            let unit_selection = unit::UnitSelection {
                source: selected.source().clone(),
                profile: selected.profile().clone(),
                inventory: selected.unit_inventory().identity.clone(),
            };
            let floors: Vec<_> = indices
                .iter()
                .map(|(body, i)| construction::BodyFloor {
                    body: *body,
                    inventory_json: &held.inputs[*i].raw,
                })
                .collect();
            let constructed=construction::construct_configured_unit(construction::ConstructInput{
                configured_assembly:&held.inputs[ci].raw,syntax_selection:syntax_floor.selection(),syntax_inventory_json:syntax_floor.inventory_json(),
                unit_selection:&unit_selection,unit_inventory_json:&held.inputs[ui].raw,body_floors:&floors,target,
            }).map_err(|failure|{let f=*failure;serde_json::json!({"format":"ocore-configured-machine-unit-construction-failure-v1","qualification":false,"inputs":f.inputs,"records":f.records,"bodies":f.bodies,"issues":f.issues}).to_string()})?;
            let consumed:Vec<_>=held.inputs.iter().map(|r|serde_json::json!({"path":r.path,"native":r.before,"identity":identity(&r.raw)})).collect();
            let value = serde_json::json!({"format":OUTPUT_FORMAT,"qualification":false,"original_inventory_authenticated":false,"source_or_native_admission":false,"complete_runtime_or_provider":false,"target":target.name(),"selection":selected,"consumed_files":consumed,"configured_assembly_bytes":held.inputs[ci].raw,"syntax_inventory_bytes":syntax_floor.inventory_json(),"syntax_inventory_origin":syntax_floor.origin(),"unit_inventory_bytes":held.inputs[ui].raw,"inputs":constructed.inputs,"unit":constructed.unit,"verification":constructed.report,"records":constructed.records,"bodies":constructed.bodies});
            let mut raw = serde_json::to_vec_pretty(&value).map_err(err)?;
            raw.push(b'\n');
            let errors = held.guards();
            if !errors.is_empty() {
                return Err(errors.join("; "));
            }
            held.output(output, raw)
        })();
        let mut errors = vec![];
        if let Err(e) = body {
            errors.push(e);
        }
        errors.extend(held.guards());
        errors.extend(held.closes());
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configured_floor_paths_refuse_escape_absolute_and_empty() {
        for p in ["", "../floor.json", "/floor.json", "a/../floor.json"] {
            assert!(relative(Path::new(p)).is_err(), "{p}");
        }
        assert!(relative(Path::new("floors/body.json")).is_ok());
    }
    #[test]
    fn configured_floor_unknown_fields_and_invalid_digests_refuse() {
        assert!(serde_json::from_value::<FloorFile>(serde_json::json!({"path":"floor.json","identity":{"bytes":1,"sha256":"a".repeat(64)},"admitted":true})).is_err());
        assert!(pin(&ArtifactIdentity {
            bytes: 1,
            sha256: "A".repeat(64)
        })
        .is_err());
        assert!(pin(&ArtifactIdentity {
            bytes: 0,
            sha256: "a".repeat(64)
        })
        .is_err());
    }
}

#[cfg(all(test, unix))]
mod file_route_tests {
    use super::*;
    use crate::ocore::native_machine_asm_unit::tests::fixture;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Owner(PathBuf);
    impl Owner {
        fn new() -> Self {
            let p = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "ocore-configured-source-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn selected(owner: &Owner) -> (AssemblySelection, PathBuf, String) {
        let f = fixture(&["addi a0,a0,1", "ret"]);
        for (name, bytes) in [
            ("source.s", &f.raw),
            ("syntax.json", &f.syntax_raw),
            ("unit.json", &f.unit_raw),
            ("body.json", &f.body_raw),
        ] {
            std::fs::write(owner.0.join(name), bytes).unwrap();
        }
        let s = AssemblySelection {
            format: SELECTION_FORMAT.into(),
            owner: owner.0.clone(),
            source: f.syntax.source,
            profile: f.syntax.profile,
            syntax_inventory: FloorFile {
                path: "syntax.json".into(),
                identity: identity(&f.syntax_raw),
            },
            unit_inventory: FloorFile {
                path: "unit.json".into(),
                identity: identity(&f.unit_raw),
            },
            body_inventories: vec![BodyFloorFile {
                body: 0,
                path: "body.json".into(),
                identity: identity(&f.body_raw),
            }],
        };
        let raw = serde_json::to_vec(&s).unwrap();
        let descriptor = owner.0.join("selection.json");
        std::fs::write(&descriptor, &raw).unwrap();
        (s, descriptor, identity(&raw).sha256)
    }
    #[test]
    fn ordinary_driver_constructs_versioned_unadmitted_machine_unit_from_actual_files() {
        let owner = Owner::new();
        let (_, descriptor, sha) = selected(&owner);
        let output = owner.0.join("typed.machine.json");
        construct_configured_assembly(
            &owner.0.join("source.s"),
            &descriptor,
            &sha,
            Target::Riscv64UnknownNone,
            &output,
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(value["format"], OUTPUT_FORMAT);
        assert_eq!(value["qualification"], false);
        assert_eq!(value["source_or_native_admission"], false);
        assert_eq!(value["unit"]["bodies"].as_array().unwrap().len(), 1);
        assert_eq!(value["records"].as_array().unwrap().len(), 7);
    }
    #[test]
    fn ordinary_driver_refuses_independent_target_mismatch_without_output() {
        let owner = Owner::new();
        let (_, descriptor, sha) = selected(&owner);
        let output = owner.0.join("no.machine.json");
        let e = construct_configured_assembly(
            &owner.0.join("source.s"),
            &descriptor,
            &sha,
            Target::X86_64UnknownNone,
            &output,
        )
        .unwrap_err();
        assert!(e.message.contains("independently selected CLI target"));
        assert!(!output.exists());
    }
    #[test]
    fn ordinary_driver_refuses_missing_duplicate_and_extra_body_selection_before_output() {
        for mode in 0..3 {
            let owner = Owner::new();
            let (mut value, descriptor, _) = selected(&owner);
            match mode {
                0 => value.body_inventories.clear(),
                1 => value
                    .body_inventories
                    .push(value.body_inventories[0].clone()),
                _ => value.body_inventories[0].body = 99,
            }
            let raw = serde_json::to_vec(&value).unwrap();
            std::fs::write(&descriptor, &raw).unwrap();
            assert!(
                value.body_inventories.is_empty()
                    || value.body_inventories.len() == 2
                    || value.body_inventories[0].body == 99
            );
            let output = owner.0.join("no.machine.json");
            let e = construct_configured_assembly(
                &owner.0.join("source.s"),
                &descriptor,
                &identity(&raw).sha256,
                Target::Riscv64UnknownNone,
                &output,
            )
            .unwrap_err();
            assert!(
                e.message.contains(
                    "duplicate, missing or extra required body selector before construction"
                ),
                "{}",
                e.message
            );
            assert!(!output.exists());
        }
    }
    #[test]
    fn ordinary_driver_refuses_reachable_symlink_floor_without_output() {
        let owner = Owner::new();
        let (_, descriptor, sha) = selected(&owner);
        let body = owner.0.join("body.json");
        std::fs::rename(&body, owner.0.join("saved-body.json")).unwrap();
        std::os::unix::fs::symlink("saved-body.json", &body).unwrap();
        let output = owner.0.join("no.machine.json");
        let e = construct_configured_assembly(
            &owner.0.join("source.s"),
            &descriptor,
            &sha,
            Target::Riscv64UnknownNone,
            &output,
        )
        .unwrap_err();
        assert!(std::fs::symlink_metadata(&body)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(e.message.contains("nofollow openat"), "{}", e.message);
        assert!(
            e.message.contains("body.json"),
            "refused a component other than the planted symlink: {}",
            e.message
        );
        assert!(!output.exists());
    }

    // These reuse the original authored unit fixture without rewriting any
    // source identity, origin, ABI interface or required unit/body inventory.
    fn selected_identity(
        owner: &Owner,
        separate_original: bool,
    ) -> (IdentityAssemblySelection, PathBuf, String) {
        let (legacy, descriptor, _) = selected(owner);
        let raw = std::fs::read(owner.0.join("source.s")).unwrap();
        assert_eq!(legacy.source.files.len(), 1);
        assert_eq!(legacy.source.files[0].identity, identity(&raw));
        assert_eq!(legacy.source.decoded_assembly, identity(&raw));
        let path = if separate_original {
            "original.S"
        } else {
            "source.s"
        };
        if separate_original {
            std::fs::write(owner.0.join(path), &raw).unwrap();
        }
        let value = IdentityAssemblySelection {
            format: IDENTITY_SELECTION_FORMAT.into(),
            owner: legacy.owner,
            original_file: IdentityOriginalFile {
                file_id: legacy.source.files[0].id,
                input: FloorFile {
                    path: path.into(),
                    identity: identity(&raw),
                },
            },
            source: legacy.source,
            profile: legacy.profile,
            unit_inventory: legacy.unit_inventory,
            body_inventories: legacy.body_inventories,
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(&descriptor, &bytes).unwrap();
        (value, descriptor, identity(&bytes).sha256)
    }
    fn save_identity_descriptor(value: &IdentityAssemblySelection, descriptor: &Path) -> String {
        let bytes = serde_json::to_vec(value).unwrap();
        std::fs::write(descriptor, &bytes).unwrap();
        identity(&bytes).sha256
    }
    fn run_identity(
        owner: &Owner,
        descriptor: &Path,
        sha: &str,
        output: &Path,
    ) -> Result<(), Diagnostic> {
        construct_configured_assembly(
            &owner.0.join("source.s"),
            descriptor,
            sha,
            Target::Riscv64UnknownNone,
            output,
        )
    }
    fn assert_identity_output(output: &Path) -> serde_json::Value {
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(value["format"], OUTPUT_FORMAT);
        assert_eq!(
            value["syntax_inventory_origin"]["mode"],
            "held-identity-original"
        );
        assert_eq!(value["syntax_inventory_origin"]["identity_origin_file"], 0);
        for key in [
            "qualification",
            "original_inventory_authenticated",
            "source_or_native_admission",
            "complete_runtime_or_provider",
        ] {
            assert_eq!(value[key], false, "{key}");
        }
        assert_eq!(
            value["syntax_inventory_origin"]["producer_attribution_proven"],
            false
        );
        assert_eq!(
            value["syntax_inventory_origin"]["unit_or_abi_inventory_derived"],
            false
        );
        assert_eq!(value["unit"]["bodies"].as_array().unwrap().len(), 1);
        assert_eq!(value["records"].as_array().unwrap().len(), 7);
        let raw: Vec<u8> = serde_json::from_value(value["syntax_inventory_bytes"].clone()).unwrap();
        let floor: syntax::SyntaxInventory = serde_json::from_slice(&raw).unwrap();
        assert_eq!(floor.records.len(), 7);
        assert_eq!(
            value["inputs"]["syntax_floor"],
            serde_json::to_value(identity(&raw)).unwrap()
        );
        value
    }
    #[test]
    fn identity_driver_constructs_from_same_held_original_without_a_syntax_file() {
        let owner = Owner::new();
        let (_, descriptor, sha) = selected_identity(&owner, false);
        std::fs::remove_file(owner.0.join("syntax.json")).unwrap();
        let output = owner.0.join("identity.machine.json");
        run_identity(&owner, &descriptor, &sha, &output).unwrap();
        assert_identity_output(&output);
    }
    #[test]
    fn identity_driver_constructs_with_a_separately_held_identical_original() {
        let owner = Owner::new();
        let (_, descriptor, sha) = selected_identity(&owner, true);
        std::fs::remove_file(owner.0.join("syntax.json")).unwrap();
        let output = owner.0.join("identity.machine.json");
        run_identity(&owner, &descriptor, &sha, &output).unwrap();
        let value = assert_identity_output(&output);
        assert!(value["consumed_files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| { r["path"] == serde_json::to_value(owner.0.join("original.S")).unwrap() }));
    }
    #[test]
    fn identity_driver_rejects_transformed_s_before_opening_unit_floors() {
        let owner = Owner::new();
        let (mut value, descriptor, _) = selected_identity(&owner, true);
        let original = std::fs::read(owner.0.join("original.S")).unwrap();
        let mut configured = b"# 1 \"authored.S\"\n".to_vec();
        configured.extend_from_slice(&original);
        assert_ne!(configured, original);
        std::fs::write(owner.0.join("source.s"), &configured).unwrap();
        value.source.decoded_assembly = identity(&configured);
        let sha = save_identity_descriptor(&value, &descriptor);
        std::fs::remove_file(owner.0.join("unit.json")).unwrap();
        let output = owner.0.join("no.machine.json");
        let error = run_identity(&owner, &descriptor, &sha, &output).unwrap_err();
        assert!(
            error
                .message
                .contains("nonidentity configured-source origins"),
            "{}",
            error.message
        );
        assert!(!output.exists());
    }
    #[test]
    fn identity_driver_checks_selected_original_identity_before_unit_floors() {
        let owner = Owner::new();
        let (mut value, descriptor, _) = selected_identity(&owner, true);
        value.source.files[0].identity.sha256 = "0".repeat(64);
        assert_ne!(
            value.source.files[0].identity,
            value.original_file.input.identity
        );
        let sha = save_identity_descriptor(&value, &descriptor);
        std::fs::remove_file(owner.0.join("unit.json")).unwrap();
        let output = owner.0.join("no.machine.json");
        let error = run_identity(&owner, &descriptor, &sha, &output).unwrap_err();
        assert!(
            error.message.contains("held original file bytes differ"),
            "{}",
            error.message
        );
        assert!(!output.exists());
    }
    #[test]
    fn identity_driver_refuses_missing_or_duplicate_origin_file_selection() {
        for duplicate in [false, true] {
            let owner = Owner::new();
            let (mut value, descriptor, _) = selected_identity(&owner, false);
            let expected = if duplicate {
                value.source.files.push(value.source.files[0].clone());
                assert_eq!(value.source.files.len(), 2);
                "selected identity-origin original file is duplicated"
            } else {
                value.original_file.file_id = u64::MAX;
                assert_ne!(value.original_file.file_id, value.source.files[0].id);
                "selected identity-origin original file is absent"
            };
            let sha = save_identity_descriptor(&value, &descriptor);
            std::fs::remove_file(owner.0.join("unit.json")).unwrap();
            let output = owner.0.join("no.machine.json");
            let error = run_identity(&owner, &descriptor, &sha, &output).unwrap_err();
            assert!(error.message.contains(expected), "{}", error.message);
            assert!(!output.exists());
        }
    }
    #[test]
    fn identity_driver_still_requires_the_selected_unit_floor() {
        let owner = Owner::new();
        let (_, descriptor, sha) = selected_identity(&owner, false);
        std::fs::remove_file(owner.0.join("unit.json")).unwrap();
        let output = owner.0.join("no.machine.json");
        let error = run_identity(&owner, &descriptor, &sha, &output).unwrap_err();
        assert!(
            error.message.contains("nofollow openat"),
            "{}",
            error.message
        );
        assert!(!output.exists());
    }
    #[test]
    fn identity_driver_preserves_complete_required_body_membership() {
        for mode in 0..3 {
            let owner = Owner::new();
            let (mut value, descriptor, _) = selected_identity(&owner, false);
            match mode {
                0 => value.body_inventories.clear(),
                1 => value
                    .body_inventories
                    .push(value.body_inventories[0].clone()),
                _ => value.body_inventories[0].body = 99,
            }
            assert!(
                value.body_inventories.is_empty()
                    || value.body_inventories.len() == 2
                    || value.body_inventories[0].body == 99
            );
            let sha = save_identity_descriptor(&value, &descriptor);
            let output = owner.0.join("no.machine.json");
            let error = run_identity(&owner, &descriptor, &sha, &output).unwrap_err();
            assert!(
                error.message.contains(
                    "duplicate, missing or extra required body selector before construction"
                ),
                "{}",
                error.message
            );
            assert!(!output.exists());
        }
    }
    #[test]
    fn identity_driver_refuses_symlink_original_input() {
        let owner = Owner::new();
        let (_, descriptor, sha) = selected_identity(&owner, true);
        let original = owner.0.join("original.S");
        std::fs::remove_file(&original).unwrap();
        std::os::unix::fs::symlink("source.s", &original).unwrap();
        assert!(std::fs::symlink_metadata(&original)
            .unwrap()
            .file_type()
            .is_symlink());
        let output = owner.0.join("no.machine.json");
        let error = run_identity(&owner, &descriptor, &sha, &output).unwrap_err();
        assert!(
            error.message.contains("nofollow openat"),
            "{}",
            error.message
        );
        assert!(!output.exists());
    }
    #[test]
    fn identity_driver_refuses_wrong_format_and_undeclared_authority_fields() {
        for unknown in [false, true] {
            let owner = Owner::new();
            let (selected, descriptor, _) = selected_identity(&owner, false);
            let mut value = serde_json::to_value(&selected).unwrap();
            let expected = if unknown {
                value["producer_authenticated"] = serde_json::json!(true);
                assert_eq!(value["producer_authenticated"], true);
                "selection JSON"
            } else {
                value["format"] = serde_json::json!(SELECTION_FORMAT);
                assert_ne!(value["format"], IDENTITY_SELECTION_FORMAT);
                "unsupported identity-original configured assembly selection format"
            };
            let raw = serde_json::to_vec(&value).unwrap();
            std::fs::write(&descriptor, &raw).unwrap();
            let output = owner.0.join("no.machine.json");
            let error =
                run_identity(&owner, &descriptor, &identity(&raw).sha256, &output).unwrap_err();
            assert!(error.message.contains(expected), "{}", error.message);
            assert!(!output.exists());
        }
    }
}
