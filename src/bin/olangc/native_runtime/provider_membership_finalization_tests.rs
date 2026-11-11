//! SOURCE ONLY: controls for the production finalizer and real held-policy API.
//! The object outcome and package bytes are explicitly inert DATA fixtures.
//! No compiler, native child, original engine or artifact admission is exercised.
use super::*;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

fn finalizer_sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

struct FinalizerItem {
    recipe: Vec<u8>,
    dependencies: BTreeMap<String, String>,
    compound: provider_membership::CompoundBindings,
}

struct FinalizerFixture {
    directory: tempfile::TempDir,
    items: BTreeMap<String, FinalizerItem>,
    pin: provider_order::OrderPin,
    raw_policy: Vec<u8>,
}

impl FinalizerFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create owned inert policy fixture");
        let mut items = BTreeMap::new();
        let engine = json!({
            "schema": source_recipe::RECIPE_FORMAT,
            "source": {"fixture_original": "engine"},
            "dependencies": [{"name": "compression", "source_pin": null,
                              "fixture_role": "unchanged"}]
        });
        let members = [
            ("zlib", "provider-zlib"),
            ("bzip2", "provider-bzip2"),
            ("xz", "provider-xz"),
        ];
        items.insert(
            "engine".to_owned(),
            FinalizerItem {
                recipe: serde_json::to_vec(&engine).unwrap(),
                dependencies: BTreeMap::new(),
                compound: [(
                    "compression".to_owned(),
                    members
                        .iter()
                        .map(|(member, component)| ((*member).to_owned(), (*component).to_owned()))
                        .collect(),
                )]
                .into_iter()
                .collect(),
            },
        );
        for (member, component) in members {
            let recipe = json!({
                "schema": source_recipe::RECIPE_FORMAT,
                "source": {"fixture_original": member, "version": "DATA-only"},
                "dependencies": []
            });
            items.insert(
                component.to_owned(),
                FinalizerItem {
                    recipe: serde_json::to_vec(&recipe).unwrap(),
                    dependencies: BTreeMap::new(),
                    compound: BTreeMap::new(),
                },
            );
        }
        let components = items
            .iter()
            .map(|(name, item)| {
                let recipe: Value = serde_json::from_slice(&item.recipe).unwrap();
                let mut compound = BTreeMap::<String, Value>::new();
                for (label, members) in &item.compound {
                    let declaration = recipe["dependencies"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|declaration| declaration["name"].as_str() == Some(label.as_str()))
                        .expect("actual unchanged recipe declaration");
                    let expected = members
                        .iter()
                        .map(|(member, provider)| {
                            let provider_recipe: Value =
                                serde_json::from_slice(&items[provider].recipe).unwrap();
                            (member.clone(), provider_recipe["source"].clone())
                        })
                        .collect::<BTreeMap<_, _>>();
                    compound.insert(
                        label.clone(),
                        json!({
                            "declaration": declaration, "members": expected,
                        }),
                    );
                }
                json!({"component": name,
                   "recipe": {"bytes": item.recipe.len(), "sha256": finalizer_sha(&item.recipe)},
                   "compound_dependencies": compound})
            })
            .collect::<Vec<_>>();
        let raw_policy = serde_json::to_vec(&json!({
            "schema": "ocore-original-provider-membership-v1", "components": components,
        }))
        .unwrap();
        let path = directory
            .path()
            .join("independently-selected-membership.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&raw_policy).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let pin = provider_order::OrderPin {
            path,
            bytes: raw_policy.len() as u64,
            sha256: finalizer_sha(&raw_policy),
        };
        Self {
            directory,
            items,
            pin,
            raw_policy,
        }
    }

    fn select(&self) -> provider_membership::SelectedMembership {
        let inputs = self
            .items
            .iter()
            .map(|(name, item)| provider_membership::Input {
                name,
                recipe: &item.recipe,
                dependencies: &item.dependencies,
                compound: &item.compound,
            })
            .collect::<Vec<_>>();
        provider_membership::SelectedMembership::read(&self.pin, &inputs)
            .expect("real independent four-component membership selection")
    }

    fn ir_fixture(&self) -> (PathBuf, PathBuf, Vec<u8>, Option<Value>) {
        let output = self.directory.path().join("finalizer-output");
        fs::create_dir(&output).unwrap();
        let path = output.join(whole_artifact::FILE_NAME);
        // The finalizer consumes the existence/metadata of this product, not its
        // NativeModule body. These bytes make no artifact-validity claim.
        let raw = b"{\"inert_finalizer_package\":true,\"qualified\":false}\n".to_vec();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(&raw).unwrap();
        file.sync_all().unwrap();
        let package = Some(json!({"path": path, "bytes": raw.len(),
                                  "sha256": finalizer_sha(&raw), "format": whole_artifact::FORMAT_V5}));
        (output, path, raw, package)
    }
}

#[test]
fn v5_finalizer_revokes_root_ir_after_reached_same_bytes_policy_replacement() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let (output, ir_path, ir_bytes, mut package) = fixture.ir_fixture();
    let mut ir_complete = true;
    assert_eq!(fs::read(&ir_path).unwrap(), ir_bytes);
    assert!(package.is_some());
    let before = fs::metadata(&fixture.pin.path).unwrap();
    let before_bytes = fs::read(&fixture.pin.path).unwrap();
    assert_eq!(before_bytes, fixture.raw_policy);
    let before_sha = finalizer_sha(&before_bytes);

    let mut object_hook_fired = false;
    // Explicitly INERT object-result hook: no object compiler or child exists.
    let object_result: std::result::Result<(), &'static str> = {
        object_hook_fired = true;
        let replacement = fixture.directory.path().join("replacement-membership.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&replacement)
            .unwrap();
        file.write_all(&before_bytes).unwrap();
        file.set_permissions(before.permissions()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::rename(&replacement, &fixture.pin.path).unwrap();
        Err("INERT known object-lowering failure; no process was started")
    };
    assert!(object_hook_fired);
    assert_eq!(
        object_result,
        Err("INERT known object-lowering failure; no process was started")
    );
    let after = fs::metadata(&fixture.pin.path).unwrap();
    let after_bytes = fs::read(&fixture.pin.path).unwrap();
    assert_eq!(before.dev(), after.dev());
    assert_ne!(before.ino(), after.ino());
    assert_eq!(before.mode() & 0o7777, after.mode() & 0o7777);
    assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
    assert_eq!(before_bytes, after_bytes);
    assert_eq!(before_sha, finalizer_sha(&after_bytes));
    assert!(
        ir_path.is_file(),
        "actual root product exists before finalization"
    );

    let original_issue = format!(
        "source-group object re-emission: {}",
        object_result.unwrap_err()
    );
    let mut issues = vec![original_issue.clone()];
    let actual_check_reached = Cell::new(false);
    finalize_membership_custody(&output, &mut package, &mut ir_complete, &mut issues, || {
        actual_check_reached.set(true);
        selected.check_unchanged()
    })
    .expect("recorded custody rejection is not a successful-revocation I/O error");
    assert!(actual_check_reached.get());
    assert!(package.is_none());
    assert!(!ir_complete);
    assert!(!ir_path.exists());
    assert_eq!(issues.len(), 2);
    assert_eq!(issues[0], original_issue);
    assert!(issues[1].starts_with("V5 final source-group custody failed"));
    assert!(issues[1].ends_with("membership policy physical identity changed"));
    assert_eq!(fs::read(&fixture.pin.path).unwrap(), fixture.raw_policy);
}

#[test]
fn v5_finalizer_retains_valid_root_ir_for_object_error_with_unchanged_policy() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let (output, ir_path, ir_bytes, mut package) = fixture.ir_fixture();
    let original_package = package.clone();
    let mut ir_complete = true;
    let before = fs::metadata(&fixture.pin.path).unwrap();
    let mut object_hook_fired = false;
    let object_result: std::result::Result<(), &'static str> = {
        object_hook_fired = true;
        Err("INERT known object-lowering failure; no process was started")
    };
    assert!(object_hook_fired);
    assert_eq!(
        object_result,
        Err("INERT known object-lowering failure; no process was started")
    );
    let original_issue = format!(
        "source-group object re-emission: {}",
        object_result.unwrap_err()
    );
    let mut issues = vec![original_issue.clone()];
    let actual_check_reached = Cell::new(false);
    finalize_membership_custody(&output, &mut package, &mut ir_complete, &mut issues, || {
        actual_check_reached.set(true);
        selected.check_unchanged()
    })
    .expect("unchanged real selected membership must preserve the IR product");
    assert!(actual_check_reached.get());
    assert!(ir_complete);
    assert_eq!(package, original_package);
    assert_eq!(issues, vec![original_issue]);
    assert_eq!(fs::read(&ir_path).unwrap(), ir_bytes);
    let after = fs::metadata(&fixture.pin.path).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(before.mode() & 0o7777, after.mode() & 0o7777);
    assert_eq!(fs::read(&fixture.pin.path).unwrap(), fixture.raw_policy);
}
