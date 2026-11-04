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
        let members = [("zlib", "provider-zlib"), ("bzip2", "provider-bzip2"),
                       ("xz", "provider-xz")];
        items.insert("engine".to_owned(), FinalizerItem {
            recipe: serde_json::to_vec(&engine).unwrap(),
            dependencies: BTreeMap::new(),
            compound: [("compression".to_owned(), members.iter()
                .map(|(member, component)| ((*member).to_owned(), (*component).to_owned()))
                .collect())].into_iter().collect(),
        });
        for (member, component) in members {
            let recipe = json!({
                "schema": source_recipe::RECIPE_FORMAT,
                "source": {"fixture_original": member, "version": "DATA-only"},
                "dependencies": []
            });
            items.insert(component.to_owned(), FinalizerItem {
                recipe: serde_json::to_vec(&recipe).unwrap(),
                dependencies: BTreeMap::new(), compound: BTreeMap::new(),
            });
        }
        let components = items.iter().map(|(name, item)| {
            let recipe: Value = serde_json::from_slice(&item.recipe).unwrap();
            let mut compound = BTreeMap::<String, Value>::new();
            for (label, members) in &item.compound {
                let declaration = recipe["dependencies"].as_array().unwrap().iter()
                    .find(|declaration| declaration["name"].as_str() == Some(label.as_str()))
                    .expect("actual unchanged recipe declaration");
                let expected = members.iter().map(|(member, provider)| {
                    let provider_recipe: Value =
                        serde_json::from_slice(&items[provider].recipe).unwrap();
                    (member.clone(), provider_recipe["source"].clone())
                }).collect::<BTreeMap<_, _>>();
                compound.insert(label.clone(), json!({
                    "declaration": declaration, "members": expected,
                }));
            }
            json!({"component": name,
                   "recipe": {"bytes": item.recipe.len(), "sha256": finalizer_sha(&item.recipe)},
                   "compound_dependencies": compound})
        }).collect::<Vec<_>>();
        let raw_policy = serde_json::to_vec(&json!({
            "schema": "ocore-original-provider-membership-v1", "components": components,
        })).unwrap();
        let path = directory.path().join("independently-selected-membership.json");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&path).unwrap();
        file.write_all(&raw_policy).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let pin = provider_order::OrderPin {
            path, bytes: raw_policy.len() as u64, sha256: finalizer_sha(&raw_policy),
        };
        Self { directory, items, pin, raw_policy }
    }

    fn select(&self) -> provider_membership::SelectedMembership {
        let inputs = self.items.iter().map(|(name, item)| provider_membership::Input {
            name, recipe: &item.recipe, dependencies: &item.dependencies,
            compound: &item.compound,
        }).collect::<Vec<_>>();
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
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
            .open(&path).unwrap();
        file.write_all(&raw).unwrap();
        file.sync_all().unwrap();
        let package = Some(json!({"path": path, "bytes": raw.len(),
                                  "sha256": finalizer_sha(&raw), "format": whole_artifact::FORMAT_V5}));
        (output, path, raw, package)
    }
}

include!("provider_membership_placement_cases.rs");
