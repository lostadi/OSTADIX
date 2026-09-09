//! ONative owner handles through real OIR dispatch and Python shim processes.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use o_lang::eval::migration::migrate_persistent_actors;
use o_lang::eval::{Evaluator, PreparedPlacementFragmentV2};
use o_lang::parser::Parser;
use o_lang::placement::{GenerationV1, SemanticDigestV1, TaskAttemptIdV1};
use o_lang::value::{NativeCodecSafety, OValue, RehydratePolicy};

struct Fixture {
    _root: tempfile::TempDir,
    shims: PathBuf,
    runtime: PathBuf,
    backends: HashSet<String>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let shims = root.path().join("backends");
        fs::create_dir(&shims)?;
        for (name, bytes) in o_lang::shims::read_shims(None)? {
            fs::write(shims.join(name), bytes)?;
        }
        let runtime = root.path().join("O-native-test");
        fs::copy(env!("CARGO_BIN_EXE_O"), &runtime)?;
        Ok(Self {
            _root: root,
            shims,
            runtime,
            backends: HashSet::from(["python".into()]),
        })
    }

    fn evaluator(&self) -> Evaluator {
        Evaluator::new(self.shims.clone())
            .with_registered_backends(self.backends.clone())
            .with_runtime_executable(self.runtime.clone())
    }

    fn eval(
        &self,
        evaluator: &mut Evaluator,
        source: &str,
        scope: &mut HashMap<String, OValue>,
    ) -> Result<OValue> {
        evaluator.eval_document_with_scope(Parser::new(source, &self.backends).parse()?, scope)
    }

    fn target(&self, evaluator: &mut Evaluator) -> Result<PreparedPlacementFragmentV2> {
        evaluator.prepare_placement_fragment(
            "python[7]^(raise RuntimeError('restore must not execute this body'))_python[7]",
            TaskAttemptIdV1::new(
                SemanticDigestV1::hash_bytes("ostadix/native-migration-test/v1", b"target"),
                GenerationV1::new(1)?,
            ),
        )
    }
}

const LIMIT: u64 = 4 * 1024 * 1024;

#[test]
fn native_descriptor_round_trips_through_oir_and_a_foreign_python_actor() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut evaluator = fixture.evaluator();
    let mut scope = HashMap::new();
    let handle = fixture.eval(&mut evaluator,
        "let handle = python[7]^(shared = []\nshared.append(shared)\nvalue = {'left': shared, 'right': shared, 'function': (lambda: 42)}\nO.native(value))_python[7]\n$handle",
        &mut scope)?;
    let OValue::Native { v } = &handle else {
        panic!("not an ONative handle: {handle:?}")
    };
    assert_eq!(v.safety, NativeCodecSafety::LiveHandle);
    assert_eq!(v.rehydrate, RehydratePolicy::SameProcess);
    assert!(v.identity.stable.is_none() && v.identity.live.is_some() && v.payload.is_none());
    assert!(!handle.is_cache_safe() && !handle.is_replay_safe() && !handle.is_boot_persistable());
    let carried = fixture.eval(&mut evaluator, "python[8]^($handle)_python[8]", &mut scope)?;
    assert_eq!(carried, handle);
    let resolved = fixture.eval(&mut evaluator,
        "python[7]^(resolved = O.resolve_native($handle)\nresolved is value and resolved['left'] is resolved['right'] and resolved['left'][0] is resolved['left'] and resolved['function']() == 42)_python[7]",
        &mut scope)?;
    assert_eq!(resolved, OValue::bool_(true));
    let error = fixture
        .eval(
            &mut evaluator,
            "python[8]^(O.resolve_native($handle))_python[8]",
            &mut scope,
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("native.owner-mismatch"),
        "{error:#}"
    );
    Ok(())
}

#[test]
fn live_handle_blocks_migration_without_killing_its_owner() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut source = fixture.evaluator();
    let mut destination = fixture.evaluator();
    let mut scope = HashMap::new();
    fixture.eval(
        &mut source,
        "let handle = python[7]^(O.native(lambda: 42))_python[7]\n$handle",
        &mut scope,
    )?;
    let target = fixture.target(&mut destination)?;
    let error =
        migrate_persistent_actors(&mut source, &mut destination, vec![target], LIMIT).unwrap_err();
    assert!(
        format!("{error:#}").contains("$native_handles"),
        "{error:#}"
    );
    assert!(destination
        .checkpoint_persistent_actors(LIMIT)?
        .actors
        .is_empty());
    assert_eq!(
        fixture.eval(
            &mut source,
            "python[7]^(O.resolve_native($handle)())_python[7]",
            &mut scope
        )?,
        OValue::int(42)
    );
    Ok(())
}

#[test]
fn release_unpins_portable_actor_state_for_real_migration() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut source = fixture.evaluator();
    let mut destination = fixture.evaluator();
    let mut scope = HashMap::new();
    fixture.eval(
        &mut source,
        "let handle = python[7]^(values = [20, 22]\nO.native(values))_python[7]\n$handle",
        &mut scope,
    )?;
    assert!(source.checkpoint_persistent_actors(LIMIT).is_err());
    fixture.eval(
        &mut source,
        "python[7]^(O.release_native($handle))_python[7]",
        &mut scope,
    )?;
    let target = fixture.target(&mut destination)?;
    let receipt = migrate_persistent_actors(&mut source, &mut destination, vec![target], LIMIT)?;
    assert!(receipt.source_shutdown_failures.is_empty());
    assert_eq!(
        fixture.eval(
            &mut destination,
            "python[7]^(sum(values))_python[7]",
            &mut HashMap::new()
        )?,
        OValue::int(42)
    );
    Ok(())
}

#[test]
fn fresh_actor_handle_expires_visibly_after_its_exporting_block_finishes() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut evaluator = fixture.evaluator();
    let mut scope = HashMap::new();
    let error = fixture.eval(&mut evaluator,
        "let handle = python^(O.native(lambda: 42))_python\npython^(O.resolve_native($handle)())_python",
        &mut scope).unwrap_err();
    assert!(
        format!("{error:#}").contains("native.owner-mismatch"),
        "{error:#}"
    );
    Ok(())
}
