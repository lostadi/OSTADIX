// Included after the unchanged inert FinalizerFixture definitions. These are
// callbacks through the actual production helpers; no native process exists.
fn replace_placement_policy(fixture: &FinalizerFixture) {
    let before = fs::metadata(&fixture.pin.path).unwrap();
    let raw = fs::read(&fixture.pin.path).unwrap();
    assert_eq!(raw, fixture.raw_policy);
    let replacement = fixture.directory.path().join("placement-replacement.json");
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&replacement).unwrap();
    file.write_all(&raw).unwrap();
    file.set_permissions(before.permissions()).unwrap();
    file.sync_all().unwrap();
    drop(file);
    fs::rename(&replacement, &fixture.pin.path).unwrap();
    let after = fs::metadata(&fixture.pin.path).unwrap();
    assert_eq!(before.dev(), after.dev());
    assert_ne!(before.ino(), after.ino(), "actual atomic replacement must occur");
    assert_eq!(before.mode(), after.mode());
    assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
    assert_eq!(raw, fs::read(&fixture.pin.path).unwrap());
    assert_eq!(finalizer_sha(&raw), finalizer_sha(&fs::read(&fixture.pin.path).unwrap()));
}

#[test]
fn early_preparation_error_still_finalizes_real_changed_membership() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let (output, root, raw, mut package) = fixture.ir_fixture();
    let mut ir_complete = true;
    let mut object_complete = false;
    let mut issues = Vec::new();
    let preparations = Cell::new(0);
    let emissions = Cell::new(0);
    let object_guards = Cell::new(0);
    let final_guards = Cell::new(0);
    assert!(root.is_file());
    run_object_phase(&output, &mut package, &mut ir_complete, &mut object_complete,
        &mut issues, true,
        || -> Result<()> {
            preparations.set(preparations.get() + 1);
            replace_placement_policy(&fixture);
            assert_eq!(fs::read(&root).unwrap(), raw);
            bail!("INERT original early object preparation error")
        },
        |_| { emissions.set(emissions.get() + 1); Ok(()) },
        || { object_guards.set(object_guards.get() + 1); Ok(()) },
        Some(|| {
            final_guards.set(final_guards.get() + 1);
            selected.check_unchanged()
        }),
    ).unwrap();
    assert_eq!((preparations.get(), emissions.get(), object_guards.get(), final_guards.get()), (1, 0, 1, 1));
    assert!(!object_complete && !ir_complete && package.is_none());
    assert!(!root.exists());
    assert_eq!(issues.len(), 2);
    assert_eq!(issues[0], "source-group object re-emission: INERT original early object preparation error");
    assert!(issues[1].ends_with("membership policy physical identity changed"));
}

#[test]
fn unchanged_policy_preserves_ordinary_preparation_and_emission_errors() {
    for preparation_error in [true, false] {
        let fixture = FinalizerFixture::new();
        let selected = fixture.select();
        let (output, root, raw, mut package) = fixture.ir_fixture();
        let original_package = package.clone();
        let mut ir_complete = true;
        let mut object_complete = false;
        let mut issues = Vec::new();
        let preparations = Cell::new(0);
        let emissions = Cell::new(0);
        let final_guards = Cell::new(0);
        run_object_phase(&output, &mut package, &mut ir_complete, &mut object_complete,
            &mut issues, true,
            || -> Result<()> {
                preparations.set(preparations.get() + 1);
                if preparation_error { bail!("INERT unchanged-policy preparation error"); }
                Ok(())
            },
            |_| { emissions.set(emissions.get() + 1); bail!("INERT unchanged-policy emission error") },
            || Ok(()),
            Some(|| { final_guards.set(final_guards.get() + 1); selected.check_unchanged() }),
        ).unwrap();
        assert_eq!(preparations.get(), 1);
        assert_eq!(emissions.get(), if preparation_error { 0 } else { 1 });
        assert_eq!(final_guards.get(), 1);
        assert!(ir_complete && !object_complete);
        assert_eq!(package, original_package);
        assert_eq!(fs::read(&root).unwrap(), raw);
        assert_eq!(issues, vec![if preparation_error {
            "source-group object re-emission: INERT unchanged-policy preparation error"
        } else { "source-group object re-emission: INERT unchanged-policy emission error" }]);
    }
}

#[test]
fn successful_object_callbacks_preserve_exact_phase_result() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let (output, root, raw, mut package) = fixture.ir_fixture();
    let mut ir_complete = true;
    let mut object_complete = false;
    let mut issues = Vec::new();
    let emitted = Cell::new(0);
    let final_guards = Cell::new(0);
    run_object_phase(&output, &mut package, &mut ir_complete, &mut object_complete,
        &mut issues, true, || Ok(37u32),
        |prepared| { assert_eq!(prepared, 37); emitted.set(emitted.get() + 1); Ok(()) },
        || Ok(()), Some(|| { final_guards.set(final_guards.get() + 1); selected.check_unchanged() }),
    ).unwrap();
    assert_eq!((emitted.get(), final_guards.get()), (1, 1));
    assert!(ir_complete && object_complete && package.is_some() && issues.is_empty());
    assert_eq!(fs::read(&root).unwrap(), raw);
}

#[test]
fn ir_only_phase_finalizes_without_preparing_or_emitting() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let (output, root, raw, mut package) = fixture.ir_fixture();
    let mut ir_complete = true;
    let mut object_complete = false;
    let mut issues = Vec::new();
    let phase_calls = Cell::new(0);
    let final_guards = Cell::new(0);
    run_object_phase(&output, &mut package, &mut ir_complete, &mut object_complete,
        &mut issues, false,
        || { phase_calls.set(phase_calls.get() + 1); Ok(()) },
        |_| { phase_calls.set(phase_calls.get() + 1); Ok(()) },
        || { phase_calls.set(phase_calls.get() + 1); Ok(()) },
        Some(|| { final_guards.set(final_guards.get() + 1); selected.check_unchanged() }),
    ).unwrap();
    assert_eq!((phase_calls.get(), final_guards.get()), (0, 1));
    assert!(ir_complete && !object_complete && package.is_some() && issues.is_empty());
    assert_eq!(fs::read(&root).unwrap(), raw);
}

#[test]
fn detached_published_callback_error_still_checks_and_revokes() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let output = fixture.directory.path().join("detached-output");
    fs::create_dir(&output).unwrap();
    let root = output.join(whole_artifact::FILE_NAME);
    assert!(!root.exists());
    let callbacks = Cell::new(0);
    let guards = Cell::new(0);
    let error = run_detached_readmission(Some(&selected), &output,
        || {
            callbacks.set(callbacks.get() + 1);
            fs::write(&root, b"INERT published detached DATA").unwrap();
            assert_eq!(fs::read(&root).unwrap(), b"INERT published detached DATA");
            replace_placement_policy(&fixture);
            bail!("INERT original detached callback error")
        },
        || { guards.set(guards.get() + 1); selected.check_unchanged() },
    ).unwrap_err();
    assert_eq!((callbacks.get(), guards.get()), (1, 1));
    assert_eq!(error.root_cause().to_string(), "INERT original detached callback error");
    assert!(format!("{error:#}").contains("V5 outer readmission custody also failed: membership policy physical identity changed"));
    assert!(!root.exists());
}

#[test]
fn detached_unchanged_error_and_legacy_success_only_guard_keep_original_outcome() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let output = fixture.directory.path().join("ordinary-detached-output");
    fs::create_dir(&output).unwrap();
    let root = output.join(whole_artifact::FILE_NAME);
    fs::write(&root, b"INERT partial result; no acceptance claim").unwrap();
    let guards = Cell::new(0);
    let error = run_detached_readmission(Some(&selected), &output,
        || { bail!("INERT unchanged-policy inner error") },
        || { guards.set(guards.get() + 1); selected.check_unchanged() },
    ).unwrap_err();
    assert_eq!(guards.get(), 1);
    assert_eq!(error.to_string(), "INERT unchanged-policy inner error");
    assert!(error.chain().nth(1).is_none());
    assert_eq!(fs::read(&root).unwrap(), b"INERT partial result; no acceptance claim");
    let legacy_guards = Cell::new(0);
    let error = run_detached_readmission(None, &output,
        || { bail!("INERT legacy inner error") },
        || { legacy_guards.set(legacy_guards.get() + 1); Ok(()) },
    ).unwrap_err();
    assert_eq!(legacy_guards.get(), 0);
    assert_eq!(error.to_string(), "INERT legacy inner error");
    run_detached_readmission(None, &output, || Ok(()),
        || { legacy_guards.set(legacy_guards.get() + 1); Ok(()) }).unwrap();
    assert_eq!(legacy_guards.get(), 1);
}

#[test]
fn actual_root_product_faults_revoke_ir_and_selected_descriptor() {
    for fault in ["absent", "changed", "symlink", "descriptor-path", "descriptor-length", "descriptor-sha"] {
        let fixture = FinalizerFixture::new();
        let selected = fixture.select();
        let (output, root, raw, mut package) = fixture.ir_fixture();
        let target = fixture.directory.path().join("unrelated-symlink-target");
        fs::write(&target, &raw).unwrap();
        let reason = match fault {
            "absent" => { fs::remove_file(&root).unwrap(); assert!(!root.exists()); "published source group is absent" },
            "changed" => { fs::write(&root, b"changed actual DATA").unwrap(); assert_ne!(fs::read(&root).unwrap(), raw); "published source-group bytes differ" },
            "symlink" => { fs::remove_file(&root).unwrap(); std::os::unix::fs::symlink(&target, &root).unwrap();
                assert!(fs::symlink_metadata(&root).unwrap().file_type().is_symlink()); "published source group is not a regular file" },
            "descriptor-path" => { package.as_mut().unwrap()["path"] = json!(target); assert_eq!(package.as_ref().unwrap()["path"], json!(target)); "published source-group descriptor path differs" },
            "descriptor-length" => { package.as_mut().unwrap()["bytes"] = json!(raw.len() + 1); assert_eq!(package.as_ref().unwrap()["bytes"], raw.len() + 1); "published source-group bytes differ" },
            "descriptor-sha" => { package.as_mut().unwrap()["sha256"] = json!("0".repeat(64)); assert_ne!(package.as_ref().unwrap()["sha256"], finalizer_sha(&raw)); "published source-group bytes differ" },
            _ => unreachable!(),
        };
        let mut ir_complete = true;
        let mut issues = Vec::new();
        let guards = Cell::new(0);
        finalize_membership_custody(&output, &mut package, &mut ir_complete, &mut issues,
            || { guards.set(guards.get() + 1); selected.check_unchanged() }).unwrap();
        assert_eq!(guards.get(), 1);
        assert!(!ir_complete && package.is_none());
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains(reason), "fault {fault}: {issues:?}");
        assert!(!root.exists());
        assert_eq!(fs::read(&target).unwrap(), raw, "revocation must not remove a symlink target");
    }
}

#[test]
fn detached_cleanup_failure_keeps_inner_and_custody_error_context() {
    let fixture = FinalizerFixture::new();
    let selected = fixture.select();
    let output = fixture.directory.path().join("detached-cleanup-error");
    fs::create_dir(&output).unwrap();
    let root = output.join(whole_artifact::FILE_NAME);
    let guards = Cell::new(0);
    let error = run_detached_readmission(Some(&selected), &output,
        || {
            fs::create_dir(&root).unwrap(); assert!(root.is_dir());
            replace_placement_policy(&fixture);
            bail!("INERT inner error retained across cleanup failure")
        },
        || { guards.set(guards.get() + 1); selected.check_unchanged() },
    ).unwrap_err();
    assert_eq!(guards.get(), 1);
    assert!(root.is_dir(), "failed cleanup retains actual failed-state evidence");
    let text = format!("{error:#}");
    assert!(text.contains("cannot revoke V5 readmission package"));
    assert!(text.contains("membership policy physical identity changed"));
    assert_eq!(error.root_cause().to_string(), "INERT inner error retained across cleanup failure");
}
