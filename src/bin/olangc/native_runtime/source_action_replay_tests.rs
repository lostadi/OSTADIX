// Authored post-verifier DATA controls. No actual replay, capture admission,
// original Rust compiler, native output discovery or execution is established.
fn rust_action_replay_fixture(count: usize) -> (Value, BTreeSet<String>, Vec<Vec<u8>>) {
    assert!(count > 0);
    let (mut capture, _) = fixture();
    let template = capture["units"][0].clone();
    let source = template["source"].clone();
    let raw = (0..count)
        .map(|index| format!("authored Rust replay {index}").into_bytes())
        .collect::<Vec<_>>();
    let mut units = Vec::new();
    for (index, bytes) in raw.iter().enumerate() {
        let mut unit = template.clone();
        unit["id"] = json!(format!("action-1:{index}"));
        unit["kind"] = json!("rustc");
        unit["producer"] = json!("rustc-llvm-v1");
        unit["frontend_version"] = json!("authored rustc version");
        unit["dependencies"] = json!([source.clone()]);
        unit["ir"]["path"] = json!(format!("/capture/rust-replay/library.codegen-{index}.ll"));
        unit["ir"]["sha256"] = json!(digest(bytes));
        unit["ir"]["bytes"] = json!(bytes.len());
        unit["ir"]["format"] = json!("llvm-text");
        for key in ["replay_argv", "replay_exit_code", "saved_cgu_index", "capture_policy"] {
            unit.as_object_mut().unwrap().remove(key);
        }
        units.push(unit);
    }
    let action = &mut capture["invocations"][0];
    action["producer"] = json!("rustc-llvm-v1");
    action["kind"] = json!("rustc");
    action["driver_kind"] = json!("rustc");
    action["compiler"] = json!("/tool/rustc");
    action["frontend"]["version"] = json!("authored rustc version");
    action["sources"] = json!([source]);
    action["argv"] = json!(["--crate-name", "library", "src/lib.rs", "--crate-type", "rlib"]);
    action["replay_argv"] = json!(["/tool/rustc", "--crate-name", "library", "src/lib.rs",
        "--crate-type", "rlib", "--emit=llvm-ir,dep-info", "--out-dir", "/capture/rust-replay"]);
    action["replay_exit_code"] = json!(0);
    for key in ["rust_capture", "saved_cgus", "rust_native_resources", "executed_argv"] {
        action.as_object_mut().unwrap().remove(key);
    }
    action["units"] = json!(units);
    let selected = sync_producer_units(&mut capture);
    (capture, selected, raw)
}

#[test]
fn rust_action_replay_multiple_units_share_only_the_actual_owner_command() {
    let (capture, selected, raw) = rust_action_replay_fixture(2);
    let owner = bind(&capture, &selected).unwrap();
    assert_eq!(owner.units.len(), 2);
    let mut evidence_owners = Vec::new();
    let mut names = Vec::new();
    for (index, bytes) in raw.iter().enumerate() {
        let unit = &capture["units"][index];
        assert!(unit.get("replay_argv").is_none() && unit.get("replay_exit_code").is_none());
        let input = &owner.units[unit["id"].as_str().unwrap()].input;
        let ProducerInput::ActionFrontendReplay { evidence, emitted_filename, .. } = input else {
            panic!("actual owning-action replay contract not selected")
        };
        assert_eq!(evidence.action, capture["invocations"][0]);
        assert_eq!(evidence.replay_argv, strings(&capture["invocations"][0]["replay_argv"], "authored replay").unwrap());
        assert_eq!(emitted_filename, &format!("library.codegen-{index}.ll"));
        input.check_consumed(&capture["invocations"][0], unit, bytes).unwrap();
        evidence_owners.push(std::sync::Arc::clone(evidence));
        names.push(emitted_filename.clone());
    }
    assert!(std::sync::Arc::ptr_eq(&evidence_owners[0], &evidence_owners[1]));
    assert_ne!(names[0], names[1]);
}

#[test]
fn rust_action_replay_requires_the_actual_successful_action_status_and_argv() {
    for mutation in ["status_missing", "status_nonzero", "status_boolean", "argv_missing", "argv_empty"] {
        let (mut capture, selected, _) = rust_action_replay_fixture(2);
        let action = &mut capture["invocations"][0];
        let reason = match mutation {
            "status_missing" => {
                assert!(action.as_object_mut().unwrap().remove("replay_exit_code").is_some());
                assert!(action.get("replay_exit_code").is_none());
                "did not complete successfully"
            }
            "status_nonzero" => {
                action["replay_exit_code"] = json!(7);
                assert_eq!(action["replay_exit_code"], 7);
                "did not complete successfully"
            }
            "status_boolean" => {
                action["replay_exit_code"] = json!(false);
                assert_eq!(action["replay_exit_code"], false);
                "did not complete successfully"
            }
            "argv_missing" => {
                assert!(action.as_object_mut().unwrap().remove("replay_argv").is_some());
                assert!(action.get("replay_argv").is_none());
                "action-scoped Rust frontend replay argv must be an array"
            }
            "argv_empty" => {
                action["replay_argv"] = json!([]);
                assert!(action["replay_argv"].as_array().unwrap().is_empty());
                "registered output contract"
            }
            _ => unreachable!(),
        };
        error(&capture, &selected, reason);
    }
}

#[test]
fn rust_action_replay_rejects_changed_command_and_noncanonical_output_contracts() {
    for mutation in ["compiler", "extra_emit", "single_output", "directory_relative", "directory_parent"] {
        let (mut capture, selected, _) = rust_action_replay_fixture(2);
        let before = capture["invocations"][0]["replay_argv"].clone();
        let argv = capture["invocations"][0]["replay_argv"].as_array_mut().unwrap();
        let reason = match mutation {
            "compiler" => { argv[0] = json!("/tool/another-rustc"); "registered output contract" }
            "extra_emit" => { argv.insert(1, json!("--emit=llvm-bc")); "registered output contract" }
            "single_output" => { argv.insert(1, json!("-oother.ll")); "registered output contract" }
            "directory_relative" => { *argv.last_mut().unwrap() = json!("relative"); "not canonical and absolute" }
            "directory_parent" => { *argv.last_mut().unwrap() = json!("/capture/other/../rust-replay"); "not canonical and absolute" }
            _ => unreachable!(),
        };
        assert_ne!(capture["invocations"][0]["replay_argv"], before, "{mutation}");
        error(&capture, &selected, reason);
    }
}

#[test]
fn rust_action_replay_rejects_injected_per_unit_replay_fields() {
    for field in ["replay_argv", "replay_exit_code"] {
        let (mut capture, _, _) = rust_action_replay_fixture(2);
        let value = if field == "replay_argv" { json!(["/tool/rustc", "invented-unit-replay"]) } else { json!(0) };
        capture["invocations"][0]["units"][1][field] = value.clone();
        let selected = sync_producer_units(&mut capture);
        assert_eq!(capture["units"][1][field], value);
        assert!(has_replay(&capture["units"][1]));
        error(&capture, &selected, "cannot invent a per-unit command");
    }
}

#[test]
fn rust_action_replay_rejects_missing_ambiguous_or_unowned_emitted_outputs() {
    for mutation in ["missing_ir", "ambiguous_filename", "outside_directory", "wrong_format"] {
        let (mut capture, _, _) = rust_action_replay_fixture(2);
        let before = capture["invocations"][0]["units"][1].clone();
        let reason = match mutation {
            "missing_ir" => {
                assert!(capture["invocations"][0]["units"][1].as_object_mut().unwrap().remove("ir").is_some());
                "path"
            }
            "ambiguous_filename" => {
                capture["invocations"][0]["units"][1]["ir"]["path"] = capture["invocations"][0]["units"][0]["ir"]["path"].clone();
                "output selector is ambiguous"
            }
            "outside_directory" => {
                capture["invocations"][0]["units"][1]["ir"]["path"] = json!("/capture/other/library.codegen-1.ll");
                "outside its owning LLVM output directory"
            }
            "wrong_format" => {
                capture["invocations"][0]["units"][1]["ir"]["format"] = json!("llvm-bitcode");
                "outside its owning LLVM output directory"
            }
            _ => unreachable!(),
        };
        let selected = sync_producer_units(&mut capture);
        assert_ne!(capture["units"][1], before, "{mutation}");
        assert_eq!(capture["units"].as_array().unwrap().len(), 2);
        error(&capture, &selected, reason);
    }
}

#[test]
fn rust_action_replay_rejects_unit_producer_frontend_source_or_policy_substitution() {
    for field in ["producer", "kind", "frontend_version", "source", "capture_policy"] {
        let (mut capture, _, _) = rust_action_replay_fixture(2);
        let value = match field {
            "source" => json!({"path":"/not-an-action-source.rs","sha256":"e".repeat(64),"bytes":12}),
            "capture_policy" => json!("unknown-replay-policy"),
            _ => json!("different-original-owner"),
        };
        capture["invocations"][0]["units"][1][field] = value.clone();
        let selected = sync_producer_units(&mut capture);
        assert_eq!(capture["units"][1][field], value);
        error(&capture, &selected, "unit producer/frontend/source/policy differs from owner");
    }
}

#[test]
fn rust_action_replay_does_not_fall_back_when_native_evidence_is_injected() {
    for field in ["rust_capture", "saved_cgus", "rust_native_resources", "executed_argv"] {
        let (mut capture, selected, _) = rust_action_replay_fixture(2);
        let value = if field == "rust_capture" { json!({"policy":"unexpected-native-policy"}) } else { json!(["authored contradiction"]) };
        capture["invocations"][0][field] = value.clone();
        assert_eq!(capture["invocations"][0][field], value);
        error(&capture, &selected, "cannot substitute native-edge or executed-command evidence");
    }
}

#[test]
fn rust_action_replay_rechecks_the_complete_action_before_consuming_any_unit() {
    for field in ["replay_argv", "argv", "outputs"] {
        let (capture, selected, raw) = rust_action_replay_fixture(2);
        let mut owner = bind(&capture, &selected).unwrap();
        let value = if field == "outputs" { json!([{"path":"/injected/native-output.o","sha256":"f".repeat(64),"bytes":1}]) } else { json!(["changed-owning-command"]) };
        let unit_owner = owner.units.get_mut("action-1:1").unwrap();
        unit_owner.action[field] = value.clone();
        assert_eq!(unit_owner.action[field], value);
        assert_ne!(unit_owner.action, capture["invocations"][0]);
        let result = unit_owner.input.check_consumed(&unit_owner.action, &unit_owner.unit, &raw[1]);
        let error = result.unwrap_err();
        assert!(error.to_string().contains("consumed action-scoped replay evidence changed"), "{error:#}");
    }
}

#[test]
fn rust_action_replay_rechecks_each_consumed_ir_byte_identity() {
    let (capture, selected, raw) = rust_action_replay_fixture(2);
    let owner = bind(&capture, &selected).unwrap();
    let unit = &capture["units"][1];
    let input = &owner.units["action-1:1"].input;
    input.check_consumed(&capture["invocations"][0], unit, &raw[1]).unwrap();
    assert_ne!(digest(&raw[0]), digest(&raw[1]));
    let error = input.check_consumed(&capture["invocations"][0], unit, &raw[0]).unwrap_err();
    assert!(error.to_string().contains("consumed LLVM buffer differs"), "{error:#}");
}
