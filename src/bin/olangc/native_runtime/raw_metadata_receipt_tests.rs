//! Structural receipt/dispatch controls, not original-runtime execution proof.
use super::*;
use o_lang::ocore::native_ir::{Instruction, Operation, NOALIAS_SCOPE_DECL};

const INPUT: &[u8] = b"exact original LLVM source bytes\0\xff";
const PARSER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn plain() -> NativeModule {
    let mut module = object_inventory_tests::module();
    module.provenance.input_sha256 = digest(INPUT);
    module.provenance.importer = "ocore_llvm_import.py".into();
    module.provenance.importer_version = format!("1; LLVM 22.1.6; library-sha256={PARSER}");
    module
}

fn canonical() -> NativeModule {
    let mut module = plain();
    module.types.push(Type::Metadata {});
    module.functions.push(
        serde_json::from_value(json!({
            "name":NOALIAS_SCOPE_DECL,"linkage":"external","intrinsic":NOALIAS_SCOPE_DECL,
            "signature":{"params":[2],"result":0,"abi":"c","variadic":false},
            "params":[{"id":0,"ty":2}],"entry":null,"blocks":[]
        }))
        .unwrap(),
    );
    module.provenance.source_function_count += 1;
    module.functions[0].blocks[0]
        .instructions
        .push(Instruction {
            result: None,
            operation: Operation::NoAliasScopeDecl {
                scope_list: 2,
                source_instruction: 0,
            },
        });
    module.noalias_metadata = serde_json::from_value(json!({
        "domains":[{"id":0,"storage":"distinct","identity":{"kind":"self_reference"},
            "description":[100,0,255]}],
        "scopes":[{"id":1,"storage":"distinct","identity":{"kind":"self_reference"},
            "domain":0,"description":null}],
        "lists":[{"id":2,"storage":"uniqued","scopes":[1]}],"attachments":[]
    }))
    .unwrap();
    module.provenance.noalias_metadata_graph_source = Some(serde_json::from_value(json!({
        "schema":"ocore.llvm-metadata-graph/v1",
        "nodes":[
            {"id":0,"kind":"tuple","metadata_kind":4,"storage":"uniqued","operands":[1]},
            {"id":1,"kind":"tuple","metadata_kind":4,"storage":"distinct","operands":[1,2]},
            {"id":2,"kind":"tuple","metadata_kind":4,"storage":"distinct","operands":[2,3]},
            {"id":3,"kind":"string","metadata_kind":0,"bytes":[100,0,255]}],
        "alias_bindings":[{"alias_id":0,"node":2},{"alias_id":1,"node":1},{"alias_id":2,"node":0}],
        "roots":[{"kind":"scope_declaration","site":{"function":"f","block":0,
            "source_instruction":0},"node":0}]
    })).unwrap());
    o_lang::ocore::native_verify::verify(&module).unwrap();
    module
}

fn source(id: usize, printer: &[u8]) -> Value {
    json!({"id":id,"metadata_kind":4,"printer_bytes":printer,"printer_sha256":digest(printer)})
}

fn packet(module: &NativeModule) -> Value {
    json!({"schema":RAW_METADATA_SCHEMA,"input_sha256":digest(INPUT),"input_bytes":INPUT.len(),
        "import_complete":true,"parser":{"version":[22,1,6],"sha256":PARSER},
        "alias_nodes":if module.provenance.noalias_metadata_graph_source.is_some() {
            json!([source(0,b"<0xCAFE> = distinct !{<0xCAFE>, !\"d\\00\\FF\"}"),
                source(1,b"!7 = distinct !{!7, !8}"),source(2,b"!5 = !{!7}")])
        } else { json!(module.provenance.noalias_metadata_source) },
        "graph_source":module.provenance.noalias_metadata_graph_source})
}

fn check(module: &NativeModule, packet: &Value) -> Result<Value> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("diagnostics.json");
    fs::write(&path, serde_json::to_vec(packet).unwrap()).unwrap();
    validate_metadata_diagnostics(Some(&path), module, INPUT, Some(PARSER))
}

#[test]
fn raw_metadata_receipts_bind_exact_bytes_without_modifying_canonical_module() {
    let module = canonical();
    let before = serde_json::to_vec(&module).unwrap();
    let first = check(&module, &packet(&module)).unwrap();
    assert_eq!(first["tuple_count"], 3);
    assert_eq!(first["validated"], true);
    assert_eq!(first["canonical_graph_source"], true);
    let mut moved = packet(&module);
    moved["alias_nodes"][0] = source(
        0,
        b"<0xDEADBEEF> = distinct !{<0xDEADBEEF>, !\"d\\00\\FF\"}",
    );
    let second = check(&module, &moved).unwrap();
    assert_ne!(first["sha256"], second["sha256"]);
    assert_eq!(serde_json::to_vec(&module).unwrap(), before);
}

#[test]
fn raw_metadata_receipts_reject_wrong_headers_inputs_parser_and_incomplete_imports() {
    let module = canonical();
    for (pointer, bad) in [
        ("/schema", json!("other")),
        ("/input_sha256", json!("b".repeat(64))),
        ("/input_bytes", json!(INPUT.len() + 1)),
        ("/import_complete", json!(false)),
        ("/parser/version", json!([22, 1, 5])),
        ("/parser/sha256", json!("b".repeat(64))),
        ("/parser/sha256", json!("A".repeat(64))),
        ("/parser/sha256", json!("a".repeat(63))),
        ("/parser", Value::Null),
    ] {
        let mut bad_packet = packet(&module);
        *bad_packet.pointer_mut(pointer).unwrap() = bad;
        assert!(check(&module, &bad_packet).is_err(), "accepted {pointer}");
    }
    for field in [
        "schema",
        "input_sha256",
        "input_bytes",
        "import_complete",
        "parser",
        "alias_nodes",
        "graph_source",
    ] {
        let mut bad = packet(&module);
        bad.as_object_mut().unwrap().remove(field);
        assert!(check(&module, &bad).is_err(), "missing {field}");
    }
    let mut unknown = packet(&module);
    unknown["unadmitted_extra"] = json!(true);
    assert!(check(&module, &unknown).is_err());
    let mut failed = packet(&module);
    failed["error"] = json!({"message":"failed whole module"});
    assert!(check(&module, &failed).is_err());
}

#[test]
fn raw_metadata_receipts_reject_missing_extra_duplicate_unknown_and_specialized_tuples() {
    let module = canonical();
    let original = packet(&module);
    let mut variants = Vec::new();
    let mut missing = original.clone();
    missing["alias_nodes"].as_array_mut().unwrap().pop();
    variants.push(missing);
    let mut extra = original.clone();
    extra["alias_nodes"]
        .as_array_mut()
        .unwrap()
        .push(source(99, b"!0 = !{}"));
    variants.push(extra);
    for (pointer, bad) in [
        ("/alias_nodes/0/id", json!(1)),
        ("/alias_nodes/0/id", json!(99)),
        ("/alias_nodes/0/metadata_kind", json!(5)),
        ("/alias_nodes/0/printer_sha256", json!("0".repeat(64))),
        ("/alias_nodes/0/printer_bytes", json!([255, 0, 1])),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        variants.push(changed);
    }
    for printer in [
        b"!0 = !{}".as_slice(),
        b"<0xZZ> = distinct !{}",
        b"! = distinct !{}",
        b"!0=distinct !{}",
    ] {
        let mut changed = original.clone();
        changed["alias_nodes"][0] = source(0, printer);
        variants.push(changed);
    }
    for (index, changed) in variants.iter().enumerate() {
        assert!(check(&module, changed).is_err(), "accepted variant {index}");
    }
}

#[test]
fn raw_metadata_receipts_reject_any_canonical_graph_difference() {
    let module = canonical();
    for (pointer, bad) in [
        ("/graph_source/nodes/3/bytes/1", json!(1)),
        ("/graph_source/nodes/0/operands/0", json!(2)),
        ("/graph_source/alias_bindings/0/node", json!(1)),
        ("/graph_source/roots/0/site/source_instruction", json!(1)),
        ("/graph_source", Value::Null),
    ] {
        let mut changed = packet(&module);
        *changed.pointer_mut(pointer).unwrap() = bad;
        assert!(check(&module, &changed).is_err(), "accepted {pointer}");
    }
    let mut broken = module.clone();
    broken.noalias_metadata.scopes[0].domain = 99;
    assert!(check(&broken, &packet(&broken)).is_err());
}

#[test]
fn raw_metadata_receipts_pin_parser_independently_of_worker_self_report() {
    let module = canonical();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("diagnostics.json");
    fs::write(&path, serde_json::to_vec(&packet(&module)).unwrap()).unwrap();
    assert!(
        validate_metadata_diagnostics(Some(&path), &module, INPUT, Some(&"b".repeat(64))).is_err()
    );
    assert!(validate_metadata_diagnostics(Some(&path), &module, b"changed", Some(PARSER)).is_err());
    let mut changed = module.clone();
    changed.provenance.importer_version = "1".into();
    assert!(validate_metadata_diagnostics(Some(&path), &changed, INPUT, Some(PARSER)).is_err());
    let inferred = validate_metadata_diagnostics(Some(&path), &module, INPUT, None).unwrap();
    assert_eq!(inferred["explicit_parser_pin_checked"], false);
}

#[test]
fn raw_metadata_receipts_distinguish_legacy_and_metadata_free_imports() {
    let plain = plain();
    assert_eq!(check(&plain, &packet(&plain)).unwrap()["tuple_count"], 0);
    let legacy = validate_metadata_diagnostics(None, &plain, INPUT, None).unwrap();
    assert_eq!(legacy["mode"], "legacy_embedded_provenance");
    assert_eq!(legacy["deterministic_graph_source_gate"], false);
    assert!(validate_metadata_diagnostics(None, &plain, b"changed", None).is_err());
    assert!(validate_metadata_diagnostics(None, &canonical(), INPUT, None).is_err());
    let mut extra = packet(&plain);
    extra["alias_nodes"] = json!([source(0, b"!0 = !{}")]);
    assert!(check(&plain, &extra).is_err());
    let mut legacy_module = canonical();
    let legacy_raw = packet(&legacy_module)["alias_nodes"].clone();
    legacy_module.provenance.noalias_metadata_graph_source = None;
    legacy_module.provenance.noalias_metadata_source = serde_json::from_value(legacy_raw).unwrap();
    assert!(check(&legacy_module, &packet(&legacy_module)).is_ok());
    let mut changed = packet(&legacy_module);
    changed["alias_nodes"][0] = source(0, b"!77 = distinct !{}");
    assert!(check(&legacy_module, &changed).is_err());
}

#[test]
fn raw_metadata_receipts_keep_failed_evidence_separate_and_detect_postcheck_mutation() {
    let module = canonical();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("diagnostics.json");
    let mut failed = packet(&module);
    failed["import_complete"] = json!(false);
    failed["error"] = json!({"stage":"unsupported","message":"whole import failed"});
    fs::write(&path, serde_json::to_vec(&failed).unwrap()).unwrap();
    let retained = retained_metadata_diagnostics(&path);
    assert_eq!(retained["validated"], false);
    assert_eq!(retained["sha256"], digest(&fs::read(&path).unwrap()));
    assert!(validate_metadata_diagnostics(Some(&path), &module, INPUT, Some(PARSER)).is_err());
    fs::write(&path, serde_json::to_vec(&packet(&module)).unwrap()).unwrap();
    let valid = validate_metadata_diagnostics(Some(&path), &module, INPUT, Some(PARSER)).unwrap();
    metadata_diagnostics_postguard(&valid).unwrap();
    fs::write(&path, b"replaced").unwrap();
    assert!(metadata_diagnostics_postguard(&valid).is_err());
    fs::remove_file(&path).unwrap();
    assert!(retained_metadata_diagnostics(&path)
        .get("unavailable")
        .is_some());
}

#[cfg(unix)]
#[test]
fn raw_metadata_help_negotiation_is_exact_and_retains_actual_child_evidence() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let compiler = dir.path().join("selected-compiler");
    for (index, help, status, expected) in [
        (0, "--llvm-metadata-diagnostics <PATH>", 0, true),
        (1, "--llvm-metadata-diagnostics-other <PATH>", 0, false),
        (2, "--llvm-metadata-diagnostics <PATH>", 1, false),
        (3, "old compiler help", 0, false),
    ] {
        fs::write(
            &compiler,
            format!("#!/bin/sh\nprintf '%s\\n' '{help}'\nexit {status}\n"),
        )
        .unwrap();
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o700)).unwrap();
        let out = dir.path().join(format!("case-{index}"));
        fs::create_dir(&out).unwrap();
        let (supported, record) = metadata_diagnostics_capability(&compiler, &out).unwrap();
        assert_eq!(supported, expected);
        assert_eq!(record["sha256"], digest(&fs::read(&compiler).unwrap()));
        assert_eq!(
            record["stdout"]["sha256"],
            digest(&fs::read(out.join("metadata-diagnostics-help.stdout")).unwrap())
        );
        assert_eq!(record["status"], status);
    }
}
