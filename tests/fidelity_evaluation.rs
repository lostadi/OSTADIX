//! Semantic-loss witnesses, with real hosted crossings and exact CBOR controls.

use std::io::Cursor;
use std::path::Path;
use std::process::Command;

use o_lang::backend_morphism::{
    observed_value_sha256, BackendCrossingObservationV1, BackendMorphismRejectionKindV1,
    RuntimeCrossingStateV1, RuntimeInputProfileV1,
};
use o_lang::hgraph::{
    solve::{fidelity_assessment_for, solve_types},
    HEdge, HGraph, HNode, OpKind, Port, PortRole,
};
use o_lang::value::{AnnotationKind, FidelityAssessmentV2, OValue};
use o_lang::wire::{read_frame, write_frame};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

mod support;

fn cbor_control<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    value: &T,
) -> String {
    let mut frame = Vec::new();
    write_frame(&mut frame, value).unwrap();
    let mut reader = Cursor::new(&frame);
    let decoded: T = read_frame(&mut reader).unwrap().unwrap();
    assert_eq!(&decoded, value, "CBOR itself must preserve the witness");
    assert_eq!(reader.position(), frame.len() as u64);
    hex::encode(&frame[4..]) // Exclude O's four-byte framing prefix.
}

fn run_case(file: &str, executor: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_O"));
    command.args(["--executor", executor]);
    command.arg(if executor == "graph" {
        "--crossing-evidence"
    } else {
        "--json"
    });
    let output = command
        .arg(root.join("benchmarks/fidelity").join(file))
        .arg(root.join("backends"))
        .output()
        .expect("launch the compiled O executable");
    assert!(
        output.status.success(),
        "{file} ({executor}) failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

// This is a known-value witness graph, not constant inference from Python
// source. The intermediate payload is the actual result observed at runtime.
fn solve_witness_chain(original: &OValue, crossed: &OValue) -> Value {
    let mut graph = HGraph::default();
    let input = graph.add_node(HNode::with_value(original.clone()));
    let intermediate = graph.add_node(HNode::with_value(crossed.clone()));
    let output = graph.add_node(HNode::with_value(crossed.clone()));
    let first = fidelity_assessment_for(graph.node(input).unwrap(), "python", "javascript");
    let second = fidelity_assessment_for(graph.node(intermediate).unwrap(), "javascript", "python");
    assert_eq!(second, FidelityAssessmentV2::Lossless);
    // Deliberately visit the second crossing first to exercise the fixpoint.
    for (source, destination, from_lang, to_lang) in [
        (intermediate, output, "javascript", "python"),
        (input, intermediate, "python", "javascript"),
    ] {
        graph.add_edge(HEdge::constraint(
            OpKind::BackendCrossing {
                from_lang: from_lang.into(),
                to_lang: to_lang.into(),
            },
            vec![
                Port {
                    node: source,
                    role: PortRole::Input,
                },
                Port {
                    node: destination,
                    role: PortRole::Output,
                },
            ],
        ));
    }
    solve_types(&mut graph).unwrap();
    let accumulated = graph.node(output).unwrap();
    assert_eq!(accumulated.fidelity_assessment.as_ref(), Some(&first));
    assert_eq!(accumulated.fidelity, Some(first.possible_fidelity()));
    assert_ne!(first, FidelityAssessmentV2::Lossless);
    json!({
        "analysis": "known-value crossing graph",
        "python_to_javascript": first,
        "javascript_to_python": second,
        "accumulated": accumulated.fidelity_assessment,
    })
}

struct Case {
    file: &'static str,
    original: OValue,
    crossed: OValue,
    plain: Value,
    expected_before: OValue,
    expected_after: OValue,
    same_numeric_value: bool,
    losses: Vec<AnnotationKind>,
}

fn evaluate(case: Case) {
    let Case {
        file,
        original,
        crossed,
        plain,
        expected_before,
        expected_after,
        same_numeric_value,
        losses,
    } = case;
    if !support::require_runtimes(&["python3", "node"]) {
        return;
    }
    let plain_cbor = cbor_control(&plain);
    let tagged_cbor = cbor_control(&original);
    let graph_run = run_case(file, "graph");
    let serial_run = run_case(file, "serial");
    let result: OValue = serde_json::from_value(graph_run["value"].clone()).unwrap();
    assert_eq!(
        result,
        serde_json::from_value::<OValue>(serial_run["value"].clone()).unwrap()
    );
    let OValue::Map { v: fields } = &result else {
        panic!("expected witness fields")
    };
    assert_eq!(fields["original"], original);
    assert_eq!(fields["crossed"], crossed);
    assert_eq!(fields["before"], expected_before);
    assert_eq!(fields["after"], expected_after);
    assert_ne!(fields["before"], fields["after"]);
    assert_eq!(
        fields["same_numeric_value"],
        OValue::bool_(same_numeric_value)
    );

    let records = graph_run["backend_crossings"].as_array().unwrap();
    assert_eq!(records.len(), 3);
    let mut javascript_profile = None;
    for record in records {
        let observation: BackendCrossingObservationV1 =
            serde_json::from_value(record["observation"].clone()).unwrap();
        observation
            .verify(
                record["sha256"].as_str().unwrap(),
                &observation.admission_sha256,
                &observation.graph_sha256,
            )
            .unwrap();
        assert_eq!(observation.state, RuntimeCrossingStateV1::ResultObserved);
        assert!(observation.published && !observation.discarded);
        if observation.backend == "javascript" {
            let binding = observation
                .bindings
                .iter()
                .find(|b| b.name == "original")
                .unwrap();
            assert_eq!(binding.value_sha256, observed_value_sha256(&original));
            assert_eq!(
                observation.result.as_ref().unwrap().value_sha256,
                observed_value_sha256(&crossed)
            );
            javascript_profile = Some(binding.input_profile.clone());
        }
    }
    let javascript_profile = javascript_profile.unwrap();
    let expected_assessment = FidelityAssessmentV2::structural(losses.clone(), losses).unwrap();
    if same_numeric_value {
        assert_eq!(
            javascript_profile,
            RuntimeInputProfileV1::Assessed {
                fidelity: expected_assessment.clone()
            }
        );
    } else {
        assert!(
            matches!(&javascript_profile, RuntimeInputProfileV1::OutsideProfile { reason }
            if reason.kind == BackendMorphismRejectionKindV1::IntegerOutOfRange)
        );
    }
    let chain = solve_witness_chain(&fields["original"], &fields["crossed"]);
    assert_eq!(
        chain["accumulated"],
        serde_json::to_value(expected_assessment).unwrap()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "case": file,
            "plain_cbor_roundtrip_exact": true,
            "plain_cbor_payload_hex": plain_cbor,
            "tagged_ovalue_cbor_roundtrip_exact": true,
            "tagged_ovalue_cbor_payload_hex": tagged_cbor,
            "graph_matches_serial": true,
            "actual_result": result,
            "runtime_javascript_input_profile": javascript_profile,
            "fidelity": chain,
        }))
        .unwrap()
    );
}

#[test]
fn cbor_preserves_float_but_javascript_crossing_changes_type_dispatch() {
    evaluate(Case {
        file: "type_tag.O",
        original: OValue::float(1.0),
        crossed: OValue::int(1),
        plain: json!(1.0),
        expected_before: OValue::text("float branch"),
        expected_after: OValue::text("integer branch"),
        same_numeric_value: true,
        losses: vec![AnnotationKind::TypeTag, AnnotationKind::NumericExactness],
    });
}

#[test]
fn cbor_preserves_integer_but_javascript_crossing_changes_parity() {
    evaluate(Case {
        file: "integer_precision.O",
        original: OValue::int(9_007_199_254_740_993),
        crossed: OValue::int(9_007_199_254_740_992),
        plain: json!(9_007_199_254_740_993_i64),
        expected_before: OValue::bool_(true),
        expected_after: OValue::bool_(false),
        same_numeric_value: false,
        losses: vec![
            AnnotationKind::TypeTag,
            AnnotationKind::NumericPrecision,
            AnnotationKind::NumericExactness,
        ],
    });
}
