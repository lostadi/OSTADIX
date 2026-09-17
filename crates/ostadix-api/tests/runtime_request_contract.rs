use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ostadix_api::executor::CancellationToken;
use ostadix_api::{OValue, Runtime, RuntimeRequest, RuntimeRequestLimits, RuntimeStage};

fn request(id: &str, values: Vec<i64>) -> RuntimeRequest {
    RuntimeRequest {
        caller_id: "aicore-experiment/uid-1000".into(),
        request_id: id.into(),
        source: "$values".into(),
        bindings: HashMap::from([(
            "values".into(),
            OValue::list(values.into_iter().map(OValue::int).collect()),
        )]),
        limits: RuntimeRequestLimits::default(),
        cancellation: CancellationToken::new(),
    }
}

#[test]
fn typed_result_depends_on_request_private_input_and_uses_canonical_graph() {
    let shim_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../backends");
    let mut runtime = Runtime::new(shim_dir);

    let first = runtime
        .prepare_request(request("r1", vec![2, 3, 5]))
        .unwrap();
    assert!(first.plan_nodes() > 0);
    assert!(first.hgraph_nodes() > 0);
    assert!(first.hgraph_exec_edges() > 0);
    assert_eq!(first.source_sha256().len(), 64);
    assert_eq!(first.execution_intent_sha256().len(), 64);
    assert_eq!(first.request_scope_content_identity().len(), 64);
    let first = runtime.execute_request(first).unwrap();

    let second = runtime.prepare_request(request("r2", vec![7, 11])).unwrap();
    let second = runtime.execute_request(second).unwrap();

    assert_eq!(first.caller_id, "aicore-experiment/uid-1000");
    assert_eq!(first.request_id, "r1");
    assert_ne!(first.value, second.value);
    assert_eq!(first.value.type_name(), second.value.type_name());
    assert_eq!(first.evidence.source_sha256, second.evidence.source_sha256);
    assert_eq!(
        first.evidence.execution_intent_sha256,
        second.evidence.execution_intent_sha256
    );
    assert_eq!(first.evidence.oir_sha256, second.evidence.oir_sha256);
    assert_eq!(first.evidence.plan_sha256, second.evidence.plan_sha256);
    assert_ne!(
        first.evidence.request_scope_content_identity,
        second.evidence.request_scope_content_identity
    );
    assert_ne!(
        first.evidence.result_content_identity,
        second.evidence.result_content_identity
    );
    for digest in [
        &first.evidence.source_sha256,
        &first.evidence.execution_intent_sha256,
        &first.evidence.request_scope_content_identity,
        &first.evidence.oir_sha256,
        &first.evidence.plan_sha256,
        &first.evidence.analyzed_graph_sha256,
        &first.evidence.evidence_sha256,
        &first.evidence.admitted_graph_sha256,
        &first.evidence.admission_sha256,
        &first.evidence.result_content_identity,
    ] {
        assert_eq!(digest.len(), 64, "invalid SHA-256 identity: {digest}");
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn bounds_cancellation_and_deadline_fail_closed_before_execution() {
    let runtime = Runtime::new(PathBuf::new());
    let mut oversized = request("oversized", vec![1]);
    oversized.limits.max_source_bytes = 1;
    let error = runtime.prepare_request(oversized).unwrap_err();
    assert_eq!(error.stage(), RuntimeStage::Parse);
    assert!(error.message().contains("request limit"));

    let mut oversized_binding = request("oversized-binding", vec![1]);
    oversized_binding.limits.max_binding_bytes = 1;
    let error = runtime.prepare_request(oversized_binding).unwrap_err();
    assert_eq!(error.stage(), RuntimeStage::Parse);
    assert!(error.message().contains("canonical bytes"));

    let cancelled = request("cancelled", vec![1]);
    cancelled.cancellation.cancel();
    let error = runtime.prepare_request(cancelled).unwrap_err();
    assert_eq!(error.stage(), RuntimeStage::Evaluate);
    assert_eq!(error.message(), "request cancelled");

    let mut expired = request("expired", vec![1]);
    expired.limits.deadline = Some(Instant::now() - Duration::from_millis(1));
    let error = runtime.prepare_request(expired).unwrap_err();
    assert_eq!(error.stage(), RuntimeStage::Evaluate);
    assert_eq!(error.message(), "request deadline exceeded");
}
