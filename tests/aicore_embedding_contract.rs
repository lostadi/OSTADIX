use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ostadix_api::executor::CancellationToken;
use ostadix_api::{OValue, Runtime, RuntimeRequest, RuntimeRequestLimits};

const POSTPROCESS: &str = r#"python^(
scores = $scores
labels = $labels
if len(scores) != len(labels) or not scores:
    raise ValueError("scores and labels must have equal non-zero length")
winner = max(range(len(scores)), key=lambda i: scores[i])
__oval_result__ = {
    "label": labels[winner],
    "confidence_milli": scores[winner],
    "candidate_count": len(scores),
}
)_python"#;

// Mirrors the fields exposed by this installed AICore build's LLMReply:
// text, score, stopReason, and policyScores. File descriptors and the model
// session remain owned by AICore and never enter O scope.
const LLM_REPLY_POSTPROCESS: &str = include_str!("fixtures/aicore_llm_reply_postprocess.O");
const ANDROID_LLM_REPLY_POSTPROCESS: &str =
    include_str!("fixtures/aicore_llm_reply_postprocess_bash.O");
const ANDROID_SMART_REPLY_POSTPROCESS: &str =
    include_str!("fixtures/aicore_smart_reply_postprocess_bash.O");

fn android_llm_result_request(
    id: &str,
    replies: &[(i64, i64, i64)],
    policy_limit: i64,
) -> RuntimeRequest {
    assert!(replies.len() <= 3);
    let mut bindings = HashMap::from([("policy_limit".into(), OValue::int(policy_limit))]);
    for index in 0..3 {
        let (present, score, stop_reason, max_policy_score) = replies
            .get(index)
            .map(|&(score, stop, policy)| (1, score, stop, policy))
            .unwrap_or((0, 0, 0, 0));
        bindings.insert(format!("present_{index}"), OValue::int(present));
        bindings.insert(format!("score_{index}"), OValue::int(score));
        bindings.insert(format!("stop_reason_{index}"), OValue::int(stop_reason));
        bindings.insert(
            format!("max_policy_score_{index}"),
            OValue::int(max_policy_score),
        );
    }
    RuntimeRequest {
        caller_id: "aicore-android-contract/uid-1000".into(),
        request_id: id.into(),
        source: ANDROID_LLM_REPLY_POSTPROCESS.into(),
        bindings,
        limits: RuntimeRequestLimits::default(),
        cancellation: CancellationToken::new(),
    }
}

fn android_smart_reply_request(id: &str, replies: &[(i64, i64, i64)]) -> RuntimeRequest {
    assert!(replies.len() <= 3);
    let mut bindings = HashMap::new();
    for index in 0..3 {
        let (present, score, has_text, safety_classification) = replies
            .get(index)
            .map(|&(score, has_text, safety)| (1, score, has_text, safety))
            .unwrap_or((0, 0, 0, 0));
        bindings.insert(format!("present_{index}"), OValue::int(present));
        bindings.insert(format!("score_{index}"), OValue::int(score));
        bindings.insert(format!("has_text_{index}"), OValue::int(has_text));
        bindings.insert(
            format!("safety_classification_{index}"),
            OValue::int(safety_classification),
        );
    }
    RuntimeRequest {
        caller_id: "aicore-smart-reply-contract/uid-1000".into(),
        request_id: id.into(),
        source: ANDROID_SMART_REPLY_POSTPROCESS.into(),
        bindings,
        limits: RuntimeRequestLimits::default(),
        cancellation: CancellationToken::new(),
    }
}

fn llm_reply(text: &str, score_milli: i64, stop_reason: i64, policy: &[i64]) -> OValue {
    OValue::map(HashMap::from([
        ("text".into(), OValue::text(text)),
        ("score_milli".into(), OValue::int(score_milli)),
        ("stop_reason".into(), OValue::int(stop_reason)),
        (
            "policy_scores_milli".into(),
            OValue::list(policy.iter().copied().map(OValue::int).collect()),
        ),
    ]))
}

fn llm_result_request(id: &str, replies: Vec<OValue>) -> RuntimeRequest {
    RuntimeRequest {
        caller_id: "aicore-llm-result-contract/uid-1000".into(),
        request_id: id.into(),
        source: LLM_REPLY_POSTPROCESS.into(),
        bindings: HashMap::from([
            ("replies".into(), OValue::list(replies)),
            ("policy_limit".into(), OValue::int(500)),
        ]),
        limits: RuntimeRequestLimits::default(),
        cancellation: CancellationToken::new(),
    }
}

fn postprocess_request(id: &str, scores: &[i64]) -> RuntimeRequest {
    RuntimeRequest {
        caller_id: "synthetic-aicore-contract/uid-1000".into(),
        request_id: id.into(),
        source: POSTPROCESS.into(),
        bindings: HashMap::from([
            (
                "scores".into(),
                OValue::list(scores.iter().copied().map(OValue::int).collect()),
            ),
            (
                "labels".into(),
                OValue::list(vec![
                    OValue::text("reject"),
                    OValue::text("review"),
                    OValue::text("accept"),
                ]),
            ),
        ]),
        limits: RuntimeRequestLimits::default(),
        cancellation: CancellationToken::new(),
    }
}

fn field<'a>(value: &'a OValue, name: &str) -> &'a OValue {
    match value {
        OValue::Map { v } => v
            .get(name)
            .unwrap_or_else(|| panic!("missing field {name}")),
        other => panic!("expected typed OMap result, got {other:?}"),
    }
}

#[test]
fn meaningful_typed_postprocessing_depends_on_ostadix_execution() {
    let mut runtime = Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
        .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));

    let left = runtime
        .prepare_request(postprocess_request("left", &[900, 80, 20]))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    let right = runtime
        .prepare_request(postprocess_request("right", &[20, 80, 900]))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();

    assert_eq!(field(&left.value, "label"), &OValue::text("reject"));
    assert_eq!(field(&right.value, "label"), &OValue::text("accept"));
    assert_eq!(field(&right.value, "confidence_milli"), &OValue::int(900));
    assert_eq!(field(&right.value, "candidate_count"), &OValue::int(3));
    assert_ne!(left.value, right.value);
    assert!(left.plan_nodes > 0 && left.hgraph_exec_edges > 0);
    eprintln!(
        "ostadix_postprocess left_ms={:.3} right_ms={:.3} plan_nodes={} hgraph_nodes={} exec_edges={}",
        left.elapsed.as_secs_f64() * 1000.0,
        right.elapsed.as_secs_f64() * 1000.0,
        right.plan_nodes,
        right.hgraph_nodes,
        right.hgraph_exec_edges,
    );
}

#[test]
fn aicore_llm_reply_shape_is_filtered_and_ranked_by_ostadix() {
    let mut runtime = Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
        .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));

    let first = runtime
        .prepare_request(llm_result_request(
            "llm-result-a",
            vec![
                llm_reply("safe lower score", 600, 0, &[20]),
                llm_reply("unsafe higher score", 950, 0, &[900]),
                llm_reply("unfinished", 990, 1, &[10]),
            ],
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    assert_eq!(
        field(&first.value, "text"),
        &OValue::text("safe lower score")
    );
    assert_eq!(field(&first.value, "source_index"), &OValue::int(0));

    let second = runtime
        .prepare_request(llm_result_request(
            "llm-result-b",
            vec![
                llm_reply("safe lower score", 600, 0, &[20]),
                llm_reply("now safe higher score", 950, 0, &[100]),
            ],
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    assert_eq!(
        field(&second.value, "text"),
        &OValue::text("now safe higher score")
    );
    assert_eq!(field(&second.value, "source_index"), &OValue::int(1));
    assert_ne!(first.value, second.value);
    assert_eq!(
        first.evidence.execution_intent_sha256,
        second.evidence.execution_intent_sha256
    );
    assert_ne!(
        first.evidence.request_scope_content_identity,
        second.evidence.request_scope_content_identity
    );
    assert_ne!(
        first.evidence.result_content_identity,
        second.evidence.result_content_identity
    );

    let error = runtime
        .prepare_request(llm_result_request(
            "llm-result-no-safe-reply",
            vec![llm_reply("unsafe", 999, 0, &[501])],
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap_err();
    assert!(error.message().contains("no policy-safe finished reply"));
}

#[test]
fn android_bash_postprocessor_consumes_only_bounded_reply_metadata() {
    let mut runtime = Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
        .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));

    let first = runtime
        .prepare_request(android_llm_result_request(
            "android-a",
            &[(600, 0, 20), (950, 0, 900), (990, 1, 10)],
            500,
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    assert_eq!(field(&first.value, "source_index"), &OValue::int(0));
    assert_eq!(field(&first.value, "score_milli"), &OValue::int(600));

    let second = runtime
        .prepare_request(android_llm_result_request(
            "android-b",
            &[(600, 0, 20), (950, 0, 100), (990, 1, 10)],
            500,
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    assert_eq!(field(&second.value, "source_index"), &OValue::int(1));
    assert_eq!(field(&second.value, "score_milli"), &OValue::int(950));
    assert_eq!(
        first.evidence.execution_intent_sha256,
        second.evidence.execution_intent_sha256
    );
    assert_ne!(
        first.evidence.request_scope_content_identity,
        second.evidence.request_scope_content_identity
    );
    assert_ne!(first.value, second.value);

    let error = runtime
        .prepare_request(android_llm_result_request(
            "android-no-safe-reply",
            &[(999, 0, 501)],
            500,
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap_err();
    assert!(error.message().contains("no policy-safe finished reply"));
}

#[test]
fn android_smart_reply_postprocessor_uses_named_scalar_contract() {
    let mut runtime = Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
        .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));

    let first = runtime
        .prepare_request(android_smart_reply_request(
            "smart-reply-a",
            &[(600, 1, 0), (950, 0, 0), (990, 1, 1)],
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    assert_eq!(field(&first.value, "source_index"), &OValue::int(0));
    assert_eq!(field(&first.value, "score_milli"), &OValue::int(600));

    let second = runtime
        .prepare_request(android_smart_reply_request(
            "smart-reply-b",
            &[(600, 1, 0), (950, 1, 0), (990, 1, 2)],
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    assert_eq!(field(&second.value, "source_index"), &OValue::int(1));
    assert_eq!(field(&second.value, "score_milli"), &OValue::int(950));
    assert_eq!(
        first.evidence.execution_intent_sha256,
        second.evidence.execution_intent_sha256
    );
    assert_ne!(
        first.evidence.request_scope_content_identity,
        second.evidence.request_scope_content_identity
    );
    assert_ne!(first.value, second.value);

    let error = runtime
        .prepare_request(android_smart_reply_request(
            "smart-reply-no-safe-nonempty",
            &[(999, 1, 2), (998, 0, 0)],
        ))
        .and_then(|request| runtime.execute_request(request))
        .unwrap_err();
    assert!(error.message().contains("no safe nonempty reply"));
}

#[test]
fn independent_callers_do_not_share_request_scope_or_backend_state() {
    let run = |caller: &'static str, id: &'static str, scores: Vec<i64>| {
        std::thread::spawn(move || {
            let mut request = postprocess_request(id, &scores);
            request.caller_id = caller.into();
            let mut runtime =
                Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
                    .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));
            runtime
                .prepare_request(request)
                .and_then(|request| runtime.execute_request(request))
                .unwrap()
        })
    };

    let first = run("caller-a/uid-1001", "a", vec![700, 200, 100]);
    let second = run("caller-b/uid-1002", "b", vec![100, 200, 700]);
    let first = first.join().unwrap();
    let second = second.join().unwrap();

    assert_eq!(first.caller_id, "caller-a/uid-1001");
    assert_eq!(second.caller_id, "caller-b/uid-1002");
    assert_eq!(field(&first.value, "label"), &OValue::text("reject"));
    assert_eq!(field(&second.value, "label"), &OValue::text("accept"));
}

#[test]
fn invalid_typed_input_is_an_error_and_runtime_restart_recovers() {
    let make_runtime = || {
        Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
            .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")))
    };

    let mut runtime = make_runtime();
    let error = runtime
        .prepare_request(postprocess_request("invalid", &[]))
        .and_then(|request| runtime.execute_request(request))
        .unwrap_err();
    assert!(error.message().contains("equal non-zero length"));
    drop(runtime);

    let mut restarted = make_runtime();
    let result = restarted
        .prepare_request(postprocess_request("after-restart", &[10, 20, 30]))
        .and_then(|request| restarted.execute_request(request))
        .unwrap();
    assert_eq!(result.request_id, "after-restart");
    assert_eq!(field(&result.value, "label"), &OValue::text("accept"));
}

#[test]
fn backend_deadline_reaps_unresponsive_request_and_runtime_recovers() {
    let mut runtime = Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
        .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));
    let started = Instant::now();
    let request = RuntimeRequest {
        caller_id: "deadline-caller/uid-1003".into(),
        request_id: "timeout".into(),
        source: "python^(\nimport time\ntime.sleep(10)\n__oval_result__ = 1\n)_python".into(),
        bindings: HashMap::new(),
        limits: RuntimeRequestLimits {
            deadline: Some(Instant::now() + Duration::from_millis(150)),
            ..RuntimeRequestLimits::default()
        },
        cancellation: CancellationToken::new(),
    };
    let error = runtime
        .prepare_request(request)
        .and_then(|request| runtime.execute_request(request))
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(3), "{error}");
    assert!(error.message().contains("deadline"), "{error}");

    let result = runtime
        .prepare_request(postprocess_request("after-timeout", &[10, 20, 30]))
        .and_then(|request| runtime.execute_request(request))
        .unwrap();
    assert_eq!(field(&result.value, "label"), &OValue::text("accept"));
}

#[test]
fn cancellation_after_dispatch_reaps_backend_and_runtime_recovers() {
    let cancellation = CancellationToken::new();
    let worker_cancellation = cancellation.clone();
    let marker_dir = tempfile::tempdir().unwrap();
    let marker = marker_dir.path().join("backend-started");
    let worker_marker = marker.clone();
    let worker = std::thread::spawn(move || {
        let mut runtime = Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
            .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));
        let request = RuntimeRequest {
            caller_id: "cancel-caller/uid-1004".into(),
            request_id: "cancel-after-dispatch".into(),
            source: "python^(\nimport time\nopen($marker, 'w').write('started')\ntime.sleep(10)\n__oval_result__ = 1\n)_python".into(),
            bindings: HashMap::from([(
                "marker".into(),
                OValue::text(worker_marker.to_string_lossy()),
            )]),
            limits: RuntimeRequestLimits::default(),
            cancellation: worker_cancellation,
        };
        let prepared = runtime.prepare_request(request).unwrap();
        let started = Instant::now();
        let error = runtime.execute_request(prepared).unwrap_err();
        let cancelled_after = started.elapsed();

        let recovered = runtime
            .prepare_request(postprocess_request("after-cancel", &[10, 20, 30]))
            .and_then(|request| runtime.execute_request(request))
            .unwrap();
        (error, cancelled_after, recovered)
    });

    let marker_deadline = Instant::now() + Duration::from_secs(5);
    while !marker.is_file() && Instant::now() < marker_deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(marker.is_file(), "backend never reached request code");
    cancellation.cancel();
    let (error, cancelled_after, recovered) = worker.join().unwrap();
    assert!(cancelled_after < Duration::from_secs(3), "{error}");
    assert!(error.message().contains("cancellation"), "{error}");
    assert_eq!(field(&recovered.value, "label"), &OValue::text("accept"));
}
