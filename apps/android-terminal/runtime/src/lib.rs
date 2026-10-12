//! Supported JNI boundary for the standalone Ostadix Terminal APK.
//!
//! The Android app embeds the stable `ostadix_api::Runtime` instead of
//! executing a binary copied into writable app storage. Android 10 and newer
//! intentionally disallow that writable-code pattern.

use jni::errors::LogErrorAndDefault;
use jni::objects::{JClass, JIntArray, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::{Env, EnvUnowned};
use ostadix_api::executor::CancellationToken;
use ostadix_api::{OValue, Runtime, RuntimeRequest, RuntimeRequestLimits};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct AndroidRuntime {
    inner: Mutex<Runtime>,
    /// Request-private cancellation tokens. Entries exist only from bounded
    /// call registration through completion and never survive runtime drop.
    active_cancellations: Mutex<HashMap<(String, String), CancellationToken>>,
}

const AICORE_REPLY_POSTPROCESS: &str =
    include_str!("../../../../tests/fixtures/aicore_llm_reply_postprocess_bash.O");
const AICORE_SMART_REPLY_POSTPROCESS: &str =
    include_str!("../../../../tests/fixtures/aicore_smart_reply_postprocess_bash.O");
const MAX_BINDINGS_JSON_BYTES: usize = 1024 * 1024;

// JNI 0.22 separates the FFI-safe environment argument from its borrowed API.
// Keep Java's native call frame alive while its strings and arrays are used;
// return the established zero/null fallback if environment access fails.
fn with_jni_env<'local, T: Default>(
    unowned_env: &mut EnvUnowned<'local>,
    operation: impl FnOnce(&mut Env<'local>) -> T,
) -> T {
    unowned_env
        .with_env(|env| Ok::<T, jni::errors::Error>(operation(env)))
        .resolve::<LogErrorAndDefault>()
}

fn java_string(env: &mut Env<'_>, value: String) -> jstring {
    match JString::from_str(env, value) {
        Ok(text) => text.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

fn error_json(stage: &str, message: impl AsRef<str>) -> String {
    json!({
        "schema": "ostadix.runtime-request-result/v1",
        "disposition": "failed",
        "ok": false,
        "stage": stage,
        "message": message.as_ref(),
    })
    .to_string()
}

fn json_binding_to_ovalue(value: Value) -> Result<OValue, String> {
    match value {
        Value::Null => Ok(OValue::null()),
        Value::Bool(value) => Ok(OValue::bool_(value)),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(OValue::int(value))
            } else if let Some(value) = value.as_u64() {
                i64::try_from(value).map(OValue::int).map_err(|_| {
                    "JSON integer exceeds O's signed 64-bit ordinary binding range".to_string()
                })
            } else {
                value
                    .as_f64()
                    .filter(|value| value.is_finite())
                    .map(OValue::float)
                    .ok_or_else(|| "JSON binding number is not finite".to_string())
            }
        }
        Value::String(value) => Ok(OValue::text(value)),
        Value::Array(values) => values
            .into_iter()
            .map(json_binding_to_ovalue)
            .collect::<Result<Vec<_>, _>>()
            .map(OValue::list),
        Value::Object(values) => values
            .into_iter()
            .map(|(name, value)| json_binding_to_ovalue(value).map(|value| (name, value)))
            .collect::<Result<HashMap<_, _>, _>>()
            .map(OValue::map),
    }
}

fn parse_bindings_json(value: &str) -> Result<HashMap<String, OValue>, String> {
    if value.len() > MAX_BINDINGS_JSON_BYTES {
        return Err(format!(
            "bindings JSON exceeds {MAX_BINDINGS_JSON_BYTES} bytes"
        ));
    }
    let parsed: Value =
        serde_json::from_str(value).map_err(|error| format!("invalid bindings JSON: {error}"))?;
    let Value::Object(bindings) = parsed else {
        return Err("bindings JSON must be an object".to_string());
    };
    bindings
        .into_iter()
        .map(|(name, value)| json_binding_to_ovalue(value).map(|value| (name, value)))
        .collect()
}

/// Create one app-owned evaluator. The handle is never shared with Java code
/// other than as an opaque token and is serialized by the Java wrapper.
#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativeCreate(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    shim_dir: JString<'_>,
    runtime_executable: JString<'_>,
    bash_executable: JString<'_>,
) -> jlong {
    with_jni_env(&mut unowned_env, |env| {
        let shim_dir: String = match shim_dir.try_to_string(env) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let runtime_executable: String = match runtime_executable.try_to_string(env) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let bash_executable: String = match bash_executable.try_to_string(env) {
            Ok(value) => value,
            Err(_) => return 0,
        };
        let runtime = AndroidRuntime {
            // This private executor thread never changes Landlock/seccomp
            // authority between evaluations. Reuse is therefore safe here; the
            // core still rebuilds workers whenever Android affinity changes.
            inner: Mutex::new(
                Runtime::new(shim_dir)
                    .with_runtime_executable(runtime_executable)
                    .with_backend_executable("bash", bash_executable)
                    .with_reusable_local_workers(),
            ),
            active_cancellations: Mutex::new(HashMap::new()),
        };
        Box::into_raw(Box::new(runtime)) as jlong
    })
}

fn execute_bounded(
    runtime: &AndroidRuntime,
    source: String,
    caller_id: String,
    request_id: String,
    bindings: HashMap<String, OValue>,
    timeout_ms: jlong,
) -> String {
    if timeout_ms <= 0 {
        return error_json("request", "timeout must be positive");
    }
    let timeout = Duration::from_millis(timeout_ms as u64);
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return error_json("request", "timeout overflowed");
    };
    let cancellation = CancellationToken::new();
    let cancellation_key = (caller_id.clone(), request_id.clone());
    {
        let mut active = match runtime.active_cancellations.lock() {
            Ok(active) => active,
            Err(_) => return error_json("runtime", "cancellation registry is poisoned"),
        };
        if active.contains_key(&cancellation_key) {
            return error_json(
                "request",
                "caller/request identity already has an active evaluation",
            );
        }
        active.insert(cancellation_key.clone(), cancellation.clone());
    }
    let response = match runtime.inner.lock() {
        Ok(mut inner) => {
            let request = RuntimeRequest {
                caller_id,
                request_id,
                source,
                bindings,
                limits: RuntimeRequestLimits {
                    deadline: Some(deadline),
                    ..RuntimeRequestLimits::default()
                },
                cancellation,
            };
            match inner
                .prepare_request(request)
                .and_then(|request| inner.execute_request(request))
            {
                Ok(result) => {
                    let selected = match &result.value {
                        OValue::Map { v } => (
                            v.get("source_index").and_then(|value| value.as_int().ok()),
                            v.get("score_milli").and_then(|value| value.as_int().ok()),
                        ),
                        _ => (None, None),
                    };
                    json!({
                        "schema": "ostadix.runtime-request-result/v1",
                        "disposition": "executed",
                        "executionMode": "embedded_runtime_request",
                        "ok": true,
                        "stage": "complete",
                        "callerId": result.caller_id,
                        "requestId": result.request_id,
                        "type": result.value.type_name(),
                        "output": match &result.value {
                            OValue::Text { v } => v.utf8.clone(),
                            OValue::Html { v } => v.clone(),
                            other => other.to_string(),
                        },
                        "typedValue": &result.value,
                        "selectedSourceIndex": selected.0,
                        "selectedScoreMilli": selected.1,
                        "planNodes": result.plan_nodes,
                        "hgraphNodes": result.hgraph_nodes,
                        "hgraphExecEdges": result.hgraph_exec_edges,
                        "sourceSha256": result.evidence.source_sha256,
                        "executionIntentSha256": result.evidence.execution_intent_sha256,
                        "requestScopeContentIdentity": result.evidence.request_scope_content_identity,
                        "oirSha256": result.evidence.oir_sha256,
                        "planSha256": result.evidence.plan_sha256,
                        "analyzedGraphSha256": result.evidence.analyzed_graph_sha256,
                        "evidenceSha256": result.evidence.evidence_sha256,
                        "admittedGraphSha256": result.evidence.admitted_graph_sha256,
                        "admissionSha256": result.evidence.admission_sha256,
                        "resultContentIdentity": result.evidence.result_content_identity,
                        "elapsedMs": result.elapsed.as_millis(),
                    })
                    .to_string()
                }
                Err(error) => error_json(&error.stage().to_string(), error.message()),
            }
        }
        Err(_) => error_json("runtime", "runtime lock is poisoned"),
    };
    match runtime.active_cancellations.lock() {
        Ok(mut active) => {
            active.remove(&cancellation_key);
        }
        Err(_) => return error_json("runtime", "cancellation registry is poisoned"),
    }
    response
}

/// Execute a bounded request with ordinary JSON values exposed as typed O bindings.
/// The original no-binding JNI entry point remains stable for existing hosts.
#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativeEvaluateBoundedWithBindings(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
    source: JString<'_>,
    bindings_json: JString<'_>,
    caller_id: JString<'_>,
    request_id: JString<'_>,
    timeout_ms: jlong,
) -> jstring {
    with_jni_env(&mut unowned_env, |env| {
        if handle == 0 {
            return java_string(env, error_json("runtime", "runtime is closed"));
        }
        let read = |env: &mut Env<'_>, value: &JString<'_>, name: &str| {
            value
                .try_to_string(env)
                .map_err(|error| format!("invalid {name}: {error}"))
        };
        let source = match read(env, &source, "source") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let bindings_json = match read(env, &bindings_json, "bindings JSON") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let caller_id = match read(env, &caller_id, "caller id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let request_id = match read(env, &request_id, "request id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let bindings = match parse_bindings_json(&bindings_json) {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("bindings", error)),
        };
        // SAFETY: created by nativeCreate, serialized by the Java wrapper, and
        // released exactly once by nativeDestroy.
        let runtime = unsafe { &*(handle as *mut AndroidRuntime) };
        java_string(
            env,
            execute_bounded(runtime, source, caller_id, request_id, bindings, timeout_ms),
        )
    })
}

/// Evaluate a complete O document and return a small JSON envelope. JNI is
/// deliberately coarse-grained: terminal rendering never crosses this edge.
#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativeEvaluate(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
    source: JString<'_>,
) -> jstring {
    with_jni_env(&mut unowned_env, |env| {
        if handle == 0 {
            return java_string(env, error_json("runtime", "runtime is closed"));
        }

        let source: String = match source.try_to_string(env) {
            Ok(value) => value,
            Err(error) => {
                return java_string(env, error_json("jni", format!("invalid source: {error}")))
            }
        };

        // SAFETY: `handle` is created by `nativeCreate`, access is serialized by
        // the Java wrapper and the allocation is released exactly once by
        // `nativeDestroy`.
        let runtime = unsafe { &*(handle as *mut AndroidRuntime) };
        let mut runtime = match runtime.inner.lock() {
            Ok(runtime) => runtime,
            Err(_) => return java_string(env, error_json("runtime", "runtime lock is poisoned")),
        };

        let response = match runtime.evaluate(&source) {
            Ok(value) => {
                let output = match &value {
                    OValue::Text { v } => v.utf8.clone(),
                    OValue::Html { v } => v.to_string(),
                    other => other.to_string(),
                };
                json!({
                    "ok": true,
                    "type": value.type_name(),
                    "output": output,
                })
                .to_string()
            }
            Err(error) => error_json(&error.stage().to_string(), error.message()),
        };
        java_string(env, response)
    })
}

/// Execute one explicitly identified, bounded Android request through the
/// canonical request preflight and graph evaluator.
#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativeEvaluateBounded(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
    source: JString<'_>,
    caller_id: JString<'_>,
    request_id: JString<'_>,
    timeout_ms: jlong,
) -> jstring {
    with_jni_env(&mut unowned_env, |env| {
        if handle == 0 {
            return java_string(env, error_json("runtime", "runtime is closed"));
        }
        let read = |env: &mut Env<'_>, value: &JString<'_>, name: &str| {
            value
                .try_to_string(env)
                .map_err(|error| format!("invalid {name}: {error}"))
        };
        let source = match read(env, &source, "source") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let caller_id = match read(env, &caller_id, "caller id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let request_id = match read(env, &request_id, "request id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        // SAFETY: created by nativeCreate, serialized by the Java wrapper, and
        // released exactly once by nativeDestroy.
        let runtime = unsafe { &*(handle as *mut AndroidRuntime) };
        let response = execute_bounded(
            runtime,
            source,
            caller_id,
            request_id,
            HashMap::new(),
            timeout_ms,
        );
        java_string(env, response)
    })
}

/// Select one policy-safe completed AICore reply from bounded scalar metadata.
/// Model-owned text, sessions, FDs, and buffers deliberately stay outside O.
#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativePostprocessAicoreReplies(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
    scores: JIntArray<'_>,
    stop_reasons: JIntArray<'_>,
    max_policy_scores: JIntArray<'_>,
    policy_limit: jint,
    caller_id: JString<'_>,
    request_id: JString<'_>,
    timeout_ms: jlong,
) -> jstring {
    with_jni_env(&mut unowned_env, |env| {
        if handle == 0 {
            return java_string(env, error_json("runtime", "runtime is closed"));
        }
        let lengths = [
            scores.len(env),
            stop_reasons.len(env),
            max_policy_scores.len(env),
        ];
        let lengths = match lengths {
            [Ok(a), Ok(b), Ok(c)] if a == b && b == c && (1..=3).contains(&a) => a,
            [Ok(_), Ok(_), Ok(_)] => {
                return java_string(
                    env,
                    error_json(
                        "request",
                        "reply arrays must have equal length from 1 through 3",
                    ),
                )
            }
            _ => return java_string(env, error_json("jni", "could not read reply arrays")),
        };
        let mut score_values = vec![0; lengths];
        let mut stop_values = vec![0; lengths];
        let mut policy_values = vec![0; lengths];
        if scores.get_region(env, 0, &mut score_values).is_err()
            || stop_reasons.get_region(env, 0, &mut stop_values).is_err()
            || max_policy_scores
                .get_region(env, 0, &mut policy_values)
                .is_err()
        {
            return java_string(env, error_json("jni", "could not copy reply arrays"));
        }
        let read = |env: &mut Env<'_>, value: &JString<'_>, name: &str| {
            value
                .try_to_string(env)
                .map_err(|error| format!("invalid {name}: {error}"))
        };
        let caller_id = match read(env, &caller_id, "caller id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let request_id = match read(env, &request_id, "request id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let mut bindings =
            HashMap::from([("policy_limit".into(), OValue::int(i64::from(policy_limit)))]);
        for index in 0..3 {
            let present = usize::from(index < lengths);
            bindings.insert(format!("present_{index}"), OValue::int(present as i64));
            bindings.insert(
                format!("score_{index}"),
                OValue::int(score_values.get(index).copied().unwrap_or(0).into()),
            );
            bindings.insert(
                format!("stop_reason_{index}"),
                OValue::int(stop_values.get(index).copied().unwrap_or(0).into()),
            );
            bindings.insert(
                format!("max_policy_score_{index}"),
                OValue::int(policy_values.get(index).copied().unwrap_or(0).into()),
            );
        }
        // SAFETY: created by nativeCreate, serialized by the Java wrapper, and
        // released exactly once by nativeDestroy.
        let runtime = unsafe { &*(handle as *mut AndroidRuntime) };
        let response = execute_bounded(
            runtime,
            AICORE_REPLY_POSTPROCESS.into(),
            caller_id,
            request_id,
            bindings,
            timeout_ms,
        );
        java_string(env, response)
    })
}

/// Select one nonempty, safety-classified Smart Reply from bounded scalar metadata.
/// The generated reply text remains in AICore's Java object and never crosses JNI.
#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativePostprocessAicoreSmartReplies(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
    scores: JIntArray<'_>,
    has_text: JIntArray<'_>,
    safety_classifications: JIntArray<'_>,
    caller_id: JString<'_>,
    request_id: JString<'_>,
    timeout_ms: jlong,
) -> jstring {
    with_jni_env(&mut unowned_env, |env| {
        if handle == 0 {
            return java_string(env, error_json("runtime", "runtime is closed"));
        }
        let lengths = [
            scores.len(env),
            has_text.len(env),
            safety_classifications.len(env),
        ];
        let lengths = match lengths {
            [Ok(a), Ok(b), Ok(c)] if a == b && b == c && (1..=3).contains(&a) => a,
            [Ok(_), Ok(_), Ok(_)] => {
                return java_string(
                    env,
                    error_json(
                        "request",
                        "Smart Reply arrays must have equal length from 1 through 3",
                    ),
                )
            }
            _ => return java_string(env, error_json("jni", "could not read Smart Reply arrays")),
        };
        let mut score_values = vec![0; lengths];
        let mut has_text_values = vec![0; lengths];
        let mut safety_values = vec![0; lengths];
        if scores.get_region(env, 0, &mut score_values).is_err()
            || has_text.get_region(env, 0, &mut has_text_values).is_err()
            || safety_classifications
                .get_region(env, 0, &mut safety_values)
                .is_err()
        {
            return java_string(env, error_json("jni", "could not copy Smart Reply arrays"));
        }
        if has_text_values.iter().any(|value| !matches!(*value, 0 | 1)) {
            return java_string(
                env,
                error_json("request", "Smart Reply has_text values must be 0 or 1"),
            );
        }
        let read = |env: &mut Env<'_>, value: &JString<'_>, name: &str| {
            value
                .try_to_string(env)
                .map_err(|error| format!("invalid {name}: {error}"))
        };
        let caller_id = match read(env, &caller_id, "caller id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let request_id = match read(env, &request_id, "request id") {
            Ok(value) => value,
            Err(error) => return java_string(env, error_json("jni", error)),
        };
        let mut bindings = HashMap::new();
        for index in 0..3 {
            let present = usize::from(index < lengths);
            bindings.insert(format!("present_{index}"), OValue::int(present as i64));
            bindings.insert(
                format!("score_{index}"),
                OValue::int(score_values.get(index).copied().unwrap_or(0).into()),
            );
            bindings.insert(
                format!("has_text_{index}"),
                OValue::int(has_text_values.get(index).copied().unwrap_or(0).into()),
            );
            bindings.insert(
                format!("safety_classification_{index}"),
                OValue::int(safety_values.get(index).copied().unwrap_or(0).into()),
            );
        }
        // SAFETY: created by nativeCreate, serialized by the Java wrapper, and
        // released exactly once by nativeDestroy.
        let runtime = unsafe { &*(handle as *mut AndroidRuntime) };
        let response = execute_bounded(
            runtime,
            AICORE_SMART_REPLY_POSTPROCESS.into(),
            caller_id,
            request_id,
            bindings,
            timeout_ms,
        );
        java_string(env, response)
    })
}

/// Propagate an owning request's cancellation signal to one active evaluation.
/// Returns false if the request has not started or has already completed.
#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativeCancelRequest(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
    caller_id: JString<'_>,
    request_id: JString<'_>,
) -> jboolean {
    with_jni_env(&mut unowned_env, |env| {
        if handle == 0 {
            return false;
        }
        let caller_id = match caller_id.try_to_string(env) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let request_id = match request_id.try_to_string(env) {
            Ok(value) => value,
            Err(_) => return false,
        };
        // SAFETY: the Java lifecycle read lock permits cancellation concurrently
        // with evaluation while its write lock excludes nativeDestroy.
        let runtime = unsafe { &*(handle as *mut AndroidRuntime) };
        let active = match runtime.active_cancellations.lock() {
            Ok(active) => active,
            Err(_) => return false,
        };
        let Some(cancellation) = active.get(&(caller_id, request_id)) else {
            return false;
        };
        cancellation.cancel();
        true
    })
}

#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativeVersion(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jstring {
    with_jni_env(&mut unowned_env, |env| {
        java_string(env, env!("CARGO_PKG_VERSION").to_string())
    })
}

#[no_mangle]
pub extern "system" fn Java_org_ostadix_terminal_OstadixRuntime_nativeDestroy(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if handle != 0 {
        // SAFETY: ownership of the pointer is returned exactly once by the
        // Java wrapper's synchronized `close` method.
        unsafe { drop(Box::from_raw(handle as *mut AndroidRuntime)) };
    }
}
