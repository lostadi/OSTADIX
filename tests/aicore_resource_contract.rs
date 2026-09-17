#![cfg(any(target_os = "android", target_os = "linux"))]

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ostadix_api::executor::CancellationToken;
use ostadix_api::{OValue, Runtime, RuntimeRequest, RuntimeRequestLimits};

const PROGRAM: &str = include_str!("fixtures/aicore_llm_reply_postprocess.O");

fn reply(text: &str, score: i64, policy: i64) -> OValue {
    OValue::map(HashMap::from([
        ("text".into(), OValue::text(text)),
        ("score_milli".into(), OValue::int(score)),
        ("stop_reason".into(), OValue::int(0)),
        (
            "policy_scores_milli".into(),
            OValue::list(vec![OValue::int(policy)]),
        ),
    ]))
}

fn request(index: usize) -> RuntimeRequest {
    RuntimeRequest {
        caller_id: "aicore-resource-contract/uid-1000".into(),
        request_id: format!("resource-{index}"),
        source: PROGRAM.into(),
        bindings: HashMap::from([
            (
                "replies".into(),
                OValue::list(vec![
                    reply("lower", 500, 10),
                    reply("winner", 900 + index as i64, 20),
                ]),
            ),
            ("policy_limit".into(), OValue::int(500)),
        ]),
        limits: RuntimeRequestLimits::default(),
        cancellation: CancellationToken::new(),
    }
}

fn open_fd_count() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

fn resident_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap()
}

fn child_pids() -> BTreeSet<u32> {
    let task = format!("/proc/{}/task", std::process::id());
    let mut children = BTreeSet::new();
    for entry in fs::read_dir(task).unwrap() {
        let path = entry.unwrap().path().join("children");
        let Ok(value) = fs::read_to_string(path) else {
            continue;
        };
        children.extend(
            value
                .split_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok()),
        );
    }
    children
}

#[test]
fn repeated_typed_requests_release_descriptors_and_owned_backend_processes() {
    let initial_fds = open_fd_count();
    let initial_rss = resident_kib();
    let initial_children = child_pids();
    let mut max_fds = initial_fds;
    let mut max_rss = initial_rss;
    let mut latencies = Vec::new();

    {
        let mut runtime = Runtime::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("backends"))
            .with_runtime_executable(Path::new(env!("CARGO_BIN_EXE_O")));
        for index in 0..12 {
            let started = Instant::now();
            let result = runtime
                .prepare_request(request(index))
                .and_then(|prepared| runtime.execute_request(prepared))
                .unwrap();
            latencies.push(started.elapsed().as_secs_f64() * 1000.0);
            assert_eq!(result.request_id, format!("resource-{index}"));
            let OValue::Map { v } = &result.value else {
                panic!("expected typed OMap result, got {:?}", result.value);
            };
            assert_eq!(v.get("score_milli"), Some(&OValue::int(900 + index as i64)));
            max_fds = max_fds.max(open_fd_count());
            max_rss = max_rss.max(resident_kib());
        }
    }

    let final_fds = open_fd_count();
    let final_children = child_pids();
    latencies.sort_by(f64::total_cmp);
    let percentile = |numerator: usize| latencies[(latencies.len() - 1) * numerator / 100];
    eprintln!(
        "aicore_resource_contract requests={} p50_ms={:.3} p95_ms={:.3} max_rss_delta_kib={} max_fd_delta={} final_fd_delta={}",
        latencies.len(),
        percentile(50),
        percentile(95),
        max_rss.saturating_sub(initial_rss),
        max_fds.saturating_sub(initial_fds),
        final_fds.saturating_sub(initial_fds),
    );

    assert_eq!(
        final_children, initial_children,
        "owned backend child leaked"
    );
    assert!(
        final_fds <= initial_fds + 2,
        "file descriptors grew from {initial_fds} to {final_fds}"
    );
}
