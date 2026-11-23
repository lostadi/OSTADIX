//! Informational request timers. These never create an execution deadline.

use rmcp::{model::ProgressNotificationParam, service::RequestContext, RoleServer};
use std::future::Future;
use std::time::{Duration, Instant};

fn clock(seconds: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn message(elapsed: Duration, timeout_secs: Option<u64>) -> String {
    let elapsed_text = clock(elapsed.as_secs());
    match timeout_secs.filter(|seconds| *seconds != 0) {
        Some(seconds) => {
            let remaining = Duration::from_secs(seconds).saturating_sub(elapsed);
            let seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0);
            format!(
                "Request elapsed {elapsed_text}; requested timeout remaining ~{} (request clock)",
                clock(seconds)
            )
        }
        None => format!(
            "Request elapsed {elapsed_text}; no request timeout (cancel manually if needed)"
        ),
    }
}

/// Progress delivery is polled beside the operation, never in its critical
/// path. A slow/disconnected progress consumer cannot delay the result, and
/// dropping this future drops its notification loop without a detached task.
pub(super) async fn track<F: Future>(
    context: &RequestContext<RoleServer>,
    timeout_secs: Option<u64>,
    enabled: bool,
    operation: F,
) -> F::Output {
    let token = enabled.then(|| context.meta.get_progress_token()).flatten();
    let Some(token) = token else {
        return operation.await;
    };
    with_notifications(
        operation,
        timeout_secs,
        Duration::from_secs(1),
        |elapsed, message| {
            context.peer.notify_progress(
                ProgressNotificationParam::new(token.clone(), elapsed).with_message(message),
            )
        },
    )
    .await
}

async fn with_notifications<F, N, NF, T>(
    operation: F,
    timeout_secs: Option<u64>,
    interval: Duration,
    mut notify: N,
) -> F::Output
where
    F: Future,
    N: FnMut(f64, String) -> NF,
    NF: Future<Output = T>,
{
    let started = Instant::now();
    let notifications = async {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            let elapsed = started.elapsed();
            // Elapsed is monotonic numeric progress; a countdown belongs in
            // the message, not a decreasing MCP progress value. There is no
            // total because wall time is not a completion percentage.
            notify(elapsed.as_secs_f64(), message(elapsed, timeout_secs)).await;
        }
    };
    tokio::select! {
        biased;
        result = operation => result,
        _ = notifications => unreachable!("notification loop runs until the operation ends"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn countdown_is_explicit_and_saturates_without_a_default_limit() {
        assert!(message(Duration::from_secs(125), None).contains("no request timeout"));
        assert!(message(Duration::from_secs(125), Some(0)).contains("no request timeout"));
        assert!(
            message(Duration::from_millis(1200), Some(3)).ends_with("~00:00:02 (request clock)")
        );
        assert!(message(Duration::from_secs(5), Some(3)).ends_with("~00:00:00 (request clock)"));
    }

    #[tokio::test]
    async fn progress_increases_and_stops_when_the_operation_completes() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let sink = messages.clone();
        let result = with_notifications(
            async {
                tokio::time::sleep(Duration::from_millis(85)).await;
                42
            },
            None,
            Duration::from_millis(20),
            move |elapsed, text| {
                sink.lock().unwrap().push((elapsed, text));
                std::future::ready(())
            },
        )
        .await;
        assert_eq!(result, 42);
        let count = messages.lock().unwrap().len();
        assert!(count >= 2);
        tokio::time::sleep(Duration::from_millis(40)).await;
        let messages = messages.lock().unwrap();
        assert_eq!(messages.len(), count);
        assert!(messages.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert!(messages
            .iter()
            .all(|(_, text)| text.contains("no request timeout")));
    }

    #[tokio::test]
    async fn blocked_progress_delivery_does_not_delay_completion() {
        let result = tokio::time::timeout(
            Duration::from_millis(300),
            with_notifications(
                async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    "done"
                },
                Some(1),
                Duration::from_millis(10),
                |_, _| std::future::pending::<()>(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(result, "done");
    }

    #[tokio::test]
    async fn protocol_progress_requires_a_token_and_a_foreground_request() {
        use rmcp::model::{
            CallToolRequestParams, CallToolResponse, CallToolResult, ServerCapabilities,
            ServerConfig,
        };
        use rmcp::{ServerHandler, ServiceExt};
        use serde_json::{json, Value};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        struct TimerServer;
        impl ServerHandler for TimerServer {
            fn get_info(&self) -> ServerConfig {
                ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            }

            async fn call_tool(
                &self,
                request: CallToolRequestParams,
                context: RequestContext<RoleServer>,
            ) -> Result<CallToolResponse, rmcp::ErrorData> {
                track(&context, Some(5), request.name != "background", async {
                    tokio::time::sleep(Duration::from_millis(2150)).await;
                    Ok(CallToolResult::success(Vec::new()).into())
                })
                .await
            }
        }

        let (server, client) = tokio::io::duplex(8192);
        let service = tokio::spawn(async move {
            TimerServer
                .serve(server)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let (read, mut write) = tokio::io::split(client);
        let mut lines = BufReader::new(read).lines();
        let initialize = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
            "protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"timer-test","version":"1"}
        }});
        write
            .write_all(format!("{initialize}\n").as_bytes())
            .await
            .unwrap();
        let initialized: Value =
            serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(initialized["id"], 0);
        write
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();

        for (id, with_token, background) in [(1, false, false), (2, true, false), (3, true, true)] {
            let mut params =
                json!({"name":if background {"background"} else {"foreground"},"arguments":{}});
            if with_token {
                params["_meta"] = json!({"progressToken":"timer-test"});
            }
            let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params});
            write
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
            let mut progress = Vec::new();
            loop {
                let line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let response: Value = serde_json::from_str(&line).unwrap();
                if response["id"] == id {
                    assert!(response.get("error").is_none(), "{response}");
                    break;
                }
                assert_eq!(response["method"], "notifications/progress");
                progress.push(response["params"].clone());
            }
            if with_token && !background {
                assert!(progress.len() >= 2, "{progress:?}");
                assert!(progress
                    .windows(2)
                    .all(|pair| pair[0]["progress"].as_f64().unwrap()
                        < pair[1]["progress"].as_f64().unwrap()));
                assert!(progress
                    .iter()
                    .all(|entry| entry["progressToken"] == "timer-test"
                        && entry.get("total").is_none()));
                assert!(progress[0]["message"]
                    .as_str()
                    .unwrap()
                    .contains("(request clock)"));
            } else {
                assert!(progress.is_empty(), "unsolicited progress: {progress:?}");
            }
        }
        drop(write);
        drop(lines);
        tokio::time::timeout(Duration::from_secs(3), service)
            .await
            .unwrap()
            .unwrap();
    }
}
