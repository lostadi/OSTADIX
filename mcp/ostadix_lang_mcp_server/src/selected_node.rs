//! Complete-document hosted execution through the native authenticated client.
//! This is separate from project mesh and never adds local fallback or retries.

use super::*;

// Hosted V1's existing wire contract, not a bound on ordinary O execution.
const HOSTED_SOURCE_BYTES: usize = 1024 * 1024;

fn native_timeouts(requested: Option<u64>) -> (u64, u64) {
    match requested.filter(|seconds| *seconds != 0) {
        Some(seconds) => (seconds.min(3600), seconds.min(86400)),
        None => (60, 300),
    }
}

impl OstadixMcp {
    pub(super) async fn execute_selected_node(
        &self,
        args: &ExecuteArgs,
        input: &Input,
        node: &str,
        deadline: Option<Instant>,
        context: &RequestContext<RoleServer>,
    ) -> Result<Value, String> {
        // Pin the submitted bytes even for path input; no later read of the
        // caller's mutable file can change the document sent by this request.
        let mut file = tokio::fs::File::open(
            input
                .path
                .as_ref()
                .ok_or("node input requires a source snapshot")?,
        )
        .await
        .map_err(|e| format!("open node source: {e}"))?;
        let mut bytes = Vec::new();
        (&mut file)
            .take((HOSTED_SOURCE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| format!("read node source: {e}"))?;
        if bytes.len() > HOSTED_SOURCE_BYTES {
            return Err(format!("selected-node hosted V1 source exceeds its {HOSTED_SOURCE_BYTES}-byte native protocol limit; use local execution or a supported project-mesh artifact"));
        }
        let source =
            String::from_utf8(bytes).map_err(|e| format!("node source is not UTF-8: {e}"))?;
        if is_project_source(&source) {
            return Err("node cannot execute a lifted project's routes; use project mesh".into());
        }
        let snapshot = SourceSnapshot::new(&source)?;
        let (io_timeout, publication_deadline) = native_timeouts(args.timeout_secs);
        let mut result = self
            .unified_job(
                CliArgs {
                    command: "octl".into(),
                    args: vec![
                        "node".into(),
                        "run".into(),
                        format!("--node={node}"),
                        "--io-timeout-seconds".into(),
                        io_timeout.to_string(),
                        "--deadline-seconds".into(),
                        publication_deadline.to_string(),
                        snapshot.path.display().to_string(),
                    ],
                    cwd: Some(input.cwd.display().to_string()),
                    env: args.env.clone(),
                    stdin: None,
                    timeout_secs: remaining_timeout(deadline)?,
                    background: args.background,
                    pty: false,
                },
                Some(snapshot),
                context,
            )
            .await?;
        result["action"] = json!("execute");
        result["mode"] = json!("direct");
        result["placement"] = json!({"route":"selected-node-document", "requested_node":node,
            "local_fallback":false, "ordinary_graph_partitioning":false});
        result["input"] = json!({"kind":"ordinary", "source_inline":args.source.is_some(),
            "cwd":input.cwd, "context_scope":"local-client-only"});
        result["admission"] = json!({"contract":"native-hosted-v1", "source_intent_binding":false,
            "receipt_kind":"digest-bound-over-mutual-tls"});
        result["remote_execution"] = json!({"completion":"unknown", "automatic_retry":false,
            "cancellation_scope":"local-client-only", "remote_effects_may_continue":true,
            "native_io_timeout_secs":io_timeout, "native_publication_deadline_secs":publication_deadline,
            "deadline_cancels_effects":false});
        if result["state"] != "running" && result["stdout"]["path"].is_string() {
            match bounded_stdout(&result, false)
                .await
                .and_then(|stdout| native_json(&stdout))
            {
                Ok(receipt) if receipt["schema"] == "ostadix.hosted-operation-receipt/v1" => {
                    result["remote_execution"]["completion"] = receipt["outcome"]["status"].clone();
                    if let Some(value) = receipt["outcome"].get("value") {
                        result["value"] = value.clone();
                    }
                    result["result"] = receipt;
                }
                native => {
                    result["result"] = Value::Null;
                    result["result_projection_error"] = json!(native.err().unwrap_or_else(|| {
                        "native node client did not return a hosted V1 receipt".into()
                    }));
                    result["result_retrieval"] = json!({"tool":"o_job_read", "job_id":result["job_id"],
                        "stream":"stdout", "offset":0, "full_output_retained":true});
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_supervisor_zero_does_not_claim_unbounded_native_service() {
        assert_eq!(native_timeouts(None), (60, 300));
        assert_eq!(native_timeouts(Some(0)), (60, 300));
        assert_eq!(native_timeouts(Some(45)), (45, 45));
        assert_eq!(native_timeouts(Some(5000)), (3600, 5000));
        assert_eq!(native_timeouts(Some(100000)), (3600, 86400));
    }
}
