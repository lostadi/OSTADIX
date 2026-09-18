//! Human-facing CLI diagnostics. These views never change engine errors,
//! execution, admission, source digests, or machine-readable output schemas.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::eval::{Evaluator, TraceEvent};
use crate::hgraph::{HGraph, NodeId};
use crate::ir::{OIrProgram, PlanNodeId};
use crate::parser::{Parser, SourceSpanV1};

/// Render an error chain for stderr. The caller retains control of exit codes
/// and stdout, including JSON and native backend protocols.
pub fn render_error(tool: &str, error: &anyhow::Error) -> String {
    if let Some(rendered) = error.downcast_ref::<HumanDiagnostic>() {
        return rendered.report.clone();
    }
    let mut report = error_heading(tool, "command", error);
    append_help(&mut report, error, None);
    report
}

/// Attach a presentation sidecar to an unchanged underlying error chain.
/// Use only at CLI boundaries, after any JSON error envelope has been built.
pub fn with_human_diagnostic(error: anyhow::Error, report: String) -> anyhow::Error {
    error.context(HumanDiagnostic { report })
}

#[derive(Debug)]
struct HumanDiagnostic {
    report: String,
}

impl std::fmt::Display for HumanDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source diagnostic attached")
    }
}

/// Render the exact source and a genuine source-projected HGraph. Parsing and
/// projection are inspection only: this function never admits or executes
/// anything. Runtime failure identities are used only when the retained plan
/// matches this source's canonical plan; nested/dynamic evaluations otherwise
/// remain explicitly unlocated.
pub fn render_o_error(
    tool: &str,
    error: &anyhow::Error,
    input: &str,
    source: &str,
    phase: &str,
    evaluator: Option<&Evaluator>,
) -> String {
    if error.downcast_ref::<HumanDiagnostic>().is_some() {
        return render_error(tool, error);
    }
    let backends = crate::ir::BackendRegistry::global().registered_backend_tags();
    let mut parser = Parser::new(source, &backends);
    let parsed = match parser.parse_with_origins() {
        Ok(parsed) => parsed,
        Err(inspection_error) => {
            let causes: Vec<_> = error.chain().map(ToString::to_string).collect();
            let inspection_message = inspection_error.to_string();
            let source_parse_failed = causes.contains(&inspection_message);
            // Some established entry points strip the shebang before parsing.
            // Compare the actual errors instead of guessing from a word such
            // as "expected", which can also describe a transport/build error.
            let parser_relative = !source_parse_failed
                && source.starts_with("#!")
                && source.split_once('\n').is_some_and(|(_, executable)| {
                    Parser::new(executable, &backends)
                        .parse()
                        .err()
                        .is_some_and(|parse_error| causes.contains(&parse_error.to_string()))
                });
            let primary_parse_failure = source_parse_failed || parser_relative || phase == "parse";
            let mut report = error_heading(
                tool,
                if primary_parse_failure {
                    "parse"
                } else {
                    phase
                },
                error,
            );
            if !primary_parse_failure {
                writeln!(
                    report,
                    "\nSource inspection also failed (secondary): {}",
                    visible(&inspection_message)
                )
                .unwrap();
            }
            append_source(&mut report, input, source, parser.diagnostic_position());
            if parser_relative {
                report.push_str("  The original parser cause omits the shebang line; this excerpt uses original document coordinates.\n");
            }
            report.push_str("\nHGraph: not constructed because source inspection could not parse this document.\n");
            append_help(&mut report, error, Some(input));
            return report;
        }
    };
    let program = OIrProgram::lower(parsed.nodes());
    let plan = program.plan();
    let matching_evaluator = evaluator.filter(|e| e.last_execution_plan() == Some(&plan));
    let failed = matching_evaluator
        .and_then(Evaluator::last_execution_trace)
        .and_then(|trace| {
            trace.events.iter().find_map(|event| match event {
                TraceEvent::NodeFailed { id, .. } => Some(*id),
                _ => None,
            })
        });
    let mut report = error_heading(tool, phase, error);
    if let Some(span) = failed.and_then(|id| parsed.origin_for_plan_node(id)) {
        append_source(&mut report, input, source, *span);
    } else {
        writeln!(report, "\n  --> {}", visible(input)).unwrap();
        report.push_str("  No exact failing source operation was recorded for this document.\n");
    }
    match program.hgraph_for_plan(&plan) {
        Ok(graph) => {
            append_graph(&mut report, &graph, failed);
            if evaluator.is_some() && matching_evaluator.is_none() {
                report.push_str("  The retained execution plan belongs to a different evaluation; its node IDs were not applied to this source.\n");
            }
            if !input.starts_with('<') {
                let input = shell_word(input);
                writeln!(report, "\ninspect: olangc {input} --target ir").unwrap();
                writeln!(report, "         olangc {input} --target dot > graph.dot").unwrap();
                report.push_str("         These explicit views retain the complete source graph; this diagnostic shows only its local neighborhood.\n");
            } else {
                report.push_str("\ninspect: save the exact inline or embedded source as program.O, then use\n         olangc program.O --target ir\n         olangc program.O --target dot > graph.dot\n         These explicit views retain the complete source graph.\n");
            }
        }
        Err(reason) => {
            writeln!(
                report,
                "\nHGraph: construction rejected: {}",
                visible(&reason)
            )
            .unwrap();
            report.push_str(
                "  No valid graph is available; no node or edge identities were invented.\n",
            );
        }
    }
    append_help(&mut report, error, Some(input));
    report
}

/// Render native compiler data without importing the O-core compiler into the
/// hosted AOT runtime. The caller adapts the compiler's actual diagnostic.
/// Missing/generated locations remain unlocated, never guessed.
pub fn render_native_error(
    tool: &str,
    message: &str,
    input: &str,
    source: Option<&str>,
    span: Option<SourceSpanV1>,
    phase: &str,
) -> String {
    let mut report = format!(
        "error: {} failed\nphase: {}\ncause: {}\n",
        visible(tool),
        visible(phase),
        visible(message)
    );
    if let Some((source, span)) = source.zip(span) {
        append_source(&mut report, input, source, span);
    } else {
        writeln!(report, "\n  --> {}", visible(input)).unwrap();
        report.push_str("  This compiler failure has no source span.\n");
    }
    report.push_str(
        "\nO-core pipeline: source -> AST -> typed HIR -> SSA MIR -> target assembly/object.\n",
    );
    report.push_str("  O-core native compilation does not construct a hosted O HGraph.\n");
    if !input.starts_with('<') {
        writeln!(
            report,
            "\nnext: correct the marked .oc source, then rerun the same compilation command with all of its input modules.\ninspect: ocorec --check {} (parse only; does not typecheck or execute)",
            shell_word(input)
        )
        .unwrap();
    } else {
        report.push_str("\nnext: check the selected target, assembler, and output path reported in the cause.\n");
    }
    report
}

fn error_heading(tool: &str, phase: &str, error: &anyhow::Error) -> String {
    let causes: Vec<_> = error
        .chain()
        .map(|cause| visible(&cause.to_string()))
        .collect();
    let mut report = format!(
        "error: {} failed\nphase: {}\ncause: {}\n",
        visible(tool),
        visible(phase),
        causes
            .last()
            .map(String::as_str)
            .unwrap_or("unknown failure")
    );
    if causes.len() > 1 {
        report.push_str("\ncontext (outermost first):\n");
        for cause in &causes[..causes.len() - 1] {
            writeln!(report, "  - {}", cause.replace('\n', "\n    ")).unwrap();
        }
    }
    report
}

fn append_source(report: &mut String, input: &str, source: &str, span: SourceSpanV1) {
    let start = floor_char_boundary(source, span.start_byte.min(source.len()));
    let end = floor_char_boundary(source, span.end_byte.min(source.len()).max(start));
    let line_start = source[..start].rfind('\n').map_or(0, |index| index + 1);
    let line_end = source[start..]
        .find('\n')
        .map_or(source.len(), |index| start + index);
    let line = source[..line_start]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let column = source[line_start..start].chars().count() + 1;
    // Match the parser's Unicode-scalar columns. Expand tabs consistently in
    // both source and caret prefixes; never split a UTF-8 character.
    let before: String = source[line_start..start]
        .chars()
        .map(display_char)
        .collect();
    let text: String = source[line_start..line_end]
        .chars()
        .map(display_char)
        .collect();
    let width = source[start..end.min(line_end)]
        .chars()
        .map(display_char)
        .collect::<String>()
        .chars()
        .count()
        .max(1);
    writeln!(report, "\n  --> {}:{line}:{column}", visible(input)).unwrap();
    writeln!(report, "  {line} | {text}").unwrap();
    writeln!(
        report,
        "  {} | {}{}",
        " ".repeat(line.to_string().len()),
        " ".repeat(before.chars().count()),
        "^".repeat(width)
    )
    .unwrap();
    if end > line_end {
        report.push_str("       marked operation continues on following lines\n");
    }
}

fn floor_char_boundary(source: &str, mut byte: usize) -> usize {
    while !source.is_char_boundary(byte) {
        byte -= 1;
    }
    byte
}

fn display_char(character: char) -> String {
    match character {
        '\t' => "    ".to_string(),
        '\r' => "\\r".to_string(),
        value if value.is_control() => format!("\\u{{{:x}}}", value as u32),
        value => value.to_string(),
    }
}

fn visible(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' => "\n".to_string(),
            other => display_char(other),
        })
        .collect()
}

fn append_graph(report: &mut String, graph: &HGraph, failed: Option<PlanNodeId>) {
    writeln!(
        report,
        "\nHGraph: source projection ({} nodes, {} execution hyperedges, {} constraint hyperedges).",
        graph.node_count(), graph.execution_operation_count(), graph.constraint_edge_count()
    ).unwrap();
    report.push_str("  This is the validated source structure, not a snapshot of live materialization or admission state.\n");
    let Some(failed) = failed else {
        report.push_str(
            "  No failed runtime operation was recorded; the failure may precede execution.\n",
        );
        let operations = graph.exec_ops_ordered();
        for operation in operations.iter().take(6) {
            if let Some(edge) = graph.exec_edge(operation.edge) {
                writeln!(
                    report,
                    "  source P{} -> e{} {:?} inputs={} outputs={}",
                    operation.plan_node.0,
                    operation.edge.0,
                    edge.op,
                    node_list(&operation.inputs),
                    node_list(&operation.outputs)
                )
                .unwrap();
            }
        }
        if operations.len() > 6 {
            writeln!(
                report,
                "  {} more source operations are available in the complete graph view.",
                operations.len() - 6
            )
            .unwrap();
        }
        return;
    };
    let Some(operation) = graph.op_for(failed) else {
        writeln!(
            report,
            "  Recorded failure: P{} (no executable hyperedge in this projection).",
            failed.0
        )
        .unwrap();
        return;
    };
    let edge = graph
        .exec_edge(operation.edge)
        .expect("registered operation has an edge");
    writeln!(
        report,
        "  failed P{} -> e{} {:?}",
        failed.0, operation.edge.0, edge.op
    )
    .unwrap();
    writeln!(report, "  inputs:  {}", node_list(&operation.inputs)).unwrap();
    writeln!(report, "  outputs: {}", node_list(&operation.outputs)).unwrap();
    let mut nodes: BTreeSet<NodeId> = operation
        .inputs
        .iter()
        .chain(&operation.outputs)
        .copied()
        .collect();
    nodes.insert(operation.value_output);
    let mut neighbors = BTreeSet::new();
    for id in &nodes {
        if let Some(node) = graph.node(*id) {
            if let Some(producer) = node.producer {
                neighbors.insert(producer);
            }
            neighbors.extend(node.consumers.iter().copied());
        }
    }
    for id in nodes.iter().take(12) {
        if let Some(node) = graph.node(*id) {
            writeln!(
                report,
                "    n{} {:?} producer={} consumers=[{}]",
                id.0,
                node.kind,
                node.producer
                    .map_or_else(|| "none".to_string(), |id| format!("e{}", id.0)),
                node.consumers
                    .iter()
                    .map(|id| format!("e{}", id.0))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .unwrap();
        }
    }
    if nodes.len() > 12 {
        writeln!(
            report,
            "    {} more incident nodes are available in the complete graph view.",
            nodes.len() - 12
        )
        .unwrap();
    }
    neighbors.remove(&operation.edge);
    for neighbor in neighbors.iter().take(8) {
        if let Some(edge) = graph.exec_edge(*neighbor) {
            let ports = edge
                .ports
                .iter()
                .map(|port| format!("{:?}:n{}", port.role, port.node.0))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(
                report,
                "  adjacent e{} {:?} ports=[{ports}]",
                neighbor.0, edge.op
            )
            .unwrap();
        }
    }
    if neighbors.len() > 8 {
        writeln!(
            report,
            "  {} more adjacent hyperedges are available in the complete graph view.",
            neighbors.len() - 8
        )
        .unwrap();
    }
}

fn node_list(nodes: &[NodeId]) -> String {
    format!(
        "[{}]",
        nodes
            .iter()
            .map(|id| format!("n{}", id.0))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn append_help(report: &mut String, error: &anyhow::Error, input: Option<&str>) {
    let message = format!("{error:#}");
    let lower = message.to_ascii_lowercase();
    let hint = if message.contains("Unclosed expression") {
        "add the exact closing tag named in the cause, including its environment and attributes."
    } else if message.contains("Undefined variable") {
        "define the named value before this operation, or correct its $variable reference."
    } else if (message.contains("Line ") && message.contains("expected"))
        || message.contains("Malformed block attribute")
        || message.contains("Empty block attribute")
        || message.contains("Invalid character in block attribute")
    {
        "correct the syntax named in the cause at the marked source position."
    } else if lower.contains("permission denied") || lower.contains("operation not permitted") {
        "check access to the exact file/process named in the cause and the execution environment's permissions."
    } else if (lower.contains("connection") || lower.contains("connect") || lower.contains("tls"))
        && (lower.contains("timed out") || lower.contains("timeout") || lower.contains("refused"))
    {
        "check that the selected peer is powered on, reachable, and its node service is listening at the address in the cause; use o node list to inspect remembered/discovered peers and o node status to inspect the local node service."
    } else if lower.contains("certificate")
        || lower.contains("unknown issuer")
        || lower.contains("unknownissuer")
        || lower.contains("untrusted peer")
        || lower.contains("peer identity mismatch")
    {
        "inspect the selected peer and remembered identity with o node list; verify the existing pairing and certificate/trust configuration on both ends."
    } else if message.contains("not discovered") {
        "keep a fresh pairing offer running on the peer; for a routed network pass --address HOST:7340."
    } else if message.contains("Undefined backend")
        || message.contains("failed to spawn")
        || message.contains("not found")
        || message.contains("No such file")
        || lower.contains("not installed")
        || lower.contains("missing prerequisite")
        || (lower.contains("unavailable")
            && (lower.contains("runtime")
                || lower.contains("executable")
                || lower.contains("toolchain")))
    {
        "check the named input, backend shim, executable path, and required runtime prerequisites; use o doctor to inspect this installation and o which to see its selected commands."
    } else if message.contains("effects=")
        || message.contains("effect classification")
        || message.contains("cannot upgrade")
    {
        "correct the effect declaration; declaring purity does not establish that a backend is safe to run as pure."
    } else if input.is_some() {
        "correct the reported source or backend failure and rerun the same command; completed external effects are not rolled back."
    } else {
        "check the cause and command arguments; use the command's --help for its supported options."
    };
    writeln!(report, "\nnext: {hint}").unwrap();
}

fn shell_word(value: &str) -> String {
    format!("'{}'", visible(value).replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_source_excerpt_and_tab_keep_valid_boundaries_without_terminal_controls() {
        let source = "é\t$missing\x1b";
        let mut text = String::new();
        append_source(
            &mut text,
            "sample.O",
            source,
            SourceSpanV1 {
                start_byte: 3,
                end_byte: 11,
                start_line: 1,
                start_column: 3,
                end_line: 1,
                end_column: 11,
            },
        );
        assert!(text.contains("sample.O:1:3"), "{text}");
        assert!(text.contains("é    $missing\\u{1b}"), "{text}");
        assert!(text.contains("     ^^^^^^^^"), "{text}");
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn malformed_source_never_claims_to_have_an_hgraph() {
        let error = anyhow::anyhow!("Line 2: Unclosed expression, expected )_python");
        let text = render_o_error("O", &error, "bad.O", "python^(\n", "parse", None);
        assert!(text.contains("bad.O:2:1"), "{text}");
        assert!(text.contains("HGraph: not constructed"), "{text}");
        assert!(!text.contains("failed P"));
        assert!(text.contains("exact closing tag"));
    }

    #[test]
    fn error_sidecar_retains_underlying_typed_error() {
        let error = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        let wrapped = with_human_diagnostic(error, "precise diagnostic".to_string());
        assert!(wrapped.downcast_ref::<std::io::Error>().is_some());
        assert_eq!(render_error("O", &wrapped), "precise diagnostic");
    }

    #[test]
    fn unlocated_failures_show_source_structure_without_claiming_runtime_identity() {
        let text = render_o_error(
            "o",
            &anyhow::anyhow!("admission failed"),
            "example.O",
            "$missing",
            "admit",
            None,
        );
        assert!(text.contains("source P0 -> e"), "{text}");
        assert!(text.contains("inputs="), "{text}");
        assert!(text.contains("outputs="), "{text}");
        assert!(text.contains("No failed runtime operation"), "{text}");
        assert!(!text.contains("failed P"), "{text}");
    }

    #[test]
    fn expected_value_failures_are_not_mislabeled_as_syntax_errors() {
        let text = render_error(
            "o",
            &anyhow::anyhow!(
                "Python backend smoke did not produce the expected value 2; run o doctor"
            ),
        );
        assert!(!text.contains("correct the syntax"), "{text}");
    }

    #[test]
    fn shebang_parser_relative_cause_is_labeled_without_changing_it() {
        let source = "#!/usr/bin/env O\npython^(é\n";
        let backends = crate::ir::BackendRegistry::global().registered_backend_tags();
        let cause = Parser::new(source.split_once('\n').unwrap().1, &backends)
            .parse()
            .unwrap_err();
        let original = cause.to_string();
        let text = render_o_error("O", &cause, "é.O", source, "parse", None);
        assert!(text.contains(&format!("cause: {original}")), "{text}");
        assert!(text.contains("é.O:3:1"), "{text}");
        assert!(
            text.contains("original parser cause omits the shebang line"),
            "{text}"
        );
    }

    #[test]
    fn secondary_parse_failure_does_not_replace_the_actual_build_phase() {
        let text = render_o_error(
            "olangc",
            &anyhow::anyhow!("linker failed: output is read-only"),
            "broken.O",
            "python^(é",
            "native build",
            None,
        );
        assert!(text.contains("phase: native build"), "{text}");
        assert!(!text.contains("phase: parse"), "{text}");
        assert!(
            text.contains("cause: linker failed: output is read-only"),
            "{text}"
        );
        assert!(
            text.contains("Source inspection also failed (secondary):"),
            "{text}"
        );
        assert!(text.contains("broken.O:1:10"), "{text}");
        assert!(text.contains("HGraph: not constructed"), "{text}");
    }

    #[test]
    fn transport_hints_distinguish_reachability_from_existing_trust() {
        for cause in [
            "failed to establish mutually authenticated TLS with 100.121.192.11:7337: connection timed out",
            "TCP connection refused at 100.121.192.11:7337",
        ] {
            let text = render_error("octl", &anyhow::anyhow!(cause));
            assert!(text.contains(&format!("cause: {cause}")), "{text}");
            assert!(text.contains("reachable"), "{text}");
            assert!(text.contains("o node status"), "{text}");
            assert!(!text.contains("certificate/trust configuration"), "{text}");
        }
        let text = render_error(
            "octl",
            &anyhow::anyhow!("TLS certificate rejected: UnknownIssuer"),
        );
        assert!(text.contains("existing pairing"), "{text}");
        assert!(text.contains("certificate/trust configuration"), "{text}");
        assert!(!text.contains("reset"), "{text}");
        assert!(!text.contains("pair again"), "{text}");
        let text = render_error("octl", &anyhow::anyhow!("Malformed TLS certificate"));
        assert!(text.contains("certificate/trust configuration"), "{text}");
        assert!(!text.contains("correct the syntax"), "{text}");
    }

    #[test]
    fn prerequisite_and_permission_hints_retain_the_exact_failing_path() {
        let cause = "required runtime /opt/missing/python is not installed";
        let text = render_error("O", &anyhow::anyhow!(cause));
        assert!(text.contains(&format!("cause: {cause}")), "{text}");
        assert!(text.contains("o doctor"), "{text}");
        assert!(text.contains("o which"), "{text}");
        let cause = "permission denied opening /restricted/program.O";
        let text = render_error("O", &anyhow::anyhow!(cause));
        assert!(text.contains(&format!("cause: {cause}")), "{text}");
        assert!(
            text.contains("check access to the exact file/process"),
            "{text}"
        );
        assert!(!text.contains("sudo"), "{text}");
    }
}
