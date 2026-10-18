use super::*;
use crate::backend_catalog::BackendRegistry;
use crate::eval::{Evaluator, TraceEvent};
use crate::hgraph::from_oir::build_program;
use crate::hgraph::solve::solve_types;
use crate::hgraph::HNodeKind;
use crate::ir::{InvokeMode, OIr};
use crate::value::GroupMode;

fn program(trap: bool) -> OIrProgram {
    OIrProgram {
        nodes: vec![
            OIr::Store {
                name: "x".into(),
                expr: Box::new(OIr::Text("41".into())),
            },
            OIr::Store {
                name: "x".into(),
                expr: Box::new(OIr::Invoke {
                    fn_name: crate::native_leaf::BUILTIN.into(),
                    mode: InvokeMode::Eager,
                    args: vec![
                        OIr::Exec {
                            lang: "text".into(),
                            env_id: u32::MAX,
                            attr: None,
                            backend: BackendRegistry::global().interface_for("text"),
                            body: vec![OIr::Text(crate::native_leaf::test_descriptor(1, trap))],
                        },
                        OIr::Load("x".into()),
                    ],
                }),
            },
            OIr::Load("x".into()),
        ],
    }
}

#[test]
fn native_leaf_graph_store_chain_publishes_real_resource_successors() {
    let program = program(false);
    let plan = program.plan();
    let native = plan
        .nodes
        .iter()
        .find(|node| matches!(node.kind, PlanNodeKind::NativeI64 { .. }))
        .unwrap()
        .id;
    let stores: Vec<_> = plan
        .nodes
        .iter()
        .filter(|node| matches!(&node.kind,PlanNodeKind::Store {name} if name=="x"))
        .map(|node| node.id)
        .collect();
    assert_eq!(stores.len(), 2);
    let mut graph = build_program(&program);
    solve_types(&mut graph).unwrap();
    let versions: Vec<_> = graph
        .node_ids()
        .into_iter()
        .filter_map(|id| match &graph.node(id)?.kind {
            HNodeKind::ResourceState {
                resource: crate::effects::ResourceKey::ScopeBinding(name),
                version,
            } if name == "x" => Some(*version),
            _ => None,
        })
        .collect();
    assert_eq!(versions, vec![0, 1, 2]);
    let mut evaluator = Evaluator::new("/tmp".into());
    let mut scope = HashMap::new();
    let result = evaluator
        .eval_ir_program_graph_with_scope(&program, &mut scope)
        .unwrap();
    assert_eq!(crate::native_leaf::argument(&result).unwrap(), 42);
    assert_eq!(crate::native_leaf::argument(&scope["x"]).unwrap(), 42);
    let admission = evaluator.last_execution_admission().unwrap();
    assert_eq!(admission.executable_manifest().native_leaves.len(), 1);
    let operation = admission
        .operations()
        .iter()
        .find(|op| op.plan_node == native)
        .unwrap();
    assert_eq!(
        operation.evidence.dispatch_contract.adapter,
        DispatchAdapterV1::NativeI64V1
    );
    assert_eq!(
        operation.evidence.failure_contract.class,
        FailureClassV1::MayFailNoExternalEffects
    );
    let trace = evaluator.last_execution_trace().unwrap();
    let finished = |id| {
        trace
            .events
            .iter()
            .position(
                |event| matches!(event,TraceEvent::NodeFinished {id:actual,..} if *actual==id),
            )
            .unwrap()
    };
    let started = |id| {
        trace
            .events
            .iter()
            .position(|event| matches!(event,TraceEvent::NodeStarted(actual) if *actual==id))
            .unwrap()
    };
    assert!(finished(stores[0]) < started(native));
    assert!(finished(native) < started(stores[1]));
    for (store, version) in stores.iter().zip([1, 2]) {
        assert!(trace
            .publications
            .iter()
            .any(|publication| publication["plan_node"] == store.0
                && publication["outputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|output| output["kind"] == "resource_state"
                        && output["resource"] == "scope:x"
                        && output["version"] == version)));
    }
}

#[test]
fn native_leaf_graph_trap_blocks_store_value_completion_and_resource_outputs() {
    let program = program(true);
    let plan = program.plan();
    let native = plan
        .nodes
        .iter()
        .find(|node| matches!(node.kind, PlanNodeKind::NativeI64 { .. }))
        .unwrap()
        .id;
    let stores: Vec<_> = plan
        .nodes
        .iter()
        .filter(|node| matches!(node.kind, PlanNodeKind::Store { .. }))
        .map(|node| node.id)
        .collect();
    let mut evaluator = Evaluator::new("/tmp".into());
    let mut scope = HashMap::new();
    let error = evaluator
        .eval_ir_program_graph_with_scope(&program, &mut scope)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("native scalar leaf failed"),
        "{error:#}"
    );
    let trace = evaluator.last_execution_trace().unwrap();
    assert!(trace
        .events
        .iter()
        .any(|event| matches!(event,TraceEvent::NodeFailed {id,..} if *id==native)));
    assert!(trace
        .publications
        .iter()
        .any(|publication| publication["plan_node"] == stores[0].0));
    assert!(!trace
        .publications
        .iter()
        .any(|publication| publication["plan_node"] == native.0
            || publication["plan_node"] == stores[1].0));
    assert!(!trace
        .events
        .iter()
        .any(|event| matches!(event,TraceEvent::NodeStarted(id) if *id==stores[1])));
    assert!(!trace
        .publications
        .iter()
        .flat_map(|publication| publication["outputs"].as_array().unwrap())
        .any(|output| output["resource"] == "scope:x" && output["version"] == 2));
}

#[test]
fn native_leaf_graph_invalid_descriptor_never_acquires_execution_authority() {
    let mut program = program(false);
    let OIr::Store { expr, .. } = &mut program.nodes[1] else {
        unreachable!()
    };
    let OIr::Invoke { args, .. } = expr.as_mut() else {
        unreachable!()
    };
    args[0] = OIr::Load("descriptor-must-not-be-dynamic".into());
    let plan = program.plan();
    let error = program.hgraph_for_plan(&plan).unwrap_err();
    assert!(error.contains("static literal text descriptor"), "{error}");
}

#[test]
fn native_leaf_graph_rejects_deleted_resource_dependency() {
    let program = program(false);
    let plan = program.plan();
    let mut graph = build_program(&program);
    solve_types(&mut graph).unwrap();
    let second = plan.roots[1];
    let info = graph.op_for(second).unwrap().clone();
    let state=*info.inputs.iter().find(|id|matches!(graph.node(**id).map(|node|&node.kind),Some(HNodeKind::ResourceState {resource:crate::effects::ResourceKey::ScopeBinding(name),version:1}) if name=="x")).unwrap();
    graph
        .op_map
        .get_mut(&second)
        .unwrap()
        .inputs
        .retain(|id| *id != state);
    graph
        .exec_edges
        .get_mut(&info.edge)
        .unwrap()
        .ports
        .retain(|port| port.node != state);
    let node = graph.nodes.get_mut(&state).unwrap();
    node.consumers.retain(|edge| *edge != info.edge);
    node.incident.retain(|edge| *edge != info.edge);
    let error = graph
        .validate_execution_source(&program, &plan)
        .unwrap_err();
    assert!(
        error.contains("ScopeBinding") || error.contains("resource"),
        "{error}"
    );
}

#[test]
fn native_leaf_trap_inside_a_batch_is_a_member_error_and_never_a_publication() {
    let text = BackendRegistry::global().interface_for("text");
    let program = OIrProgram {
        nodes: vec![
            OIr::Store {
                name: "x".into(),
                expr: Box::new(OIr::Text("41".into())),
            },
            OIr::Invoke {
                fn_name: "batch".into(),
                mode: InvokeMode::Group(GroupMode::Batch),
                args: vec![
                    OIr::Invoke {
                        fn_name: crate::native_leaf::BUILTIN.into(),
                        mode: InvokeMode::Eager,
                        args: vec![
                            OIr::Exec {
                                lang: "text".into(),
                                env_id: u32::MAX,
                                attr: None,
                                backend: text.clone(),
                                body: vec![OIr::Text(crate::native_leaf::test_descriptor(1, true))],
                            },
                            OIr::Load("x".into()),
                        ],
                    },
                    OIr::Exec {
                        lang: "text".into(),
                        env_id: u32::MAX,
                        attr: None,
                        backend: text,
                        body: vec![OIr::Text("sibling".into())],
                    },
                ],
            },
        ],
    };
    let plan = program.plan();
    let native = plan
        .nodes
        .iter()
        .find(|node| matches!(node.kind, PlanNodeKind::NativeI64 { .. }))
        .unwrap()
        .id;
    let mut evaluator = Evaluator::new("/tmp".into());
    let mut scope = HashMap::new();
    // every api caller fails on a failed member; the trace still records how
    // the batch settled.
    let error = evaluator
        .eval_ir_program_graph_with_scope(&program, &mut scope)
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("native scalar leaf failed"),
        "{error:#}"
    );
    let trace = evaluator.last_execution_trace().unwrap();
    assert_eq!(
        trace
            .failed_batch_members
            .iter()
            .map(|failure| (failure.node, failure.member))
            .collect::<Vec<_>>(),
        vec![(native, 0)]
    );
    // the trapped leaf must not be listed among the successful settlements.
    assert!(
        !trace
            .publications
            .iter()
            .any(|publication| publication["plan_node"] == native.0),
        "{:?}",
        trace.publications
    );
    assert!(!trace
        .publications
        .iter()
        .flat_map(|publication| publication["outputs"].as_array().unwrap())
        .any(|output| output["kind"] == "completion" && output["producer"] == native.0));
}
