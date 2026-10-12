// ─────────────────────────────────────────────────────────────────────────────
// ir.rs — the executable Ostadix-lang intermediate representation.
//
// This module is the stable seam between four concerns that were previously
// fused inside parser.rs / eval.rs / olangc.rs:
//
//   1. Syntax            — ONode, produced by the parser.
//   2. Execution plan    — OIr / OIrProgram, a lowered, backend-neutral form
//                          of the program (this module).
//   3. Runtime values    — OValue, produced by the evaluator.
//   4. Backend metadata  — exact named re-exports from the canonical catalog
//                          for existing callers.
//
// Non-goals (deliberately out of scope for this layer):
//   - no native codegen from OIR
//   - no optimizer, no SSA, no LLVM, no VM
//
// ONode is syntax only. Every hosted execution lowers to OIR, builds and
// validates an ExecutionPlan, and interprets OIR. Backend execution mode,
// purity, and splice rendering are frozen into each Exec instruction during
// lowering so analysis and runtime dispatch cannot silently diverge.
// ─────────────────────────────────────────────────────────────────────────────

use crate::environment::EnvironmentRefV2;
use crate::parser::ONode;
use crate::value::GroupMode;
use std::collections::{BTreeSet, HashMap, HashSet};

pub use crate::backend_catalog::{
    BackendAdapterKind, BackendInterface, BackendMorphismProfileV1, BackendRegistry, BackendSpec,
    BackendValueCapabilities, ExecutionMode, IntegerExactness, RichNumberPreservation,
    RuntimeRequirementPrecision, RuntimeRequirementSpec, SpliceRenderer,
    BACKEND_CATALOG_CURRENT_SCHEMA, BACKEND_CATALOG_SCHEMA_V1, BACKEND_CATALOG_SCHEMA_V3,
    BACKEND_CATALOG_SCHEMA_V4, BACKEND_CATALOG_SCHEMA_V5, BACKEND_CATALOG_SCHEMA_V6,
};

// ═════════════════════════════════════════════════════════════════════════════
// OIr — the lowered instruction forms
// ═════════════════════════════════════════════════════════════════════════════

/// Evaluation policy carried by an Invoke instruction. Special-form behavior
/// is fixed during lowering instead of being rediscovered from a string by the
/// evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeMode {
    Eager,
    Lazy,
    Autonomous,
    Group(GroupMode),
}

impl InvokeMode {
    pub(crate) fn for_name(name: &str) -> Self {
        match name {
            "lazy" => Self::Lazy,
            "autonomous" => Self::Autonomous,
            "batch" => Self::Group(GroupMode::Batch),
            "all" => Self::Group(GroupMode::All),
            "any" => Self::Group(GroupMode::Any),
            "race" => Self::Group(GroupMode::Race),
            _ => Self::Eager,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Eager => "eager",
            Self::Lazy => "lazy",
            Self::Autonomous => "autonomous",
            Self::Group(GroupMode::Batch) => "group:batch",
            Self::Group(GroupMode::All) => "group:all",
            Self::Group(GroupMode::Any) => "group:any",
            Self::Group(GroupMode::Race) => "group:race",
        }
    }
}

/// One executable OIR instruction. The tree shape preserves lexical and
/// structural evaluation regions while `ExecutionPlan` makes dependencies
/// and legal scheduling order explicit.
// Keep this public AST's direct variant ownership stable. Boxing only the
// largest variant would churn every constructor and pattern for a size hint.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum OIr {
    /// Verbatim text destined for a backend splice buffer.
    Text(String),

    /// Read a variable from scope (`$name`).
    Load(String),

    /// Bind the result of `expr` to `name` in scope (`let name = expr`).
    Store { name: String, expr: Box<OIr> },

    /// Invoke a built-in O-level function (`instantiate(...)`, `now(...)`, …).
    Invoke {
        fn_name: String,
        mode: InvokeMode,
        args: Vec<OIr>,
    },

    /// Execute a typed-expression block on backend `lang`.
    Exec {
        lang: String,
        env_id: u32,
        attr: Option<String>,
        backend: BackendInterface,
        body: Vec<OIr>,
    },
}

/// A whole lowered program: the IR form of a parsed `.O` document.
#[derive(Debug, Clone, PartialEq)]
pub struct OIrProgram {
    pub nodes: Vec<OIr>,
}

impl OIrProgram {
    /// Lower a parsed ONode forest into an OIrProgram.
    pub fn lower(nodes: &[ONode]) -> Self {
        Self {
            nodes: nodes.iter().map(lower_node).collect(),
        }
    }

    /// Human-readable dump used by `olangc --target ir`.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("; OIrProgram\n");
        for node in &self.nodes {
            dump_node(node, 0, &mut out);
        }
        out.push('\n');
        out.push_str(&self.plan().to_text());
        out
    }

    /// Build the canonical execution plan for this program.
    ///
    /// The plan is a dependency graph over OIR nodes:
    ///   - structural edges capture child → parent evaluation dependencies
    ///   - sequence edges preserve left-to-right source order
    ///   - data edges connect `load $x` to the latest dominating `store $x`
    ///
    /// This is the planning surface used by the evaluator. It is also the
    /// designated home for scheduling, batching, purity-aware reordering, and
    /// future code generation.
    pub fn plan(&self) -> ExecutionPlan {
        let mut builder = PlanBuilder::new();
        let mut scope_stack = vec![std::collections::HashMap::new()];
        let mut previous_sibling = None;
        let mut roots = Vec::new();

        for node in &self.nodes {
            let id = builder.add_node(node, &mut scope_stack, None, previous_sibling);
            roots.push(id);
            previous_sibling = Some(id);
        }

        builder.finish(roots)
    }

    /// Return the executable OIR nodes in the same preorder used by
    /// `ExecutionPlan` node allocation.
    ///
    /// Quoted bodies are deliberately skipped: `quote^` owns its body as syntax,
    /// so nested expressions inside it are not executable plan nodes.
    pub fn flatten_for_plan(&self) -> Vec<&OIr> {
        flatten_nodes_for_plan(&self.nodes)
    }
}

fn flatten_nodes_for_plan(nodes: &[OIr]) -> Vec<&OIr> {
    let mut out = Vec::new();
    for node in nodes {
        flatten_node_for_plan(node, &mut out);
    }
    out
}

fn flatten_node_for_plan<'a>(node: &'a OIr, out: &mut Vec<&'a OIr>) {
    out.push(node);
    match node {
        OIr::Text(_) | OIr::Load(_) => {}
        OIr::Store { expr, .. } => flatten_node_for_plan(expr, out),
        OIr::Invoke { args, .. } => {
            for arg in args {
                flatten_node_for_plan(arg, out);
            }
        }
        OIr::Exec { body, .. } if is_quote_exec(node) => {
            let _ = body;
        }
        OIr::Exec { body, .. } => {
            for child in body {
                flatten_node_for_plan(child, out);
            }
        }
    }
}

fn is_quote_exec(node: &OIr) -> bool {
    matches!(
        node,
        OIr::Exec { backend, .. }
            if backend.execution == ExecutionMode::InlineAst && backend.canonical == "quote"
    )
}

/// ONode → OIr lowering. Purely structural; never fails.
pub fn lower_node(node: &ONode) -> OIr {
    match node {
        ONode::RawText(s) => OIr::Text(s.clone()),
        ONode::VarRef(name) => OIr::Load(name.clone()),
        ONode::LetBinding { name, expr } => OIr::Store {
            name: name.clone(),
            expr: Box::new(lower_node(expr)),
        },
        ONode::Call { fn_name, args } => OIr::Invoke {
            fn_name: fn_name.clone(),
            mode: InvokeMode::for_name(fn_name),
            args: args.iter().map(lower_node).collect(),
        },
        ONode::TypedExpr {
            lang,
            env_id,
            attr,
            body,
        } => OIr::Exec {
            lang: lang.clone(),
            env_id: *env_id,
            attr: attr.clone(),
            backend: BackendRegistry::global().interface_for(lang),
            body: body.iter().map(lower_node).collect(),
        },
    }
}

/// Reconstruct executable OIR as parseable O source. This is used by the
/// `quote` instruction, so quotation no longer reaches back into ONode.
pub fn reconstruct_source(nodes: &[OIr]) -> String {
    let mut out = String::new();
    for node in nodes {
        reconstruct_node(node, &mut out);
    }
    out
}

fn reconstruct_node(node: &OIr, out: &mut String) {
    match node {
        OIr::Text(text) => out.push_str(text),
        OIr::Load(name) => {
            out.push('$');
            out.push_str(name);
        }
        OIr::Store { name, expr } => {
            out.push_str("let ");
            out.push_str(name);
            out.push_str(" = ");
            reconstruct_node(expr, out);
        }
        OIr::Invoke { fn_name, args, .. } => {
            out.push_str(fn_name);
            out.push('(');
            for (index, arg) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                reconstruct_node(arg, out);
            }
            out.push(')');
        }
        OIr::Exec {
            lang,
            env_id,
            attr,
            body,
            ..
        } => {
            out.push_str(lang);
            let environment = EnvironmentRefV2::from_encoded(*env_id);
            if let Some(marker) = environment.source_marker() {
                out.push_str(&marker);
            }
            if let Some(attr) = attr {
                out.push('{');
                out.push_str(attr);
                out.push('}');
            }
            out.push_str("^(");
            for child in body {
                reconstruct_node(child, out);
            }
            out.push_str(")_");
            out.push_str(lang);
            if let Some(marker) = environment.source_marker() {
                out.push_str(&marker);
            }
            if let Some(attr) = attr {
                out.push('{');
                out.push_str(attr);
                out.push('}');
            }
        }
    }
}

fn dump_node(node: &OIr, depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    match node {
        OIr::Text(s) => {
            out.push_str(&format!("{indent}text {s:?}\n"));
        }
        OIr::Load(name) => {
            out.push_str(&format!("{indent}load ${name}\n"));
        }
        OIr::Store { name, expr } => {
            out.push_str(&format!("{indent}store ${name} =\n"));
            dump_node(expr, depth + 1, out);
        }
        OIr::Invoke {
            fn_name,
            mode,
            args,
        } => {
            out.push_str(&format!(
                "{indent}invoke {fn_name}/{} [{}]\n",
                args.len(),
                mode.label()
            ));
            for arg in args {
                dump_node(arg, depth + 1, out);
            }
        }
        OIr::Exec {
            lang,
            env_id,
            attr,
            body,
            ..
        } => {
            let attr_s = attr
                .as_deref()
                .map(|a| format!(" {{{a}}}"))
                .unwrap_or_default();
            let env_s = match EnvironmentRefV2::from_encoded(*env_id) {
                EnvironmentRefV2::Ephemeral => String::new(),
                EnvironmentRefV2::LinkerIsolated => " [env *]".to_string(),
                EnvironmentRefV2::Persistent(id) => format!(" [env {id}]"),
            };
            out.push_str(&format!("{indent}exec {lang}{env_s}{attr_s}\n"));
            for child in body {
                dump_node(child, depth + 1, out);
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ExecutionPlan — canonical dependency graph over OIR
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanNodeId(pub usize);

impl From<PlanNodeId> for usize {
    fn from(value: PlanNodeId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlanEdgeKind {
    Structural,
    Sequence,
    Data,
}

impl PlanEdgeKind {
    fn label(self) -> &'static str {
        match self {
            PlanEdgeKind::Structural => "structural",
            PlanEdgeKind::Sequence => "sequence",
            PlanEdgeKind::Data => "data",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanNodeClass {
    Pure,
    Effect,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    Memoize,
    Bypass,
}

impl CachePolicy {
    pub fn cacheable(self) -> bool {
        match self {
            Self::Memoize => true,
            Self::Bypass => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanRequestKind {
    Instantiate,
    Realise,
    DryActivate,
    Activate,
}

impl PlanRequestKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Instantiate => "instantiate",
            Self::Realise => "realise",
            Self::DryActivate => "dry_activate",
            Self::Activate => "activate",
        }
    }

    pub fn cache_policy(self) -> CachePolicy {
        match self {
            Self::Instantiate | Self::Realise => CachePolicy::Memoize,
            Self::DryActivate | Self::Activate => CachePolicy::Bypass,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanScheduleKind {
    Force,
    Lazy,
    Autonomous,
}

impl PlanScheduleKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Force => "force",
            Self::Lazy => "lazy",
            Self::Autonomous => "autonomous",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEdge {
    pub from: PlanNodeId,
    pub to: PlanNodeId,
    pub kind: PlanEdgeKind,
}

// `PlanNodeKind` is a public execution-plan vocabulary; preserve its direct
// variant ownership instead of changing that API solely to equalize sizes.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanNodeKind {
    Text,
    Load {
        name: String,
    },
    Store {
        name: String,
    },
    Call {
        fn_name: String,
        mode: InvokeMode,
        arg_count: usize,
    },
    Request {
        fn_name: String,
        kind: PlanRequestKind,
        arg_count: usize,
    },
    Group {
        mode: GroupMode,
        member_count: usize,
    },
    Schedule {
        fn_name: String,
        kind: PlanScheduleKind,
        arg_count: usize,
    },
    Exec {
        lang: String,
        env_id: u32,
        attr: Option<String>,
        backend: BackendInterface,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanNode {
    pub id: PlanNodeId,
    pub kind: PlanNodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub roots: Vec<PlanNodeId>,
    pub nodes: Vec<PlanNode>,
    pub edges: Vec<PlanEdge>,
}

/// Per-pass lookup data for an immutable, validated execution plan. This is
/// deliberately separate from the public mutable plan and never participates
/// in its semantic identity, serialization, or edge ordering.
#[derive(Debug)]
pub(crate) struct ExecutionPlanIndex {
    incoming: Vec<Vec<PlanEdge>>,
    outgoing: Vec<Vec<PlanEdge>>,
    order: Vec<PlanNodeId>,
    children: Vec<Vec<PlanNodeId>>,
}

impl ExecutionPlanIndex {
    pub(crate) fn new(plan: &ExecutionPlan) -> Result<Self, String> {
        // Keep identity, roots, edge bounds and cycle rejection at the same
        // authority boundary as the unindexed plan operations.
        plan.validate(plan.roots.len())?;
        let order = plan.topological_order()?;
        let mut incoming = vec![Vec::new(); plan.nodes.len()];
        let mut outgoing = vec![Vec::new(); plan.nodes.len()];
        for edge in &plan.edges {
            incoming[edge.to.0].push(edge.clone());
            outgoing[edge.from.0].push(edge.clone());
        }
        let mut children = vec![Vec::new(); plan.nodes.len()];
        for &child in &order {
            for edge in &outgoing[child.0] {
                if edge.kind == PlanEdgeKind::Structural
                    && children[edge.to.0].last() != Some(&child)
                {
                    children[edge.to.0].push(child);
                }
            }
        }
        Ok(Self {
            incoming,
            outgoing,
            order,
            children,
        })
    }

    pub(crate) fn incoming(&self, node: PlanNodeId) -> &[PlanEdge] {
        &self.incoming[node.0]
    }

    pub(crate) fn outgoing(&self, node: PlanNodeId) -> &[PlanEdge] {
        &self.outgoing[node.0]
    }

    pub(crate) fn topological_order(&self) -> &[PlanNodeId] {
        &self.order
    }

    pub(crate) fn child_schedule(&self, parent: PlanNodeId) -> Result<&[PlanNodeId], String> {
        self.children
            .get(parent.0)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("execution plan parent {} is out of bounds", parent.0))
    }
}

impl ExecutionPlan {
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("; ExecutionPlan\n");
        if !self.roots.is_empty() {
            let roots = self
                .roots
                .iter()
                .map(|id| id.0.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("roots [{roots}]\n"));
        }
        for node in &self.nodes {
            out.push_str(&format!("node {} {}\n", node.id.0, node.kind.describe()));
        }
        for edge in &self.edges {
            out.push_str(&format!(
                "edge {} -> {} {}\n",
                edge.from.0,
                edge.to.0,
                edge.kind.label()
            ));
        }
        out
    }

    /// Validate plan identity, edge bounds, acyclicity, and root coverage.
    /// Runtime execution calls this before evaluating any instruction.
    pub fn validate(&self, root_count: usize) -> Result<(), String> {
        if self.roots.len() != root_count {
            return Err(format!(
                "execution plan has {} roots for {root_count} OIR instructions",
                self.roots.len()
            ));
        }
        for (index, node) in self.nodes.iter().enumerate() {
            if node.id != PlanNodeId(index) {
                return Err(format!(
                    "execution plan node identity mismatch at {index}: got {}",
                    node.id.0
                ));
            }
        }
        let mut roots = BTreeSet::new();
        for root in &self.roots {
            if root.0 >= self.nodes.len() {
                return Err(format!("execution plan root {} is out of bounds", root.0));
            }
            if !roots.insert(root.0) {
                return Err(format!("execution plan root {} is duplicated", root.0));
            }
        }
        for edge in &self.edges {
            if edge.from.0 >= self.nodes.len() || edge.to.0 >= self.nodes.len() {
                return Err(format!(
                    "execution plan edge {} -> {} is out of bounds",
                    edge.from.0, edge.to.0
                ));
            }
        }
        self.topological_order()?;
        self.root_schedule()?;
        Ok(())
    }

    /// Stable topological order over every planned instruction. Lower node
    /// identifiers win ties so source order remains deterministic whenever
    /// the dependency graph permits more than one schedule.
    pub fn topological_order(&self) -> Result<Vec<PlanNodeId>, String> {
        let mut indegree = vec![0usize; self.nodes.len()];
        let mut successors = vec![Vec::new(); self.nodes.len()];
        for edge in &self.edges {
            indegree[edge.to.0] += 1;
            successors[edge.from.0].push(edge.to.0);
        }

        let mut ready: BTreeSet<usize> = indegree
            .iter()
            .enumerate()
            .filter_map(|(id, degree)| (*degree == 0).then_some(id))
            .collect();
        let mut order = Vec::with_capacity(self.nodes.len());
        while let Some(id) = ready.iter().next().copied() {
            ready.remove(&id);
            order.push(PlanNodeId(id));
            for successor in &successors[id] {
                indegree[*successor] -= 1;
                if indegree[*successor] == 0 {
                    ready.insert(*successor);
                }
            }
        }
        if order.len() != self.nodes.len() {
            return Err("execution plan dependency graph contains a cycle".to_string());
        }
        Ok(order)
    }

    /// Return top-level OIR indices in their executable dependency order.
    /// The evaluator uses this schedule instead of walking parser nodes.
    pub fn root_schedule(&self) -> Result<Vec<usize>, String> {
        let positions: HashMap<PlanNodeId, usize> = self
            .roots
            .iter()
            .copied()
            .enumerate()
            .map(|(position, id)| (id, position))
            .collect();
        let schedule: Vec<usize> = self
            .topological_order()?
            .into_iter()
            .filter_map(|id| positions.get(&id).copied())
            .collect();
        if schedule.len() != self.roots.len() {
            return Err("execution plan did not schedule every root".to_string());
        }
        Ok(schedule)
    }

    /// Return the direct structural children of `parent` in executable plan
    /// order. Recursive OIR evaluation uses this for every Store, Invoke, and
    /// Exec region rather than assuming vector order independently of the
    /// dependency graph.
    pub fn child_schedule(&self, parent: PlanNodeId) -> Result<Vec<PlanNodeId>, String> {
        if parent.0 >= self.nodes.len() {
            return Err(format!(
                "execution plan parent {} is out of bounds",
                parent.0
            ));
        }
        let children: BTreeSet<PlanNodeId> = self
            .edges
            .iter()
            .filter_map(|edge| {
                (edge.kind == PlanEdgeKind::Structural && edge.to == parent).then_some(edge.from)
            })
            .collect();
        Ok(self
            .topological_order()?
            .into_iter()
            .filter(|id| children.contains(id))
            .collect())
    }
}

impl PlanNodeKind {
    pub fn class(&self) -> PlanNodeClass {
        match self {
            Self::Text | Self::Load { .. } | Self::Store { .. } | Self::Call { .. } => {
                PlanNodeClass::Pure
            }
            Self::Exec { .. } if self.eval_cache_policy().is_some() => PlanNodeClass::Control,
            Self::Exec { .. } => PlanNodeClass::Effect,
            Self::Request { .. } | Self::Group { .. } | Self::Schedule { .. } => {
                PlanNodeClass::Control
            }
        }
    }

    pub fn eval_cache_policy(&self) -> Option<CachePolicy> {
        match self {
            Self::Exec { attr, .. } => parse_eval_cache_policy(attr.as_deref()),
            Self::Request { kind, .. } => Some(kind.cache_policy()),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            PlanNodeKind::Text => "text".to_string(),
            PlanNodeKind::Load { name } => format!("load ${name}"),
            PlanNodeKind::Store { name } => format!("store ${name}"),
            PlanNodeKind::Call {
                fn_name,
                mode,
                arg_count,
            } => {
                format!("call {fn_name}/{arg_count} [{}]", mode.label())
            }
            PlanNodeKind::Request {
                fn_name,
                kind,
                arg_count,
            } => {
                format!("request {fn_name}/{arg_count} [{}]", kind.label())
            }
            PlanNodeKind::Group { mode, member_count } => {
                format!("group {}/{}", mode.name(), member_count)
            }
            PlanNodeKind::Schedule {
                fn_name,
                kind,
                arg_count,
            } => {
                format!("schedule {fn_name}/{arg_count} [{}]", kind.label())
            }
            PlanNodeKind::Exec {
                lang,
                env_id,
                attr,
                backend,
            } => {
                let attr_s = attr
                    .as_deref()
                    .map(|a| format!(" {{{a}}}"))
                    .unwrap_or_default();
                let env = match EnvironmentRefV2::from_encoded(*env_id) {
                    EnvironmentRefV2::Ephemeral => "ephemeral".to_string(),
                    EnvironmentRefV2::LinkerIsolated => "*".to_string(),
                    EnvironmentRefV2::Persistent(id) => id.to_string(),
                };
                let required = backend
                    .required_authorities
                    .iter()
                    .map(|authority| authority.name())
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "exec {} [env {}]{} backend={} spec={} pure={} renderer={:?} execution={} required=[{}]",
                    lang,
                    env,
                    attr_s,
                    backend.canonical,
                    backend.specification_sha256.as_deref().unwrap_or("unknown"),
                    backend.pure,
                    backend.renderer,
                    backend.execution.label(),
                    required
                )
            }
        }
    }
}

fn parse_eval_cache_policy(attr: Option<&str>) -> Option<CachePolicy> {
    let mut policy = None;
    for entry in attr.into_iter().flat_map(|attr| attr.split(',')) {
        match entry.trim() {
            "lazy" => policy = Some(CachePolicy::Memoize),
            "defer" => policy = Some(CachePolicy::Bypass),
            _ => {}
        }
    }
    policy
}

struct PlanBuilder {
    nodes: Vec<PlanNode>,
    edges: Vec<PlanEdge>,
    edge_membership: HashSet<(PlanNodeId, PlanNodeId, PlanEdgeKind)>,
    /// Names referenced by the body of each `let` bound to a `quote^` block,
    /// keyed by the binding's plan node. A block that references such a
    /// binding may `O.eval` it, so it also receives these names.
    quote_references: std::collections::HashMap<PlanNodeId, QuoteReferences>,
}

#[derive(Default)]
struct QuoteReferences {
    tokens: std::collections::HashSet<String>,
    o_scope: bool,
}

impl PlanBuilder {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            edge_membership: HashSet::new(),
            quote_references: std::collections::HashMap::new(),
        }
    }

    fn finish(self, roots: Vec<PlanNodeId>) -> ExecutionPlan {
        ExecutionPlan {
            roots,
            nodes: self.nodes,
            edges: self.edges,
        }
    }

    fn add_edge(&mut self, from: PlanNodeId, to: PlanNodeId, kind: PlanEdgeKind) {
        if self.edge_membership.insert((from, to, kind)) {
            self.edges.push(PlanEdge { from, to, kind });
        }
    }

    fn add_node(
        &mut self,
        node: &OIr,
        scope_stack: &mut Vec<std::collections::HashMap<String, PlanNodeId>>,
        parent: Option<PlanNodeId>,
        previous_sibling: Option<PlanNodeId>,
    ) -> PlanNodeId {
        let id = PlanNodeId(self.nodes.len());
        let kind = self.plan_kind(node);
        self.nodes.push(PlanNode { id, kind });

        if let Some(parent_id) = parent {
            self.add_edge(id, parent_id, PlanEdgeKind::Structural);
        }
        if let Some(prev) = previous_sibling {
            self.add_edge(prev, id, PlanEdgeKind::Sequence);
        }

        match node {
            OIr::Text(_) => {}
            OIr::Load(name) => {
                if let Some(source) = scope_stack.iter().rev().find_map(|scope| scope.get(name)) {
                    self.add_edge(*source, id, PlanEdgeKind::Data);
                }
            }
            OIr::Store { name, expr } => {
                if let OIr::Exec { backend, body, .. } = expr.as_ref() {
                    if backend.execution == ExecutionMode::InlineAst && backend.canonical == "quote"
                    {
                        let mut refs = QuoteReferences::default();
                        collect_exec_references(body, &mut refs.tokens, &mut refs.o_scope);
                        self.quote_references.insert(id, refs);
                    }
                }
                scope_stack.push(std::collections::HashMap::new());
                self.add_node(expr, scope_stack, Some(id), None);
                scope_stack.pop();
                scope_stack
                    .last_mut()
                    .expect("scope stack always has a root scope")
                    .insert(name.clone(), id);
            }
            OIr::Invoke { fn_name, args, .. } => {
                // scope() reads every currently visible lexical binding even
                // though it has no syntactic arguments. Record those implicit
                // reads as data dependencies so the plan describes the same
                // semantics the evaluator executes. Inner bindings shadow
                // outer bindings with the same name.
                if fn_name == "scope" {
                    let mut seen = std::collections::HashSet::new();
                    let mut sources = Vec::new();
                    for lexical_scope in scope_stack.iter().rev() {
                        for (name, source) in lexical_scope {
                            if seen.insert(name.clone()) {
                                sources.push(*source);
                            }
                        }
                    }
                    sources.sort_by_key(|source| source.0);
                    for source in sources {
                        self.add_edge(source, id, PlanEdgeKind::Data);
                    }
                }
                scope_stack.push(std::collections::HashMap::new());
                let mut prev = None;
                for arg in args {
                    prev = Some(self.add_node(arg, scope_stack, Some(id), prev));
                }
                scope_stack.pop();
            }
            OIr::Exec {
                attr,
                backend,
                body,
                ..
            } => {
                // A shim receives exactly the visible `let` bindings that its
                // body references by whole identifier token or `$name`
                // splice, anywhere in its OIR subtree, for every backend
                // including bash and sh. Reflective or runtime-built access to
                // an unreferenced name gets nothing (see
                // REFLECTION_FULL_SCOPE_FALLBACK). Persistent state lives only
                // in numbered environments such as python[0];
                // plain blocks are ephemeral. Effect ordering does not depend
                // on these Data edges: Sequence edges and resource-state
                // chains preserve it independently.
                if backend.execution == ExecutionMode::Shim {
                    for source in
                        shim_scope_sources(scope_stack, backend, body, &self.quote_references)
                    {
                        self.add_edge(source, id, PlanEdgeKind::Data);
                    }
                }
                if let Some(binding) = attr_capability_binding(attr.as_deref()) {
                    if let Some(source) = scope_stack
                        .iter()
                        .rev()
                        .find_map(|scope| scope.get(binding.as_str()))
                    {
                        self.add_edge(*source, id, PlanEdgeKind::Data);
                    }
                }
                if backend.execution == ExecutionMode::InlineAst && backend.canonical == "quote" {
                    return id;
                }
                scope_stack.push(std::collections::HashMap::new());
                let mut prev = None;
                for child in body {
                    prev = Some(self.add_node(child, scope_stack, Some(id), prev));
                }
                scope_stack.pop();
            }
        }

        id
    }

    fn plan_kind(&self, node: &OIr) -> PlanNodeKind {
        match node {
            OIr::Text(_) => PlanNodeKind::Text,
            OIr::Load(name) => PlanNodeKind::Load { name: name.clone() },
            OIr::Store { name, .. } => PlanNodeKind::Store { name: name.clone() },
            OIr::Invoke {
                fn_name,
                mode,
                args,
            } => match mode {
                InvokeMode::Group(mode) => PlanNodeKind::Group {
                    mode: *mode,
                    member_count: args.len(),
                },
                InvokeMode::Lazy => PlanNodeKind::Schedule {
                    fn_name: fn_name.clone(),
                    kind: PlanScheduleKind::Lazy,
                    arg_count: args.len(),
                },
                InvokeMode::Autonomous => PlanNodeKind::Schedule {
                    fn_name: fn_name.clone(),
                    kind: PlanScheduleKind::Autonomous,
                    arg_count: args.len(),
                },
                InvokeMode::Eager => match fn_name.as_str() {
                    "instantiate" => PlanNodeKind::Request {
                        fn_name: fn_name.clone(),
                        kind: PlanRequestKind::Instantiate,
                        arg_count: args.len(),
                    },
                    "realise" => PlanNodeKind::Request {
                        fn_name: fn_name.clone(),
                        kind: PlanRequestKind::Realise,
                        arg_count: args.len(),
                    },
                    "dry_activate" => PlanNodeKind::Request {
                        fn_name: fn_name.clone(),
                        kind: PlanRequestKind::DryActivate,
                        arg_count: args.len(),
                    },
                    "activate" => PlanNodeKind::Request {
                        fn_name: fn_name.clone(),
                        kind: PlanRequestKind::Activate,
                        arg_count: args.len(),
                    },
                    "now" => PlanNodeKind::Schedule {
                        fn_name: fn_name.clone(),
                        kind: PlanScheduleKind::Force,
                        arg_count: args.len(),
                    },
                    _ => PlanNodeKind::Call {
                        fn_name: fn_name.clone(),
                        mode: *mode,
                        arg_count: args.len(),
                    },
                },
            },
            OIr::Exec {
                lang,
                env_id,
                attr,
                backend,
                ..
            } => PlanNodeKind::Exec {
                lang: lang.clone(),
                env_id: *env_id,
                attr: attr.clone(),
                backend: backend.clone(),
            },
        }
    }
}

/// Shell backends. Their shims export received `let` values as environment
/// variables for that block only.
const SHELL_BACKENDS: &[&str] = &["bash", "shell", "sh"];

/// Whether shell blocks receive the `let` bindings they reference. Set to
/// `false` to pass no `let` values to shell blocks at all.
const SHELL_RECEIVES_REFERENCED_LETS: bool = true;

/// Restores the conservative marker fallback: when `true`, a non-shell block
/// whose text contains a reflective token (Python namespace or frame access,
/// JavaScript global-object or dynamic-code access) or an `O.scope`/`O.eval`
/// accessor receives the complete visible scope. When `false`, every block
/// receives exactly the `let` bindings it references.
const REFLECTION_FULL_SCOPE_FALLBACK: bool = false;

/// Whole identifier tokens that trigger [`REFLECTION_FULL_SCOPE_FALLBACK`].
const REFLECTIVE_TOKENS: &[&str] = &[
    "globals",
    "locals",
    "vars",
    "eval",
    "exec",
    "compile",
    "__dict__",
    "__builtins__",
    "__import__",
    "importlib",
    "inspect",
    "currentframe",
    "_getframe",
    "f_locals",
    "f_globals",
    "f_back",
    "tb_frame",
    "gi_frame",
    "getattr",
    "__getattribute__",
    "modules",
    "environ",
    "globalThis",
    "Function",
    "process",
    "require",
    "__filename",
    "__dirname",
    "readFileSync",
];

/// Tokens that trigger [`REFLECTION_FULL_SCOPE_FALLBACK`] only when followed,
/// optionally after whitespace, by one of the given characters.
const REFLECTIVE_ACCESSORS: &[(&str, &[char])] =
    &[("O", &['.', '[']), ("this", &['[']), ("import", &['('])];

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Add every whole identifier token of `text` to `tokens`, and report whether
/// the text contains a reflective token.
fn scan_exec_text(
    text: &str,
    tokens: &mut std::collections::HashSet<String>,
    o_scope: &mut bool,
) -> bool {
    let mut dynamic = false;
    let mut previous: Option<&str> = None;
    let mut rest = text;
    while let Some(start) = rest.find(is_identifier_char) {
        let after_start = &rest[start..];
        let len = after_start
            .find(|c: char| !is_identifier_char(c))
            .unwrap_or(after_start.len());
        let token = &after_start[..len];
        let next = after_start[len..].trim_start().chars().next();
        if REFLECTIVE_TOKENS.contains(&token)
            || REFLECTIVE_ACCESSORS
                .iter()
                .any(|(name, follow)| *name == token && next.is_some_and(|c| follow.contains(&c)))
        {
            dynamic = true;
        }
        // `O.scope` is O syntax: it reads every visible `let` binding, so it
        // references all of them.
        if token == "scope" && previous == Some("O") && rest[..start].trim_end().ends_with('.') {
            *o_scope = true;
        }
        let next_rest = &after_start[len..];
        previous = if next_rest.trim_start().starts_with('.') {
            Some(token)
        } else {
            None
        };
        tokens.insert(token.to_string());
        rest = next_rest;
    }
    dynamic
}

/// Collect the identifier tokens of an Exec body subtree, including nested
/// typed blocks and calls. The returned flag reports a reflective token in
/// the text, or an O `scope()`, `eval()`, or `quote` node in the OIR.
fn collect_exec_references(
    nodes: &[OIr],
    tokens: &mut std::collections::HashSet<String>,
    o_scope: &mut bool,
) -> bool {
    let mut dynamic = false;
    for node in nodes {
        match node {
            OIr::Text(text) => dynamic |= scan_exec_text(text, tokens, o_scope),
            OIr::Load(name) => {
                tokens.insert(name.clone());
            }
            OIr::Store { name, expr } => {
                tokens.insert(name.clone());
                dynamic |= collect_exec_references(std::slice::from_ref(expr), tokens, o_scope);
            }
            OIr::Invoke { fn_name, args, .. } => {
                if fn_name == "scope" {
                    *o_scope = true;
                }
                if matches!(fn_name.as_str(), "eval" | "quote") {
                    dynamic = true;
                }
                dynamic |= collect_exec_references(args, tokens, o_scope);
            }
            OIr::Exec { backend, body, .. } => {
                if backend.canonical == "quote" {
                    dynamic = true;
                }
                dynamic |= collect_exec_references(body, tokens, o_scope);
            }
        }
    }
    dynamic
}

/// Plan sources of the visible `let` bindings a shim block receives: exactly
/// the bindings whose names its body references by whole identifier token
/// or `$name` splice, for every backend and every parallel branch. With
/// [`REFLECTION_FULL_SCOPE_FALLBACK`] enabled, a non-shell block with a
/// reflective token or O scope node receives the complete visible scope.
fn shim_scope_sources(
    scope_stack: &[std::collections::HashMap<String, PlanNodeId>],
    backend: &BackendInterface,
    body: &[OIr],
    quote_references: &std::collections::HashMap<PlanNodeId, QuoteReferences>,
) -> Vec<PlanNodeId> {
    let shell = SHELL_BACKENDS.contains(&backend.canonical.as_str());
    if shell && !SHELL_RECEIVES_REFERENCED_LETS {
        return Vec::new();
    }
    let mut tokens = std::collections::HashSet::new();
    let mut o_scope = false;
    let reflective = collect_exec_references(body, &mut tokens, &mut o_scope);
    // A referenced quote binding can be evaluated with `O.eval`, so the names
    // its quoted body uses are references too, transitively.
    let mut visible = std::collections::HashMap::new();
    for lexical_scope in scope_stack.iter().rev() {
        for (name, source) in lexical_scope {
            visible.entry(name.as_str()).or_insert(*source);
        }
    }
    let mut expanded = std::collections::HashSet::new();
    loop {
        let pending: Vec<PlanNodeId> = visible
            .iter()
            .filter(|(name, source)| tokens.contains(**name) && !expanded.contains(*source))
            .map(|(_, source)| *source)
            .collect();
        if pending.is_empty() {
            break;
        }
        for source in pending {
            expanded.insert(source);
            if let Some(refs) = quote_references.get(&source) {
                tokens.extend(refs.tokens.iter().cloned());
                o_scope |= refs.o_scope;
            }
        }
    }
    if o_scope || (REFLECTION_FULL_SCOPE_FALLBACK && reflective && !shell) {
        return visible_scope_sources(scope_stack);
    }
    let mut seen = std::collections::HashSet::new();
    let mut sources = Vec::new();
    for lexical_scope in scope_stack.iter().rev() {
        for (name, source) in lexical_scope {
            if seen.insert(name.clone()) && tokens.contains(name) {
                sources.push(*source);
            }
        }
    }
    sources.sort_by_key(|source| source.0);
    sources
}

fn visible_scope_sources(
    scope_stack: &[std::collections::HashMap<String, PlanNodeId>],
) -> Vec<PlanNodeId> {
    let mut seen = std::collections::HashSet::new();
    let mut sources = Vec::new();
    for lexical_scope in scope_stack.iter().rev() {
        for (name, source) in lexical_scope {
            if seen.insert(name.clone()) {
                sources.push(*source);
            }
        }
    }
    sources.sort_by_key(|source| source.0);
    sources
}

fn attr_capability_binding(attr: Option<&str>) -> Option<String> {
    attr.into_iter()
        .flat_map(|attr| attr.split(','))
        .map(str::trim)
        .find_map(|entry| {
            entry
                .strip_prefix("cap=")
                .filter(|name| !name.is_empty())
                .map(str::to_string)
        })
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn typed(lang: &str, body: Vec<ONode>) -> ONode {
        ONode::TypedExpr {
            lang: lang.to_string(),
            env_id: 0,
            attr: None,
            body,
        }
    }

    #[test]
    fn lower_raw_text() {
        let prog = OIrProgram::lower(&[ONode::RawText("hi".into())]);
        assert_eq!(prog.nodes, vec![OIr::Text("hi".into())]);
    }

    #[test]
    fn lower_nested_typed_expr() {
        let nodes = vec![typed(
            "html",
            vec![
                ONode::RawText("<p>".into()),
                typed("python", vec![ONode::RawText("2 + 2".into())]),
                ONode::VarRef("x".into()),
                ONode::RawText("</p>".into()),
            ],
        )];
        let prog = OIrProgram::lower(&nodes);
        assert_eq!(
            prog.nodes,
            vec![OIr::Exec {
                lang: "html".into(),
                env_id: 0,
                attr: None,
                backend: BackendRegistry::global().interface_for("html"),
                body: vec![
                    OIr::Text("<p>".into()),
                    OIr::Exec {
                        lang: "python".into(),
                        env_id: 0,
                        attr: None,
                        backend: BackendRegistry::global().interface_for("python"),
                        body: vec![OIr::Text("2 + 2".into())],
                    },
                    OIr::Load("x".into()),
                    OIr::Text("</p>".into()),
                ],
            }]
        );
    }

    #[test]
    fn lower_let_and_call() {
        let nodes = vec![ONode::LetBinding {
            name: "drv".into(),
            expr: Box::new(ONode::Call {
                fn_name: "instantiate".into(),
                args: vec![ONode::VarRef("expr".into())],
            }),
        }];
        let prog = OIrProgram::lower(&nodes);
        assert_eq!(
            prog.nodes,
            vec![OIr::Store {
                name: "drv".into(),
                expr: Box::new(OIr::Invoke {
                    fn_name: "instantiate".into(),
                    mode: InvokeMode::Eager,
                    args: vec![OIr::Load("expr".into())],
                }),
            }]
        );
    }

    #[test]
    fn lowering_types_policy_changing_invocations() {
        for (name, expected) in [
            ("lazy", InvokeMode::Lazy),
            ("autonomous", InvokeMode::Autonomous),
            ("batch", InvokeMode::Group(GroupMode::Batch)),
            ("all", InvokeMode::Group(GroupMode::All)),
            ("any", InvokeMode::Group(GroupMode::Any)),
            ("race", InvokeMode::Group(GroupMode::Race)),
            ("now", InvokeMode::Eager),
        ] {
            let program = OIrProgram::lower(&[ONode::Call {
                fn_name: name.into(),
                args: vec![ONode::RawText("x".into())],
            }]);
            assert!(matches!(
                &program.nodes[0],
                OIr::Invoke { mode, .. } if *mode == expected
            ));
        }
    }

    #[test]
    fn source_lowers_typed_group_members_into_direct_exec_arguments() {
        let source = "autonomous(batch(python^(1)_python, python^(2)_python))";
        let backends = BackendRegistry::global().registered_backend_tags();
        let parsed = Parser::new(source, &backends).parse().unwrap();
        let program = OIrProgram::lower(&parsed);
        let OIr::Invoke {
            mode: InvokeMode::Autonomous,
            args: autonomous_args,
            ..
        } = &program.nodes[0]
        else {
            panic!("expected autonomous invocation")
        };
        let OIr::Invoke {
            mode: InvokeMode::Group(GroupMode::Batch),
            args: members,
            ..
        } = &autonomous_args[0]
        else {
            panic!("expected nested batch invocation")
        };
        assert_eq!(members.len(), 2);
        assert!(members.iter().all(|member| matches!(
            member,
            OIr::Exec {
                env_id: u32::MAX,
                backend,
                ..
            } if backend.canonical == "python"
        )));
    }

    #[test]
    fn ir_dump_is_stable() {
        let nodes = vec![typed("python", vec![ONode::RawText("1 + 1".into())])];
        let prog = OIrProgram::lower(&nodes);
        let python_spec = BackendRegistry::global()
            .specification_sha256("python")
            .expect("python specification digest");
        assert_eq!(
            prog.to_text(),
            format!(
                concat!(
                "; OIrProgram\n",
                "exec python [env 0]\n",
                "  text \"1 + 1\"\n",
                "\n",
                "; ExecutionPlan\n",
                "roots [0]\n",
                "node 0 exec python [env 0] backend=python spec={} pure=false renderer=Python execution=shim required=[]\n",
                "node 1 text\n",
                "edge 1 -> 0 structural\n",
                ),
                python_spec
            )
        );
    }

    #[test]
    fn plan_builds_data_and_sequence_edges() {
        let prog = OIrProgram::lower(&[
            ONode::LetBinding {
                name: "x".into(),
                expr: Box::new(ONode::Call {
                    fn_name: "instantiate".into(),
                    args: vec![ONode::VarRef("expr".into())],
                }),
            },
            ONode::TypedExpr {
                lang: "python".into(),
                env_id: 0,
                attr: None,
                body: vec![ONode::VarRef("x".into())],
            },
        ]);

        let plan = prog.plan();
        assert_eq!(plan.roots, vec![PlanNodeId(0), PlanNodeId(3)]);
        assert!(plan.edges.iter().any(|e| {
            e.from == PlanNodeId(0) && e.to == PlanNodeId(3) && e.kind == PlanEdgeKind::Sequence
        }));
        assert!(plan.edges.iter().any(|e| {
            e.from == PlanNodeId(0) && e.to == PlanNodeId(4) && e.kind == PlanEdgeKind::Data
        }));
    }

    #[test]
    fn quote_body_is_syntax_not_executable_plan_nodes() {
        let program = OIrProgram::lower(&[typed(
            "quote",
            vec![typed("python", vec![ONode::RawText("6 * 7".into())])],
        )]);

        let plan = program.plan();
        assert_eq!(program.flatten_for_plan().len(), 1);
        assert_eq!(plan.nodes.len(), 1);
        assert!(plan
            .edges
            .iter()
            .all(|edge| edge.kind != PlanEdgeKind::Structural));
    }

    #[test]
    fn backend_capability_attr_is_a_graph_visible_data_dependency() {
        let program = OIrProgram::lower(&[
            ONode::LetBinding {
                name: "runner".into(),
                expr: Box::new(ONode::RawText("capability placeholder".into())),
            },
            ONode::TypedExpr {
                lang: "python".into(),
                env_id: 0,
                attr: Some("cap=runner,process".into()),
                body: vec![ONode::RawText("__oval_result__ = 1".into())],
            },
        ]);

        let plan = program.plan();
        let runner_store = plan
            .nodes
            .iter()
            .find(|node| matches!(&node.kind, PlanNodeKind::Store { name } if name == "runner"))
            .unwrap()
            .id;
        let python_exec = plan
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    &node.kind,
                    PlanNodeKind::Exec { lang, attr, .. }
                        if lang == "python" && attr.as_deref() == Some("cap=runner,process")
                )
            })
            .unwrap()
            .id;

        assert!(plan.edges.iter().any(|edge| {
            edge.from == runner_store && edge.to == python_exec && edge.kind == PlanEdgeKind::Data
        }));
    }

    #[test]
    fn scope_capture_depends_on_every_visible_store() {
        let program = OIrProgram::lower(&[
            ONode::LetBinding {
                name: "x".into(),
                expr: Box::new(ONode::RawText("one".into())),
            },
            ONode::LetBinding {
                name: "y".into(),
                expr: Box::new(ONode::RawText("two".into())),
            },
            ONode::LetBinding {
                name: "captured".into(),
                expr: Box::new(ONode::Call {
                    fn_name: "scope".into(),
                    args: vec![],
                }),
            },
        ]);
        let plan = program.plan();
        let capture = plan
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    &node.kind,
                    PlanNodeKind::Call { fn_name, .. } if fn_name == "scope"
                )
            })
            .unwrap()
            .id;
        let visible_stores = plan
            .edges
            .iter()
            .filter(|edge| edge.to == capture && edge.kind == PlanEdgeKind::Data)
            .map(|edge| edge.from)
            .collect::<BTreeSet<_>>();

        assert_eq!(
            visible_stores,
            BTreeSet::from([PlanNodeId(0), PlanNodeId(2)])
        );
    }

    #[test]
    fn plan_index_matches_scans_for_permuted_dags_with_duplicate_edges() {
        // Keep this oracle scan-based: it checks ordering and multiplicity
        // against the original public operations, not against the index.
        for seed in 0..32usize {
            let count = 2 + seed % 15;
            let mut order = (0..count).collect::<Vec<_>>();
            order.rotate_left(seed % count);
            if seed % 2 == 1 {
                order.reverse();
            }
            let mut edges = Vec::new();
            for from in 0..count {
                for to in from + 1..count {
                    let code = (from * 17 + to * 7 + seed) % 7;
                    if code < 3 {
                        let edge = PlanEdge {
                            from: PlanNodeId(order[from]),
                            to: PlanNodeId(order[to]),
                            kind: [
                                PlanEdgeKind::Structural,
                                PlanEdgeKind::Sequence,
                                PlanEdgeKind::Data,
                            ][code],
                        };
                        edges.push(edge.clone());
                        if (from + to + seed) % 3 == 0 {
                            edges.push(edge);
                        }
                    }
                }
            }
            if seed % 2 == 0 {
                edges.reverse();
            }
            let plan = ExecutionPlan {
                roots: (0..count).map(PlanNodeId).collect(),
                nodes: (0..count)
                    .map(|id| PlanNode {
                        id: PlanNodeId(id),
                        kind: PlanNodeKind::Text,
                    })
                    .collect(),
                edges,
            };
            let index = ExecutionPlanIndex::new(&plan).unwrap();
            assert_eq!(index.topological_order(), plan.topological_order().unwrap());
            for node in (0..count).map(PlanNodeId) {
                assert_eq!(
                    index.incoming(node),
                    plan.edges
                        .iter()
                        .filter(|edge| edge.to == node)
                        .cloned()
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    index.outgoing(node),
                    plan.edges
                        .iter()
                        .filter(|edge| edge.from == node)
                        .cloned()
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    index.child_schedule(node).unwrap(),
                    plan.child_schedule(node).unwrap()
                );
            }
            assert_eq!(
                index.child_schedule(PlanNodeId(count)).unwrap_err(),
                plan.child_schedule(PlanNodeId(count)).unwrap_err()
            );
        }
    }

    #[test]
    fn plan_index_preserves_identity_bounds_root_and_cycle_rejections() {
        let valid = ExecutionPlan {
            roots: vec![PlanNodeId(1)],
            nodes: (0..2)
                .map(|id| PlanNode {
                    id: PlanNodeId(id),
                    kind: PlanNodeKind::Text,
                })
                .collect(),
            edges: vec![PlanEdge {
                from: PlanNodeId(0),
                to: PlanNodeId(1),
                kind: PlanEdgeKind::Structural,
            }],
        };
        let mut cases = Vec::new();
        let mut identity = valid.clone();
        identity.nodes[0].id = PlanNodeId(7);
        cases.push(identity);
        let mut bounds = valid.clone();
        bounds.edges[0].from = PlanNodeId(2);
        cases.push(bounds);
        let mut root = valid.clone();
        root.roots.push(root.roots[0]);
        cases.push(root);
        let mut cycle = valid;
        cycle.edges.push(PlanEdge {
            from: PlanNodeId(1),
            to: PlanNodeId(0),
            kind: PlanEdgeKind::Data,
        });
        cases.push(cycle);
        for plan in cases {
            assert_eq!(
                ExecutionPlanIndex::new(&plan).unwrap_err(),
                plan.validate(plan.roots.len()).unwrap_err()
            );
        }
    }

    #[test]
    fn plan_builder_membership_keeps_first_edge_order_and_distinct_kinds() {
        let mut builder = PlanBuilder::new();
        let mut expected = Vec::new();
        for round in 0..3 {
            for from in (0..32).rev() {
                for kind in [
                    PlanEdgeKind::Structural,
                    PlanEdgeKind::Data,
                    PlanEdgeKind::Sequence,
                ] {
                    builder.add_edge(PlanNodeId(from), PlanNodeId(from + 1), kind);
                    if round == 0 {
                        expected.push(PlanEdge {
                            from: PlanNodeId(from),
                            to: PlanNodeId(from + 1),
                            kind,
                        });
                    }
                }
            }
        }
        assert_eq!(builder.finish(Vec::new()).edges, expected);
    }

    #[test]
    fn executable_plan_validates_and_schedules_roots() {
        let program = OIrProgram::lower(&[
            ONode::LetBinding {
                name: "x".into(),
                expr: Box::new(ONode::RawText("value".into())),
            },
            ONode::VarRef("x".into()),
            typed("html", vec![ONode::VarRef("x".into())]),
        ]);
        let plan = program.plan();
        plan.validate(program.nodes.len()).unwrap();
        assert_eq!(plan.root_schedule().unwrap(), vec![0, 1, 2]);
        assert_eq!(
            plan.child_schedule(plan.roots[0]).unwrap(),
            vec![PlanNodeId(1)]
        );
        assert_eq!(
            plan.child_schedule(plan.roots[2]).unwrap(),
            vec![PlanNodeId(4)]
        );
        assert_eq!(plan.topological_order().unwrap().len(), plan.nodes.len());
    }

    #[test]
    fn plan_promotes_request_group_and_schedule_nodes() {
        let program = OIrProgram::lower(&[
            ONode::Call {
                fn_name: "instantiate".into(),
                args: vec![ONode::RawText("drv".into())],
            },
            ONode::Call {
                fn_name: "dry_activate".into(),
                args: vec![ONode::RawText("/nix/store/demo-system".into())],
            },
            ONode::Call {
                fn_name: "activate".into(),
                args: vec![ONode::RawText("/nix/store/demo-system".into())],
            },
            ONode::Call {
                fn_name: "batch".into(),
                args: vec![ONode::RawText("a".into()), ONode::RawText("b".into())],
            },
            ONode::Call {
                fn_name: "autonomous".into(),
                args: vec![ONode::RawText("body".into())],
            },
            ONode::Call {
                fn_name: "now".into(),
                args: vec![ONode::RawText("req".into())],
            },
            ONode::TypedExpr {
                lang: "html".into(),
                env_id: 0,
                attr: Some("lazy".into()),
                body: vec![ONode::RawText("<p>x</p>".into())],
            },
        ]);
        let plan = program.plan();

        assert!(plan.nodes.iter().any(|node| {
            matches!(
                &node.kind,
                PlanNodeKind::Request {
                    kind: PlanRequestKind::Instantiate,
                    ..
                }
            ) && node.kind.class() == PlanNodeClass::Control
                && node.kind.eval_cache_policy() == Some(CachePolicy::Memoize)
        }));
        assert!(plan.nodes.iter().any(|node| {
            matches!(
                &node.kind,
                PlanNodeKind::Request {
                    kind: PlanRequestKind::DryActivate,
                    ..
                }
            ) && node.kind.class() == PlanNodeClass::Control
                && node.kind.eval_cache_policy() == Some(CachePolicy::Bypass)
        }));
        assert!(plan.nodes.iter().any(|node| {
            matches!(
                &node.kind,
                PlanNodeKind::Request {
                    kind: PlanRequestKind::Activate,
                    ..
                }
            ) && node.kind.class() == PlanNodeClass::Control
                && node.kind.eval_cache_policy() == Some(CachePolicy::Bypass)
        }));
        assert!(plan.nodes.iter().any(|node| {
            matches!(
                &node.kind,
                PlanNodeKind::Group {
                    mode: GroupMode::Batch,
                    member_count: 2,
                }
            ) && node.kind.class() == PlanNodeClass::Control
        }));
        assert!(plan.nodes.iter().any(|node| {
            matches!(
                &node.kind,
                PlanNodeKind::Schedule {
                    kind: PlanScheduleKind::Autonomous,
                    ..
                }
            ) && node.kind.class() == PlanNodeClass::Control
        }));
        assert!(plan.nodes.iter().any(|node| {
            matches!(
                &node.kind,
                PlanNodeKind::Schedule {
                    kind: PlanScheduleKind::Force,
                    ..
                }
            ) && node.kind.class() == PlanNodeClass::Control
        }));
        assert!(plan.nodes.iter().any(|node| {
            matches!(
                &node.kind,
                PlanNodeKind::Exec {
                    attr: Some(attr),
                    ..
                } if attr == "lazy"
            ) && node.kind.class() == PlanNodeClass::Control
                && node.kind.eval_cache_policy() == Some(CachePolicy::Memoize)
        }));
    }

    #[test]
    fn executable_plan_rejects_dependency_cycles() {
        let mut plan = OIrProgram::lower(&[ONode::RawText("a".into())]).plan();
        plan.edges.push(PlanEdge {
            from: PlanNodeId(0),
            to: PlanNodeId(0),
            kind: PlanEdgeKind::Sequence,
        });
        assert!(plan.validate(1).unwrap_err().contains("cycle"));
    }

    #[test]
    fn executable_oir_reconstructs_quoted_source() {
        let nodes = vec![typed(
            "html",
            vec![
                ONode::RawText("<p>".into()),
                ONode::VarRef("answer".into()),
                ONode::RawText("</p>".into()),
            ],
        )];
        let program = OIrProgram::lower(&nodes);
        assert_eq!(
            reconstruct_source(&program.nodes),
            "html[0]^(<p>$answer</p>)_html[0]"
        );
    }

    #[test]
    fn executable_oir_preserves_linker_isolated_source_marker() {
        let mut node = typed("python", vec![ONode::RawText("1".into())]);
        let ONode::TypedExpr { env_id, .. } = &mut node else {
            unreachable!("typed helper always constructs a typed expression")
        };
        *env_id = crate::environment::LINKER_ISOLATED_ENV_ID;
        let program = OIrProgram::lower(&[node]);

        assert_eq!(
            reconstruct_source(&program.nodes),
            "python[*]^(1)_python[*]"
        );
        let dump = program.to_text();
        assert!(dump.contains("exec python [env *]"), "{dump}");
    }

    fn exec_data_sources(source: &str) -> Vec<Vec<String>> {
        let backends = BackendRegistry::global().registered_backend_tags();
        let parsed = Parser::new(source, &backends).parse().unwrap();
        let plan = OIrProgram::lower(&parsed).plan();
        plan.nodes
            .iter()
            .filter(|node| matches!(node.kind, PlanNodeKind::Exec { .. }))
            .map(|exec| {
                let mut names = plan
                    .edges
                    .iter()
                    .filter(|edge| edge.to == exec.id && edge.kind == PlanEdgeKind::Data)
                    .filter_map(|edge| match &plan.nodes[edge.from.0].kind {
                        PlanNodeKind::Store { name } => Some(name.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                names.sort();
                names
            })
            .collect()
    }

    fn three_bindings(last_block: &str) -> String {
        format!(
            "let a = python^(__oval_result__ = 1)_python\n\
             let b = python^(__oval_result__ = 2)_python\n\
             let c = python^(__oval_result__ = 3)_python\n\
             {last_block}\n"
        )
    }

    fn chain_source(depth: usize) -> String {
        let mut source = String::from("let v0 = python^(__oval_result__ = 0)_python\n");
        for step in 1..depth {
            source.push_str(&format!(
                "let v{step} = python^(__oval_result__ = v{} + 1)_python\n",
                step - 1
            ));
        }
        source
    }

    #[test]
    fn trimmed_chain_step_receives_only_referenced_bindings() {
        let execs = exec_data_sources(&chain_source(5));
        assert_eq!(execs.len(), 5);
        assert!(execs[0].is_empty(), "{execs:?}");
        for (step, names) in execs.iter().enumerate().skip(1) {
            assert_eq!(names, &vec![format!("v{}", step - 1)], "{execs:?}");
        }
    }

    #[test]
    fn trimming_matches_whole_identifier_tokens_only() {
        let execs = exec_data_sources(&three_bindings(
            "python^(\nenvironment = 1\nevaluate = 2\n__oval_result__ = ab + c\n)_python",
        ));
        assert_eq!(execs.last().unwrap(), &vec!["c".to_string()], "{execs:?}");
    }

    #[test]
    fn python_import_statement_is_not_a_dynamic_marker() {
        let execs = exec_data_sources(&three_bindings(
            "python^(\nimport math\n__oval_result__ = math.floor(c)\n)_python",
        ));
        assert_eq!(execs.last().unwrap(), &vec!["c".to_string()], "{execs:?}");
    }

    #[test]
    fn nested_block_references_propagate_to_the_enclosing_shim() {
        let execs = exec_data_sources(&three_bindings(
            "python^(__oval_result__ = javascript^(console.log(b))_javascript)_python",
        ));
        let outer = &execs[3];
        assert!(outer.contains(&"b".to_string()), "{execs:?}");
        assert!(!outer.contains(&"a".to_string()), "{execs:?}");
    }

    #[test]
    fn foreign_reflection_does_not_widen_the_namespace() {
        for body in [
            "python^(__oval_result__ = globals()[chr(97)] + c)_python",
            "python^(__oval_result__ = vars ()[chr(97)] + c)_python",
            "python^(\nimport sys\n__oval_result__ = sys._getframe().f_back.f_globals[chr(97)] + c\n)_python",
            "python^(\nimport os\n__oval_result__ = os.environ.get(chr(97), c)\n)_python",
            "javascript^(console.log(globalThis[String.fromCharCode(97)] + c))_javascript",
            "javascript^(console.log(require('fs').readFileSync(__filename, 'utf8') + c))_javascript",
            "javascript^(console.log(Function('return ' + String.fromCharCode(97))() + c))_javascript",
        ] {
            let execs = exec_data_sources(&three_bindings(body));
            assert_eq!(execs.last().unwrap(), &vec!["c".to_string()], "{body}");
        }
    }

    #[test]
    fn o_scope_references_every_visible_binding() {
        let full = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        for body in [
            "python^(__oval_result__ = O.scope())_python",
            "python^(__oval_result__ = O . scope().bindings)_python",
        ] {
            let execs = exec_data_sources(&three_bindings(body));
            assert_eq!(execs.last().unwrap(), &full, "{body}");
        }
        // O.eval of a named quote references only that name.
        let execs = exec_data_sources(&three_bindings(
            "python^(\nq = quote^(python[1]^($b * 6)_python[1])_quote\n__oval_result__ = O.eval(q)\n)_python",
        ));
        assert_eq!(execs[3], vec!["b".to_string()], "{execs:?}");
    }

    #[test]
    fn shell_blocks_receive_only_referenced_bindings() {
        for (body, expected) in [
            ("bash^(echo \\$c)_bash", vec!["c".to_string()]),
            (
                "bash^(awk 'BEGIN{print ENVIRON[toupper(\"q\")]}')_bash",
                vec![],
            ),
            ("bash[0]^(echo \\$b)_bash[0]", vec!["b".to_string()]),
            ("shell^(echo hello)_shell", vec![]),
        ] {
            let execs = exec_data_sources(&three_bindings(body));
            assert_eq!(execs.last().unwrap(), &expected, "{body}");
        }
    }

    #[test]
    fn autonomous_batch_branches_each_receive_only_their_references() {
        let execs = exec_data_sources(&three_bindings(
            "let r = autonomous(batch(\n\
             python^(__oval_result__ = a)_python,\n\
             python^(__oval_result__ = b + c)_python,\n\
             python^(__oval_result__ = globals()[chr(97)])_python,\n\
             bash^(echo \\$c)_bash\n\
             ))",
        ));
        assert_eq!(execs.len(), 7, "{execs:?}");
        let full = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(execs[3], vec!["a".to_string()], "{execs:?}");
        assert_eq!(
            execs[4],
            vec!["b".to_string(), "c".to_string()],
            "{execs:?}"
        );
        let reflective = if REFLECTION_FULL_SCOPE_FALLBACK {
            full
        } else {
            Vec::new()
        };
        assert_eq!(execs[5], reflective, "{execs:?}");
        assert_eq!(execs[6], vec!["c".to_string()], "{execs:?}");
    }

    #[test]
    fn nested_lexical_scope_trims_inner_and_outer_bindings() {
        let execs = exec_data_sources(&three_bindings(
            "python^(\n\
             let inner = python^(__oval_result__ = b)_python\n\
             __oval_result__ = $inner + 1\n\
             )_python",
        ));
        let inner = &execs[4];
        assert_eq!(inner, &vec!["b".to_string()], "{execs:?}");
        let outer = &execs[3];
        assert!(!outer.contains(&"a".to_string()), "{execs:?}");
        assert!(!outer.contains(&"c".to_string()), "{execs:?}");
    }

    #[test]
    fn plan_size_is_linear_in_chain_depth() {
        let edges = |depth: usize| {
            let backends = BackendRegistry::global().registered_backend_tags();
            let parsed = Parser::new(&chain_source(depth), &backends)
                .parse()
                .unwrap();
            OIrProgram::lower(&parsed).plan().edges.len()
        };
        let (small, large) = (edges(100), edges(400));
        assert!(
            large <= small * 4 + 16,
            "plan edges grew superlinearly: depth 100 -> {small}, depth 400 -> {large}"
        );
    }
}
