# Glossary and NotebookLM question set

## Core language terms

| Term | Meaning |
|---|---|
| typed expression | A matched `LANG^(...)_LANG` region whose delimiter names its evaluator. |
| evaluator/backend | The implementation that evaluates or structurally renders a typed expression. |
| backend catalog | The compile-time canonical metadata set for tags, aliases, execution mode, renderers, purity, runtime alternatives, authority, and value capabilities. Current schema: `ostadix.backend-catalog/v6`. |
| renderer / `render_child` | The receiving backend's projection from OValue into its body/source or presentation representation. |
| ephemeral environment | A fresh backend attempt for a bare `LANG` block. |
| persistent environment | Explicit logical backend state keyed by `(canonical language, numeric environment ID)`. |
| linker-isolated fresh environment | `LANG[*]`; a fresh-per-occurrence attempt carrying explicit placement/linker intent, not a persistent identity. |
| O scope | Lexical mapping of O `let` names to OValues. |
| OScope | Detached first-class scope snapshot used by explicit `O.eval(expr, scope)`. It can contain live/effectful values and is not automatically cache/replay/persistence safe. |
| OValue | Canonical tagged exchange and runtime-boundary value family. Serialization does not automatically imply safety or authority. |
| OExpr | Unevaluated O source captured by `quote^`. |
| Request / ORequest | Deferred computation with identity/fingerprint and force policy. |
| Group / OGroup | Ordered batch/all/any/race execution topology. A group is a control value, not work already executed. |
| lazy | Cacheable deferral allowed only under the registry's cache-safety contract. |
| defer | Uncached explicit deferral usable for effectful backends. |
| autonomous | Explicit scheduling policy for eligible buffered work; not automatic proof that external effects are independent. |

## Compiler and execution terms

| Term | Meaning |
|---|---|
| ONode | Parsed hosted syntax tree; not the production execution representation. |
| OIR / OIrProgram | Recursive executable hosted IR with Text, Load, Store, Invoke, and Exec instructions. Not SSA or native machine IR. |
| BackendInterface | Catalog-derived execution/renderer/authority metadata frozen into each OIR Exec. |
| ExecutionPlan | Validated dependency plan with structural, sequence, and data edges. |
| HGraph | Directed execution hypergraph in which operations may consume and produce multiple value, completion, resource, actor, and evidence nodes. |
| solved Graph V2 | Current executable graph identity including typed representation/fidelity assessments. |
| completion token | Graph output proving successful completion; a failed operation produces none of its normal graph outputs. |
| resource version | Explicit state node ordered by read/write frontier semantics. |
| HostWorld | Conservative resource umbrella for hosted effects that are not completely verified. |
| ActorState | Persistent backend-environment state version used to serialize an explicit logical actor. |
| Evidence V6 | Current bound pre-execution fact bundle. Evidence is not admission. |
| Admission V6 | Current process-local authority for the coordinator to execute the exact bound graph. |
| execution intent | Stable authority-free identity used for inspection/recomputation. Matching does not authorize execution. |
| static wave | Non-executing readiness geometry. It is not proof of physical dispatch, overlap, runtime readiness, or capacity fit. |
| provisional publication | Coordinator-controlled temporary visibility of a safe result before final deterministic settlement. |
| settlement | Coordinator-owned semantic decision that makes a result/failure part of the committed execution trace. |
| observation | Post-execution trace/runtime/receipt data. Observation is not a reusable admission certificate. |

## Project and placement terms

| Term | Meaning |
|---|---|
| ProjectBundle | Lossless source-closed capture of a heterogeneous project plus route metadata. Foreign files remain foreign source, not OIR. |
| route | Named project command/contract with prerequisites, outputs, policy, environment, requirements, and failure/effect declarations. |
| Project Logical HGraph | Canonical logical route/prerequisite graph for a captured project. |
| route island | One selected route plus its transitive prerequisites, materialized/executed as the project mesh unit. |
| operation contract/interface | Descriptive semantic obligation and named port surface. |
| realization descriptor/set | Descriptive implementation/representation/target declarations and exact membership. They provide no execution authority. |
| candidate tuple | Explicit logical-operation, realization, target, port representation/residency, and cost-profile combination assessed by the operation planner. |
| DeploymentPlan | Deterministic record of candidate assessments and selected static tuple. Selection is not live eligibility. |
| RuntimeGraph | Bound record of proposed/started/terminal observations. Internal consistency is not observer authentication. |
| RecoveryPlan | Conditional alternative record after a bound failure. It does not perform recovery. |
| Hosted Placement V6 | Bounded proof/lease and direct-node transport milestone, distinct from local Admission V6 and catalog V6. |
| Hosted V1 | Frozen fresh single-operation direct transport. |
| Hosted V2 | Opt-in durable session/actor transport with one-use signed authority and node-signed journal. |
| Project Mesh V1 | Authenticated source-closed project route-island execution on paired peers. Not live process migration. |
| Fabric V1 | Narrow pure-renderer capsule/candidate profile; M3 adds selected-node authentication/lease while leaving graph publication and settlement to the coordinator. |
| placement lease | Narrow one-use authority for the exact profile/target/attempt named by the lease. Not World membership. |
| candidate | Inert provisional worker result awaiting coordinator validation/publication/settlement. |

## Native and World terms

| Term | Meaning |
|---|---|
| O-core | Statically typed `.oc` language with AST -> HIR -> SSA MIR -> freestanding object pipeline. |
| OKernel | Capability-oriented kernel built using O-core and proven through bounded gates. |
| KernelWorld | Strict package/manifest/lifecycle boundary for a contained kernel/driver world. Current synthetic and object gates are narrower than Alpha G7. |
| O-Machine | General architecture-resource/virtualization contract; current mechanisms cover only named subsets. |
| World | Governed identity/resource/namespace/execution ontology and its protocols. |
| Governor | Intended authoritative replicated World decision/commit layer. A local signer or registry is not a Governor. |
| Live-World | Hosted package/service reference oracle. It does not qualify as a native World. |
| Information V1 | Authority-free immutable information substrate. Verified information is descriptive, not execution permission. |
| generation | Monotonic identity component used to reject stale handles/actors/resources. Same name with a new generation is not the old live authority. |
| OWIDENT | Bounded World identity format. Descriptive identities are not capabilities. |
| OWPROTO | Bounded record/negotiation format. Not a live transport or handshake. |
| OWVALUE | Bounded portable inert value subset. Not the full hosted OValue or hosted shim wire. |
| OWRECEIPT | Canonical World receipt/signing-preimage record. Valid signature alone is not authorization or Governor commit. |
| G0-G13 | Dependency-ordered OSTADIX Alpha qualification gates. They are separate from the 26 portable component gates. |

## Version-axis terms

The same numeral can refer to unrelated axes. Always spell the complete name:

- package `0.4.0`;
- solved Graph V2;
- `oexec.evidence/v6` and `oexec.admission/v6`;
- schedule explanation/why V2;
- `ostadix.backend-catalog/v6`;
- Hosted Placement V6 milestone;
- Hosted transport V1/V2;
- Project Mesh V1;
- OIR Execution Fabric V1;
- World wire family V1;
- Information family V1.

Do not infer compatibility just because two axes use the same number.

## Anti-conflation checklist

Before answering a capability question, ask:

1. Is the subject an ordinary `.O` operation, a foreign project route, an
   operation-planning record, a hosted node request, or a native `.oc` gate?
2. Is the cited artifact syntax, evidence, admission, placement authority,
   execution, or post-execution observation?
3. Is the coordinate current, archival, experimental, or proposed?
4. Does the claim come from a source constant/test manifest or only prose?
5. Was execution local, same-host two-process, LAN peer, QEMU TCG, KVM, or
   identified physical hardware?
6. Did the gate prove a synthetic mechanism or the real kernel/device/network
   named by a broader target?
7. Are effects verified, conservatively `HostWorld`, or merely
   author-declared?
8. Is an identity descriptive, or does it resolve to a live capability/lease
   in the issuing session?
9. Does a successful signature identify a trusted signer and current Governor
   authority, or only byte integrity?
10. What explicit non-claims accompany the cited gate?

## High-value NotebookLM prompts

### Learn the system

> Explain Ostadix-lang to a systems programmer. Start with typed expressions
> and OValue, then trace one `.O` program through OIR, ExecutionPlan, HGraph,
> Evidence V6, Admission V6, dispatch, and settlement. Cite source paths.

> Contrast hosted `.O`, O-core `.oc`, OKernel, O-Machine, World, and OSTADIX
> Alpha. Use a table and label implemented, bounded, and future parts.

### Write and debug O

> Write an O program that computes data in persistent Python, queries a
> persistent SQL environment, and renders Markdown. Explain every environment
> marker and show parse-only and JSON execution commands.

> Diagnose this `.O` program. Check opener/closer matching, `$` escaping,
> Python result selection, environment lifetime, lazy versus defer, and the
> same-environment `O.eval` recursion limitation.

> Choose between `{lazy}`, `{defer}`, `lazy(expr)`, `now`, and
> `autonomous(batch(...))` for these tasks. State cache and effect risks.

### Inspect architecture

> Map this proposed runtime change to the owning `ostadix-api` modules and the
> architecture-root boundary. Identify which tests and generated-runtime
> closure may need updates.

> Explain why an admitted static HGraph wave is not proof of simultaneous
> worker execution. Distinguish graph readiness, physical dispatch,
> provisional publication, and semantic settlement.

> Explain Graph V1's active frozen role in authority-free Execution Intent V1
> versus current executable Graph V2. Then compare archival Evidence V5 with
> current Evidence V6 and explain why neither intent nor archival records can
> be uplifted into current execution authority.

### Evaluate claims

> Audit the claim that “Ostadix already runs a general Linux kernel and Debian
> as a native personality.” Find the exact bounded gates and their non-claims,
> then contrast them with Alpha G7 and G9 acceptance criteria.

> Audit the claim that all 26 portable native gates mean OSTADIX Alpha has
> passed G0-G13. Explain the two manifests and their different roles.

> For this feature claim, produce four columns: strongest supporting evidence,
> execution substrate, explicit non-claims, and what additional evidence is
> required.

### Projects and distribution

> Compare literal `o-link`, a ProjectBundle, operation-realization records,
> Hosted V2, Project Mesh V1, and Fabric V1 by execution unit, transport,
> authority, state model, retry behavior, and non-claims.

> Design a safe command sequence to inspect routes, plan without execution,
> run locally without durable recording, and then require an authenticated
> mesh result. Identify every command with side effects.

### Native development

> Trace an O-core module through parser, type checking, SSA MIR, codegen,
> object emission, linking, and QEMU gate. List current ABI, floating-point,
> aggregate, indirect-call, and AArch64 limitations.

> Given a new OKernel capability operation, identify the native modules,
> authority invariants, positive/negative gates, and explicit non-claims that a
> precise contribution should include.

## Answer template for claim-sensitive questions

NotebookLM can use this response structure:

```text
Status: implemented | bounded/experimental | archival | proposed | future

Exact claim:
  What the repository actually establishes.

Execution substrate:
  Local process | same-host transport | LAN peer | QEMU TCG | KVM | physical.

Authority boundary:
  Which component may inspect, admit, dispatch, publish, settle, or commit.

Evidence:
  Exact source paths, schema IDs, tests/gates, and observed command output.

Non-claims:
  The nearest explicit exclusions.

Unknown/unverified:
  Anything not established by the supplied sources.
```
