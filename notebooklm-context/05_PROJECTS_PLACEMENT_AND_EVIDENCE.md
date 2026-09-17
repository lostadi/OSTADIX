# Projects, placement, and evidence boundaries

This part of the repository contains several related but intentionally
non-interchangeable systems. Keep the execution unit and authority of each one
explicit.

## Ordinary O versus foreign projects

An ordinary `.O` document lowers into OIR and the hosted executable HGraph.

A heterogeneous source directory can instead become a lossless ProjectBundle.
Its Rust, C, Python, shell, and other files remain ordinary foreign-language
files; they are not rewritten into OIR. Project routes and prerequisites lower
into a Project Logical HGraph. Execution materializes a source-closed workspace
and runs an explicitly selected route policy.

```text
.O document -> OIR -> hosted operation HGraph

project directory -> ProjectBundle + route contracts
                  -> Project Logical HGraph
                  -> selected route/prerequisite island
```

Primary sources: `src/bin/olink.rs`, `crates/ostadix-api/src/project/`,
`docs/PROJECT_MESH_V1.md`, and `docs/UNIFIED_INTENT_FRONT_DOOR_V1.md`.

## Project routes and execution

`o-link --project` captures a directory in a route-preserving bundle. Route
metadata can come from an `olang.project.toml` manifest or explicit route
declarations. A route has an ID, command, working directory, result codec,
dependencies, requirements, policy, and relevant effect/failure declarations.

The Project Logical HGraph preserves:

- route and prerequisite topology;
- logical inputs and outputs;
- environment and effect declarations;
- exact bundle and route-contract identities; and
- residual unknown `HostWorld` where effects are not closed.

The project executor owns isolated materialization, prerequisite ordering,
route settlement, and a runtime trace. Multi-alternative policies can include
explicit/default/fallback/first-success/race/all/equivalence/benchmark modes,
but each mode retains its own continuation and evidence rules. A declaration
that a route is idempotent is an author contract, not independent proof of its
effects.

Planning a project does not run route commands. A runtime trace is unsigned
observation unless a higher boundary explicitly wraps it; it is not placement
or World authority.

## Unified intent front door

The compiled `o-cli` accepts:

- an ordinary `.O` document;
- a project directory;
- an already lifted ProjectBundle `.O` file; or
- a marked operation project for the experimental operation-planning slice.

A standalone foreign-language file is rejected with guidance to capture its
containing project. `o routes` is read-only. `o plan` is non-executing unless a
separately named live-inspection mode is requested. `o run` repeats preflight
and current admission before dispatch.

Primary source: `docs/UNIFIED_INTENT_FRONT_DOOR_V1.md`.

## Operation and realization records

The experimental operation-realization V1 boundary defines four canonical,
descriptive, authority-free records:

```text
OperationContractV1
  -> OperationInterfaceV1
  -> one or more RealizationDescriptorV1 records
  -> RealizationSetV1
```

Their schemas are:

| Record | Schema |
|---|---|
| contract | `ostadix.operation-contract/v1` |
| interface | `ostadix.operation-interface/v1` |
| descriptor | `ostadix.realization-descriptor/v1` |
| set | `ostadix.realization-set/v1` |

`o operation inspect` validates one explicitly typed record. `o operation
verify` checks exact contract/interface/descriptor/set references, port
coverage, set membership, and stable-name uniqueness.

A pass means referential consistency only. It does not establish that a
contract is true, that two implementations behave equivalently, that a target
is eligible, or that work may be placed or executed. The records contain
content identities, not locators, credentials, or invocation authority.

Primary source: `docs/OPERATION_REALIZATION_V1.md` and
`crates/ostadix-api/src/computation_core.rs`.

## Operation planning and observation

The experimental planning family adds representation, transfer, cost,
objective, logical graph, deployment, runtime observation, recovery, and
planning-request records. The first implemented planner profile:

- accepts exactly one logical operation;
- accepts caller-supplied complete candidate tuples rather than building a
  Cartesian product;
- checks the exact semantic record closure, ports, static target footprint,
  representations, fidelity references, and cost-profile binding;
- rejects unresolved dynamic environment/effect/resource requirements; and
- ranks legal static candidates by the declared bounded cost objective with a
  canonical tie break.

`StaticallyCompatibleForRanking` is not live eligibility. “Selected” means only
that a tuple won this offline objective; it does not mean admitted, authorized,
reserved, placed, reachable, resident, or executed.

A marked operation project creates two additional exact joins:

1. a descriptor implementation digest must equal the manifest-named captured
   file bytes; and
2. its pipeline reference must equal the deterministic projection of the
   bound project route.

These joins still do not prove that the route loads the named implementation,
that alternatives are behaviorally equivalent, or that execution occurred on
the physically described target.

`o observe` verifies retained planning and terminal records against an
unchanged project. `o replan --without-target` computes a new non-executing
plan. A RecoveryPlan record is a consistent conditional description; it does
not retry, restore, migrate, reserve, fence effects, or dispatch.

Primary source: `docs/OPERATION_PLANNING_V1.md` and
`crates/ostadix-api/src/computation/realization_plan.rs`.

## Local evidence and admission

Current ordinary hosted execution uses:

```text
solved HGraph V2
  -> oexec.evidence/v6
  -> oexec.admission/v6
  -> coordinator execution
```

The evidence bundle binds analyzed facts to exact semantic and executable
inputs. Admission validates and freezes the local execution authority. An
execution-intent identity is stable and authority-free; it can be compared
across analysis and execution, but matching still triggers fresh V6 evidence
and admission.

Schedule Explanation V2 and Why V2 expose inspection projections. They do not
dispatch work, probe every runtime, mint a placement lease, or prove observed
parallelism.

Primary sources: `SPEC.md` section 2.5, `docs/VERSIONING.md`, and
`docs/SEMANTIC_CUSTODY.md`.

## Hosted Placement V6

Hosted Placement V6 is a bounded placement milestone with a
transport-independent proof core and two direct-node transports:

- frozen Hosted transport V1 executes one fresh source document and does not
  consume the complete placement proof;
- durable Hosted transport V2 carries the proof under a one-use signed
  authority envelope, reconstructs a sealed single-shim fragment, and records
  session mutation in a node-signed hash-chain journal.

Both require an explicitly selected node. The milestone models requirements,
targets, warrants, executable realizations, capacity evidence, and one-use
leases. Durable V2 separates the TLS identity, session bearer, logical session,
and actor generation and applies hard state quotas.

Hosted Placement V6 is not:

- automatic placement or a global scheduler;
- an OSTADIX World, Governor, WorldFS, or World membership;
- a general arbitrary-project or arbitrary-HGraph placement service;
- exactly-once arbitrary external effects;
- automatic retry, alternate-node selection, compensation, or universal
  cancellation;
- process-memory migration or a coherent distributed address space; or
- physical hardware/device isolation evidence.

The name `Hosted Placement V6` is independent of local Admission V6 and backend
catalog V6.

Primary source: `docs/HOSTED_PLACEMENT_V6.md`.

## Project Mesh V1

Project Mesh V1 remotely executes a whole source-closed project route and its
transitive prerequisite island. Its transport is TLS 1.3 mutual authentication
with a versioned ALPN. Each actor request binds exact bundle bytes, route
contract, Project Logical HGraph, selected destination, actor generation, and
portable limits. The destination recomputes those identities and checks local
runtime/capacity conditions.

Discovery combines LAN endpoint hints with a durable paired-peer registry. LAN
advertisements are routing hints; pinned pairing state owns the transport trust
material. The front door uses only already-running peers and never starts a
node implicitly.

Retry/fallback is policy-controlled. The safe default local fallback is allowed
only while actor execution is proven not to have started; an explicitly
idempotent route may opt into broader replay. A restarted actor is a fresh
generation with a rematerialized immutable bundle. This is settled-boundary
replay, not live migration of memory, descriptors, sockets, processes, or
backend state.

Project Mesh does not provide NAT traversal, a global registry, a distributed
shared filesystem, arbitrary OIR operation placement, automatic toolchain
installation, weighted device/resource reservations, verified idempotency,
exactly-once host effects, World mutation, or Governor admission.

Primary source: `docs/PROJECT_MESH_V1.md`.

## OIR Execution Fabric V1

Execution Fabric is separate from Hosted transport V1/V2 and Project Mesh. Its
frozen M2 records describe a narrow source-closed trusted pure renderer
operation and its provisional candidate. The additive M3 boundary can execute
that exact profile on an explicitly selected authenticated node under a one-use
lease.

The remote worker computes inert candidate bytes. It cannot:

- mutate the HGraph;
- publish the HGraph value;
- choose the winning attempt;
- advance resource versions;
- settle semantic trace order;
- commit an external effect; or
- initiate retry.

The coordinator remains the sole graph-commit and linearization authority. It
must validate candidate identity/timeliness, decide publication, and settle the
result.

The current executable subset is an HTML, Markdown, LaTeX, or text renderer
over source literals and exact input slots with portable OWVALUE core records.
It is not arbitrary OIR, general `.O` distribution, scope transport, actors,
external effects, a capacity scheduler, distributed settlement, automatic
retry, hardware execution, or a physical multinode claim.

Primary source: `docs/OIR_EXECUTION_FABRIC_V1.md`.

## Semantic custody

The repository contains several linked custody chains, not one universal proof
that source became a governed World result. Examples include:

- source -> OIR -> plan -> solved graph -> stable intent;
- current evidence -> local admission -> dispatch -> result/trace;
- source/project facets -> generated executable manifest;
- backend input/output assessments -> optional crossing evidence;
- Project Logical HGraph -> deployment description -> runtime observation;
- World codec corpora -> bounded Rust/O-core byte convergence.

Each transformation states what identity and fidelity it preserves. A chain
must not be extended across a missing authority, transport, or observation
boundary simply because adjacent records share a digest.

Primary source: `docs/SEMANTIC_CUSTODY.md`.

## Live-World, Information, and O-Git are separate

- Hosted Live-World is a bounded package CAS, activation, health, service,
  rollback, restart, and composition reference. It is a simulator/oracle and
  not native World qualification.
- Information V1 is an authority-free immutable information substrate with
  typed identities, deltas, projections, provenance, stores, and offline
  records. Verified information does not grant execution authority.
- O-Git is a narrow semantic-receipt/diff demo. Its receipt is separate from
  canonical OWRECEIPT and Governor commit semantics.

Primary sources: `docs/HOSTED_LIVE_REFERENCE.md`, `docs/INFORMATION_KERNEL_V1.md`,
`crates/ostadix-api/src/information/`, `src/bin/ogit.rs`, and
`docs/SEMANTIC_CUSTODY.md`.

## Authority comparison

| Artifact/system | What it establishes | What it does not establish |
|---|---|---|
| Execution Intent V1 | Stable authority-free identity of analyzed semantics | Admission or permission to run |
| Evidence V6 | Bound pre-execution facts/contracts | Local execution authority by itself |
| Admission V6 | Current local coordinator authority for exact bound execution | Remote placement or World authority |
| Hosted placement lease | Bounded operation/session authority on selected node | Governor/World membership or global scheduling |
| Fabric candidate | Provisional computed result bytes | HGraph publication or settlement |
| Project mesh trace | Observation of discovery/attempt/fallback | Signed World receipt or authority |
| RuntimeGraph/receipt | Post-execution observation under its named contract | Reusable admission for a later run |
| Information record | Validated immutable descriptive information | Capability, freshness, or execution permission |
