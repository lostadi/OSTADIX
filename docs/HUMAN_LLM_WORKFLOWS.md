# One runtime, human and LLM interfaces

OSTADIX exposes task discovery to a human through `o capabilities` and
`o guide`, and to an MCP client through `o_capabilities` and `o_guide`.
Both compile the same command catalog, recipes and guides from
[`src/command_catalog.rs`](../src/command_catalog.rs). A recipe pairs a human
command with structured MCP arguments and states its effect. Discovery lists
commands and locates executables; it does not execute the recipes, run help,
start services or establish runtime readiness.

Execution uses the existing native implementation. `o_execute` accepts a
complete program or project; `o_operation` accepts a marked operation project.
Human `o tool COMMAND [ARGS...]` and the expert `o_cli` interface preserve
the full literal argument array of any cataloged command, including script
entries whose short names are not standalone shell commands. They use the
same executable resolver. These interfaces share native planners, executors, records
and validation rules rather than maintaining separate meanings of an operation.

## Discover an action

| Task | Human CLI | MCP call |
|---|---|---|
| Browse commands and recipes | `o capabilities` | `o_capabilities({})` |
| Search operation workflows | `o discover operation --json` | `o_capabilities({"query":"operation"})` |
| Read the operation workflow | `o guide operations` | `o_guide({"topic":"operations"})` |
| Read compiler guidance | `o guide compiler` | `o_guide({"topic":"compiler"})` |
| Invoke a cataloged script | `o tool capacity --help` | `o_cli({"command":"capacity","args":["--help"]})` |
| Inspect a native command's current help | `o node --help` | `o_cli({"command":"o","args":["node","--help"]})` |

The JSON catalog includes command IDs, families, documentation paths, resolved
paths, supported help arguments, guide topics and paired recipes. Its
`available` field means that the executable or script/interpreter was located.
The installed executable can lag the source catalog. Use its supported help
invocation before relying on unfamiliar options, and use `o doctor` or
`o_doctor` for installation diagnostics. The catalog intentionally has no
automatic help probe for commands such as the notebook or language server
whose invocation could start a service.

The complete catalog includes runtime and compiler tools, linking, projects,
hosted nodes and sessions, registries, live services, information records,
O-core and kernel workflows, capacity, devices, setup and supporting tools.
The native command remains responsible for its accepted arguments and effects.

## Hand over a complete cross-language computation

For example, put this complete computation in `report.O`:

```o
html^(
<p>Result: python^(
__oval_result__ = sum([1, 2, 3])
)_python</p>
)_html
```

The Python expression supplies an OValue to the containing HTML expression.
The runtime represents the dependency and evaluates the child before its
parent. A caller can therefore submit one program instead of extracting a
result and constructing a second tool call around it. The existing
[`html_python_html.O`](../examples/html_python_html.O) example contains a more
deeply nested composition.

| Task | Human CLI | MCP arguments to `o_execute` |
|---|---|---|
| Parse without executing payloads | `o check report.O` | `{"path":"report.O","action":"check"}` |
| Inspect the static plan | `o plan report.O --json` | `{"path":"report.O","action":"plan"}` |
| Execute the complete program | `o run report.O --json` | `{"path":"report.O"}` |
| Inspect compiler IR | `o ir report.O` | `{"path":"report.O","action":"compile","target":"ir"}` |
| Compile a native artifact | `o ship report.O -o report-bin` | `{"path":"report.O","action":"compile","target":"binary","output":"report-bin"}` |

Supply an explicit `cwd` to MCP calls when the file or program uses relative
paths. Exactly one of `source` and `path` is accepted. Inline source is also a
complete program:

```json
{
  "source": "html^(<p>Result: python^( __oval_result__ = sum([1, 2, 3]) )_python</p>)_html",
  "action": "execute"
}
```

`check` establishes parse success. `plan` provides static inspection. Neither
proves arbitrary hosted-language behavior, backend readiness or execution
admission. Compilation may invoke the native build toolchain; artifact creation
is separate from running or qualifying that artifact.

For ordinary source, `mode: "admitted"` binds the source and execution intent
and requires fresh native admission. Project admission follows its native
contract. Native backend, placement and concurrency options remain available
through `o_execute` and `o_cli`; see the runtime, compiler and projects guides
for their distinct contracts.

## Manage an operation and its alternative implementations

An operation project has an explicit `[operation]` section in
`olang.project.toml`, an operation planning request, and exact bindings between
offered descriptors, targets, cost profiles, project routes and captured
implementation files. Start with the existing
[`examples/normalize`](../examples/normalize) project.

The following commands assume the checkout is the working directory. The MCP
examples use `examples/normalize`; relative MCP paths resolve against an
explicit `cwd`, or otherwise against the configured `O_LANG_ROOT`.

| Task | Human CLI | MCP arguments to `o_operation` |
|---|---|---|
| Describe and structurally validate | `o operation examples/normalize --json` | `{"path":"examples/normalize"}` |
| List declared implementations | `o realizations examples/normalize --json` | `{"path":"examples/normalize","action":"realizations"}` |
| Select without executing | `o plan examples/normalize --json` | `{"path":"examples/normalize","action":"plan"}` |
| Explain acceptance, rejection and selection | `o plan examples/normalize --explain --json` | `{"path":"examples/normalize","action":"explain"}` |
| Select, bind, execute and record | `o run examples/normalize --json` | `{"path":"examples/normalize","action":"run"}` |
| Observe a retained run | `o observe examples/normalize --run RUN_ID --json` | `{"path":"examples/normalize","action":"observe","run":"RUN_ID"}` |
| Exclude a supplied target and replan | `o replan examples/normalize --run RUN_ID --without-target 'Ambient Python Primary' --json` | `{"path":"examples/normalize","action":"replan","run":"RUN_ID","without_targets":["Ambient Python Primary"]}` |

`describe` is the default MCP action. Only explicit `action: "run"` dispatches
the operation. The typed interface requires a marked project in the native
planning/execution invocation; it does not silently reinterpret an unmarked
directory as a generic project run. `run` selects through the native planner;
there is no MCP route override for this interface.

Every result retains the native job identity, exit status and logs. For a
foreground call, `result` contains the native JSON report without replacing its
selection, execution or evidence fields. A report too large for inline
projection remains available in full through the returned `o_job_read`
retrieval information. Native failures remain errors with their native report
when it is available, plus the retained stderr and stdout.

### Retain the exact run identity

Copy the `run_id` from the native run summary; in an `o_operation` foreground
response this is under `result.run_id`. Use that ID in subsequent observation,
replanning and record inspection:

```bash
o inspect RUN_ID --json
o explain RUN_ID
o observe examples/normalize --run RUN_ID --json
```

```json
{"command":"o-cli","args":["inspect","RUN_ID","--json"]}
```

The JSON call above uses `o_cli`. Keep the same state configuration for these
calls: if execution supplied `env` overrides such as a separate state root,
inspection must use those same overrides. `last-run` is a convenience default
for observe and replan; an exact ID preserves the intended association when
other work runs concurrently.

New operation runs retain the original planning request, deployment, selected
candidate and pre-execution decision. Observation verifies those records and
their exact bundle/route binding; it does not substitute a new planner choice
for the historical one. Legacy records lacking that original decision use an
explicitly labeled current-planner reconstruction. Inspect the native
`binding`, `runtime_binding` and `nonclaims` fields to distinguish the two.

The record separates selection, execution outcome and available observations.
For example, a selected route does not establish semantic equivalence of its
implementation, and an indirect route does not by itself establish that an
interpreter loaded a separately named implementation file. Changes to the
project can invalidate the exact bundle association needed for observation;
retain the original project snapshot when investigating that run.

### Replan without changing the declared operation

`replan` requires at least one exact declared target in `without_targets`.
It verifies the prior run and bundle association, excludes those offers, and
computes another selection. It does not execute the new selection. Calling
`run` again independently plans from the current project; it does not consume
the preceding replan report as an execution request.

A descriptive recovery plan is emitted only when the source observation
records failure and selection changes. The normalization example's primary
and fallback targets both use local Python. Their alternatives demonstrate
selection over supplied offers, not independent-machine failover or discovery
of target unavailability.

### Propose and revise an implementation

The supported development loop is:

1. Keep the operation contract and interface explicit. Add the candidate's
   implementation and a native project route that can execute it.
2. Construct its realization descriptor, target requirements, representation
   bindings and matching cost profile. Add the descriptor to the realization
   set and supply a complete candidate tuple in the planning request.
3. Bind the offer to its captured implementation and exact route-pipeline
   identity in the marked manifest. Recompute affected typed identities when
   records change; a stale implementation digest is rejected.
4. Use `describe`, `realizations` and `explain` to inspect structural joins and
   deterministic candidate assessments before explicitly running the project.
5. Retain the run ID, inspect its recorded result, and use domain tests or other
   appropriate evidence to assess semantic correctness before further revision.

The typed constructors and canonical encoding in
[`realization_plan.rs`](../crates/ostadix-api/src/computation/realization_plan.rs)
and the semantic records described in
[`OPERATION_REALIZATION_V1.md`](OPERATION_REALIZATION_V1.md) define these
records. This surface does not translate an informal wish into a verified
contract or automatically author a candidate closure. Standalone records can
be checked with `o operation inspect KIND FILE` and
`o operation verify --contract FILE --interface FILE --descriptor FILE --set FILE`;
the same commands are available through `o_cli` with literal arguments.

The planner checks declared relationships: exact port coverage, representation
and target compatibility, cost-profile bindings and its implemented objective.
It does not prove that two implementations compute the same function. Costs
are supplied predictions, not runtime measurements. The current planning
request profile selects among explicit candidate tuples for one logical
operation; it does not perform general optimization across many operation
nodes. See [`OPERATION_PLANNING_V1.md`](OPERATION_PLANNING_V1.md) for the precise
schema and evidence boundaries.

## Long tasks and expert commands

Set `background: true` on `o_execute`, `o_operation` or `o_cli` to receive a
managed job identity immediately. Inspect it with `o_job_status` and read its
stdout/stderr using `o_job_read`. Native JSON stays in the output log; a job
being started is not evidence of completion. Foreground calls default to a
120-second local deadline, background calls to no deadline, and
`timeout_secs: 0` explicitly disables the local deadline. Native command limits
and remote-effect contracts still apply.

Use `o_cli` for flags or command families outside the structured convenience
interfaces. Obtain the command ID from the catalog and pass each native
argument as one string:

```json
{
  "command": "olangc",
  "args": ["report.O", "--target", "dot"],
  "cwd": "/absolute/project"
}
```

There is no shell expansion of that array. `env` affects only the child job.
MCP jobs belong to their live server session; short-lived clients should use
the existing persistent `ostadix-mcp-client` bridge. Reconnect native MCP
clients after an MCP upgrade so they load the new tool schemas. A catalog
entry or workflow example is not a claim that every optional runtime, device,
remote service or native command has been tested on this installation.

## Implementation ownership

| Responsibility | Source of truth |
|---|---|
| Command IDs, executable resolution, guides and paired recipes | [`src/command_catalog.rs`](../src/command_catalog.rs), compiled by both CLI and MCP |
| Human command parsing and operation bridge | [`src/bin/o-cli.rs`](../src/bin/o-cli.rs) |
| Native command routing | [`native_dispatch.rs`](../src/bin/o-cli/native_dispatch.rs) |
| Semantic operation schemas and deterministic selection | [`crates/ostadix-api/src/computation/realization_plan.rs`](../crates/ostadix-api/src/computation/realization_plan.rs) |
| Complete-program MCP interface | [`unified.rs`](../mcp/ostadix_lang_mcp_server/src/unified.rs) |
| Structured operation MCP interface | [`operation.rs`](../mcp/ostadix_lang_mcp_server/src/operation.rs) |
| Session-owned concurrent jobs and retained output | [`execution.rs`](../mcp/ostadix_lang_mcp_server/src/execution.rs) |

The MCP operation interface constructs native arguments and projects native
reports. Changing a planner rule therefore changes the shared native behavior,
without requiring a second selection algorithm in the LLM interface.
