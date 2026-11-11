# Current public contract

This page separates the hosted language, its runtime boundary, and the native-system objective. It describes the inspected source baseline `1da570dcc61ef10285fc8c8b78a20ca087081daf` and the accompanying public-contract changes. A source-backed capability is not a claim that every listed runtime was installed or every test was executed on this revision. Fresh validation belongs in the named result/receipt, with its source and environment.

## The expression and its value

`LANG^(body)_LANG` chooses the evaluator for a syntactic region. The parser's `ONode::TypedExpr` stores the language, environment identity, attributes and body. These are **evaluator tags**, not static foreign-language result types. A Python-tagged expression may return a number, text, a collection or an error; it can also perform effects. O-core's statically checked `.oc` types are a separate language boundary.

`OValue` is the interchange algebra. It includes explicit numeric forms, encoded text, bytes, sequences, maps with arbitrary value keys, graphs, native capsules, quoted expressions, scopes and operational values. A rich carrier can represent distinctions that a particular adapter discards. Canonical CBOR preserves the encoded OValue; it does not prove that lifting from, or rendering into, another language preserves its semantics.

The [numeric witnesses](../benchmarks/fidelity/README.md) demonstrate the distinction. Python `1.0` can return through JavaScript stdout as integer `1`, changing type dispatch while equality survives. Integer `9007199254740993` can return as `9007199254740992`, changing parity. Both ordinary-scalar and tagged-OValue CBOR controls remain exact. Those are dated, concrete cases, not an accuracy survey of all backends.

Sources: [parser](../crates/ostadix-api/src/parser.rs), [OValue](../crates/ostadix-api/src/value.rs), [wire framing](../crates/ostadix-api/src/wire.rs), [witness implementation](../tests/fidelity_evaluation.rs).

## Foreign source is another boundary

Child values and O bindings must pass through a receiver-specific projection before a foreign evaluator parses its body. Literal data insertion, intentional presentation, and explicit code insertion have different contracts. The [SPEC](../SPEC.md#4-backend-protocol) is the normative splice surface; the [research note](research/fidelity-boundaries.md) states the conditional confinement result and its limitations.

The literal contract is deliberately profile-specific. Lexical checks are conservative. Unsupported contexts around ordinary holes include Python f/t-strings, JavaScript/Nix interpolation, complex shell substitution/parameter/array forms, `[[` conditions, heredocs, ambiguous JavaScript slash, Nix indented strings and path prefixes, and bare Python/JavaScript backslashes. An unsupported prefix may leave later ordinary holes unavailable even after it appears to close. Simple native shell `${name}` and guest code with no O holes retain their existing path. This is not a full guest-parser proof. Known executable profiles must admit an ordinary value hole in a supported expression position and produce a receiver literal; placing the hole inside a guest string, comment or adjacent identifier is rejected. The literal profiles are Python, SQLite SQL, Bash/shell, JavaScript, and `nix`, `nix_expr`, `nix_store`, `nixos_test`. TypeScript is not catalog-registered. An explicit `$!name` insertion lowers to a visible `code($name)` call and relinquishes literal confinement, including for unknown executable profiles. Only an immediate code-call hole is raw; storing its ordinary returned value does not confer that projection. A subsequent ordinary hole after dynamic code is rejected when its lexical context is unknown. Presentation profiles such as HTML, text, Markdown and LaTeX do not establish executable-language confinement, HTML sanitization or safe browser interpretation. A backend name alone does not establish a literal grammar profile.

Typed numeric binding, output lifting, literal rendering, source-context validation and authority checks are distinct gates. A statically invalid hole context is refused before execution; a value-dependent projection refusal concerns the receiving backend and does not undo producer effects already used to obtain that value. A syntactically confined value can still lose numeric precision. Explicit code can be authorized to execute yet remain semantically different from its producer. A literal inserted into a deliberately dangerous parent operation does not make the operation safe. In particular, authored `eval`, Bash `let`/`declare -i`, or existing integer-variable attributes can reinterpret data during execution. Lexical acceptance is not a proof of the complete guest grammar or of effect safety. The known nested `[[` context is refused around ordinary holes; native `${name}` remains guest syntax with its original semantics.

The authoritative Rust source now also records actual receiver-fragment preparation under `execution_evidence.trace.source_renderings`. Records use schema `ostadix.source-render-observation/v1`, phase `prepared`, and scope `rendered_fragment_not_guest_execution`; they identify receiver/child plan nodes, language, renderer, value/code role, fidelity and hashes of the canonical value and rendered fragment. A completed-body hash covers the receiver splice buffer before backend-owned wrappers, preludes or control framing. No raw value or source is added. Partial preparation can retain records without that body hash, and guest failure retains already prepared records. Denied/unused quoted regions get no fabricated observation. Trusted inline presentation-only worker fast paths are outside this coverage. Preparation does not establish dispatch/completion, a pre-admitted final guest program or new authority. These are additive runtime trace fields, not a V6 or wire-version relabel.

Source guards now exist in the Rust runtime, Python reference and C17 edition. Their source identities and real-engine tests remain edition-specific. Rust admission and prepared-fragment trace guarantees do not transfer to the reference editions. Python external shims use their own timeout; in-process Python and C17 do not inherit the Rust general step-deadline guarantee. C17 rejects embedded-NUL text where its C-string carrier cannot preserve it. The unchanged legacy C++ prototype is outside this qualification.

## What ordinary admission binds

The active Rust path lowers source to OIR and a validated ExecutionPlan, builds and solves Graph V2, analyzes Evidence V6, and constructs `AdmittedExecutionV6`. The coordinator accepts that admitted object and rechecks its runtime binding. Evidence ties the lowered program, plan, graph, catalog/interface policy, selected direct executables and other declared inputs together. V5 records remain explicit archival/compatibility surfaces.

This identity is not automatically the identity of the original source bytes. Public evaluator entrypoints also accept an already-lowered `OIrProgram`. Where the source/intent front door supplies actual and expected source and execution-intent digests, those are checked before fresh admission; the check does not replace admission and is not inherited as the identity of arbitrary nested `O.eval` fragments.

Caller-owned initial scope is also not universally digest-bound as a complete immutable input package. Its bindings are installed after ordinary admission; a narrow O-scope `Load` preparation freezes the value it actually reads. Do not infer a universal initial-scope commitment, whole-process replayability or a closed ambient environment from the lowered-program digest. Direct launcher hashing does not attest arbitrary descendants, dynamic libraries or all effects of hosted code.

Sources: [evaluator entrypoints and intent gate](../crates/ostadix-api/src/eval.rs), [analysis](../crates/ostadix-api/src/evidence/analyze.rs), [V6 evidence](../crates/ostadix-api/src/evidence/fact.rs), [admission](../crates/ostadix-api/src/evidence/admit.rs), [ordinary coordinator](../crates/ostadix-api/src/executor/coordinator.rs), [architecture](../ARCHITECTURE.md#evidence-bound-admission).

## Scheduling, state and authority

The ordinary OIR coordinator, buffered Request scheduler, and project executor are separate authorities. `ProjectCoordinator` has its own validated project branches, route policy and execution observations. Successful ordinary admission is not a universal dispatch grant for project routes, a migration warrant, an actor checkpoint or exactly-once external effects.

An environment index names a runtime environment identity; persistence depends on the backend's implementation and catalog state-support profile. In particular, the JavaScript backend is **Stateless**. Its proxy/bridge may persist while each execution spawns a fresh Node.js process. `javascript[0]` therefore does not promise durable JavaScript globals. The legacy JavaScript shim, implemented in Python, likewise launches Node per execution. Consult the actual profile before relying on persistent guest state.

The compiled catalog describes tags, aliases, adapters, renderers, execution modes, runtime alternatives and declared capabilities. Presence in the catalog, `o capabilities`, or an executable search result establishes neither health nor authority. Use the operation's actual prerequisites, admission and retained execution result.

Sources: [catalog declarations](../crates/ostadix-api/src/backend_catalog.inc.rs), [catalog implementation](../crates/ostadix-api/src/backend_catalog.rs), [JavaScript native bridge](../crates/ostadix-api/src/backend.rs), [legacy JavaScript shim](../backends/javascript_shim.py), [Request scheduler](../crates/ostadix-api/src/scheduler.rs), [project executor](../crates/ostadix-api/src/project/executor.rs), [compiled command catalog](../src/command_catalog.rs).

## Selected backend capabilities

This table describes the current Rust adapters and catalog, not installed-engine
health or a live-operation grant. Indexed interpreter state, checkpoint support
and callback support are separate properties.

| Profile | Original engine and interpreter state | Value crossing | Adapter callbacks | Checkpoint declaration | Whole engine lowered through O-core |
|---|---|---|---|---|---|
| Python `[n]` | Selected Python 3 shim with indexed environments | Python plain-data profile; rich carrier has its own codec | Framed `O.eval` requests | Bounded `ostadix.python-graph/v1`, exact implementation | No |
| SQLite `[n]` | SQLite CLI with persistent connection state | SQL scalar projection and result lifting | No evaluator-callback bridge | Bounded `ostadix.sqlite-cli-main/v1`, exact implementation | No |
| Bash/shell | Plain Bash is fresh; Bash `[n]` has live sessions; shell/sh is always fresh | One literal word or native quoted parameter expansion | No in-block evaluator-callback bridge | Catalog `Stateless` is not a portable snapshot of numbered Bash | No |
| JavaScript | Fresh Node per step, even with a persistent proxy | JavaScript Number/stdout profile can lose distinctions | Unix `O.native_*` owner-operation bridge; no general `O.eval`; unavailable on non-Unix | `Stateless`; no persistent Node globals | No |
| Unprofiled executable tag | Adapter-specific, where installed | Ordinary holes refused; explicit code remains code | Adapter-specific; not inferred from a tag | Inspect its declared profile and actual export result | No general claim |

The catalog's state-support class does not replace the actual numbered-session
contract or certify that arbitrary interpreter memory can be checkpointed.
Callbacks retain their own admission path. Read the implementation and operation
result before relying on a particular export or import.

## Capability matrix

| Surface | Current bounded capability | What remains outside that claim | Source/evidence entry |
|---|---|---|---|
| Evaluator-tagged `.O` syntax | Recursive evaluator regions, O-level bindings and plan dependencies | Static typing or soundness of arbitrary foreign bodies | [SPEC](../SPEC.md), [parser](../crates/ostadix-api/src/parser.rs) |
| OValue and canonical transport | Rich tagged carrier and framed CBOR | Lossless semantics through every adapter | [value/wire contracts](../SPEC.md), [numeric witnesses](../benchmarks/fidelity/README.md) |
| Fidelity intervals | Definite/possible structural losses, bounded algebra and executable checks | Proof of every backend loss report; arbitrary mixed-sentinel join lattice | [domain proof](fidelity-domain.md) |
| Ordinary Rust execution | OIR/plan/Graph V2 plus Evidence/Admission V6 | Universal source-byte or initial-scope commitment; all execution under one authority | [architecture](../ARCHITECTURE.md#evidence-bound-admission) |
| Source/intent front door | Explicit source and intent digest check before fresh graph admission | Automatic identity inheritance into every nested evaluation | [front-door contract](UNIFIED_INTENT_FRONT_DOOR_V1.md), [evaluator](../crates/ostadix-api/src/eval.rs) |
| Project execution and planning | Separate route/project coordinator; bounded static operation planning | Record validation as behavioral equivalence, live eligibility, recovery execution or permission | [planning contract](OPERATION_PLANNING_V1.md), [executor](../crates/ostadix-api/src/project/executor.rs) |
| Hosted engines | Original installed engines invoked through declared adapters | Their implementation bodies automatically compiled through O-core | [runtime provenance](RUNTIME_PROVENANCE.md), [catalog](../crates/ostadix-api/src/backend_catalog.inc.rs) |
| JavaScript indexed environment | Stable proxy identity; stateless fresh Node execution | Persistent Node globals or shared in-process objects across steps | [native bridge](../crates/ostadix-api/src/backend.rs), [state declaration](../crates/ostadix-api/src/backend_catalog.inc.rs) |
| Original-source native component | Pinned u9fs codec and musl component pipeline with its declared closure | Complete u9fs, Linux, Plan 9, or arbitrary runtime/compiler lowering | [component qualification](../tools/ocore-runtime/u9fs/NATIVE_PEER.md) |
| O-core ISA backends | x86-64, AArch64 and RV64GC compiler paths with profile-specific support | Whole-runtime identity across all targets; i686/ARMv7 foundations complete | [ISA requirements](../tools/ocore-runtime/isa.requirements.json), [expansion requirements](../tools/ocore-runtime/expansion.requirements.json) |
| Integrated boot | Persistent AArch64 O-core monitor with original Linux/Alpine guest and native namespace component | Full guest-kernel lowering or a completed unified OS | [boot contract](OKERNEL_PACKAGE_BOOT.md), [boot entry](../boot/README.md) |
| Emulated and physical hardware | Named virtual-device and QEMU gates, plus separately scoped hardware evidence where present | QEMU success as proof of physical X12 display, keyboard, storage or driver support | [X12 status](OKERNEL_X12.md), [claim inventory](CLAIMS.md) |

## Validation and development disclosure

The [splice migration guide](SPLICE_MIGRATION.md) gives revised SQL, Python,
JavaScript and shell examples and explains the preserved reference's older
quoted-hole syntax.

The published baseline `1da570dc` has a [public CI run](https://github.com/lostadi/OSTADIX/actions/runs/42972231895) that failed on two workflow-posture findings before the Rust jobs. That run supplies no passing Rust-suite claim. Follow-up repairs and new execution results must retain their own source identities; do not relabel this baseline failure as a later success.

The [seven splice baseline witnesses and reproduction package](../evidence/public-contract-20261111/README.md) preserve the original control, injection, syntax-failure and timeout observations. The [checked-in witnesses](../tests/fixtures/foreign-splice-witnesses.json) and [contract tests](../tests/foreign_splice_contract.rs) define the cases. The [portable runner](../scripts/reproduce_splice_contract.py) separates original inputs from revised-contract positive/negative probes; a command's existence is not an executed revised-result claim.

[CLAIMS.md](CLAIMS.md) is the detailed evidence inventory. [CI_POSTURE.md](CI_POSTURE.md) describes the static/local audit and optional tools. [The full reference](REFERENCE.md#running-the-tests) retains the existing commands and historical results. A passing parse, unit test, object build, source capture, emulated boot, hosted integration and physical-driver test answer different questions. Any report must identify which one actually ran, its prerequisites and its source.

The [AI-assisted development disclosure](AI_ASSISTED_DEVELOPMENT.md) distinguishes substantial tool assistance, maintainership, Git publication identity and evidence responsibility. The existing [technical whitepaper](../Ostadix-lang_Technical_Whitepaper.pdf) remains a dated artifact; this page does not rewrite its historical experiment dates or source identities.

## Engine API inventory

These are source inventory counts, not execution or qualification counts.
Direct engine users may import the 44 public runtime modules. The compatibility
facade retains its separate existing surface. The historical reference keeps its
original counts; this inventory is checked against the current source.

```text
# 55 engine modules, 44 public
# 43 public compatibility reexports
```
