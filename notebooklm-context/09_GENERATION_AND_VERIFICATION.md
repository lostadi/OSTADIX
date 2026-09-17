# Context-pack generation and observed verification

This file records what was actually executed while the NotebookLM context pack
was created on 2026-09-09 UTC. It is deliberately separate from historical
README audits and from claims embedded in design documents.

All commands ran from:

```text
/data/data/com.termux/files/home/Ostadix-lang
```

Git HEAD was:

```text
bf575bd9d1027a976c3e067c59689a928886d717
```

The working tree was already dirty, so these observations are not a clean-tree
release attestation. The commands used pre-existing binaries under
`target/release`; this run did not rebuild them or prove that their embedded
source generation equals the current dirty working tree.

## Hosted smoke

Command:

```bash
./target/release/O examples/hello.O backends
```

Exit: `0`

Exact stdout:

```text
[number] 2
```

This proves that the pre-existing release interpreter under `target/release`,
the selected Python backend path, and this one example worked together on this
host. It does not bind that binary to the current dirty source tree or prove
every backend, placement path, O-core, or World gate.

## Compiled version coordinates

Command:

```bash
./target/release/O version --json
```

Exit: `0`

Exact stdout:

```json
{"schema":"ostadix.version-report/v1","package_name":"o-lang","package_version":"0.4.0","minimum_rust_version":"1.93.1","release_rust_toolchain":"1.97.1","admission_schema":"oexec.admission/v6","evidence_schema":"oexec.evidence/v6","evidence_analyzer":"ostadix-oir-evidence-compiler/v6","execution_intent_schema":"oexec.execution-intent/v1","backend_catalog_schema":"ostadix.backend-catalog/v6","hosted_transport_protocols":["ostadix.hosted-transport/v1","ostadix.hosted-transport/v2"],"hosted_tls_alpn":["ostadix-hosted/1","ostadix-hosted/2"],"world_schema":1,"world_wire_codec":1,"world_identity_wire":1,"world_value_wire":1,"world_receipt_wire":1,"graph_executor_enabled":true,"notebook_enabled":false}
```

This is a descriptive report compiled into this binary. It does not prove
external runtime presence, remote authorization, current World state, or that
the optional notebook feature was built; in fact this binary reports
`notebook_enabled=false`.

## Hosted IR and graph inspection

Command:

```bash
./target/release/olangc examples/hello.O --target ir --shim-dir backends
```

Exit: `0`

Exact output:

```text
; OIrProgram
exec python
  text "\n__oval_result__ = 1 + 1\n"
text "\n"

; ExecutionPlan
roots [0, 2]
node 0 exec python [env ephemeral] backend=python spec=e6111346a1d231844cc66eb1c9146aa7658e55c9fdb67f64f30491cab9121bcd pure=false renderer=Python execution=shim required=[]
node 1 text
node 2 text
edge 1 -> 0 structural
edge 0 -> 2 sequence

; HGraph
node n0 Value plan=0 state=Unresolved producer=e3 consumers=[]
node n1 Value plan=1 state=Materialized producer=- consumers=[e3]
node n2 Value plan=2 state=Materialized producer=- consumers=[]
node n3 Completion(0) plan=0 state=Unresolved producer=e3 consumers=[]
node n4 ResourceState(HostWorld@0) plan=- state=Materialized producer=- consumers=[e3]
node n5 ResourceState(HostWorld@1) plan=0 state=Unresolved producer=e3 consumers=[]
node n6 ResourceState(EvaluatorState@0) plan=- state=Materialized producer=- consumers=[e3]
node n7 ResourceState(EvaluatorState@1) plan=0 state=Unresolved producer=e3 consumers=[]
execute e3 plan=0 op=EvalBackend { lang: "python", env: 4294967295 } inputs=[n1,n4,n6] -> outputs=[n0,n3,n5,n7] value=n0
constraint e0 op=Constraint(Structural) ports=[Input:n1,Output:n0]
constraint e1 op=Constraint(SequenceControl) ports=[Input:n0,Output:n2]
constraint e2 op=Constraint(BackendCrossing { from_lang: "O", to_lang: "python" }) ports=[Input:n1,Output:n0]
```

The internal environment value `4294967295` is the reserved ephemeral
representation, not a user-selectable persistent environment. This IR command
did not execute the Python block.

## O-core MIR inspection

Command:

```bash
./target/release/ocorec ocore/examples/minimal.oc --emit mir -o -
```

Exit: `0`

Exact output:

```text
; O-core typed SSA MIR
fn examples::minimal::add [_O_examples__minimal__add]
  bb0:
    %0 = load Place { base: Local(0), projections: [], ty: 7 }
    %1 = load Place { base: Local(1), projections: [], ty: 7 }
    %2 = Add %0, %1
    return %2
```

This verifies parse/type/MIR generation for one minimal module. It does not
build or boot OKernel.

## Baseline repository posture

Command:

```bash
python3 scripts/local_ci_posture.py --profile baseline
```

Exit: `0`

Exact summary:

```text
PASS    baseline.actions.full-sha - all external actions in 2 workflow(s) use full immutable digests
PASS    baseline.dependabot.coverage - Dependabot covers all 6 Cargo, Docker, and Actions roots
PASS    baseline.release-contract - release metadata, required aggregate, package gate, and release surfaces agree
PASS    baseline.required-aggregate - required-ci exactly aggregates 12 manifest-owned jobs
PASS    baseline.workflows.permissions - all workflows declare read-only or empty explicit permissions
PASS    baseline.workflows.present - found 2 GitHub Actions workflow(s)
PASS    baseline.workflows.risky-triggers - no high-risk workflow trigger is enabled
PASS    baseline.workflows.self-hosted - no workflow selects a self-hosted or dynamic runner
local-ci-posture: status=pass profile=baseline pass=8 findings=0 missing=0 exit=0
```

This is the baseline governance/posture profile, not the full Rust, backend,
native, or release suite.

## Contract and manifest validation

Commands and exact outputs:

```text
$ python3 scripts/contract_surfaces.py validate
contract-surfaces: ok

$ python3 tests/example_manifest.py validate
example manifest: PASS (46 files)

$ python3 scripts/release_evidence.py validate
release evidence: PASS (26 required portable QEMU gates)
```

All three exited `0`. The release-evidence command validates the retained
manifest/evidence contract; it did not rerun all 26 QEMU gates during context
generation.

## Alpha evidence status was not derivable here

Command:

```bash
python3 scripts/world_alpha_evidence.py
```

Exit: `1`

Exact output:

```text
OSTADIX Alpha evidence error: evidence/world/g0-attribution-history-continuity-2026-09-03.toml.source_commit does not resolve to a Git commit
```

This local Git object database does not contain the referenced commit, so this
run cannot support a fresh statement about which G0-G13 gates derive as passed.
It does not invalidate the independent 26-component-gate manifest validation;
the two registries answer different questions.

## What was not run for this pack

- the full Rust test suite, Clippy, or formatter gate;
- every hosted backend/example;
- C17 or Python reference suites;
- the 26 portable QEMU gates themselves;
- the supplemental nested-SVM/KVM gate;
- physical hardware, device, DMA/IOMMU, multinode, or Alpha G0-G13 evidence;
- installation, node pairing, remote execution, or mutation of a persistent
  Live-World state.
