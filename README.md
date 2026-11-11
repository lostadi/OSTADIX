# OSTADIX

*By Lee Daghlar Ostadi*

**A polyglot expression names its evaluator in its syntax; every crossing still needs a value and source-rendering contract.**

```O
html^(<p>Sum: python^(__oval_result__ = sum(range(10)))_python</p>)_html
```

The Python expression produces an `OValue`; the HTML receiver presents it. An evaluator tag selects a language implementation. It does **not** prove a foreign expression's result type or make arbitrary source interpolation safe.

| Boundary witness | What survives | What changes |
|---|---|---|
| Python `1.0` → JavaScript stdout → Python | Both CBOR controls are exact; numeric equality survives. | Float becomes integer; downstream type dispatch changes. |
| Python `9007199254740993` → JavaScript stdout → Python | Both CBOR controls preserve the original integer. | JavaScript Number rounds it; odd becomes even. |
| A value rendered into another language's source | Its bytes may arrive intact. | Without a literal contract, data can acquire the receiver's grammar. |

The first two are [recorded semantic witnesses](benchmarks/fidelity/README.md), with [dated results](benchmarks/fidelity/RESULTS.md). The third has [seven recorded baseline controls/failures](evidence/public-contract-20261111/README.md) and a separate source-confinement obligation, addressed in the [current contract](docs/CURRENT_CONTRACT.md) and [focused research note](docs/research/fidelity-boundaries.md). The [fidelity interval proof](docs/fidelity-domain.md) establishes its stated abstraction algebra; it does not prove every backend or guest lexer correct.

| Read or do | Entry point |
|---|---|
| Know exactly what is supported | [Current contract and capability matrix](docs/CURRENT_CONTRACT.md), [claim/evidence inventory](docs/CLAIMS.md) |
| Run a composed document | [Minimal setup and full reference](docs/REFERENCE.md#quickstart), [literate report](examples/literate_report.O) |
| Understand execution authority | [Architecture](ARCHITECTURE.md), [language specification](SPEC.md), [semantic custody](docs/SEMANTIC_CUSTODY.md) |
| Inspect the World research contract | [Constitution](docs/OSTADIX_WORLD.md), [non-qualifying hosted reference](docs/HOSTED_WORLD_REFERENCE_PROFILE.md), [G0–G13 registry](evidence/world_alpha_gates.toml) |
| Inspect original-source native work | [Runtime/component recipes](tools/ocore-runtime/README.md), [u9fs/musl integration](tools/ocore-runtime/u9fs/NATIVE_PEER.md) |
| Boot the development system | [Boot guide](boot/README.md), [qualified package profile](docs/OKERNEL_PACKAGE_BOOT.md) |
| Inspect validation | [CI posture](docs/CI_POSTURE.md), [test/reference guide](docs/REFERENCE.md#running-the-tests), [historical results](docs/REFERENCE.md#validation-at-the-historical-audited-master) |
| Evaluate the research | [New focused note](docs/research/fidelity-boundaries.md), [existing technical whitepaper](Ostadix-lang_Technical_Whitepaper.pdf), [whitepaper source](docs/Ostadix-lang_Technical_Whitepaper.tex) |
| Understand development and credit | [AI-assisted development disclosure](docs/AI_ASSISTED_DEVELOPMENT.md), [contribution policy](CONTRIBUTING.md), [Git publication identity](docs/COMMIT_AUTHORS.md) |

## Run a document

After the [setup instructions](docs/REFERENCE.md#quickstart), from this checkout:

```sh
o check examples/literate_report.O
o plan examples/literate_report.O --json
O examples/literate_report.O "$PWD/backends" > report.md
```

Checking parses; planning inspects; the final command executes. The example requires Python 3. Use `o capabilities` and `o guide` for the compiled command catalog; an advertised command or installed executable is not proof of runtime health or execution admission.

The [complete preserved reference](docs/REFERENCE.md) retains the former guide
and its dated evidence. The current contract distinguishes present behavior.

## Current boundaries

O orchestration (`.O`) lowers evaluator composition to OIR, an ExecutionPlan, and an admitted graph. O-core (`.oc`) compiles machine computation through a separate typed MIR. The active ordinary Rust path uses **Graph V2 / Evidence and Admission V6**; Request scheduling and `ProjectCoordinator` retain separate execution authorities. Original-source binding is an additional gate where supplied, and caller initial scope is not universally included in ordinary lowered-OIR admission identity.

The JavaScript profile is stateless: a persistent proxy does not imply a persistent Node.js environment. Hosted original engines, selected original components lowered through O-core, and complete original-runtime/compiler lowering are separate milestones. Full cross-ISA semantic equivalence remains incomplete. The integrated boot profile uses original Linux as guest code under an O-core monitor; emulated boots do not qualify physical hardware or establish full Linux/Plan 9 kernel lowering.

Public validation claims are scoped to named commands, source identities, environments, prerequisites and retained results. [Historical logs](docs/REFERENCE.md#validation-at-the-historical-audited-master) are dated observations; a workflow badge or source inventory does not establish that every current gate passes. See [current claims](docs/CLAIMS.md) and the [matrix](docs/CURRENT_CONTRACT.md#capability-matrix) before relying on an advanced surface.

The canonical repository is [lostadi/OSTADIX](https://github.com/lostadi/OSTADIX); [lostadi/ostadix-BM](https://github.com/lostadi/ostadix-BM) is another development line of the same system. Identify artifacts by repository and exact commit, not package version alone. Maintainer: Lee Daghlar Ostadi.

## License and citation

The project uses the GNU Lesser General Public License v2.1 only (`LGPL-2.1-only`); see [LICENSE](LICENSE). Generated AOT build crates are `publish = false`. Their component-scoped Cargo metadata identifies the embedded Ostadix runtime as LGPL-2.1-only while marking embedded user or project inputs as retaining the licensing attached to their source; it does not declare one license for the mixed generated package.

### How to cite

DOI `10.5281/zenodo.21544345` identifies that existing preprint/package record ([Zenodo](https://doi.org/10.5281/zenodo.21544345)); it is not an archive of a tagged Ostadix-lang source release. Cite source separately: Version 0.4.0. Commit: `FULL_COMMIT_SHA_USED`. Repository: https://github.com/lostadi/OSTADIX.

[CITATION.cff](CITATION.cff) keeps these objects distinct: the existing preprint/package DOI remains under `preferred-citation`; a separate DOI for a future tagged source release belongs in its top-level `doi` field. [Development and credit](docs/AI_ASSISTED_DEVELOPMENT.md) explains AI assistance and maintainer publication identity.

<details>
<summary>Compatibility links for the former full README</summary>

All former section headings remain addressable here and link to the preserved full reference. The [machine-readable map](docs/readme-link-map.json) records their original lines and destination anchors.

- <a id="ostadix"></a>[OSTADIX](docs/REFERENCE.md#ostadix)
- <a id="the-system-i-am-building"></a>[The system I am building](docs/REFERENCE.md#the-system-i-am-building)
- <a id="read-the-technical-artifact-set"></a>[Read the technical artifact set](docs/REFERENCE.md#read-the-technical-artifact-set)
- <a id="one-workflow-for-developers-and-llms"></a>[One workflow for developers and LLMs](docs/REFERENCE.md#one-workflow-for-developers-and-llms)
- <a id="how-to-read-ostadix-lang"></a>[How to read Ostadix-lang](docs/REFERENCE.md#how-to-read-ostadix-lang)
- <a id="1-source-is-executable-structure"></a>[1. Source is executable structure](docs/REFERENCE.md#1-source-is-executable-structure)
- <a id="2-the-source-becomes-an-admitted-graph"></a>[2. The source becomes an admitted graph](docs/REFERENCE.md#2-the-source-becomes-an-admitted-graph)
- <a id="3-placement-is-a-decision-over-admitted-work"></a>[3. Placement is a decision over admitted work](docs/REFERENCE.md#3-placement-is-a-decision-over-admitted-work)
- <a id="4-execution-preserves-evaluator-and-resource-identity"></a>[4. Execution preserves evaluator and resource identity](docs/REFERENCE.md#4-execution-preserves-evaluator-and-resource-identity)
- <a id="5-evidence-is-part-of-the-execution-model"></a>[5. Evidence is part of the execution model](docs/REFERENCE.md#5-evidence-is-part-of-the-execution-model)
- <a id="quickstart"></a>[Quickstart](docs/REFERENCE.md#quickstart)
- <a id="offline-ai-build-zips"></a>[Offline AI build ZIPs](docs/REFERENCE.md#offline-ai-build-zips)
- <a id="zero-configuration-lan-execution"></a>[Zero-configuration LAN execution](docs/REFERENCE.md#zero-configuration-lan-execution)
- <a id="peer-mesh-execution-for-whole-projects"></a>[Peer-mesh execution for whole projects](docs/REFERENCE.md#peer-mesh-execution-for-whole-projects)
- <a id="authenticated-pure-fabric-execution"></a>[Authenticated pure Fabric execution](docs/REFERENCE.md#authenticated-pure-fabric-execution)
- <a id="independent-rust-runtime-engine"></a>[Independent Rust runtime engine](docs/REFERENCE.md#independent-rust-runtime-engine)
- <a id="maturity-at-a-glance"></a>[Maturity at a glance](docs/REFERENCE.md#maturity-at-a-glance)
- <a id="boot-the-current-integrated-profile"></a>[Boot the current integrated profile](docs/REFERENCE.md#boot-the-current-integrated-profile)
- <a id="experimental-operation-and-realization-planning"></a>[Experimental operation and realization planning](docs/REFERENCE.md#experimental-operation-and-realization-planning)
- <a id="hosted-placement-v6"></a>[Hosted Placement V6](docs/REFERENCE.md#hosted-placement-v6)
- <a id="hosted-v2-development-quickstart"></a>[Hosted V2 development quickstart](docs/REFERENCE.md#hosted-v2-development-quickstart)
- <a id="using-ostadix-lang-with-ai-agents"></a>[Using Ostadix-lang with AI agents](docs/REFERENCE.md#using-ostadix-lang-with-ai-agents)
- <a id="mcp-server-for-ai-agent-tools-and-url-connectors"></a>[MCP server for AI-agent tools and URL connectors](docs/REFERENCE.md#mcp-server-for-ai-agent-tools-and-url-connectors)
- <a id="getting-started-full-setup-guide"></a>[Getting Started: Full Setup Guide](docs/REFERENCE.md#getting-started-full-setup-guide)
- <a id="prerequisites"></a>[Prerequisites](docs/REFERENCE.md#prerequisites)
- <a id="option-a-automatic-setup"></a>[Option A: Automatic setup](docs/REFERENCE.md#option-a-automatic-setup)
- <a id="recovering-stale-nix-profile-backups"></a>[Recovering stale Nix profile backups](docs/REFERENCE.md#recovering-stale-nix-profile-backups)
- <a id="option-b-manual-rust-setup"></a>[Option B: Manual Rust setup](docs/REFERENCE.md#option-b-manual-rust-setup)
- <a id="o-git-semantic-receipt-demo"></a>[O-Git semantic receipt demo](docs/REFERENCE.md#o-git-semantic-receipt-demo)
- <a id="macos"></a>[macOS](docs/REFERENCE.md#macos)
- <a id="debian-ubuntu-mint-and-pop_os"></a>[Debian, Ubuntu, Mint, and Pop!_OS](docs/REFERENCE.md#debian-ubuntu-mint-and-pop_os)
- <a id="arch-cachyos-manjaro-and-endeavouros"></a>[Arch, CachyOS, Manjaro, and EndeavourOS](docs/REFERENCE.md#arch-cachyos-manjaro-and-endeavouros)
- <a id="fedora-rhel-rocky-and-related-systems"></a>[Fedora, RHEL, Rocky, and related systems](docs/REFERENCE.md#fedora-rhel-rocky-and-related-systems)
- <a id="nixos"></a>[NixOS](docs/REFERENCE.md#nixos)
- <a id="other-systems"></a>[Other systems](docs/REFERENCE.md#other-systems)
- <a id="option-c-c17-edition-only"></a>[Option C: C17 edition only](docs/REFERENCE.md#option-c-c17-edition-only)
- <a id="embedding-the-python-and-c17-editions"></a>[Embedding the Python and C17 editions](docs/REFERENCE.md#embedding-the-python-and-c17-editions)
- <a id="option-d-build-and-boot-o-core"></a>[Option D: Build and boot O-core](docs/REFERENCE.md#option-d-build-and-boot-o-core)
- <a id="build-the-bootable-x86_64-uefi-iso"></a>[Build the bootable x86_64 UEFI ISO](docs/REFERENCE.md#build-the-bootable-x86_64-uefi-iso)
- <a id="install-absorbed-os-kernel-and-userspace-capacity"></a>[Install absorbed OS, kernel, and userspace capacity](docs/REFERENCE.md#install-absorbed-os-kernel-and-userspace-capacity)
- <a id="build-the-combined-staged-tree-ostadix-x86_64-uefi-iso"></a>[Build the combined staged-tree OSTADIX x86_64 UEFI ISO](docs/REFERENCE.md#build-the-combined-staged-tree-ostadix-x86_64-uefi-iso)
- <a id="install-the-hosted-live-iso-on-ventoy"></a>[Install the hosted-live ISO on Ventoy](docs/REFERENCE.md#install-the-hosted-live-iso-on-ventoy)
- <a id="hosted-live-world-reference"></a>[Hosted Live-World reference](docs/REFERENCE.md#hosted-live-world-reference)
- <a id="ostadix-alpha-native-constitution"></a>[OSTADIX Alpha native constitution](docs/REFERENCE.md#ostadix-alpha-native-constitution)
- <a id="project-hgraph-planning-and-ordered-hosted-execution-gates"></a>[Project HGraph planning and ordered hosted execution gates](docs/REFERENCE.md#project-hgraph-planning-and-ordered-hosted-execution-gates)
- <a id="docker"></a>[Docker](docs/REFERENCE.md#docker)
- <a id="browser-ai-chat-pdf-export"></a>[Browser AI chat PDF export](docs/REFERENCE.md#browser-ai-chat-pdf-export)
- <a id="native-android-device-control"></a>[Native Android device control](docs/REFERENCE.md#native-android-device-control)
- <a id="what-gets-built"></a>[What gets built](docs/REFERENCE.md#what-gets-built)
- <a id="build-artifacts-and-source-only-checkout"></a>[Build artifacts and source-only checkout](docs/REFERENCE.md#build-artifacts-and-source-only-checkout)
- <a id="verifying-the-installation"></a>[Verifying the installation](docs/REFERENCE.md#verifying-the-installation)
- <a id="table-of-contents"></a>[Table of Contents](docs/REFERENCE.md#table-of-contents)
- <a id="what-is-new-here"></a>[What is new here?](docs/REFERENCE.md#what-is-new-here)
- <a id="1-typed-parentheses-the-language-is-in-the-syntax"></a>[1. Typed parentheses: the language is in the syntax](docs/REFERENCE.md#1-typed-parentheses-the-language-is-in-the-syntax)
- <a id="2-ovalue-the-universal-exchange-type"></a>[2. OValue: the universal exchange type](docs/REFERENCE.md#2-ovalue-the-universal-exchange-type)
- <a id="3-explicit-persistent-environments"></a>[3. Explicit persistent environments](docs/REFERENCE.md#3-explicit-persistent-environments)
- <a id="4-homoiconicity-across-languages"></a>[4. Homoiconicity across languages](docs/REFERENCE.md#4-homoiconicity-across-languages)
- <a id="5-orchestration-and-machine-computation-have-different-irs"></a>[5. Orchestration and machine computation have different IRs](docs/REFERENCE.md#5-orchestration-and-machine-computation-have-different-irs)
- <a id="related-work-and-how-ostadix-lang-differs"></a>[Related work and how Ostadix-lang differs](docs/REFERENCE.md#related-work-and-how-ostadix-lang-differs)
- <a id="gentle-introduction"></a>[Gentle introduction](docs/REFERENCE.md#gentle-introduction)
- <a id="what-is-a-programming-language-really"></a>[What is a programming language, really?](docs/REFERENCE.md#what-is-a-programming-language-really)
- <a id="nested-expressions"></a>[Nested expressions](docs/REFERENCE.md#nested-expressions)
- <a id="naming-values"></a>[Naming values](docs/REFERENCE.md#naming-values)
- <a id="persistent-state-when-you-ask-for-it"></a>[Persistent state when you ask for it](docs/REFERENCE.md#persistent-state-when-you-ask-for-it)
- <a id="native-computation"></a>[Native computation](docs/REFERENCE.md#native-computation)
- <a id="extended-command-examples"></a>[Extended command examples](docs/REFERENCE.md#extended-command-examples)
- <a id="run-a-hosted-o-program"></a>[Run a hosted O program](docs/REFERENCE.md#run-a-hosted-o-program)
- <a id="use-the-repl"></a>[Use the REPL](docs/REFERENCE.md#use-the-repl)
- <a id="use-the-local-notebook"></a>[Use the local notebook](docs/REFERENCE.md#use-the-local-notebook)
- <a id="compile-hosted-o"></a>[Compile hosted O](docs/REFERENCE.md#compile-hosted-o)
- <a id="compile-o-core"></a>[Compile O-core](docs/REFERENCE.md#compile-o-core)
- <a id="link-source-into-one-o-document"></a>[Link source into one O document](docs/REFERENCE.md#link-source-into-one-o-document)
- <a id="hosted-language-tour"></a>[Hosted language tour](docs/REFERENCE.md#hosted-language-tour)
- <a id="typed-expression-syntax"></a>[Typed expression syntax](docs/REFERENCE.md#typed-expression-syntax)
- <a id="aliases"></a>[Aliases](docs/REFERENCE.md#aliases)
- <a id="shebang-support"></a>[Shebang support](docs/REFERENCE.md#shebang-support)
- <a id="let-bindings-and-var-splicing"></a>[`let` bindings and `$var` splicing](docs/REFERENCE.md#let-bindings-and-var-splicing)
- <a id="python-result-rules"></a>[Python result rules](docs/REFERENCE.md#python-result-rules)
- <a id="o_o-sequencing"></a>[`O^(...)_O` sequencing](docs/REFERENCE.md#o_o-sequencing)
- <a id="environment-lifetime"></a>[Environment lifetime](docs/REFERENCE.md#environment-lifetime)
- <a id="lazy-and-deferred-blocks"></a>[Lazy and deferred blocks](docs/REFERENCE.md#lazy-and-deferred-blocks)
- <a id="backend-authority-is-ambient-by-default"></a>[Backend authority is ambient by default](docs/REFERENCE.md#backend-authority-is-ambient-by-default)
- <a id="quote-and-oeval"></a>[`quote^` and `O.eval`](docs/REFERENCE.md#quote-and-oeval)
- <a id="the-nix-lattice"></a>[The Nix lattice](docs/REFERENCE.md#the-nix-lattice)
- <a id="autonomous-scheduling"></a>[Autonomous scheduling](docs/REFERENCE.md#autonomous-scheduling)
- <a id="coordination-groups"></a>[Coordination groups](docs/REFERENCE.md#coordination-groups)
- <a id="builtin-call-reference"></a>[Builtin call reference](docs/REFERENCE.md#builtin-call-reference)
- <a id="ovalue-and-the-runtime-boundary"></a>[OValue and the runtime boundary](docs/REFERENCE.md#ovalue-and-the-runtime-boundary)
- <a id="ovalue-and-the-tcf-terminal-object"></a>[OValue and the TCF terminal object](docs/REFERENCE.md#ovalue-and-the-tcf-terminal-object)
- <a id="hosted-backends"></a>[Hosted backends](docs/REFERENCE.md#hosted-backends)
- <a id="compiler-and-composition-tools"></a>[Compiler and composition tools](docs/REFERENCE.md#compiler-and-composition-tools)
- <a id="o-interpreter-and-repl"></a>[`O`: interpreter and REPL](docs/REFERENCE.md#o-interpreter-and-repl)
- <a id="olangc-hosted-aot-wasi-script-oir-and-dot-graph"></a>[`olangc`: hosted AOT, WASI, script, OIR, and DOT graph](docs/REFERENCE.md#olangc-hosted-aot-wasi-script-oir-and-dot-graph)
- <a id="browser-wasi-payloads"></a>[Browser WASI payloads](docs/REFERENCE.md#browser-wasi-payloads)
- <a id="browser-linux-in-wasi-payloads"></a>[Browser Linux-in-WASI payloads](docs/REFERENCE.md#browser-linux-in-wasi-payloads)
- <a id="browser-only-interactive-guix"></a>[Browser-only interactive Guix](docs/REFERENCE.md#browser-only-interactive-guix)
- <a id="public-output-forms"></a>[Public output forms](docs/REFERENCE.md#public-output-forms)
- <a id="o-link-isolated-literal-execution-explicit-parallelism-and-safe-projects"></a>[`o-link`: isolated literal execution, explicit parallelism, and safe projects](docs/REFERENCE.md#o-link-isolated-literal-execution-explicit-parallelism-and-safe-projects)
- <a id="o-unlink-restore-either-representation"></a>[`o-unlink`: restore either representation](docs/REFERENCE.md#o-unlink-restore-either-representation)
- <a id="o-notebook-local-interactive-documents"></a>[`o-notebook`: local interactive documents](docs/REFERENCE.md#o-notebook-local-interactive-documents)
- <a id="architecture"></a>[Architecture](docs/REFERENCE.md#architecture)
- <a id="repository-layout"></a>[Repository layout](docs/REFERENCE.md#repository-layout)
- <a id="hosted-evaluation"></a>[Hosted evaluation](docs/REFERENCE.md#hosted-evaluation)
- <a id="oir-and-executionplan"></a>[OIR and ExecutionPlan](docs/REFERENCE.md#oir-and-executionplan)
- <a id="o-core-native-systems-language"></a>[O-core native systems language](docs/REFERENCE.md#o-core-native-systems-language)
- <a id="modules-items-and-control-flow"></a>[Modules, items, and control flow](docs/REFERENCE.md#modules-items-and-control-flow)
- <a id="static-types-and-aggregates"></a>[Static types and aggregates](docs/REFERENCE.md#static-types-and-aggregates)
- <a id="layout-and-abi"></a>[Layout and ABI](docs/REFERENCE.md#layout-and-abi)
- <a id="explicit-unsafe"></a>[Explicit unsafe](docs/REFERENCE.md#explicit-unsafe)
- <a id="volatile-and-atomic-operations"></a>[Volatile and atomic operations](docs/REFERENCE.md#volatile-and-atomic-operations)
- <a id="hardware-intrinsics-and-assembly"></a>[Hardware intrinsics and assembly](docs/REFERENCE.md#hardware-intrinsics-and-assembly)
- <a id="linkage-and-sections"></a>[Linkage and sections](docs/REFERENCE.md#linkage-and-sections)
- <a id="compiler-pipeline"></a>[Compiler pipeline](docs/REFERENCE.md#compiler-pipeline)
- <a id="freestanding-kernel-proof"></a>[Freestanding kernel proof](docs/REFERENCE.md#freestanding-kernel-proof)
- <a id="capabilities-and-syscall-abi"></a>[Capabilities and syscall ABI](docs/REFERENCE.md#capabilities-and-syscall-abi)
- <a id="the-freestanding-boundary"></a>[The freestanding boundary](docs/REFERENCE.md#the-freestanding-boundary)
- <a id="included-examples"></a>[Included examples](docs/REFERENCE.md#included-examples)
- <a id="running-the-tests"></a>[Running the tests](docs/REFERENCE.md#running-the-tests)
- <a id="status"></a>[Status](docs/REFERENCE.md#status)
- <a id="validation-at-the-historical-audited-master"></a>[Validation at the historical audited master](docs/REFERENCE.md#validation-at-the-historical-audited-master)
- <a id="implemented"></a>[Implemented](docs/REFERENCE.md#implemented)
- <a id="exact-implementation-boundaries"></a>[Exact implementation boundaries](docs/REFERENCE.md#exact-implementation-boundaries)
- <a id="license"></a>[License](docs/REFERENCE.md#license)
- <a id="citation-and-authorship"></a>[Citation and authorship](docs/REFERENCE.md#citation-and-authorship)
- <a id="related-preprints"></a>[Related preprints](docs/REFERENCE.md#related-preprints)
- [How to cite](docs/REFERENCE.md#how-to-cite) (the current section above preserves this anchor)
- <a id="archival-releases-and-doi"></a>[Archival releases and DOI](docs/REFERENCE.md#archival-releases-and-doi)
- <a id="core-contribution"></a>[Core contribution](docs/REFERENCE.md#core-contribution)
</details>


<details>
<summary>Required native release gate inventory</summary>

This is a generated inventory of required checks, not a report that they passed
for the current commit. Use source-bound completed results for qualification.

<!-- BEGIN GENERATED: REQUIRED_QEMU_EVIDENCE -->
The 26 required portable QEMU release gates and 1
supplemental hardware-dependent gate are defined once in
[`evidence/gates.toml`](evidence/gates.toml). The aggregate reads that manifest
at runtime, selects only `required = true`, streams each gate's output, and
requires every declared marker exactly once in that live transcript. This table
is a checked projection.

| Gate | Required | Milestone | Evidence | Establishes | Explicit non-claims |
|------|----------|-----------|----------|-------------|---------------------|
| `ocore-bootstrap` | yes | M0.1-M0.3 | [ocore/kernel/smoke-qemu.sh](ocore/kernel/smoke-qemu.sh) (`portable_tcg`) | CPL3 entry, SYSCALL return, IRQ0 return, and a later heartbeat execute in QEMU<br>W^X pages, frame reclamation, typed memory objects, and capability denials pass the bounded bootstrap corpus | This one-process bootstrap is not multi-process isolation, IPC, or a foreign ABI<br>It is not evidence of Linux, Plan 9, or a foreign-kernel boot |
| `ostadix-x86_64-boot-info` | yes | OSTADIX Alpha x86_64 BootInfo / Mode 33 | [ocore/kernel/smoke-x86_64-boot-info-qemu.sh](ocore/kernel/smoke-x86_64-boot-info-qemu.sh) (`portable_tcg`) | A challenged x86_64 UEFI/Multiboot2 handoff is strictly normalized into bounded kernel-owned BootInfo facts and causally selects one page-aligned allocator subwindow from the firmware memory map<br>The temporary firmware inspection aperture is closed before the W^X check, and the same challenged mode-0 image reaches CPL3 entry, timer return, and a later heartbeat<br>The transcript grammar accepts the exact challenge and source commit in causal order and rejects a wrong challenge | This QEMU TCG and OVMF gate is not physical-machine, KVM, Secure Boot, measured-boot, or hardware-trust evidence<br>The bounded Multiboot2 parser and ACPI status validation are not a general ACPI consumer, initrd loader, firmware service, or general physical-memory allocator<br>It provides no SMP, PCI/device assignment, DMA isolation, IOMMU isolation, interrupt remapping, or hardware-reset evidence |
| `ostadix-x86_64-smp4` | yes | OSTADIX Alpha x86_64 bounded SMP / Mode 34 | [ocore/kernel/smoke-x86_64-smp-qemu.sh](ocore/kernel/smoke-x86_64-smp-qemu.sh) (`portable_tcg`) | One challenged QEMU q35/TCG and OVMF boot admits an exact four-CPU ACPI/MADT topology, validates PIT progress before x2APIC INIT/SIPI, and brings three APs into kernel RX text on distinct stacks<br>The low trampoline follows an RW/NX copy, R/X execution, erased-and-unmapped retirement sequence without a writable-and-executable mapping<br>Four unique APIC identities cross one atomic BSP/AP release-and-progress barrier and reach a later PIT transition and heartbeat; the same image under one vCPU rejects before startup success markers | This is exactly a four-vCPU QEMU TCG and OVMF proof using bounded type-0 8-bit APIC identities; it is not physical-machine, KVM, or arbitrary-topology evidence<br>APs park after one barrier; this is not a general SMP scheduler, IPI service, interrupt balancer, per-CPU allocator, concurrent syscall path, or SMP-safe version of every existing O-core subsystem<br>It provides no Secure Boot, measured boot, PCI/device assignment, DMA isolation, IOMMU isolation, interrupt remapping, or hardware-reset evidence |
| `world-g2-aarch64-native` | yes | World G2 / AArch64 native compiler | [ocore/kernel/smoke-aarch64-g2-qemu.sh](ocore/kernel/smoke-aarch64-g2-qemu.sh) (`qemu_tcg_aarch64`) | One O-core kernel compiled for AArch64 retains EL2, enters host EL1, completes one domain-separated HVC return with register and stack integrity, and in one live QEMU TCG run executes native EL0 process, IPC, capability, lifecycle, stale-generation, reclamation, and bounded post-lifecycle counter-progress checks | This single-vCPU QEMU TCG gate is not physical AArch64, KVM/SVM, SMP, or G3 evidence<br>It does not boot Linux or Plan 9 and does not establish a general foreign ABI<br>It provides no PCI or physical-device assignment, DMA isolation, or IOMMU/SMMU evidence |
| `world-identity-v1` | yes | World identity PR2 / Mode 27 | [ocore/kernel/smoke-world-identity-qemu.sh](ocore/kernel/smoke-world-identity-qemu.sh) (`portable_tcg`) | All 20 constitutional World identity atoms have shared typed Rust and O-core definitions with strict nonzero generation, version, term, and index rules<br>A bounded OWIDENT v1 identity-only corpus converges byte-for-byte between the Rust oracle and native O-core under QEMU; strict decode rejects malformed or zero-valued records, and hierarchical current/reference comparison rejects stale generations and same-generation logical mismatches | Serialized capability IDs are descriptive non-authority; this gate creates no bearer, CSpace handle, delegation, or authenticated authority<br>OWIDENT v1 remains the identity-only nested format and does not itself provide OWPROTO framing, transport, schema negotiation, an OValue envelope, a receipt codec, a Governor, or consensus<br>This repository-conformance slice does not pass G0 or any G0-G13 gate, and QEMU TCG is not physical or hardware-isolation evidence |
| `world-protocol-v1` | yes | World protocol PR3 / Mode 28 | [ocore/kernel/smoke-world-protocol-qemu.sh](ocore/kernel/smoke-world-protocol-qemu.sh) (`portable_tcg`) | The architecture-independent OWPROTO v1 record codec uses deterministic big-endian framing, four fixed record kinds, a 16 KiB hard maximum, caller/negotiated record bounds, and strict exact-length, reserved-field, kind, schema, and nested-identity validation<br>A fixed 20-record, 1254-byte corpus containing two offers, one canonical v1 selection, one disjoint rejection, and all 16 OWIDENT v1 conformance records converges byte-for-byte between the Rust oracle and native O-core under QEMU; version negotiation deterministically selects the highest common version and smaller record limit or an exact contextual rejection | OWPROTO v1 is a record codec with an offline bounded negotiation function, not a stream or network transport, live peer handshake, authenticated session, encryption, replay protection, membership protocol, or multiplexing layer<br>Identity and capability descriptions remain inert metadata; decoding or negotiating a record grants no bearer, CSpace handle, delegation, authenticated authority, or ambient process identity<br>This PR3 slice does not implement PR4 OValue or extension envelopes, PR5 receipts, a Governor, consensus, WorldFS, or Workstream A acceptance, and it passes no G0-G13 gate; QEMU TCG is not physical or hardware-isolation evidence |
| `world-value-v1` | yes | World OValue PR4 / Mode 29 | [ocore/kernel/smoke-world-value-qemu.sh](ocore/kernel/smoke-world-value-qemu.sh) (`portable_tcg`) | The separate self-framed OWVALUE v1 format freezes an explicit portable allowlist with a 4096-byte record maximum, depth-16 and 128-node limits, deterministic architecture-independent framing, strictly ordered records and scalar-key maps, and a root-only inert versioned extension envelope whose payload must itself be portable<br>The fixed 19-record, 928-byte corpus (1856 lowercase hex digits; concatenated-corpus SHA-256 264e00550bbbe7561412d9a43f89036667ffbcf27add522131f8e650abef19bc) converges byte-for-byte between the Rust oracle and native O-core under QEMU, with matching SHA-256 over each complete record; canonical encode/decode/reencode is stable, strict decoding rejects malformed or noncanonical values, and hosted projection rejects authority-bearing, capsule, and effectful values | OWVALUE v1 is inert portable data and admits no capability bearer, CSpace handle, delegation or session token, native capsule, live process, system, or device reference, executable request, or ambient identity; code and object references remain descriptive only<br>Versioned extension envelopes do not auto-dispatch code, load schemas, rehydrate capsules, resolve authority, or authenticate peers<br>Mode 29 is an offline codec and hash oracle, not a transport, live M9 crossing, PR5 receipt or signature implementation, execution or grounding convergence result, Governor, consensus, WorldFS, or Workstream A acceptance; it passes no G0-G13 gate, and QEMU TCG is not physical or hardware-isolation evidence<br>This gate does not make the full hosted crates/ostadix-api/src/value.rs OValue enum portable or replace the hosted canonical-CBOR shim wire format |
| `world-receipt-v1` | yes | World receipt PR5 / Mode 30 | [ocore/kernel/smoke-world-receipt-qemu.sh](ocore/kernel/smoke-world-receipt-qemu.sh) (`portable_tcg`) | The separate self-framed OWRECEIPT v1 format deterministically binds one bounded canonical execution receipt to exact World identities and generations, SHA-256 content references, descriptive capability rights, terminal and commit fields, evidence-gate identity, and an algorithm-tagged signature envelope<br>The fixed two-record, 3239-byte conformance corpus (6478 lowercase hex digits; concatenated-corpus SHA-256 1edd90bf881cd42d08e2031482baae4e7c9a95bd78cfa65f0cbe14147c0a2604) converges byte-for-byte between the Rust oracle and native O-core under QEMU, including its 1575-byte current and 1546-byte stale canonical signing preimages; hosted Ed25519 signs and verifies the exact domain-separated preimage and rejects tampering or a wrong key, while native O-core strictly validates the bounded receipt and signature-envelope structure | OWRECEIPT v1 carries signed descriptive evidence; receipt capability identities and rights are not bearers, CSpace handles, delegation certificates, session tokens, or grants of authority, and signature validity does not establish authorization or current World state<br>The pinned conformance key is public test material; this slice provides no production key generation, secure storage, hardware binding, enrollment, certificate chain, rotation, revocation, recovery, peer authentication, or trusted-signer policy<br>Mode 30 proves canonical receipt bytes and signing-preimage convergence under QEMU plus hosted Ed25519 sign/verify; native O-core structurally validates the signature envelope but does not implement or prove a general freestanding Ed25519 verifier<br>The Mode 30 corpus is constructed offline and does not itself prove live emission; the separate World-project hosted-reference path emits a caller-signed uncommitted OWRECEIPT and Mode 32 consumes it for bounded canonical/semantic comparison, while live-system, KernelWorld, object, capability, and evidence components remain outside that path and the existing O-Git semantic receipt remains a separate unsigned JSON demo<br>Local generation and commit-field checks are not an authoritative Governor snapshot, replay or commit-fencing service, transport, consensus, WorldFS, or Workstream A acceptance<br>This gate is not the typed OSTADIX Alpha attestation schema, does not admit evidence into evidence/world_alpha_gates.toml, passes no G0-G13 gate, and QEMU TCG is not physical, hardware-virtualization, or hardware-isolation evidence<br>OWRECEIPT remains separate from frozen four-kind OWPROTO v1 and OWVALUE v1 and does not change the hosted canonical-CBOR shim wire format |
| `world-project-runtime-mode32` | yes | World project runtime / Mode 32 | [ocore/kernel/smoke-world-project-runtime-qemu.sh](ocore/kernel/smoke-world-project-runtime-qemu.sh) (`portable_tcg`) | One focused hosted test enters the coordinator through an exact caller-supplied current-view World launch before workspace or child creation, observes a terminal RuntimeGraph, and emits a caller-signed OWRECEIPT with an unconditional Uncommitted fence<br>Native Mode 32 fully decodes and exactly re-encodes that live generated receipt, reconstructs its validated signing preimage, independently matches the signer-independent semantic SHA-256, rejects a malformed envelope, clears reused success-only validation tags, and reaches a later timer | The launch/current view and coordinator observer are caller-supplied descriptive identities, not authenticated Governor membership, admission, authority, reservation, provider placement, dispatch, recovery, or commit<br>Mode 32 compares canonical receipt structure and semantic content only; it neither executes the project natively nor verifies Ed25519 in freestanding O-core<br>The hosted execution retains residual HostWorld effects and provides no exactly-once guarantee, remote execution, physical-hardware evidence, G1 passage, Workstream A acceptance, or passage of any G0-G13 gate |
| `m02-fault-recovery` | yes | M0.2 | [ocore/kernel/smoke-faults-qemu.sh](ocore/kernel/smoke-faults-qemu.sh) (`portable_tcg`) | Eight fresh boots contain the bounded fatal CPL3 fault corpus<br>A ninth boot recovers a bounded user-copy fault and reaches a later heartbeat | The one-process fault corpus is not the current kernel ceiling<br>It does not establish arbitrary fault recovery or multi-process scheduling |
| `m1-process-isolation` | yes | M1 | [ocore/kernel/smoke-processes-qemu.sh](ocore/kernel/smoke-processes-qemu.sh) (`portable_tcg`) | Two bounded native processes use separate CR3s and same-VA physical isolation<br>Exit and fault teardown reject stale identities, reclaim frames, and preserve the sibling | The gate is single-CPU and does not establish SMP isolation<br>It is not a general scheduler, IPC, or foreign-process proof |
| `m2-scheduler` | yes | M2 | [ocore/kernel/smoke-scheduler-qemu.sh](ocore/kernel/smoke-scheduler-qemu.sh) (`portable_tcg`) | Four TCBs across two processes exercise bounded single-CPU yield, sleep, wake-once, and timer preemption<br>One million forced identity transactions and lifecycle reclamation pass | The gate does not establish SMP safety or an unbounded production scheduler<br>The million-transaction phase does not itself enter CPL3 |
| `m3-ipc-foundation` | yes | M3 foundation | [ocore/kernel/smoke-ipc-foundation-qemu.sh](ocore/kernel/smoke-ipc-foundation-qemu.sh) (`portable_tcg`) | Kernel-side shared mapping, bounded FIFO/cancel, waiter cleanup, endpoint generation, and attenuating-transfer mechanisms pass<br>The bounded foundation reclaims its resources and reaches a later timer | This foundation gate is not the public CPL3 IPC gate<br>It does not establish a general foreign personality or distributed IPC |
| `m3-public-ipc` | yes | M3 | [ocore/kernel/smoke-ipc-qemu.sh](ocore/kernel/smoke-ipc-qemu.sh) (`portable_tcg`) | Four CPL3 processes exercise public endpoint calls, bounded blocking, request/reply, and exact attenuated capability transfer<br>Personality failure is contained while an unrelated world survives and all bounded resources are reclaimed | The fixed-capacity single-CPU gate is not unbounded or SMP IPC<br>It does not implement a Linux or other foreign ABI |
| `m4-native-loader` | yes | M4 | [ocore/kernel/smoke-loader-qemu.sh](ocore/kernel/smoke-loader-qemu.sh) (`portable_tcg`) | A deterministic OVFS image imports two separately linked native ELF personalities as data<br>Malformed and W+X corpus entries are rejected before isolated loads, service lookup, teardown, and frame reclamation | The bounded read-only OVFS is not a general filesystem or dynamic linker<br>The native test personalities are not Linux, Plan 9, or another foreign OS |
| `m5-native-live` | yes | M5 | [ocore/kernel/smoke-live-qemu.sh](ocore/kernel/smoke-live-qemu.sh) (`portable_tcg`) | Four packaged native ELFs are hash-verified, loaded into isolated CSpaces, and health-gated before publication<br>A package-daemon fault withdraws generation 1, preserves unrelated services, and republishes a healthy generation 2 before reclamation | The bounded control plane is not a general package manager or unbounded retry policy<br>It does not boot or supervise a foreign operating system |
| `m5-supervisor-semantics` | yes | M5 semantics | [ocore/kernel/smoke-live-semantics-qemu.sh](ocore/kernel/smoke-live-semantics-qemu.sh) (`portable_tcg`) | The bounded native state corpus covers immutable roots, overgrant denial, failed-health nonpublication, rollback, stale references, and strict parsing<br>Crash and restart preserve explicitly unrelated state and reach a post-test tick | The self-test corpus is not the separate interactive M5 service-process gate<br>It does not establish a general backoff, durability, or foreign-service policy |
| `m6a-scalar-personality` | yes | M6A | [ocore/kernel/smoke-personality-qemu.sh](ocore/kernel/smoke-personality-qemu.sh) (`portable_tcg`) | Four packaged CPL3 ELFs exercise health-gated scalar personality RPC, deterministic terminal arbitration, and one supervised restart<br>Generation-1 authority stays stale after generation-2 rebind while an unrelated observer survives and resources return to baseline | Pointer-bearing calls and request-scoped foreign memory views are disabled<br>The native test personality is not a Linux or other foreign operating-system ABI |
| `m6b-bounded-copy` | yes | M6B mechanism | [ocore/kernel/smoke-m6b-qemu.sh](ocore/kernel/smoke-m6b-qemu.sh) (`portable_tcg`) | Generation-tagged bounded-copy request views enforce snapshot input, written-prefix output, typed rights, quotas, and revoke-before-terminal ordering<br>Five delegated lease classes support transactional create-bind rollback and request-wide revocation while unrelated scope survives | The mechanism is not integrated with the live M6A CPL3 RPC path<br>It does not establish pinned windows, streaming, signals, a Linux oracle, or concrete delegated services |
| `m6b-live-bounded-personality` | yes | M6B Mode 24 live | [ocore/kernel/smoke-live-bounded-personality-qemu.sh](ocore/kernel/smoke-live-bounded-personality-qemu.sh) (`portable_tcg`) | Four digest-pinned CPL3 ELFs exercise one-shot four-byte INOUT bounded personality RPC across health-gated publication, one contained daemon fault, and a generation-2 rebind<br>The live terminal corpus covers cancellation, timeout, service death, and supervisor-triggered pre-terminal unmap, request-revoke, delegated-resource-revoke, and caller-exit dispositions with stale and duplicate denial plus bounded cleanup | Mode 24 is a native test personality, not a Linux or Plan 9 boot, general foreign ABI, or general guest-agent path<br>The generation-2 lifecycle operations are supervisor-triggered pre-terminal dispositions; the gate does not mutate a mapping, observe an external resource event, or cover the post-reply/pre-consume process-exit or unmap race<br>The delegated device resource is one internal typed lease; this is not KVM, PCI or physical-device assignment, DMA, IOMMU, interrupt-remapping, or physical-device evidence |
| `m6-linux-minimal-live` | yes | M6 Linux Mode 25 live | [ocore/kernel/smoke-live-linux-personality-qemu.sh](ocore/kernel/smoke-live-linux-personality-qemu.sh) (`portable_tcg`) | One exact digest-pinned static Linux x86-64 ELF and three native service principals load from immutable OVFS data into isolated CPL3 address spaces<br>Bounded fd 1/fd 2 writes, exact -ENOSYS, and exit_group(42) survive one contained daemon fault, health-gated generation-2 replacement, stale generation-1 denial, and complete authority/resource reclamation<br>Seven Linux-adapter and four bounded-bridge injected preparation failures leave the same request waiting with observable accounting unchanged before one successful retry; after reply publication, commitment is deterministic no-fail or fail-stop | The pinned four-call success path, with a fifth failure-only exit site, is not Linux or Plan 9 boot, a distribution, root filesystem, dynamic linker, general foreign ABI, or arbitrary Linux binary compatibility<br>QEMU TCG CPL3 execution is not KVM/SVM or physical-hardware evidence<br>The gate has no PCI or physical-device assignment, DMA mapping/isolation, IOMMU isolation, interrupt remapping, or hardware reset |
| `m7-linux-plan9-9p2000-live` | yes | M7 Linux/Plan 9 Mode 26 live | [ocore/kernel/smoke-live-linux-plan9-qemu.sh](ocore/kernel/smoke-live-linux-plan9-qemu.sh) (`portable_tcg`) | One exact digest-pinned static Linux x86-64 ELF, an unprivileged native Linux 9P2000 server, a native supervisor, and a Plan-9-style native 9P2000 client load from immutable OVFS data into four isolated CPL3 address spaces<br>The Linux ELF's bounded stdout/stderr results are read through exact 9P2000 version, attach, walk, open, read, and clunk exchanges at /srv/linux/status across namespace withdrawal, one contained server fault, generation-2 replacement, stale generation-1 denial, and complete resource reclamation | Mode 26 executes the same bounded Linux-ABI ELF and a native O-core Plan-9-style client; it does not boot Linux or Plan 9, run a Plan 9 binary, provide a distribution, root filesystem, or dynamic linker, or establish a general foreign ABI<br>The exact 128-byte 9P2000 corpus exposes only the generation-bound /srv/linux/status path; it is not a general 9P server, Plan 9 namespace or mount environment, network transport, persistent filesystem, or guest-agent framework<br>Generation 2 is the same server implementation serving a later, different snapshot after generation 1 completed; this is not two-provider routing for one immutable object, requester-local fallback, fresh provider-B session/fid reconstruction, causal multi-attempt tracing, or live OWRECEIPT emission<br>QEMU TCG CPL3 execution is not KVM/SVM or physical-hardware evidence<br>The gate has no PCI or physical-device assignment, DMA mapping or isolation, IOMMU isolation, interrupt remapping, or hardware reset |
| `m7b-logical-read-fallback-live` | yes | M7B-1 native LogicalRead Mode 31 | [ocore/kernel/smoke-m7b-logical-read-qemu.sh](ocore/kernel/smoke-m7b-logical-read-qemu.sh) (`portable_tcg`) | One deterministic provider ELF is instantiated as two generation-distinct isolated CPL3 provider principals; distinct A/B service bindings, endpoints, and client call capabilities are admitted before one requester-local LogicalRead for an exact immutable 20-byte object<br>Provider A returns a valid terminal 9P Rerror, faults, and has its local route and call authority withdrawn; the client proves A stale before staged provider-B activation, then completes a fresh B-local version/attach/walk/open/read/clunk sequence with different fids, verifies the pinned SHA-256, and reaches separate cleanup, full reclamation, witness-survival, and post-timer evidence | This is the bounded M7B-1 local mechanism, not complete M7B: requester and router are one principal, both providers instantiate one implementation artifact, and the route set is fixed local configuration rather than a general route registry<br>The kernel causal state and serial transcript are non-persisted unsigned diagnostics, not a live OWRECEIPT, attestation, Governor commitment, lease protocol, or distributed consensus evidence<br>The exact read-only 9P2000 corpus is not general 9P, WorldFS, a writable filesystem, fid migration, exactly-once effects, network transport, persistence, Linux or Plan 9 boot, or a foreign KernelWorld<br>Forced QEMU TCG CPL3 execution is not KVM/SVM, physical-hardware, G7/G8, PCI/device assignment, DMA/IOMMU isolation, interrupt-remapping, or hardware-reset evidence |
| `kernel-world-mode20-objects` | yes | KernelWorld Mode 20 | [ocore/kernel/smoke-kernel-world-qemu.sh](ocore/kernel/smoke-kernel-world-qemu.sh) (`portable_tcg`) | The exact hash-pinned V2 record is parsed under default-deny package, manifest, request, export, and typed-rights binding<br>Generation-bound nonexecuting VM, vCPU, and guest-page objects enforce quota, stale denial, exact-world reclaim, and unrelated-VM survival | Mode 20 does not enter a guest, execute firmware, or publish a provider export<br>It does not establish device assignment, DMA mapping, or IOMMU isolation |
| `kernel-world-mode21-svm-kvm` | no | KernelWorld Mode 21 | [ocore/kernel/smoke-kernel-world-execution-qemu.sh](ocore/kernel/smoke-kernel-world-execution-qemu.sh) (`hardware_kvm`) | On an AMD host with nested SVM/NPT and writable /dev/kvm, KVM enters a bounded synthetic guest and observes controlled hypercall and interrupt exits<br>An unmapped guest-physical access fails closed before exact NPT teardown, vCPU restart, and unrelated-VM survival | Mode 21 is supplemental hardware-dependent evidence and is not part of the portable release aggregate<br>It does not boot Linux, Plan 9, firmware, or a supplied image<br>It has no provider lifecycle, guest agent, service export, virtual device, PCI assignment, DMA mapping, or IOMMU-isolation proof |
| `kernel-world-mode22-live` | yes | KernelWorld Mode 22 | [ocore/kernel/smoke-kernel-world-live-qemu.sh](ocore/kernel/smoke-kernel-world-live-qemu.sh) (`portable_tcg`) | The TCG-compatible native administrative gate health-publishes exact typed exports and dispatches bounded reset intent<br>Failure withdraws clients before exact VM-graph revoke; policy restarts generation 2 while unrelated service survives and generation 1 stays stale | Mode 22 does not enter a guest or enforce the manifest health timeout<br>It has no Linux or Plan 9 boot, guest agent, shared queue, device assignment, DMA/IOMMU isolation, or hardware reset |
| `kernel-world-mode23-execution-device` | yes | KernelWorld Mode 23 | [ocore/kernel/smoke-kernel-world-execution-device-qemu.sh](ocore/kernel/smoke-kernel-world-execution-device-qemu.sh) (`portable_tcg`) | QEMU TCG emulates SVM/NPT guest entry, VMMCALL-derived health, one validated virtual PIO request/reply, and an NPF VMEXIT<br>Quiesce releases execution pins before endpoint and supervisor teardown; generation 2 rebinds while stale generation 1 and cross-world authority fail closed | Mode 23 does not boot Linux, Plan 9, firmware, or a supplied user image<br>It is not KVM, physical-hardware, PCI assignment, DMA/IOMMU, interrupt-remapping, or hardware-reset evidence<br>It has no general guest agent, shared queue or ring, asynchronous guarantee, or SMP guarantee |

Validate the schema, scripts, runtime transcript checks, projections, CI wiring,
claim-guard wiring, and aggregate byte identity with:

```bash
python3 scripts/release_evidence.py validate
./boot-and-test.sh smoke
```
<!-- END GENERATED: REQUIRED_QEMU_EVIDENCE -->

</details>
