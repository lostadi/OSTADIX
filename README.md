# OSTADIX

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
