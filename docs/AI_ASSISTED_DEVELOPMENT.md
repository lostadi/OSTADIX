# AI-assisted development and responsibility

OSTADIX development uses substantial AI assistance, including coding agents and coordinated parallel work. Agents generate and revise implementation code, tests, documentation and analysis; they also inspect source and run tools within delegated scopes. This assistance is part of the development process and should be disclosed when describing how an artifact was produced.

Lee Daghlar Ostadi is the project maintainer. A maintainer byline is not a statement that Lee manually typed every line or personally derived, understood, reviewed or empirically defended every generated result. Record [development credit](COMMIT_AUTHORS.md) and validation evidence for the work performed.

A development tool's involvement is provenance, and factual provenance may be recorded without automatically assigning it human authorship. Conversely, a maintainer identity does not erase another human contributor's work or establish that an assistant's output has been independently checked. Attribute actual human contributions accurately and retain truthful tool/agent assistance when relevant, under the [contribution policy](../CONTRIBUTING.md).

Review and validation must be stated per artifact. Distinguish a suggested patch from an integrated change, a source review from a passed test, a test harness from an executed experiment, and a component result from a system claim. Retain commands, source/tool identities, prerequisites, failures and raw results. An AI-generated explanation, a plausible theorem statement, or an optimistic agent summary is not a substitute for those records.

For research communication, label proposed arguments, completed mathematical proofs, implementation assumptions and empirical observations separately. The [focused boundary note](research/fidelity-boundaries.md) and [current public contract](CURRENT_CONTRACT.md) follow that rule: the fidelity algebra has a stated proof domain; a conditional confinement argument depends on explicit renderer/grammar assumptions; neither establishes all backend semantics or a complete native operating system.

The project makes no blanket claim here that every historical line has received human review or that all current acceptance gates pass. Corrections should preserve the prior evidence and explain the narrower result supported by the current source and validation.

## Native compiler source integration

The configured-assembly source-unit route and producer/action-order integration
were developed with OpenAI Codex and reviewed by a separate Codex source-review
agent. This records tool assistance, not a human source-review sign-off.
Validation distinguishes source review, authored tests, actual fixture/compiler
runs and complete original-runtime/ISA acceptance. See
[configured assembly source units](CONFIGURED_ASSEMBLY_SOURCE_UNITS.md).

## Technical whitepaper revision, 17 November 2026

The technical whitepaper was revised with OpenAI Codex, using separate agents
for hosted-contract and inventory review, native-compiler review, and editorial
review. Its prose was adapted to the maintainer's writing style. Private style
references are not part of the repository or publication.

The implementation basis is `c0b02c326b2329a95ba52447c7180bc93957cd57`.
The revision updates source contracts, examples, compiler profiles, mathematical
claim boundaries and dated evidence; it does not turn older experiments into
new native-system qualification. Fresh document checks and PDF build identities
are retained in [the revision record](../evidence/whitepaper_revision_20261117.json).
Agent review is source/editorial review, not a human sign-off or a rerun of the
complete hosted, compiler, runtime and hardware acceptance matrices.

## Setup with existing system packages, 17 November 2026

The `--no-system-packages` installer option was implemented with OpenAI Codex
and reviewed by a separate Codex agent. It skips OS package installation while
retaining capability checks and the selected builds. Validation covered 43
setup tests and 16 native-install tests (one platform skip); this is installer
validation, not qualification of every runtime or target.

## FDE association validation, 17 November 2026

The FDE relocation guard and configured-artifact module integration were
implemented with OpenAI Codex and reviewed by a separate Codex agent. Tests
exercise raw ELF fixtures, the typed CIE adapter, shared source-CFI evaluation,
artifact reconstruction and source registration. These checks do not establish
original-producer admission, native unwind execution or cross-ISA runtime
qualification. Commands and outcomes are recorded in the
[validation record](../evidence/fde-cie-relocation-20261117/validation.json).
