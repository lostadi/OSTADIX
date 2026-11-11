# AI-assisted development and responsibility

OSTADIX development uses substantial AI assistance, including coding agents and coordinated parallel work. Agents generate and revise implementation code, tests, documentation and analysis; they also inspect source and run tools within delegated scopes. This assistance is part of the development process and should be disclosed when describing how an artifact was produced.

Lee Daghlar Ostadi is the maintainer and publication identity. The repository's declared Git author/committer and citation identity follow its [publication policy](COMMIT_AUTHORS.md). That metadata identifies responsibility for publishing the project; it is not a statement that Lee manually typed every line or personally derived, understood, reviewed or empirically defended every generated result. No such statement should be inferred from a byline or synthesized contribution history.

A development tool's involvement is provenance, and factual provenance may be recorded without automatically assigning it human authorship. Conversely, a maintainer identity does not erase another human contributor's work or establish that an assistant's output has been independently checked. Attribute actual human contributions accurately and retain truthful tool/agent assistance when relevant, under the [contribution policy](../CONTRIBUTING.md).

Review and validation must be stated per artifact. Distinguish a suggested patch from an integrated change, a source review from a passed test, a test harness from an executed experiment, and a component result from a system claim. Retain commands, source/tool identities, prerequisites, failures and raw results. An AI-generated explanation, a plausible theorem statement, or an optimistic agent summary is not a substitute for those records.

For research communication, label proposed arguments, completed mathematical proofs, implementation assumptions and empirical observations separately. The [focused boundary note](research/fidelity-boundaries.md) and [current public contract](CURRENT_CONTRACT.md) follow that rule: the fidelity algebra has a stated proof domain; a conditional confinement argument depends on explicit renderer/grammar assumptions; neither establishes all backend semantics or a complete native operating system.

The project makes no blanket claim here that every historical line has received human review or that all current acceptance gates pass. Corrections should preserve the prior evidence and explain the narrower result supported by the current source and validation.
