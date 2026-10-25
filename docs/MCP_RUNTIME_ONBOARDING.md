# Runtime and MCP onboarding

Use `./setup.sh --runtime-only --verify` for the evaluator, native command front
door, orchestration compiler, O-core compiler, and MCP server. This profile avoids
building unrelated command-line programs and editor integrations. It preserves
the default and `--minimal` profiles; it does not install every optional hosted
runtime provider. Inspect the setup plan with `--dry-run` before installation.

The [native runtime bundle guide](NATIVE_RUNTIME_BUNDLES.md) describes building,
verifying, and installing a bundle with exact source and build manifests. Bundles
are platform-specific. A Linux ARM64 artifact is not a macOS ARM64 artifact, and
an x86-64 test does not qualify either ARM64 target. Target-native release jobs
must run successfully before publishing the resulting assets.

## Establish the running identity

Run `o doctor --json` and use the MCP `o_env` and `o_doctor` tools. Their structured
runtime provenance identifies the selected source root, observed commit and dirty
state, the current process's executable and hash, architecture, backend root,
resolved tools, and client configuration metadata. Compiled source provenance is
reported separately from the runtime checkout. An unavailable identity remains
unavailable instead of borrowing a nearby checkout's commit.

The [runtime identity reference](RUNTIME_PROVENANCE.md) defines the report fields,
hash limits, platform scope, and fixed execution check in detail.

MCP environment inspection does not execute a program. `o_doctor` accepts an
explicit bounded execution check. Inspect the selected server's tool schema for
the supported parameters. A successful probe establishes only that exact probe
on that process and host; runtime discovery does not qualify every backend or
remote machine. Configuration metadata omits file contents and secret values.

When comparing a Mac, Orange Pi, installed service, and source snapshot, compare
the executable hashes and both source identities before treating their results
as interchangeable. A registry name or package version alone cannot distinguish
these builds.

## Read watcher evidence

The [watcher resource contract](WATCHER_MCP_RESOURCES.md) defines four fixed MCP
resources:

- `ostadix://watcher/measurements`
- `ostadix://watcher/findings`
- `ostadix://watcher/actions`
- `ostadix://watcher/qualification`

An operator may configure a snapshot produced by their watcher. This checkout
does not contain a qualified watcher or collect measurements on resource reads.
Measurements, model interpretations, and proposed actions remain separate.
Qualification includes reviewed false alarms and missed incidents; absent labels
do not imply perfect detection. Resource presence and imported hashes establish
neither truth nor permission to execute a proposed action.
