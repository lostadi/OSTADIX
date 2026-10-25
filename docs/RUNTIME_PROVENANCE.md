# Runtime identity and doctor

`o doctor --json`, MCP `o_env`, and MCP `o_doctor` distinguish the running
process from the source checkout and from separately selected tools. This is
useful when an editor, a source snapshot, an immutable MCP release, and another
architecture have different binaries despite sharing the package version.

The native CLI retains its `ostadix.installation-check/v1` result and adds
`provenance` with schema `ostadix.runtime-provenance/v1`. MCP tools retain their
human-readable text and add the same report as `structuredContent`.

The report includes:

- `binary`: current process path, exact SHA-256, byte length, detected executable
  architecture, running architecture and OS. Linux hashes `/proc/self/exe`, so
  replacing an installed file does not misidentify an older running process as
  the replacement. Other platforms hash the current executable path and label
  that scope explicitly.
- `buildSource`: source root, commit, dirty state, target, host and build profile
  retained by the shared build script. Unknown values remain null. A build from
  source without Git does not acquire a commit merely from an unverified
  manifest. Dirty state describes the build-script observation, rather than a
  later source checkout.
- `runtimeSource`: independently observed selected source root, Git commit and
  dirty state, including nonignored untracked files. A source snapshot inside
  another repository cannot inherit that parent repository's commit. Git
  metadata commands are local, use no optional locks or filesystem monitor, and
  each have a one-second timeout. An unavailable or oversized response remains
  explicitly unavailable or incomplete. Inherited `GIT_*` context overrides are
  cleared, and the selected root must contain its own `.git` marker. Source
  snapshot manifests are hashed and their allowlisted commit declarations are
  reported separately; they never become a fabricated observed Git commit or
  clean dirty state.
- `buildCommitMatchesRuntimeSource`: comparison only when both commits are
  known. Equality does not prove clean source, matching child binaries, or
  qualification.
- `backendRoot`, `tools` and `configuredPaths`: actual selected adapter root,
  hashes and architectures of selected executable files, and only the explicit
  source/backend path overrides. A selected executable entrypoint can launch
  other processes; its hash does not attest that entire runtime closure.
- `installationManifest` and `clientConfiguration`: paths, existence, sizes and
  exact hashes of recognized local configuration files. Configuration contents,
  argument arrays, credentials and arbitrary environment variables are never
  returned. File presence does not prove which editor configuration launched
  this process. The MCP report also identifies its own transport.

Installation and source manifests additionally expose allowlisted declared
source commits, installation profiles and bundle hashes. They are labeled as
declarations not re-verified by this diagnostic; no raw manifest contents or
arbitrary fields are returned. Bundle installation's full archive verification
is a separate operation from this read-only environment report.

Configuration hashing is limited to two MiB per regular file; executable
hashing is limited to one GiB per file. Special files, changing files and files
over those bounds are labeled rather than receiving a successful hash.

## Execution checks

MCP `o_env` and default `o_doctor {}` only inspect identity and inventory.
`executionCheck.status` is `not_requested`; installed files and runtime catalog
entries are not execution evidence. To request one bounded result explicitly:

```json
{"execution_check": true, "timeout_secs": 5}
```

Only the fixed Python expression `1 + 1` is accepted by this doctor probe. There
is no arbitrary source or command parameter. The deadline is one through ten
seconds, default five, with at most 64 KiB retained from each output stream.
Unix process groups are cleaned up on completion and timeout. Platforms without
that bounded implementation report an unavailable probe instead of launching
an unbounded child. MCP marks a requested failed or unavailable probe as a tool
error while retaining the structured identity report.

The native `o doctor` preserves its established behavior of running this Python
smoke, now with a five-second deadline and the same output bounds. It retains
the legacy `backends.python_smoke_passed` field and adds `executionCheck`.
Captured streams are represented by hashes, byte counts and truncation flags;
backend diagnostic contents and unexpected values are omitted from environment
reports. A successful result checks the typed numeric value `2`, not merely a
substring in stdout.

The runtime-only installation profile requires its evaluator and compilers;
other specialist tools are listed as optional rather than making the runtime
profile fail solely because those tools were intentionally omitted. Existing
unspecified installations retain their previous required-tool checks.

The probe is ordinary hosted Python execution. Its result is not evidence of
all runtime adapters, native O-core admission, hardware isolation, cross-ISA
equivalence, or complete foreign-runtime lowering. Preserve those independent
qualification receipts when comparing installations.
