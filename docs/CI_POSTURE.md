# Local CI posture audit

`scripts/local_ci_posture.py` provides a deterministic, local-first audit of
the repository's CI and release posture. The baseline profile uses only the
Python standard library, does not build Ostadix, and is the posture check run by
the required `Contract surfaces` CI lane.

Run the same baseline locally with either human-readable or machine-readable
output:

```bash
python3 scripts/local_ci_posture.py --profile baseline --format text
python3 scripts/local_ci_posture.py --profile baseline --format json
```

The baseline checks:

- immutable full-SHA pins for external Actions, and SHA-256 image digests for
  any `docker://` action;
- high-risk workflow triggers, explicit permissions, and self-hosted or
  dynamically selected runners;
- exact agreement among `ci/required-jobs.toml`, `ci/test-suites.toml`, the
  `required-ci` aggregate, and its stable `Required CI` check name;
- Dependabot coverage for every checked-in Cargo root, Dockerfile directory,
  and GitHub Actions workflow;
- agreement among release metadata, the release-claim/package jobs, the
  contracts lane, and the required source-release surfaces.

### Required exact-LLVM scalar FP contract

The independent `ocore-constrained-fp` job on Ubuntu 24.04 is required by
`required-ci`; it runs outside the older optional installed-SDK block. A
missing download, tool, parser library, original source, compiler or test is a
failed required job. It does not turn the older optional SDK suites into
qualified executions.

`scripts/prepare_ci_llvm_profile.py` authenticates the complete official
`LLVM-22.1.6-Linux-X64.tar.xz`: 1,937,446,204 bytes, SHA-256
`c5ac8ef89ca39d30cb32e9b83772f995dd891c685ebc188d593c943a64d5f8b5`.
It streams only the exact members in `ci/llvm-22.1.6-linux-x64.json` into a
new prefix: six executable bodies, all 305 resource headers, the original
three aliases and archive license notice (653,779,274 regular-file bytes).
It never extracts the full SDK. Cold provisioning needs about 2.6 GB for the
compressed archive plus selected subset, with additional headroom for the
compiler build and test outputs. An existing extracted SDK or version string
alone does not establish archive membership. No global PATH, loader or tools
are replaced.

The supplied tools require an x86-64 Linux host, its ELF loader and declared
native DSOs. The job installs build-essential, make, Git, Python 3, xz,
libxml2 and zlib through the runner package manager. The provisioner captures
actual tool versions and resolved host DSO identities; these runner inputs
remain provided dependencies. The required LLVM C API parser is independently
pinned to the actual Rust 1.97.1 Linux x86-64 library (199,494,192 bytes,
SHA-256 `ed4f320c4e1ed6de7d2db6fd89faccf764d63186c2f877057ddf31065b1fac09`)
and checks `LLVMGetVersion` as 22.1.6. No SDK-library fallback is allowed.
Complete upstream license text is retained in `ci/llvm-22.1.6-LICENSE.TXT`;
original selected resource notices remain unchanged.

The job checks out clean original musl at
`0784374d561435f7c787a555aeab8ede699ed298`, builds `ocorec` from the CI source
commit with Rust 1.97.1 and the locked dependency graph, freezes its bytes,
and executes two required nine-test suites with that same compiler:
`tests.test_ocore_native_constrained_fmul` with
`OCORE_CONSTRAINED_FP_REQUIRED=1`, and
`tests.test_ocore_native_fp_register_barrier` with
`OCORE_FP_REGISTER_BARRIER_REQUIRED=1`. Each suite must independently discover
and execute all nine tests without skips, expected failures or compiler
mutation. Both result files and the combined `required-suites-result.json`
are retained; a failed suite cannot be offset by another suite passing.
The artifact is uploaded with
`always()` and includes setup/refusal records, actual tool/compiler/source
identities, configure/build commands, original LLVM IR, native modules,
objects and raw oracle outputs, even when a later stage fails. The artifact
contains supplied/generated executables and is not a public text-only bundle.

For a local run, use a new absent `--prefix` and `--output`, the exact archive
(or an absent archive path for a cold download), and the explicitly selected
Rust tool and parser:

```bash
python3 -B scripts/prepare_ci_llvm_profile.py \
  --archive /path/to/LLVM-22.1.6-Linux-X64.tar.xz \
  --prefix /new/llvm-subset --output /new/setup-evidence \
  --rustc /path/to/rust-1.97.1/bin/rustc \
  --parser-library /path/to/rust-1.97.1/lib/libLLVM.so.22.1-rust-1.97.1-stable
```

The setup's `environment.json` provides exact test tool/library inputs. Set
`OCOREC_BIN` and `OCOREC_BIN_SHA256` to the newly built, frozen compiler,
`OCORE_MUSL_SOURCE` to that clean musl checkout and
`OCORE_CONSTRAINED_FP_OUTPUT` and `OCORE_FP_REGISTER_BARRIER_OUTPUT` to separate
new evidence directories. Prefix the test
child PATH with the subset's `bin` for original configure/link tools. The
workflow contains the complete invocation and zero-skip result guard.

This is a bounded scalar dynamic-multiply/register-barrier source and
verification gate with actual x86-64 host execution. The new closed
`scalar_dynamic_mul_register_barrier_v1` profile admits the original AArch64
ordered scalar register barrier; CI checks its AArch64 object, while the
x86-64 reference uses the original header's volatile-memory path. CI does not
execute the AArch64 object or qualify an x86/RV realization of that new
operation. Long-double profiles, cross-ISA raw NaN identity, full musl
lowering, native kernel FP lifecycle and whole-system/driver/efficiency
acceptance remain unmet. Preserved exception bits under `fpexcept.ignore` are observations for
the pinned reference cases, not a universal exception-flag or trap guarantee.

### Native runtime release contract

The native bundle workflow retains the explicit source-bound reviews in
`ci/workflow-reviews.toml` for its finite hosted ARM64 matrix and release-asset
publisher. The baseline additionally recognizes their structural contract when the complete
workflow text matches the SHA-256 in `NATIVE_RUNTIME_CONTRACT` in
`scripts/local_ci_posture.py` and its structural checks also match:

- Linux AArch64 uses `ubuntu-24.04-arm`, and macOS AArch64 uses `macos-15`;
  arbitrary expressions, additional matrix entries and self-hosted runners do
  not match.
- The native job depends on `installer-contract`, and pull requests must come
  from the same repository. The publisher depends on the native job, including
  both matrix results, and runs only for `release` with action `published`.
- The workflow defaults to `contents: read`. Only the publisher receives
  `actions: read` and `contents: write`, for attaching already qualified release
  assets; it does not create releases or overwrite existing asset names.

The audit prints `baseline.workflows.native-runtime-contract` when this exact
contract matches. Recognition supplies evidence and never suppresses a generic
finding: the explicit review registry still must match each finding. This is
not a filename-wide exemption or a claim of general workflow security. Changes to inherited environment, defaults or steps also
invalidate the full-text binding and require renewed source review. Changing
the digest alone cannot widen the explicit runner, event, dependency or
permission constraints. Unknown or changed workflows retain the usual findings;
optional full-profile analyzers remain independent checks.

## Full local audit

The full profile first runs the baseline, then detects these optional tools on
`PATH`: `actionlint`, `zizmor`, `gitleaks`, `cargo-audit`, `cargo-deny`, and
`git-sizer`.

```bash
python3 scripts/local_ci_posture.py --profile full --format text
```

The script never installs a tool and never launches `cargo` in the live
checkout. It invokes the two Cargo ecosystem analyzers by their direct
`cargo-audit` and `cargo-deny` binaries, with fetching disabled, a temporary
`CARGO_TARGET_DIR`, and locked, offline inputs where supported. Because
`cargo-deny` can internally request Cargo metadata, it runs only against an
isolated temporary mirror that excludes `.git`, build outputs, caches, and
nested checkouts. `cargo-audit` disables advisory fetching and yanked-index
lookups, so it needs an already available local RustSec advisory database.
`cargo-deny` is not run until the repository has an explicitly reviewed
`deny.toml`; the script does not invent license, source, or dependency-ban
policy. Workflow and secret scanners use offline/redacted modes. A before/after
Git status guard detects visible repository mutations.

Missing full-profile tools, Git metadata, the local advisory database, or
required policy configuration make the audit incomplete rather than silently
skipped.

## Optional GitHub inspection

Add `--github` to either profile to inspect remote policy through authenticated
read-only `gh api --method GET` requests:

```bash
python3 scripts/local_ci_posture.py --profile baseline --format json --github
```

This checks that GitHub Actions defaults to read-only permissions without pull
request approval and that the default branch's effective rulesets or legacy
branch protection require pull requests plus the stable `Required CI` status.
Branch names are URL-encoded before inspection. It does not edit repository
settings, rulesets, branch protection, secrets, Actions, Dependabot, or pull
requests. Missing `gh` authentication or permission is reported explicitly.

## Exit and report contract

Both text and JSON contain all checks in deterministic ID/path/line order. JSON
uses schema `ostadix.local-ci-posture/v1`.

- exit `0`: every requested check passed;
- exit `1`: one or more posture findings were found (or an optional GitHub
  inspection was unavailable in the baseline profile);
- exit `2`: the full profile is incomplete because a required optional tool or
  configuration is missing.

This is a static and tool-backed posture audit, not proof that a workflow is
secure or that remote branch policy cannot change after inspection. It never
replaces the independent semantic, Hosted, release, Docker, MCP, or O-core
evidence lanes.

## Source and documentation drift checks

The complete tracked language-source audit is separate from the static CI
posture result. `scripts/check_language_sources.py validate` enforces exact
classification coverage and package-source mirror equality;
`check --o-bin PATH --ocorec PATH` parses every source with actual binaries.
Neither action runs the classified programs. Runtime behavior is checked by the
example manifest and native/benchmark harnesses named in `ci/language-sources.json`.

`python3 scripts/render_docs.py validate` checks the complete tracked export
inventory without Node. `python3 scripts/render_docs.py check` uses the version
of `marked` pinned in `docs/html-exports.json` and compares all generated bytes.
`write` regenerates exports after Markdown edits. These checks detect source or
export drift; they do not replace the semantic and environment-specific CI lanes.
