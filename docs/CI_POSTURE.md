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
