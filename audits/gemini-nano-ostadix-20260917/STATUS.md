# Gemini Nano target — 2026-09-17

## Current controlled model/tool cycle — 17:57–17:59 UTC

The [current implementation/live/unverified report](../gemini-nano-rebuild-20260917/STATUS.md)
now records a local factory-model program executed through the canonical primary
MCP `o_execute`, followed by the model consuming the actual returned result.
Python, Rust and Bash composed to produce **26 units**, **north 13 / south 13**,
with selected shipment IDs **2, 3, 8, 13**. Native execution took **802 ms**;
the later result-consumption model attempt took **40,869 ms including loading
and cleanup**. These are controlled host measurements, not assistant latency.

The sequence required four program-generation attempts: raw empty output,
a chat-framed program with `AttributeError`, repair 1 with `IndentationError`,
and repair 2 whose outer Markdown fence initially became the final O text value.
The host then removed only that fence; the program body was unchanged. See the
[complete source/result evidence](../gemini-nano-rebuild-20260917/nano-program-mcp-result.json),
[acceptance check](../gemini-nano-rebuild-20260917/nano-program-acceptance.json),
and [model result-consumption run](../gemini-nano-rebuild-20260917/canonical-nano-result.json).

This proves a controlled local model → tool → model cycle. The host submitted
the tool call and provided its returned result to the model. Autonomous function
invocation and an ordinary Pixel assistant caller remain unverified, as do the
exact public Nano release identity and availability of the public Prompt API.
The separately installed UID 10402 loopback host initially returned HTTP 200
with a native linker failure in the
[18:00 test](../gemini-nano-rebuild-20260917/nano-program-canonical-broker-result.json).
After a [loader fix verified only under `u:r:ksu:s0`](../gemini-nano-rebuild-20260917/appfunction-host-loader-diagnostic.json),
the restarted host PID **9901** passed the
[18:08 controlled HTTPS retest](../gemini-nano-rebuild-20260917/nano-program-canonical-broker-fixed-result.json):
HTTP 200, `isError: false`, completed execution, the same typed result 26 and
identical source/result identities, with **787 ms native execution**. The
[restart record](../gemini-nano-rebuild-20260917/canonical-mcp-host-install.json)
retains UID 10402 and the KernelSU SELinux context. No real AppFunction or
ordinary Gemini caller, other execution context, or boot persistence was
established by this retest.

The 17:35 arithmetic completion and the earlier blocked readiness observations
remain historical records. They have been superseded as evidence of what the
private native path can do, without changing the outcomes of those older tests.

## Earlier local reconstruction findings — historical checkpoint

The later [factory reconstruction audit](../gemini-nano-rebuild-20260917/FACTORY-FORMAT-RECOVERY.md)
disproves the earlier inference that usable factory metadata required a server
manifest. The installed local TrustyDecrypt service decoded the factory
manifest, config and checkpoint. All 191 available payload files now match the
manifest's byte sizes and SHA-1 values; one DVFS tuning file is absent. These
results do not change the public Prompt API observations recorded below.

The rebuilt Java JNI boundary reached the original native runtime. The first
actual local model load failed obtaining a device descriptor from the EdgeTPU
service (`Unknown error -8`, statusCode 5), then freed the runtime. The retained
record is `../gemini-nano-rebuild-20260917/local-model-load-readonly.json`, with
adjacent stdout/stderr. No inference occurred in that test. Investigation
continued through this concrete local loading path; the older blocked audit is
a historical checkpoint, not evidence that local recovery is impossible.

The full goal remains incomplete. [GOAL-REMAINING.md](GOAL-REMAINING.md) separates
the now-demonstrated controlled native cycle from the missing ordinary assistant
route. `blocked-audit-current.json` retains the earlier readiness check and its
then-installed artifact identities; it is not the latest native inference state.

## Implementation — public API diagnostic preserved from the earlier checkpoint

The user explicitly requires **Gemini Nano on device**. The ordinary Pixel
assistant entrypoint and the primary MCP `o_execute` remain part of the intended
end-to-end chain. Opening the Gemini app is not sufficient evidence that Nano
executed a request.

Pixel AI Probe version 3 / 0.1.2 explicitly requested `ModelReleaseStage.STABLE`
and `ModelPreference.FULL` through ML Kit Prompt `1.0.0-beta4` and AICore.
Version 4 / 0.1.3 additionally accepts the four documented Nano release/preference
combinations through a bounded `nano_model` intent value, retaining stable/full
as the default and rejecting unknown values before client initialization.
The requested model configuration is logged separately from returned model
identity. No cloud inference fallback exists in this probe. It only submits its
fixed synthetic prompt if the API reports `AVAILABLE` while the Activity is
resumed, focused and unlocked. This probe is a readiness diagnostic, not the
completed assistant-to-Ostadix integration.

The eight-stage build completed, including the existing source contract,
compilation, APK signature verification and package checks. The installed APK
identity for the first explicit stable/full test, read from its installed path, is:

```text
ee0369e3fe2e7a01d7ed5dab2f17cf065d855672060e22d04a7a84126305b772
```

The subsequent four-configuration build also passed all eight stages and was
installed with SHA-256:

```text
9e19524868997f11b43fa5fb5ca2b55edffe1f630581095d951df42764a09806
```

Its installed path is in `installed-variants-probe.json`. The readiness and hook
coexistence scripts now inspect AICore's own legacy inference history as well as
the distinct framework history. Missing history is reported as unknown rather
than zero. Both scripts passed `bash -n` and completed their live read-only check.

## Live observations — historical public API and routing tests

The initial intent-driven measurement aborted on an Activity pause without a
prompt dispatch. `nano-prompt-measurement.txt` preserves that unsuccessful
measurement; its hardware counters must not be treated as a Nano inference test.

A subsequent tap of the visible Prompt button, after checking the focused
window, produced the actual API observations in `nano-prompt-direct.log`:

```text
provider=AICore; modelFamily=Gemini Nano; release=STABLE; preference=FULL
tokenLimit: tokens=8192
baseModel.failure: 606-FEATURE_NOT_FOUND: Feature 636 is not available.
syntheticInference: skipped; status=UNAVAILABLE
status: value=0 (UNAVAILABLE)
syntheticTokenCount.failure: 606-FEATURE_NOT_FOUND: Feature 636 is not available.
complete: client closed; elapsedMs=485
```

The requested family label is configured by the probe, not returned model
identity. The token limit alone does not establish model loading or inference.

### All documented Nano configurations

Four separately launched foreground requests on version 4 produced:

| Requested configuration | Feature reported missing | API status | Suite completion |
|---|---:|---|---:|
| Stable / full | 636 | UNAVAILABLE | 663 ms |
| Stable / fast | 645 | UNAVAILABLE | 48 ms |
| Preview / full | 647 | UNAVAILABLE | 33 ms |
| Preview / fast | 646 | UNAVAILABLE | 41 ms |

Each base-model-name and token-count query reported error 606. Each inference
was explicitly skipped. These durations cover API checks; they are not inference
or Ostadix execution times. The four raw logs are `nano-stable_full.log`,
`nano-stable_fast.log`, `nano-preview_full.log`, and `nano-preview_fast.log`.
Launch records and installed identity are in `nano-variant-tests.json`; parsed
observations are in `nano-variant-results.json`. No download or preview enrollment
was requested by these tests.

Readiness checks before and after the request found a running AICore process,
zero framework inference records, zero model mappings matched by the audit's
heuristic, and zero payload candidates in the inspected AICore private files
directory. Preload work remained `FAILED(3),attempts=12,stop_reason=-256`.
These observations do not establish absence of every model elsewhere on the
device. Exact outputs are in `readiness-before.txt` and `readiness-after.txt`.

The service's own dump additionally reported `Number of recent inferences
collected: 0`; see `aicore-legacy-inference-history.txt` and
`readiness-including-legacy.txt`. This covers the legacy service used by current
ML Kit/system clients, a path the earlier framework-only check did not cover.
The current AS.OSS coexistence capture found Vector and activation present but
did not find the Ostadix runtime mapping in that process. No successful AICore
callback, runtime initialization, or Nano-to-Ostadix execution is inferred from
those observations.

### Model artifacts and assistant routing

`model-artifacts.md` records the read-only inventory of the 5,748,499,776-byte
factory preload store. Twelve files contain readable TFLite headers, and three
inspected graphs contain compiled Edge TPU operations. This corrects any blanket
description of the entire store as encrypted. The inspection did not establish
a complete independently usable Nano model, its exact release, or a usable
feature catalog. Other app models were not attributed to Nano without metadata.

`assistant-route-findings.md` records inspection of the pinned Google app's
15 base-APK DEX files and 39 native libraries. No general Pixel Nano prompt
request/response path was identified within that bounded scope. Apparent
on-device inference references resolved to glasses integration; an inspected
general LLM path uses online Pro/Flash endpoints. Dynamic modules and complete
native control flow were not covered. This is not proof that a Nano path is
impossible. The existing AppFunction catalog hook does not select a model.

The prior ordinary Gemini attempt has corrected provenance: the coding assistant
opened Gemini and entered the prompt; the user states they pressed Send. The
user transcribed a response describing separate Python/Rust/Bash files and
stating that Gemini lacked local execution access. That response did not prove
Nano inference or an Ostadix call. See the adjacent Gemini integration audit.

## Unverified claims

- An ordinary power-button Gemini assistant request has not been shown selecting
  this local model, invoking Ostadix and consuming the returned result. The
  controlled source-generation/result-consumption test does not prove that route.
- Exact public Nano release identity and the four public Prompt API features
  remain unverified after private native recovery. The earlier error-606 results
  are unchanged historical observations, not proof that local inference is now
  impossible.
- The cause of those missing public features remains undetermined. Google's
  [Prompt API setup documentation](https://developers.google.com/ml-kit/genai/prompt/android/get-started)
  lists initialization/configuration and an unlocked bootloader as possible
  causes; these are not a diagnosis of this device.
- The prior inventory result 50 was generated by this coding assistant. The later
  shipment result 26 came from the recorded model-generated program, after model
  repairs and the disclosed outer-fence extraction. These are separate proofs.
- No successful remote execution, general device control, automatic function
  invocation, air-gapped operation, or complete Nano-to-ordinary-assistant flow
  has been demonstrated by the current evidence. The successful UID 10402 HTTPS
  retest establishes the recorded KernelSU host context only; real AppFunction
  invocation and other Android execution contexts remain unverified.

The explicit selection follows Google's
[model configuration API](https://developers.google.com/ml-kit/genai/prompt/android/select-model).
`evidence-files.json` records hashes of the raw captures; these local hashes are
not signed Google or hardware attestations.
