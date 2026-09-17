# Gemini Nano target — 2026-09-17

## Superseding successful local load — 17:19 UTC

The [current reconstruction status](../gemini-nano-rebuild-20260917/STATUS.md)
records a successful model load and token-count request inside the genuine
installed AICore process, PID 7088 / UID 10173. An explicitly derived config
omits only the factory audio submessage; all model weight files are unchanged.
Native initialization took 5.281 seconds and the synthetic `Ostadix` input
returned 3 tokens. Model/runtime cleanup and all 191 descriptor closures
completed successfully. The process remained alive.

This supersedes the earlier local model-loading blocker. The successful test
performed no generation, established no exact public Nano model identity, and
did not connect an ordinary assistant invocation to Ostadix. The original
Prompt API observations below remain historical results; availability of
those public features has not been demonstrated by the private native probe.

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

The full goal remains incomplete. `GOAL-REMAINING.md` records the requirement
audit and the same unavailable-Nano prerequisite across three consecutive goal
turns. `blocked-audit-current.json` retains the final live readiness check and
installed artifact identities. Continuation requires usable Nano inference;
the ordinary assistant-to-tool connection still needs implementation and proof.

## Implementation

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

## Live observations

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

- Nano has not generated a complete `.O` program, called `o_execute`, or consumed
  its returned result in these tests.
- The ordinary power-button assistant has not been shown routing this request to
  Nano. This probe update does not alter that assistant routing.
- No inference result or execution evidence can be attributed to Nano from this
  request. The previously demonstrated Ostadix inventory result of 50 was
  generated by this coding assistant and executed via direct test calls.
- The exact cause of Feature 636 being unavailable remains undetermined.
  Google's [Prompt API setup documentation](https://developers.google.com/ml-kit/genai/prompt/android/get-started)
  identifies initialization/configuration and an unlocked bootloader as possible
  causes of this error. Those documented possibilities are not a causal diagnosis
  of this specific request.
- The same missing-feature failure now covers all four documented Nano
  configurations. A functioning Nano request and a correlated connection from
  the ordinary assistant to that request remain prerequisites. Static catalog
  edits and the working direct MCP tests do not satisfy them.
- No offline, remote-execution, general-device-control or Nano-to-assistant
  completion claim follows from these observations.

The explicit selection follows Google's
[model configuration API](https://developers.google.com/ml-kit/genai/prompt/android/select-model).
`evidence-files.json` records hashes of the raw captures; these local hashes are
not signed Google or hardware attestations.
