# Ordinary Gemini → local Nano → Ostadix: observed result

September 18 follow-up: [source validation, default text routing and persistent
result history](../nano-source-validation-20260918/STATUS.md). The observations
below describe the earlier prefix-selected build.

Date: 2026-09-17. Canonical repository: `lostadi/OSTADIX`.
This report supersedes the open assistant milestone in
[the earlier dispatch trace](ASSISTANT-DISPATCH-TRACE.md).

## Implementation

The owned extension connects the stock Gemini pending-turn callback to the
existing local AICore native engine and primary MCP `o_execute`. Activation
requires the extension gate and `ostadix_gemini_nano_tool_mode=local-o-v1`.
The current entry phrase is **“Use Ostadix”**. Other inputs retain their stock
callback. This is a host-selected tool workflow, not autonomous tool discovery
by the stock Gemini model.

The path is:

```text
Stock Gemini FloatyActivity → asvw.c → published pending turn → asue.invoke
  → local AICore model generates a complete .O document
  → existing HostMcpClient → authenticated loopback host → MCP o_execute
  → native O execution and evidence
  → local AICore model interprets the actual typed result
  → stock response flow, parser, renderer and turn completion
```

`GeminiNanoActionHooks` supplies the host's actual Flow/Continuation contract,
adapts the optimized cancellation handler, and supplies closed audio/operation
side streams for the selected local turn. `GeminiLocalResponse` encodes a
minimal text candidate and verifies it through the installed stock parser.
It does not replace a TextView or fabricate a Google conversation identifier.

`NanoActionReceiver` checks Android-provided broadcast UID/package identity
and the pinned Google APK/version/signer. `NanoActionClient` correlates one
request and result, observes cancellation and rejects late results.
`NanoLocalProbe` owns generation limits, native lifecycle and cleanup.
`NanoToolTurn` submits the model's source after outer whitespace/fence removal;
it performs no program repair or automatic reexecution. The model receives no
authority to set deadlines, credentials, backend paths or node placement.
The actual Android execution envelope has empty bindings and a host-selected
120-second execution deadline. Existing process permissions still apply;
this patch does not add a code sandbox or prove arbitrary generated code safe.

The MCP schema and handler were inspected before reuse. `o_execute` already
accepts complete `source` or `path` and delegates to `execute_computation`.
No replacement tool or second planner was added. Ordinary programs use native
O execution; lifted projects retain the native project route machinery.

Once the callback claims a local turn, failure is returned through that turn;
the original inference callback is not retried. An interpretation failure
after successful execution includes the actual typed value and result identity.

## Live observations

### Successful ordinary assistant request

Codex invoked `KEYCODE_ASSIST`, checked the stock Gemini panel, typed the
synthetic natural-language request and tapped Send. **The user did not send
this test.** No `.O` source was included in the user input. The request asked
for Python square sums, a Rust cube sum, a Bash unique-label count and a final
Python combination. See [input](nano-assistant-action-v10-input.json).

The local model generated [this complete program](nano-assistant-generated-program.O).
Its dependent result was **276**: Python produced 174, Rust 100, Bash 2, and
the final Python block added them. The three independent branches use
`autonomous(batch(...))`; this run does not quantify their actual overlap.

| Observation | Recorded value |
|---|---|
| Assistant turn | `ostadix-turn-21317ec8-50e9-49ca-94c8-45c300750989` |
| Google search caller | PID 24413, UID 10191 |
| Local AICore model host | PID 24246, UID 10173 |
| MCP dispatch attempts | 1 |
| Original inference callback delegations | 0 |
| Native execution | 946 ms |
| Turn to answer ready | 61,887 ms |
| Actual OValue | number / integer `276` |
| Placement | `ordinary-local` |

Evidence: [full turn](nano-assistant-action-v10-turn.json),
[MCP request](nano-assistant-mcp-request.json),
[actual MCP result](nano-assistant-mcp-result.json),
[correlated native events](nano-assistant-action-v10.events.jsonl),
[returned answer](nano-assistant-answer.txt),
[UI observation](nano-assistant-action-v10-observation.json), and
[stock completion logs](nano-assistant-action-v10-completion.logcat).

The generated source, submitted source and native source identity agree:

```text
source_sha256: 01ecd091196f8e2a3eefa4feb6b7cb1a52df93672d8ef25185689086de7c888f
result_identity: 3f6a2137568075a5f63bfdf0591651b856a003ec9a044f29d04bee0927acb657
```

The stock Gemini panel visibly displayed 276, the local model's explanation
and the host-appended exact result identity. Stock logs recorded response
handling and send-message completion; the microphone control returned.
They also recorded **“Failed to update project.”** Successful cloud history
or project persistence is therefore not claimed. Screenshots remain local;
the observation record stores their hashes.

Both model calls used the same AICore process and completed native session,
model and runtime cleanup, including closing 191 descriptors each. Device:
Pixel 10 Pro (`blazer`), firmware `CP2A.260805.005/15828068`.
The original AICore bundle identifies feature 234/build 10745 and model
`edgetpu_gem3_it_final_20250505_opt_with_audio_20250525_buenos_dvfs`.
Local Ostadix and its Python/Rust/Bash processes run on the same phone.
The model's EdgeTPU/CPU configuration does not imply those language processes
use the model accelerator.

### Installed and loaded identity

The six-stage [v10 build](nano-assistant-action-v10-build.log) passed package
checks, signing, reply replacement and ASI delegation self-tests.
[Installation](nano-assistant-action-v10-install.json) read back the matching APK:

```text
version: 10 / 0.10.0-nano-assistant-action
APK SHA-256: 6909d036003e3cef4b72a960d209b8ef71121da860832189feda2101824659cb
loaded module Java source digest: d751550220793d8830447af5720afa132eef3f6bdb8a73bf462ff6080c07d363
```

[Owned startup logs](nano-assistant-action-live.logcat) identify v10 and the
installed module path in both executing processes. The compiled source digest
covers sorted module Java file hashes, including their absolute filenames;
it is a diagnostic identity, not a portable whole-build digest or attestation.
The APK digest identifies the packaged artifact.

### Cancellation and caller rejection

Codex sent a separate synthetic request and tapped the visible stock Stop
control after native dispatch. The [assistant turn](nano-assistant-cancel-turn.json)
failed with cancellation and **zero MCP dispatch attempts**. The model
finished a candidate shortly after Stop, but the output was discarded.
[Native events](nano-assistant-cancel.events.jsonl) show session/model/runtime
cleanup and all 191 descriptors closed, followed by unsuccessful completion
with `CancellationException` in the same AICore process. The controller's
generation-result flag remained false; immediate interruption of token
generation is not proven. See [observation](nano-assistant-cancel-observation.json).
No post-cancellation model recovery request was run.

A broadcast lacking shared Android sender identity was
[rejected with UID -1](nano-action-identity-rejection.logcat), despite an
extra claiming the Google caller package. No native dispatch followed it.

### Earlier failures retained

- v6: callback reached; optimized cancellation-handler cast failed before
  worker/model/MCP dispatch.
- v7: model returned malformed source; MCP parse rejection, no backend
  execution. Error appeared, but open stock side streams delayed completion.
- v8: installed APK identity changed, while observed behavior matched v7.
  Loaded build identity was not then recorded; the cause is unverified.
- v9: model generated valid code with the wrong Rust operation, yielding
  **180**, rather than the requested computation. Interpretation repeated
  hashes until the token limit. That build's displayed failure wording
  incorrectly implied no execution; v10 preserves the successful tool result
  when interpretation fails. The v9 record is retained without correction.
- The earlier diagnostic transport returned 5 late; its missing client
  post-wait deadline check was subsequently fixed. That diagnostic was not
  an ordinary assistant request.

These are separate deliberate development tests. No failed effectful request
was silently repaired and retried inside a turn.

### Preserved ASI and independent lifted-project verification

ASI's original-method invocation remains outside the transformation fallback
catch. The current build's four success/failure combinations each delegate
once; fatal preparation delegates zero times. The previously corrected live
ASI package identity and correlated provenance remain in
[the ASI audit](../gemini-ostadix-20260917/live/asi-corrected-correlated.txt)
and [installed hash](../gemini-ostadix-20260917/live/asi-corrected-installed.sha256).
No new ASI feature or v10 live ASI retest is claimed.

The canonical MCP binary SHA-256 is
`b879c51f6480cf8b1e7a0f1d24a519519f7ae6263ad6a7e5749524b274ce88e6`.
A [fresh schema and lifted execution capture](canonical-mcp-lifted-verification.json)
independently passed on that binary: complete lifted source, project-local
route, exit 0, `ostadix.run-summary/v1` disposition `succeeded`, and retained
route-output references. This was a host test, not Nano generating a project.
[Earlier lifecycle evidence](../source-first-mcp/lifted-lifecycle-20260917T175517.870842Z.json)
on that same binary proves cancellation/deadline cleanup, one dispatch,
no late descendant writes, removed workspaces and a subsequent result of 7.

## Unverified claims and limits

- “Nano can do anything” is not established. The wrong-operation and malformed
  programs demonstrate real model reliability limits; no success-rate benchmark
  was performed. The current workflow has one source-generation call, one tool
  call and one interpretation call, not an open-ended agent loop.
- Google Nano weights, AICore and Gemini were not rebuilt from proprietary
  source. The owned extension was rebuilt. The public Nano release name of
  this factory bundle remains unverified.
- These local model calls and O execution were observed; a fully offline
  assistant launch, absence of all Google networking and cloud project/history
  persistence were not demonstrated.
- Physical power-button and spoken invocation were not tested in this capture;
  system assistant invocation plus typed input was tested.
- The loopback host is not boot persistent. Reboot recovery, long-duration use,
  thermal cost, concurrent user workloads and future Google APKs are unverified.
- No remote execution is claimed. Execution evidence hashes identify content;
  they are not signed receipts or independent hardware attestation.

To disable this local assistant route, remove the global setting
`ostadix_gemini_nano_tool_mode`. Do not rotate/reveal the private loopback
credentials when merely disabling the route. Current diagnostic probe gates
are off; the local assistant route remains explicitly enabled.
