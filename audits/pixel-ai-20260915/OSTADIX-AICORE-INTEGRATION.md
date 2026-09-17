# OSTADIX ↔ AICore integration status

Evidence refreshed: 2026-09-15 UTC. This file distinguishes a reusable OSTADIX
embedding contract from integration into Google's installed AICore package.

## Current result

Direct AICore integration is **not complete**. No installed AICore request has
yet delegated computation to OSTADIX. The public ML Kit probe is an AICore
client only and is not represented as OSTADIX integration.

The installed active AICore is exactly:

```text
package=com.google.android.aicore
versionCode=494417
versionName=0.release.prod_aicore_20260723.00_RC11.964081323
targetSdk=35
flags=SYSTEM HAS_CODE UPDATED_SYSTEM_APP PRIVILEGED PRODUCT
services=AiCoreIntelligenceService -> AiCoreIsolatedService
```

The product stub is version code 395592; package manager selects the updated
`/data/app/...` package. The framework service was `Unbound`, with zero pending
or unfinished jobs, when refreshed.

## Reconstructed system call path

Decompiled callers and live bindings establish this path for system features,
but a successful request has not yet been traced across every stage:

```text
ASI feature entry
  -> ASI feature-specific input preparation
  -> AS.OSS GenAiInferenceService
  -> AS.OSS caller UID/package allow-list + signature policy
  -> AICoreMultiUserService feature dispatch
  -> AICore runtime/model loader and inference implementation
  -> feature-specific output callback/completion
```

AS.OSS accepts `com.google.android.as`; a third-party caller encounters
`Caller is not allow-listed for AICore service forwarding.` AICore and AS.OSS
are Google/system-signed privileged updateable packages. No supported generic
plug-in or postprocessor interface was found. Consequently, replacing either
APK, signature impersonation, disabling caller policy, or recursively calling
the intercepted public ML Kit API is outside this experiment.

Candidate insertion points visible in recovered code are feature-specific
input preparation, immediately after native inference returns, or before the
existing completion callback. They are implementation methods, not supported
extension interfaces. Exact per-feature method names must be revalidated
against the active APK before any update-specific patch experiment.

The least ambiguous recovered LLM forwarding path on this build is:

```text
ASI AiCoreLlmService.b(List, String, continuation)
  -> bind component com.google.android.as.oss/...GenAiInferenceService
  -> fln.dispatchTransaction(5) / fln.g(AIFeature)
  -> IAICoreService.getLLMService(AIFeature)
  -> fls.dispatchTransaction(2) / fls.a(LLMRequest, flr)
  -> ILLMService.runCancellableInference(LLMRequest, fmz)
  -> fmz.onLLMInferenceSuccess(LLMResult)
  -> flr.b(LLMResult) one-way PccLlmResultCallback transaction 1
  -> AiCoreLlmService.b coroutine resumes and completes its feature result
```

`fls.b` is the non-cancellable `ILLMService.runInference` variant; `flo.a`
forwards cancellation to AICore's `ICancellationCallback.cancel`. The exact
narrow post-inference insertion seam would be
`fmz.onLLMInferenceSuccess(LLMResult)` before `flr.b`, because it consumes the
actual internal result without recursively re-entering ML Kit. Equivalent
typed seams exist at `fmt.onSummarizationInferenceSuccess` and
`fna.onSmartReplyInferenceSuccess`. These names are ProGuard artifacts tied to
this exact APK and are not a supported extension ABI.

The installed AIDL fixes the resource boundary as well. Transaction 3,
`ILLMService.runCancellableInference(LLMRequest, ILLMResultCallback)`, returns
an owned `ICancellationCallback`; its `cancel()` is one-way transaction 2.
`LLMRequest.closeAllFileDescriptors()` closes image embeddings, image and audio
inputs, LoRA/drafter LoRA files, the auxiliary session-state file, and the
prefix-cache descriptor. `LLMResult` is parcel data: each `LLMReply` contains
text, score, stop reason, policy scores, citations, and function calls, plus
result-level trace/Legion metadata. A correct post-result integration must keep
the model service, cancellation binder, and all descriptors owned by the
AICore request owner. OSTADIX receives only a bounded typed copy of fields used
by its O program; it must not retain the Binder session or borrow a descriptor
beyond callback completion.

The active APK signing certificates are different Google keys: AICore signer
SHA-256 `b7971ccc10a03932e14a3557a1b4c2a84be0ecb506777f0c72dd46cf5d7093c6`;
AS.OSS signer SHA-256
`071f09456bf1a8e8ad2e808ffe6a0ebc13582a7e6f9aba13e47280ad9a85d833`.
Therefore a locally re-signed replacement would not satisfy package update or
signature-policy identity. Root alone does not manufacture the original
signing keys, Android package identity, or SELinux domain.

An unlocked foreground run on this exact build now proves real public requests
reach AICore feature preparation, but the installed feature catalog rejects all
three tested routes before inference:

```text
prompt feature 636: FEATURE_NOT_FOUND (606), status UNAVAILABLE, 317 ms cold / 38 ms warm
image-description feature 627: FEATURE_NOT_FOUND (606), 26 ms
summarization feature 622: FEATURE_NOT_FOUND (606), 27 ms
```

The prompt token limit (`8192`) is available client-side, but no synthetic
inference ran. This is a verified AICore request/error path, not the required
working inference path and not OSTADIX integration.

A later read-only live-state check gives the stronger current explanation.
Android's `on_device_intelligence` service is registered and bound to AICore,
and the legacy multi-user service has live bindings from system, AS.OSS,
Gboard, Pixel Agent, TTS, and one third-party client. Despite those bindings,
the framework `InferenceInfoStore` contains zero records, AICore's private
files contain zero model-payload candidates outside download metadata, and the
live AICore process has zero model-file mappings. Logcat also records repeated
protected-download manifest-fetch failures; Gboard reports AICore features 703
and 607 as unavailable/`FEATURE_NOT_FOUND`. The WorkManager database identifies
`AICORE_PRELOAD_MODEL`/`PreloadModelWorker` initially remained enqueued after
11 run attempts. On 2026-09-16 it reached terminal WorkManager `FAILED(3)`
after attempt 12 (`stop_reason=-256`) while inference records, private model
payloads, and live model mappings all remained zero. A binder connection is
therefore not evidence of a working request or an owned model session on this
boot.

`check-aicore-runtime-readiness.sh` repeats these checks without starting,
stopping, clearing, downloading, or modifying a package. It currently exits 4
with `readiness=false reason=no_observed_inference_or_loaded_model`. Once it
observes an inference record or loaded model mapping, the next step is to trace
one already-authorized client's real request rather than inject another
synthetic feature ID.

## Reusable OSTADIX embedding contract added

`ostadix_api::Runtime` now supports a two-stage request lifecycle:

```text
persistent Runtime / evaluator / admitted backend infrastructure
  -> prepare_request(request-private source, typed bindings, caller/request IDs)
     -> Parser -> OIR -> validated ExecutionPlan -> HGraph -> schedule
  -> execute_request(fresh request-private scope)
     -> graph evaluator/admission -> typed OValue result
```

The request contract enforces source, binding-count, and canonical binding-byte
bounds before parsing,
checks cancellation/deadline before preflight and before/after evaluator entry,
and returns typed `OValue` plus plan/HGraph counts and elapsed execution time.
Caller and request IDs are correlation metadata only: they are not injected
into O scope, persisted, logged, or treated as authority.

Preflight now also compiles OSTADIX's existing authority-free
`ExecutionIntentV1`, binding the exact stripped source, OIR, plan, solved
HGraph, catalog projection, analyzer, and base policy. Execution recomputes and
verifies that intent before V6 evidence/admission and dispatch. The returned
`RuntimeExecutionEvidenceV1` exposes the existing OIR/plan/analyzed-graph,
evidence, admitted-graph, and process-local admission digests together with the
typed result's `OValue::content_identity()`. It contains no caller ID, prompt,
or result text and grants no authority. Request bindings remain deliberately
outside the existing admission digest, but their bounded request-private map is
identified with the existing canonical `OScope` content identity. Different
typed AICore result projections therefore have different scope identities even
when source/intent/admission are unchanged. This remains execution identity
metadata, not a signed end-to-end receipt across an untrusted transport.

Cancellation is checked at graph-coordinator safe points and at 25 ms polls
while a coordinator-owned or autonomous local-worker backend is running. The
coordinator polls outstanding worker events every 5 ms, propagates the request
token into each local task, and retains worker ownership until a cancelled
hosted subprocess is forcibly reaped. A test proves cancellation only after
backend request code created its private start marker, then proves same-runtime
recovery. External physical-attempt drivers and native model sessions still
need explicit cancellation contracts. Thermal admission likewise remains with
the host; the embedding contract does not bypass Android/AICore thermal policy.

The JNI host now retains each active token only under its exact caller/request
pair. A lifecycle read/write lock permits `cancelRequest` concurrently with an
evaluation while excluding runtime destruction; completion removes the token.
The release smoke waits until Bash creates a private post-dispatch marker,
propagates cancellation, observes forced actor reap in 126 ms, and then proves
same-runtime recovery. This is ready to map from AICore's owned
`ICancellationCallback`; that mapping is not installed yet.

## Verified behavior

`runtime_request_contract` proves:

- typed request-private input reaches canonical OIR/ExecutionPlan/HGraph
  execution and changes the returned typed value;
- two requests on one persistent runtime retain distinct request identities and
  fresh scopes;
- source-size bounds, pre-cancel, and expired deadlines fail closed;
- structural metadata confirms a nonempty plan, graph, and executable edge set.

The portable contract test uses `$values`, a typed OSTADIX scope-load operation.
A root-package integration test now uses an actual O program with a hosted
Python block to validate equal-length typed score/label arrays, select the
maximum score, and return an `OMap` containing `label`, `confidence_milli`, and
`candidate_count`. Changing only typed scores changes `reject` to `accept`.
Execution crosses Parser, OIR, validated ExecutionPlan, HGraph, admission, the
explicitly admitted `O --o-backend` executable, and OValue projection.

The first Python-backed attempt exposed an exact embedding requirement:
a generic library host is relaunched with OSTADIX's private `--o-backend`
argument, which the host binary does not implement (`Unrecognized option:
'o-backend'`). `Runtime::with_runtime_executable` now lets a host bind the exact
owned executable, which is opened, hashed, retained, and checked by existing
admission machinery. The host test passes through that route. Android/AICore
still cannot copy an executable into writable app storage; it needs either a
packaged executable accepted by Android's loader/process policy or a pure
in-process admitted backend.

## Deployment alternatives

- **In-process:** lowest IPC overhead and preserves typed values directly, but
  requires modifying/re-signing an updateable privileged Google package and
  loading an ABI-compatible OSTADIX library in AICore's SELinux/native-library
  environment. No authorization or supported injection point exists yet.
- **Explicit worker:** isolates runtime/native buffers, supports hard process
  cancellation and reversible disablement, but requires an AICore-authorized
  binder contract, caller-identity forwarding, SELinux rules, package signing,
  lifecycle ownership, and bounded typed serialization. No such AICore worker
  contract was found. A separately launched broker would be only an external
  harness until AICore itself invokes it.

## Disabled build-only AS.OSS experiment

`apps/aicore-ostadix-extension` is now a narrow libxposed API 102 experiment
for this exact AS.OSS build. It is **not installed, enabled, activated, or
present in Vector's module/scope database**. Its APK statically names only
`com.google.android.as.oss`, rejects any firmware, AICore/AS.OSS version,
base-APK hash, or signer mismatch, and installs no hook unless the exact
`ostadix_aicore_extension_token` global value is explicitly present. On an
incompatible update, only this experiment remains detached; AICore and AS.OSS
are untouched.
The token is rechecked at request entry and completion, so removing it disables
result transformation immediately even if installed hooks remain until the
next AS.OSS restart.

The planned internal path is:

```text
fls.a(LLMRequest, flr) on the incoming ASI Binder thread
  -> capture Binder.getCallingUid and correlate flr/flo request objects
  -> existing ILLMService.runCancellableInference (unchanged)
  -> fmz.onLLMInferenceSuccess(LLMResult)
  -> copy at most 3 replies' score/stop/max-policy scalar metadata
  -> bounded OSTADIX JNI -> Parser/OIR/ExecutionPlan/HGraph/V6 admission/Bash
  -> typed {source_index, score_milli}
  -> construct LLMResult with selected reply and original trace/Legion/thought
  -> invoke existing flr.b(replacement) exactly once
```

`flo.a()` first propagates the matching request token into OSTADIX and then
continues through AICore's existing `ICancellationCallback`. Severe thermal
status, an unsupported reply count, timeout, JNI/reflection error, or OSTADIX
error all retain the original `LLMResult`; generated text, citations, FDs,
sessions, and native buffers are never copied into OSTADIX or logged. The
module loads the pinned JNI library by its absolute package-owned path and uses
the package-owned O/Bash executables directly. Initialization writes nothing
into AS.OSS private storage, so detach/disable/uninstall leaves no runtime
infrastructure there.

The six-stage module build verifies its static scope, v3 signature, seven-file
hash-pinned native closure with an embedded manifest, explicit activation
guard, and result replacement. A host fake
`LLMResult` test proves that the selected index narrows the reply list while
preserving trace, Legion metadata, and thought-process objects by identity and
that out-of-range output fails closed. The read-only installed-contract check
verifies the exact `fls`/`fmz`/`flo`, `LLMResult`, and `LLMReply` shapes after
first passing the live version/APK/signer policy. The build additionally checks
that all eight in-process version/APK/signer constants remain byte-for-byte
present in the shared compatibility policy. Artifact:

```text
OstadixAicoreExtension-debug.apk
SHA-256 262bdc3b7b75f076f2cfd3448e602d59652123d9b8546993c5be277fd9f3ef04
```

This is stronger deployment preparation, not direct integration evidence.
Running it still requires explicit authorization to install/scope/activate,
and actual AS.OSS fork/exec, linker-namespace behavior, and module-native
loading remain untested. Read-only policy inspection does remove one suspected
categorical blocker: both live AICore and AS.OSS processes are
`u:r:priv_app_36:s0:c512,c768`, and platform CIL grants `appdomain`
read/open/map/execute/`execute_no_trans` on `apk_data_file`. This permits the
shape of package-owned execution but does not prove this module's cross-package
native closure can run. More fundamentally, the installed AICore preload is
terminal `FAILED(3)`, so there
is no working inference result on which to prove that AS.OSS consumed the
replacement.

The JNI host smoke was also rerun with the `.so` O and Bash paths directly,
not terminal command symlinks. It cancelled a post-dispatch Bash request in
102 ms, then selected index 0 in 84 ms and index 1 in 98 ms on the same runtime.
This proves the no-write launcher configuration on the current host, not under
the AS.OSS linker namespace or SELinux process.

## Measured overhead and remaining proof

The portable tests complete in 0.05 s. Seven root integration tests complete in
2.08 s when Cargo overlaps independent tests. In the latest run,
evaluator-reported hosted postprocessing was 794.904 ms and 697.359 ms, with 6
plan nodes, 15 HGraph nodes, and 3 executable edges. Prior runs were
approximately 535–1854 ms per request. These are
debug-build host measurements dominated by process/admission startup, not
Android production latency. Concurrent independent-runtime callers, invalid
typed input, runtime drop/recreate, deadline reap/recovery, post-dispatch
cancellation/recovery, and post-restart success also pass. One test mirrors
the installed `LLMReply` shape and proves OSTADIX filters non-finished or
over-policy replies, ranks eligible replies deterministically, changes output
when policy input changes, and returns a typed error when no safe finished
reply exists.

An isolated resource-lifecycle test executes the same AICore-shaped O program
12 times, verifies each typed score result, then drops the runtime. It measured
516.949 ms p50 and 532.221 ms p95 request latency, a 5,796 KiB peak RSS increase,
zero peak/final file-descriptor increase, and no surviving owned backend child
process. This covers OSTADIX host-side request/backend cleanup only; it cannot
measure AICore model buffers while no model is provisioned.

No AICore→OSTADIX IPC, JNI, memory, model
session, energy, or thermal overhead has been measured because that call path
does not yet exist. Reporting the ML Kit probe or native Edge TPU context load
as this overhead would conflate unrelated paths.

Remaining integration work is to select one recovered, active feature and
trace its exact current methods end-to-end; establish lawful signing/update and
SELinux deployment authority; define cancellation for external physical-attempt
drivers and owned model sessions; make the proven deterministic ranking O
program consume actual inference output; make the existing
internal inference result feed it without public-API re-entry; and prove output
dependency, errors, cancellation, concurrent callers, backend isolation,
restart, AICore-process memory/latency/thermal cost, update incompatibility
disablement, and rollback on-device.

## Android build evidence

The Android JNI embedding now has a fixed AICore-result postprocessor in
addition to its compatibility call. It accepts one to three replies as bounded
integer arrays containing only score, stop reason, and maximum policy score;
generated text, citations, model sessions, file descriptors, and native buffers
do not cross the boundary. The fixed Bash O program returns a typed map with
the selected source index and score. Both the packaged O proxy and Bash direct
launcher are explicit embedding paths whose exact files remain hashed,
admitted, retained, and revalidated by the existing executable machinery;
JNI does not mutate process-global `PATH`.

The full portable release build passed native, Java, JNI, CLI, Bash, ELF, DEX,
APK signing, and package checks. With identical source, execution intent, and
admitted graph, changing only policy metadata changed the typed result from
index 0/score 600 to index 1/score 950. The source-matched release build's two
requests completed in 85 ms and 105 ms and had different request-scope and
result identities. An unsafe-only
input returned an evaluate-stage error. The first result was:

```json
{"ok":true,"stage":"complete","callerId":"asoss/uid-1000","requestId":"llm-result-1","type":"map","output":"{\"score_milli\": 600, \"source_index\": 0}","selectedSourceIndex":0,"selectedScoreMilli":600,"planNodes":50,"hgraphNodes":81,"hgraphExecEdges":14,"sourceSha256":"675af36862ee1d150a594b588f7442779cb07b251834e9bcef03aaa59de731fe","executionIntentSha256":"f132bf4336be6b32a80bea649aae48c59fd042ee88cee7e2de1103ac76fab850","requestScopeContentIdentity":"83c3b0b8edb3024ee1d1e249c36692477a4dfe60055d0898373ab46c165498c4","admittedGraphSha256":"9858db893aa2ea76eb2507e782bff89fbe83735db96dfe604be6c772df363705","resultContentIdentity":"8a91b13a85215b8d958922b8d40e2d8af51a9f12b43c895848925fc7f7f2cd37","elapsedMs":85}
```

Build artifacts (not installed by this experiment):

```text
APK SHA-256      fd76156dcec49f0a85d90afd855b15f376f84699d77f77e05b18167926d3b6be
v2 APK SHA-256   9ef7cb62184a4927c37eb4928ea74888bb8bfef2bf8d52935d7bfb2d14f64cd4
runtime .so      b94db0d5503b62a4323c6450d75eb50c522d2f3471addf896f344061abe91e75
packaged O CLI   ae5604aad11c742d5fafa04ab9a05b19ed834135a0c4d0b0c5875ddd61fa91a4
APK identity     org.ostadix.terminal 0.1.8 (9), minSdk 28, targetSdk 34
APK signatures   separate debug artifacts verified with v3 and v2 respectively
```

This proves the OSTADIX Android embedding/build route, not integration into the
Google-signed AICore process or request architecture.

This proves meaningful typed processing through the packaged Android JNI and
backend path. It still does not prove that AS.OSS invokes the JNI method or
consumes its selected index in a real AICore request.

## Update and rollback gate

`check-extension-compatibility.sh` performs a read-only comparison of the
active AICore and AS.OSS version codes, version names, base-APK SHA-256 values,
and signer-certificate SHA-256 values. It currently reports:

```text
extension_compatible=true action=extension_may_continue
```

Any mismatch exits with status 3 and prints
`action=disable_experimental_extension_only`. It never disables, replaces,
restarts, or clears AICore/AS.OSS. A future extension must use this as a
precondition and make its own disable operation reversible; the gate itself is
not evidence that such an extension has been installed.

The comparison is now separated into a pure snapshot policy and the live
read-only collector. Ten policy cases pass: the exact snapshot, eight
single-field mismatches covering version code/name, APK hash, and signer for
both packages, and a malformed snapshot. Every mismatch returns status 3 and
names only `disable_experimental_extension_only`; the live collector still
passes against the installed pair. Because no internal extension exists, there
is deliberately no disable implementation that could be misrepresented as an
AICore integration rollback.
