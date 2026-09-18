# OSTADIX ↔ AICore integration status

Evidence refreshed: 2026-09-16 UTC. This file distinguishes a reusable OSTADIX
embedding contract from integration into Google's installed AICore package.

## Current result

Direct AICore integration is **not complete**. A real framework request now
reaches Android System Intelligence's active Smart Reply handler, but AICore
does not produce a result for the installed OSTADIX callback to transform. The
public ML Kit probe is an AICore client only and is not represented as OSTADIX
integration.

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

## Activated AS.OSS Smart Reply experiment

## Accepted local ASI Smart Reply path

The extension now also targets the conventional ASI Smart Reply provider that
already succeeds without an AICore model download. Installed enum and class
recovery identifies provider `12` as `SMART_REPLY`, provider `25` as
`AICORE_SMART_REPLY`, `jfk` as the conventional provider, `ish` as its candidate
object, and `jht.d` as the seam that converts the final candidate list into
Android `Dataset` and `FillResponse` objects.

The version-pinned hook intercepts `jht.d(ksf,isj,ffg,ffg,List)`. It projects at
most three already accepted candidates into order score, text-presence, and
safety scalars, runs the same bounded OSTADIX intent, then supplies the selected
original candidate as a singleton list to the original `jht.d`. Candidate text
never crosses JNI. Reflection, JNI, timeout, or invalid-selection failures call
the original method with its untouched list.

The post-reboot live request produced this correlated sequence:

```text
AiAiAutofill: Autofill onFillRequest
OstadixAicoreExperiment: event=asi_candidates_enter request_id=asi-autofill-10201-2 candidate_count=1
OstadixAicoreExperiment: event=asi_ostadix_selected ... source_index=0 score_milli=1000 elapsed_ms=342
OstadixAicoreExperiment: event=asi_result_forwarded ... selected_source_index=0
AsiSmartReplyTrigger: event=autofill_event value=input_shown
```

ASI's service history records a normal response with `cp=[12-1/1]`, while the
same request records provider 25 failing because its service is uninitialized.
The exact installed/local module SHA-256 is
`92d541ebbdaf53c5648470ceb2f050238e3583e960dddb0aa389fda4fe88c02f`.
Raw logs, package identities, Vector scope, service history, and process mappings
are in `OSTADIX-ASI-ACCEPTED-REQUEST-20260917.txt`.

This proves a Google-server-independent system request path through OSTADIX and
back to the framework caller. It does not prove the AICore inference chain:
provider 12 generated the candidate locally, and provider 25 still had no model.

Live ASI configuration enables AICore Smart Reply and disables the open-prompt
route, so the deployed module now targets transaction 6 and this exact path:

```text
flw.c(SmartReplyRequest, flv)
  -> ISmartReplyService.runCancellableInference
  -> fna.onSmartReplyInferenceSuccess(SmartReplyResult)
  -> bounded OSTADIX JNI over score/has-text/safety scalars
  -> construct SmartReplyResult with the selected original entry and trace
  -> flv.b(replacement) exactly once
```

The installed DEX descriptors for the obfuscated host classes are `Lflv;`,
`Lflw;`, `Lfna;`, and `Lflo;`. JADX's `defpackage` directory is synthetic and
cannot be used as the runtime class prefix. AS.OSS also has no current
`Application` during libxposed `onPackageReady`; the module therefore installs
a one-shot `Application.attach` bootstrap and resolves host classes through the
attached package class loader. The bootstrap unhooks itself. Partial host-hook
installation unhooks every earlier handle in reverse order and closes the
OSTADIX runtime.

The module is installed as Vector module 319, enabled, and scoped only to user
0 `com.google.android.as.oss`. Its exact activation token is present. Current
APK evidence is:

```text
OstadixAicoreExtension-debug.apk
SHA-256 f025e13fe0d2fd1b83ea4aad18745eeef1d5d0bec2ae7d7f01fa1485f85a59a6
```

AS.OSS PID 24327 loaded `libostadix_runtime.so` from the module's extracted
native directory. A fixed in-process scalar smoke then selected source 1 at
score 950 in 204 ms with Smart Reply execution intent
`3a044ddbad08687073ec95031f0de36649149da20e225c5fac050829a3de7790`,
after which all four version-pinned Smart Reply hooks installed. This proves
native loading, package-owned backend execution, and OSTADIX selection under
the live AS.OSS process context. SELinux was permissive for this measurement;
audit denials for cgroup and shell-test paths mean the same result under
enforcing mode remains unproven.

The callback correlation latches cancellation and atomically commits
replacement delivery. Cancellation or activation-token removal before that
commit forwards the original result. Severe thermal status, unsupported reply
count, timeout, JNI/reflection error, or OSTADIX error also forwards the
original Smart Reply result unchanged. The replacement keeps the original
selected entry and inference trace; generated reply text never crosses JNI.

### Live framework-to-provider replay

The installed synthetic trigger has APK SHA-256
`cdc1af5634054a189f8c525cd09ae56cb5a878c748459a21a1ebd5456735862a`.
Its installed APK and the local build artifact match. The activity ran over the
secure keyguard without dismissing it. Android Autofill recorded the exact
allow-listed component, an empty focused reply field, a suggestion area, and
inline suggestions enabled. ASI then logged `Autofill onFillRequest` and
entered its registered candidate providers. The concise command output is in
`ASI-SMART-REPLY-LIVE-REPLAY-20260916.txt`.

Recovered bytecode fixes the active internal route before AS.OSS:

```text
AiAiAugmentedAutofillService.onFillRequest
  -> jhh.e / jhh.f
  -> jix.b (screen-context preparation)
  -> jix.i (parallel candidate providers)
  -> jct.n / jct.m / jct.l (AICore Smart Reply provider)
  -> AiCoreLlmService.b
  -> AS.OSS flw.c only after AICore service initialization succeeds
```

`jix.e` gives each provider the live
`Autofill__candidate_provider_timeout_millis=4700` timeout, while Android's
augmented-autofill service deadline is 5000 ms. Screen-context preparation
runs before that provider timeout. The first cold replay entered ASI at
13:06:16.560 and lost the race with Android's 5-second deadline, leaving no ASI
history record. A warm replay is more diagnostic: it completed in 1597 ms and
recorded result codes `31,11,1` (view node present, handler responded, response
completed). Conventional provider 12 produced one candidate in 362 ms. Provider
25 (`AICORE_SMART_REPLY`) failed at
`AiCoreLlmService.b(PG:199)` with `RuntimeException: Uninitialized service`.
Providers 1 and 29 returned no candidates. ASI therefore completed without an
AICore Smart Reply, and no `OstadixAicoreExperiment request_enter` event was
emitted. This locates the recurring failure before AS.OSS `flw.c`, rather than
inside the installed OSTADIX hook.

The trigger was then instrumented with Android's public `AutofillCallback`.
The rebuilt and installed APK hashes match, and a live conventional-provider
smoke recorded `event=autofill_event value=input_shown`. This supplies a caller
side observation for the prepared clean replay without reading reply text.

### Provisioning cause and factory payload

AICore's catalog is empty because the official AS.OSS ProtectedDownload call
to `google.internal.abuse.ondevicesafety.v2.ProtectedDownloadService/
GetManifestConfig` returns `PERMISSION_DENIED` for client
`com.google.android.aicore:18103149225492435673`. The request includes the
client/rollout labels, an encryption public key, and attestation/integrity
material. It does not use an account OAuth token. Package versions, granted
permissions, the active August 2026 Play system train, network state, scheduler
state, and the relevant enablement flags are coherent. The remaining remote
causes are rejection of the attestation/client tuple or absent server
entitlement for this rollout.

The 5.36 GiB read-only `/data/vendor/intelligence` partition is the official
Pixel AI preload payload, not evidence of a populated AICore catalog.
`/vendor/bin/storage_intelligence.sh` identifies it as the Gemini/AICore preload
feature, and live flags point BASE_MODEL feature 234 at it. AICore must first
receive an authorized server manifest that defines feature groups, build IDs,
checksums, and URLs. It can then replace matching URLs with local
`preloadedfile:sha1:` assets and decrypt/copy the factory payload. The partition
cannot bootstrap feature 234 or Smart Reply feature 103 without that manifest.

The local partition does contain files named `manifest.binarypb`,
`config.binarypb`, and `checkpoint.binarypb`. Direct inspection does not make
them a substitute catalog: their leading bytes are high-entropy data, generic
protobuf decoding yields no fields, and strings do not expose file mappings or
feature definitions. AICore's recovered preload code first requests configured
feature 234 from its own service; only after a feature definition supplies
`preloadedfile:sha1:` URLs does `bwn` map those URLs to factory files. The
preload worker therefore fails with feature 234 unavailable before it can use
the payload. The factory `manifest.binarypb` SHA-256 is
`bd045d18a0ac1ce8321d7fd8b58bc74c124dea489fe8ebf763cd92b6807e90e9`.

This device also runs Play Integrity Fix and TEESimulator-RS. TEESimulator's
target list included AICore, ASI, AS.OSS, PSI, GMS, ODAD, Play Store, and the
Google app, so green/locked boot properties alone do not prove that
ProtectedDownload received stock hardware attestation. A reversible test
backed up the list to
`/data/adb/tricky_store/target.txt.ostadix-pre-20260916` and removed the seven
entries other than PSI. After restarting ASI, AS.OSS, AICore, and PSI, the same
remote denial persisted.

Decompilation and live logs show why that exclusion was not a stock-attestation
test. TEESimulator reloads `target.txt` immediately, but its KeyMint pre-handler
still handles any request containing device-property attestation tags even
when the caller is absent from the target map. AS.OSS creates the fixed
`PcsAttestationKey` alias with
`setDevicePropertiesAttestationIncluded(true)` and a fresh server challenge on
every ProtectedDownload request. During the exclusion window the key's Android
Keystore entry changed, then TEESimulator logged `Found generated response for
PcsAttestationKey`; its forwarded hardware path uses the distinct `Found TEE
response` log. Restarting only the supervised TEESimulator daemon also left
this unconditional interception in place. The original target file was
restored byte-for-byte with SHA-256
`0236bb20ffa7eb6d63e506d3e9cfacdf401669c7d8aabcb8a82da2e9cbaa5c18`.

The decisive reboot test was run on 2026-09-17. Boot ID changed from
`150938be-c605-4848-8416-9db5a408eaad` to
`3d6e1607-3649-4b77-9fe2-aaf7831a10ab`. KernelSU reported `tricky_store`
disabled, its disable marker was present, and neither the TEESimulator process
nor its supervisor was running. No TEESimulator boot activity was recorded.
This establishes that its native KeyMint interceptor was absent for the test.

Stock hardware attestation did not recover ProtectedDownload. Three observed
manifest downloads used fresh public-key hashes and each ended with
`GetManifestConfig` `PERMISSION_DENIED: The caller does not have permission`.
The later two hashes were
`b48330ea8731b6c09fa9dc400a7474ce4e18c2b663113501c2c8eccdf8c9526e` and
`0e3a34f77f0eedb7d558b8d545d21bba3d62f237da857442685d7f68a1ac5532`.
This disproves TEESimulator's direct substitution of `PcsAttestationKey` as the
cause of the persistent server rejection. It does not distinguish absent
server entitlement, rejection of another part of the client/integrity tuple,
or rollout configuration.

Kernel boot parameters provide the missing trust-state evidence. In the clean
boot, `/proc/bootconfig` reports `androidboot.vbmeta.device_state="unlocked"`,
`androidboot.verifiedbootstate="orange"`,
`androidboot.verifiedbooterror="ERROR_VERIFICATION"`, and
`androidboot.verifyerrorpart="init_boot"`. At the same time, `getprop` reports
locked/green, showing that Android-visible properties were rewritten and were
not authoritative for hardware attestation. The server response does not name
which check failed, so the unlocked and failed verified-boot state is a strong
cause candidate rather than a proven server-side diagnosis. It explains why
removing the simulator did not create an acceptable stock attestation.

The other client inputs are coherent. Decompilation maps this request to
`AI_CORE_CLIENT_37`, the installed OS is SDK 37, the selected client ID is
`com.google.android.aicore:18103149225492435673`, and its live
`AicDataRelease__build_id_18103149225492435673` value is `21590`. Build labels
are present, ProtectedDownload and attestation are enabled, and AS.OSS and
AICore are Play Store installed updated system packages. These checks make a
random client-ID selection or missing build flag less likely.

The request ownership is also explicit. AICore's `dsh` accepts only
`client_group`, `device_tier`, `variant`, and `build_id`, constructs the local
`GetManifestConfig` protobuf, and supplies its bundled production API key for
`ondevicesafety-pa.googleapis.com`. AS.OSS receives that protobuf over its
private Binder gRPC service, derives the selected client configuration, adds a
fresh encryption public key plus attestation/integrity response, and calls the
remote v2 service. The returned status contains only `PERMISSION_DENIED: The
caller does not have permission`; no captured status detail identifies an API
key, rollout, client-label, or verified-boot predicate. This prevents a more
specific server-side conclusion from the available evidence.

The framework created augmented-autofill sessions and the trigger callback
reported `input_shown`, but ASI history contained only `rc=[3, 2]`, with no
nonempty provider-25 result. AICore also reported missing features including
607, 614, 703, 2007, and 2008. Consequently AS.OSS never reached the installed
OSTADIX hook and there was no correlated
`request_enter`/selection/result-forwarded chain. The end-to-end result is
therefore incomplete for a specifically measured pre-inference provisioning
failure, rather than an OSTADIX execution error.

### Live coexistence gate

The hook half of the remaining prerequisite is now proven from the live AS.OSS
process rather than inferred from Vector configuration. In boot
`3d6e1607-3649-4b77-9fe2-aaf7831a10ab`, AS.OSS PID 1443 maps both
`/data/adb/modules/zygisk_vector/zygisk/arm64-v8a.so` and the installed
extension's `libostadix_runtime.so`. The global activation value hashes to the
exact token derived by the pinned extension, without recording the token.

`check-aicore-hook-coexistence.sh` repeats these checks alongside AICore's live
model and inference state. Its recorded run proves Vector loaded, OSTADIX
runtime loaded, and activation matched, while AICore still had zero inference
records and zero loaded model mappings. It exits 4 until both halves are true,
then permits the correlated system-request replay. This narrows the missing
condition to usable AICore model state; reinjecting or reinstalling the hook is
not currently required.

The live rollout tuple is structurally valid. Base64 decoding
`AicDataRelease__build_labels=CAMQDg` yields protobuf fields `08 03 10 0e`:
device tier 3 (`MID`) and recognized variant 14 (`VARIANT_14`). AICore's
`brl` gate rejects unknown or unspecified tier/variant before any download,
while this request proceeded to the remote service. `buf` constructs the four
labels as client group, `VARIANT_14`, `Mid`, and build ID `21590`. No local
evidence maps the obfuscated variant number to a marketing device name, but it
is a valid configured enum rather than missing or malformed input.

The gate then followed the same live `PreloadModelWorker` rather than forcing a
new job. Work ID `fd17750d-b007-4944-b01e-96009f874aeb` advanced from attempt 8
to attempt 9. During that execution AICore made multiple fresh
`GetManifestConfig` calls through the already hooked AS.OSS process; each was
denied, and the worker reported feature 234 unavailable before returning to
`ENQUEUED`. The post-attempt gate still proved both injected libraries and the
activation token while reporting zero model mappings and zero inference
records. This directly demonstrates hook/catalog coexistence at request time,
with authorization as the remaining failed condition.

`run-stock-attestation-replay.sh` is the prepared one-shot verifier. After the
first post-reboot unlock it refuses to run if the module disable marker is
missing or a TEESimulator process still exists, performs the cold and warm
synthetic requests, waits for provisioning when the manifest is not denied,
and captures only the relevant logs and service state. Its candidate pass gate
requires no manifest denial or TEESimulator activity, correlated OSTADIX entry,
selection and forwarding events, a nonempty ASI provider-25 result, and the
trigger activity's public `AutofillCallback` reporting that the framework
showed the returned input suggestion. On exit it stages `tricky_store` enabled
for the following reboot.

`arm-stock-attestation-replay.sh` atomically copies that verifier into
KernelSU's `service.d`, disables only `tricky_store`, and stops before reboot.
Its `--undo` path removes the one-shot service and stages the module enabled.
The service waits for the first user unlock, detaches from KernelSU's serial
boot scripts, removes itself after capture, and leaves the module staged to
load again on the following reboot.

The clean retry disabled only the component proven to replace AS.OSS's KeyMint
result. Play Integrity Fix remained enabled and targeted GMS/Play Store, so the
run isolated TEESimulator's direct attestation substitution; it was not a claim
that every device-integrity modification was absent. The one-shot runner
staged `tricky_store` enabled for the following reboot and removed its service
file. The module is staged but is not loaded in the current test boot.

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
