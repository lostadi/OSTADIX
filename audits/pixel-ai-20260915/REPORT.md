# Pixel 10 Pro on-device AI and neural-processing audit

Audit date: 2026-09-15 UTC

Device under test: Google Pixel 10 Pro (`blazer`, platform `laguna`, reported SoC `Tensor G5`)

## Result at a glance

This phone has a substantial, live on-device AI stack. AICore, Android System Intelligence (ASI),
the AS.OSS private-compute package, Edge TPU/Darwinn services, installed model artifacts, the
Neural Networks HAL, and a separate Context Hub are all present. ASI was observed binding through
AS.OSS into AICore, and multiple Pixel apps contain concrete AICore or local-ML clients.

The audit does **not** yet claim a controlled AI inference or attributable TPU execution. The
foreground ML Kit probe is installed, but its first launch was obscured by secure keyguard. Android
paused it before a request completed. The probe was then hardened so no call can begin until its
Activity is resumed, focused, and the device is unlocked. The hardened APK was rebuilt, signed,
and installed; only the foreground run remains pending an operator unlock.

| Question | Evidence-backed status |
|---|---|
| Installed packages, splits, native libraries, services, model store | Verified on this build |
| ASI -> AS.OSS -> AICore system integration | Verified from decompiled callers plus live bindings |
| Local implementations for several Pixel features | Verified at implementation/artifact level |
| Public third-party ML Kit/AICore access | Not yet tested while visibly foreground |
| Edge TPU vendor library initialization and context creation | Verified under root; no model submitted |
| Independent LiteRT-LM NPU inference | Blocked by gated G5 model and matching dispatch build |
| A controlled request executing on TPU/NPU | Not verified |
| Back-gesture ML implementation | Present but vendor-disabled; CPU TFLite, not TPU |
| CHRE execution environment | Verified on AoCv2; separate from TPU |

## Safety, privacy, and preserved state

- No AICore, ASI, AS.OSS, Recorder, keyboard, photo, message, audio, or credential database was
  dumped. Only package code, public/configuration metadata, service state, model metadata, and
  synthetic inputs were used.
- No bootloader action, device-identity change, AICore data clear, overlay write, DeviceConfig
  write, thermal-policy change, or security-policy bypass was performed.
- Existing patches, settings, Magisk/KernelSU service scripts, and prior audit backups were not
  modified. In particular, the existing screen-off audio script and previous interface settings
  were left intact.
- The back-gesture ML flag was not changed.
- No polling daemon or permanently resident model was added.
- The only installed package from this pass is the foreground probe
  `org.ostadix.pixelai.probe`; exact rollback is `pm uninstall org.ostadix.pixelai.probe`.
- No reboot was performed, so reboot persistence is not claimed.

Previous evidence retained in place:

- `/data/data/com.termux/files/home/OS-hardware-integration-20260915.md`
- `/data/data/com.termux/files/home/Core-app-feature-audit-20260915.md`
- `/data/data/com.termux/files/home/OS-optimization-20260915.md`
- `/data/adb/ostadix-audits/20260915-core-apps/`
- `/data/adb/ostadix-backups/20260915-*`

## 1. Installed stack

### Device and OS

The following values are what Android reports. Package hashes, ELF inspection, service queries,
and runtime calls corroborate the software stack, but this audit did not independently attest the
physical SoC or boot chain.

```text
manufacturer=Google
model=Pixel 10 Pro
device=blazer
board_platform=laguna
soc_model=Tensor G5
release=17 sdk=37
build_id=CP2A.260805.005 incremental=15828068
security_patch=2026-08-05
fingerprint=google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys
kernel=6.6.118-android15-8-g1831c2a45d9b-ab15739706-4k
root_context=uid=0 context=u:r:ksu:s0
selinux=Enforcing
flash_locked_reported=1
verified_boot_reported=green
```

The boot properties above say locked/green. They are reported properties, not an independent
bootloader-state proof. The public ML Kit readiness call and its exact error remain authoritative
for API eligibility.

### Central and adjacent packages

| Package | Version code | Version name / role |
|---|---:|---|
| `com.google.android.aicore` | 494417 | `0.release.prod_aicore_20260723.00_RC11.964081323` |
| `com.google.android.as` | 16934935 | `C.6.playstore.pixel11.961955194` (ASI) |
| `com.google.android.as.oss` | 143685 | `1.0.release.962568596` (private-compute/GenAI forwarding) |
| `com.google.android.apps.recorder` | 42423113 | `4.2.20260709.976121876` |
| `com.google.android.inputmethod.latin` | 175963086 | `18.1.4.962075747-release-arm64-v8a` |
| `com.google.android.apps.pixel.agent` | 4396 | `1.26.281.05.pixel.release` (Pixel Screenshots) |
| `com.google.android.apps.pixel.psi` | 15282 | `18.20260731.08.pixel.release.26q3` (Device Intelligence) |
| `com.google.android.GoogleCamera` | 69623332 | `11.0.073.974803897.34` |
| `com.google.android.apps.photos` | 52331974 | `7.91.0.973540846` |
| `com.google.android.dialer` | 20053583 | `237.0.973536915-pixel2026` |
| `com.google.android.apps.translate` | 700981682 | `10.35.63.979927992.5-release` |
| `org.ostadix.pixelai.probe` | 2 | `0.1.1`, installed by this pass |

The read-only collector records every active split path and SHA-256. Representative base hashes:

```text
AICore base     67aa6c6cc457163d18b8cff35706eeffd60ac234fa10bf4f3b4b7bd8e1d45f57
AICore arm64    ced771931232d843df7634498e6cb0bf0758ef6a12d73c0464d06cf4b98a1aaa
ASI base        16d2b265fbea8c8abc46b537b6191628f7a855d7e3fd760b4a60bb6ea9c93e68
AS.OSS base     c08952bafbd19a4bcb4399aaebc17ae7b1685c8b20cad033a41b435fbfe3620c
```

### Live interfaces and init state

Observed framework/vendor binder registrations:

```text
android.hardware.contexthub.IContextHub/default
android.hardware.neuralnetworks.IDevice/google-edgetpu
com.google.edgetpu.IEdgeTpuAppService/default
on_device_intelligence
personal_context
```

Observed init properties:

```text
edgetpu_app_service=running
edgetpu_vendor_service=stopped
hal_neuralnetworks_darwinn=running
edgetpu_tachyon_service=<unset>
```

`dumpsys on_device_intelligence` resolves the framework services to:

```text
com.google.android.aicore/...AiCoreIntelligenceService
com.google.android.aicore/...AiCoreIsolatedService
```

That connector is dynamically bound and may show `Bound` during use and `Unbound` when idle. The
Tachyon init declaration exposes `com.google.edgetpu.tachyon.IComputeService/default` and
`android.hardware.npu.IScheduling/default`, but is explicitly `disabled`/`oneshot`; no live
Tachyon binder was observed.
The stopped vendor service is not evidence that the app service or Darwinn HAL is unavailable;
both of those were live.

### TPU runtime and installed model store

- `/dev/edgetpu` resolves to `/dev/edgetpu-soc`.
- `/vendor/etc/public.libraries.txt` exposes the Edge TPU client/util libraries, OpenCL, GXP,
  `libedgetpu_tachyon.google.so`, and `libedgetpu_litert.so`.
- `/vendor/lib64/libedgetpu_litert.so` is 6,183,536 bytes, SHA-256
  `efc4c6f4bc5dc8933afc260528d188ce5c39a36c107f23b96e6e2e80d29ae193`, build ID
  `b971...`, and exports Google Tensor runtime/context entrypoints.
- AICore ships Darwinn interpreter, model-loader, LLM, embedding, SentencePiece, and Edge TPU
  runtime libraries. ASI maps Edge TPU, TFLite, and SODA libraries in live processes.
- The live Edge TPU sysfs client table contained PIDs mapping to the Darwinn HAL, Edge TPU logging
  service, Google camera provider, and `com.google.android.as`, with active group records. This
  proves open device clients on this boot; it does not assign any observed inference to a feature.
- `/data/vendor/intelligence` occupied about 5.4 GiB with 192 files when inventoried. Its metadata
  hashes were `manifest.binarypb` (61,440 bytes,
  `bd045d18a0ac1ce8321d7fd8b58bc74c124dea489fe8ebf763cd92b6807e90e9`),
  `config.binarypb` (8,192 bytes,
  `78fca8e881cc79617362c28ff67bbb8d224c1e36440f851c5fc4aa971fa4eeca`), and
  `checkpoint.binarypb` (4,689,920 bytes,
  `1ffa3a04bf9bf4d7d801c4a6bdc3b85eea1b62516bc424d1f15ee84138979e44`). Its graph set includes
  audio adapter/feature/layer and cross-attention files. FlatBuffer/model strings include `TFL3`,
  Edge TPU custom operations, and Darwinn artifacts.
- AICore decompilation traces `RuntimeModelLoaderWrapper` and `RuntimeEdgetpu` native transitions;
  native strings include Edge TPU LLM execution and Pixel 10 TPU DVFS code.

These findings prove that compatible models and runtime code are deployed. They do not prove that
any particular request ran on the TPU.

### Android NpuManager and legacy NNAPI

Android 17 includes the NpuManager APEX/flags, but `android.hardware.npu` and a corresponding live
`npu` binder were absent. AICore's effective `AicCommon__enable_npu_manager_integration` was
`false`, and the service path enforces `ACCESS_NPU_MODEL_MANAGER_API`. This is not a safe flag to
toggle: the required platform feature/interface is absent.

The legacy `android.hardware.neuralnetworks.IDevice/google-edgetpu` HAL remains live. This is
consistent with Android's distinction: the app-facing NNAPI NDK API was deprecated starting in
Android 15, while the Neural Networks HAL remains supported. It is useful for reconstructing
existing apps, not the default foundation for new work.

### CHRE / always-on processing

`dumpsys contexthub` reports `CHRE on AoCv2`, software `1.12.28257`, 25 nanoapps, and registered
endpoints including ASI. Activity recognition, carried-position, Flip to Shhh, Columbus, and other
ambient paths are represented there. CHRE is a low-power AoC environment, not the Tensor TPU.
No sensor-event payloads were retained.

## 2. Reconstructed capability paths

### Architecture map

```text
third-party visible app
  -> ML Kit GenAI API -> AICore -> selected Gemini Nano feature/runtime -> unknown backend

Pixel system feature
  -> ASI -> AS.OSS GenAiInferenceService -> AICoreMultiUserService
  -> LLM / summarization / smart reply / embedding feature -> unknown backend

independent application/native executable
  -> LiteRT-LM / LiteRT dispatch -> libedgetpu_litert.so -> Tensor G5 TPU
  -> requires matching AOT model + matching dispatch/runtime ABI

non-GenAI local feature
  -> TFLite CPU/NNAPI, SODA, audio DSP, or CHRE depending on the feature
```

### Capability matrix

| Capability | Reconstructed path and present artifacts | Current state / backend conclusion |
|---|---|---|
| Public prompt / summary / image / advanced speech | Probe -> pinned ML Kit client -> AICore | Installed but foreground readiness not yet run; backend unverified |
| ASI GenAI forwarding | ASI `AiCoreLlmService` -> exported AS.OSS `GenAiInferenceService` -> `AICoreMultiUserService` | Live for ASI; direct third-party caller rejected by allowlist/signature policy |
| ASI Smart Reply | ASI handler -> AS.OSS/AICore feature request | Locale/model metadata present, but live log failed: no available feature `103` |
| Recorder transcription/summarization | Recorder UI -> SODA transcription and AICore summary clients | Concrete client/error/feature strings; controlled test not run; TPU placement unverified |
| Gboard proofread/rewrite/smart reply | Gboard UI -> AICore/Astrea clients with status/download and fallback logic | Implemented clients found; eligibility and execution not tested |
| Pixel Screenshots semantic features | Screenshot ingest -> embeddings/AppSearch -> memory/Q&A AICore services | Strong implementation evidence; controlled synthetic collection not tested |
| ASI offline speech | `SpeechRecognizer` -> `AiAiSpeechRecognitionService` -> SODA connector -> installed language pack | Models present; local speech path; processor placement unverified |
| Photo OCR | overview/screenshot bitmap -> signature content-suggestions API -> Smartrec PhotoOcr -> local models | Models match APK; privileged entry; TFLite/possible NNAPI; TPU unverified |
| Text classification | framework `TextClassifierManager` -> `QAiaiTextClassifierService` -> TextClassifierLib / superpacks | Active local implementation; no AICore or TPU evidence |
| Now Playing | SoundTrigger DSP -> internal service -> NnfpV3 native fingerprint -> local index | Local always-on implementation; audio DSP path, not TPU |
| Back-gesture ML | SystemUI gesture -> resource + DeviceConfig gate -> TFLite model -> score/threshold | Fully present but vendor resource disables it; plain CPU TFLite interpreter |
| Contextual/ambient features | system entry -> CHRE nanoapp on AoCv2 | Separate low-power processor; not TPU |
| Camera / Photos | app feature modules/native libraries/models | Broad ML implementation evidence; feature-by-feature backend tracing incomplete |
| Calling / Translate | package/component inventory and selected clients | Not enough evidence to label individual operations local or TPU-backed |

Selected evidence locations (the `/data/local/tmp` trees are working decompilations and are not
claimed reboot-persistent; package hashes above let them be reproduced):

| Finding | Evidence location |
|---|---|
| AS.OSS exported bridge/caller policy | `/data/local/tmp/ostadix-ai-audit-20260915/asoss-jadx/sources/com/google/android/apps/miphone/astrea/ai/service/GenAiInferenceService.java`; adjacent `defpackage/{fln,fmm,fmn,fmq,kae}.java` |
| ASI AICore smart-reply client | `/data/local/tmp/ostadix-ai-audit-20260915/asi-jadx/sources/com/google/android/apps/miphone/aiai/autofill/candidates/aicoresmartreply/AiCoreLlmService*.java` |
| ASI offline speech entry | `/data/local/tmp/ostadix-ai-audit-20260915/asi-jadx/sources/com/google/android/apps/miphone/aiai/app/AiAiSpeechRecognitionService.java` |
| ASI text classifier | `/data/local/tmp/ostadix-ai-audit-20260915/asi-jadx/sources/com/google/android/apps/miphone/aiai/textclassifier/service/QAiaiTextClassifierService.java` |
| ASI Now Playing | `/data/local/tmp/ostadix-ai-audit-20260915/asi-jadx/sources/com/google/android/apps/miphone/aiai/nowplaying/api/NowPlayingService.java` |
| AICore Java-to-native runtime | `/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/com/google/android/apps/aicore/runtime/wrapper/RuntimeModelLoaderWrapper.java`; `runtime/impl/edgetpu/RuntimeEdgetpu.java`; `inference/tflite/DarwinnInterpreter.java` |
| Back-gesture consumer/provider | `/data/local/tmp/ostadix-ai-audit-20260915/sysui-jadx/sources/com/android/systemui/navigationbar/gestural/EdgeBackGestureHandler.java`; `.../com/google/android/systemui/gesture/BackGestureTfClassifierProviderGoogle.java` |
| Repeatable live inventory | `audits/pixel-ai-20260915/collect-readonly.sh` |

### ASI -> AS.OSS -> AICore details

AS.OSS exports a `GenAiInferenceService` without a manifest permission, but that is not a public
interface. Its binder code identifies the calling UID's package, hardcodes `com.google.android.as`
as the allowed caller, and can apply a signature security policy. The exact rejection string is:

```text
Caller is not allow-listed for AICore service forwarding.
```

Effective flags were live and enabled:

```text
PcsAi__enable_genai_inference_service=true
PccSecurity__enable_genai_inference_service_security_policy=true
```

Live service dumps showed ASI bound to AS.OSS and AS.OSS bound to AICore. The same AICore service
dump showed live `AiCoreMultiUserService` bindings from Gboard and Pixel Screenshots as well as
AS.OSS. This establishes working system integrations on this build, not a supported generic
third-party API. The minimal safe developer path is the public ML Kit API, not impersonating ASI or
patching its security policy.

### Offline speech, OCR, classification, and ambient features

- ASI's exported speech recognizer forces/prepares an offline path through SODA. The installed
  `/product/usr/srec/en-US` pack is about 92 MiB and includes encoder, punctuation, language-ID,
  and speaker-related TFLite/model artifacts. Native code contains Darwinn/Tachyon paths, but that
  does not establish which backend this particular recognition request uses. Selected artifact
  hashes: `medium-encoder.tflite`
  `3539404429a53e7f96ea9754f9826e35006609665cacfda06313c94fde703ce1`,
  `medium-decoder.tflite`
  `53a37c2d0072120c0013ea8d021c48189c6bf2401801d89c2ef308f05af6b224`, and
  `SODA_punctuation_model.tflite`
  `a8d841673c8b5df032dffa579931181c5cdbce104454e05a49bf76d2fa5d6046`.
- Photo OCR assets under ASI private storage match the APK's model set. The service entry is
  signature-protected; high-level code uses TFLite and contains alternate NNAPI configurations.
- The framework text-classifier path is locally active and uses model superpacks/fallbacks. Direct
  binding is signature protected, while the framework API is the intended entry.
- Now Playing uses SoundTrigger/audio DSP and a native neural fingerprint implementation. It is a
  useful on-device capability but not a TPU workload.

### Back-gesture ML lead resolved

The earlier `config_useBackGestureML=false` lead was traced end to end:

```text
base SystemUI resource=true
vendor overlay=/vendor/overlay/SystemUIGoogle__blazer__auto_generated_rro_vendor.apk
effective resource=false
DeviceConfig use_back_gesture_ml_model=true
DeviceConfig back_gesture_ml_model_name=backgesture
DeviceConfig threshold=0.8
```

SystemUI's `EdgeBackGestureHandler.updateMLModelState()` requires both the effective resource and
DeviceConfig value. Models are installed in `SystemUIGoogle.apk`, including
`backgesture.tflite` (520,656 bytes, SHA-256
`270b0b7b6df44e87c4dc72b4841a83411d41d137bd29eb4f1bd1a909031384c1`) and
`backgesture1000.tflite` (16,360 bytes, SHA-256
`e051cd379469052f547883129fc5363d48126b62713502e3072ec406839babc3`), with vocabulary assets. The provider calls
plain `org.tensorflow.lite.Interpreter` and loads only `libtensorflowlite_jni`; no delegate is
installed in this path. The model is therefore a CPU TFLite classifier, not a TPU feature.

Enabling the resource would change gesture acceptance and false-positive behavior. With no
accuracy/latency test showing a benefit, it was correctly left unchanged. A reversible experiment
would require a narrow overlay, recorded gesture corpus, false-positive/false-negative comparison,
and removal of that overlay as rollback.

## 3. Developer interfaces tested early

### Foreground ML Kit/AICore probe

Source: `apps/pixel-ai-probe/`

Pinned official dependencies:

```text
com.google.mlkit:genai-prompt:1.0.0-beta4
com.google.mlkit:genai-summarization:1.0.0-beta1
com.google.mlkit:genai-image-description:1.0.0-beta1
com.google.mlkit:genai-speech-recognition:1.0.0-alpha1
```

The app:

- asks readiness before inference and never starts a download automatically;
- reports prompt base-model name, token limit, request tokens, timings, and complete ML Kit error
  chains;
- uses a deterministic synthetic compiler log for the useful log-analysis demonstration;
- uses a >400-character synthetic article and an in-memory generated bitmap;
- checks advanced speech readiness only and requests no microphone permission;
- reads no files, media, messages, photos, audio, credentials, or other app data;
- cancels futures and closes clients on pause or focus loss;
- requires resumed + focused + unlocked state before any button or automation call.

Manifest-merger parity was reviewed across all 42 resolved AARs. The hand-written manifest keeps
the direct-call requirements (ML Kit initializer/discovery, AICore query/bind permission, speech
network/TTS declarations, GMS metadata) but intentionally omits transitive DataTransport
telemetry/job/alarm components, AndroidX Startup, and `GoogleApiActivity`. Bytecode inspection found
no direct GenAI-call dependency on the latter components; absent DataTransport discovery drops its
telemetry asynchronously rather than failing inference. This avoids adding background scheduling.
Any first-call exception will still be retained rather than assuming the omission is harmless.

The hardened APK built and installed successfully, and its on-device hash matched the build
artifact:

```text
package=org.ostadix.pixelai.probe
version=0.1.1 (2)
APK_SHA256=da54cae70993a62b1a52257dda36707cff4e5d0920ff9ea8d4f088cc62f9d50e
APK_signature=v2:true,v3:true
installed_hash_matches_build=true
```

The earlier version 1 artifact (SHA-256
`499f5528763abfe9b8fc1c4c6ddf4edba9fdfbebf7293c3d6eec19d7ed11196f`) was replaced with
`pm install -r`; it is not the currently installed artifact.

The initial launch evidence was:

```text
deviceLocked=1
currentFocus=NotificationShade
focusedApp=org.ostadix.pixelai.probe/.MainActivity
probe lifecycle=foreground, then paused
result=no controlled request completed
```

This exposed a lifecycle distinction: a resumed Activity is not necessarily visibly top and
unobscured. A cold `ACTION_MAIN` launch of installed version 2 behind keyguard then proved the
fail-closed gate without sending a probe action:

```text
version=0.1.1
[lifecycle] resumed
Probe calls disabled; resumed=true; windowFocus=false; deviceLocked=true
[lifecycle] paused
Cancelled pending futures and closed ML clients
readiness_or_inference_events=<none>
cold_activity_total_time_ms=141
```

The 141 ms value is only UI/process cold launch behind keyguard; it contains no AICore/model work
and is not an inference-startup measurement. Actual feature statuses will be added after operator
unlock and execution.

Official constraints accounted for in the design: public GenAI inference is allowed only for the
top foreground app; a foreground service is insufficient; AICore applies quotas; readiness may be
`AVAILABLE`, `DOWNLOADABLE`, or `UNAVAILABLE`; and Google's docs say unlocked bootloaders are
unsupported. No inference result from this API alone would prove TPU placement.

### Native Tensor runtime probe

Source: `audits/pixel-ai-20260915/native/`

The narrow native probe dynamically loads the installed public `libedgetpu_litert.so`, resolves the
documented vendor/runtime context functions, initializes, creates one empty context, deletes it,
and exits. It was built and run under the existing root/KSU context:

```text
binary_sha256=df72e0524d11b0e0bac555367c55181bd51ab3fddf5529f9cc180bccc2ca9361
caller=uid=0(root), u:r:ksu:s0
library=libedgetpu_litert.so
vendor_api_version=0.20.0
vendor_id=sb_pixel
initialize_status=0
context_create=non-null
context_delete_status=0
```

This proves that the installed Tensor dispatch substrate can be loaded and initialized from a
native process with root context. It is not model loading, inference, an app-supported API, or TPU
execution proof.

### Independent LiteRT-LM route

The current Android ARM64 LiteRT-LM Python wheel was inspected and exercised locally:

```text
litert_lm_api=0.17.0
wheel_size=13,970,245
wheel_sha256=91fdf62721a624a6b91c04228021c6781b1383e7142087deb9fe51acf40df9a1
embedded_library_sha256=af525a713b7ac4d5c7c93280075139b8cbf3cc22e9aea6f9f34484166fc2e7ba
import=ok
backend_construct=ok
backend_name=npu
```

Constructing the NPU backend only creates configuration; it does not load a model or invoke TPU
hardware.

The exact G5 artifact currently listed by the official guide/model repository is:

```text
repo=litert-community/Gemma3-1B-IT
revision=a6306a4e292016480083b73b8dc6f3f939ae04c3
file=Gemma3-1B-IT_q8_ekv1280_Google_Tensor_G5.litertlm
size=1,678,542,365 bytes
quantization=8-bit per-channel
context=1280
anonymous_resolve=HTTP 401, x-error-code: GatedRepo
```

No model was downloaded and no Hugging Face credential was present. The docs' generated example
URL still says `q4`, while the G5 support table/repository exposes the `q8` artifact above; the
artifact table/repository must win over blind substitution.

ABI inspection found that generic LiteRT dispatch artifacts from other release tracks are not safe
to mix blindly with the LiteRT-LM 0.17 runtime. The smallest reproducible path is:

1. Accept the gated repository terms and authenticate outside this audit.
2. Download only the exact G5 q8 artifact and record its post-auth SHA-256.
3. Build LiteRT-LM and its Google Tensor dispatch from one matched source/release. For the inspected
   0.17 wheel, its pinned LiteRT commit is
   `9fe5be45564c868408e6514c8aabb83e211a0911`; build
   `@litert//litert/vendors/google_tensor/dispatch:dispatch_api_so` for Android ARM64.
4. Deploy the matched main/Python runtime, dispatch library, and model together.
5. Run a fixed prompt with `backend=npu`, bracket it with Edge TPU trace/counters, and compare an
   equivalent output/backend where available.

The current Tensor SDK release track separately documents LiteRT 2.1.6 for G5 compiled-model work.
That does not establish ABI compatibility with the separately versioned LiteRT-LM 0.17 wheel.

The investigation covered LiteRT-LM 0.17, the Android wheel, the pinned
LiteRT source, comparison runtime archives, and failed build evidence.
Key retained hashes are:

```text
LiteRT pinned source tar 5dbb113744e103f899c7b1b7c5479126b36a0b7414c3d971185c1f02041bfa39
LiteRT-LM Android wheel  91fdf62721a624a6b91c04228021c6781b1383e7142087deb9fe51acf40df9a1
2.1.6 runtime archive    98aabbdce8607f6dc6ab7cb92217326eef24a8c97b973b69e62bd0ce14b7495b
2.2.0 runtime archive    b4c8380df3e9652677dbb93a5aad4499eb756a9b7d9651a9baacb122faadbf0d
```

### Custom models and Tensor SDK

The current Tensor SDK is a beta supporting Tensor G5. Its documented preparation environment is
an x86-64 Linux workstation (Ubuntu 22.04, Bazel 7.4.1, Android SDK/NDK; at least 16 GiB RAM, more
for large models). Google Tensor currently supports AOT execution; its SDK does not yet provide
on-device JIT compilation. Thus:

```text
workstation: conversion -> compatibility check -> Tensor G5 AOT compile -> packaged model
phone: matching LiteRT runtime/dispatch -> load compiled artifact -> inference
```

This Termux ARM64 phone is a valid execution/test target, not the documented full compiler host.
Compiler controls such as representation, sharding, large-model handling, and low-bit options are
model-quality/performance choices that require output validation; they are not Android flags.

## 4. Demonstration status

Two pieces of new software were produced:

1. The native runtime probe above, which successfully initializes and destroys an `sb_pixel`
   Tensor runtime context under root.
2. A foreground Android ML Kit probe with a useful synthetic build-log analysis operation and
   readiness tests for prompt, summarization, image description, and advanced speech.

Only item 1 has completed its runtime test. Item 2 is installed, but its controlled foreground call
is intentionally pending unlock. Therefore the requested useful local inference demonstration is
**not yet complete**, and the report does not relabel a readiness/client/library result as one.

## 5. Execution verification and measurement

### Available observability

- Tracefs exposes Edge TPU event families for client/group creation and VII commands/responses,
  with common PID/client identifiers.
- Sysfs exposes `inference_count`, operation/utilization/cycle/stall counters, cache counters,
  preemptions, reconfiguration, firmware crash/watchdog counts, firmware version, clients, and
  groups.
- PowerStats exposes a cumulative `TPU` energy consumer plus `S7M_VDD_TPU` and
  `S9M_VDD_TPU_M` rails, TPU DVFS, and residency information.
- Process memory, CPU time, wall latency, and thermal service data are available.

An isolated 15-second trace baseline captured no Edge TPU event, with `inference_count=16` stable,
and the private trace instance was removed. Later idle collection showed `inference_count=17` and
cumulative TPU energy increasing from about 365.47 mWs to 780.99 mWs. That background change is
important negative evidence: an unbracketed counter/rail delta cannot be attributed to this probe.

The measurement harness in this directory:

- refuses to run when the device is locked;
- verifies the probe is the top/resumed focused app;
- creates a private Edge TPU trace instance and removes it on exit;
- snapshots inference counters, TPU rails/consumer, thermal state, CPU/memory, and logs;
- triggers exactly one stable synthetic probe action;
- waits with a bounded timeout and reports observed trace/counter correlations.

Testing should be performed cool and preferably unplugged. The audit's idle thermal snapshot was
already `MODERATE` while charging, with virtual skin around 43 C and no reliable direct TPU sensor.
Those conditions are unsuitable for defensible comparative energy/thermal conclusions.

A complete comparison still needs separate measurements for:

- process/app cold start;
- model/client initialization;
- input preparation/tokenization or bitmap conversion;
- first inference and warm repetitions;
- output handling;
- median/tails, memory, CPU, TPU energy/rails, and thermal state;
- equivalent output quality and observed fallback/unsupported operations.

## 6. Packaged work and rollback

| Artifact | Purpose | State |
|---|---|---|
| `apps/pixel-ai-probe/` | Foreground public ML Kit/AICore readiness + synthetic demo | Source/build/tests complete; hardened v2 APK installed; foreground run pending |
| `audits/pixel-ai-20260915/collect-readonly.sh` | Repeatable package/service/model/runtime inventory | Run successfully; read-only |
| `audits/pixel-ai-20260915/measure-foreground.sh` | Request-bracketed TPU/system measurement | Pending unlock/run |
| `audits/pixel-ai-20260915/native/edgetpu_sb_probe.c` | Minimal vendor runtime initialization | Built and run successfully |
| `audits/pixel-ai-20260915/native/build-and-run.sh` | Reproduce native probe | Verified |
| `audits/pixel-ai-20260915/REPORT.md` | Findings, evidence, blockers, rollback | This report |

Build the Android probe:

```bash
cd /data/data/com.termux/files/home/Ostadix-lang/apps/pixel-ai-probe
./build.sh
```

Build/run the native probe in the caller's current root/KSU context:

```bash
cd /data/data/com.termux/files/home/Ostadix-lang
audits/pixel-ai-20260915/native/build-and-run.sh
```

Run the read-only inventory:

```bash
cd /data/data/com.termux/files/home/Ostadix-lang
audits/pixel-ai-20260915/collect-readonly.sh
```

Rollback the installed Android component:

```bash
pm uninstall org.ostadix.pixelai.probe
```

The app is a normal user package and is persistent across ordinary process restarts by package
manager design, but reboot survival was not actually tested. There is no separately installed
native service, boot script, overlay, or model.

## Exact blockers and next smallest experiments

1. **Secure keyguard / foreground requirement.** Unlock the phone and leave the probe visible.
   Rebuild/reinstall the hardened APK, then run readiness only. Record all four statuses and errors.
2. **Public API readiness.** If prompt is `AVAILABLE`, run one deterministic synthetic build-log
   request inside the measurement harness. If it is `DOWNLOADABLE`, do not download without an
   explicit decision; record that exact state. If `UNAVAILABLE`, preserve the AICore error without
   clearing data, relocking, or changing identity.
3. **TPU attribution.** Correlate the request interval with Edge TPU trace events, client/PID,
   `inference_count`, and rails. If observability cannot associate a client, state placement as
   unverified even if latency is good.
4. **Existing OS capability.** Use a synthetic image/text collection in Pixel Screenshots or
   synthetic audio in an explicitly selected offline speech client. Verify results and network
   behavior before claiming fully local execution.
5. **Independent NPU model.** Accept/authenticate the gated Gemma repository, verify the exact G5
   q8 artifact hash, and build a release-matched LiteRT-LM/dispatch on supported x86-64 Linux.
6. **Optimization.** Only after a working path exists, compare full cold/warm workflows under sane
   thermal/power conditions. Keep optional new capability costs separate from efficiency claims.

## Official references checked on 2026-09-15

- https://developer.android.com/ai/gemini-nano
- https://developers.google.com/ml-kit/genai
- https://developers.google.com/ml-kit/genai/prompt/android/get-started
- https://developers.google.com/ml-kit/genai/summarization/android
- https://developers.google.com/ml-kit/genai/image-description/android
- https://developers.google.com/ml-kit/genai/speech-recognition/android
- https://developers.google.com/edge/litert/next/litert_lm_npu
- https://developers.google.com/edge/litert-lm/android
- https://developers.google.com/edge/litert/next/tensor-sdk
- https://developers.google.com/edge/litert/next/npu
- https://developers.google.com/edge/tensor-sdk/release-notes
- https://source.android.com/docs/core/interaction/neural-networks
- https://huggingface.co/litert-community/Gemma3-1B-IT

## Final accounting

### Foreground follow-up (2026-09-15 16:32 UTC)

The device was later observed unlocked and the hardened probe reached its full
resumed + focused + unlocked gate. Real public AICore requests completed their
preparation/error callbacks, resolving the earlier keyguard blocker:

```text
prompt feature 636: error 606 FEATURE_NOT_FOUND, UNAVAILABLE, no inference
image feature 627: error 606 FEATURE_NOT_FOUND, no inference
summary feature 622: error 606 FEATURE_NOT_FOUND, no inference
```

Prompt reported an 8192-token client limit. The first prompt sequence completed
in 317 ms and a later warm sequence in 38 ms; image and summary error sequences
completed in 26 ms and 27 ms. These timings measure feature lookup/preparation
failure, not model inference. Because all installed public features were
missing, there is still no successful controlled inference or TPU attribution.
Some previously queued automation actions also dispatched while the Activity
was focused; each used only its documented synthetic constant and completed at
the same pre-inference feature gate.

The subsequent read-only runtime-readiness probe found the service alive and
bound to real clients, but found zero framework inference records, zero private
model-payload candidates, and zero live model-file mappings. Protected-download
manifest retrieval was repeatedly failing, and Gboard independently reported
features 703 and 607 unavailable. `AICORE_PRELOAD_MODEL` was initially enqueued
after 11 WorkManager attempts, then reached terminal `FAILED(3)` on attempt 12
with stop reason `-256`; model payload/mapping and inference counts remained
zero. This locates the current blocker at model provisioning, before an OSTADIX
insertion point or model session can be exercised. See
`check-aicore-runtime-readiness.sh`.

Recovered AIDL establishes concrete ownership for the future insertion:
`runCancellableInference` returns an `ICancellationCallback`, while
`LLMRequest.closeAllFileDescriptors()` owns cleanup of image/audio/embedding,
LoRA, session-state, and prefix-cache descriptors. `LLMResult`/`LLMReply` carry
parcelled text, score, stop reason, policy scores, citations, and metadata. The
OSTADIX contract test now consumes a bounded `OValue` projection of those real
reply fields, filters unsafe or unfinished candidates, and deterministically
ranks the remainder. This is reusable seam validation, not a claim that AICore
invokes OSTADIX on the currently unprovisioned device.

The same checked-in O program is reused by a 12-request resource-lifecycle
test. It measured 516.949 ms p50, 532.221 ms p95, 5,796 KiB peak RSS growth,
zero file-descriptor growth, and no backend child remaining after runtime drop.
Those are debug OSTADIX host figures, not AICore/model or Android-production
overhead.

Rollback decision logic is now independently tested instead of relying only on
the installed-version success path. The exact AICore/AS.OSS snapshot passes;
eight one-field version/APK/signer mismatches and one malformed snapshot all
exit 3 with `disable_experimental_extension_only`. The live read-only package
collector continues to pass. No internal extension exists yet, so this proves
the compatibility decision contract, not an extension disable operation.

The embedding result is now evidence-bound using OSTADIX's existing machinery.
Preflight compiles `ExecutionIntentV1`; execution re-verifies it before V6
evidence/admission and dispatch; the result returns canonical source, intent,
OIR, plan, solved/admitted graph, evidence/admission, and typed-result content
identities. The full 10-stage Android build passed, and bounded JNI returned
those identities plus the canonical request-scope identity in a successful
5 ms smoke request. This strengthens proof of
which OSTADIX semantics ran, but is not a signed receipt and does not imply an
AICore caller.

The Android-compatible path now executes meaningful processing rather than a
literal-text smoke. A fixed Bash-backed O program receives only bounded scalar
reply metadata (score, stop reason, and maximum policy score), so AICore-owned
text, descriptors, sessions, and native buffers remain outside OSTADIX. The JNI
smoke selected index 0/score 600 in 85 ms, then index 1/score 950 in 105 ms when
only policy metadata changed. Both runs used the same 50-node plan, 81-node
HGraph, 14 executable edges, source identity, execution intent, and admitted
graph; scope/result identities changed. Unsafe-only input failed closed. The
seven-test host contract and complete ten-stage Android build pass. This proves
the packaged reusable seam, not an AS.OSS-to-OSTADIX call.

The JNI boundary now also maps an exact caller/request pair to an active core
cancellation token without blocking behind evaluation. Java lifecycle read
locks allow cancellation while a write lock excludes native destruction. The
release smoke waited for a Bash post-dispatch marker, cancelled and forcibly
reaped the actor in 126 ms, and then ran both selector requests on the same
runtime. A future AS.OSS seam can therefore propagate its owned
`ICancellationCallback`; no such hook is installed yet.

A disabled build-only Vector/libxposed API 102 experiment now models that
exact hook without changing the device. It captures the original Binder UID at
`fls.a`, transforms `LLMResult` at `fmz.onLLMInferenceSuccess`, consumes the
typed OSTADIX index by constructing a metadata-preserving one-reply result, and
propagates `flo.a` cancellation through both OSTADIX and AICore. It is pinned
to the exact firmware plus both package versions, APK hashes, and signer hashes;
requires an explicit global activation token; checks severe thermal state; and
fails open to the original result on transformation errors. The signed APK
(`262bdc3b7b75f076f2cfd3448e602d59652123d9b8546993c5be277fd9f3ef04`)
passes its result-replacement self-test and installed seam verifier. It was not
installed, scoped, or activated, and therefore is not direct-integration proof.

Live SELinux inspection shows AICore and AS.OSS both in `priv_app_36` and the
platform policy grants `appdomain` execute/map/open on `apk_data_file`. There
is therefore no categorical policy denial for a package-owned launcher, but
cross-package native loading, linker namespaces, and actual child execution
remain untested until installation is explicitly authorized.

- **Actually inspected:** device/build/kernel properties; the complete active split sets and hashes
  for central AI and selected Pixel apps; manifests/resources; selected decompiled Java and native
  transitions; effective overlays/DeviceConfig; binders/init state; model metadata; public vendor
  libraries; Edge TPU counters/traces/power interfaces; Context Hub summary; official developer
  routes.
- **Capabilities found:** live AICore/ASI/AS.OSS integration; installed on-device foundation-model
  assets; app clients for summarization, generative writing, semantic screenshot workflows, speech,
  OCR, text classification, Now Playing, and contextual sensing; an independent Tensor runtime.
- **Demonstrated:** root-context Tensor runtime initialization/context lifecycle; Android probe
  build/sign/install/lifecycle safety. No inference result or TPU placement yet.
- **Installed:** only `org.ostadix.pixelai.probe`; no daemon, overlay, service script, or model.
- **Unresolved:** public AICore readiness behind secure keyguard; request-attributable TPU execution;
  gated/matched independent G5 model route; whole-workflow performance/quality comparison.
