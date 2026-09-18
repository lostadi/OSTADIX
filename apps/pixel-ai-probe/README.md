# Pixel AI Probe

Current probe release: `0.1.3` (`versionCode=4`).

Foreground-only probe for the public ML Kit GenAI interfaces. Prompt, summarization, and image
description exercise the documented AICore route; advanced speech readiness is recorded separately
without assuming the same runtime or hardware backend. The probe reports feature readiness and,
only when a feature is already `AVAILABLE`, runs fixed synthetic requests. It accepts no user input,
reads no files or app data, requests no microphone permission, does not automatically download
models, and closes clients when the activity is paused.
Calls additionally require the activity window to hold focus while the device is unlocked. Losing
focus cancels outstanding futures and closes every client. Controlled automation intents remain
queued until that same resumed, focused, unlocked gate passes, so `onResume` behind the secure
keyguard cannot begin a readiness or inference request.

Pinned official APIs:

- `com.google.mlkit:genai-prompt:1.0.0-beta4`
- `com.google.mlkit:genai-summarization:1.0.0-beta1`
- `com.google.mlkit:genai-image-description:1.0.0-beta1`
- `com.google.mlkit:genai-speech-recognition:1.0.0-alpha1`

The prompt explicitly requests Gemini Nano through AICore with `STABLE` / `FULL`
model configuration by default. The controlled `RUN_PROMPT` intent accepts an
optional `nano_model` string: `stable_full`, `stable_fast`, `preview_full`, or
`preview_fast`. Unknown values fail before creating a client. Each explicit
choice checks only that variant and never enrolls in preview or downloads a
model automatically. It has no cloud model fallback. The requested configuration
is logged separately from returned model metadata and successful inference;
opening the Gemini assistant app alone does not establish Nano execution.

The prompt reports status, base-model name, token limit, synthetic request token count, and a
synthetic build-log analysis. Summarization uses an `ARTICLE` input over 400 characters. Image
description uses only a 256x256 bitmap generated in memory. Speech checks the published advanced
mode status; it never opens the microphone. Every UI/logcat result includes elapsed milliseconds.
`GenAiException` reports preserve the entire cause message chain, error code, and retry delay.

The hand-written manifest intentionally includes the components required for the direct ML Kit
calls, but does not add transitive DataTransport telemetry/job/alarm components, AndroidX Startup,
or `GoogleApiActivity`. Inspection of the resolved bytecode found no direct-call dependency on the
latter components; without DataTransport discovery, telemetry is dropped rather than scheduled in
the background. This keeps the probe narrow and avoids adding a background job. Any contrary
runtime failure must be preserved as evidence instead of silently adding components. Although the
published dependencies require normal `INTERNET` and network-state permissions, the probe has no
network code; runtime network observation is still required before making an offline claim.

## Build

The build is designed for this Termux environment and uses the installed ARM64 `aapt2`, `d8`, and
`apksigner`, plus Gradle only as a Maven resolver:

```bash
cd apps/pixel-ai-probe
./build.sh
```

The output is `build/outputs/apk/debug/PixelAiProbe-debug.apk`. The script resolves all transitive
artifacts, compiles and merges their resources, generates library `R` classes, creates multidex as
needed, signs the APK with an isolated debug key, verifies v2/v3 signatures and package metadata,
then prints its SHA-256 digest.

Audited version 4 artifact (four explicit Nano configurations):

```text
SHA-256 9e19524868997f11b43fa5fb5ca2b55edffe1f630581095d951df42764a09806
APK Signature Scheme v2=true, v3=true
```

Earlier version 3 artifact (explicit stable/full Nano target):

```text
SHA-256 ee0369e3fe2e7a01d7ed5dab2f17cf065d855672060e22d04a7a84126305b772
APK Signature Scheme v2=true, v3=true
```

The installed build and direct Nano availability result are recorded in
`audits/gemini-nano-ostadix-20260917/STATUS.md` at the repository root.

Earlier audited version 2 artifact:

```text
SHA-256 da54cae70993a62b1a52257dda36707cff4e5d0920ff9ea8d4f088cc62f9d50e
APK Signature Scheme v2=true, v3=true
```

The build does not perform a general Android manifest merge. The hand-written manifest includes
the ML Kit initialization provider and discovery service, AICore binding permission and package
query, speech network permissions and TTS package query, Google Play services version metadata,
and AndroidX component factory required by these resolved artifacts. It deliberately omits
transitive AndroidX emoji/process-lifecycle initializers, generic Google API error-resolution UI,
and DataTransport's CCT telemetry discovery and background-scheduler components because this probe
does not use those facilities. The pinned GenAI libraries may still attempt asynchronous metrics;
without the DataTransport backend declaration those metrics are dropped rather than scheduled for
upload. Runtime readiness and inference results—not manifest presence—remain authoritative.

## Controlled adb entrypoints

Installation and execution are intentionally not part of `build.sh`. After an operator installs the
APK, each probe can be launched visibly and independently for tracing:

```bash
adb shell am start -W -a org.ostadix.pixelai.probe.RUN_PROMPT \
  -n org.ostadix.pixelai.probe/.MainActivity
adb shell am start -W -a org.ostadix.pixelai.probe.RUN_SUMMARY \
  -n org.ostadix.pixelai.probe/.MainActivity
adb shell am start -W -a org.ostadix.pixelai.probe.RUN_IMAGE \
  -n org.ostadix.pixelai.probe/.MainActivity
adb shell am start -W -a org.ostadix.pixelai.probe.RUN_SPEECH_STATUS \
  -n org.ostadix.pixelai.probe/.MainActivity
adb logcat -s PixelAiProbe
```

For request-bracketed on-device tracing, first unlock the phone and leave this Activity visible,
then run one route at a time from the repository root:

```bash
audits/pixel-ai-20260915/measure-foreground.sh prompt
```

The harness refuses a locked, unfocused, or non-resumed run. Avoid `RUN_ALL` for measurement: its
concurrent clients make per-route hardware and energy attribution ambiguous.

Exact uninstall rollback:

```bash
pm uninstall org.ostadix.pixelai.probe
```

The buttons also have stable resource IDs: `probe_prompt`, `probe_summary`, `probe_image`,
`probe_speech`, `probe_clear`, and `probe_output`.

The speech alpha API exposes its readiness call as a Kotlin suspend method and currently has no
Java futures wrapper. The Java activity uses the artifact's actual `Continuation<Integer>` ABI for
that readiness check. It does not attempt speech inference.

Official starting references:

- https://developers.google.com/ml-kit/genai/prompt/android/get-started
- https://developers.google.com/ml-kit/genai/summarization/android
- https://developers.google.com/ml-kit/genai/image-description/android
- https://developers.google.com/ml-kit/genai/speech-recognition/android
