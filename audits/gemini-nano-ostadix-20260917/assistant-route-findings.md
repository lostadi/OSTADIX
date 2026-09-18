# Ordinary Pixel assistant to Gemini Nano: bounded routing review

## Implementation inspected

No application, hook, configuration, UI, or installed package was changed in
this review. The installed GSA base APK was re-read and SHA-256 verified:

`c227beb9468f1740c395e457d5f06fb780f288a89156d8487ef069953c1c359a`

The package manager still resolves that base APK at
`/data/app/~~9fZb6Q9HYF7DNY7pMFubGQ==/com.google.android.googlequicksearchbox-iPBfzurbJ98pcm3Op8ZjXQ==/base.apk`.

This review covered all 15 DEX files in that base APK, focused decompilation of
the relevant string owners, and printable strings in its 39 arm64 shared
libraries. Dynamic modules, the three installed Lens/tclib feature splits,
encrypted resources, complete native control flow, and runtime-only objects
were not analyzed. This is a search result within that scope, not a proof that
no possible Nano route exists.

The extension's `GeminiAppFunctionSchemaHooks` adds an `ostadix/executeO/v1`
function metadata entry to GSA's compiled schema inventory. It does not select
a model, instantiate an AICore client, specify a Nano feature ID, or verify a
returned model identity. Inventory-hook success cannot establish Nano routing.

## Observations from the installed code

### General Nano prompting route: not identified

The base APK's DEX string tables contain no matching package/class literal for
`android.app.ondeviceintelligence`, `android.service.ondeviceintelligence`,
`com.google.android.aicore`, or `com.google.mlkit.genai`, and no `Gemini Nano`
family literal. No general prompt request builder, Nano feature-ID selection,
Nano model-identity check, or Nano response callback reachable from the ordinary
Pixel assistant was demonstrated in this review.

The matching AICore string owners are captured in
`gsa-nano-string-owners.json`. `scan_gsa_nano_strings.py` walks DEX methods and
instruction boundaries to locate const-string references. Focused jadx
outputs used to check their meanings are under
`/data/local/tmp/ostadix-gsa-nano-dex/`.

### Candidate routes inspected and their actual meanings

| Candidate | Concrete code evidence | What it establishes |
| --- | --- | --- |
| `djyv.b(esxh, ListenableFuture)` | Invokes three existing SmartAction generators and logs that the AiCore SmartAction generator is not present. | This particular SmartAction aggregation implementation has no active AiCore generator. It does not establish absence of every other Nano path. |
| `aqzw.c(...)`, `aqug.a(byte[])` | Parse `dbud` / `dbuc` incoming `OnDeviceInferenceResult`. Their shared dependency `aqza` implements `com.google.android.glasses.sdk.ai.GlassesInferenceListener`; `aqza.a` connects to `GlassesAiModule`. | The apparent on-device model response boundary belongs to the glasses/AR integration. No Pixel Nano identity follows from its name. |
| `dmnf.a(dmmr, hdkj)` → `dmnm.a(dmmr)` | `dmnf` logs `#getOnlineLlmResponse`; its map selects `dmnm` or `dmoe`. `dmnm` constructs Google Generative Language HTTPS URLs for Gemini Pro/Flash model names. | This LLM abstraction is an online candidate. It does not meet the explicit Nano requirement, and its use by the ordinary assistant was not proved. |
| `bpmi.onViewCreated` → `bqvi` | Shopping test-menu setup requires both a non-production flag and successful decryption of a resource; the method only creates/shows menu UI. | An AICore-named shopping test-menu string is not a demonstrated generic inference route. No keys were sought, no flags were changed, and no test menu was activated. |
| `fjjr`, `fjkl`, `ahvl`, `dnyk` and native SODA strings | Speech initialization/configuration, audio encoder/transcript errors, speech native-library loading. | AICore references here describe speech processing rather than general `.O` synthesis. |

All native keyword matches in the base APK occurred in
`libgoogle_speech_jni.so` and `libsoda_jni_no_terse.so`, with `speech.soda.*`
configuration/protobuf names and speech-processor messages. See
`gsa-nano-native-strings.json`. No Nano family or general text-generation
interface was recovered by that literal scan. This does not replace native
control-flow analysis.

### Existing action-dispatch boundary remains usable but model-neutral

The inspected generic AppFunction executor `avje` forwards a parsed invocation
through `auyi.b(...)`; the established AppFunction broker then has an Ostadix
service entrypoint which forwards to the primary `o_execute` MCP operation.
That action path is independent of which model decided to call it. Registering
or observing that executor does not prove Nano selected the action.

## Live observations and their limits

This review performed only package identity checks and file analysis. It did
not submit a Gemini request and did not run an inference. The earlier probe's
Feature 636 failure is documented in `STATUS.md`; it must not be relabeled as
a result from the ordinary assistant or as a GSA feature-ID discovery.

The corrected provenance of the earlier ordinary assistant test is: the coding
assistant opened Gemini and entered the text; the user pressed Send. The
user-reported fallback response and absence of an Ostadix dispatch remain
negative evidence for that request. Its model identity is unverified.

## Unverified prerequisites and next connection

Two concrete prerequisites remain separate:

1. A functioning prompt-capable Nano request must return actual generated text
   with model identity from AICore/the Nano API. A configured family label,
   token limit, or installed service is insufficient.
2. The ordinary assistant query must be routed into that verified Nano request,
   and its response must pass a real function call with complete `.O` source to
   the existing `o_execute` path, followed by result consumption in the same
   assistant interaction.

The smallest grounded action interface is the existing source-first
`o_execute` operation. If the ordinary assistant's native Nano route cannot be
identified, a future explicit adapter could bridge an assistant query to the
public Nano Prompt API and then forward the generated invocation through that
same operation. Such an adapter would still need a demonstrated assistant
query/response boundary, cancellation, host-owned permissions, and correlation.
It has not been built or validated by this review. A separate probe or fixed
reply selector would not satisfy that missing assistant connection.

No feature-ID or model-identity value was invented, and no cloud model was
substituted for Nano.
