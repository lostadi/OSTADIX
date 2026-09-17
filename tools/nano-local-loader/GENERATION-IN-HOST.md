# Native generation inside the original AICore process

## Current checkpoint — 2026-09-17 17:35–17:36 UTC

**Implementation:** `NanoLocalProbe` now supports an explicitly requested native
generation session, response artifacts, dispatch/return evidence and session
cleanup. The canonical Java build used for the initial generation smoke was
installed as APK SHA-256
`5766bd0a5e5522d6b886d6c8e8491a031a0e2197478e952aaf29cc389ef6c568`;
the seven pinned native payloads were reused from the prior local build.

**Live observations:** genuine AICore PID 22419 / UID 10173 generated a response
to `The sum of 2 and 3 is` using explicit `matformer_0`, the derived config with
audio disabled, and a 32-token output limit. The response began ` 5.` and
repeated the arithmetic statement before an incomplete ending. Generation
enter/return spanned 5,109 ms; session/model/runtime cleanup and all 191
descriptor closures succeeded. See the
[current report](../../audits/gemini-nano-rebuild-20260917/STATUS.md)
and [actual run](../../audits/gemini-nano-rebuild-20260917/canonical-nano-text.json).

**Unverified:** an omitted matformer signature's default, a correct assistant
chat template, exact public Nano identity, `.O` synthesis/tool use by this
model, and the ordinary Pixel assistant connection remain unproved.

The API reconstruction, initial proposal and adaptation sketch below are
retained as historical design notes. Their statements that generation had not
yet been installed or executed are superseded by this checkpoint.

## Established boundary

The original classes from the installed AICore classloader provide:

| Original class | Boundary |
| --- | --- |
| `LargeLanguageModelWrapper` | private `long nativeCreateSession(long model, byte[] cfe)` |
| `StatefulSessionWrapper` | constructor `(long session)` |
| `StatefulSessionWrapper` | private `byte[] nativeGenerateResponse(long session, byte[] cer, Controller)` |
| `StatefulSessionWrapper$Controller` | `int process(float progress)` |
| `StatefulSessionWrapper` | private `void nativeUnload(long session)` |

Classes have prefix `com.google.android.apps.aicore.runtime.wrapper.`.
`cjn` initializes the same original `llm_wrapper_jni` library that `cje` uses.
Resolve it with `Class.forName("cjn", true, context.getClassLoader())` inside the
existing evidence-tracked library initialization. Do not add replacement classes
in a `com.google.*` package to the extension.

Stock `StatefulSessionWrapper.m2839a` returns **0 to continue**, **2 to cancel**,
and 3/4 for other stock stop conditions. Its ordinary Java wrapper calls native
generation synchronously under its session lock and parses the returned bytes as
`ceu`. A fresh session exclusively owned by the probe has no other caller.

## Initial explicit test

After a successful model-load/tokenizer result, extend the private manifest with
an explicit `generation` member and require its presence. Keep the initial test
fixed at **32 output tokens**, one sample, top-k 1, top-p 1, temperature 0, RNG
seed 123, and a 10-second cooperative generation deadline. Keep the existing
outer process watchdog for blocked JNI calls, thermal entry gate, activation
token, sender permission, request correlation, and cleanup.

Use a synthetic text such as `The sum of 2 and 3 is` for the initial raw-completion
test. Record the exact request bytes and actual returned bytes. This is a native
execution smoke test; its quality alone cannot establish the correct chat
template or assistant instruction-following behavior.

No callback should perform filesystem I/O or call an LLM. It should only count
callbacks and return the stop code. Use `SystemClock.elapsedRealtime()` and an
`AtomicBoolean` cancellation flag. A callback deadline is cooperative: the
original native implementation may block before invoking it. The existing
watchdog must encompass session creation, generation, and session cleanup.

### Session protobuf

The stock `cjj` builder has seed 123, integer defaults 1440 and 0, and boolean
true. It writes these into `cfe` extension 100, type `cfq`:

```text
cfe {
  [100] cfq { 1: 123, 2: 1440, 3: 0, 4: true }
  18: 0  // stock default session version
  20: 0  // text input mode
}
```

The seed comes from `bhn.f3082t` via `ccr -> cjj.f6152a`. Do not use `cfe` field 2
as the seed. The native meaning of the 1440 and 0 defaults has not been fully
recovered; preserving the original builder values avoids inventing parameters.
Omit optional LoRA, prefix-cache state, audio/image configuration, and feature
identity fields for this isolated test.

### Request protobuf

```text
cer {
  2: float(0.0)          // temperature
  3: 32                 // max output tokens
  5: 1                  // top-k
  6: 1                  // sample count
  11: ceq {
    1: cdv { 1: "The sum of 2 and 3 is" }
    10: 1               // single text generation mode
  }
  14: float(1.0)        // top-p
}
```

`ceq` field 3 defaults to true in the original protobuf. The prompt is the nested
`cer.11 -> ceq.1 -> cdv.1` string, **not `cer` field 4**.
`evidence/stock-wire-verification-complete.json` records a successful live check
using the installed APK's original `cer`, `cfe`, `cfq`, `ceu`, and `cdw` parsers.
That check validates the wire encoding; it does not establish model execution.

The existing standalone `Wire` encoder supports fixed32 floats. The extension's
small nested encoder currently needs that operation added before encoding these
sampling values. No protobuf runtime or duplicate native wrapper is required.

## Reflection and original-interface proxy

The following is an adaptation sketch for the existing `Attempt`, not installed
source. It assumes `modelWrapper` and `model` already hold the successfully loaded
original wrapper/handle, `sessionConfig` and `request` contain the bytes above,
and `invokeNative` retains its enter/return/failure evidence behavior.

```java
ClassLoader host = context.getClassLoader();
Class<?> sessionClass = Class.forName(
    "com.google.android.apps.aicore.runtime.wrapper.StatefulSessionWrapper",
    true, host);
Class<?> controllerClass = Class.forName(
    "com.google.android.apps.aicore.runtime.wrapper.StatefulSessionWrapper$Controller",
    false, host);
Method createSession = modelWrapper.getClass().getDeclaredMethod(
    "nativeCreateSession", long.class, byte[].class);
Method generate = sessionClass.getDeclaredMethod(
    "nativeGenerateResponse", long.class, byte[].class, controllerClass);
Method unloadSession = sessionClass.getDeclaredMethod("nativeUnload", long.class);
createSession.setAccessible(true);
generate.setAccessible(true);
unloadSession.setAccessible(true);
Constructor<?> sessionConstructor = sessionClass.getDeclaredConstructor(long.class);
sessionConstructor.setAccessible(true);

final AtomicBoolean cancel = new AtomicBoolean(false);
final AtomicInteger callbacks = new AtomicInteger();
final long deadline = SystemClock.elapsedRealtime() + 10_000L;
Object controller = Proxy.newProxyInstance(host, new Class<?>[]{controllerClass},
    (proxy, method, arguments) -> {
        if (method.getDeclaringClass() == Object.class) {
            switch (method.getName()) {
                case "toString": return "OstadixNanoSyntheticController";
                case "hashCode": return System.identityHashCode(proxy);
                case "equals": return proxy == arguments[0];
                default: throw new UnsupportedOperationException(method.toString());
            }
        }
        if (!method.getName().equals("process")
                || method.getReturnType() != int.class
                || method.getParameterCount() != 1
                || method.getParameterTypes()[0] != float.class) {
            throw new UnsupportedOperationException(method.toString());
        }
        if (callbacks.incrementAndGet() > 4096
                || SystemClock.elapsedRealtime() >= deadline) cancel.set(true);
        return cancel.get() ? 2 : 0;
    });

long session = 0;
Object sessionWrapper = null;
try {
    // cjn must already have initialized under a library-init evidence event.
    session = (Long) invokeNative("session_create", createSession,
        modelWrapper, model, sessionConfig);
    if (session == 0) throw new IllegalStateException("zero native session");
    sessionWrapper = sessionConstructor.newInstance(session);
    verifyEvidence();
    // Mark inference_dispatched=true immediately before this invocation.
    byte[] response = (byte[]) invokeNative("generation", generate,
        sessionWrapper, session, request, controller);
    // Mark inference_returned=true even if later decoding fails.
    verifyEvidence();
    if (response == null || response.length > 4 * 1024 * 1024)
        throw new IllegalStateException("invalid or oversized response");
    // Persist raw response hash/bytes and decode ceu.field1 -> cdw candidates.
    // A cancellation records returned data as partial, not a passing response.
} finally {
    if (session != 0 && sessionWrapper != null) {
        // Run cleanup even when evidence storage, activation, or thermal gates fail.
        invokeNative("session_unload", unloadSession, sessionWrapper, session);
    }
}
```

Implementation details needed when integrating the sketch:

- Recognize `session_unload` as cleanup in `invokeNative`, alongside model unload
  and runtime free. Cleanup must still execute after a gate closes or evidence
  write fails. Preserve an earlier exception and attach cleanup failures.
- Resolve/initialize classes and constructors before creating a session. An
  unexpected constructor failure after obtaining its handle must record the
  cleanup failure rather than claiming that session cleanup succeeded.
- Always unload the session before unloading the model, then free the runtime.
- Emit `native_call_active=true` before each native call and false on its return
  or failure. Keep `request_id`, actual PID/UID, and terminal `complete` unchanged.
- Add truthful `inference_dispatched` and `inference_returned` fields. The current
  load-only probe always reports `inference_executed=false`; leaving that field
  unchanged during generation would be misleading.
- Write response protobuf bytes to a bounded request-specific private artifact;
  log hashes and decoded synthetic text. Do not invent a successful answer if
  there are no candidates, cancellation, or a native exception.

## Prompt formatting evidence

Stock `ccs.mo2437h` obtains the feature prompt template from `cdl.m2465g(hfw)`.
`ccr.m2443m` applies that template before converting text to `cdv` parts. With an
empty template, it appends the raw text parts directly. Other supported cases
include exactly one `[AICORE_GROUP_PLACEHOLDER]` or positional string formatting.
These transformations happen in Java before the native generation request.

There is no role member in the text `cdv` used here. Thus a user/model role
template must be explicitly present in the text if the feature requires one.
The local factory weights/config do not by themselves identify the registered
feature's prompt template. Do not treat successful tokenization as evidence that
a chat template was selected.

Read-only inspection of the actual decoded checkpoint's embedded tokenizer found
262144 pieces and these exact entries:

Checkpoint: `/data/local/tmp/ostadix-nano-rebuild-20260917/checkpoint.decoded.pb`,
SHA-256 `50f79aa10d36bf5f9d81e9dcec1d0aeef83ffeaea8662c7d9b5b17cc87c80291`.
The tokenizer is checkpoint field 2; its repeated field 1 entries contain piece
text in field 1 and type in field 3. IDs below are the entries' zero-based order.

| Piece | ID | Recorded SentencePiece type |
| --- | ---: | ---: |
| `<eos>` | 1 | 3 |
| `<bos>` | 2 | 3 |
| `<ctrl40>` | 46 | 4 |
| `<ctrl41>` | 47 | 4 |
| `<ctrl46>` | 52 | 4 |
| `<ctrl99>` | 105 | 4 |
| `<ctrl100>` | 106 | 4 |

The actual vocabulary contains no literal `<start_of_turn>` or `<end_of_turn>`
piece. Stock `ccr.java` lines 205 and 228 construct function declaration text
using `\n<ctrl99>developer\n<ctrl40>` and `<ctrl41><ctrl100>\n`. This is direct
evidence for that developer-tool formatting only. It does not prove that a
guessed `<ctrl99>user ... <ctrl99>model` template is the correct feature prompt.
The first completion smoke should therefore preserve and label its exact raw
input; template recovery and assistant routing remain separate work.

## Matformer choice

The factory config's variant-3 message has field 13 strings `matformer_0` and
`matformer_1`, plus field 17 records for both. Native code contains checks for a
session matformer signature and errors for unsupported signatures. Stock Java
copies optional `hfw.f18292B` through `cjj.f6166o` to `cfe` string field 9.

The field-9 association with the native matformer signature was subsequently
confirmed by following the C++ serializer and session state comparison; see
`../../audits/gemini-nano-rebuild-20260917/MATFORMER-SESSION-FIELD.md`.
The native behavior when the field is absent remains under
analysis. Do not label the absent value as a proven `matformer_0` default.
Preserve the minimal original-builder absence until the default is established;
if native session creation rejects it, report the actual error before selecting
another configuration. Neither branch's cost or generation compatibility has
been measured here.

## Optional modality loading

Later read-only disassembly confirms that the factory config's V3 submessage
uses optional **field 5 for image** and **field 6 for audio**. Their absence
selects the native `aicore::NoImageEncoder` and `aicore::NoAudioEncoder` branches.
The V3 audio loader explicitly joins the literal `frontend.tflite` to the model
directory and loads it as a CPU graph. This explains the corresponding live
missing-file failure during model loading even for a text-only caller.

The five-field JNI loader config `cfa` has no modality switch. `enable_ssv2`
(field 5 in `cfa`, distinct from factory config field 5) is propagated into the
model object after resource loading; it is not an established way to omit the
audio graph. A derived factory config can instead omit exactly the V3 image and
audio submessages, preserving all original weights. Such a config must carry its
own identity and retain the original config for comparison. Disassembly alone
does not prove that this derivative can create a working text generation session.

`evidence/native-optional-modalities.json` preserves the actual native library
hash and disassembly proving the wire fields, presence checks, hardcoded frontend
name, and SSV2 flag ordering. No model payload or Java source was changed during
this analysis.

## Evidence limits

This note contains static API reconstruction, actual tokenizer-file inspection,
and a previously observed successful original-protobuf parser check. It contains
no successful Nano model load, generated answer, assistant invocation, or
Ostadix execution. Parent-controlled live model-load evidence is recorded
separately under `audits/gemini-nano-rebuild-20260917`.
