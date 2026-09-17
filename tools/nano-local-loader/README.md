# Local AICore native loader reconstruction

This is owned Java source for the observed JNI ABI in the installed AICore
runtime. It reuses the device's original native libraries. It does not rebuild
Google's native implementation, model weights, or AICore application.

## Implementation

`NativeLoaderProbe` loads the runtime and loader JNI entrypoints, creates a native
runtime object, and frees it. It never opens a model or runs inference.

`LocalModelProbe` adds the recovered protobuf boundary for a local model load and
unload. An optional `tokenText` property requests tokenizer information. A
separate `SyntheticGenerationProbe` entrypoint exposes bounded generation;
`LocalModelProbe` rejects manifests containing generation instructions. Its host
manifest supports:

```json
{
  "baseDirectory": "/absolute/staged/base",
  "modelName": "relative/model/directory"
}
```

Alternatively replace `baseDirectory` with `files`, an object mapping logical
relative model filenames to absolute existing files. Descriptors stay open until
the model is unloaded. This mode has been implemented, not yet run on a model.

The recovered `cfa` protobuf boundary is:

| Field | Wire value | Observed use |
| --- | --- | --- |
| 1 | string | Base storage directory |
| 2 | map<string,int32> | Logical filename to live read-only file descriptor |
| 3 | string | Model directory relative to the base / logical namespace |
| 4 | enum (varint) | `1` is LLM, from `cix` and `hft` |
| 5 | boolean | `AicInference__enable_ssv2`, stock default false |

In the original Java `RuntimeModelLoaderWrapper`, path mode sets fields
1/3/4/5; descriptor mode sets 2/3/4. `bwj` provides the application private-data
directory as field 1 and joins storage paths onto `hfs.c` for field 3.

ABI entrypoints:

| Java class suffix | Native method |
| --- | --- |
| `runtime.impl.edgetpu.RuntimeEdgetpu` | `static long nativeCreate()` |
| `runtime.wrapper.RuntimeModelLoaderWrapper` | `static long nativeLoadModel(long, byte[])`; `void nativeFree(long)` |
| `runtime.wrapper.LargeLanguageModelWrapper` | `byte[] nativeGetTokenInfo(long, byte[])`; `void nativeUnload(long)` |

All names have prefix `com.google.android.apps.aicore.`. The token-info input is
`cer` field 11 → `ceq` field 1 → `cdv` string field 1. This follows the original
`cbq.mo1913e` method. The `cer` field 4 string is not the prompt. The `cfh` response has a
uint32 field 1. Generation uses `nativeCreateSession(long, byte[])`, recovered
`cfe` session configuration, and the original `StatefulSessionWrapper` JNI ABI.
Original Java controller
ABI is `int process(float)`; a streaming consumer is
`int accept(String,float,byte[])`.

## Prepared generation boundary

Select main class `org.ostadix.nanoloader.SyntheticGenerationProbe` explicitly,
with the same native-directory and model-manifest arguments. Add this host-owned
manifest member:

```json
"generation": {
  "prompt": "A synthetic prompt selected by the host",
  "maxOutputTokens": 32,
  "timeoutMs": 10000,
  "seed": 123,
  "temperature": 0,
  "stream": true
}
```

This source compiles but generation has not been run by this agent. The callback
deadline is cooperative; use an outer process timeout as well. Host bounds are
512 output tokens, 30 seconds, 16KiB prompt text, 4096 callbacks, and 1MiB total
streamed bytes. Native calls are not retried. Session/model/runtime handles are
released in that order. Output preserves callback chunks and the entire returned
protobuf, alongside decoded candidate text, score when present, and raw finish
reason enum.

Recovered request (`cer`) fields used by the bounded probe:

| Field | Meaning and encoding |
| --- | --- |
| 2 | temperature, float/fixed32 |
| 3 | maximum response tokens, int32 |
| 5 | top-k, int32; probe uses 1 |
| 6 | number of samples, int32; probe uses 1 |
| 11 | repeated `ceq`; its field 1 repeats `cdv` whose string field 1 is text |
| 14 | top-p, float/fixed32; probe uses 1 |

Session `cfe` extension 100 is `cfq`: field 1 is RNG seed, field 2 defaults to
1440, field 3 to 0 in `cjj`, and field 4 to true. This probe preserves those stock
defaults and sets the supplied seed. Session fields 18 and 20 are enum zero,
matching the stock unspecified session version and text input mode. The native
response `ceu` field 1 repeats `cdw`: string field 1 is candidate text, double
field 2 is its score, field 5 is its finish-reason enum.

`StockWireVerifier` loads the installed AICore APK in a classloader and parses
our encoded request/session using its original protobuf classes. It verifies the
exact nested text, limits and sampling values, recognized RNG extension, and
agreement between our response decoder and the original parser. This live parser
check passed without invoking any native model methods; see
`evidence/stock-wire-verification-complete.json`.

## Build and launch

```bash
bash tools/nano-local-loader/build.sh
```

Run in Android ART using `app_process`, with `CLASSPATH` set to the built JAR
and `-Djava.library.path` set to the directory of the original extracted JNI
libraries. Supply the normal Android runtime environment. A Termux environment
without `ANDROID_ART_ROOT` and the boot classpath caused an exit before Java
with no probe events, even with exit code zero. That is not a passing result.

The successful command/environment keys are captured in
`evidence/initialization-native-path.json`. On this device the nonsecret runtime
variables were recovered from the running zygote's environment and inherited
through `su -p 10402`; `LD_PRELOAD` was removed. The resulting Unix UID was
10402, but SELinux remained the KernelSU shell context, not an Android app
context. This does not establish that a normally launched app can use this ABI.

Load the JNI wrapper libraries, not `libgoogle3.so` directly. The wrappers load
`libgoogle3.so` through their native dependency. Calling its generic JNI_OnLoad
directly returned JNI_ERR. LD_LIBRARY_PATH alone did not configure ART's
classloader native-library namespace; the Java library path did.

## Live observations

At `2026-09-17T16:28:13.822007Z` the reconstructed wrapper, running at UID10402,
successfully loaded both JNI entrypoints, obtained a nonzero runtime handle and
freed it. Native stderr confirms `RuntimeEdgetpu nativeCreate` and
`RuntimeModelLoaderWrapper nativeFree`. See
`evidence/initialization-native-path.json`; library hashes are in
`evidence/initialization.json`. Probe JAR hash at that measurement:
`1d8a232aa08d67c5513a8242ceab6e1ab751b95e6965b33a0db89038b6dc6a7a`.

Root's subsequent real local-model load reached the checkpoint reader and EdgeTPU
executor, then failed acquiring a device descriptor. The runtime was freed.
`../../audits/gemini-nano-rebuild-20260917/local-model-load-readonly.stderr`
records that attempt; no model handle, tokenization or inference succeeded.

The library reports `Unknown error -8` because its `GetEdgeTpuFd` returns
`AStatus_getExceptionCode` as if it were a Linux errno. In the NDK Binder API,
`-8` is `EX_SERVICE_SPECIFIC`, so that message discards the underlying reason.

`EdgeTpuAccessProbe` was rebuilt to query the original Binder service directly.
No arguments performs transaction 7, `userIsAuthorized`, for its own actual UID.
The explicit `get-fd` argument performs transaction 1, `getEdgeTpuFd`, preserving
the full service exception. Any returned descriptor remains parcel-owned and is
closed when the parcel is recycled; no device operation or model runs.

Live results:

- Actual UID10402: `userIsAuthorized=false`.
- Actual root UID0: `userIsAuthorized=false`.
- UID10402 `getEdgeTpuFd`: service-specific error **16**, message **"Current
  application should not be allowed to access EdgeTPU."**

Evidence: `evidence/edgetpu-authorization-uid10402.json`,
`evidence/edgetpu-authorization-uid0.json`, and
`evidence/edgetpu-device-status-uid10402.json`. Both launches retained
`u:r:ksu:s0`. No package UID was impersonated and no authorization settings were
modified. The next integration needs a real authorized application context.

## Unverified

No model has been successfully loaded by this harness at the time this note was written.
No Nano inference, model identity, supported feature registration, assistant
routing, or Ostadix dispatch follows from constructing a runtime handle.
`LocalModelProbe` and `SyntheticGenerationProbe` are prepared boundaries; root's
separate model-load audit determines whether the staged assets actually work.
