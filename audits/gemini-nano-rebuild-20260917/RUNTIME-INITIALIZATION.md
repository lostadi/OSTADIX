# Installed AICore runtime initialization comparison

## Implementation inspected

Read-only comparison of the installed AICore Java loader, its native library,
and `tools/nano-local-loader/src/org/ostadix/nanoloader/LocalModelProbe.java`.
No model load, inference, service restart, property change, or binary patch was
performed by this investigation.

Native library SHA-256:
`62015826fb79be5f10d7d7aa9d137a1bc0a4980c2b687bcab44a9cc4c3a71823`.

### Java initialization matches the probe's essential call sequence

Source root:
`/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/`.

- `p000/cja.java:22` loads `runtime_edgetpu_jni`. It has no other initialization
  call. `RuntimeEdgetpu.m2827a()` initializes this class, then calls the
  zero-argument native `nativeCreate()`.
- `p000/cji.java:22` loads `runtime_model_loader_wrapper_jni`. It has no other
  initialization call.
- `RuntimeModelLoaderWrapper.m2835d(cfa)` initializes `cji`, lazily creates a
  nonzero runtime handle, then calls `nativeLoadModel(handle, configBytes)`
  under a monitor. No Context, package name, UID token, Tachyon readiness value,
  or separate hardware initializer is supplied by these methods.
- `p000/cfa.java` defines five wire fields: base directory, logical-file/FD map,
  model name, model type, and the `enable_ssv2` boolean. The probe uses this
  same boundary. `cba` declares `AicInference__enable_ssv2` with default false;
  the probe explicitly supplies false on its base-directory path.
- The stock `bos`/`boo` pre-load callback checks the one-large-model lifecycle
  invariant when its flag is enabled. Its inspected implementation updates
  Java bookkeeping; it does not initialize or select a hardware driver.
- The JNI shim's ELF dependencies include `libgoogle3.so`. The probe's
  successful nativeCreate and entry into the same native loader already
  establish that these shared objects initialized sufficiently to reach model
  construction. This does not prove every runtime environment dependency.

No omitted Java Tachyon initializer was identified in the stock load path.

## Live read-only observation and native branch

`getprop vendor.edgetpu.tflite_delegate.tachyon_aicore_ready` returned an empty
value. This is retained in `runtime-init-readonly-observations.json`.

The installed native library explains the observed message directly:

1. The helper at `0x2ded228` lazily computes and caches a boolean, using a C++
   initialization guard. Its cached byte is at `0x39bb638`.
2. It first calls the hardware-type condition at `0x2b390a8`. That function
   accepts detected types greater than 3 except type 7. The numeric types are
   not relabeled as product names here.
3. If that condition passes, it calls `0x2b09960`, which reads
   `vendor.edgetpu.tflite_delegate.tachyon_aicore_ready`, with default false.
4. `0x2b09b6c` reads the property through `__system_property_get`. The boolean
   parser at `0x2b09c14` accepts `true`/`1`, accepts `false`/`0`, and returns the
   supplied false default when the property is empty.
5. A false readiness value reaches the exact warning at `0x2ded294`:
   `Tachyon not ready for AICore; falling back to Driver2.`

This is a configuration/readiness gate in native code. It is not evidence that
a separate Java initialization method was forgotten. The fact that the warning
was emitted also shows the hardware-type condition passed in that model-load
process; otherwise the warning branch is skipped.

Because the result is cached, a future legitimate readiness change would not
be re-read by this helper inside an existing process. A new loader process would
be needed to observe changed state.

Exact code windows are retained in `runtime-init-tachyon-disassembly.txt`;
string cross-references are in `runtime-init-native-xrefs.json`. Addresses are
relative to this exact library image. Objdump's nearest-exported-symbol labels
are not recovered function names and should not be interpreted as such.

## Other native observations

- The native library also contains a test-only forced-Tachyon branch. Its log
  string alone does not establish a public configuration API or a supported
  alternative to the readiness gate; no test flag was changed.
- The Tachyon client dynamically loads `libedgetpu_tachyon.google.so`.
  `/vendor/etc/public.libraries.txt` lists that library and `libedgetpu_litert.so`.
  Their presence does not prove service availability or model compatibility.
- The known model-load failure happens after driver selection, while acquiring
  an EdgeTPU device FD: errno -8. This investigation does not determine that
  error's underlying service or identity cause. That requires the separate
  acquisition/service investigation.

## Unverified claims

Setting the readiness property is not established as a repair. It would change
which backend is selected; it would not itself establish an initialized service,
compatible model graphs, successful model load, or inference. No such claim is
made, and no property was set.
