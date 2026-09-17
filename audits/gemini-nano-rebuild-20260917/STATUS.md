# Local factory model reconstruction — 2026-09-17

Checkpoint: **17:19 UTC, successful model loading and token counting inside
the genuine installed AICore process.** Generation, public Gemini Nano model
identity, and ordinary assistant integration remain unverified.

## Implementation

The rebuilt components are the owned Java factory reader, JNI host/probe,
Vector extension, model-staging tools, and bounded process watchdog. This work
uses the installed AICore native runtime and existing factory model weights;
it does not establish a source rebuild of Google's native runtime or weights.

The factory reader reproduces the installed loader's local TrustyDecrypt
interface. It recovered the manifest, config, checkpoint, and smaller payloads.
All **191 available factory payloads** passed the manifest's SHA-1 and byte-size
checks. The manifest names 192 payloads; `dvfs_manager_params.binarypb` is
absent. Static analysis found the native default DVFS branch, documented in
[DVFS-MISSING-FILE.md](DVFS-MISSING-FILE.md). The successful load below shows
that this missing file did not prevent that particular initialization.

The extension was scoped and activated for `com.google.android.aicore`. It uses
the original host class loader and native wrappers, explicit request IDs,
activation/package gates, deadline checks before native entry, and an outer
watchdog with process identity checks and pidfd termination. The installed
descriptor-map build's APK SHA-256 is
`4d3797e3f72f82a87e0b896afd7c5cf81b61474cdba070aa489c1cde2871abb6`;
see [installation evidence](extension-fdmap-installed.json).

The original factory mount was inaccessible from AICore's live SELinux domain.
The 13 large factory files were therefore copied into AICore-owned private
staging and checked against the same manifest. The probe opens its 191 staged
files in the real process and passes their descriptors through the original
loader API. No SELinux policy or Edge TPU service authorization gate was changed.

The native audio loader then required an unavailable `frontend.tflite`.
Independent disassembly mapped variant-3 protobuf field **6** to the audio
configuration and proved its absence selects the compiled `NoAudioEncoder`
branch. The owned
[`derive_audio_disabled_config.py`](../../tools/nano-factory-reader/derive_audio_disabled_config.py)
removed only nested field **3/6**, preserving every other nested field's
original bytes. Image configuration and model weight files were retained.

| Configuration identity | SHA-256 | Bytes |
|---|---|---:|
| Decoded factory config | `2579a3a81a1c22403cf4f930581d85e743b9b33e7340ac917508b6419f1ef54e` | 1,703 |
| Derived config with audio disabled | `60ebe6ed7768ea588b24993ae7ecd1229cef3dd70459e294167b72a678a8adff` | 1,618 |

The derived config has its own recorded identity and no claim to the factory
config's original checksum. See
[derivation evidence](config-audio-disabled-derivation.json) and
[native field mapping](audio-config-field-disassembly.txt).

## Live observations

### Test sequence

Times below use the watchdog's recorded UTC timestamps. Earlier failures are
retained as historical observations.

| Order | Actual observation | Evidence |
|---|---|---|
| Local recovery | Installed TrustyDecrypt returned status 0; manifest, config and checkpoint parsed; 191 payloads verified. | [manifest run](factory-manifest-reader-run.json), [metadata runs](factory-config-checkpoint-reader-runs.json), [materialization](materialization.jsonl) |
| Standalone JNI host | Runtime creation succeeded; model loading failed at Edge TPU authorization. Same-UID probing resolved Binder category `-8` to service error **16**. UID 10402 and UID 0 were unauthorized. | [host run](local-model-load-readonly.json), [caller-context analysis](EDGETPU-HOST-CONTEXT.md) |
| 17:04, actual AICore path loader | Opening staged `data0` through a factory symlink returned `PERMISSION_DENIED`. | [path-loader run](aicore-local-model-load.json) |
| Expired deadline | An expired request was rejected before native work. | [deadline result](aicore-expired-lease.json) |
| 17:09, descriptor-map attempt | Factory directory traversal was denied by enforcing SELinux to `priv_app_36`; file-map validation failed. | [descriptor-map run](aicore-local-model-fdmap.json), [actual AVC denial](aicore-local-model-fdmap.logcat) |
| 17:11, private regular files | All 191 descriptors opened and TPU graphs began loading. The low-memory guard killed the pinned AICore PID before a model handle returned. | [guarded run](aicore-private-model-fds.json), [verified copies](aicore-large-file-copies.jsonl) |
| 17:14, reclaimed memory | The original config progressed through TPU graph loading, then returned `NOT_FOUND` for `frontend.tflite` from the V3 audio loader. No successful model handle or inference was recorded. | [run](aicore-model-reclaimed-memory.json), [native trace](aicore-model-reclaimed-memory.logcat) |
| 17:19, derived audio-disabled config | The same genuine AICore PID 7088 loaded the model, counted tokens, unloaded the model, freed the runtime and closed all 191 descriptors. | [final run](aicore-model-audio-disabled.json), [correlated events](aicore-model-audio-disabled.stdout), [native log](aicore-model-audio-disabled.logcat) |

### Successful final request

Request ID: `local-model-no-audio-20260917-1717`.

- Actual process: `com.google.android.aicore`, PID **7088**, UID **10173**,
  `u:r:priv_app_36:s0:c512,c768`.
- Recorded model package:
  `edgetpu_gem3_it_final_20250505_opt_with_audio_20250525_buenos_dvfs`.
- The native log reported **5.28117003 seconds** initialization time. Correlated
  Java model-load enter/return events span **5,283 ms**. These are distinct
  measurements of this local initialization, without a generation request.
- The model returned a nonzero native handle. Token counting for the synthetic
  `Ostadix` input returned **3 tokens**.
- Token-request SHA-256:
  `403af2251b8acb7cdc512c38100f658de607fdffd55cd90c97e51a569f95db6c`.
  Token-result SHA-256:
  `2d88972e9536ba54deed37db380728b3c58eab9bca1d173ae523098b0774cdf5`.
- Model unload, runtime free and closure of all **191 descriptors** each
  recorded successful return. The process remained alive; the watchdog sent
  no signal. The full monitored attempt, including cleanup, took **9,643 ms**.
- Every event retained `inference_executed=false`; the watchdog recorded
  `generation_requested=false` and terminal `success=true` for this probe.

This resolves the earlier local bootstrap and model-loading blockers for the
recorded derived configuration. The earlier Edge TPU denial remains accurate
for its standalone caller; successful execution in actual AICore uses that
process's own accepted identity.

## Unverified claims and remaining milestones

- No generated response, reasoning task, or `.O` synthesis has been observed
  from this loaded model. Token counting does not demonstrate inference.
- The factory package's exact public Gemini Nano release/model identity has
  not been established. Its internal `gem3` name alone is insufficient.
- The public Prompt API's previously unavailable feature IDs have not been
  repaired or shown available by this private native-loading experiment.
- The original configuration's audio path still lacks a demonstrated compatible
  frontend graph. Image inference was not tested; retaining image config does
  not prove it works. The recorded success uses the explicitly derived config.
- An ordinary Pixel assistant invocation has not been shown reaching this local
  model, producing a complete `.O` program, calling the primary `o_execute`,
  and consuming its actual result. That is still the user's full acceptance
  condition.
- This one successful load is not a repeated-run reliability, thermal-cost or
  end-to-end assistant latency measurement. No remote execution or cloud
  fallback is claimed by this test.
