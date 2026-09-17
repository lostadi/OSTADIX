# Local factory model reconstruction — 2026-09-17

Checkpoint: **17:57–18:08 UTC, the controlled local model → primary `o_execute`
→ model result-consumption chain and a subsequent loopback-host execution succeeded.** The local factory model generated
a complete Python/Rust/Bash `.O` program after two model repair rounds; the host
removed its outer Markdown fence without changing the program body. Ostadix
returned **26 units: north 13, south 13**, and the model consumed that actual
result and returned a matching natural-language answer. Ordinary Pixel assistant
routing, autonomous function invocation and exact public Nano release identity
remain unverified. The separate UID 10402 loopback host first failed at 18:00 UTC;
after the scoped loader fix, its controlled HTTPS retest returned the same typed
result in **787 ms** at 18:08 UTC. This host ran in `u:r:ksu:s0`; a real Android
AppFunction or ordinary Gemini caller was not tested.

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
watchdog with process identity checks and pidfd termination. The earlier
descriptor-map build's APK SHA-256 was
`4d3797e3f72f82a87e0b896afd7c5cf81b61474cdba070aa489c1cde2871abb6`;
see [installation evidence](extension-fdmap-installed.json).

The Java extension used for the initial generation smoke was subsequently
built in the canonical `OSTADIX` checkout and installed, with APK SHA-256
`5766bd0a5e5522d6b886d6c8e8491a031a0e2197478e952aaf29cc389ef6c568`.
Its seven native payloads were reused from the prior local build after checking
their pinned hashes; this was not a fresh native rebuild. The probe now creates
an original native session, submits explicit request bytes, records returned
bytes and dispatch/return state, and unloads the session before model/runtime
cleanup. See [generation installation](canonical-generation-install.json).

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

The canonical checkout is `/data/data/com.termux/files/home/OSTADIX`. Its existing
primary MCP `o_execute` accepts the complete source as one argument and delegates
to the native O execution path. Native JSON now exposes the actual V6 admission,
input hashes and typed-result content identity. The newer source/path, action,
job and placement interfaces were retained. Primary transport cancellation,
Android session cleanup and ownership of lifted temporary workspaces were
verified separately in the [lifecycle test](../source-first-mcp/lifted-lifecycle-20260917T175517.870842Z.json)
and [native evidence test](../source-first-mcp/native-json-evidence-20260917T175733.887678Z.json).
These infrastructure checks are not assistant invocation evidence.

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
| 17:35–17:36, native text generation | Genuine AICore PID 22419 loaded the derived configuration and generated an arithmetic completion with a 32-token limit. Session/model/runtime cleanup and all 191 descriptor closures succeeded. | [generation run](canonical-nano-text.json), [correlated events](canonical-nano-text.stdout), [native log](canonical-nano-text.logcat) |

### Successful load and tokenizer request — 17:19 UTC

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

### Successful text generation — 17:35–17:36 UTC

Request ID: `canonical-nano-text-20260917-1737`. The ID's suffix is a label;
the watchdog records actual start **17:35:44.928 UTC** and finish
**17:36:19.547 UTC**.

- Actual process: `com.google.android.aicore`, PID **22419**, UID **10173**,
  `u:r:priv_app_36:s0:c512,c768`.
- Exact raw prompt: `The sum of 2 and 3 is`. The request specified a **32-token
  output limit**, temperature 0, top-k 1, top-p 1, one sample, seed 123, and
  explicit session signature `matformer_0`.
- Correlated generation enter/return events span **5,109 ms**. The complete
  monitored attempt, including model loading and cleanup, took **34,619 ms**.
  Neither value is end-to-end assistant latency.
- The native response contained one candidate with finish-reason enum **2**.
  The controller ran 99 times; cancellation and deadline-exceeded flags were
  false. Dispatch and return were both observed.
- Session unload, model unload, runtime free and all **191 descriptor closures**
  completed successfully. The terminal event and watchdog report success;
  the process remained alive and the watchdog sent no signal.

Actual returned text, including its repetition and incomplete ending:

```text
 5.
The sum of 2 and 3 is 5.
The sum of 2 and 3 is 5.

The sum
```

| Generation evidence | SHA-256 |
|---|---|
| Session protobuf | `61e8a1510d1d1da013dcdc83dc204c20ae98199113cf3d9d8f404670b2544054` |
| Request protobuf | `dd12d69c6b83fa64d09789aff262371249946cf6a9058a8f0f062e448f1a441a` |
| Response protobuf | `ae31af08d1ae141623a793fc86609d29e5de7d0c8a9ca9ffd45447b7cb91527b` |

The exact synthetic request and returned protobuf bytes are retained in the
[request artifact](canonical-nano-text-20260917-1737.generation-request.dd12d69c6b83fa64d09789aff262371249946cf6a9058a8f0f062e448f1a441a.json)
and [response artifact](canonical-nano-text-20260917-1737.generation-response.ae31af08d1ae141623a793fc86609d29e5de7d0c8a9ca9ffd45447b7cb91527b.json).
This demonstrates local native inference with the recorded derived configuration
and explicit session signature. It does not establish a correct assistant chat
template or general instruction-following quality.

### Model-generated heterogeneous program and actual result — 17:39–17:57 UTC

There were **four program-generation attempts, including the empty raw-prompt
attempt, and two model repair rounds**. The host supplied the syntax/task prompt,
submitted the generated responses to the existing primary tool, and fed execution
errors back in repair prompts. This was controlled host orchestration.

| Attempt | Actual observation | Evidence |
|---|---|---|
| Raw source-generation prompt | Native generation returned without a usable program; the returned candidate text was empty. | [raw run](canonical-nano-o.json), [events](canonical-nano-o.stdout) |
| Chat-framed first program | Exact model response reached `o_execute`; Python raised `AttributeError` because the builtin `input` was used with `.splitlines()`. | [generation](canonical-nano-o-chat.json), [exact tool result](nano-chat-exact-mcp-result.json) |
| Model repair 1 | Exact repaired response reached the tool and produced `IndentationError`. | [generation](canonical-nano-o-repair.json), [exact tool result](nano-repair-exact-mcp-result.json) |
| Model repair 2 | The model's program executed, but its closing Markdown fence became the final O text value. This exact-response call did not return the required map. | [generation](canonical-nano-o-repair2.json), [exact tool result](nano-repair2-exact-mcp-result.json) |
| Host fence extraction | The host removed exactly one outer `ostadix` Markdown fence, preserving the program body and terminating newline. One source-only `o_execute` call returned the correct typed map. No program code was repaired or substituted by the host. | [submitted program](nano-generated-shipment-program.O), [request/result/evidence](nano-program-mcp-result.json), [acceptance check](nano-program-acceptance.json) |

The program parses the shipment CSV in Python, computes eligible Fibonacci IDs
in Rust, deduplicates enabled depots in Bash, and uses a dependent Python join
to select and aggregate the rows. Its actual typed result decodes to:

```json
{"selected_ids":[2,3,8,13],"total_units":26,"totals":{"north":13,"south":13}}
```

This matches the [independently calculated expected result](expected-task-result.json).
Native execution recorded **802 ms**, not end-to-end assistant latency. The
result includes actual OIR, plan, analyzed/admitted graph, evidence and admission
identities. The direct invocation's `source_intent_gate` is null; no separately
verified required-intent gate or signed caller identity is implied.

| Identity | SHA-256 |
|---|---|
| Unmodified second-repair model text, including fence | `c9701b8499b554ab6b661620bc66967a8b95d0bf63eb4a6b63969b653c433f55` |
| Submitted `.O` body | `58f4f49e8fa4a7481800dafe158564e67f30fc18a6bc5d36c4313ba67765fe0a` |
| Typed result content identity | `7a06fec778a8fdf1970f466793a268c660c0bb3238ffb35844b83e7a1e33f193` |
| Executed native O binary | `d2db4e3662976e99b788ce55efbac00eecf0e04add05ea3e7abbe03198784cf2` |
| Primary MCP binary | `b879c51f6480cf8b1e7a0f1d24a519519f7ae6263ad6a7e5749524b274ce88e6` |

### Model consumed the actual tool result — 17:58–17:59 UTC

The host supplied the actual Ostadix result in a subsequent
[result-consumption prompt](nano-result-consumption-prompt.txt). Genuine AICore
PID **27816**, UID **10173**, dispatched and returned the generation for request
`canonical-nano-result-20260917-1759`. The model returned:

> Shipment IDs 2, 3, 8, and 13 with depots north and south yielded a total of 26 units, with north totaling 13 and south totaling 13.

The [watchdog run](canonical-nano-result.json) spans **17:58:51.799–17:59:32.667
UTC**, recording **40,869 ms for the complete attempt**, including model loading
and cleanup. This is not a token-generation-only or ordinary-assistant latency.
See the [correlated events](canonical-nano-result.stdout),
[returned text](nano-result-consumption-response.txt), and
[raw response artifact](canonical-nano-result-20260917-1759.generation-response.e2fbb0fd8d23a182676f2fb2d5bac668fd636b291d1bfbc399537e29840e7f9b.json).
The host provided the tool result; the model did not autonomously invoke a
function API in this demonstration.

### Canonical loopback host: historical failure and successful retest — 18:00–18:08 UTC

The [initial HTTPS test](nano-program-canonical-broker-result.json) verified its
certificate pin and received HTTP 200, but returned **`state: failed`, exit 1**.
Native stderr reported `expected absolute path: "--o-backend"` followed by backend
stdout closure. This failure remains retained as a historical observation.

The [loader diagnostic](appfunction-host-loader-diagnostic.json) reproduced the
failure in a private UID **10402** subprocess under **`u:r:ksu:s0`**. Disabling
the Termux system-linker wrapper in that verified KernelSU context allowed the
same primary tool to return typed 42. Native admission was retained; the fix
has only been verified for this context.

The host then restarted as PID **9901**, UID **10402**, `u:r:ksu:s0`; see the
[installation and restart record](canonical-mcp-host-install.json). The
[18:08 full-program HTTPS retest](nano-program-canonical-broker-fixed-result.json)
verified the certificate pin and returned **HTTP 200, `isError: false`,
`state: completed`, exit 0**. The full model-generated Python/Rust/Bash program
returned **26 units, north 13 / south 13, IDs 2, 3, 8, 13**, with native elapsed
time **787 ms** and the same source and result identities recorded above.
Its actual fresh admission identity differs from the earlier direct run.

The caller was a controlled local HTTPS test host. This demonstrates the repaired
loopback execution transport under the recorded KernelSU context; it does not
establish a real Android AppFunction invocation, an ordinary Gemini caller,
other SELinux contexts, boot persistence or assistant latency.

## Unverified claims and remaining milestones

- The controlled model/source/tool/result/model cycle above is demonstrated.
  Autonomous model function selection, automatic repair orchestration and an
  ordinary Gemini UI caller are not demonstrated by that host-driven cycle.
- The tested shipment fixture passed; general task reliability, the zero-unit
  depot edge case and measured overlap of all three runtime branches remain
  unverified. Four generation attempts do not establish first-attempt reliability.
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
  condition; the controlled native model/tool cycle supplies working components
  but does not prove this entrypoint integration.
- These load and generation probes are not repeated-run reliability,
  thermal-cost or end-to-end assistant latency measurements. No remote execution or cloud
  fallback is claimed by this test.
