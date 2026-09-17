# OSTADIX AICore result experiment

This is a build-only, disabled-by-default libxposed API 102 experiment for the
exact installed AS.OSS/AICore versions documented in
`audits/pixel-ai-20260915/OSTADIX-AICORE-INTEGRATION.md`.

It is not a supported AICore plug-in. Do not install, scope, or activate it as
part of an ordinary build. The static scope is only `com.google.android.as.oss`.
At runtime it rejects any firmware, version, base-APK hash, or signer mismatch
and requires the exact `ostadix_aicore_extension_token` global setting before
installing hooks.
The token is rechecked at request entry and completion, so removing it stops
result transformation immediately even before AS.OSS is restarted.

When enabled on the pinned build, three protected hooks preserve the internal
path:

```text
fls.a(LLMRequest, flr)       capture original Binder caller UID
fmz.onLLMInferenceSuccess    run fixed OSTADIX selector and replace LLMResult
flo.a()                      propagate cancellation to OSTADIX and AICore
```

The replacement preserves inference trace, Legion metadata, and thought
process, but narrows the reply list to the typed index chosen by OSTADIX. Any
gate, thermal check, JNI, timeout, reflection, or OSTADIX failure calls the
original AS.OSS completion unchanged. Generated text, model sessions, FDs, and
native buffers never enter OSTADIX; only bounded scalar reply metadata does.
The JNI library and O/Bash launchers run directly from immutable module package
storage; module initialization creates no file in AS.OSS private storage.

Build after the Android terminal artifacts exist:

```bash
./apps/aicore-ostadix-extension/build.sh
```

The build does not install the APK or alter Vector configuration. Real
integration remains unproven until a provisioned working AICore request is
observed consuming the replaced result on-device.

`verify-source-policy.sh` also makes the build fail if any of the eight
version/APK/signer values diverges from the shared live compatibility policy.
All seven packaged native files are separately hash-pinned and their manifest
is embedded as `META-INF/ostadix/native-sha256.txt`.
