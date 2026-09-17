# Edge TPU caller context — read-only findings

**Superseding observation, 2026-09-17 17:35–17:36 UTC:** the 13 large-file
copies proposed below were completed and manifest-verified. Genuine AICore
opened all 191 staged regular files, loaded the derived audio-disabled config
and generated text, with successful cleanup. The UID 10402/root authorization
denials and factory-directory SELinux denial remain valid historical results;
no service authorization gate or SELinux policy was changed. See the
[current report](STATUS.md) for the live evidence and remaining assistant work.

## Implementation evidence

The installed service executable's compressed `.gnu_debugdata` supplied actual
method symbols. Its `EdgeTpuAppService::getEdgeTpuFd` first calls
`IsCurrentAppAllowed`; only an accepted result reaches `open("/dev/edgetpu")`.
The denial path returns a Binder service-specific error **16** with the message
`Current application should not be allowed to access EdgeTPU.` A package lookup
error uses code 13. A subsequent device-open failure would instead return the
positive operating-system errno.

`-8` in the earlier model log is the Binder exception category
`EX_SERVICE_SPECIFIC`, confirmed by the installed NDK header. It is not a
kernel errno or evidence of a missing shared library.

The service's `IsAppAllowed` has a special low-UID branch, but it permits UIDs
below 10,000 only when `ro.build.type` equals `userdebug` or `eng`. This device
reports `user`. Thus running the same harness as root does not imply Edge TPU
authorization. The normal path checks installed package identity and signing
information. No authorization gate was changed during this investigation.

## Live observations

- Edge TPU app service was running, PID 20272, as system in the
  `edgetpu_app_server` SELinux domain.
- `/dev/edgetpu` points to `/dev/edgetpu-soc`; the latter exists and is owned
  system:system, mode 0660, with `edgetpu_device` labeling.
- The vendor service was stopped but its init definition is `disabled` and
  `oneshot` with an AIDL interface trigger. That alone is not evidence of a
  failed dependency; it is configured for demand activation.
- The app service dump showed zero mlock sessions. Its currently retained
  log buffers contained no records for PID 20272, so no vendor log has been
  invented to support the diagnosis.
- The team's separate live diagnostic returned `authorized=false` for the
  actual UID 10402 and actual UID 0. Its device-FD request as UID 10402 returned
  service code 16 and the exact denial message above. This establishes which
  branch caused the observed local harness failure.

The app process's earlier native trace already passed checkpoint parsing and
reached the v3 Edge TPU executor. It does not prove successful device access or
complete model initialization.

## Genuine installed AICore process requirements

At inspection, the main AICore process was PID 26387, UID **10173**, package
`com.google.android.aicore`, SELinux
`u:r:priv_app_36:s0:c512,c768`. The application class is
`com.google.android.apps.aicore.app.AiCoreApplication`. A separate declared
`:isolated_service` process exists; its identity and file access should not be
assumed to match the main process.

The installed AICore manifest already declares the optional native libraries
`libedgetpu_util.so`, `libedgetpu_client.google.so`, `libOpenCL.so`, and
`libOpenCL-pixel.so`. APK native libraries use `extractNativeLibs=false`.

The original host classes `cja`, `cji`, and `cje` initialize
`runtime_edgetpu_jni`, `runtime_model_loader_wrapper_jni`, and `llm_wrapper_jni`
respectively. Their actual DEX descriptors were checked; the `p000` package in
the old decompilation is synthetic. Initializing these classes using AICore's
class loader preserves its native-library namespace and existing JNI class
identities. Loading duplicate replacement Java classes through the module's
class loader would not establish the same setup.

Static policy inspection found rules for:

- `priv_app_all` to read/map `shell_data_file` and traverse such directories
  (platform CIL lines 55837 and 55842).
- `priv_app_202604` to read/map `intelligence_data_file` and traverse its
  directories (vendor CIL lines 13187 and 13190).

Those rules did **not** establish effective factory-file access for the live
`priv_app_36` process. In the actual descriptor-map probe on 2026-09-17, PID
4896, UID 10173, request `local-model-fdmap-20260917-1709`, the process failed
file-map validation before inference. Its log records an enforcing SELinux
denial of directory `search`, from `u:r:priv_app_36:s0:c512,c768` to
`u:object_r:intelligence_data_file:s0`, on the factory mount. The static rule
for `priv_app_202604` cannot be treated as an effective allow for this live
caller. See `aicore-local-model-fdmap.logcat` lines 15–16. Supplying a path or
opening its descriptor inside AICore therefore does not bypass this denial;
read access to the original factory files was not demonstrated.

The staging directories originally also had mode 0700 and owner UID 10402,
a separate Unix file-permission obstacle for UID 10173. Assigning generated
staging directories and decoded regular files to AICore, with directory mode
0500/0700 and file mode 0400, addresses that ownership issue. It does not make
factory symlink targets accessible. Parent directories `/data/local` and
`/data/local/tmp` already permit Unix traversal.

The deployment owner is replacing the 13 large factory symlinks with regular
copies owned by AICore, validating each against its manifest size and SHA-1.
This is a staging change, with no SELinux policy or factory-file changes.
Successful opening/loading from that new staging arrangement remains a
separate live test; it must not be inferred from this proposed correction.

## Vector append and process refresh

The read-only live `scope ls` query returned only ASI, AS.OSS and the Google
app. It is retained as `vector-current-scope-readonly.json`.

The declared module scope is static, so an updated APK declaring AICore must
be installed before appending that package. The official command is:

```sh
/data/adb/modules/zygisk_vector/cli --json scope add org.ostadix.aicore.extension com.google.android.aicore/0
```

The previously working equivalent uses the filesystem UNIX socket
`/data/adb/lspd/.cli_sock`: two big-endian signed 64-bit magic values
`547804284405368043` and `-8221824086627864083`, then a big-endian unsigned
16-bit JSON byte length and this ASCII JSON:

```json
{"command":"scope","action":"add","targets":["org.ostadix.aicore.extension","com.google.android.aicore/0"],"options":{}}
```

The response is a 16-bit length followed by JSON. This framing matches Java
`writeUTF` for these ASCII-only requests; it is not a general substitute for
modified UTF-8 for arbitrary text. The server appends scope and refreshes its
cached configuration. The module has `autoHotReload=false`; its newly scoped
code is loaded when the specific AICore app process is recreated. No separate
`reload` command was found in the inspected CLI. This investigation executed
only `scope ls`, not the append or process restart.

## Evidence files

- `edgetpu-host-context-readonly.json`
- `edgetpu-auth-and-open-disassembly.txt`
- `edgetpu-low-uid-disassembly.txt`
- `vector-current-scope-readonly.json`
- `aicore-local-model-fdmap.logcat`

Successful Nano inference and the ordinary assistant-to-Ostadix connection
remain separate, unverified milestones.
