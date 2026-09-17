# Prismatic SystemUI Glass (proof of concept)

This is an intentionally narrow, fail-closed modern Xposed module for one audited
Pixel SystemUI build. Its source/build pipeline never enables it, changes Vector
scope, writes either consent token, or restarts SystemUI automatically.

Source checkpoint on the audited device (2026-09-05): this tree builds
`0.2.0-stage2`, and an isolated build was validated without installation. The
device still has the earlier stage-one APK installed; Vector records `enabled=0`
and `auto_include=0`, both consent tokens are absent, and the stage-two APK has
not been installed or loaded into SystemUI.

Visual behavior remains separately off by default. Installing the APK and enabling
it with the exact SystemUI scope in Vector is not sufficient. The privileged-operated
`Settings.Global` key `ostadix_prismatic_glass_build_token` must equal the full
audited build fingerprint exactly:

`google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys`

The primary token gates both surfaces and is the only visual token required for
`VolumeDialog`. `GlobalActionsDialogLite` additionally requires the key
`ostadix_prismatic_glass_global_actions_token` to equal:

`google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys:global-actions-v1`

A missing, mismatched, or unreadable primary token disables all visual changes. A
missing, mismatched, or unreadable secondary token disables only Global Actions.
Both tokens are build-specific compatibility and consent latches, not secrets.

## Exact compatibility gate

The process, framework, API, and firmware conditions must match before the hook is
installed. SystemUI version, certificate, and resource-table conditions must also
match before that hook makes any visual change:

- framework name: `Vector`
- libxposed API: `102`
- Android API level: `37`
- process and package: main `com.android.systemui` only
- hooked method: public framework implementation
  `android.view.WindowManagerImpl.addView(View, ViewGroup.LayoutParams)`
- Android build fingerprint:
  `google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys`
- SystemUI version code: `37`
- SystemUI signing-certificate SHA-256:
  `86170a4850632ee9e435372bb6139441a1bd207f54e973a00f0ac2cb961c0ca1`
- accepted window titles: exact `VolumeDialog` and `GlobalActionsDialogLite`
- `volume_dialog_background` must resolve to `0x7f0a0a33`
- `volume_dialog_container` must resolve to `0x7f0a0a35`
- `global_actions_view` must resolve to `0x7f0a03c3` and have exact class
  `com.android.systemui.globalactions.GlobalActionsLayoutLite`
- that Global Actions target must have an ancestor named
  `global_actions_container` resolving to `0x7f0a03bf`
- the primary consent token must exactly match the full build fingerprint
- Global Actions must also have the secondary token ending in
  `:global-actions-v1`

The shared resource-table gate requires every listed ID to match before either
surface can decorate. A mismatch therefore disables both plans, even though the
secondary consent token controls only Global Actions.

`META-INF/xposed/scope.list` contains only `com.android.systemui`, and
`staticScope=true`. Runtime package and process checks remain in place because the
libxposed specification warns that a scoped process can load additional packages.

## What the proof of concept does

It installs one protected hook on the framework implementation of
`WindowManagerImpl.addView(View, ViewGroup.LayoutParams)`. Only windows whose titles
are exactly `VolumeDialog` or `GlobalActionsDialogLite` are considered.

- It adds low-alpha sheen and edge `Drawable`s through `ViewOverlay` to exact,
  audited SystemUI target views. It never replaces a background, adds a `View`,
  changes layout parameters, or intercepts input or actions.
- It deliberately adds **no window blur** and makes no `WindowManager.LayoutParams`
  mutation. Existing blur or transparency from SystemUI or Iconify is left untouched.
- It performs a bounded immediate/750 ms/2.5 s lookup so late inflation does not
  require a permanent global-layout listener.
- Each exact target is isolated, with rollback for incomplete overlay registration;
  delayed, listener, and drawable callbacks contain non-VM-fatal failures.

Stage one decorates only `volume_dialog_background` and `volume_dialog_container`
after the primary token matches. Stage two decorates only the exact
`global_actions_view` shape after **both** tokens match. Global Actions can be shown
over a locked device; the module has no keyguard-state gate, but it still changes
only an overlay and does not hook authentication, input, emergency actions, power
actions, or controls.

`NotificationShade`, Quick Settings, media, keyguard surfaces, lockscreen
authentication, biometric, permission, Settings, launcher, system-server,
telephony, radio, firmware, and baseband paths remain outside this module's scope.

## Build in Termux

The build is a no-Gradle `aapt2 -> javac -> d8 -> apksigner` pipeline. It compiles
against the Android 34 public SDK because every Android API used was public by API 31;
runtime execution is still gated to the audited API 37 firmware.

It requires the official `io.github.libxposed:api:102.0.0` AAR as a compile-only
dependency. The script pins its SHA-256 to:

```
423484a6e1807e7a423c4b88fcd8176d104318259d91791877fed88fe91479d0
```

With the currently audited local artifact:

```bash
./build.sh
```

Or point to the same verified AAR explicitly:

```bash
LIBXPOSED_API_AAR=/absolute/path/api-102.0.0.aar ./build.sh
```

The API classes are compile-only and are not bundled into the APK.

## Risk and recovery boundary

Any injected SystemUI code can cause a SystemUI crash loop, make the volume UI or
global power menu unavailable, increase GPU cost, or conflict with another module.
Fingerprint and resource gates reduce compatibility risk but do not prove runtime
safety. Test only with a known recovery path that does not depend on SystemUI or the
power menu.

A firmware update intentionally disables this module until the new build is audited
and the fingerprint, certificate/version, hook signature, both window titles, exact
resource IDs, Global Actions class/ancestor shape, and behavior are revalidated. Do
not loosen these gates to wildcards.

`Settings.Global` is privileged-operated, not root-exclusive. A sufficiently
privileged shell or administrator path can manage it; the root shell below is the
available operator used for these exact examples.

The commands below are manual examples only; the current device remains opted out.
Before the first opt-in, keep both tokens absent, enable the module in Vector with
only its declared `com.android.systemui` scope, reboot, and inspect SystemUI and
Vector logs through a recovery path that is already known to work.

Enable stage one first, verify the stored primary token, then reboot and test the
volume dialog:

```bash
su -c '/system/bin/settings put global ostadix_prismatic_glass_build_token google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys'
su -c '/system/bin/settings get global ostadix_prismatic_glass_build_token'
su -c '/system/bin/reboot'
```

Only after stage one is stable, enable stage two, verify its separate token, reboot,
and test Global Actions independently:

```bash
su -c '/system/bin/settings put global ostadix_prismatic_glass_global_actions_token google/blazer/blazer:17/CP2A.260805.005/15828068:user/release-keys:global-actions-v1'
su -c '/system/bin/settings get global ostadix_prismatic_glass_global_actions_token'
su -c '/system/bin/reboot'
```

Disable only the Global Actions decoration and keep the volume stage eligible:

```bash
su -c '/system/bin/settings delete global ostadix_prismatic_glass_global_actions_token'
su -c '/system/bin/reboot'
```

Disable all visual changes:

```bash
su -c '/system/bin/settings delete global ostadix_prismatic_glass_global_actions_token'
su -c '/system/bin/settings delete global ostadix_prismatic_glass_build_token'
su -c '/system/bin/reboot'
```

A controlled SystemUI restart or full reboot is **required after both setting and
deleting either token**. The module does not hot-apply to an existing window, and an
already attached overlay is not hot-removed when a token is deleted. The examples
use a full reboot so the behavior is explicit.

These commands do not install or enable the module. The APK must first be installed,
then explicitly enabled in Vector with only its declared `com.android.systemui`
scope. The module never runs any of these commands itself.

If SystemUI loops, delete both tokens from a privileged ADB shell, reboot, then
disable or uninstall `org.ostadix.prismatic.systemui` through the recovery path. Keep
ADB and a tested privileged shell available before the first opt-in.

## Primary references

- libxposed API 102: <https://github.com/libxposed/api>
- official modern-module guide: <https://github.com/LSPosed/LSPosed/wiki/Develop-Xposed-Modules-Using-Modern-Xposed-API>
- official example: <https://github.com/libxposed/example>
- Vector 2.2 release/API 102 notes: <https://github.com/JingMatrix/Vector/releases/tag/v2.2>

