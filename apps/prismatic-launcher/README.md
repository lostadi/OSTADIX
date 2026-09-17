# Prismatic Launcher

Prismatic Launcher is a standalone, reversible Android home-screen module with
an original adaptive-glass visual identity. It targets Android 14 (API 34),
runs on Android 12 (API 31) and newer, and does not require root or modify
SystemUI.

## What the glass layer does

- Shows the real system wallpaper behind a translucent Home activity.
- Derives its accent and foreground tone from Android wallpaper colors.
- Uses Android cross-window blur when the device enables it, plus localized
  gradients, edge highlights, colored lowlights, and touch-position sheen.
- Raises surface opacity when blur is unavailable and becomes fully opaque
  when **Reduce transparency** is enabled.
- Provides app search, a four-item editable Dock, work-profile-aware launch
  handling, large-text reflow, polite accessibility updates, reduced motion,
  and 48 dp or larger interactive controls.
- Requests the HOME role only through Android's visible consent UI.

Open the three-dot button on the Home screen to change transparency, motion,
labels, or blur. Long-press an app to pin it, remove it from the Dock, or open
its Android app-info screen.

## Platform boundary

This is an Android interpretation of a fluid glass material, not Apple's
private Liquid Glass renderer, and it contains no Apple assets. Public Android
APIs can blur the launcher window as a whole but cannot sample and refract the
wallpaper independently behind every card. A normal Home app also cannot skin
Quick Settings, notifications, the lock screen, volume panels, or Settings.

Private Space is intentionally not claimed by this API 34 build. Android 15+
requires a dedicated private-profile container, lock handling, target SDK 35+,
and the corresponding role-gated permission.

The manifest exposes `org.ostadix.prismatic.HomeActivity` as both a HOME role
candidate and a normal launcher entry. Runtime Java sources belong under
`app/src/main/java/org/ostadix/prismatic/`; resources and packaging remain
independent from the other Android modules in this repository.

All bundled visual assets are original to this module. Release builds should
continue to use original or appropriately licensed icons, type, wallpaper,
sounds, and other artwork.

## Build without Gradle

The local build follows the repository's `aapt2` → `javac` → `d8` →
`apksigner` pipeline. It expects the Android API 34 platform at
`$HOME/android-sdk/platforms/android-34/android.jar` and uses the standard
Android debug keystore at `$HOME/.android/debug.keystore`. Override those
locations with `ANDROID_JAR` and `DEBUG_KEYSTORE` if necessary.

```sh
cd "$HOME/Ostadix-lang/apps/prismatic-launcher"
./build.sh
```

The build verifies and writes two APKs:

```text
build/outputs/apk/debug/PrismaticLauncher-debug.apk
build/outputs/apk/debug/PrismaticLauncher-universal.apk
```

The debug artifact is v3-signed. The universal compatibility artifact is
v2-signed for installer front ends that misclassify v3 APKs. Both are
development artifacts; production releases need a private release key.

## Install and select the home app

The build script never installs or changes the default home app. Install one
artifact through Android's package installer or from a connected host:

```sh
adb install -r build/outputs/apk/debug/PrismaticLauncher-debug.apk
```

Then open **Settings → Apps → Default apps → Home app** and select
**Prismatic Launcher**. Keep Pixel Launcher installed as the recovery home.

## Roll back

First open **Settings → Apps → Default apps → Home app** and select
**Pixel Launcher**. Confirm that the stock home screen opens, then uninstall
Prismatic Launcher from Settings or from a connected host:

```sh
adb uninstall org.ostadix.prismatic
```

Changing the default home app and uninstalling this package does not alter the
boot image, verified boot state, SystemUI, or the stock launcher.
