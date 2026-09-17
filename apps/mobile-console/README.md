# mobile-console

`mobile-console` turns a rooted Android phone with USB gadget support into a programmable USB boot keyboard. It is a native Rust daemon and CLI for Termux. All changes are runtime configfs state and disappear at reboot; it never writes Android partitions.

## Install

Use a current Termux from F-Droid or GitHub:

```bash
pkg update
pkg install rust binutils coreutils
cd /data/data/com.termux/files/home/Ostadix-lang/apps/mobile-console
chmod +x install.sh
./install.sh
```

The CLI re-executes privileged operations through `su -c`; approve Termux in KernelSU/SukiSU. The root daemon alone opens `/dev/hidgN`. Its mode-0600 socket and log are `/data/local/tmp/mobile-console.sock` and `/data/local/tmp/mobile-console.log`.

## Use

Connect the Pixel's data-capable USB-C port to the target computer:

```bash
mobile-console start
mobile-console status
mobile-console type "hello world"
mobile-console key ENTER
mobile-console key LEFT
mobile-console key F12
mobile-console stop
```

Text uses a US keyboard layout and supports printable ASCII plus newline, tab, escape, and backspace. Named keys include Enter, Escape, Backspace, Tab, Space, arrows, Home, End, Page Up/Down, Delete, and F1–F12. Unsupported Unicode is rejected rather than mistyped.

`start` briefly disconnects and re-enumerates USB. If Android already owns an active composite gadget, the daemon adds `hid.mobile_console` to that configuration so ADB/MTP functions remain. With no active gadget it creates `/config/usb_gadget/mobile_console`. `stop`, SIGINT, and SIGTERM send all-keys-up, unbind the UDC, remove only this HID function, and rebind the original gadget. Reboot clears configfs state.

Keep a wireless or onscreen recovery route available before changing USB mode. Android may rebuild its gadget after a cable or USB-mode change. If that happens, stop (or reboot), select the Android USB mode, then start again. SIGKILL or a kernel crash cannot run cleanup; reboot is the safe fallback.

## Kernel-level design

- **USB configfs gadget** (`/config/usb_gadget`) is the kernel device-side composition API. Writing an empty `UDC` disconnects the device. The daemon links a kernel `f_hid` function into a configuration, then rebinds the UDC so the peer enumerates a keyboard.
- **HID gadget** (`functions/hid.*`, `/dev/hidgN`) is the actual peer-facing kernel transport. `report_desc` declares a boot keyboard. Every `/dev/hidgN` write is eight bytes: modifier bitmap, reserved byte, and six usage slots. Press reports are followed by eight zero bytes for release.
- **`/dev/uhid`** creates a virtual HID device on Android's host side. It suits a future Bluetooth bridge but cannot make the USB peer see a keyboard.
- **`/dev/uinput`** injects local Linux/Android input. It controls the phone, not the attached computer, and is intentionally unused.

Root may not be sufficient: SELinux and Android's USB service can restrict or rebuild configfs. This project never disables SELinux. Diagnose with:

```bash
su -c 'id; ls -ld /config/usb_gadget /sys/class/udc; ls /sys/class/udc'
su -c 'cat /data/local/tmp/mobile-console.log'
su -c 'dmesg | tail -100'
```

A device-specific KernelSU policy/module may be required. Keep it narrow: configfs gadget nodes, the selected UDC, `/dev/hidgN`, socket, and log. Do not use `setenforce 0` or modify `/system`, `/vendor`, or boot images.

## Extensibility and development

`src/keyboard.rs` only produces key usages and eight-byte reports. The `HidKeyboard` trait in `src/backend.rs` is the transport boundary. A future Android `BluetoothHidDevice` companion or UHID bridge can implement it without changing mapping, macros, SSH input, or an Ostadix command → action graph → HID/SSH executor.

Tests do not touch USB:

```bash
cargo fmt --manifest-path Cargo.toml -- --check
cargo test --manifest-path Cargo.toml
cargo build --release --manifest-path Cargo.toml --locked
```

Hardware validation is deliberately explicit because it re-enumerates USB: start, verify the target sees a keyboard, type into a harmless editor, test special keys, stop, and confirm Android's previous USB functions return.
