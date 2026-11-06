# X12 hosted OKernel development ISO

This profile boots the original installed x86-64 Linux kernel directly through
UEFI GRUB. Linux supplies the physical display, keyboard, storage and other
driver interfaces. The captured O-core monitor then supervises its original
Linux and Plan 9 domains using the declared QEMU/TCG execution profile. The
foreground interface is the persistent unified console.

This is a compatibility development image. Native O-core physical driver
lowering, a completed single-native operating system, physical X12 peripheral
functionality and whole-system efficiency require further qualification.
Including a module and its firmware is distinct from testing a device or its
required userspace service. Fingerprint, camera, audio and cellular userspace
are not admitted by this profile.

## Contents

- Original `7.0.14-ustad-native-20261031` kernel and configuration.
- All 6,900 readable matching `.ko` modules. The ten unreadable installed
  generated module indexes are recorded and regenerated only in the private
  copy using original `depmod`. Kernel build/source directory links are excluded.
- The complete readable installed firmware tree, including symlinks and
  compressed Intel GPU, AX211, Bluetooth and SOF firmware, plus installed
  firmware/kernel-tool license documentation. The kernel supports Zstandard
  firmware. This captures installed binary inputs, not their source build.
- Original BusyBox, Bash, tmux, Python 3.12/stdlib/extensions, kmod, IP tools,
  WPA supplicant/CLI/passphrase tools, terminal information and their selected
  local ELF dependency closure. No host network configuration or credentials
  are copied. `iw` is absent on this build host; the WPA CLI supplies this
  profile's wireless control interface.
- One exact frozen runtime and one explicitly selected, verified saved disk
  and native namespace pair. The paired-save receipt is retained. Boot checks
  generation bytes and hashes before rebasing only the declared paths into a
  new `/run/okernel/state` directory.

The ISO root is read-only SquashFS with a tmpfs overlay. The copied state,
package changes, network credentials and logs live in RAM and disappear on
poweroff. This is not an installer or persistent USB system. The bootstrap
mounts only the declared optical/USB ISO read-only. It does not mount internal
NVMe, MMC or SATA filesystems. No existing working state is selected at boot.

## Build

Build on the named running Linux kernel, using installed GRUB x86-64 EFI,
xorriso, squashfs-tools, kmod, gzip and Python 3.10 or newer. These commands
install or download nothing and require no sudo. Every output directory must
be new. Supply the final qualified frozen runtime and private saved fork;
the builder does not contact or save a running VM.
The carrier payload explicitly uses installed `/usr/bin/python3.12` and its
matching `/usr/lib/python3.12`, independent of the builder's interpreter.
The ISO assembly fixes newc ownership/time, SquashFS inode/build time and
ownership, GRUB's rescue FAT identity and ISO dates. Payload metadata records
content hashes without the new output directory or construction time. Repeat
assembly from the same captured carrier, frozen runtime and saved fork is
checked separately from a fresh source/toolchain or package rebuild.

Only data clusters marked free by both identical EFI FAT allocation tables
are zeroed during assembly; the allocated EFI executable is checked unchanged.
Installed firmware, kernel and captured host-tool package copyright notices,
plus referenced common licenses, are retained in the ISO's `/licenses` directory
(mounted as `/media/okernel/licenses` after boot). This captures binary inputs
and notices, not a complete corresponding-source build. The active init shell
is original BusyBox; an optional original dash is retained separately at
`/media/okernel/carrier-tools/dash`.

```sh
python3 -B scripts/build_okernel_x12_iso.py carrier \
  --output "$HOME/.cache/okernel-x12-carrier-next"

python3 -B scripts/fork_okernel_state.py \
  --source /path/to/explicit-saved-unified-state \
  --output "$HOME/.cache/okernel-x12-saved-pair-next"

python3 -B scripts/build_okernel_x12_iso.py build \
  --carrier "$HOME/.cache/okernel-x12-carrier-next" \
  --runtime /path/to/qualified-frozen-runtime \
  --state-seed "$HOME/.cache/okernel-x12-saved-pair-next" \
  --output "$HOME/.cache/okernel-x12-iso-next"
```

The result is `okernel-x12-development.iso` and a receipt binding kernel,
SquashFS, initramfs, captured helper sources, root inventory, runtime and saved
pair. No original source, driver, firmware, saved state or prior output is
overwritten. The carrier can be reused after its entire copied inventory is
verified. No host checkout path is needed by the completed boot image.

To assemble the same captured boot payloads again without rebuilding SquashFS,
use a completed build as input and a new output directory:

```sh
python3 -B scripts/build_okernel_x12_iso.py repack \
  --from-build /path/to/completed-iso-build \
  --output /path/to/new-assembly
```

The repack receipt binds the original kernel, SquashFS, bootstrap and retained
notice bytes. Compare the complete ISO SHA-256 between assemblies. Identical
captured inputs reproduce the assembled media; a new saved pair or different
installed binary inputs deliberately change it.

## Use

The first GRUB entry starts the normal visible tty1 console, with an original
32-pixel console font. The second entry sends the console to ttyS0 for bounded
QEMU automation. Secure Boot/signature qualification and physical boot remain
separate from a successful UEFI QEMU test.

Boot offers an eight-second `n` choice for host networking, then starts the
unified console. Type `i` at that same prompt to open the lightweight local
interface instead. It runs in userspace on the physical machine's existing
Linux text terminal, with no browser or desktop dependency. The menu opens or
reconnects to OKernel, shows session status and local display/input/network
diagnostics, configures networking, explains commands and safely saves/stops.
Its poweroff action asks for `POWER OFF`, waits for a successful managed stop,
then powers off. A save failure blocks that action and leaves the panel open.
Normal OKernel save/exit returns to a host menu whose visible `i` choice opens
the same interface; opening and exiting its managed console returns to the panel.
The legacy host menu also retains resume, networking, diagnostic-shell and
poweroff choices. Poweroff discards the volatile
RAM session. A paired save within this boot supports resume during this boot;
it does not make the ISO writable or persist across a physical reboot.

For WPA-PSK Wi-Fi, select `n`, provide the visible interface and SSID, then enter
the hidden password. Original `wpa_passphrase` receives the secret on stdin;
its plaintext comment is removed. The config remains under private `/run`.
Original `wpa_supplicant`/`wpa_cli` establish association and BusyBox DHCP sets
the live-host address, route and DNS in RAM. Wired interfaces use DHCP without
the wireless prompts. Enterprise Wi-Fi and arbitrary cellular/fingerprint/
camera services are outside this helper. Existing host profiles and secrets
are never read. Physical association is not established by a QEMU boot.

## Validation

`tests/test_okernel_x12_iso.py` checks copy boundaries, canonical paths,
symlink/modified-byte rejection, no-clobber outputs and root-owned newc device
metadata without creating privileged host device nodes. Actual ISO/driver
loading, foreground input, Linux/Plan 9 shared-file use, original compiler use,
paired save, exit and poweroff require separately retained boot evidence.
Failed construction/boot attempts remain distinct from later successful bytes.

Nested software emulation can exceed the embedded runner's normal 180-second
startup budget. The verifier can retain that failure, detach only its own failed
console, then use the ISO's host diagnostic shell to inventory-check and launch
the same frozen controller with its supported `--timeout 900` option:

```sh
python3 -B scripts/verify_okernel_x12_iso.py \
  --iso /path/to/okernel-x12-development.iso \
  --output /path/to/new-slow-emulation-check \
  --slow-timeout 900 --timeout 5400
```

That mode changes only the explicit validation caller's deadline. It neither
changes the image/defaults nor turns the default nested startup failure into a
pass. Full command, shared-file, compiler, saved-pair, typed-exit and poweroff
checks still apply. Physical X12 startup is a separate qualification.
