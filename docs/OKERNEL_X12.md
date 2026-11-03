# OKernel on the X12

`okernel` opens one persistent OS console: Linux userspace runs below the native
O-core AArch64 EL2 monitor in QEMU/TCG. Original Linux programs, compilers,
packages, and writable files run inside that supervised domain. A native
O-core 9P2000 service supplies the shared `/n/okernel` namespace to Linux and
the native Plan 9 protocol peer. There is one shell and one `pkg` interface.

This currently runs on the X12 as a virtual machine. The shared native 9P
service and peer implement real file operations on the same governed objects;
they do not establish a complete Plan 9 kernel or executable ABI. Plan9port
provides original Plan 9 tools compiled for the Linux ABI when explicitly built.
The original 9front ARM64 kernel and its original `rc` also pass a separate
O-core execution probe. Connecting that kernel to the common store is an
isolated integration gate; it is not yet the default console's execution provider.

## Prepare, start, and reconnect

Prepare the monitor, Linux payload, root filesystem, and explicit network and
namespace grants once. This is a deliberate build, and can download source and
signed packages:

```bash
okernel packages build --network --namespace
okernel doctor
okernel
```

From the checkout, `./scripts/okernel-console.sh` accepts the same arguments.
Start checks the prepared profile and its bound monitor/payload artifacts.
It never rebuilds artifacts or installs packages. A running session is
reconnected without replacing its VM.

```bash
okernel start --detach   # Start without attaching
okernel attach          # Reconnect to the existing shell
okernel status          # Session state and log location
okernel logs            # Last 100 log lines
okernel stop            # Sync, save, and exit; wait for completion
okernel restart         # Save, stop, and reopen the prepared OS
okernel run             # Run directly in this terminal instead of tmux
```

Inside tmux, Ctrl-B followed by D detaches without stopping the OS. Closing the
terminal also leaves its tmux session running. Inside the OS console, Ctrl-]
interrupts the foreground command, confirms that the shell is accepting
commands, requests a filesystem sync, saves a matching root-disk/native-namespace
snapshot, and exits. Save edited files before using it; return to the shell
first if a program handles Ctrl-C itself. Ctrl-C is delivered to the guest. `okernel stop` sends the
same save request and waits; if it times out, it leaves the VM running and
reports the pending save. A failed save resumes the same VM and leaves the
console available for inspection and another Ctrl-] attempt. Check its log
before retrying. Closing console input is not treated as a save/stop request.

The package console uses a separate tmux socket from the old development
console. State is under `~/.local/state/ostadix/okernel/package-domain/`; each
`session-*` directory contains a console log, immutable boot inputs, and a
result record. `head.json` names the saved root disk and native namespace
objects together. Guest block flush makes monitor-owned RAM current; the
controlled host QMP export and atomic head publication provide persistence
between VM runs. Forced host shutdown does not substitute for a completed save.

The OS tmux session and the Codex development session have separate lifetimes.
Closing a support chat does not stop the OS. To continue development after
exiting Codex, use `codex resume SESSION_ID --cd /home/ustad/ostadix-BM` with
the session recorded in
`~/.local/state/ostadix/okernel/development-handoff.json`. That record also lists
passing evidence and unfinished work. Saving the OS does not keep Codex itself
running after its process exits.

`OSTADIX_OKERNEL_STATE` selects the parent state directory.
`OSTADIX_OKERNEL_PACKAGE_QEMU` selects `qemu-system-aarch64`;
`OSTADIX_OKERNEL_PACKAGE_SOCKET` selects the package tmux socket. Default
start/run requires Python 3, tmux, QEMU AArch64, and prepared artifacts, without
requiring the Rust compiler or an x86 QEMU installation.

To test a change while leaving the running OS alone, copy its latest saved
checkpoint into a separate state:

```bash
okernel fork "$HOME/.local/state/ostadix/okernel/my-test-state"
okernel packages run --state "$HOME/.local/state/ostadix/okernel/my-test-state"
```

The copy includes the selected package disk, native namespace and boot inputs.
It does not include unsaved changes in the running VM. Its writable data uses
separate files; saving or replacing the test state does not replace the main
saved checkpoint.

## Use packages and shared files

At the guest shell:

```sh
pkg help
pkg search jq
pkg install jq
pkg install zlib
pkg install plan9port
9 rc -c 'echo hello from rc'
status
pkg-namespace status
printf 'hello from Linux\n' > /n/okernel/work/from-linux
cat /n/okernel/work/from-plan9
```

`pkg install` prefers registered source providers, then original signed APK
packages and their dependencies. The zlib provider runs the original patched
source through GCC, Make, checks, and installation inside the domain.
`pkg add NAME` explicitly selects APK installation. These routes publish
package/build receipts under the same native `/n/okernel/pkg` and
`/n/okernel/build` namespace; metadata grants no execution or device authority.

The Plan9port source provider builds the original `rc`, `mk`, `9p`, and
`9pserve`, plus original `u9fs` with a declared path-containment patch, for the
Linux ABI. Its private GNU libc development/runtime closure comes from original
signed Ubuntu ARM64 packages, without replacing Alpine's system libraries.
The provider records this closure, source, patch, supervision helpers, and
installed file identities. `pkg install
plan9port` verifies and reuses a matching installed generation; `pkg source
plan9port` explicitly builds another fresh source tree. These tools use the
same mounted files as other programs. They do not provide a full Plan 9 kernel
or executable ABI. Additional package repository ecosystems require their own
providers; the available binary provider currently follows original APK rules.

New source builds also supply a private Unix-socket service for original `9p`
clients. It exports the mounted native store, with no host filesystem service
or TCP listener. In a state containing this build:

```sh
pkg-9p status
pkg-9p test
9p -n read okernel/work/from-linux
pkg-9p stop
pkg-9p start
```

PID 1 restores the service on restart. Existing saved environments need the
updated guest helpers and a source rebuild before these commands are available.
The source installer rolls back its owned installation if activation fails.
The live qualification command accepts an explicit isolated state, so a working
console can stay open:

```bash
python3 scripts/verify_okernel_9p_service.py --state /absolute/stopped-test-state --build
```

Its success requires original client/server wire operations, binary transfers,
independent native-peer exchange, package verification, and two real VM
restarts. The direct original Plan 9 kernel gate is separate from this Linux ABI
qualification.

The original Plan 9 kernel shared-store gate is also qualified separately:
Linux writes a file, original Plan 9 mounts and reads it and writes a response,
then an isolated Linux fork recovers that exact response across a restart.
The current evidence and source identities are recorded in
`evidence/plan9_native_namespace_probe.json`. To repeat it, first create a
stopped fork and select its saved namespace path from `head.json`. Use a new
output directory and the original-tool kernel derivation receipt:

```bash
python3 scripts/probe_okernel_plan9.py \
  --kernel-uimage /absolute/kernel-build/patched-1/artifacts/NATIVE.U \
  --derivation-receipt /absolute/kernel-build/result.json \
  --namespace-state /absolute/test-state/namespace-generations/selected.raw \
  --expect-path /work/from-linux \
  --output /absolute/new-plan9-proof

python3 scripts/import_okernel_plan9_namespace.py \
  --state /absolute/test-state \
  --proof /absolute/new-plan9-proof/result.json --verify
```

Use the actual content-addressed namespace filename from the selected saved
head. The probe records and verifies the expected source bytes, preserves its
input, and exports into its own evidence directory. The importer refuses the
default working state, a running test state, a different starting generation,
or an unqualified export. A post-publication durability error is reported as an
uncertain outcome requiring inspection, with both generations retained.
These gates qualify sequential cross-ABI shared files; they do not switch the
default console into the original Plan 9 kernel or provide concurrent domains.

New package environments use a 1 GiB governed root disk. Existing 512 MiB
environments remain supported. A stopped environment can be grown without
modifying its selected image in place:

```bash
python3 scripts/grow_okernel_disk.py
okernel packages build --network --namespace
```

Growth verifies the complete filesystem tree and retains the previous image
and exact shared namespace generation. The monitor build and `okernel verify`
select the saved disk size automatically. The common native namespace remains
16 MiB with 1,024 object slots; keep large source trees and build caches under
`/work`. The default shell starts in `/n/okernel/work` for shared work.

The native peer reads `/work/from-linux` through its independently scoped 9P
session and writes `/work/from-plan9`. Linux accesses those same objects through
its virtio-9P mount. Its grant, object generations, and fid checks are enforced
by native O-core code. There is no host filesystem server behind this mount.
A missing namespace grant is an error, rather than a fallback directory.

## Verify the prepared OS and monitor bytes

Run acceptance after detaching or stopping an interactive session; the runner
locks the state to prevent two VMs writing the same generation:

```bash
okernel test                         # Online packages, shared files, two zlib builds, restart
okernel test --skip-source           # Faster package/namespace/restart checks
okernel test --plan9port             # Also build original Plan9port tools
okernel verify /absolute/new-evidence # Two independent native monitor builds
```

`test` runs the real prepared guest and checks repository access, compilation,
Linux/native-peer shared files, and saved-state restart. Its full source route
compares two zlib build receipts. A new online repository resolution can change
the package inputs; retain the downloaded package/source closures and recorded
receipts when comparing runs.

`verify` freezes native O-core source, the prepared Linux payload, and selected
compiler/linker/device-tree tool bytes, then compares independent monitor,
profile, and DTB builds. It does not rebuild Linux or bootstrap the foreign
compiler toolchain. Its result file states those limits. The command requires
an existing compiler build and a new output directory. Neither command qualifies
a physical X12 boot.

## Keep the mode-16 development console available

The previous x86 mode-16 console remains available explicitly:

```bash
okernel native                  # Start/build or reconnect to the original tmux session
okernel native status
okernel native logs
okernel native stop              # QEMU Ctrl-A, then X
okernel native test              # Embedded package lifecycle smoke
okernel native verify           # Two independent x86 native executable builds
```

This developer console runs four isolated O-core service executables and
supports help, status, and embedded package install/activation. It has no general
shell or writable filesystem. Backspace edits input, Ctrl-U clears the line,
and Ctrl-C cancels it. Activation runs its bounded lifecycle test and parks.
It is separate from the default persistent OS, and its existing tmux session is
preserved. Its launcher selects the installed x86 QEMU and limits Cargo to two
jobs; builds include current source changes without committing or discarding
work.

## Reproduce native executable bytes

First build the compiler with the repository's pinned Rust toolchain and locked
dependencies. The existing checkout-local development helper selects the host
tools. From the repository root:

```bash
source scripts/bm-dev-env.sh
export CARGO_BUILD_JOBS=2
cargo build --locked --package o-lang --bin ocorec
python3 scripts/verify_okernel_repro.py --help
```

`okernel native verify` performs the compiler build and snapshot/rebuild verification
using those selections. It prints the path to its `result.json`. The command
does not start a VM or overwrite an existing evidence directory.

`verify_okernel_repro.py` captures staged, unstaged, and new source using a
private Git index. It preserves the original branch and index, exports one
source archive, and builds the native kernel, service ELFs, and OVFS package in
two independent directories. Its evidence binds the source archive and actual
tool bytes. Its reproduction claim uses one frozen, prebuilt compiler; it does
not establish reproducible compiler bootstrap or hermetic host dependencies.

## Reproduce and boot console UEFI media

Use a source export from the executable reproduction run, such as `source-1`.
The media output directory must be new and outside that source tree:

```bash
python3 scripts/verify_okernel_media.py \
  --source /absolute/reproduction-run/source-1 \
  --output /absolute/new-media-verification \
  --ocorec /absolute/reproduction-run/tools/ocorec \
  --qemu "$HOME/.local/opt/qemu-11.1.3/bin/qemu-system-x86_64" \
  --firmware /usr/share/OVMF/OVMF_CODE_4M.fd
```

Select the compiler path recorded in `result.json` under
`tools.ocorec.frozen_path`. Optional
`--clang` and `--lld` arguments select exact tools when the development helper's
PATH is unavailable. The media verifier:

1. builds two complete mode-16 GPT/ESP images in isolated output directories;
2. requires all bytes to match and runs the strict GPT/ESP inspector;
3. boots the exact first image through OVMF and QEMU TCG, with read-only
   firmware/media, no network, and no `-kernel` shortcut;
4. sends `help` and `status` only after the native console is ready, checks
   their output and a subsequent live observation window; and
5. saves raw serial output, QEMU stderr and arguments, tool identities, source
   identity, image hashes, and `evidence.json`.

Success requires both exit status zero and `"ok": true` in the evidence file.
The verifier writes regular files under its new output directory. It does not
write a USB device, internal disk, EFI partition, or firmware configuration.
The resulting `.img` is a raw GPT/ESP image; it is not an installer or an ISO.

## Physical X12 boundary

The inspected machine is a Lenovo ThinkPad X12 Detachable Gen 2
(`21LKCTO1WW`), booted with x86-64 UEFI and Secure Boot disabled. Its keyboard is
a USB folio device and its system disk is NVMe. At inspection no removable disk
was attached.

The current native serial implementation accesses legacy COM1 at I/O port
`0x3f8`; the GRUB configuration also uses COM1. Linux reported legacy
`ttyS0` through `ttyS3` as UART type zero, so this audit did not identify a
usable corresponding physical UART. A USB-to-serial adapter is not a substitute
without a native USB driver. No native framebuffer console, USB/xHCI keyboard,
or NVMe storage driver was found in the audited native implementation.

Consequently, virtual UEFI console success cannot establish interactive use on
the X12 display and keyboard. That requires native hardware support and a
separately observed physical boot. Do not write the internal Mint disk to test
these development bytes.

The combined Hosted Linux ISO has a different scope: its Alpine userspace can
provide a shell, files, and desktop. Its separate direct O-core entry does not
inherit those Linux facilities. Booting Hosted Linux therefore does not satisfy
native OKernel program/filesystem or hardware-driver acceptance.
