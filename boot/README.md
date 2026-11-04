# Boot the interactive O-Kernel system

From the repository root, run:

```sh
./boot/boot.sh
# Equivalent system entry through the existing driver:
./boot-and-test.sh kernel
```

The normal boot profile is the persistent AArch64 O-core monitor with original
Linux/Alpine userspace, a shared native namespace, mediated networking, and the
original u9fs/musl codec compiled through O-core. It provides an interactive shell,
original packages and compiler tools, and paired disk/namespace persistence.
Linux still runs as a guest. This integration does not establish complete Linux
or Plan 9 kernel source lowering.

The initial state is prepared explicitly. Startup validates its artifact and
component identities and opens its terminal; it never downloads, builds, or
selects a different profile implicitly. `Ctrl+]` asks the running system to save
the disk and native namespace together and exit. A save failure must be inspected
before treating the state as persisted.

## Prepare a separate saved state

When an existing qualified native-codec state is available:

```sh
./boot/boot.sh prepare --from-state /absolute/path/to/source/package-domain
./boot/boot.sh doctor
./boot/boot.sh
```

Preparation copies the verified saved generation into a new destination, including
its captured native-codec dependency. It does not control the source VM or capture
unsaved guest memory. The destination must not already exist.

The default exact state directory is
`${XDG_STATE_HOME:-$HOME/.local/state}/ostadix/okernel/native-source/package-domain`.
Select another exact state with `--state PATH`. The existing
`OSTADIX_OKERNEL_STATE` environment override selects its **parent** directory,
so the boot entry appends `package-domain`, as the existing console launcher does.

For example:

```sh
./boot/boot.sh prepare --from-state /path/to/source/package-domain --state /path/to/new/package-domain
./boot/boot.sh doctor --state /path/to/new/package-domain
./boot/boot.sh --state /path/to/new/package-domain --qemu /path/to/qemu-system-aarch64
```

Normal run and doctor need Python 3.11+, AArch64 system QEMU, and the native
symbol-inspection tools used by codec admission. They do not require a compiler
or tmux. The selected prepared profile must retain both mediated networking and
the shared native namespace; a profile without the original-source codec rejects.
`--qemu` overrides `OSTADIX_OKERNEL_PACKAGE_QEMU`, whose default is
`qemu-system-aarch64` on `PATH`.

## Prepare from source

First build a qualified AArch64 codec using the pinned recipes in the
[original-source component instructions](../tools/ocore-runtime/u9fs/README.md).
Then prepare a new system state:

```sh
cargo build --locked --bin ocorec --bin olangc
./boot/boot.sh prepare --codec-manifest /absolute/path/to/aarch64/native-codec.json
./boot/boot.sh doctor
./boot/boot.sh
```

This explicit preparation builds the original Linux payload, authenticated Alpine
root filesystem, and native monitor with `--network --namespace`. It needs a
Linux build environment and the declared Linux/rootfs/compiler prerequisites,
including LLVM/LLD tools, make, gcc, flex, bison, bc, curl, tar, dtc, fakeroot,
filesystem tools, and the pinned codec toolchain. The underlying builders fail
with their missing-prerequisite diagnostic. Build inputs are fetched only by
explicit preparation, with the original source/package identity checks.

`OCORE_LINUX_OCOREC_BIN`, `OCORE_LINUX_LLD`, and the documented source-builder
environment options remain available for an explicitly selected toolchain.
No built kernel, VM disk, or local cache is committed by this entry point.

## Preserved native kernel profiles

The former x86-64 kernel remains available:

```sh
./boot/boot.sh native       # Mode 16: native protected-principal console
./boot/boot.sh baseline     # Mode 0: baseline kernel heartbeat
./boot-and-test.sh console  # Mode 16 through the existing driver
./boot-and-test.sh baseline
```

An explicit `OCORE_PROBE_MODE=0` or `16` continues to select the legacy native
runner for `boot/boot.sh run` and `boot-and-test.sh kernel`. Its existing
`OCORE_QEMU_BIN`, build-directory, compiler, and linker selections remain valid.
The native mode proves protected principals, IPC, fault containment and bounded
package activation; the ordinary system profile supplies the broader interactive
environment. These are distinct capability sets, so both stay accessible.

The root driver's `quick`, `smoke`, and `full` phases retain their existing native
gate matrix. They do not silently turn into foreign guest tests. The separate
Linux/original-9front dual-kernel experiment also remains a distinct profile;
the Linux/native-codec boot path does not claim to supersede it.

## Validation

The focused boot-entry tests validate default and legacy dispatch, state/QEMU
selection, failure/exit propagation, explicit preparation, and rejection of
missing or changed artifacts and absent grants. Backend tests validate complete
codec receipts and isolated state copying. Live acceptance must use a new fork:
boot the ordinary entry, use the shared namespace and original tools, request a
paired save, restart, and verify the saved bytes. Native mode-16 acceptance and
the original smoke gates retain their own contracts.
