# Embedded Linux exit-status channel

This overlay keeps the workload, Linux guest, emulator, and exit-status path
inside one core WASI module. It is not a stdout parser or an external wrapper.
It applies only to the compiler's amd64 Bochs profile, not TinyEMU or Emscripten.

The vendored Dockerfile derives from container2wasm v0.8.4, commit
`6ed3d98882a2b22eafc1334f574c364a5b2b8c47`, under its Apache-2.0 license
(included as `LICENSE.container2wasm`). Its upstream SHA-256 is
`b3b85664e7a1f37ac7d4e7ca03b2f9f2e34941576b929e1f0705cbbbccba3e87`.
The paired Bochs source is commit
`a88d1f687ec83ff82b5318f59dcecb8dab44fc83` of `ktock/Bochs`.
The patches retain upstream source headers and licenses. The patch script
checks the exact SHA-256 of each original target before applying any change.
The source fetch uses the official `container2wasm/container2wasm` repository
and verifies the full commit, because the old `ktock/container2wasm` fork does
not publish the v0.8.4 tag referenced by the upstream recipe.

Upstream init discards a workload failure when it powers off the guest, and
Bochs's simulator quit path can exit WASI with status zero. This overlay instead
returns the runc result to guest init's main function. Init drains pending tty
output, verifies the exit port signature, and writes the status byte to guest
I/O port `0xf4` through `/dev/port`. The paired Bochs handler calls libc `exit`
directly, preserving the byte in WASI `proc_exit`. No new host import is added.

For the sealed profile, successful completion reports zero; ordinary child exits retain their 0–255
status; signals are represented numerically as 128 plus the signal number;
init/setup errors report 125. This does not reproduce native signal delivery.
Port or drain failure does not fall back to successful poweroff. Kernel crashes
and a broken exit channel can still require the host's execution timeout.

The pinned Linux configuration already enables `CONFIG_DEVPORT`,
`CONFIG_DEVTMPFS`, and `CONFIG_DEVTMPFS_MOUNT`. Guest init retains the guest
`CAP_SYS_RAWIO` needed for `/dev/port`; this does not grant host I/O access or
change the runtime image's configured workload user.

The emulator also treats an empty optional MSR configuration filename as
disabled, before attempting to open it. With root preopens, WASI libc can resolve
an empty filename to the root directory; the upstream MSR reader then retries
directory-read errors indefinitely. The configuration and MSR readers now stop
at EOF before inspecting stale buffers, and report actual read errors as startup
failure 125 under WASI. This preserves filesystem descriptor handling rather
than removing or renumbering host preopens. Qualification includes an empty-root
preopen regression in addition to each engine's default environment.

`write_assets(build_dir)` writes the vendored Dockerfile and a small overlay
directory, returning `Assets`. Add its arguments to the real converter command
with `Assets::add_to_command(&mut command)`. Docker Buildx is required:

```text
c2w --dockerfile <generated>/Dockerfile \
  --extra-flag=--build-context=ostadix-exit=<generated>/overlay \
  --target-arch=amd64 --build-arg VM_MEMORY_SIZE_MB=512 \
  --build-arg OPTIMIZATION_MODE=native <image> <output.wasm>
```

The two exit-patch steps remain in `init-amd64-dev` and `bochs-dev-common`.
No upstream repository fork or publication is necessary. Hash checks bind
these patched files and the prebuilt tools listed below, not every dependency
of the conversion; the broader upstream build is not claimed to be hermetic.

## Optional browser Guix state and finalization

The compiler's explicit `--browser-guix` profile sets the build argument
`OSTADIX_GUIX_STATE=1`; the default is zero. Its immutable
`/oci/ostadix-guix-state.json` activates the new guest-init helper. Absence of
that file preserves sealed behavior. The paired Bochs template patch adds a
second EHCI USB disk at `/browser-state/guix.img`, after checking the original
template hash. No workload capability, host device, or general-purpose root
filesystem persistence is added.

Init discovers whole SCSI disks through a private kernel sysfs mount; it does
not assume the second USB port is `/dev/sdb`. Exactly one ext4 disk must match
the immutable profile's UUID and fixed 2 GiB size/geometry and be clean without
journal recovery. A read-only `noload` admission mount checks its profile marker
against the schema, layout, runtime-image digest, UUID, and size. Only then may
init mount it writable and overlay `/gnu/store`, `/var/guix`, and `/root` over
the original embedded OCI lower directories. The raw disk preopen is removed
from the workload's OCI mounts. `/ostadix` and its source-bound executable and
adapters are not persistent overlays. Boot never formats or repairs existing
state.

Guix workers can create independent sessions, so process-group cleanup alone
is insufficient. After runc returns, init stops remaining workers belonging to
the exact owned container `foo`, unmounts the three overlays, calls `Syncfs`,
and unmounts ext4. Cleanup has a ten-second caller deadline; a blocked sync or
unmount cannot emit a late clean acknowledgement. Any cleanup failure reports
init failure and leaves the browser responsible for treating storage as dirty.

The paired trusted-init channel uses I/O port `0xf5`: reads return `0x53`, and
only a single-byte write of `0xa5` sets the emulator's finalization flag. Other
writes clear it. After successful cleanup, init acknowledges on F5 before the
existing F4 status write. F4 then reports `0x4f530000 | status` to WASI;
without acknowledgement it reports the original low-byte status. Thus a clean
disk and the Guix command's success/failure are separate facts. The browser
recognizes the tag, flushes its OPFS access handle, and only then clears its
dirty marker. The tag is a protocol between the fixed emulator and guest init,
not cryptographic authentication or evidence that an arbitrary guest is trusted.
Guest OCI capabilities do not expose `/dev/port` or the private block nodes.

The separate `bochs-network.patch` repairs the pinned Ethernet allocator's
interior-pointer free: the device caller receives the allocation base, while
the sender owns a temporary four-byte-length-prefixed wire buffer. It also
rejects short writes and frame sizes outside 14–16,384 bytes, corrects partial
header pointer arithmetic, and distinguishes EOF from `EAGAIN`. `apply.sh`
checks original `bochs/wasm.cc` SHA-256
`11f064262c1027618c729966a14f8407326dff061c745f60b44ffcebad3bb9a7`
before applying this separate zero-context patch with `--unidiff-zero`.
These changes preserve the existing WASI network imports; they do not grant
arbitrary networking to the sealed host.

**Status:** these Guix state, finalization, and network changes are implemented
in source only. No new patch-application check, build, test, guest boot,
installation, or persistence qualification was run; those were deferred to
better-equipped hardware. Earlier sealed Python fixture results do not qualify
this changed overlay. See the
[browser profile guide](../../../../docs/OLANGC_WASM.md#browser-only-interactive-guix-profile)
for the complete bounds and manual acceptance steps.

When distributing binaries, retain the applicable source, license, and notice
materials for the actual linked/runtime components. `LICENSE.container2wasm`
does not cover Bochs or its embedded TinyEMU-derived virtio code, the Guix
closure, Linux, or the remaining dependencies. The compiler guide's
[source/license inventory](../../../../docs/OLANGC_WASM.md#source-and-license-materials)
is a starting point, not a completed binary-redistribution notice bundle.

## Cold-boot, lower-resource build

The amd64 exit overlay now defaults to and requires
`OPTIMIZATION_MODE=native`. Here, `native` means **without a preinitialized
snapshot**, not host-native execution: the output still contains Bochs, Linux,
the runtime image, and the compiled O program in one core WASI module. Each
execution cold-boots Linux, so startup is slower and runtime tests may need a
longer timeout. The original `_start` is retained and the full `/pack` directory
is embedded. Requests for Wizer optimization fail explicitly; there is no
fallback to a different exit-status protocol.

The amd64 tool stage uses Ubuntu 22.04 instead of a Rust build image. It checks
the SHA-256 of these exact upstream downloads before unpacking or using them:

| Input | SHA-256 |
| --- | --- |
| [wasi-vfs v0.3.0 Linux x86-64 CLI](https://github.com/kateinoigakukun/wasi-vfs/releases/download/v0.3.0/wasi-vfs-cli-x86_64-unknown-linux-gnu.zip) | `bfb542ba89a0a8645f556eef32d95feaf5ad6b276516b112e9c90fecf1da23df` |
| [wasi-vfs v0.3.0 Wasm static library](https://github.com/kateinoigakukun/wasi-vfs/releases/download/v0.3.0/libwasi_vfs-wasm32-unknown-unknown.zip) | `604d037e5b14374b78cf7b96a1c958a6ba5eee4263fb4b4733fabba4496684eb` |
| [wizer.h at 04e49c989542f2bf3a112d60fbf88a62cce2d0d0](https://raw.githubusercontent.com/bytecodealliance/wizer/04e49c989542f2bf3a112d60fbf88a62cce2d0d0/include/wizer.h) | `5a7a641c6dbb489d2bd3b4a19c47db64ec21437163b8b4cd66317299aeff9729` |

The standalone Wizer executable and its Cargo build are omitted from this
profile. The version-matched wasi-vfs CLI still performs filesystem packing;
the exact pinned header supplies Bochs's compile-time initialization hooks.
Overriding the filesystem-library or header versions is rejected rather than
silently accepting an unreviewed combination. The hash-checked Bochs and
guest-init overlays remain part of this build, including the optional state
profile described above.

Explicit Make parallelism is one job, and Go stages inherit `GOMAXPROCS=1` and
`GOFLAGS=-p=1`. Bochs is fetched shallowly at its exact commit. The amd64 Linux
v6.1 sources are cloned, configured, built, and removed in one build step, so
the large source tree is not retained in a separate image layer. The original
Bochs/QEMU kernel configurations and output paths are preserved. Other upstream
architecture stages remain in the file but are not covered by this amd64 exit
profile.

Repository fetch stages share one Ubuntu 22.04 Git installation, before their
source-specific build arguments. The amd64 cross-toolchain, BIOS, and Bochs
stages also share one native build-tools layer; BIOS no longer pulls a separate
floating Ubuntu release. Shared package layers discard apt indexes within the
same installation step. The two patch stages copy only their respective patch
inputs, so documentation or unrelated build-context changes do not invalidate
the emulator and init caches. A running conversion must be restarted to use a
changed Dockerfile; already completed compatible layers can still be reused.

The BIOS boot ISO uses Ubuntu 22.04's packaged GRUB rather than compiling GRUB
from source. Both `grub-common` and `grub-pc-bin` are pinned to
[`2.06-2ubuntu7.2`](https://packages.ubuntu.com/jammy-updates/grub-pc-bin),
with packages obtained through the configured Ubuntu apt archive.
[`grub-mkrescue`](https://manpages.ubuntu.com/manpages/jammy/man1/grub-mkrescue.1.html)
uses the packaged `/usr/lib/grub/i386-pc` BIOS modules and xorriso, retaining the
same kernel, boot configuration template, and `/out/boot.iso` output path.
This is Ubuntu's downstream build of GRUB 2.06, not bit-identical upstream
GRUB 2.06. The package version pins do not make the wider conversion hermetic,
and the resulting ISO still requires actual guest-boot qualification.

The amd64 BusyBox stage lists applets directly from the already compiled
`/out/bin/busybox` when creating its symlinks. The converter runs on
Linux/amd64, so this avoids a second host build solely for `--list`; the first
static BusyBox binary shipped in the guest is unchanged. Other architecture
stages retain their original build procedure.

These changes reduce build pressure; they do not guarantee a particular peak
memory or disk usage. BuildKit can still execute independent stages in parallel;
a constrained builder should separately set worker `max-parallelism=1` using
[Docker's BuildKit configuration](https://docs.docker.com/build/buildkit/configure/#max-parallelism).
WASI SDK and Binaryen remain x86-64 build tools, so the converter's Linux/amd64
build platform must be retained on an arm64 host.

The amd64 packer writes directly to its final `/out/${OUTPUT_NAME}` path in
one build step. Moving a large packed module in a later overlay layer can copy
the whole lower-layer file before removing the old name, requiring another
module-sized allocation even though packing itself succeeded. The single-step
layout avoids that particular copy-up; it does not bound Wizer's memory use or
the cache/exporter's storage requirements.

Qualification must run both successful and failing O programs under the actual
target engines, with exact exit status and observable output checks. Merely
applying patches or producing a Wasm header does not qualify this protocol.
