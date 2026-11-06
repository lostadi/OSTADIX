# Persistent Linux package domain

This profile runs original Alpine AArch64 userspace in a real Linux guest under
the O-core EL2 monitor. Linux performs the normal shell, process, dynamic-linker,
package-manager and filesystem work. O-core mediates its virtual device access.
It does not lower Linux, GCC, or the installed packages into O-core code.

The unified package/ABI target and the current common native 9P namespace
boundary are described in [OKERNEL_PACKAGE_NAMESPACE.md](../../../../docs/OKERNEL_PACKAGE_NAMESPACE.md).
The persistent Linux/native-codec boot entry is described in
[OKERNEL_PACKAGE_BOOT.md](../../../../docs/OKERNEL_PACKAGE_BOOT.md).
The native 9P peer is a protocol client, not a complete Plan 9 executable ABI.

The boot archive mounts the governed `/dev/vda` ext4 disk and uses ordinary
`switch_root`. The root filesystem, APK database, installed commands, `/work`,
and source build outputs all reside on that disk. The host runner owns durable
disk snapshots; a device flush alone orders RAM writes and is not host-storage
durability.

## Build inputs and artifacts

From the repository root, using Python 3.12+, `fakeroot`, GnuPG and e2fsprogs:

```sh
python3 ocore/guest/linux/package-domain/build.py \
    --output /absolute/new-output-directory \
    --cache "$HOME/.cache/ostadix/package-domain" \
    --disk-bytes 536870912
```

The builder writes `initramfs.cpio`, `initramfs.cpio.gz`,
`package-domain.ext4`, and `package-domain.json`. It never overwrites an
existing output directory or opens a physical block device. `fakeroot` preserves
guest ownership metadata without requiring privileged host extraction.

Both bootstrap rootfs archives are verified using Alpine's release signature
and pinned primary fingerprint
`0482D84022F52DF1C4E7CD43293ACD0907D9495A`. The verified original x86_64 APK tool
resolves the AArch64 dependency closure and verifies repository-index and APK
signatures using Alpine's supplied public keys. It does not install packages on
the host. The manifest records each archive, index, package and output hash.

The initial offline repositories are Alpine v3.24 `main` and `community`.
`--package NAME` may be repeated to stage additional complete package closures
alongside the compiler baseline. Full signed indexes are retained; a package
listed by an index still needs its archive staged before an offline install.
The default profile has no guest network device. Network-enabled monitor
profiles require a separate explicit mediated Ethernet grant.

## Add repository packages later

Stop the guest before changing its repository media. Existing installed
packages, the APK database and `/work` are retained:

```sh
python3 scripts/stage_okernel_repository.py \
    --state "$HOME/.local/state/ostadix/okernel/package-domain" \
    --package curl --package git
```

The stager takes the same exclusive domain lock as the runner, reuses and
reverifies the disk's signed indexes, resolves requested names together with
the guest's existing APK world, and downloads the complete authenticated
closure. It edits a private candidate through `debugfs`, reads back every
payload, checks the filesystem, and publishes a new immutable disk generation
with the previous generation retained. Workspace and APK state must compare
unchanged before publication. No host root privileges or host package
installation are needed.

This stages repository archives; it does not install them. After restarting
the guest, run `pkg install curl git` or use the full original `apk` interface.
This offline transport is an explicit operation while the guest is stopped.
It remains useful when no network device is granted.

## Guest networking and local helper upgrades

`pkg-net online` uses the original Linux `ip` and BusyBox `udhcpc` commands to
configure an explicitly granted Ethernet device. Its DHCP hook configures the
address, default route and DNS; only a completed configuration selects the
original Alpine HTTPS repositories. A missing lease or failed hook returns a
failure and leaves the previous APK repository selection intact. The runner
records and provisions a guest real-time clock value before ordinary TLS
certificate checks; it never changes the host's clock.

```sh
# Inside a guest whose monitor explicitly grants networking:
pkg-net online
pkg install curl git
pkg-net status
pkg-net offline
```

`offline` selects the staged local repositories. It does not withdraw an
O-core device grant; device authority remains the monitor's responsibility.

Existing disks can receive the local source-first package helper, network
helper and DHCP hook without reinstalling their packages:

```sh
python3 scripts/update_okernel_guest_tools.py \
    --state "$HOME/.local/state/ostadix/okernel/package-domain"
```

The guest must be stopped. This updater uses the domain lock, a private disk
candidate, exact fixed helper paths, complete readback hashes and root-owned
executable modes. It preserves `/work`, APK configuration and the installed
database, publishes a new immutable head, retains the previous disk, and
records each deployed source/tool hash. It does not execute the helpers on the
host or silently replace arbitrary guest files.

## Use inside the guest

The ready marker is `OKERNEL PACKAGE DOMAIN READY`; the shell prompt is `pkg> `.

```sh
pkg help
pkg install zlib
pkg install jq
apk add gcc make musl-dev
cd /work
printf '#include <stdio.h>\nint main(void){puts("hello from Linux");}\n' > hello.c
cc hello.c -o hello
./hello
sync
```

`pkg install NAME` prefers a registered source provider. The initial source
provider is zlib 1.3.2 with the Alpine security patch. It checks the source and
patch against the pinned SHA-512 values from Alpine's APKBUILD, installs the
original compiler dependency closure through APK, and runs upstream configure,
Make, tests, and installation inside the guest. Source metadata is normalized
to `SOURCE_DATE_EPOCH=0` because this virtual profile starts without an RTC.
Source bytes remain unchanged except for the declared security patch.

`pkg source zlib` explicitly requires the source provider. A source checksum,
patch, configure, build or test failure is returned to the caller; it never
silently falls back to a binary package. Names without a registered provider
use original APK through `pkg install NAME`. `pkg add NAME` explicitly selects
APK. The complete original `apk` interface remains available.

Support for multiple repositories currently means those two APK repositories.
Other repository formats and general automatic source-recipe inference are not
implemented by this profile.

## Original Plan9port command-line tools

```sh
pkg install plan9port
9 rc -c 'echo original-rc > /n/okernel/work/from-rc'
rc -c 'cat /n/okernel/work/from-rc'
mk -f /path/to/mkfile
```

The provider selects the original `rc`, `mk`, `9p`, `9pserve`, `u9fs`, `yacc` and `cleanname`
commands and their complete selected library closure, using upstream
`dist/buildmk` and the original mkfiles. It preserves the complete source
archive/tree and records compiler, dependencies, build configuration, commands,
tests, dynamic libraries and installed output hashes outside the source tree.
Each build starts from authenticated archive bytes and installs a separate
runtime generation. Existing unrelated commands or prefix directories are
preserved instead of silently overwritten.
If new bridge health fails, activation restores the prior owned prefix and
restarts its bridge when it was running. A failed first installation removes
only its newly created links. The failed receipt remains incomplete and both
source/runtime generations remain available for inspection.

`pkg install plan9port` reuses an existing generation only after verifying its
two pinned source archives, signed GNU ABI closure, compiler binding, provider
and local bridge/patch identities, complete receipt and installed output hashes,
inventory and command links. It republishes the same receipt to the common
namespace. Corruption returns a clear failure and preserves existing files;
`pkg source plan9port` explicitly requests a new build. The original signed
build dependency closure includes Linux headers needed by lib9 and libip.

`status` or `okernel-status` reports the actual hostname/kernel, native mount,
root-storage space, installed APK count and console save/reconnect controls.

The source is official
[9fans/plan9port commit 1f1396913fb5372408f442ed26933f5ae4b399cd](https://github.com/9fans/plan9port/tree/1f1396913fb5372408f442ed26933f5ae4b399cd),
with the archive SHA-256 pinned in the builder and provider. This is a
content-verified HTTPS source pin, not an upstream release-signature claim.
An absent staged source archive is downloaded using original guest Curl.
Compiler/build tools use the configured original signed APK repositories. Positive
`SOURCE_DATE_EPOCH=1` is the default because upstream mk uses zero file mtimes
to represent missing files.

This is original Plan9port userland on the Linux ABI, not a complete Plan 9
kernel or executable ABI. Graphical tools are not selected.

The original u9fs authentication code uses `ruserok` and netgroups, which musl
does not fully provide. Its source is therefore compiled against a private,
complete original GNU libc compiler/runtime closure. Original APT resolves the
ARM64 `libc6-dev` and `libgcc-s1` dependency graph from signed Ubuntu archives
in private host state. Verification rechecks signatures, signed index/package
hashes, the original solver plan and reconstructed payloads. No host packages
or Ubuntu guest system are installed and no package scripts execute.

Fresh rootfs builds capture or reverify this dependency automatically. To
upgrade an existing stopped disk, stage the verified closure with the helpers:

```sh
python3 scripts/build_glibc_abi.py --output /absolute/new-gnu-abi
python3 scripts/update_okernel_guest_tools.py \
    --state "$HOME/.local/state/ostadix/okernel/package-domain" \
    --glibc-abi /absolute/new-gnu-abi
```

The recorded GCC binding excludes ambient libc/fortify headers, uses original
GNU headers/initialization objects and a private ELF interpreter, and retains
GCC's original initialization objects. The u9fs launcher sets its own private
GNU library path; other tools retain original musl. GNU loader `--list` and
ELF metadata record actual dependencies. Global `/lib` and the host library
environment are not changed. This is a dual-libc application profile on the
same Linux kernel, not an emulated replacement for the authentication APIs.

## Original 9P tools on the common native objects

The source recipe also builds pinned original
[u9fs](https://github.com/Plan9-Archive/u9fs/tree/fcec3e1e2e8e8c28b89270e6c44554c4ca9e50a9)
and Plan9port's original
[`9pserve`](https://9fans.github.io/plan9port/man/man4/9pserve.html).
A local process/FD supervisor connects them through a socket pair and a
private guest Unix socket. The original server/client implementations retain
their 9P encoding, decoding and file operations. No TCP listener is introduced.
The export is the existing native `okernel` mount at `/n/okernel`; an ordinary
directory with that spelling is rejected.

The declared `u9fs-path-hardening.patch` validates names after upstream escape
decoding and bounds malformed frames. Its exact bytes and hash, the pristine
archive/source identity and the patched source inventory are all retained in
the build receipt. The supervisor and service helper identities are recorded
separately from upstream source.

When the native mount is present, source installation activates and tests the
original wire roundtrip before reporting success. PID1 sets
`NAMESPACE=/run/okernel-9p` and health-starts an already installed bridge after
mounting the native objects. A bridge failure is visible and leaves the shell
available for repair. Host source feasibility builds explicitly record the
absence of this guest/native service proof.

```sh
pkg source plan9port        # Also upgrades a retained older recipe generation
pkg-9p status
9p -n ls okernel/work
printf 'ordinary Linux file write\n' > /n/okernel/work/example
9p -n read okernel/work/example
printf 'original Plan9port wire write\n' | 9p -n write okernel/work/example
cat /n/okernel/work/example
pkg-9p test
```

`pkg-9p start`, `stop`, and `status` operate on the identity-checked supervisor
and its original server processes. The separate native O-core wire peer uses
an independent native grant against the same objects. Neither protocol path
claims a complete Plan 9 binary or kernel ABI.
