# Interactive package system under the O-core monitor

The package profile boots original AArch64 Linux and Alpine userspace beneath
the native O-core EL2 monitor in QEMU. Its shell, compiler, APK database, and
installed programs live on a persistent guest disk. The common native 9P store
is mounted at `/n/okernel`. The optional original-source profile links seven
O-core-generated u9fs/musl codec objects into the monitor's native peer.

This profile provides an interactive environment and original package tools.
The native x86-64 kernel's capability/process/IPC development gates remain a
separate execution profile. Linux and the installed guest programs retain their
original Linux ABI; this does not qualify complete Linux or Plan 9 source
lowering, physical hardware support, or a completed unified operating system.

## Prepare from a checkout

Use a Linux host with Python 3.12+, Bash, Cargo, Clang/LLD, `make`, `dtc`,
QEMU AArch64, `fakeroot`, GnuPG, and e2fsprogs. The Linux payload build also
requires the ordinary upstream kernel build tools (`bc`, Flex, Bison and Perl).
The builder authenticates original Alpine bootstrap archives and package
repositories, stages an AArch64 package closure, and creates regular disk-image
files. It does not install those packages on the host or write physical disks.

Build `olangc` and `ocorec`, then follow the
[original-source component recipe](../tools/ocore-runtime/u9fs/README.md) with
clean pinned u9fs and musl sources and the explicitly selected LLVM 22.1.6 SDK
and parser-library digest. Select `--isa aarch64 --verify` for the monitor;
retain the complete output directory, not just its top-level JSON file.

From the repository root:

```sh
cargo build --locked --bin ocorec --bin olangc
export OCORE_LINUX_NATIVE_9P_MANIFEST=/absolute/path/to/aarch64-output/native-codec.json
python3 scripts/okernel_package_domain.py build \
  --state "$HOME/.local/state/ostadix/okernel/source-native" \
  --network --namespace
python3 scripts/okernel_package_domain.py run \
  --state "$HOME/.local/state/ostadix/okernel/source-native"
```

The source-native manifest is an explicit input. The monitor build validates
both source-recipe/coverage chains, every object, the complete symbol closure,
and the bound semantic-test artifacts, then captures them under the state
directory. Omitting the manifest selects the original handwritten peer and
does not establish original-source codec execution.

The first source build needs network access and substantial build space. Rootfs
repository/package identities are recorded when the original package resolver
runs; this is not a promise that mutable repository indexes produce an identical
future disk. The Linux source archive, codec sources, recipes, compiler inputs,
and produced artifacts have their own recorded identities.

Inside the guest, ordinary shell commands, `cc`, `apk`, and `pkg` are available.
Write `/n/okernel/work/from-linux` and read `from-plan9` to exercise the native
peer. Plan9port tools, when installed through their original source recipe,
also use the shared namespace. They are guest Linux programs; the peer itself
is native monitor code.

Press **Ctrl+]** to sync, save the paired disk/namespace generation, and exit.
An EOF or terminated host session is not a completed save. Restart reopens the
saved disk and namespace with a fresh transport generation.

## Fork and verify

Fork an existing saved state into a new, short path before automated acceptance:

```sh
python3 scripts/fork_okernel_state.py \
  --source "$HOME/.local/state/ostadix/okernel/source-native" \
  --output "$HOME/okernel-check"
python3 scripts/verify_okernel_native_codec.py --state "$HOME/okernel-check"
```

The fork copies the selected immutable checkpoint and complete native-codec
capture. Snapshot paths are relocated into the fork; original source-recipe
paths remain provenance and are resolved against the captured identities.
The source VM's unsaved memory is outside this operation. The verifier boots
the fork twice, performs fresh shared-file exchanges with native execution
counters, compiles/runs original guest C code, checks Plan9port access, and saves
and reloads a consistent pair. It writes verification files into the selected
fork. Keep the path short because the QEMU control socket has a platform length
limit.

The separate original-9front dual-kernel experiment has additional command
dispatch and provider-recovery behavior. Its frozen host runtime and saved disk
are explicit external artifacts; they are not implied by this source-native
package profile or silently selected by its boot command.
