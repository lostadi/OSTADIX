# Android RISC-V source preparation

`scripts/prepare_android_riscv64_toolchain.py` prepares an isolated correction for
four Android RISC-V `libc` open flags. It serves both terminal users and agents:
the CLI emits JSON, and the prepared directory contains the exact source paths,
compiler identities, hashes, build environment, and execution receipts.

This is an experimental, pinned build procedure. A prepared directory or a
successful cross-build is **not** native execution qualification. The script
always reports `supported_execution: false`; the acceptance checks below remain
necessary for each compiler, application, and guest combination.

## What is corrected

The inspected crates `libc` 0.2.185, 0.2.186, and 0.2.189 encode these four values
as hexadecimal in `src/unix/linux_like/android/b64/riscv64/mod.rs`. Android NDK r30
API 37 RISC-V headers encode the corresponding values as octal:

| Constant | Original Rust literal | Corrected Rust literal |
| --- | --- | --- |
| `O_DIRECT` | `0x40000` | `0o40000` |
| `O_DIRECTORY` | `0x200000` | `0o200000` |
| `O_NOFOLLOW` | `0x400000` | `0o400000` |
| `O_LARGEFILE` | `0x100000` | `0o100000` |

These are different integer values, not a formatting change. File operations
using the incorrect constants can fail or lose their intended flag behavior.
Changing an application's `libc` alone leaves the copy compiled into a rebuilt
Rust standard library unchanged.

The preparation script reads each supplied application's lock plus the selected
Rust library's lock. Each exact crate archive must match its lock's SHA-256. It
copies every archive member, preserving upstream source and license notices,
then changes only the four expected definitions. Different or already corrected
definitions are rejected for inspection. No dependency upgrade is performed.

Each application lock gets its own Cargo `paths` override containing **one**
exact crate version. A shared list of several libc paths is incorrect: Cargo
can choose the first compatible path even when a different version remains in
the lock. The unit graph must establish the actual selected version. Cargo
documents that this override must preserve the dependency graph. The prepared
crates retain their original manifests. See the [Cargo dependency override
reference](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html#paths-overrides).

For `-Z build-std`, the script also copies the selected `rust/library` directory,
adds an exact-version `libc` path patch to its `Cargo.toml`, and removes only the
`source` and `checksum` lines of that libc entry from the **copied** lock. All
input locks and installed Rust sources remain byte-for-byte unchanged.

## Prepare once, inspect, then build

Use Python 3.11 or newer. Install the selected nightly's `rust-src` component
before preparation. Supply absolute executables from the same selected Rust
toolchain; the script records their full verbose versions and executable hashes.
The inspected prototype used rustc `1.98.0-nightly` commit `4429659e4` and Cargo
`1.98.0-nightly` commit `a595d0da2`.

```sh
python3 scripts/prepare_android_riscv64_toolchain.py \
  --output /absolute/new/android-riscv64-prepared \
  --lock /absolute/OSTADIX/Cargo.lock \
  --lock /absolute/OSTADIX/mcp/ostadix_lang_mcp_server/Cargo.lock \
  --rustc /absolute/selected-nightly/bin/rustc \
  --cargo /absolute/selected-nightly/bin/cargo \
  --ndk-cc /absolute/NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/riscv64-linux-android37-clang \
  --offline
```

`--rust-library` can explicitly select a source directory; the default is
`lib/rustlib/src/rust/library` under the selected compiler's sysroot. When this
option is used, verify that the supplied source matches the recorded compiler.
`--archive-dir` can be repeated for local `.crate` archive directories. The script
also discovers Cargo's existing archive cache without modifying it. `--offline`
forbids downloads; omitting it permits missing archives to be downloaded from
`static.crates.io` into the new output directory and checksum-verified there.

`--ndk-cc` is optional. It compiles C static assertions for all four constants,
requires Android/RISC-V64/API 37+ predefined macros, and verifies that the result
is a real RISC-V64 ELF object. This verifies the compiler/header agreement; it
does not execute the object in Android. The NDK argument must be a compiler that
runs on the build host and targets Android, not a guest-side Linux compiler.

Existing output directories are refused. Failed preparations retain
`status.json` and their partial artifacts for inspection. Start a new directory
for a retry. No global registry, installed toolchain, application manifest, or
application lock is edited.

Inspect `provenance.json`, `build-environment.json`, `paths-override-VERSION.toml`, and the
original/derived file-hash manifests. Build from the intended workspace:

```sh
python3 /absolute/OSTADIX/scripts/prepare_android_riscv64_toolchain.py \
  run /absolute/new/android-riscv64-prepared -- \
  build --locked --offline -Z build-std \
  --target riscv64-linux-android --bin O --message-format=json
```

The `run` interface requires an explicit `build`, `check`, or `test` action,
`--locked`/`--frozen`, `-Z build-std`, and exactly one explicit Android RISC-V
target. It uses Cargo's `locate-project --workspace` (including any explicit
`--manifest-path`) to find the actual workspace lock, requires its bytes to match
a prepared application lock, and selects that lock's single-version config.
Several application locks are supported; a single lock containing several libc
versions is refused because `paths` cannot preserve that selection faithfully.
It verifies the prepared source hashes and recorded tool identities,
then supplies the selected `--config` and environment to Cargo. Caller arguments
are passed as literal argument-array elements, with no shell evaluation. The
exact command and environment overlay appear on stderr; Cargo's stdout remains
available for JSON artifacts. `run-*.json` records the child exit status. Running
`test` on a cross target still requires a separately configured real target
runner; this helper does not emulate a guest.

The isolated target directory defaults to `PREPARED/target`. Additional native
dependencies and their environment (for example OpenSSL or pkg-config) remain
the caller's responsibility. `run` owns its `--config` source override. Direct
Cargo invocation using `build-environment.json` remains available when a build
needs more configurations, with the same source-verification obligations.

## The standard-library hook is internal

The emitted environment uses `__CARGO_TESTS_ONLY_SRC_ROOT` to point `build-std`
at the copied library. This is Cargo's internal testing hook, **not a stable
upstream interface**. The inspected [pinned Cargo source](https://github.com/rust-lang/cargo/blob/a595d0da21f228b7fdae64d3d5c0e527ea66bb59/src/cargo/core/compiler/standard_lib.rs)
reads it in `detect_sysroot_src_path`. Record the selected Cargo commit and
revalidate the actual unit graph and compiled source paths whenever it changes.
The script records identity; it does not assume every future nightly retains
this behavior.

## Required acceptance evidence

For each application workspace, first capture its actual Cargo unit graph using
the prepared `run` interface with `build --locked --offline -Z build-std
-Z unstable-options --unit-graph --target riscv64-linux-android` and the desired
package/target selection. Then build with `--message-format=json`. Inspect both
records and require:

1. Every resolved/compiled `libc` version points to its prepared crate path.
   Check the main workspace and the separately locked MCP workspace independently.
2. The `std`/`core` sources point to `PREPARED/rust-library`, and the libc compiled
   for std is the exact version patched in the copied library lock. A registry
   source in either graph is an unresolved qualification failure.
3. Original and copied locks retain their recorded hashes after the build.
   Join built artifact hashes to the bytes deployed in the actual Android guest.
4. Native probes check flag values and behavior: create/open/read files,
   `create_new`/exclusive creation, directory opening, and rejection of a symlink
   when `O_NOFOLLOW` is requested. Exercise both application libc and Rust std
   operations, then run the OSTADIX acceptance and stress harnesses.

The procedure cannot establish native compiler availability, implementation
semantics, or comprehensive platform support by itself. Retain failed attempts
and the exact guest image/API/ABI alongside successful evidence.

Focused preparation tests:

```sh
python3 -m unittest discover -s tests -p test_prepare_android_riscv64_toolchain.py -v
```
