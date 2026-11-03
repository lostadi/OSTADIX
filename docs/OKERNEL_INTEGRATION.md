# OKernel integration branch

`integration/okernel-linux-plan9-20261103` collects the current OKernel source,
tests and documentation on top of `ostadix-BM` master
`b314fd264b63afcdcfb1e82117e659923bfce3db`. It includes the original working
changes based on `3dec485e2806c23cf7089a40465597da82c5b854`, with the overlapping
kernel build and smoke checks reconciled against the newer master.

The original checkout, its staging area, working virtual machines and saved
heads are preserved. Empty terminal-paste artifacts `Layer` and `gate:` are
excluded. Machine-specific caches, disks, compiled kernels and standalone proof
bundles remain external inputs; this Git branch contains source and test code.

## Included work

- The preserved Linux/original-9front compatibility profile, one operator
  console, common native namespace, original command/compiler provider,
  persistence and Plan 9 domain replacement on interruption.
- Strict separate admission of the original userland derivation. The new
  verifier checks the complete declared export set through read-only
  descriptors without calling the builder's extraction/revalidation routines.
  It retains exact receipt, original-file, tool, source, PAQ and kernel binding.
- Native namespace/session isolation, original u9fs/musl codec source recipes,
  bounded protected x86-64 file/startup interfaces and per-thread FS state.
- Original basic BusyBox CAT source/build reference capture, generic original
  linker-map preservation and exact compatibility pins for capture workers.
- Build-derived native image bindings, Python runtime checks and terminal
  completion parsing that ignores wrapped echoes of the command itself.
- Classification of all 17 added O-core sources in the language manifest.

Native images rebuilt from changed source use their generated image bindings;
independent foreign-binary and immutable-object pins remain checked. The two
`.patch` resources retain their exact payload bytes: their unified-diff context
contains significant leading spaces and tabs, so `.gitattributes` scopes Git's
whitespace exemption to those resources.

## Validation and reproduction

On the integrated branch, the 82-module validation run completed 644 tests:
630 passed and 14 skipped because their explicit runtime fixtures were not
selected. The three component-recipe suites passed another 24 tests without
skips. Fresh `O`, `ocorec` and `olangc` builds succeeded, all 252 classified
language sources parsed, and the protected x86-64 FS/TLS QEMU fixture passed
with matching kernel rebuilds. These checks qualify their stated components;
they do not qualify the unfinished whole-system target.

A later native session-identity run passed 16 tests without skips, including
eight added collision cases. These exercise production Linux virtqueue and
Plan 9 UART version/revocation paths with constructed trusted generations,
plus read-only authority and stale-handle checks. They run against the current
store's existing monotonic issuer; the historical R9 issuer patch is not
applied. Coverage is x86-64 native execution and AArch64 MIR validation, with
the previously admitted R9 monitor and live VMs preserved.

Build fresh branch tools without replacing the original checkout's compilers:

```sh
CARGO_BUILD_JOBS=2 cargo build --locked --bin O --bin ocorec --bin olangc
python3 scripts/check_language_sources.py check --jobs 4
```

The local development helper selects the exact available LLVM SDK, its parser
library and private cross-ISA tools. It only configures this command's shell
and ignored tool wrappers:

```sh
scripts/bm-dev-env.sh python3 -m unittest discover -s tests -p 'test_okernel_*.py' -v
scripts/bm-dev-env.sh python3 -m unittest \
  tests.test_plan9_userland_readonly_admission \
  tests.test_unified_userland_admission_readonly_integration \
  tests.test_unified_world_plan9_userland_admission \
  tests.test_ocore_ovfs_pins -v
```

The `p9` CLI defaults to a 120,000 ms invocation budget for original tools under
emulation. `Client.run` retains its 30,000 ms API default and the wire maximum
remains 300,000 ms. The longer CLI budget delays automatic hang detection;
`--timeout-ms` and Ctrl+C remain available. The focused budget regression uses
actual CLI/API requests with a local protocol fixture:

```sh
python3 -B -m unittest tests.test_p9_timeout_defaults -v
```

To qualify the exact current guest helper with original Plan 9 compiler and
linker execution, first create a new saved-state fork and deploy the current
helpers with `scripts/prepare_okernel_unified.py`. Then run:

```sh
python3 -B scripts/verify_okernel_p9_default_compile.py \
  --state /absolute/new/private/state --build /absolute/admitted/unified/build
```

This gate checks installed helper hashes, types `p9 7c`, `p9 7l` and the compiled
program without timeout overrides, and validates 120,000 ms in all three wire
requests. It retains the exact source, object, executable and complete protocol
captures after one paired save. It requires both original kernels to remain
live and owns only its explicitly forked test state. Previously frozen client
receipts retain their original helper hashes and qualification scope.

The current 33,362-byte client (`1d000bb7b1cfe958c3fe25b6d00c65ab9b8cb33f83f53b857cbefbbac7416d9e`)
passed this live check on X12, with the four focused budget tests passing
separately. This follow-up adds exact-byte runtime qualification and regression
coverage for the existing CLI setting.

Read the named tests' prerequisites. Some original-image, SDK, ABI and native
console tests require explicit captured fixtures and report a skip when those
fixtures are absent. A skip does not qualify that runtime. The pure admission
integration test denies filesystem writes and process launches during the
complete admission call. Its frozen build-7 provider remains a separately
pinned external input; the branch does not regenerate or relabel that receipt.

For the protected hardware fixture, use the instructions in
[`native_tls/README.md`](../ocore/kernel/native_tls/README.md) with a new output
directory and the original codec manifest. This test owns and closes only its
own QEMU process. The paired native kernel rebuilds use one frozen codec object
closure; they are not independent rebuilds of the upstream toolchain.

## Qualification limits

The simultaneous Linux/9front system is a compatibility experiment. It is not
the completed single native O-core OS, nor proof that the original kernels,
compilers, package managers or drivers have been lowered through O-core.
The source-native codec component and protected file/FS fixtures have narrower
explicit qualifications. The original CAT Linux reference still has no complete
native application admission; original assembly, floating-point/long-double,
weak linkage, helpers and operating-system interfaces remain required work.

Writable POSIX semantics, general processes/signals/PTYs, full original Linux
and Plan 9 ABI support, source-native driver/package-manager closures and the
final interactive self-contained `.O` are unfinished. No whole-system
efficiency improvement or physical X12 boot qualification is claimed.

See [implementation status](OKERNEL_UNIFIED_IMPLEMENTATION.md),
[operator documentation](OKERNEL_UNIFIED.md), and the
[original provider handoff](../ocore/guest/plan9/unified/HANDOFF.md) for the
separate component and runtime evidence.
