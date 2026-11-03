# Original BusyBox basic-cat source/build reference

`capture.py` builds the unchanged BusyBox 1.36.1 release using its own
Kconfig, Kbuild and single-applet implementation. The declared profile enables
`CAT` and static linking, disables `FEATURE_CATN` and `FEATURE_CATV`, and uses
the original 4 KiB copy buffer. It does not claim the other BusyBox applets or
optional `cat` functionality.

This is an original-source **Linux reference build**. It is not an admitted
O-core application. The top-level command succeeds only when all five recipe
steps, the configured producer inventory, source fidelity checks, requested ELF
layout and all 16 Linux behavior cases pass. A separate, preserved generic
capture can fail; its failure never becomes source-lowering admission.

## Reproduce

The defaults name existing local, pinned source/runtime/toolchain inputs on
X12. Each run must use a new output directory. It copies the original musl
reference artifacts and headers; it does not rebuild musl or modify a VM.

```sh
cd /home/ustad/ostadix-BM
python3 -B tools/ocore-runtime/busybox/capture.py run \
  --output "$HOME/.cache/okernel-busybox-cat-reference-$(date +%Y%m%dT%H%M%S)"
python3 -B -m unittest discover \
  -s tools/ocore-runtime/busybox -p 'test_*.py' -v
```

Optional `--archive-directory`, `--musl-reference` and `--sdk` arguments select
other copies of those exact inputs. Original musl's shell driver requires a
shell-word-safe output path; the builder checks that restriction. Builds use
two jobs. The capture records host tools, compiler commands, native outputs,
LLVM attempts and their failures; generated private recipe/helper files are
digest-bound and made read-only.

The release archive is `busybox_1.36.1.orig.tar.bz2`, 2,525,473 bytes, SHA-256
`b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314`.
The checksum and size must agree with the supplied local Ubuntu `.dsc`.
The detached signature and `.dsc` identities are retained; signature trust
is **not verified** and Debian patches are **not applied**. A deterministic
private Git import supplies the clean commit required by generic capture.
It is explicitly not represented as an upstream Git commit. Every release
file, symlink, original mode and Git entry is compared, including files that
the upstream `.gitignore` would otherwise omit. Original archive directories
and their modes are also recorded, since Git does not represent empty ones.

The musl reference input is the complete original x86-64 source build at
`~/.cache/okernel-musl-source-current-soc9clfn`. Its existing result, complete
source inventory, unchanged source commit
`0784374d561435f7c787a555aeab8ede699ed298`, startup/static artifacts, driver
templates and 218 headers are checked and bound into the new receipt.
These source-built artifacts remain **reference inputs**, not lowered libc.
The selected LLVM SDK is 22.1.6 and the actual target is
`x86_64-unknown-linux-musl`.

## What the receipt proves

`result.json` distinguishes `reference_complete` from generic capture and
native qualification. Follow its artifact records for:

- Private source import and complete archive/tree equivalence before and
  after the build.
- Original `allnoconfig` output, explicit selection changes, `oldconfig`
  input/output and a repeated `oldconfig` fixed point. This Kconfig fork
  resets Boolean selections in `KCONFIG_ALLCONFIG`; the builder uses its
  own documented allnoconfig/select/oldconfig route instead.
- The original complete make dry run, all Kbuild command files, matching
  successful producer occurrences, generated headers, all configured objects
  and ordered archives. Cold archive members and archive-format
  `built-in.o` outputs stay in the inventory. Host tools, assembly and probes
  stay in the evidence; no guessed exclusion grants admission.
- Actual final linker argv/tool and input identities, the original link map
  and selected reference archive members. System GCC startup and helper
  providers remain explicit unlowered input/source obligations.
- Original ELF entry and every program header. The current profile's
  authentic `CONFIG_EXTRA_LDFLAGS` sets minimum `PT_LOAD` to `0x02000000`;
  this does not establish compatibility with O-core's ABI or loader.
- Sixteen behavior cases with exact raw expected and actual stdin, stdout,
  stderr, exit codes, environment and file fixtures. They cover 0, 4 KiB,
  64 KiB and 1 MiB data, file/stdin/concatenation, `-u`, a rejected `-n`,
  continued processing after a missing file, long allocator-backed errors
  and `ENOSPC` from `/dev/full`. These are host Linux tests, not kernel tests.

The frozen R3 default-address reference and failed R1/R2 attempts are retained
in their original cache directories. R4 is a fresh build with a declared
address-profile difference, not a claim of binary identity with R3.

The verified R4 result is
`/home/ustad/.cache/okernel-busybox-cat-reference-20261103-r4/result.json`.
All five original recipe steps exit zero, the full configured inventory has
no issues, and all 16 behavior cases pass. It retains 137 C and five assembly
producers, 175 object outputs, 56 archives (28 `.a` and 28 archive-format
`built-in.o` outputs), 65 final linker input occurrences and 220 selected
reference archive-member records. The original ELF is 61,896 bytes, entry
`0x020084ec`, SHA-256
`f64796a31b1aee3c600ded424911ef559934e1ebe191a1411ad046e57510303d`.
Its private import commit is
`3fb530158cb6928a6d2e63676d4ccee829314a7f`.
`provenance/post-build-identity-audit.json` independently checks 3,178 stable
artifact identities bound by the receipts, with zero mismatches. R4's generic
capture remains false and its frozen worker and failure records are retained.

## Native admission remains blocked

All `native_ocore_application_qualified`, `ocore_lowering_complete` and
`dependency_closure_complete` flags remain false. The generic report retains
stdin configure probes, unclassified host/probe units and assembly importer
limits. Its original linker-map instrumentation conflict, if present in the
frozen capture worker, remains reported; original upstream map flags are not
removed to obtain a passing result.

The original startup, libc/TLS, allocator, variadic formatting, GCC helpers,
POSIX/Linux ABI and file/process services still need complete compiler-owned
admission. Required musl-unit import receipts separately reject crt1 module
assembly, vfprintf's strictfp attribute and `__init_tls` external-weak
`_DYNAMIC` linkage. A successful happy-path `cat` execution cannot exclude
those providers: the original long-error path requires allocator and formatted
output support. No source-body filtering, replacement helper, target-triple
rewrite or embedded reference ELF is counted as lowered implementation.
