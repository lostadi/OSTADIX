# Compiling `.O` programs to Wasm

`olangc` has two distinct Wasm routes. Neither converts arbitrary foreign
language source directly into Wasm instructions.

| Route | Execution model | Current boundary |
| --- | --- | --- |
| `--target wasm` | Compile the generated O runtime to `wasm32-wasip1`. | Inline-only plans execute locally; shim-backed plans still need an admitted host provider. |
| `--target wasm --wasm-runtime-image IMAGE --wasm-builder-image IMAGE` | Compile the same generated O runtime as a native Linux executable, package it with supplied runtimes, then convert the container to an emulated Linux WASI module. | Opt-in ordinary `.O` input route; requires explicit runtime contents and external build tools. The Python fixture below passes in Wasmtime and Wasmer; other workloads require their own qualification. |

The direct route remains the smaller, non-emulated option. For example:

```sh
olangc examples/wasm_hello.O --target wasm -o hello.wasm
wasmtime run hello.wasm
```

The image route preserves the generated O evaluator, ExecutionPlan handling,
OValue crossings, and compatibility adapters. Python, Node, Bash, and other
commands execute inside the supplied Linux environment, not as browser host
processes. It is packaging plus CPU/OS emulation, not a static translation of
those interpreters into O operations.

## Supply two explicit images

Both flags require digest-pinned OCI image references of the form
`REGISTRY/REPOSITORY@sha256:DIGEST`. Each image must provide `linux/amd64`:

- The builder image must contain Rustup and the Rust toolchain pinned by the
  generated `cargo/rust-toolchain.toml`, including the
  `x86_64-unknown-linux-gnu` standard library, Cargo, a C compiler, the linker,
  and any native build dependencies. The build selects that installed
  toolchain explicitly and runs as root inside the builder container. The
  resulting GNU/Linux executable needs a compatible glibc loader and libraries
  in the runtime image; a musl-only Alpine runtime is not sufficient.
- The runtime image must contain every command and library the program needs:
  for example `python3`, `node`, `bash`, their standard libraries, imported
  packages, helper programs, and application data at the intended guest paths.
  Include required environment configuration in the image.

The runtime image's user is preserved, but the program starts in `/tmp` so O
can extract its embedded adapters. That user must be able to write there.
Relative application paths therefore resolve under `/tmp`, not the image's
original working directory; package assets at explicit guest paths.

There is no automatic runtime discovery or dependency-closure certification.
A digest pins image contents; it does not prove that a program can execute
with those contents. External daemons, credentials, network services, and
runtime-loaded assets need explicit provision and separate validation.

Install Docker with Buildx, a working Linux/amd64 build environment, and
`container2wasm`'s `c2w` command separately. Buildx is required for the local
converter overlay; the legacy Docker builder is not supported by this profile.
The compiler does not install these tools. Basic prerequisite checks are:

```sh
docker info
docker buildx version
c2w --version
```

Install Wasmtime and Wasmer as well to run the two-engine qualification gate.
Conversion can download additional build dependencies and require substantial
disk space. See the upstream
[installation instructions](https://github.com/container2wasm/container2wasm#getting-started).

Image builds execute supplied build tools and dependency build scripts. Use
images and sources you trust, and review the generated build context before
building. Pinning the two images alone does not make the entire Docker/Cargo/
container2wasm conversion hermetic or reproducible.

## Inspect without building

For example, a `program.O` may contain:

```O
python^(
__oval_result__ = 40 + 2
)_python
```

These are the image references used by the passing Python qualification below,
using Rust 1.97.1. Materializing another program with these images does not
qualify its execution. The Python image is not a complete environment for
arbitrary Node, Guix, or other programs; supply a suitable pinned image and
validate the resulting artifact for those workloads.

```sh
OLANG_WASM_RUNTIME_IMAGE='docker.io/library/python:3.11-slim-bookworm@sha256:b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250'
OLANG_WASM_BUILDER_IMAGE='docker.io/library/rust:1.97.1-slim-bookworm@sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b'

olangc program.O --target wasm -o program.wasm \
  --wasm-runtime-image "$OLANG_WASM_RUNTIME_IMAGE" \
  --wasm-builder-image "$OLANG_WASM_BUILDER_IMAGE" \
  --materialize-only ./program-wasm-build
```

The output directory must not already exist. Materialization writes the
generated Cargo project under `cargo/`, `Dockerfile.wasm-container`, its
context-filtering `.dockerignore`, `plan.txt`, the paired converter assets under
`wasm-exit/`, and the source-bound `wasm-build.json` recipe. The manifest's
`converter` field records the `amd64-bochs-cold-boot-exit-status-v1` profile,
upstream source commit, converter Dockerfile hash, and individual overlay
hashes. It invokes neither Cargo nor Docker nor
`c2w`, produces no `.wasm` artifact, and always retains the directory. Do not
combine `--materialize-only` with `--keep-build-dir`.

The recipe records build inputs and the unqualified execution profile; it is
not evidence of successful compilation, runtime closure, or hermetic execution.

## Build and run

After supplying real image references and installing the prerequisites:

```sh
olangc program.O --target wasm -o program.wasm \
  --wasm-runtime-image "$OLANG_WASM_RUNTIME_IMAGE" \
  --wasm-builder-image "$OLANG_WASM_BUILDER_IMAGE" \
  --keep-build-dir

wasmtime run ./program.wasm --no-stdin
wasmer run ./program.wasm -- --no-stdin
```

The generated multistage Dockerfile compiles the fixed native binary
`o-program` in the builder image and copies it into the runtime image. The
compiler uses `docker buildx build --load --platform=linux/amd64` so the
resulting image is available to `c2w`, then verifies its reported platform.

Conversion uses `c2w --target-arch=amd64`, `VM_MEMORY_SIZE_MB=512`, and
`OPTIMIZATION_MODE=native`, with the compiler's frozen converter Dockerfile and
hash-checked exit-status overlay supplied as a Buildx context. Here `native`
means **cold boot of the emulated Linux guest**, without Wizer's preboot snapshot
optimization. It does not run the workload natively on the browser or WASI host.
The complete kernel, guest filesystem, and emulator remain in the single Wasm
artifact. The converter uses verified prebuilt wasi-vfs v0.3.0 tooling to reduce
build overhead; it still compiles the patched emulator and boots real Linux.

The converter recipe is derived from container2wasm v0.8.4, source commit
`6ed3d98882a2b22eafc1334f574c364a5b2b8c47`, paired with Bochs commit
`a88d1f687ec83ff82b5318f59dcecb8dab44fc83`. The overlay checks the original
source-file hashes before patching guest init and the emulator. Its exit-status
channel drains guest terminal output and reports the workload's status through
an emulated I/O port to WASI `proc_exit`, instead of relying on guest poweroff.
This adds no external stdout parser or additional host import. Actual success
and failure propagation are part of the qualification gate below, not inferred
from successful compilation. See the [overlay design](../src/bin/olangc/wasm_exit/README.md).

The result includes an emulated Linux guest;
it is not a WASI component or container2wasm's separate `--to-js` Emscripten
output. Upstream describes the packaging and emulator in
[How does it work](https://github.com/container2wasm/container2wasm#how-does-it-work).

`--keep-build-dir` retains the compiler's intermediate directory for inspection;
the compiler reports its path. Docker image/cache storage is separate from that
directory. `--no-stdin` is a container2wasm guest option for noninteractive
programs; omit it only when testing a suitable interactive host. No host
directory or networking access is granted by the example command. Upstream
currently lists Wasmer stdin as unsupported; do not assume equivalent
interactive behavior across WASI engines. See the
[runtime integration status](https://github.com/container2wasm/container2wasm#wasi-runtimes-integration-status).

## Limits and validation status

On 2026-09-12, the fresh Python fixture passed the complete opt-in gate:
8 evidence-helper tests and the end-to-end test containing a real compiler
build and all five executions below. The run completed with 9 tests passing,
no skips, and a `passed` receipt in 2,663.395 seconds.

| Engine | Case | Observed exit status |
| --- | --- | --- |
| Wasmtime 47.0.3 | Success | 0 |
| Wasmtime 47.0.3 | Intentional Python exception | 1 |
| Wasmer 7.2.1 | Success | 0 |
| Wasmer 7.2.1 | Intentional Python exception | 1 |
| Wasmtime 47.0.3 | Empty root-like preopens regression | 0 |

Every success printed `OSTADIX WASM Linux 42`. Both failure executions reported
`OSTADIX WASM INTENTIONAL FAILURE` without the success marker. The original
source was deleted before execution; the Docker builder VM was stopped during
the first engine check and remained off for the remaining checks.

The artifact is 156,555,045 bytes (about 149 MiB), with SHA-256
`1b676c6088b84d73906f7dca64149c474f1ad0372f6b0c6ae8c945b52c8c52a3`.
Its fixture source SHA-256 is
`9c6da9fae1fb58f299c3a458a3a1df8163dfa9679e0a7e46236fe6c51c7d3f69`.
The run used container2wasm v0.8.4 with the compiler's recorded overlay.
Earlier attempts that hit a build deadline or exhausted builder storage remain
failed attempts; they are not counted as passing evidence. The passing run used
the 7,200-second build budget and unchanged 600-second execution budgets.

This is qualification of one packaged Python workload, not arbitrary runtime
closures, Guix, or browser integration. The compiler itself does not execute
newly built programs to certify them; its build recipe is separate from the
test's execution receipt.

The opt-in gate builds one fresh Python `.O` artifact, removes its source, and
runs that same artifact under both Wasmtime and Wasmer from an unrelated
directory, without requested host preopens or an inherited host environment. Each engine
runs a successful case and an intentional Python exception. The negative case
explicitly passes `OSTADIX_WASM_EXPECT_FAILURE=1` through the engine's `--env`
option into the guest; it does not depend on an ambient host variable.
A fifth execution maps one fresh, empty, private directory to the guest aliases
`/`, `.`, and `//` in Wasmtime. This reproduces the root-preopen layout that
exposed an upstream empty-MSR-filename startup loop. It must still print the
success marker and exit zero; it grants no access to user files.
The gate requires both image variables above and Docker, Buildx, `c2w`,
Wasmtime, and Wasmer; it is skipped unless explicitly enabled:

```sh
export OLANG_WASM_RUNTIME_IMAGE OLANG_WASM_BUILDER_IMAGE
OSTADIX_RUN_WASM_CONTAINER_E2E=1 \
  python3 -m unittest discover -s tests -p test_olang_wasm_container.py -v
```

It uses `target/debug/olangc` by default; set `OLANGC_WASM_TEST_BIN` to test
another compiler. Set `OLANG_WASM_E2E_DIR` to a directory that does not yet exist
to retain the artifact, build/runtime logs, and a hash-bound `receipt.json` on
success or failure. Without that setting, the gate uses a temporary directory.
The build-only deadline is 7,200 seconds (two hours), allowing the low-resource
profile to compile Linux, Rust, and Bochs from a cold cache with limited
parallelism. Each of the five runtime checks retains its independent
600-second deadline. The receipt records the actual deadline for each command;
changing the test does not extend a qualification run already in progress or
turn a previous timeout into a pass.
Success must print `OSTADIX WASM Linux 42` and return zero.
Failure must report `OSTADIX WASM INTENTIONAL FAILURE`, omit the success marker,
and return exactly one. These checks exercise guest failure propagation as well
as execution; artifact existence, a valid header, or a skipped test is not a pass.

- The image route cannot currently be combined with `--browser-bundle` or
  `--runtime-bundle`.
- Existing browser bundles retain their explicit whole-program-provider
  requirement for hosted/effectful plans. Supplying an OCI image does not
  silently change that contract.
- Upstream can run its WASI container artifacts in a browser, but this route's
  raw output has not been validated with O's browser host. That host needs a
  qualified import profile, Worker lifecycle, and suitable polling/stdin
  support. This command does not produce a ready-to-run browser application.
  See the upstream [WASI browser example](https://github.com/container2wasm/container2wasm/tree/main/examples/wasi-browser).
- Host paths are not guest assets. A `.O` program referring to a local Downloads
  directory, a Guix disk image, or a native QEMU controller still needs those
  files and compatible executables inside its guest environment. Packaging the
  source text does not package arbitrary files it may read later, and nested
  virtualization or emulation is not qualified by this feature.
- Materialization, helper tests, or a successful image build alone are not
  end-to-end compilation and execution success. The passing fixture does not
  qualify a different program or runtime image. Validate its actual artifact
  under the intended WASI
  engine, including output, exit status, missing dependencies, and any required
  input behavior, before relying on it. Signal termination is represented by
  an exit-status number, not native host signal delivery; kernel or exit-channel
  failures may still require an execution timeout.
