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

Both routes accept `--browser-bundle DIR`, but emit distinct browser schemas
and execution hosts. Without image flags, the existing direct-WASI v1 contract
is unchanged: hosted/effectful plans require an explicit whole-program provider.
With both image flags, the Linux browser bundle executes its packaged guest
locally in a Worker; it does not use that provider route.
The additional `--browser-guix` flag explicitly selects the interactive,
origin-private Guix profile described below. It is implemented in source but
has not received a fresh build or runtime qualification.

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

## Linux browser bundles

To package the image route with its dedicated browser host, use both image pins
and `--browser-bundle` together:

```sh
olangc program.O --target wasm \
  --wasm-runtime-image "$OLANG_WASM_RUNTIME_IMAGE" \
  --wasm-builder-image "$OLANG_WASM_BUILDER_IMAGE" \
  --browser-bundle ./program-linux-browser

python3 apps/olang-browser-wasi/serve.py ./program-linux-browser --port 8000
```

Open `http://127.0.0.1:8000/`. The output directory must not already exist.
Do not combine `--browser-bundle` with `-o`/`--output`, `--materialize-only`, or
`--keep-build-dir`; its artifact is `DIR/program.wasm`. The image route still
cannot be combined with `--runtime-bundle`.

The emitted manifest uses `ostadix.olang-linux-browser-bundle/v1`, distinct from
`ostadix.olang-browser-bundle/v1`. It binds `program.O`, `program.wasm`,
`program.plan.txt`, the exact selected adapters and grants, host assets, and
`wasm-build.json`. Before execution, the Linux runner checks that the build
record's source, plan, adapter hashes, and grants agree with the bundle. That
record also carries the image pins and converter recipe hashes. These are
consistency checks, not proof that an arbitrary runtime closure works or that
the wider image build was hermetic. The recipe's execution/closure/browser
qualification flags remain false; separate execution evidence is required.

The original `compatibility` and `provider` fields deliberately retain the
**direct-WASI assessment**. For example, a Python plan can still have
`provider.required: true` there. In the Linux schema those fields are
informative only: they do not select the execution route, summon a provider,
or claim Python can execute directly in WASI. The distinct Linux schema selects
the embedded guest. The Linux runner rejects an explicitly supplied `provider`
option rather than redirecting execution to an external service.

The sealed Linux profile, without `--browser-guix`, runs in a dedicated module
Worker with a separate WASI import profile,
captured stdout/stderr, empty stdin, clocks, and explicit arguments/environment.
Its filesystem and processes are the packaged Linux guest's, not the browser
host's. No host filesystem preopens, host process spawning, or network sockets
are provided. Loading bundle assets over HTTP is separate from guest networking.
This runner supplies `--no-stdin`; it does not admit interactive input. A hard
Worker deadline defaults to 600 seconds, with an 8 MiB combined stdout/stderr
limit. The parent terminates the Worker on completion, error, timeout, or abort.

### Serving and origin requirements

The Linux host requires a secure context, `SharedArrayBuffer`, and cross-origin
isolation for synchronous polling off the UI thread. Serve over HTTPS or a
browser-trusted loopback origin with these response headers:

```text
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

The repository's `serve.py` helper sets these headers and binds only to
`127.0.0.1`; it is a development server, not an emitted bundle asset or production
hosting service. A plain `python3 -m http.server` does not add the required
isolation headers. `file://` is not a supported deployment.

If a Content Security Policy is configured, it must allow the bundle's module
scripts and same-origin asset fetches, WebAssembly compilation, and module
Workers/imports created from verified `blob:` URLs. In particular, account for
`worker-src 'self' blob:` and appropriate `script-src` permissions, including
`blob:` and `'wasm-unsafe-eval'`, in the site's complete policy. The runner does
not relax the site's CSP. Asset hashes prove internal consistency only after
the runner is trusted; authenticate the deployed origin or verify an externally
authenticated archive digest. Replacing both JavaScript and its manifest is not
prevented by self-contained hashes.

## Browser-only interactive Guix profile

`--browser-guix` packages the real Guix session `.O` ExecutionPlan with browser
terminal I/O, a narrowly bounded substitute-download path, and an origin-private
ext4 disk. The emitted schema is `ostadix.olang-guix-browser-bundle/v1`; it is
neither the sealed Linux schema nor the direct-WASI provider contract. The
source, plan, Wasm, adapters, build record, state profile, network module, and
browser assets retain their hash bindings. The compiler's input metadata does
not claim execution or runtime-closure qualification.

**Implementation status:** the complete profile is present in source. New
compiler builds, tests, browser sessions, package installation, and persistence
restart qualification were explicitly deferred to better-equipped hardware.
There is no new passing qualification receipt. Earlier Python fixture results
below and historical Guix mock checks do not qualify this profile. It also makes
no new claim about interactive Wasmtime or Wasmer support.

Use a newly built Guix runtime image from
[`examples/guix-wasm/Dockerfile`](../examples/guix-wasm/Dockerfile). Its new
offline `guix archive --authorize` step installs the official Bordeaux
substitute signing key from the verified, immutable Guix distribution. A prior
archive-only image lacks this authorization: **rebuild it and obtain its new
OCI manifest digest**, rather than reusing the earlier runtime pin. The compiler
does not discover, publish, or push your runtime image.

From the repository root, after preparing that image and the build tools:

```sh
OLANG_GUIX_RUNTIME_IMAGE='your-accessible-repository@sha256:YOUR_NEW_RUNTIME_MANIFEST_DIGEST'
OLANG_GUIX_BUILDER_IMAGE='docker.io/library/rust:1.97.1-slim-bookworm@sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b'

olangc guix.O --target wasm --browser-guix \
  --browser-bundle target/guix-browser \
  --wasm-runtime-image "$OLANG_GUIX_RUNTIME_IMAGE" \
  --wasm-builder-image "$OLANG_GUIX_BUILDER_IMAGE"

python3 apps/olang-browser-wasi/serve.py target/guix-browser --port 8787
```

The runtime reference is deliberately a placeholder; replace it with the real
digest of your rebuilt image. `target/guix-browser` must not exist. Open
`http://127.0.0.1:8787/` in a browser supporting the required isolated Workers
and OPFS synchronous access handles. This is a substantial native-Rust/Linux/
emulator build, not an instantaneous conversion performed by `O guix.O`.
The repository's `guix.O` is now the guest session subject, matching
`examples/guix-wasm/guix-session.O`; it is not a macOS native-VM launcher. Do not
execute it against a host Guix installation.

This profile has **no local runtime helper**. The server above serves static
bundle files and isolation headers only: it performs no Guix computation,
network proxying, disk storage, or host filesystem bridging for the guest.
The bundled, hash-pinned container2wasm network module runs in a second browser
Worker. Browser Fetch admits only GET/HEAD substitute metadata and NAR objects
under `https://mirror.yandex.ru/mirrors/guix/`, with at most eight active
requests, 512 MiB per archive, and 2 GiB downloaded per session. Credentials,
arbitrary destinations, redirects, and range requests are not admitted. Browser
CORS and deployment CSP still apply; mirror availability and successful
installation have not been established by this implementation. Guix verifies
substitute signatures using the immutable image's authorized key. Arbitrary
network access, `guix pull`, and source-build downloads outside this policy are
unsupported; an unavailable substitute must surface as a real error.

Storage is a fixed **2 GiB logical** OPFS-backed ext4 disk, initialized from
hash-checked sparse assets only when no state exists. This is not a 2 GiB RAM
allocation, nor a guarantee that a browser grants sufficient disk quota. The
browser requests persistence permission, which does not prevent user-cleared
site data or storage exhaustion. State is tied to the browser origin and exact
runtime-image profile. Keep the scheme, hostname, port, and runtime pin stable
between sessions; changing `127.0.0.1` to `localhost` selects another origin.
Use the COOP/COEP headers above. Only `/gnu/store`, `/var/guix`, and `/root`
receive persistent overlays. The packaged `/ostadix` program and adapters are
not writable persistent state.

The UI submits at most 4 KiB per line, including its newline, to the guest TTY;
it is a command dispatcher, not a shell or terminal emulator with job control.
The outer runner owns the entire disposable Linux guest and network Worker and
has a 65-minute limit. It supplies a one-hour O backend operation budget before
evaluation; the `.O` session reserves five seconds for direct-child cleanup.
Normal `exit` lets init stop remaining owned Guix workers, unmount the three
overlays, sync and unmount ext4, and acknowledge clean shutdown. Only then does
the browser flush its disk and clear its dirty marker. A Guix error status and
a clean disk are separate facts. Force stop, a crash, timeout, quota failure,
or missing acknowledgement must leave state dirty and reject the next open.
Existing state is never silently erased, reformatted, or automatically repaired;
this version supplies no recovery/export/reset UI.

For the manual installation/restart and forced-stop acceptance sequence, see
the [Guix example guide](../examples/guix-wasm/README.md#manual-browser-acceptance-on-better-equipped-hardware).
The builder also requires `curl` to acquire the exact pinned network module;
the disk-asset stage installs `e2fsprogs` inside its build container. Those steps
do not install host Guix or make the wider build hermetic. The flag can also be
combined with `--materialize-only NEW_DIR` and both image pins, without
`--browser-bundle`, to inspect the generated recipe without building it.

### Source and license materials

When distributing compiled bundles, retain their source/build records, upstream
license and notice texts, and the corresponding source materials required for
the included components; a Wasm extension does not remove those responsibilities.
The upstream source locations include [Guix](https://git.guix.gnu.org/guix),
[container2wasm v0.8.4](https://github.com/container2wasm/container2wasm/tree/v0.8.4),
[the pinned Bochs fork](https://github.com/ktock/Bochs/tree/a88d1f687ec83ff82b5318f59dcecb8dab44fc83),
[Linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/?h=v6.1),
and [wasi-vfs v0.3.0](https://github.com/kateinoigakukun/wasi-vfs/tree/v0.3.0).
The converter's included `LICENSE.container2wasm` covers that component, not
every runtime-image dependency. Image publication and complete redistribution
materials remain the distributor's responsibility, not an automatic compiler
upload step.

## Limits and validation status

On 2026-09-12, the fresh Python fixture passed the complete container opt-in gate:
8 evidence-helper tests and the end-to-end test containing a real compiler
build and the first five executions below. That run completed with 9 tests
passing, no skips, and a `passed` receipt in 2,663.395 seconds. The final two
rows are a subsequent browser qualification of the same retained artifact.

| Engine | Case | Observed exit status |
| --- | --- | --- |
| Wasmtime 47.0.3 | Success | 0 |
| Wasmtime 47.0.3 | Intentional Python exception | 1 |
| Wasmer 7.2.1 | Success | 0 |
| Wasmer 7.2.1 | Intentional Python exception | 1 |
| Wasmtime 47.0.3 | Empty root-like preopens regression | 0 |
| Chrome 152.0.7977.83, headless | Shipped Run program UI; same artifact | 0 |
| Chrome 152.0.7977.83, headless | Verified browser runner, intentional Python exception; same artifact | 1 |

In the fresh-build gate, every success printed `OSTADIX WASM Linux 42`. Both
failure executions reported `OSTADIX WASM INTENTIONAL FAILURE` without the
success marker. The original source was deleted before those executions; the
Docker builder VM was stopped during the first engine check and remained off
for the remaining Wasmtime/Wasmer checks.

The artifact is 156,555,045 bytes (about 149 MiB), with SHA-256
`1b676c6088b84d73906f7dca64149c474f1ad0372f6b0c6ae8c945b52c8c52a3`.
Its fixture source SHA-256 is
`9c6da9fae1fb58f299c3a458a3a1df8163dfa9679e0a7e46236fe6c51c7d3f69`.
The run used container2wasm v0.8.4 with the compiler's recorded overlay.
Earlier attempts that hit a build deadline or exhausted builder storage remain
failed attempts; they are not counted as passing evidence. The passing run used
the 7,200-second build budget and unchanged 600-second execution budgets.

This qualifies one packaged Python workload, not arbitrary runtime closures,
Guix, or every browser. The compiler itself does not execute newly built
programs to certify them; its build recipe is separate from execution receipts.

The same approximately 149 MiB raw fixture also passed success/failure execution
with exit statuses 0/1 under the Linux WASI host exercised in Node. Separately,
the compiler's actual Linux browser bundle writer repackaged that retained
module, without changing its artifact or source hashes and without a second
fresh Docker build. Headless Chrome 152.0.7977.83 then exercised the shipped
`index.html` and Run program UI at a 1280×900 viewport. The real guest printed
`OSTADIX WASM Linux 42` and exited zero. A second execution through the verified
browser runner passed `OSTADIX_WASM_EXPECT_FAILURE=1` into the guest, returned
exactly one, reported `OSTADIX WASM INTENTIONAL FAILURE`, and omitted the success
marker. The browser ran the actual Linux Wasm module in its Worker; the Node
harness drove Chrome and collected evidence, not a substitute evaluator or
`node:wasi` execution.

The browser receipt records 2,321 ms startup and 116,637 ms for the two execution
checks. Maximum UI-heartbeat gaps were 123.32 ms during success and 112.035 ms
during intentional failure. Neither phase recorded console/resource errors or
an error overlay. The hash-bound `ostadix.browser-qualification/v1` receipt,
rendered DOM records, and screenshots were retained outside the checkout.
These measurements describe that headless Chrome run, not a performance or
memory guarantee. Safari, Firefox, mobile browsers, and Guix remain unqualified.

The qualified `program.O` fixture is:

```O
python^(
import os, platform
if os.environ.get('OSTADIX_WASM_EXPECT_FAILURE') == '1':
    raise RuntimeError('OSTADIX WASM INTENTIONAL FAILURE')
__oval_result__ = 'OSTADIX WASM ' + platform.system() + ' ' + str(6 * 7)
)_python
```

Build it with the Linux browser bundle command above, then reproduce the
browser check with an existing Chrome/Chromium installation:

```sh
OLANG_BROWSER_EVIDENCE_DIR=/absolute/new/evidence-directory-outside-the-checkout \
  node apps/olang-browser-wasi/test-browser.mjs \
  ./program-linux-browser 'OSTADIX WASM Linux 42'
```

The evidence directory must be new and its parent must exist. `CHROME_BIN` can
select the browser executable. The harness serves the bundle on loopback with
the required headers and tests both success and intentional failure. For a
different workload, supply its expected stdout substring and set
`OLANG_BROWSER_FAILURE_ENV` and `OLANG_BROWSER_FAILURE_MARKER` to its explicit
negative-test contract. A successful check of this retained fixture is not a
second fresh end-to-end container build or qualification of another workload.

The separate [Guix example](../examples/guix-wasm/README.md) supplies a portable
`.O` package/inheritance workload and a pinned Guix 1.5.0 binary-closure image
recipe. It is offline historical-release package-DSL evaluation, not a native
VM controller or package installation workflow. Its earlier O parse check and
49 synthetic/controller tests passed; those historical tests mocked commands and used synthetic
archives. Separately, real Guix 1.5.0 and the package-construction/inheritance
expression passed inside a network-disabled, read-only Linux container with a
512 MiB limit. That is dependency preflight, not compiled O or Wasm execution;
Guix-in-Wasm and Guix in a browser remain unqualified. The complete expanded
distribution is about 885 MB before
conversion, so the small Python fixture's size and memory behavior do not
predict Guix's.

Interactive Guix is the separate, source-implemented `--browser-guix` profile
above. The earlier 11 interactive-host contract groups and nine filesystem
contract groups were component checks, not execution of today's integrated
profile. No new test run or installation/restart qualification is claimed.
The sealed profile still supplies none of the interactive, networking, or
durable-storage capabilities of that explicit opt-in. Guix creates independent
worker sessions, so the implemented owner terminates the entire disposable
guest, not just the O backend process group.

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

- Direct browser bundles retain their explicit whole-program-provider
  requirement for hosted/effectful plans. The Linux browser schema is a separate
  execution route, not a weakening of that original contract.
- An emitted Linux browser bundle still needs the serving configuration above
  and actual browser validation. A successful build or a Node host check does
  not establish browser startup time, memory requirements, or completion.
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
