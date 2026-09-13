# Guix O workloads: offline witness and browser session

This directory keeps two distinct subjects: the offline `guix-package.O`
witness below, and `guix-session.O`, the real interactive command/install
subject selected by the new `--browser-guix` profile. The repository-root
`guix.O` matches the latter; it is no longer a native macOS VM controller.
The complete browser profile is implemented in source, but its new build,
browser execution, installation, and restart checks are deferred to
better-equipped hardware. No new passing qualification receipt is claimed.

`guix-package.O` runs the actual Guix 1.5.0 package language. Its Python backend
invokes the absolute Guix profile executable with `guix repl -q -- FILE`.
Scheme loads `(guix packages)`, `(guix build-system trivial)`, and the prefixed
license module, constructs a complete package whose calculated version is 42,
and uses `package (inherit ...)` to construct version 43. Assertions check the
original and inherited fields before printing `OSTADIX_GUIX_PACKAGE:42->43`.
The checked stdout becomes an OValue through `__oval_result__`.

This example never lowers or builds the package, connects to a Guix daemon,
installs anything, or requests a substitute/download. Its builder expression is
data, not executed code. This is an offline, historical-release DSL example,
not qualification of Guix as a current networked package manager. No native VM
or host Guix installation is used or modified.

## Prepare the runtime closure

Supply the official [Guix 1.5.0 x86-64 binary distribution](https://ftp.gnu.org/gnu/guix/guix-binary-1.5.0.x86_64-linux.tar.xz)
in a private directory outside the checkout. Verify its detached signature
against an independently established Guix release key as appropriate; the recipe
also verifies the exact SHA-256 before extracting anything:

```text
aa41025489c5061543e9c48873eaa829b900b2da75d40f9648913622f5f47817
```

The archive is 135,985,908 compressed bytes and 885,248,000 xz-uncompressed bytes.
The recipe preserves the complete `/gnu/store` and `/var/guix` layout, including
the `current-guix` profile and absolute store symlinks. It is not a trimmed
closure. Extraction occurs only in the image build; never run the extractor
against the host root. Python's standard-library XZ support avoids an additional
apt installation. The final image excludes the compressed archive and extractor.

From the repository root, with Docker Buildx already installed:

```sh
GUIX_ARCHIVE_DIR=/absolute/private/directory/containing-the-archive
docker buildx build --load --platform=linux/amd64 --network=none \
  --build-context "guix-distribution=$GUIX_ARCHIVE_DIR" \
  -t olang-guix-runtime:1.5.0 examples/guix-wasm
```

The exact archive filename must be `guix-binary-1.5.0.x86_64-linux.tar.xz`.
Base-image acquisition can require registry access before offline build steps.
Both stages pin Python 3.11 Bookworm to
`sha256:b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250`.
The build runs one offline Guix command: `guix archive --authorize`, reading
`/gnu/store/ganla421f3g1p9rh3r68zj9djc9b807m-guix-1.5.0/share/guix/bordeaux.guix.gnu.org.pub`
from the verified distribution. This establishes substitute-signing trust in
the immutable image, without fetching or authorizing keys from writable browser
state. No daemon or package installation runs. **Rebuild the runtime image and
obtain its new OCI manifest digest**: an older archive-only image lacks the
required authorization and must not be reused for the browser install profile.
The retained root
profile layout is intended for this image's default root user, not a host root
identity or a privileged container.

## Compile and qualify separately

The compiler requires a digest-pinned OCI manifest reference for the completed
runtime image. A local tag or Docker image ID is not a substitute. Make that
image available through your chosen registry or OCI workflow and supply its
verified `repository@sha256:...` reference below; these commands do not publish
or push an image on your behalf.

```sh
OLANG_GUIX_RUNTIME_IMAGE='your-accessible-repository@sha256:YOUR_RUNTIME_MANIFEST_DIGEST'
OLANG_GUIX_BUILDER_IMAGE='docker.io/library/rust:1.97.1-slim-bookworm@sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b'

O --check --json examples/guix-wasm/guix-package.O
olangc examples/guix-wasm/guix-package.O --target wasm \
  --wasm-runtime-image "$OLANG_GUIX_RUNTIME_IMAGE" \
  --wasm-builder-image "$OLANG_GUIX_BUILDER_IMAGE" \
  --materialize-only ./guix-wasm-build

olangc examples/guix-wasm/guix-package.O --target wasm -o ./guix-package.wasm \
  --wasm-runtime-image "$OLANG_GUIX_RUNTIME_IMAGE" \
  --wasm-builder-image "$OLANG_GUIX_BUILDER_IMAGE" \
  --keep-build-dir

wasmtime run ./guix-package.wasm --no-stdin
wasmer run ./guix-package.wasm -- --no-stdin
```

Both successful runs must exit zero and print the exact marker above. For a
negative test of the same artifact, set `OSTADIX_GUIX_FORCE_FAILURE=1` in the
engine's WASI environment: it must report `OSTADIX_GUIX_INTENTIONAL_FAILURE`,
exit nonzero, and omit the success marker. No host preopens, socket forwarding,
credentials, host `/gnu/store` mount, or Docker socket are required. Guile
auto-compilation is disabled, C locale is selected, and the Scheme script lives
only in the guest's temporary directory. The subprocess deadline is 300 seconds.

See [the compiler image-route guide](../../docs/OLANGC_WASM.md) for prerequisites
and limits. Conversion still builds an emulator/kernel and can fetch its build
dependencies: `--network=none` above applies to runtime-image build steps, not
the entire compiler pipeline. The converter packs an uncompressed ISO, so this
large closure can produce a Wasm artifact near a gigabyte and requires ample
build storage and runtime memory. A 512 MiB Linux guest and browser execution
are not established by producing an image or a Wasm header.

## Opt-in end-to-end qualification

`qualify.py` is a host-side test controller, like the repository's other
qualification tests; it is not an O evaluator. The subject remains the actual
`guix-package.O`, compiled through `olangc` and executed inside the packaged
Linux guest. No runtime deadline or O execution semantics are changed.

With Docker, Buildx, `c2w`, Wasmtime, Wasmer, Node, and Chrome/Chromium installed,
run from the repository root:

```sh
export OLANG_GUIX_RUNTIME_IMAGE='your-accessible-repository@sha256:YOUR_RUNTIME_MANIFEST_DIGEST'
OLANG_GUIX_EVIDENCE_DIR=/absolute/new/directory-outside-the-checkout \
  python3 -B examples/guix-wasm/qualify.py
```

The evidence directory must not exist, and its parent must exist. The controller
uses `target/release/olangc` unless `OLANGC_GUIX_TEST_BIN` selects another
executable. It fixes the Rust builder image to the digest above and runs these
gates:

- Copy the exact `.O` source into private evidence and perform a fresh compiler
  build with `--browser-bundle`, allowing up to 10,800 seconds.
- Verify the Wasm header and source, artifact, plan, build-record, adapter, and
  asset hashes; check the image pins and grants; delete only its input copy
  before runtime tests. The emitted bundle retains its own source.
- Run the same artifact under Wasmtime and Wasmer, each with success exit 0
  and intentional-failure exit 1, explicit output markers, empty inherited
  environments, no host preopens, EOF stdin, and a 600-second deadline per run.
- Drive the emitted browser UI and the verified runner's failure case in real
  Chrome, using the existing browser harness with a 1,300-second outer deadline.
  Require a passing browser receipt bound to the same artifact and source.

Full command stdout/stderr, timestamps, durations, exit statuses, the top-level
receipt, and browser evidence remain in the requested directory, including on
failure. A top-level `passed` receipt is written only after every gate passes.
Adding or running synthetic tests for this controller does not qualify Guix.

Build tools inherit the caller's Docker configuration. For the explicitly owned
task builder, `DOCKER_CONTEXT=colima-ostadix-wasm` and
`BUILDX_BUILDER=ostadix-wasm-converter` select it. Optionally set
`OLANG_GUIX_BUILDER_PROFILE=ostadix-wasm` to stop that profile after the build
and before guest execution, or after a build abort. Any other profile is
rejected; no native Guix VM is controlled. Without this option, no VM is stopped.
The build checks host free space before launch and every 30 seconds, aborting
below 1.5 GiB. Timeouts and interruptions terminate only owned command process
groups; the browser harness closes its separately owned Chrome group. The
controller never prunes caches or deletes previous evidence.

## Launch an already qualified bundle

After the real controller passes, install its **whole emitted bundle** and a
copy of its passed receipt from the repository root. This example refuses an
existing destination or an existing `qualification.json`; it does not replace
an earlier installation:

```sh
GUIX_EVIDENCE_DIR=/absolute/directory/from-a-passed-qualification \
python3 - <<'PY'
import json, os, shutil
from pathlib import Path
evidence = Path(os.environ['GUIX_EVIDENCE_DIR']).resolve()
receipt_bytes = (evidence / 'receipt.json').read_bytes()
receipt = json.loads(receipt_bytes)
if receipt.get('schema') != 'ostadix.guix-wasm-qualification/v1' or receipt.get('status') != 'passed':
    raise SystemExit('A passed Guix qualification receipt is required')
destination = Path('target/guix-wasm')
shutil.copytree(evidence / 'bundle', destination)
with (destination / 'qualification.json').open('xb') as output:
    output.write(receipt_bytes)
PY

O examples/guix-wasm/run.O
```

The small Python snippet only installs files. `run.O` uses the ordinary O Python
backend to verify the local receipt, required qualification assertions, Linux
profile, source/plan/build bindings, and streamed artifact hash and length. It
then runs the installed workload and returns its actual stdout only after exit
zero and the checked package marker. A trusted local receipt establishes file
consistency, **not authenticity**: hashes cannot authenticate a bundle and receipt
that an attacker replaced together. Establish trust in the retained evidence
before installation.

The default is `target/guix-wasm` relative to the invocation directory, using
Wasmtime. Select an explicit installed bundle and either `wasmtime` or `wasmer`
with the launcher options. For a slow guest, set the parent O operation budget
before invocation, for example:

```sh
OSTADIX_GUIX_WASM_BUNDLE=/absolute/installed/guix-bundle \
OSTADIX_GUIX_WASM_ENGINE=wasmer \
O_BACKEND_OPERATION_TIMEOUT_MS=600000 \
  O examples/guix-wasm/run.O
```

The parent's default is 60,000 ms, with a 3,600,000 ms ceiling. The launcher
charges its own measured verification time and reserves five seconds for local
cleanup; it cannot observe the parent's exact admission timestamp or extend its
deadline. The engine inherits O's backend process group: there is no detachment
or re-execution of the launcher outside O. Local failure kills only that engine
child; O remains responsible for whole-group shutdown. Execution uses an empty
private working directory, EOF stdin, no host preopens, and no inherited guest
environment. Explicit `OSTADIX_GUIX_FORCE_FAILURE=1` is forwarded only as the
engine's guest environment option and must surface as a launcher failure.

## Browser-only interactive Guix — implemented, not qualified

`guix-session.O` is a separate O ExecutionPlan subject for interactive Guix
commands and real package operations. It invokes the actual Guix executable
with parsed arguments, starts a private foreground daemon, and leaves Guix's
normal build sandbox and substitute signature authentication enabled. The new
compiler integration supplies its browser terminal, bounded network access,
and durable-store profile. These changes are **source-only implementation**:
new compilation, tests, browser execution, real installation, and restart
qualification were explicitly deferred. The offline witness and earlier
component tests do not establish those results.

After rebuilding the runtime image as described above, use its actual new
digest and an installed compiler containing `--browser-guix`:

```sh
OLANG_GUIX_RUNTIME_IMAGE='your-accessible-repository@sha256:YOUR_NEW_RUNTIME_MANIFEST_DIGEST'
OLANG_GUIX_BUILDER_IMAGE='docker.io/library/rust:1.97.1-slim-bookworm@sha256:39f68a3e8e3ff425f8945ffa91128e60ff930d53e17fbb5214e95824bdd46f1b'

olangc guix.O --target wasm --browser-guix \
  --browser-bundle target/guix-browser \
  --wasm-runtime-image "$OLANG_GUIX_RUNTIME_IMAGE" \
  --wasm-builder-image "$OLANG_GUIX_BUILDER_IMAGE"

python3 apps/olang-browser-wasi/serve.py target/guix-browser --port 8787
```

Run these commands from the repository root. The runtime image reference is a
placeholder, not a usable or invented digest; the compiler does not push an
image for you. The bundle destination must not already exist. Building still
requires Docker/Buildx, `c2w`, `curl`, and substantial CPU, RAM, and free disk for
Rust, the kernel/emulator, the Guix closure, and filesystem packing. A completed
build would be an artifact, not a qualification receipt. `O guix.O` does not
magically convert it into Wasm or provide its guest assets; compile the subject
for this browser profile, or use it only inside an explicitly owned Guix guest.
Do not run it against the host.

Open `http://127.0.0.1:8787/` and use **Start**. The target is browser-only,
with **no local native helper**, host Guix process, filesystem bridge, or
companion VM at runtime. The Python server serves static bundle assets and
COOP/COEP headers only. Networking and storage execute inside the browser, not
behind endpoints on that server. Browser support for isolated Workers,
`SharedArrayBuffer`, and OPFS synchronous access handles is required. HTTPS or
trusted loopback plus the required headers is mandatory; `file://` and a plain
headerless HTTP server are not supported.

The dedicated `ostadix.olang-guix-browser-bundle/v1` manifest binds source,
ExecutionPlan, adapters, Wasm, build inputs, the state profile, and browser
assets. A pinned container2wasm network module runs in its own Worker. Its
browser Fetch broker admits only GET/HEAD substitute metadata and NAR downloads
from `https://mirror.yandex.ru/mirrors/guix/`: at most eight active requests,
512 MiB per archive, and 2 GiB downloaded per session. Guix's daemon selects
that mirror explicitly and still authenticates signed substitutes. The
per-session proxy CA is supplied inside the guest; no arbitrary host
environment, cookies, or credentials are forwarded. Arbitrary network access,
`guix pull`, range downloads, and source fetches outside the admitted policy are
unsupported. Browser CORS/CSP, mirror availability, and matching substitutes
remain practical prerequisites, not promised results.

The browser provisions a **2 GiB logical** ext4 disk from verified sparse
initial assets and stores it in OPFS. It persists only `/gnu/store`, `/var/guix`,
and `/root`; the compiled `/ostadix` program and adapters remain outside those
overlays. Physical storage and browser quota must be sufficient. The requested
browser persistence permission is not protection against clearing site data.
Keep the exact origin and runtime-image pin stable to reopen the same profile:
scheme, hostname, and port all matter, so use `127.0.0.1:8787` consistently.
Existing disk size, UUID, profile marker, and clean state must agree. No existing
disk is formatted or automatically repaired.

The session requires a dedicated, disposable Linux guest whose lifecycle is
owned by the enclosing runner. An ephemeral OCI container can provide that
ownership for native preflight, but is not the browser deliverable. Guix creates
workers in independent sessions: stopping O's process group is insufficient.
The subject stops and reaps direct children; the browser runner owns the whole
disposable guest and proxy Worker. Guest init stops remaining workers in its
owned runc container before finalizing storage, and the outer owner terminates
the Workers on completion, cancellation, or timeout. Its
`OSTADIX_GUIX_SESSION_GUEST=1` marker is an explicit opt-in safety guard, **not
proof of isolation**. Do not run this subject against a host Guix installation.

Human I/O uses the guest's `/dev/tty`, not Python backend RPC stdin/stdout, with
foreground-group and terminal-attribute restoration. The bounded UI accepts up
to 4 KiB per command including the newline (4,095 UTF-8 bytes of input), not
arbitrary terminal automation or shell job control. The browser profile sets
the O operation budget to 3,600,000 ms before evaluation and limits the entire
session to 65 minutes. Outside that profile O defaults to 60,000 ms and retains
the one-hour ceiling. A five-second local cleanup reserve cannot extend the
parent's deadline or guarantee restoration after forced guest termination.

Use `exit` at `guix>` for normal shutdown. Only after guest init unmounts the
three overlays, syncs and unmounts ext4, and acknowledges finalization may the
browser flush its state and clear the dirty marker. A nonzero Guix status is
reported independently of whether storage was finalized cleanly. Force stop,
crash, timeout, quota failure, or a missing clean acknowledgement leaves a dirty
marker and causes the next open to refuse the disk. The current UI does not
implement recovery, export, or reset; it never silently erases existing state.
Do not treat the browser disk as the only copy of valuable data.

### Manual browser acceptance on better-equipped hardware

These are **future manual acceptance steps**, not a report that they passed.
Retain the exact source/artifact/build/manifest hashes, compiler and browser
versions, terminal output, real exit statuses, and any failures. The existing
`qualify.py` and `run.O` concern the sealed offline witness, not this interactive
profile or a new interactive Wasmer qualification.

After the new runtime image and browser bundle are built, open the fixed origin,
start a session, and enter the following at `guix>`, one line at a time:

```text
install hello
package --list-installed
repl
```

Installation must actually succeed and the installed-package listing must
contain `hello`; a package description or printed version is not installation.
At the real Guile REPL prompt, enter:

```scheme
(system* "hello")
(quit)
```

`system*` must execute the installed program from `/root/.guix-profile/bin` and
report success. Back at `guix>`, enter `exit`, then wait for the UI's explicit
clean-save completion. Start again at the **same origin and runtime pin**, run
`package --list-installed`, enter `repl`, and repeat `(system* "hello")` and
`(quit)`. Exit normally again. This second boot, not merely a successful first
install, is the persistence acceptance check. If unavailable substitutes,
sandbox restrictions, memory, quota, or policy cause failure, retain the error;
do not disable signature checks or the Guix sandbox to turn it into a pass.

Last, on disposable test state only, start a session and confirm **Force stop**
before normal exit. A subsequent start must report recovery-required state,
not claim a clean save, silently reinitialize the disk, or run an automatic
repair. This deliberately leaves the test state unusable by the current UI;
perform it only after the positive checks and never on data you need to retain.

## Local checks and evidence boundary

```sh
python3 -B -m unittest discover -s examples/guix-wasm -p 'test_*.py' -v
```

Historically, 49 tests passed using synthetic archives, receipts, and mocked
subprocesses. They checked Python control flow, hash rejection, archive layout, launcher process
ownership, interactive terminal/cleanup contracts, and failure reporting only.
Those counts, and the earlier 11 interactive-host and nine filesystem contract
groups, are not a fresh pass of the current integrated source. No new tests,
builds, or runtime checks were run for this browser profile. These mocks do
**not** execute Guix or qualify a container, Wasm runtime, or browser. Syntax checking likewise does not execute
the package DSL. Actual Guix runtime and
Wasm qualification remain required; retain the real build manifest, artifact
hash, engine versions, stdout/stderr, and success/failure exit statuses.

When sharing compiled artifacts, include their source/build records and the
applicable upstream source, license, and notice materials, not just the Wasm
binary. See the compiler guide's
[source and license materials](../../docs/OLANGC_WASM.md#source-and-license-materials)
for Guix, container2wasm, Bochs, Linux, and wasi-vfs source links. Runtime image
dependencies have their own notices; the compiler does not publish images or
complete redistribution materials on your behalf.
