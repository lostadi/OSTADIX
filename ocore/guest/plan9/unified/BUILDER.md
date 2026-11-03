# Original ARM64 userland provider build

`scripts/build_okernel_plan9_userland.py` creates a new private build VM from
the admitted original 9front image. Original `7c` and `7l` compile `p9cmdsrv.c`;
original `disk/mkfs` and `mkpaqfs` package the service, startup script, tools,
headers, and libraries. Original `mk` then rebuilds the kernel with the existing
second-UART platform patch and the new embedded PAQ.

The selected provider includes original `rc`, basic file/text commands,
`7c`/`7a`/`7l`/`mk`, `libc.a`/`libbio.a`/`libsec.a`/`libmp.a`, all original
`/arm64/include` and `/sys/include` files, and the basic `mk` templates. This
qualifies the declared closure. Programs that need other libraries or tools
still need those dependencies. Large archives stay in the read-only PAQ to
leave the bounded shared volume for requests, results, and workspace files.
`libc.a` alone is 1,975,026 bytes. The command protocol limits requests and each
captured stream to 1 MiB; this is not the current native filesystem's per-file
limit. Its format permits at most 3,999 blocks of 4,088 data bytes per file,
subject to the free blocks shared by the entire 16 MiB volume.

The base input is build 12115, source commit
`350266104f1fed81c78c3d05fa44f523bec0ae4d`. The QCOW2 must be exactly
597,164,032 bytes with SHA-256
`67484f032a13eb9760a6287a1c0136a178da38b3c01e19ca7381d2e14a40a20f`.
This is an observed digest pin, not upstream signature verification. The native
compiler binaries are admitted from that image; this workflow does not
bootstrap them or lower their source through O-core.

## Build

The host needs Python, QEMU AArch64, `qemu-img`, Clang, `llvm-objcopy`, `dtc`,
`mkfs.fat`, and `mcopy`. On the development machine, the existing
`target/bm-dev-env/bin` provides the `dtc` launcher.

```sh
PATH="$PWD/target/bm-dev-env/bin:$PATH" \
  python3 scripts/build_okernel_plan9_userland.py \
    --output /absolute/new/private/output \
    --uart-original /absolute/preserved/baseline/artifacts/UART.C
```

The UART input must match the exact unmodified source pin already enforced by
the original builder. The output must not exist. The script copies the verified
base read-only, creates a fresh overlay and 64 MiB FAT transfer disk, and passes
only those private disks to the build VM. It passes no host filesystem export,
network, working namespace volume, or existing state head.

The native closure test mounts the new PAQ, creates a private namespace, and
replaces the compiler, header, library, and command search roots with PAQ
contents. It compiles and executes a native hello program without falling back
to the disk's installed tools. The kernel build must leave the PAQ digest
unchanged. Both private filesystems halt before host export extraction.

`result.json` records captured source/controller/platform inputs, host and
native tool identities, source inventories, command transcripts, exported
artifacts, and every extracted provider file's path, size, and digest. Host
extraction accepts only ordinary files and directories and checks the complete
native hash inventory. All selected provider originals must match their
installed original bytes. Some original boot prototypes intentionally map
different source paths, such as `rc/bin/nusbrc` from `sys/src/9/boot/nusbrc`;
their boot-prototype/source hashes are retained separately.

The main outputs under `artifacts/` are `SERVICE`, `USER.PAQ`, `KERNEL.U`, and
`USER.TAR`. `KERNEL.U` is a new derived kernel and requires its own receipt;
the older fixed-seed kernel's admission receipt does not identify this image.

## Boot namespace and runtime tests

The original boot code mounts the PAQ at `/root`, binds that tree after `/`,
adds `/arm64/bin` to `/bin`, and binds its `/rc` tree. At the emergency `!rc`
prompt, provider files are already visible at `/arm64`, `/sys`, and `/rc`.
`/boot` contains the injected boot executables and PAQ container, not the
expanded provider tree. The startup script is `/rc/bin/okernel-start`; the
service is `/arm64/bin/p9cmdsrv`. The startup wrapper backgrounds the worker
with stdin, stdout, and stderr redirected to `/dev/null`, then returns to the
original shell. A returned wrapper is not readiness; callers must still wait
for the exact generation/instance-bound `ready` marker.

The reusable `run_script_vm` function runs a caller-owned test script in another
new private VM. Inputs use unique flat FAT names and are copied into `/tmp`;
the script must export its evidence through `/dev/sdG0/data` and finish with
`fshalt`. Exact success lines and a clean halt are required. The caller binds
the selected kernel to its build receipt and evaluates the exported service
results. This hook supplies no O-core monitor or shared-store execution proof.

`verify_service.py` runs the service from the admitted PAQ in another private
original VM. Its default `foreground` profile checks commands, byte streams,
errors, replay prevention, and six malformed or stale cancellation markers.
Each accepted interruption requires its own fresh VM and service instance:

```sh
python3 ocore/guest/plan9/unified/verify_service.py \
  --build /absolute/native/build --output /absolute/new/runtime-check \
  --profile cancel-stop --cancel-case cancel_in_flight
```

The other cancellation cases are `cancel_before_submit` and
`truncation_then_cancel`. The first verifies an absent command side effect and
the exact pre-cancellation status. The running cases wait for a file written
by the command and check its recorded PID is still alive without a completion
marker before publishing cancellation, then check retained streams and result
flags. All three validate the request-bound recovery marker, service
exit, and refusal to admit a later request. `--profile timeout-stop` performs
the equivalent recovery check for a timeout. These checks exercise invocation
cancellation, not PTY job control. The coordinator must recycle the owning
Plan 9 domain before exposing interrupted completion or accepting another
invocation; a userland note-group kill does not establish descendant cleanup.

The builder freezes source copies before starting its VM. The runtime verifier
captures its controller sources and rejects a run if those sources change
during execution. Keep `protocol.py`, `verify_service.py`, the runtime fixtures,
and the two builder modules unchanged until a runtime gate finishes.

`verify_console_coexistence.py` separately exercises the packaged background
wrapper and foreground original console. It uses optional exact-marker UART
exchanges in `run_script_vm`; the receipt records every marker and transmitted
byte. The guest's original `read` consumes one line, and original `rc` executes
a second input sequence that saves a file while a resident invocation waits.
The resident invocation compiles, links, and runs a small program using only
the admitted PAQ compiler/header/library closure, with separate binary stdin.
The verifier inspects the original `/proc` descriptor table for the observed
worker, checks fd 0/1/2 point to `/dev/null`, and rejects additional known
console paths. This is a private guest-console gate; the coordinator's console
multiplexer needs its own acceptance test.

```sh
python3 ocore/guest/plan9/unified/verify_console_coexistence.py \
  --build /absolute/native/build --output /absolute/new/console-check
```

Run artifact-boundary regression tests with:

```sh
python3 -m unittest tests.test_plan9_userland_builder -v
```

After a host validator correction, `--revalidate OUTPUT` checks retained
native evidence and exports without launching a VM. It writes a separate
`result-revalidated.json`, binds the original receipt and corrected validator,
and preserves the original result unchanged. It requires export identities
recorded before the failed host check and verifies those exact bytes. Older
failed receipts without that export seal are rejected.

## Recorded build qualification

The latest private native build at
`/home/ustad/.cache/okernel-plan9-userland/build-7` passed service compilation,
the isolated PAQ compiler test, the kernel build, PAQ continuity, and clean
halt. Its ordinary successful receipt is `result.json`, SHA-256
`89bb766092b001a646a60ddc77c3507e05d926528bbde9e92000f006d4b9d9f7`.
`FROZEN.json` binds that receipt and the outputs, whose file write bits were
removed after the private VM halted. The service source captured for this
build has SHA-256
`3606d5182bfb7e03b296e93b84bd5712c63b0cfd1076b21926331a8839a2df98`.

That build contains 239 files totaling 13,163,590 uncompressed bytes. The PAQ
is 4,763,221 bytes, the rebuilt uImage is 6,050,512 bytes, and the service
executable is 110,761 bytes. These are artifact sizes, not runtime memory or
performance measurements. Command-service behavior and O-core integration
require their separate execution gates; successful compilation does not
establish descendant-process cleanup or resident timeout recovery.

Build 7 changes the startup wrapper to preserve the original console. Its
wrapper source has SHA-256
`f5f77df25eca46543906e49c80ab6e1a2cd937077a123b2b8a2fe88b2bac79f8`.
The service executable is byte-for-byte identical to build 5, SHA-256
`a53dd1cc3874881524f41be0441b4f2b5396b12585f65bda600225235f4a1675`.
The existing 22-case behavior qualification below therefore applies to those
exact service bytes; it was not rerun or relabeled as a new build-7 execution.

Build 6's native build passed, but its console gate correctly rejected the
startup wrapper's nonempty exit status. Original `rc` preserves a failed
condition's status across background launch; bare `exit` inherited that status.
Build 7 uses explicit `exit ''` while still requiring the authoritative ready
marker. The failed `runtime-coexistence-6` receipt and transcript are preserved.

Build 7's console coexistence gate passed at
`/home/ustad/.cache/okernel-plan9-userland/runtime-coexistence-7-paced/result.json`,
SHA-256 `cb50edb12fd4e9d526d01e28318c7990a3ee6eee8d9700a447c532725ad5d318`.
The packaged wrapper returned within one observed guest-clock second. The
worker's full descriptor table contained exactly fd 0 read and fd 1/2 write,
all `/dev/null`. Original foreground `read` consumed the exact injected UART
line; original foreground `rc` saved the exact requested bytes while the
resident invocation remained active. That invocation compiled, linked, and
executed a 34,528-byte hello program using the original PAQ-only toolchain in
its requested working directory. Its binary protocol stdin remained separate
and byte-exact; the final result had no flags or error status, and the worker
remained alive after completion.

The first build-7 console attempt, `runtime-coexistence-7`, is also preserved
as a failure. Its wrapper and first console read worked, but sending several
shell lines in one UART burst lost leading characters while original `rc`
started external commands. The corrected fixture sends a complete compound
line with paced writes and retains the same strict receive-byte assertions.
This transport correction did not change the service, wrapper, or builder.

The combined build-7 qualification is
`/home/ustad/.cache/okernel-plan9-userland/qualification-7/result.json`, SHA-256
`5bc82280fe6f33e5f69ae7a965c6f3eb99e944b7212c7c3cbd707fb9917dad9b`.
It binds the native build, 26 focused helper/protocol tests, the successful
console gate, both preserved failures, and the prior behavior qualification
through the identical service executable. These are private original-runtime
results; dual-domain console multiplexing and interruption recovery remain
the coordinator's separate qualification.

The build-5 private original-runtime qualification is recorded at
`/home/ustad/.cache/okernel-plan9-userland/qualification-5/result.json`, SHA-256
`0d2a8c902978a87239344feeb16f5268f5e4bcd32da7cf3c2b1e47abc95c7edd`.
It binds the successful native build, 25 focused builder/protocol tests, and
five independently booted runtime receipts totaling 22 command cases:

- `runtime-foreground-5/result.json`: 18 normal/error/stream and invalid-cancel
  cases, plus replay prevention and fresh-instance restart checks.
- `runtime-timeout-5/result.json`: timeout recovery marker, service exit, and
  subsequent-request nonadmission.
- `runtime-cancel-active-5/result.json`: a verified live command cancelled with
  exact retained stdout and stderr, flags 16.
- `runtime-cancel-before-5/result.json`: cancellation published before submit,
  no command side effect, empty streams, exact status, flags 16.
- `runtime-cancel-truncated-5/result.json`: active cancellation retaining the
  exact 33-byte stdout prefix and both cancellation/truncation flags, 18.

Those runtime paths are relative to `/home/ustad/.cache/okernel-plan9-userland`.
Each interrupted gate validates the exact request/result-bound reset marker,
service exit, and refusal of later work. Runtime outputs and receipts were
frozen after clean private-VM halts. These results do not establish unified
transport behavior or descendant cleanup; the coordinator's domain-recycling
gate remains separate.

Earlier build directories are retained. Build 2 reached a successful native
halt but its first host check incorrectly compared an intentionally remapped
boot script with an installed same-name script. Its historical revalidation
predates the required precheck export seal. Builds 3 and 4 have ordinary
successful receipts; cancellation qualification uses build 5.
