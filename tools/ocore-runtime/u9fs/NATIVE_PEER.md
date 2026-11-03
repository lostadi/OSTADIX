# Original-codec native namespace peer

The optional monitor profile replaces the native peer's handwritten 9P wire
encoding and decoding with the unchanged original u9fs `convS2M` and `convM2S`
implementations compiled through O-core. Every peer request and response uses
these functions. The existing native namespace store retains authority,
persistence, and server request handling. Linux accesses that same store through
the mediated virtio-9P transport.

The profile links the complete seven-object codec and memory/string closure
described in [README.md](README.md). It does not import the complete u9fs server,
replace Linux with a native POSIX implementation, or merge two operating-system
kernels. The host Python helper verifies and captures build artifacts; 9P codec
and namespace operations execute as native O-core-generated machine code.

## Build an isolated profile

First produce verified AArch64 and x86-64 `native-codec.json` manifests with
the original-source recipe instructions. Use the AArch64 manifest for the
monitor and the x86-64 manifest for the host integration fixture. An ordinary
monitor build without `OCORE_LINUX_NATIVE_9P_MANIFEST` retains the existing peer.

The following commands copy a saved state into a new directory and rebuild
only its monitor. The destination must not already exist. A fork captures the
selected saved checkpoint; it does not capture unsaved guest changes.

```sh
cd /home/ustad/ostadix-BM
u9fs_state="$HOME/ok-u9fs/package-domain"
u9fs_manifest=/absolute/path/to/aarch64-output/native-codec.json

python3 scripts/fork_okernel_state.py \
  --source "$HOME/.local/state/ostadix/okernel/package-domain" \
  --output "$u9fs_state"

OCORE_LINUX_NATIVE_9P_MANIFEST="$u9fs_manifest" \
  python3 scripts/okernel_package_domain.py build \
    --state "$u9fs_state" --network --namespace
```

Keep the state path short. The launcher creates a Unix control socket at
`STATE/session-XXXXXXXX/control.sock`; Linux limits this complete socket path
to 107 bytes. A long evidence-directory name can prevent QEMU from starting
before any guest code executes.

The helper verifies object identities and ISA, source-recipe and coverage
receipt chains, native module membership, the complete symbol closure, and
the bound producer semantic-test artifacts. It captures the admitted bytes in
the build directory before linking. `monitor/native-9p.json` records that
capture, and `monitor/monitor-profile.json` includes it as `native_9p_codec`.
Admission checks the producer's recorded test result; the independent fixture
below executes the actual peer/store path again.

## Use the console

For a terminal session, run:

```sh
python3 scripts/okernel_package_domain.py run \
  --state "$HOME/ok-u9fs/package-domain"
```

The guest has an interactive shell. Shared files appear under `/n/okernel`.
Writing `/n/okernel/work/from-linux` causes the native peer to update
`/n/okernel/work/from-plan9`:

```sh
printf 'hello from the shell\n' > /n/okernel/work/from-linux
cat /n/okernel/work/from-plan9
```

The reply begins with `native-9p-peer generation=...` and includes the supplied
bytes after `linux=`. This output deliberately preserves the existing peer
interface. It alone does not distinguish codec implementations; the captured
profile and live codec counters establish which path ran. Press `Ctrl+]` to
save the disk and namespace and exit.

For a console that survives closing the terminal, select a distinct tmux
socket as well as the isolated state:

```sh
OSTADIX_OKERNEL_STATE="$HOME/ok-u9fs" \
OSTADIX_OKERNEL_PACKAGE_SOCKET=okernel-u9fs \
  bash scripts/okernel-console.sh start
```

Detach with `Ctrl+B`, then `D`; repeat the same command to reconnect. Closing
the chat does not stop that tmux-hosted VM. It does not keep a Codex agent
working independently.

## Qualify the native path

```sh
OCORE_U9FS_MANIFEST=/absolute/path/to/x86_64-output/native-codec.json \
  python3 -m unittest tests.test_okernel_u9fs_peer -v
python3 -m unittest tests.test_okernel_native_codec -v
```

The first fixture uses the production native store, bridge, and peer, links
the full original-source dependency closure, and asserts the original-header
ABI. It checks shared reads and writes, binary payloads, scoped read-only
authority, fresh epochs, saved-volume reopen, and peer revocation while the
Linux session remains valid. It emits both x86-64 and AArch64 bridge objects;
its executed carrier is x86-64. An unset `OCORE_U9FS_MANIFEST` explicitly skips
this optional fixture and is not qualification.

The native bridge exports encode/decode and byte counters through
`namespace_peer::codec_encodes`, `codec_decodes`, `codec_request_bytes`, and
`codec_response_bytes`. Their backing ELF symbols are
`_O_runtime__common__u9fs_codec__ENCODE_CALLS`, `DECODE_CALLS`, `ENCODE_BYTES`,
and `DECODE_BYTES` with the same module prefix. Each is a 64-bit value. An
isolated live monitor test can resolve them from its exact ELF and read them
through QEMU's monitor after a shared-file exchange. Successful linking or a
host fixture alone is not evidence of that live AArch64 request path.

The fixture's `memmove` and `strlen` wrappers measure calls made during peer
initialization and polling. They exclude other namespace-store copies and do
not measure total memory traffic or end-to-end performance. No efficiency
improvement is inferred from this integration.

## Recorded live qualification — 2026-11-02

The optimized AArch64 profile passed two boots under QEMU/TCG in the isolated
state `/home/ustad/okernel-native/package-domain`. The machine-local
[live receipt](/home/ustad/okernel-native/package-domain/native-codec-live-4ca0c182e66242d4beafc1d941ec0383.json)
binds both executed monitor snapshots to SHA-256
`521fa3bac7f2e94492f83834c3bcf71273cca0aa01a502776225a9550f82d9ec`
and the captured seven-object O1 codec/musl closure. Each boot completed a new
Linux-to-native-peer shared-file exchange with its own namespace epoch.
Counter samples read from the exact running monitor increased as follows:

| Boot | Encodes | Decodes | Encoded bytes | Decoded bytes |
| --- | ---: | ---: | ---: | ---: |
| Initial | 20 | 20 | 473 | 516 |
| Restart | 24 | 24 | 548 | 629 |

These are measured deltas around the exchange, including peer polling; they
are not a fixed operation count or performance result. The guest GCC compiled
C source read from the shared namespace and executed the resulting Linux
binary. Original Plan9port `rc` wrote and read shared files. The executable and
shared files survived the paired disk/namespace save and restart. Independent
read-only review checked captured object and receipt identities, the exact
monitor ELF and counter symbols, stored counter bytes, successful command
completion markers, and the first saved pair used as the second boot's input.

A third interactive boot recorded actual shell output in
[interactive-acceptance.json](/home/ustad/okernel-native/package-domain/interactive-acceptance.json);
the operator also verified PTY input and detach without stopping that VM.
The tested console launcher is `/home/ustad/okernel-native/run`. This milestone
qualifies the original codec in the live native peer path. Linux remains the
guest kernel and Plan9port uses its ABI; this does not establish full Linux/Plan 9 source lowering,
a complete native POSIX system, physical hardware operation, or a self-contained
interactive `.O` distribution.
