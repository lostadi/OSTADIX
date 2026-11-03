# One OKernel package and resource namespace

The target is one system: commands select an installed tool and operate on the
same named objects. A Linux ABI implementation, a Plan 9 ABI implementation,
and native O-core services are internal execution providers. Selecting an ABI
must not require the operator to manage another machine or copy files between
separate systems.

## Implemented mechanisms and their limits

The persistent Linux profile preserves original Alpine package resolution,
dynamic libraries, GCC, Make, filesystem operations and upstream source build
recipes under the O-core EL2 monitor. Its package/source helper records exact
inputs, compiler and dependency identity, commands and output hashes. This is
execution of the original Linux software stack, not its lowering into O-core.

The native 9P object server and Linux virtio-9P transport provide a common
object boundary. The guest mounts the explicitly granted `okernel` tag at
`/n/okernel` using the original Linux 9P2000 client. Native O-core
`namespace_peer.oc` uses an independently granted `/work` session and the same
9P wire operations against the same object store. Its exchange with Linux is
a Plan 9 protocol proof; it does not run Plan 9 executables or implement the
Plan 9 binary ABI. Live qualification requires the corresponding boot,
bidirectional file, restart and stale-session tests; source presence alone is
not that evidence.

The updated Plan9port source provider also builds original `9pserve` and original
`u9fs` with a declared path-containment patch. A private Unix transport exposes
the Linux-mounted native store to the original `9p` command. The supervised
process glue preserves the original protocol engines; it does not replace them
with a handwritten client or server. Its complete signed GNU libc closure is
private to these tools. The source/activation receipt binds the patch, closure,
helpers and complete installed inventory. Live qualification verifies binary
wire transfers, common native-peer objects, service restart and real OS restart.

An additional isolated profile executes the original 9front ARM64 kernel and
original `rc` beneath O-core. A source-derived platform kernel adds a second
UART for binary 9P transport; the original console remains on the first UART.
Two fresh native-tool builds reproduce the complete patched kernel bytes using
admitted original tools, libraries and a frozen boot PAQ. This does not establish
a reproducible toolchain bootstrap. Its shared-store gate and sequential
handoff to an isolated Linux fork are distinct from simultaneous cross-ABI
process scheduling in the default OS.

The qualified sequence now includes Linux creating a unique text file,
original Plan 9 mounting the same frozen native volume with `mount -n -c
/dev/eia1 /n`, original `cat` reading the exact Linux bytes, and original `echo`
writing a new file. With the CPU stopped between native transactions, the
probe exports a complete store. The guarded importer selects it only in a
stopped explicit Linux test fork, retaining the package disk and previous
namespace. Original Linux filesystem calls and the original Plan9port `9p`
client then recover the exact Plan 9-written bytes before and after another
saved-state restart. This is sequential sharing, not concurrent scheduling.

The source-derived kernel requires an explicit successful two-build derivation
receipt. The default probe continues to require the exact admitted original
kernel. See `evidence/plan9_native_namespace_probe.json` for the source, runtime
and independent monitor-build records. The Linux return-path proof is
`plan9-linux-handoff-acceptance.json` in the selected isolated state.

`pkg-namespace` copies completed source-build receipts to
`/n/okernel/build/<receipt-manifest-sha256>` and writes package route metadata
under `/n/okernel/pkg`. APK installation records preserve the requested name
and complete installed inventory. These descriptive files do not grant
authority, turn source outputs into APK-owned files, or replace the original
APK database. The native monitor supplies the namespace grants before these
tools execute. A local directory with the same path is never accepted as a
mounted namespace.

Existing x86-64 native `package_root`, `service_registry` and
`domain_namespace` modules implement digest-bound package activation,
generation-checked service lookup and namespace membership. They are bounded
native mechanisms, not yet a general cross-ABI package resolver. The host
`ostadix_capacity.py` catalog is useful for exact artifact transport and
durable dependency snapshots; it is not the native package supervisor.

## Common package contract

A general native package broker needs one versioned descriptor containing:

- a logical name and version, immutable payload identity and aliases resolved
  under an explicit repository policy;
- authenticated repository/source identity, exact build recipe and toolchain
  inputs, complete runtime/build dependency closure, and build output receipt;
- target architecture, required application ABI, provided command and service
  interfaces, and the execution provider contract used to realize that ABI;
- immutable package paths, mutable configuration/work paths, persistent state
  schema, activation health protocol and rollback roots; and
- requested native resources and operations, resolved by activation policy to
  actual capability handles rather than inferred from names or receipt text.

Repository providers retain their original signature, version and dependency
rules. A source provider produces a package with explicit file ownership and
dependency metadata; it cannot silently satisfy a binary manager's dependency
merely because a similarly named library exists. Source failure is returned
without an undeclared binary fallback. An unknown required descriptor field
or unsupported ABI produces a concrete failure.

The broker resolves the package, dependency and provider closure before
activation. It stages immutable objects, starts the required providers,
checks health, binds their live service capabilities into the caller's
namespace, and commits one activation generation. Linux fd numbers and Plan 9
fids remain provider-local objects. They are never serialized as ambient
O-core authority. Provider restart revokes old sessions; persistent files and
unrelated providers remain available.

The initial store is deliberately bounded. Capacity failures must be explicit
and leave earlier committed objects available. A scalable object allocator,
general package manifest parser, native dependency solver, complete Plan 9
application ABI, cross-ABI process/stdio dispatch, and automatic arbitrary
source-recipe import remain separate required work.

The current common store has 16 MiB, 1,024 object slots, 255-byte names, and
512 live fids. Files stream across multiple 4 KiB storage blocks; the 8 KiB
wire message limit is not a file size limit. Keep large source trees and
compiler caches on the governed ext4 package volume under `/work`; the default
interactive working directory is the common `/n/okernel/work` directory.

Native mtimes use globally ordered logical seconds, floored by a recorded
trusted Unix time input at boot. This preserves dependency ordering between
objects in the common store, including after restart. Frequent mutations can
advance this clock ahead of wall time. Exact real-time, subsecond, and arbitrary
cross-filesystem timestamp ordering are not implemented. Explicit requested
timestamps are retained. Builds that mix ext4 and native prerequisites should
copy their working inputs into one filesystem or explicitly force a rebuild.

## Evidence required for integration

The first shared namespace gate must show an ordinary Linux tool creating a
file, the independent native 9P client reading those exact bytes and writing a
generation-specific result, and Linux reading the result through its normal
filesystem calls. It must also show package route and complete build receipt
bytes in that same native store. One durable head must bind both root-package
disk and native object-store snapshots.

Restart qualification must recover those objects and installed package state,
create fresh session epochs, reject old handles and fids, and preserve
unrelated files. Read-only grants and paths outside a scoped grant must fail
without changing the object store. An ordinary package/source operation must
return a failure if its required native publication fails.

Before exporting a pair, the runner synchronizes the guest, stops its virtual
CPU, and checks a monitor-owned quiescence word outside guest RAM. A stopped
CPU inside an unfinished native operation is resumed and stopped again. Only
a stopped CPU between native operations permits either snapshot to be
published. Both complete immutable exports become selected through one atomic
head update; failed exports retain the previously selected pair.

Full Linux/Plan 9 integration additionally requires actual Plan 9-compatible
application execution, shared cwd and standard streams, bidirectional mutable
file semantics, coherent activation/rollback, and original source recipes
with their complete declared dependencies. A common prompt or a native 9P
client alone is insufficient evidence for those capabilities.
