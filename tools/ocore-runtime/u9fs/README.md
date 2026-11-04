# Original u9fs wire codecs as native O-core components

The recipes in this directory compile four unchanged original u9fs sources
through `olangc --native-runtime`. They include a separately captured and
lowered original musl dependency component, so the resulting native objects
have no unresolved libc symbols.

| Component | Exact selected original sources |
| --- | --- |
| u9fs wire codec | `convM2S.c`, `convS2M.c`, `convM2D.c`, `convD2M.c` |
| musl generic memory/string dependency | `src/string/memcpy.c`, `src/string/memmove.c`, `src/string/strlen.c` |

u9fs is pinned to `fcec3e1e2e8e8c28b89270e6c44554c4ca9e50a9`; musl 1.2.5
is pinned to `0784374d561435f7c787a555aeab8ede699ed298`. Both source trees
must be clean Git checkouts. The helper checks the codec selection against
u9fs's evaluated original object list. It generates musl's target type header
with the original header generator and otherwise retains original source and
header bytes. This is a complete inventory of the explicitly selected library
components, not an inventory of complete u9fs or complete musl.

`build_component.py` is pinned by SHA-256 in each recipe. Changing it requires
updating all four recipe pins. The ordinary optimized build uses `-O1`,
freestanding scalar code, and target-specific original musl headers. No source
body, arithmetic operation, or original optimized generic implementation is
replaced to work around importer limitations.

## Build and verify

Use a matching Clang/LLVM 22.1.6 frontend, an explicitly digest-pinned 22.1.6
parser library, and current `olangc`/`ocorec` binaries. `ocorec` must be
resolvable by the selected `olangc` in the usual compiler installation.

```sh
python3 tools/ocore-runtime/u9fs/build_native.py \
  --isa x86_64 \
  --u9fs-source /absolute/path/to/pinned/u9fs \
  --musl-source /absolute/path/to/pinned/musl \
  --olangc /absolute/path/to/olangc \
  --clang /absolute/path/to/llvm-22.1.6/bin/clang \
  --clangxx /absolute/path/to/llvm-22.1.6/bin/clang++ \
  --llvm-nm /absolute/path/to/llvm-22.1.6/bin/llvm-nm \
  --linker /absolute/path/to/llvm-22.1.6/bin/ld.lld \
  --llvm-library /absolute/path/to/matching/libLLVM.so \
  --llvm-sha256 EXACT_LIBRARY_SHA256 \
  --output /absolute/path/to/new-output-directory \
  --verify
```

For AArch64, use `--isa aarch64`; on an x86-64 build host also supply
`--qemu-aarch64 /absolute/path/to/qemu-aarch64` for the semantic test. The
source is compiled for each target; x86 frontend IR is never retargeted.
The output parent must already exist and the output directory must be new.

The driver invokes the original-source recipe interface twice: first for the
musl component, then for u9fs with the verified native dependency module set
supplied through `--native-runtime-dependency`. The compiler owns source
capture, inventory admission, original-unit import, O-core verification, and
native object emission. The reference Clang objects are never final link
inputs. `OCORE_U9FS_MUSL_SOURCE` is set explicitly by the driver for the codec
recipe's header dependency; direct recipe callers must set it themselves.

The final `native-codec.json` records seven compiler-generated native objects,
both original source recipe receipts, both coverage receipts, native module
sets, original header identities, the LP64 ABI, and the final symbol inventory.
A relocatable link followed by an undefined-symbol check must find no unresolved
symbols before publication. Consumers must verify these identities before
linking. The public symbols are `convM2S`, `convS2M`, `convM2D`, `convD2M`,
`statcheck`, `sizeD2M`, `memcpy`, `memmove`, and `strlen`.

## Evidence boundary

The optional semantic test links all seven O-core-generated objects and
separately compiled original reference functions into a static test carrier.
It uses no libc or dynamic loader. It compares message encoding, decoding,
directory metadata, bounded outputs, truncated inputs, and aligned/unaligned,
overlapping/nonoverlapping memory operations. Only the tiny test carrier uses
Linux write/exit syscalls. The AArch64 test on x86 is QEMU user emulation,
not native hardware qualification.

The decoder mutates its input strings in place. Callers must provide a private
writable buffer and retain it for the lifetime of decoded pointer fields.
Upstream's missing `Rauth` decoding case remains a rejection; this integration
does not silently repair or relabel original behavior. Encoders require valid
original `Fcall`/`Dir` inputs, including bounded walk counts and valid buffers.

The compiler's module-set dependency schema currently cannot independently bind
a non-null `source_pin`; the dependency name is therefore bound to the included
verified module set, while both compiler-owned original source recipe receipts
retain pinned source provenance. This limitation is reported in the final
manifest. Full u9fs authentication/filesystem/server behavior, POSIX adaptation,
Linux/Plan 9 kernels, physical hardware execution, and performance improvements
remain outside this component's claim. Kernel integration needs its own live
request-path gate.
