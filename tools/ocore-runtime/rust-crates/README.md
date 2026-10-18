# Original Rust library lowering

`adler2.recipe.json` pins the unchanged upstream Adler-32 library at
`89a031a0f42eeff31c70dc598b398cbf31f1680f` (adler2 2.0.1). It compiles its
entire configured library with the original default `std` feature, Rust 1.97.1 /
LLVM 22.1.6, `panic=unwind`, optimization level 1, and two requested CGUs. Rust may
emit fewer CGUs; every actual native archive member and embedded bitcode edge
must remain accounted for.

`configured_library.py` reads the original manifest and follows its complete
default feature graph. This bounded direct-rustc profile rejects build scripts,
workspaces, proc macros, target-dependent manifests and enabled external
packages. It writes the original rlib, configuration evidence and the existing
`ocore-runtime-unit-inventory-v1` inventory. It is not a Cargo replacement.

Use the ordinary source capture command with this recipe, a clean pinned Git
checkout, separate new build/capture paths, explicit matching compiler tools,
and `--unit-inventory BUILD/unit-inventory.json`. The existing
`rust-embedded-bc-v1` policy captures the exact original rlib member's bitcode;
there is no LLVM frontend replay or source/body filtering.

Audit every captured CGU with `scripts/check_ocore_runtime_imports.py`, selecting
`--step build-entire-default-rust-library`. Supply the installed `ocorec`,
`--target riscv64-unknown-none` on this RV64 host, the explicit LLVM parser
library/digest, and `--llvm-dis` pointing to LLVM 22.1.6. The diagnostic decoder
retains full textual metadata, while the compiler receives the original raw
bitcode and must retain its SHA-256 in native IR. Input/decoder failures are
incomplete infrastructure diagnostics rather than unsupported-language evidence.

`qualify_adler2.py CAPTURE_REPORT AUDIT_REPORT --ocorec TRUSTED_OCOREC
--llvm-library LLVM_LIBRARY --llvm-sha256 LLVM_SHA256 --clang CLANG
--llvm-nm LLVM_NM --output NEW_DIRECTORY` executes the actual original `adler32_slice` API on
Linux RV64 LP64D. It independently re-admits capture, checks every original and
owned CGU/module/verification artifact. It freezes the selected O-core compiler,
re-imports every original raw bitcode unit, independently verifies it and freshly
emits every owned object. Fresh module/object hashes must match the supplied
audit; audit metadata alone cannot authorize an object. Both whole object sets
then link to the same C carrier. A small test-only assembly veneer forwards the exact observed
pointer/length parameters and normalizes the bare i32 return to the C narrow
return convention. No Rust struct layout or stable Rust FFI is assumed.

The twelve cases include empty input, all byte values, 5551/5552/5553-byte and
two-block boundaries, an all-255 block and a deterministic 1 MiB payload. Both
executables must agree with independent C modular arithmetic and Python zlib
controls. The carrier uses hosted libc; it supplies no native OSTADIX platform.

This qualifies the preserved emitted library unit and one concrete native API
on the measured host profile. Future generic instantiations, std/core provider
ownership, ordered final linker closure, other ISAs, full standard-library and
compiler bootstrap, and compiler-generated program routing remain separate
requirements. Runtime and full-compiler completion flags remain false.
