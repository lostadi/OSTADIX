The primary acceptance result concerns the complete, unchanged upstream runtime
or compiler. A successful capture, module import, ABI fixture, diagnostic object,
or infrastructure test does not make that result GREEN.

Run a profile with pinned, actual tools:

    python3 tools/ocore-runtime/acceptance/check_runtime.py PROFILE.json \
      --tools TOOLCHAIN.json --output NEW_DIRECTORY

The profile follows [contract.schema.json](contract.schema.json). Source and
recipe pins, every required target, exact native target/DataLayout/ABI fields,
the original program/library graph, and complete upstream behavior targets are
explicit. There is no language-name whitelist. Required unsupported targets,
providers, artifact forms, resources, compiler-output paths or JIT paths remain
RED and return nonzero. They do not prevent supported source/build/import stages
from being attempted.

The toolchain JSON has schema `ocore-original-runtime-toolchain-v1`, a `tools`
mapping of role to `{path,sha256}` (optional byte count), and an `environment`
mapping. Required roles are `olangc`, `ocorec`, `llvm_library`, and
`inventory_helper`; frontend roles are selected explicitly by the profile.
Paths are absolute. The actual sibling `ocorec` used by `olangc` must match the
selected compiler bytes. Start Python with the SDK's required library search
path already configured when its LLVM shared library requires it.

Every available required imported unit receives a separate original LLVM
inventory, initializer/relocation/intrinsic preservation check, fresh independent
native verification and fresh owned diagnostic object. Failed units remain in
the report. Provider resolution is separate from declaration preservation.

Current source-recipe output is a verified native module set, not a complete
runtime/script/orchestration artifact. The runner therefore leaves the complete
artifact and execution gates RED. A supplied executable, manually linked test
ELF, handwritten replacement runtime or interpreter for unchanged implementation
IR cannot satisfy them. A future complete artifact must come from the actual
`olangc` workflow and its public re-admission interface; the test harness cannot
invent its admission. Compiler bodies and their generated programs have distinct
gates, as do JIT generation, publication and invalidation. Foreign scripts may
still be interpreted by the original runtime after its own implementation has
been lowered.

Receipt flags are observations, not independent admission. Trusted capture-worker
reconstruction, the original recipe-required inventory, actual native link
journals and provider symbol closure need their own evidence. Until connected,
those gates are explicitly UNVERIFIED (non-accepting). Every available unit is
still checked, and required recipe units omitted by capture are retained as RED.

Independent capture admission additionally requires a separately pinned `capture_verifier` tool: the trusted original `ocore_runtime_capture.py` corresponding to the captured worker. The runner invokes its public `verify-report` command, binds the exact report, original recipe and checkout, and compares the complete finalized build inventory. Recipe requirements form a mandatory floor; finalized Make requirements may add rules. Missing or incompatible trusted replay remains UNVERIFIED. This admission proves source capture and unit partition, not import, provider closure, an owned executable, or runtime acceptance.
