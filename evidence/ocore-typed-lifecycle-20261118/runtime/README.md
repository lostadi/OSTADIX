# Typed lifecycle runtime qualification

The O10/namespace migration preserves distinct generation ranges and checks
its compiled policy against an independent model. Capability transfer and
request-bound memory views use typed internal boundaries while retaining one
raw mutation body, runtime authority checks and existing rejection accounting.

These results use the retained M1 compiler. The array language change has
separate source, review and qualification.

| Receipt | Scope |
|---|---|
| `qualification.json` | Stage status, exact final owner source identities, compatibility and blockers |
| `lifecycle-component.json` | Three-ISA production policy, full-width observations, exhaustive finite projections, modeled hooks and 14 policy mutations |
| `identity-runner-admission.json` / `lifecycle-identity-runner.json` | Fresh output isolation, required runner identities, and actual 64-case constructor/layout execution per ISA |
| `o10-native-components.json` | Nine fresh native suites with no required skips; namespace-off resident regression included |
| `kernel-m3-r1.json` | Actual x86-64 TCG Modes 0/13/19/24, fixed limits and retained secondary live artifacts |
| `kernel-m3-r2.json` | Fresh affected Modes 19/24 after typed resource destruction correction |
| `kernel-identity-rejections.json` | Five actual API/domain compiler rejections |

The compact lifecycle receipt identifies the complete 45,988,835-byte report
by SHA-256. Its full inputs, per-edge observations, assembly, objects, ELFs,
stdout/stderr, exact commands and minimal mutation prefixes are retained in
the implementation run archive. AArch64 and RV64GC component code executed
under user-mode QEMU; x86-64 executed natively. The carrier executes production
RAM copies and labels privileged reset/interrupt hooks as modeled.

Fresh same-build AArch64 guest acceptance is blocked on the private seed,
offline APK fixture, admitted payload/build pair and observed running provenance.
The historical acceptance packet remains historical. The initial independent
model covers O10 and namespaces; transfer and views use their compiled mechanism
and live kernel oracles. No physical or SMP qualification is claimed here.

From a configured checkout, build the current compiler, use fresh output
directories, and run the component runner without diagnostic target selection:

```sh
cargo build --locked --package o-lang --bin ocorec
python3 scripts/check_ocore_lifecycle_identity.py --ocorec target/debug/ocorec --output-dir target/fresh-lifecycle-identities
python3 scripts/check_ocore_lifecycle_conformance.py --ocorec target/debug/ocorec --output-dir target/fresh-lifecycle-conformance
OCOREC_BIN="$PWD/target/debug/ocorec" OCORE_PROBE_MODE=0 OCORE_BUILD_DIR="$PWD/target/fresh-baseline" bash ocore/kernel/smoke-qemu.sh
OCOREC_BIN="$PWD/target/debug/ocorec" OCORE_BUILD_DIR="$PWD/target/fresh-ipc" bash ocore/kernel/smoke-ipc-foundation-qemu.sh
OCOREC_BIN="$PWD/target/debug/ocorec" OCORE_BUILD_DIR="$PWD/target/fresh-views" bash ocore/kernel/smoke-m6b-qemu.sh
OCOREC_BIN="$PWD/target/debug/ocorec" OCORE_BUILD_DIR="$PWD/target/fresh-live" bash ocore/kernel/smoke-live-bounded-personality-qemu.sh
```

LLVM assembly/link tools and every canonical target's runner are prerequisites.
The default conformance result fails closed on missing lanes, empty or altered
required corpus, stale artifacts and surviving policy mutations. A different
corpus is diagnostic-only. Preserve the fixed secondary Mode 24 artifacts as
well as its requested build directory. The implementation guide records the
separate full-system workflow and remaining prerequisites.
