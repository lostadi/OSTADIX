# Configured assembly source units

The experimental `ocorec` configured-assembly input route constructs a
verified machine-state source unit from explicitly selected assembly and its
configuration. It is a development step toward importing required original
assembly bodies alongside C and other frontend-produced implementation units.

C implementation bodies continue through their frontend and O-core native
import/code-generation path. Original assembly has a separate source contract;
this route does not replace that C path or run a C preprocessor. Preserve the
original configured source, build flags, includes, target/ABI, complete body
inventory and provider obligations when preparing an assembly selection.

## Interface and current scope

The new input kind is `configured-assembly`. It requires a selected source file,
`--assembly-selection FILE` and `--assembly-selection-sha256 SHA256`. The
`machine-unit` emission is a structured source-unit artifact, not a linked
executable. The source API and file route are implemented in
`native_machine_asm_unit.rs` and `driver/configured_assembly.rs`; the CLI
entry is in `src/bin/ocorec.rs`.

The current implementation models a restricted RV64 profile and refuses
unsupported instructions, profiles and target combinations. Source selection,
whole-body floors, control flow, value/slot constraints and verification must
remain satisfied. A successful synthetic source-unit test does not establish
that a complete upstream assembly unit, library or runtime has been lowered.

## Remaining original-runtime obligations

Automatic configured-source production and admitted-capture/artifact wiring
remain separate work. A complete GNU libc or compiler profile must retain all
required C and assembly units, generated headers, startup bodies, ABI variants,
initializers, relocation/link order and original provider closure. Missing or
unsupported required units remain explicit failures. Full runtime execution and
reference/pairwise semantic identity on every implemented ISA need their own
qualification; this source interface establishes neither.

The accompanying producer/action changes retain original source-action and
provider-order distinctions rather than identifying actions by source path
alone. Rust capture also checks its original Cargo-parent relation. These
checks do not establish an authentic complete Rust producer or standard-library
closure.

Source review,
executed fixture results, compiler builds and original-runtime acceptance are
reported separately.

The source driver is `crates/ostadix-api/src/ocore/driver/configured_assembly.rs`. Its bytes remain included under the existing flat generated-source inventory key; the generated native-core module does not compile the filesystem driver.
