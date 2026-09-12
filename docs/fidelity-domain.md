# Fidelity intervals: order, adjunction, and soundness

`FidelityAssessmentV2` has an information order as well as operations for
sequential crossings and path merges. These are distinct concepts. In
particular, the severity precedence of `Unsupported` and `NativeCapsule` in
`join_paths` is not the information order.

## Concrete and abstract domains

Let `U` be the vocabulary of `AnnotationKind` values. The Rust enum has a fixed
list of variants, but `BackendSpecific { lang, label }` contains arbitrary
strings, so `U` is not finite. Neither the subset invariant nor the algebra
below requires a globally finite vocabulary.

For structural outcomes, a concrete observation is a finite set `L ⊆ U` of
lost annotation kinds. `Fidelity::Lossless` represents `L = ∅`;
`Fidelity::Structural` represents nonempty `L`. Write `C₀ = P_fin(U)`.
These observations describe fidelity judgments, not the underlying native
values or backend semantics.

The concrete domain for the adjunction is

```text
C = { S ⊆ C₀ | S is finite and nonempty }, ordered by inclusion.
```

An abstract structural assessment is an interval

```text
A = { [D, P] | D and P are finite subsets of U, D ⊆ P }.
```

`D` is the set of definite losses, `P` the set of possible losses, and
`[∅, ∅]` is the canonical `FidelityAssessmentV2::Lossless`. An absent
`definite` field means the empty set. The information order is

```text
[D₁, P₁] ⊑ [D₂, P₂]  iff  D₂ ⊆ D₁ and P₁ ⊆ P₂.
```

Smaller means more precise. The implementation is `precision_leq`; its
checked counterpart `try_precision_leq` rejects invalid bounds in either
operand. Invalid, directly assembled enum values are outside `A`; their
defensive false membership result does not introduce a bottom element.

## The Galois connection

Define abstraction and concretization by

```text
α(S)       = [ ⋂ { L | L ∈ S }, ⋃ { L | L ∈ S } ]
γ([D, P])  = { L ∈ C₀ | D ⊆ L ⊆ P }.
```

These maps are well defined: `S` is finite and nonempty, so its intersection
and union give finite bounds; `γ([D, P])` is finite and nonempty because
`P` is finite and `D ∈ γ([D, P])`. Thus they are maps `α : C → A` and
`γ : A → C`, even though the vocabulary `U` is infinite.

The adjunction is

```text
α(S) ⊑ a  ⇔  S ⊆ γ(a).
```

Proof, for `a = [D, P]`:

```text
α(S) ⊑ [D, P]
⇔ D ⊆ ⋂S and ⋃S ⊆ P
⇔ for every L ∈ S, D ⊆ L and L ⊆ P
⇔ S ⊆ γ([D, P]).
```

This proves a Galois connection between the stated posets. They are not
claimed to be complete lattices: empty outcome families would require a
bottom that the enum does not have, and unrestricted infinite families can
require infinite possible-loss bounds. On a fixed finite vocabulary `B`,
the same theorem applies to all nonempty subsets of `P(B)`.

It is also a Galois insertion. Both endpoints `D` and `P` belong to the
concretization, so its intersection is `D`, its union is `P`, and
`α(γ(a)) = a`. Consequently the order above is exactly concretization
inclusion, rather than merely a sufficient comparison rule.

The executable point embedding is
`α_point(c) = FidelityAssessmentV2::from_concrete(c)`. On structural
observations this is `α({c}) = [L, L]`. It satisfies the requested point
correspondence:

```text
α_point(c) ⊑ a  ⇔  c ∈ γ(a).
```

The implementation of `α` for a nonempty family of structural/lossless
outcomes is the existing point embedding followed by interval hulls:

```rust
let abstracted = outcomes
    .into_iter()
    .map(FidelityAssessmentV2::from_concrete)
    .reduce(FidelityAssessmentV2::join_paths)
    .expect("a nonempty family of structural/lossless outcomes");
```

This expression's domain restriction is essential; heterogeneous sentinel
outcomes do not have an interval hull in the current enum.

## Monotonicity and crossing soundness

If `S ⊆ T`, then `⋂T ⊆ ⋂S` and `⋃S ⊆ ⋃T`; hence
`α(S) ⊑ α(T)`. If `a = [D₁, P₁] ⊑ b = [D₂, P₂]`, every
`L ∈ γ(a)` satisfies `D₂ ⊆ D₁ ⊆ L ⊆ P₁ ⊆ P₂`, so
`γ(a) ⊆ γ(b)`. These are monotonicity of the two adjoints. Concrete
observations here are ordered as sets of alternatives; increasing a loss
set's severity is a different order and does not make one exact singleton
observation less precise than another.

For successive structural crossings, concrete composition is union and
`then` computes

```text
[D₁, P₁] then [D₂, P₂] = [D₁ ∪ D₂, P₁ ∪ P₂].
```

If `L₁ ∈ γ(a₁)` and `L₂ ∈ γ(a₂)`, then
`D₁ ∪ D₂ ⊆ L₁ ∪ L₂ ⊆ P₁ ∪ P₂`. Therefore
`L₁ ∪ L₂ ∈ γ(a₁ then a₂)`: abstract sequential composition is sound.
Union preserves both endpoint inclusions, so `then` is monotone in both
arguments under `⊑`. These results require no enumeration of `U`.

For structural path alternatives, `join_paths` computes the least upper
bound in the information order:

```text
[D₁, P₁] join_paths [D₂, P₂] = [D₁ ∩ D₂, P₁ ∪ P₂].
```

It may introduce additional concrete alternatives, as interval abstraction
can discard correlations between loss kinds. The adjunction establishes
that it is the most precise interval containing both input concretizations.

## Sentinel and convergence limits

`NativeCapsule` and `Unsupported` each concretize to their corresponding
single V1 outcome. The precision order treats them as isolated points,
comparable only with themselves. The point correspondence remains true for
all valid enum values, including these sentinels. Sequential composition
remains sound because its concrete and abstract sentinel precedence agrees.

The enum cannot represent `{Lossless, Unsupported}` or
`{Lossless, NativeCapsule}`. `Lossless.join_paths(Unsupported)` returns
`Unsupported`, whose concretization omits `Lossless`. Therefore that
severity merge is not a concretization upper bound, and there is no claim
of a Galois connection over arbitrary mixed V1 outcome families. A
success-selecting execution path must retain alternatives separately or use
evidence identifying the selected path.

The finite-support algebra must also be distinguished from solver
termination. For a fixed finite graph vocabulary `B`, structural intervals
have `3^|B|` possible states: each kind is absent, possible only, or
definite. This supports finite-height arguments for monotone iteration in
the appropriate order. The active solver accumulates crossing facts using
`then`, so its structural update order is `D₁ ⊆ D₂` and `P₁ ⊆ P₂`, with
severity precedence for sentinels. This is distinct from the information
order `⊑` above: increasing definite losses refines information, whereas
increasing possible losses broadens it. The adjunction is not a claim that
every solver update ascends in `⊑`. The convergence budget accounts for
both growing coordinates and the retained V1 possible-loss projection.
An unbounded supply of fresh `BackendSpecific`
labels would invalidate that convergence argument, while leaving the
subset invariant and the proofs above intact. Transfer rules that introduce
such labels need a bounded vocabulary or a widening policy; a convergence
budget must fail closed if its bound is exceeded.

## Executable checks and scope

`crates/ostadix-api/src/value.rs` tests the point correspondence, both
adjoints' monotonicity, sequential monotonicity, and concrete-member
composition soundness using generated annotation sets, including arbitrary
`BackendSpecific` labels. The finite exhaustive regression enumerates all
8 concrete loss sets, all 27 intervals, and all 255 nonempty outcome
families over a three-kind vocabulary. It checks the adjunction against
concrete membership, reflects concretization inclusion into the order,
checks abstraction monotonicity, and checks `α(γ(a)) = a`.
Sentinel regressions make the excluded mixed-family case explicit.

Run the focused tests with:

```bash
cargo test --locked -p ostadix-api --lib value::tests::fidelity_v2_
```

The proof establishes properties of fidelity abstraction and composition.
It does not by itself prove each backend's loss report correct, establish
solver authority, or show an observable interop failure. Those require
transfer-rule checks and end-to-end evaluation evidence separately.
