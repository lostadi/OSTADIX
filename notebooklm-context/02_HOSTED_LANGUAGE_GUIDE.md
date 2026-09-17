# Hosted O language guide

This file describes the authoritative Rust edition unless an alternate edition
is named explicitly. Normative source: `SPEC.md`. Agent-oriented examples:
`docs/AI_GUIDE.md` and `examples/*.O`.

## Typed expressions

The core form is a matched typed delimiter:

```text
IDENT^( body )_IDENT
IDENT[n]^( body )_IDENT[n]
IDENT[*]^( body )_IDENT[*]
```

`IDENT` must be a registered language tag or alias. The opener and closer must
match exactly, including the environment marker. An unregistered identifier
followed by `^(` remains ordinary text, which prevents target-language syntax
such as Python's `2 ^ (x + 1)` from becoming an O expression.

Typed expressions nest recursively. Evaluation is normally leaves-up:

1. evaluate each nested child;
2. receive its OValue;
3. ask the parent backend's renderer to convert the child into the parent's
   body representation;
4. evaluate or render the completed parent body.

Backslash escapes produce literal O syntax. The most important case is
`\$NAME`, which passes `$NAME` to the target language instead of asking O to
splice an O-level binding. This is required for shell variables such as
`$PATH`.

## Minimal program

`examples/hello.O` is:

```O
python^(
__oval_result__ = 1 + 1
)_python
```

The expected human output is:

```text
[number] 2
```

For structured automation, use `O --json examples/hello.O backends`.

## Bindings and splicing

An O binding stores one OValue in lexical O scope:

```O
let answer = python^(
__oval_result__ = 40 + 2
)_python

markdown^(The answer is **$answer**.)_markdown
```

`$answer` is not target-language textual interpolation. It is an O-level load,
and the receiving Markdown backend controls how the loaded OValue is rendered.
Bindings established earlier in an `O^(...)_O` region are visible to later
children in that region.

Python result selection is, in order:

1. the value assigned to `__oval_result__`;
2. the final bare Python expression;
3. captured stdout if neither of the first two produces a value.

Using `__oval_result__` is the least ambiguous form for generated code.

## Environment markers

Environment lifetime is part of the source semantics:

| Form | Meaning |
|---|---|
| `python^(...)_python` | Ephemeral: a fresh physical backend attempt for this expression. |
| `python[*]^(...)_python[*]` | Explicit linker-isolated fresh attempt. `*` is placement intent, not a shared identity. |
| `python[0]^(...)_python[0]` | Persistent logical environment keyed by canonical language and numeric ID. |
| `python[1]^(...)_python[1]` | A different persistent environment, isolated from `[0]`. |

For example:

```O
O^(
  python[0]^(x = 40)_python[0]
  python[0]^(__oval_result__ = x + 2)_python[0]
)_O
```

State such as imports, variables, functions, and backend-owned resources can
survive between uses of the same numeric environment. Bare and `[*]` blocks do
not share state. A numeric environment is a logical affinity key, not a node,
process-generation, backend-specification, or placement authority identity.

## Structural backends

Most backends use the default child-splice-then-evaluate flow. Two core
backends take control of their child structure:

- `O^(...)_O` evaluates children exactly once in planned source order and
  returns the last non-null result. Formatting-only whitespace does not replace
  that result.
- `quote^(...)_quote` captures the body as an OExpr without evaluating its
  children.

`quote^` combines with the Python bridge's `O.eval`:

```O
let q = quote^(python^(6 * 7)_python)_quote

python[0]^(
__oval_result__ = O.eval($q)
)_python[0]
```

`O.eval` runs through the same parse, OIR, plan, graph, evidence, and admission
path as ordinary source. It sees a cloned lexical snapshot of the O scope at
the backend call site. Callback-created bindings do not mutate the caller.
`scope()` creates an explicit detached OScope, and `O.eval(expr, scope)` uses
that supplied scope. A callback cannot recursively execute the same persistent
backend environment that is waiting for it; nested backend work must use a
different environment index.

## Deferred work

There are both block attributes and O-level policy calls:

```O
let cached = html{lazy}^(<p>stable</p>)_html{lazy}
let effect = python{defer}^(import time; time.time())_python{defer}

let a = now($cached)
let b = now($effect)
```

- `{lazy}` captures backend evaluation as a Request and is accepted only for
  registry-marked cache-safe backends. Its forced result is cached by
  fingerprint, and splicing may force it automatically.
- `{defer}` captures any backend evaluation as an uncached Request. It runs on
  each explicit force. Splicing it without `now()` is rejected so a rendering
  step cannot silently repeat an effect.
- `lazy(expr)` evaluates an O expression under lazy policy and captures request
  chains rather than naming a language.
- `now(request)` forces the named deferred computation.
- `autonomous(expr)` buffers eligible requests and uses the scheduler at its
  force boundary.

Purity is backend-registry metadata. It is not inferred from a language name or
a user assertion. Effect declarations can add conservative dependencies but
cannot turn unverified hosted source into pure work.

## Coordination groups

Groups are explicit control values. Creating a group does not itself perform
the work. `now(group)` or an autonomous force boundary resolves it.

| Form | Semantics |
|---|---|
| `batch(a, b, ...)` | Resolve every member and return an ordered list. Ordinary member failures become OError entries. |
| `all(a, b, ...)` | Require every member to succeed; the first failure fails the group. |
| `any(a, b, ...)` | Return the first member to succeed in source order; fail only if all fail. |
| `race(a, b, ...)` | Return the first result to settle, whether success or failure. |

The constructors are special forms. They capture deferred request chains even
under eager surrounding evaluation. Member order contributes to identity and
is never sorted. Empty groups are invalid, and groups may nest.

Current limitations:

- concurrent group dispatch is narrow, especially for threadable Nix-family
  requests and explicitly autonomous ephemeral group members;
- evaluator-local Eval requests and real activation stay on the evaluator
  thread;
- race chooses a winner but does not cancel already running losers;
- an autonomous strict-cache miss is a hard scheduler error even for `batch`.

## Important builtins

| Builtin | Purpose |
|---|---|
| `instantiate(nix_expr)` | Create an ODerivation request/result. |
| `realise(derivation)` | Build and return an OStorePath. |
| `activate(path[, profile])` | Perform a real ambient host system activation. |
| `dry_activate(path[, profile])` | Request a dry activation. |
| `current_system()` | Return a live OSystem reference. |
| `scope()` | Capture detached lexical bindings as OScope. |
| `lazy(expr)` | Enter lazy evaluation policy. |
| `now(value)` | Force a Request or Group. |
| `autonomous(expr)` | Buffer and schedule eligible requests. |
| `batch/all/any/race` | Construct an OGroup with explicit topology. |

Real `activate` is effectful and uses the current process's ambient host
authority unless an embedding-specific live capability guard is supplied.

## OValue

Every typed expression yields an OValue. The important families are:

- scalar/data: null, bool, arbitrary/rich numbers, text, char, bytes, HTML,
  symbols, and keywords;
- containers: list, map, typed sequences, object, entries map, set, and graph;
- code/native: OExpr, ONixExpr, native capsules, and blobs with media types;
- system/dependency: derivations, store paths, systems, and snapshots;
- orchestration/authority: requests, thunks, groups, scopes, errors, and
  capabilities.

OValue has a canonical tagged wire shape. Hosted backend processes use
length-prefixed canonical CBOR; JSON examples in documentation are logical
projections, not a statement that backend IPC is JSON. Legacy `int`, `float`,
and `str` tags are accepted at compatibility boundaries but normalize into the
canonical number and text families.

The runtime independently classifies:

- pure versus referential versus effectful boundary behavior;
- cache safety;
- replay safety; and
- boot-persistence safety.

Serialization or inertness alone does not imply any of the last three.
Capabilities are authority-bearing only when their opaque identity resolves in
the live private broker/session that issued them. Deserialized metadata does
not mint authority.

## Rendering rule

The receiving backend owns `render_child(OValue)`. This is why an image blob
can become an HTML data URL, a number can become a Python literal, and a list
can become a Markdown/HTML presentation without pairwise language bridges.

Rendering fidelity and backend-crossing fidelity are separate vocabularies.
Current renderer classifications include typed, structural, presentation, and
opaque outcomes. Containers fold the fidelity of their children, and an opaque
value must leave an identifying marker rather than disappearing.

Primary source: `SPEC.md` sections 3-5.

## Current backend catalog

The current catalog schema is `ostadix.backend-catalog/v6`. It defines 30
canonical backend names:

```text
O, quote, nix, nix_expr, nix_store, nixos_test,
html, markdown, latex, text,
sql, haskell, ocaml, webassembly,
python, ubuntu_vm, bash, shell, rust, racket, csharp, c, cpp,
lisp, common_lisp, ruby, matlab, mathematica, java, javascript
```

Aliases are:

```text
o -> O
md -> markdown
tex -> latex
plain -> text
py -> python
ubuntu -> ubuntu_vm
```

Inline/builtin backends need no external runtime. Shim/native-adapter backends
need their declared interpreter, compiler, or tool combination. Presence of a
binary is not proof of health, authorization, capacity, or operation
admission. The exact authoritative records are in
`crates/ostadix-api/src/backend_catalog.inc.rs`.

## Hosted authority and safety

Ordinary hosted execution is intentionally host-capable. Shim backends receive
the rights available through the default O process policy, including file,
network, and process rights when their interface requires them. Compatibility
grant syntax and Python audit/macOS sandbox plumbing exist, but plain O source
is not a general containment boundary.

Unknown source effects conservatively read and write `HostWorld`. Numeric
persistent environments also serialize through an actor-state identity. User
effect annotations add constraints and do not erase this fallback. The special
autonomous unordered path is an explicit source opt-in: already-started
external effects may race and are not rolled back.

## Alternate-edition differences

- Rust is authoritative and owns current OIR/HGraph/Evidence V6/Admission V6
  behavior.
- C17 supports documented hosted forms and fresh `[*]` execution but is not
  feature-identical; its activation behavior is dry-only.
- Python is a readable reference/test harness and lacks the general
  call-expression grammar used by `autonomous(batch(...))`.
