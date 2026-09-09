# Python native object handles

`O.native(value)` retains any Python object in its current backend process and
returns an opaque `OValue::Native` descriptor. It does not serialize the object,
run `repr`, pickle it, or reconstruct it in another runtime. Closures, arbitrary
instances, generators, mutable aliases, and cycles retain their Python identity.

```text
let handle = python[7]^(O.native(lambda value: value + 2))_python[7]
python[7]^(O.resolve_native($handle)(40))_python[7]
python[7]^(O.release_native($handle))_python[7]
```

`O.resolve_native(handle)` returns the original object in the original owner
process. Repeated resolution returns that same object. Descriptors can be
carried through O and echoed by other Python actors as opaque values; a foreign
actor cannot resolve them. The descriptor uses a random process origin and a
random 256-bit token, and the owner verifies the complete exported descriptor
before resolving or releasing it. Changed, unknown, released, or foreign-owner
handles fail explicitly. A forked process cannot reuse its parent's store.

`O.release_native(handle)` releases one explicit export and invalidates every
copy of that descriptor. Separate calls to `O.native` allocate separate exports,
even for the same object, and each must be released. Already resolved local
Python references keep their normal Python lifetime; release does not revoke
those references. Backend cleanup invalidates all remaining exports.

Use a persistent `python[N]` owner for a handle needed by later blocks. A fresh
`python^(...)_python` actor is retired when its block finishes, so its returned
handle cannot subsequently be resolved. Owner exit has the same effect. An
attempt to resolve such a handle in a replacement actor reports
`native.owner-mismatch`; a released or cleaned-up handle in its existing owner
reports `native.handle-expired`.

The descriptor declares `LiveHandle`, `SameProcess`, and an effectful boundary.
It is not cache-safe, replay-safe, or boot-persistable. The stronger Python plain
data morphism contract rejects these handles; it does not relabel them as
structural data. Native object methods continue to run under the existing
Python actor's execution authority.

While any exported handle remains live, Python checkpointing reports
`state.pin-required` at `$native_handles`. This prevents local actor migration
or checkpoint-based recovery from silently replacing an owner with a process
that lacks its objects. Releasing every export permits checkpointing only when
the remaining actor state is supported by the existing checkpoint codec.

Each process allows 4096 simultaneous exports by default. Set
`O_PYTHON_MAX_NATIVE_HANDLES` to a positive integer before starting the actor to
select a different bound. The bound counts handles; it does not estimate the
memory reachable through arbitrary retained objects. Capacity exhaustion leaves
existing handles valid, and release returns capacity.

`tests/test_python_native_handles.py` exercises the real shim protocol;
`tests/python_native_handles.rs` checks OIR/wire round trips, owner expiry,
checkpoint pinning, and migration after release.
