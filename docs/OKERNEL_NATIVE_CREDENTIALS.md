# Native Linux credential reads

`runtime::linux_credentials` stores immutable UID, effective UID, GID and
effective GID metadata for one explicitly admitted native PCB generation.
Trusted process-start policy supplies all four values. The module has no host
identity fallback and does not infer identities from process IDs, paths or
syscall arguments. Its getter dispatch implements Linux x86-64 numbers 102,
107, 104 and 108. Other numbers return `ENOSYS`; a missing or changed admitted
current process returns `ESRCH`.

The trusted start owner calls admission before first process execution.
The API checks a serialized management context with no current process, a
ready Linux-personality PCB and live address-space and CSpace
identities. It binds their complete generation handles, rejects an occupied
record and reserves the all-ones UID/GID value as Linux does. It publishes the
owner last. A running process cannot invoke this native API through a getter.
READY does not itself prove that a process has never run; the trusted start
owner enforces that timing, and this module does not track activation history.
There is no default syscall routing change.

The trusted start owner can read the same immutable metadata with `read_for`
when constructing an ELF auxiliary vector. It must use this same policy for
`AT_UID`, `AT_EUID`, `AT_GID` and `AT_EGID`; this module does not implement a full
exec transaction or authorize an executable. Credential records survive
EXITED, REAPABLE and TEARDOWN tombstones. Management retires them only after
the exact PCB generation is destroyed. Reusing a PCB slot cannot inherit or
overwrite an unretired record.

These numeric compatibility identities grant no native capability, namespace
right or filesystem permission. Setters, supplementary groups, permission
enforcement, set-ID exec, user namespaces and a complete Linux process provider
remain unsupported. This is native platform code, not original Linux or libc
source lowering. The current four-record storage follows the existing four-PCB
registry and fails initialization if that registry bound changes. Calls require
the same serialized process-start/scheduling/lifecycle policy; there is no SMP
or concurrent mutation claim.

Run the focused native carrier with a selected built compiler:

```sh
OCOREC_BIN=/path/to/ocorec python3 -B -m unittest tests.test_linux_credentials -v
```

The carrier executes the production credential, process, domain, capability,
address-space and loader modules. The host supplies privileged architecture
hooks and image delivery. It checks separate process values, immutable
admission, initial auxv consistency, invalid identities, changed AS/CSpace,
actual two-phase PCB teardown, generation reuse and surviving-process state.
Four semantic mutants must fail. Private data is visible only through a
test-specific ELF symbol-binding change; allocated code/data bytes are checked
to remain identical. The original production source and visibility are kept.
The explicit corruption controls restore the exact private registry fields.

This host carrier does not qualify a protected CPL3 syscall route, an original
application, non-x86 platform behavior, an original runtime or the final OS.
Those acceptance steps require separate artifacts and actual execution.

The separate protected carrier uses four loaded native Linux-personality
processes, the production syscall-entry/scheduler path and the verified original
codec manifest. It checks distinct configured auxv values and all four getters
before and after scheduling, sleep, TLS/file reuse and final native retirement:

```sh
python3 -B ocore/kernel/native_credentials/verify.py \
  --output /new/evidence/directory --compiler /path/to/ocorec \
  --codec-manifest /path/to/native-codec.json
```

`--deny-role 0` through `3` deliberately leaves that process unadmitted; its
getters must return `ESRCH` despite the numeric values present in its auxv.
The carrier reuses the existing idle test with captured, explicit fixture
composition. Its counters report eight real getter calls per process. This
is a single-CPU QEMU x86-64 check, with private test controls for sleep and
retirement; it does not add general Linux process termination, an original
program or a default interactive OS route. An explicitly supplied
`--credential-source` is reserved for recorded private semantic mutants.
