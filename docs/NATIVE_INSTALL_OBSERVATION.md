# Native INSTALL observations

The x86 thread registry records a private software observation while its real
`install` and `install_loaded` paths validate, retain, fill, enqueue or roll back
a TCB. This is a prerequisite for later lifecycle integration. It does not
enable FP, introduce a ledger ticket, publish an execution capability, or change
which ordinary installations succeed.

The read-only query checks the actual generation, parent identities, initial
frame, queue shape and reference transition. Management absence uses raw thread
state and `current_process_matches(0)`, rather than interpreting a lossy getter's
zero as proof. A filled EMPTY/ref1 slot is accepted only by the private
phase-specific check; ordinary frame and queue validators continue to refuse it.
The existing boot function supplies four allowed kernel-stack tops. Hosted tests
model that geometry without establishing physical guard pages or CPU context.

Its output has a distinct observation magic and a private monotonic
`observation_serial`. Neither is the FP ledger ABI or a ledger ticket. Closing
an observation prevents replay; exhaustion disables further observations while
ordinary installation remains available. The production checkpoint is inert.
Only a copied test source adds an observer and a reversible check-failure
injection; positive capsules still come from the real entrypoint's validated
arguments and registry operations. No public stage setter accepts a caller's
identity packet.

The source-bound reference fixture contains the exact thread implementation from
commit `6390bf2d2d725d477cfa1c1f087fcec426b15315`. Its SHA-256 is
`eb53d1fd6d748970e3afa5bc3510aba77e1af74f2ef5b9cd8637f76de7aa86d8`.
Tests compile it without needing Git history and compare ordinary results,
references and queues with the candidate. They check all 18 PCB fields and all
43 thread/observation fields around private queries, keep the 36 common thread
fields distinct from the seven added observation fields, and require exact
semantic diagnostics from six deliberately incorrect guards.

## Mandatory CI and local consumer checks

The mandatory Linux x86 CI lane executes all five INSTALL tests without skips,
beside the existing four current-process and three frame tests. It retains
`target/ocore-install-observation/` even after failure. Its `ci-status.json`
explicitly marks the TLS consumer **not executed and unqualified in CI**: this
job does not provision its independently verified seven-object original-codec
manifest. A passing INSTALL lane is not evidence that TLS ran there.

Run the mandatory INSTALL test locally with a built `ocorec`, Clang, `nm` and
`objcopy`. The output directory must not exist:

```sh
OCOREC_BIN=/absolute/path/to/ocorec \
OCORE_INSTALL_OBSERVATION_REQUIRED=1 \
OCORE_INSTALL_OBSERVATION_OUTPUT=/absolute/path/to/new-output \
python3 -m unittest -v tests.test_install_observation
```

`OCOREC_BIN_SHA256` optionally requires the selected compiler's exact digest.
The fixture records source and tool identities and retains its native commands.
It uses Linux x86-64 host execution, ambient host C headers and libraries, and
declared architecture/image-delivery models; it is not a hermetic bootstrap.

The existing TLS carrier remains a separate required local consumer gate for
this change. First build and verify the original u9fs/musl seven-object component
using its [compiler-owned recipes](../tools/ocore-runtime/u9fs/README.md). Supply
that complete `native-codec.json` and a built compiler. This command refuses a
missing manifest or a skipped test rather than treating either as a pass:

```sh
export OCOREC_BIN=/absolute/path/to/ocorec
export OCORE_U9FS_MANIFEST=/absolute/path/to/native-codec.json
python3 - <<'PY'
import os, unittest
if not os.environ.get("OCORE_U9FS_MANIFEST"):
    raise SystemExit("a verified original-codec manifest is required")
suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_linux_tls")
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful() or result.testsRun != 1 or result.skipped:
    raise SystemExit("the real TLS consumer must execute without skips")
PY
```

That test validates and links the original seven objects and headers. The added
stack-geometry model restores the carrier's declared architecture interface; it
does not replace original codec code. Source releases require the baseline,
test/import/helper files and all 17 x86 plus three common runtime modules used by
these carriers. An omission regression rejects missing inputs.

Actual FP ledger preflight, image management, ticket consumption, callbacks,
invariant-fatal rollback and CPU readiness/save/restore remain unfinished. The
query does not prove complete resource authority, SMP consistency, all-ISA
semantics, user-mode application execution, physical boot, drivers or efficiency.
Complete AArch64/RV64 objects currently reject the existing x86 `sysv64` interface;
hosted x86 tests do not qualify those targets or the full native-system objective.
