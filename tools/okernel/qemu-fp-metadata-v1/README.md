# QEMU x86 FP metadata R7 development recipe

This additive source package retains the reviewed seven-file QEMU 11.1.3 R7 patch, its portable recipe, and host orchestration controls. It does not install an emulator or change OKernel's default QEMU or CPU profile. Arithmetic V2, complete Intel floating point, native O-core FP services, physical drivers, a final native ISO, and whole-system efficiency remain unqualified.

The `recipe-v2` name denotes the corrected orchestration revision for the R7 **metadata-v1** patch. It does not contain the separate arithmetic-V2 implementation. The original QEMU archive, emulator binaries, firmware/SDK, and large saved evidence stay external. The archive and source freeze are pinned in `recipe-v2/pins.json`; the exact source patch is `recipe-v2/qemu-fp-v1.patch`. Preserve upstream licenses and per-file notices; see [UPSTREAM-NOTICES.md](UPSTREAM-NOTICES.md).

## Run the finite host controls

Use Linux with Python 3.12 available at `/usr/bin/python3.12`, its standard library, and Linux `/proc` plus `prctl(PR_SET_PDEATHSIG)`. Run as an ordinary user in an existing writable private cache directory. No compiler, SDK, QEMU, firmware, network, privileged installation, or running VM is needed for this command.

```sh
/usr/bin/python3.12 -I -B tools/okernel/qemu-fp-metadata-v1/run-controls.py \
  --evidence-root /absolute/path/to/external-evidence-root \
  --output /absolute/path/to/existing-private-cache/new-controls-directory
```

The evidence root must contain the **six exact saved result JSON files** named and hashed in `schema-inputs.json` (146,496 bytes total). Nothing else from that evidence tree is copied or followed. These files are schema replay inputs; their saved paths, PIDs, and old pass fields do not authorize commands or grant a new runtime pass. Missing, changed, aliased, or symlinked inputs are rejected before any driver starts. The output directory must be absent and have an existing canonical parent; it must not overlap the source package or evidence.

The launcher validates complete source membership against `source-inventory.json`, copies source and the six JSON inputs to distinct-inode files in the new cache, runs the three fixed unchanged drivers there, and rechecks all inputs. It retains actual commands, statuses, stdout/stderr, and result hashes in `result.json`. Success requires all 14 synthetic build/verify error controls, two exact source generators, one owned non-QEMU parent-death child, six saved-schema cases, the failed-stream guard, and an intercepted VM constructor. **It never builds or starts QEMU.** The synthetic cases replace subprocess execution explicitly; the owned child only sleeps and is checked after its own parent exits.

To exercise launcher custody failures as well as that positive run:

```sh
/usr/bin/python3.12 -I -B tools/okernel/qemu-fp-metadata-v1/test_run_controls.py \
  --evidence-root /absolute/path/to/external-evidence-root \
  --output /absolute/path/to/existing-private-cache/new-launcher-tests
```

These tests mutate only new private source/evidence copies and keep outputs outside the tracked source. Do not run the original three drivers directly in the checkout: their preserved historical layout writes outputs beside the driver. `run-controls.py` supplies the required writable copy. Source manifests provide integrity under a trusted-source profile, not independent authentication against a party that can coherently replace source and manifests.

## Reconstruct or build the emulator separately

See the unchanged [portable recipe](recipe-v2/README.md) for explicit archive preparation, private build, and real emulator verification commands and their additional host tool, firmware, SDK, compiler, library, and build dependencies. Those are deliberate separate actions; the host-control launcher does not perform them. All source trees, outputs, and selected tools must follow that recipe's pinned custody requirements. No global or existing emulator should be replaced.

The external evidence references in `qualification-index.json` distinguish the completed historical R7 runtime cases from later corrected-wrapper controls. They do not package the external build closure or reproduce 333 emulator checks by replaying six JSONs. The optional development recipe declares Python 3.12; static parsing on selected Python 3.10.22 is not a universal Python 3.10 execution qualification.
