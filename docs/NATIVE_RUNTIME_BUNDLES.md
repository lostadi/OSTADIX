# Native runtime installation

`./setup.sh --runtime-only --verify` builds four core Rust executables (`O`,
`o-cli`, `olangc`, `ocorec`) and the independently locked `ostadix-mcp` server.
It installs the native `o` front door and `ostadix-evaluator` aliases. It skips
the C and Python alternate editions, notebook, workspace tools, applications,
JNI and editor modifications. `--no-mcp` omits the fifth executable. `--minimal`
and normal/full setup retain their existing tool selection. Explicit
`--with-*` provider/tool dependencies still compose with runtime-only setup.

This profile retains the default graph executor and O-core compiler. Expert
commands requiring tools outside this installation report those missing tools;
catalog discovery is not proof that every command is installed. External
language providers are discovered on the host. They are not all shipped in
these bundles, and this packaging does not establish complete runtime lowering
through O-core.

Inspect selection without building or changing the machine:

```sh
./setup.sh --runtime-only --dry-run --no-env
```

## Install a prebuilt bundle

The `Native runtime bundles` workflow builds on native Linux AArch64 and Apple
Silicon runners. Same-repository packaging pull requests and manually dispatched
runs retain verified artifacts for review. Pull requests build the exact head
commit rather than attributing a synthetic merge commit to the source. A
published GitHub release additionally receives both qualified archives, their
SHA-256 sidecars, source archive, build manifests, and smoke records. A failed
architecture job prevents publication. Preparing this workflow does not itself
publish or qualify an ARM64 binary.

Both native architecture jobs also run the MCP Rust unit tests, including
provenance and watcher filesystem boundaries, and retain that test log as a
release asset. These are separate from the bundle's bounded execution smoke.

Download the archive for the actual operating system and architecture. Obtain
its expected SHA-256 from the corresponding trusted release record or sidecar.
In an existing checkout, installation needs Python 3.11+ and the runtime's host
dependencies, not Cargo or a compiler build:

```sh
python3 scripts/runtime_bundle.py install /PATH/TO/ostadix-runtime-COMMIT-TARGET.zip \
  --sha256 EXPECTED_64_CHARACTER_SHA256 \
  --destination "$HOME/.local/share/ostadix/runtime/COMMIT-TARGET" \
  --bin-dir "$HOME/.local/bin"
```

The installer verifies the external checksum, every inventory hash, exact
source archive, build and smoke identities, and native ELF/Mach-O architecture
before executing anything. It then tests the extracted evaluator, IR planner,
O-core command and MCP stdio execution from a new location, before replacing
installed commands. Each command replacement is atomic. The permanent bundle
directory supplies source/backends and must be kept; `ostadix-install.json`
beside the installed tools points to it. A new install never removes unrelated
commands from an earlier full installation. Existing destinations are refused;
choose a new version directory for upgrades.

Without a checkout, the same reviewed installer and its dependencies are inside
the archive's `source/` directory. First check the downloaded archive against
the trusted external checksum, then extract it with the platform's ZIP tool
and use `source/scripts/runtime_bundle.py` in the command above. Never treat a
self-supplied internal checksum as proof of publisher authenticity.

Linux bundles record the build host's libc version; they depend on the target
system's shared libraries. They are not universal static Linux binaries. macOS
bundles are native Apple Silicon executables; no developer signing/notarization
is claimed. Relocation smoke validates this bounded installation surface,
not every optional provider, native hardware capability, or foreign target.

## Build and inspect a bundle

Use a clean committed source tree and the pinned toolchain. Build records keep
the source commit and clean state, exact rustc/cargo versions, native host and
target triple, command arguments and exit codes, logs, binary hashes and ELF/
Mach-O architecture, and actual execution results. If source changes during a
build, it cannot be packaged as the original clean commit.

```sh
python3 scripts/runtime_bundle.py build --output-dir dist/native-build
python3 scripts/runtime_bundle.py package --build-dir dist/native-build \
  --output dist/ostadix-runtime.zip
python3 scripts/runtime_bundle.py verify dist/ostadix-runtime.zip
```

`SOURCE.zip` uses the existing reviewed allowlist and includes its source
manifest and checksums. The bundle also contains identical unpacked source for
inspection and direct installation, `BUILD-MANIFEST.json`, `SMOKE.json`, both
retained build logs, and `BUNDLE-MANIFEST.json` covering all members. ZIP paths,
duplicates, non-regular files, total member size and file count are bounded.
Source and binary hashes are retained independently of package version labels.

Runner labels are pinned to the native ARM64 entries documented by
[GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):
`ubuntu-24.04-arm` and `macos-15`. Publication uses the documented
[artifact download](https://cli.github.com/manual/gh_run_download) and
[release upload](https://cli.github.com/manual/gh_release_upload) commands.
It never creates a release or overwrites an existing asset name.
