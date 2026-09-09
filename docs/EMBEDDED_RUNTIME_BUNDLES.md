# Embedded foreign runtime bundles

`olangc --runtime-bundle DIR` embeds the regular files of an explicitly supplied
relocatable runtime tree in an ordinary native `.O` binary. The tree contains
`bin/` and this manifest:

```json
{
  "schema": "ostadix.embedded-runtime/v1",
  "environment": {
    "PYTHONHOME": "${BUNDLE}/python"
  }
}
```

The environment map is optional. Use `bin/python3`, `bin/node`, or the relevant
catalog command names. Include runtime libraries, standard libraries, helper
executables, and licenses in the tree. Internal file symlinks are retained so
invocation aliases and self-relative executable locations survive extraction.
Relative targets retain their spelling; absolute internal targets are rewritten
relative to the extracted link. Targets must remain inside the bundle. External
symlinks, directory symlinks, and special files are rejected. Empty directories,
UTF-8 paths, and Unix permissions are retained. Environment
entries support the listed Python, Node, Ruby, Java, .NET and dynamic-library
path keys; each value must name an existing path within `${BUNDLE}/`.

```bash
olangc program.O -o program --runtime-bundle ./runtime-tree
olangc program.O -o program --runtime-bundle ./runtime-tree \
  --materialize-only ./generated
```

The generated project includes `runtime-bundle-manifest.json` with path, byte
length, mode, and SHA-256 for each file, plus directory paths/modes and symlink
paths/targets. Startup checks the embedded digests,
extracts to a private randomly named temporary directory, and sets runtime
command lookup to its `bin/` exclusively before evidence/admission. Missing
commands therefore cannot be satisfied by ambient `PATH`. The extraction
remains alive during execution and is removed on normal scope exit, restoring
owner access to read-only directories during cleanup without following symlinks. Process
abort can leave its private directory behind.

This is runtime payload embedding and closed command lookup. It does not
automatically discover or verify a complete dynamic library closure, replace
the host kernel, isolate arbitrary absolute file access or environment reads,
or embed external daemons/services. Clean-environment execution must qualify
each supplied closure. In particular, this feature alone cannot establish
hermetic embedding of every catalog runtime, including Mathematica, Multipass,
or Nix services. Native project binaries and WASI targets are not supported by
this option.
