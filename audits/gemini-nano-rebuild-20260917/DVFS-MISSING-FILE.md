# Missing DVFS metadata — bounded investigation

## Implementation

No DVFS policy, frequency setting, thermal setting or system file was created
or changed. The investigation read filenames, file sizes, APK directory
entries, the installed Java decompilation and installed native code.

## Live observations

The recovered manifest expects `dvfs_manager_params.binarypb`, decoded size
3,364, SHA-1 `bfd24cec8734ca9ed8ebd2ad81b36b3ff2f9d694`.

The bounded search inspected 7,988 unique regular files across `/vendor`,
`/product`, `/system` and `/system_ext`. It found no filename containing `dvfs`
and no file with exactly the expected decoded size. It also inspected all five
installed AICore APKs and the factory AICore APK: no entry had a DVFS filename
or the expected size. The scan encountered no filesystem errors. It did not
search unrelated private app data, arbitrary embedded subranges or the whole
device. Raw scope/results: `dvfs-file-search.json`.

The installed Java search found DVFS performance requirement translation, not
a demonstrated generator for this missing file.

## Static implementation evidence

The installed `libgoogle3.so` contains a specific v3 fallback message stating
that failure to load DVFS params skips the manager and uses maximum TPU and
memory voting power states. It also contains v2/v4 equivalents,
`DefaultDvfsManager`, and a Gen2-to-Gen1 fallback.

The ARM64 references put the v3 filename and fallback in the same function:

- `0x2e9c9a8`: reference to `dvfs_manager_params.binarypb`, followed by a
  virtual model-file read.
- `0x2e9ca04`: read status branch to `0x2e9cb78` on the non-success path.
- That path rejoins cleanup and the common status test at `0x2e9ca88`.
- `0x2e9caf0`: fallback branch; `0x2e9cb08` references the explicit skip/default
  message. It constructs a result and rejoins the ordinary return path.

This supports a built-in fallback in the installed native code. The symbol
table is stripped; `llvm-objdump` labels the region relative to a distant JNI
export, which is not evidence that the surrounding function has that JNI name.

Artifacts: `dvfs-native-evidence.json`, `dvfs-native-xrefs.json`, and
`dvfs-loader-fallback-disassembly.txt`.

## Unverified

This is not yet a live observation that the selected model load reaches or
successfully completes the fallback. A native load trace must establish that.
The fallback's maximum voting states are the stock implementation's behavior;
no replacement performance policy has been proposed or synthesized.

No canonical local copy of the missing LUT was found within the stated scope.
The installed fallback provides a concrete next path to test before treating
this missing file as a mandatory blocker.
