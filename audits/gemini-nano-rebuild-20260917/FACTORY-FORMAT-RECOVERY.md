# Factory model format and recovered metadata — 2026-09-17

**Superseding observation, 2026-09-17 17:35–17:36 UTC:** all 191 available
payloads were verified and staged as AICore-readable regular files. With an
explicitly derived config omitting only audio field 3/6, genuine AICore loaded
the model, counted tokens and then generated text. The standalone caller's
authorization failure and pending-load assessment below are historical.
See [current implementation, live results and limits](STATUS.md). Public Nano
identity and the ordinary assistant-to-Ostadix chain remain unverified.

## Implementation

Three original Python tools were added in this directory:

- `inspect_factory_format.py`: read-only size/header inventory and selected
  installed Java/native loader evidence. It does not invoke the HAL or model.
- `decode_factory_metadata.py`: bounded wire decoder for the installed Java
  metadata types `edd` (preload manifest) and `hid` (partial Edge TPU config).
  Field numbers/types come from the installed GeneratedMessageLite metadata.
  Unknown byte fields are retained only as lengths/hashes.
- `inspect_decoded_factory_bundle.py`: examines already decoded config and
  checkpoint metadata, checks manifest consistency and external parameter
  ranges. It does not export tokenizer pieces or model weights.

The team's separate `FactoryReader` used the **installed** Trusty service.
This work neither rebuilds Google's model weights nor replaces AICore. Raw
decoded metadata remains under `/data/local/tmp/ostadix-nano-rebuild-20260917`,
outside the repository. This directory contains structural observations and
original inspection code, not proprietary model payload copies.

## Live observations

### The byte format follows a concrete installed loader contract

Installed AICore's `cat.m2397b(File)` chooses a direct file stream at file size
**104,857,600 bytes or above**. Smaller files go through
`vendor.google.plat_security.ITrustyDecrypt/default`. The `ivv` proxy passes
input and output file descriptors with Binder transaction 1. After success,
the Java loader reads a little-endian 32-bit logical size at the output buffer's
end minus 4,100, validates it, then limits the returned stream to that size.

`buu` case 1 calls that loader for the manifest and only then parses `edd`.
`bsk` uses its file groups to form the preload SHA-1 map. `can` resolves
`preloadedfile:sha1:` references and uses the same loader for payloads.
`btn` later reads decoded `config.binarypb` as `hid`.

The observed factory inventory matches this size rule exactly:

| Size branch | Files | Observation |
|---|---:|---|
| Direct, >= 100 MiB | 12 | All have the `TFL3` identifier |
| Direct, >= 100 MiB | 1 | `data0`, structured external parameter data |
| Trusty, < 100 MiB | 179 | No `TFL3` header before transformation |

Thus absence of a TFL3 identifier or high byte entropy was unnecessary for
inferring the transformation. The installed loader, followed by successful
service calls, now supplies direct evidence.

The live service registry included the Trusty decrypt service. Its installed
native executable references the local `com.android.trusty.ml_prot` endpoint.
The caller contract contains two file descriptors; no supplied encryption key
is part of this Java call. This does not describe the secure world's internal
key management.

### Stock local service decoded the three metadata files

The team's actual service calls returned status 0. The retained command
records are `factory-manifest-reader-run.json` and
`factory-config-checkpoint-reader-runs.json`. This inspection independently
parsed and hashed their output files.

| File | Encoded bytes | Decoded bytes | Decoded SHA-256 |
|---|---:|---:|---|
| manifest.binarypb | 61,440 | 54,756 | `428c1fe30aa4483ef790e1029f48a0b231f566efc09aeba3998affc4bd0a2749` |
| config.binarypb | 8,192 | 1,703 | `2579a3a81a1c22403cf4f930581d85e743b9b33e7340ac917508b6419f1ef54e` |
| checkpoint.binarypb | 4,689,920 | 4,683,648 | `50f79aa10d36bf5f9d81e9dcec1d0aeef83ffeaea8662c7d9b5b17cc87c80291` |

The decoded config and checkpoint **both match their manifest SHA-1 and byte
size**, beyond merely resembling valid protobufs. All 192 manifest file
records have no compression marker under the installed loader's test.

### Recovered manifest

The single group is **`feature_234`**, build **10745**. It has 192 file records,
all under the literal model prefix:

`edgetpu_gem3_it_final_20250505_opt_with_audio_20250525_buenos_dvfs`

Of those records, **191 mapped payload filenames exist** in the factory store.
The one missing mapped file is `dvfs_manager_params.binarypb`, with expected
decoded size 3,364 and SHA-1 `bfd24cec8734ca9ed8ebd2ad81b36b3ff2f9d694`.
The store's own manifest is the additional physical file, explaining the
192-file physical inventory. Whether the missing DVFS file is required for the
chosen load configuration is not established by this metadata inspection.

The recovered group contains a name, files and build ID. It does **not** itself
provide feature 636/645/646/647 API definitions or a demonstrated mapping from
those Prompt API features to a usable model session.

The subsequent materialization run decoded all 178 available smaller payloads
through the stock service and linked the 13 directly readable factory files.
**All 191 available payloads passed the manifest's SHA-1 and size checks.**
`materialization.jsonl` retains each verification and the final missing-file
list. The missing DVFS LUT has a concrete installed native fallback described
in [DVFS-MISSING-FILE.md](DVFS-MISSING-FILE.md); its absence is not yet a proven
mandatory model-load failure.

### Checkpoint and raw external parameters

Checkpoint field 3 explicitly names `data0`. Its four parameter records cover
that existing file contiguously and exactly:

| Tensor name suffix | Offset | Bytes |
|---|---:|---:|
| `lm.softmax.logits_ffn.linear.w` | 0 | 301,989,888 |
| `transformer.embedder.per_layer_embeddings.w` | 301,989,888 | 1,321,205,760 |
| `lm.embedding_lookup.extra_emb_var` | 1,623,195,648 | 8,192 |
| `lm.embedding_lookup.audio_extra_emb_var` | 1,623,203,840 | 8,192 |

The final endpoint is **1,623,212,032**, exactly the disk size of `data0`.
That is direct structural evidence against treating this file as another
opaque encrypted artifact. It does not independently verify every weight.

The first 1 MiB of `data0` has a strong 18-byte structure: all 58,254 sampled
block starts decode as finite positive FP16 values <= 0.1. The native runtime
contains `q4_0`, `sizeof(block_q4_0)`, `aicore.GgmlCheckpoint`, and checkpoint
parsing references. These observations support a quantized weight
interpretation; a full numeric tensor decoder has not been run.

Checkpoint field 2 contains 262,144 repeated field-1 messages and one each of
fields 2 and 3. This structure, the matching 262,144 config value and installed
SentencePiece code support an embedded tokenizer interpretation. Tokenizer
pieces were neither printed nor copied into the audit.

The decoded config selects wire variant 3 and names `matformer_0` and
`matformer_1`. Its context configurations reach 32,768. Structural config and
checkpoint metadata are in `decoded-bundle-structure.json`; unknown numeric
field meanings remain field-numbered instead of being invented.

## Unverified claims and revised assessment

- **The earlier blanket conclusion that no local metadata bootstrap could be
  recovered without a server manifest is disproven.** The stock local loader
  successfully transformed and parsed the factory manifest/config/checkpoint.
- This does not show that Google's server provisioning rejection changed.
  The direct local service path and remote catalog admission are distinct.
- A subsequent local model load reached `CreateModelFromCheckpoint` and the
  v3 Edge TPU executor, then failed at opening the TPU device through its
  service. The original runtime hid the underlying Binder service error as
  `errno=Unknown error -8`; a separate diagnostic recovered service code **16**,
  denying UID 10402 access. Read-only authorization checks also returned false
  for actual UID 0. This establishes a caller authorization failure, not a
  successful model load or inference. See `local-model-load-readonly.stderr`
  and the separate Edge TPU diagnostic records.
- The exact public Nano release/version is not established solely by the
  literal factory prefix, architecture dimensions, or `feature_234` name.
- All available compiled graph payloads have now been decoded/linked and
  checked against the manifest. Successful initialization of this precise
  bundle in a service-authorized app context remains unverified. The DVFS
  fallback is statically established; its behavior in that live load remains
  a separate observation.
- Ordinary Pixel assistant -> Nano -> Ostadix -> assistant response remains
  unproven by these filesystem/format results.

The concrete next step is a controlled native load in the genuine installed
AICore process, preserving its existing package identity and service access
rules, then recording load success/failure before attempting inference.
Replacing or relabeling another model as Nano would not establish the
requested result.
