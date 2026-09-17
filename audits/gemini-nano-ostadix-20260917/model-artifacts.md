# Read-only model artifact inspection — 2026-09-17

## Implementation and scope

This was a bounded, read-only filesystem and model-metadata inspection. It did
not execute a model, request a download, change app state or permissions, inspect
credentials, extract key material, or attempt to bypass provisioning. Writing
this report was the only workspace change made by this inspection.

At inspection time the adjacent probe had observed **STABLE / FULL**, feature
636, as unavailable. That observation does not establish the status of every
documented ModelConfig combination. Other combinations are being investigated
separately; this artifact does not report their results.

The commands' outputs were returned in the agent tool transcript. A separate raw
stdout capture was **not** written at execution time. The tables below transcribe
those observed outputs; the reproduction methods are provided so the distinction
between a report and a separately retained raw capture remains explicit.

## Live observations: factory preload store

`/data/vendor/intelligence` contained **192 regular files**, totaling
**5,748,499,776 bytes**. `/proc/mounts` showed a read-only f2fs mount at that path
backed by `/dev/block/loop35`.

The installed vendor script `/vendor/bin/storage_intelligence.sh` contains the
comment `The script belongs to the feature of AI preload feature, go/gemini-package`
and names `/data/vendor/intelligence` as its mount point. The script was read,
**not run**.

The current AICore configuration included:

```text
AicModels__preloaded_data_directories=ChkvZGF0YS92ZW5kb3IvaW50ZWxsaWdlbmNl
AicModels__preloaded_data_files_enabled=true
AicOnDeviceIntelligence__preload_model_feature_id=234
```

These facts identify the directory as an official Gemini/AICore preload store.
They do not identify its exact Nano release or show that AICore has admitted,
initialized, or executed its contents.

### Metadata identities

| Exact file path | Bytes | SHA-256 |
|---|---:|---|
| `/data/vendor/intelligence/manifest.binarypb` | 61,440 | `bd045d18a0ac1ce8321d7fd8b58bc74c124dea489fe8ebf763cd92b6807e90e9` |
| `/data/vendor/intelligence/config.binarypb` | 8,192 | `78fca8e881cc79617362c28ff67bbb8d224c1e36440f851c5fc4aa971fa4eeca` |
| `/data/vendor/intelligence/checkpoint.binarypb` | 4,689,920 | `1ffa3a04bf9bf4d7d801c4a6bdc3b85eea1b62516bc424d1f15ee84138979e44` |

These hashes match the earlier Pixel AI audit. Their leading bytes were not a
TFLite header. This pass did not recover usable configuration or a feature
catalog from them. It did not independently repeat the earlier generic protobuf
decoding attempt.

### The store is only partially opaque

Reading bytes 4 through 7 of every regular file found **12 `TFL3` identifiers**.
The other 180 files did not have that identifier at that position; this check
alone does **not** classify those 180 files as encrypted.

The twelve exact paths with `TFL3` identifiers were:

```text
/data/vendor/intelligence/cross_layer_0-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_1-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_2-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_3-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_4-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_5-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_6-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_7-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_8-graph-custom_op.tflite
/data/vendor/intelligence/cross_layer_9-graph-custom_op.tflite
/data/vendor/intelligence/decode_softmax-graph-custom_op.tflite
/data/vendor/intelligence/image_encoder-graph-custom_op.tflite
```

The following three were also parsed as FlatBuffers and hashed:

| File in `/data/vendor/intelligence/` | Bytes | SHA-256 |
|---|---:|---|
| `cross_layer_0-graph-custom_op.tflite` | 122,470,720 | `d4accd72d0b4e94dedb3234e74e8cfafd3e4a88dfd8fb027bd0d8141e4893a95` |
| `decode_softmax-graph-custom_op.tflite` | 205,378,304 | `56cca22152fb05167690101d194092052bd6aa136d14f4364faea2b56685836d` |
| `image_encoder-graph-custom_op.tflite` | 196,892,864 | `68a1cb5b950be0f48ac8741c3c59d4c684d3ad38380cd89abad60ca62ae4fc64` |

All three had description `MLIR Converted.`, custom operation
`edgetpu-custom-op-2`, and metadata name `min_runtime_version`.

- `cross_layer_0` had ten subgraphs: `cross_layer_0_1x{128,1,32,4,8}_matformer_{0,1}`.
  Tensor names included attention outputs, query/key/value components,
  `positional_cos`, and `per_layer_embedding`.
- `decode_softmax` had six subgraphs:
  `decode_softmax_1x{1,4,8}_cluster_{0,1}`. Tensor names included activations and
  `darwinn_external_parameter_0` through `_3` (with suffixes in later subgraphs).
- `image_encoder` had one `main` subgraph with `vision_768_images:0`, external
  Darwinn parameter tensors, and `StatefulPartitionedCall:0`.

This establishes readable compiled components of a multimodal model payload.
The inspection did not establish an independently loadable complete model or
recover the missing initialization/configuration contract.

## Live observations: other app stores

A recursive filenames-and-sizes inspection covered these exact directories:

```text
/data/user/0/com.google.android.aicore
/data/user_de/0/com.google.android.aicore
/data/misc/aicore
/data/user/0/com.google.android.as/files
/data/user/0/com.google.android.as.oss/files
/data/user/0/com.google.android.apps.pixel.agent/files
/data/user/0/com.google.android.apps.pixel.psi/files
/data/user/0/com.google.android.googlequicksearchbox/files
```

For the AICore roots the filter printed files larger than 1,000,000 bytes or
ending in `.tflite`, `.litertlm`, `.task`, or `.gguf`. It printed no matching
files. `/data/misc/aicore` was absent. This filter is not proof that every
possible model representation was absent.

For the five other app `files` roots the filter printed files larger than
100,000,000 bytes and counted the same named-model suffixes:

| App `files` root | Files traversed | Named-model suffix matches | Observation |
|---|---:|---:|---|
| `com.google.android.as` | 288 | 24 | Speech/caption, OCR and prediction model filenames; no file over 100 MB |
| `com.google.android.as.oss` | 4 | 0 | No file over 100 MB |
| `com.google.android.apps.pixel.agent` | 358 | 11 | MDD model set described below |
| `com.google.android.apps.pixel.psi` | 6 | 0 | No file over 100 MB |
| `com.google.android.googlequicksearchbox` | 864 | 22 | Inspected examples were Lens OCR/layout/recognition files; no file over 100 MB |

Counts include separate directory entries for public MDD files and their links;
they must not be interpreted as unique model copies or physical storage use.
No user-document contents were opened.

### Pixel Agent candidate set

All model filenames in the following table are relative to this exact root:

```text
/data/user/0/com.google.android.apps.pixel.agent/files/datadownload/shared/links/public/pixelai-mdd-models_9b396311e2f08626acfbf6edf0f76e68303a627a5394f165ba8faf6bf7c6d179/
```

| File | Bytes | Observed model inputs/purpose indicators | SHA-256 |
|---|---:|---|---|
| `0002.tflite` | 40,194,464 | Word IDs, type IDs, mask | `87c27cf77d7a24b2aba24e833cc10f161a05e1384498ea7892f6b8f94246f971` |
| `0003.tflite` | 39,238,912 | Input IDs, segment IDs, masks | `5ca5b366d960ebb4775302f6f515b659c38a8a2cd6e92626cc1dfc6766603d47` |
| `0004.tflite` | 39,774,720 | Word IDs, type IDs, mask | `f38753281d380b059efcc21c1e3fb66d5fab720dd3d9c92f309f81fc7815a9a9` |
| `0009.tflite` | 281,870,272 | `serving_default_text_batch:0` | `c262989734d975f3029654d9e69bde10bb5d130c9bdce5a1661b0d7b32f3931b` |
| `0012.tflite` | 1,398,512 | Image input, box/class prediction outputs | `dc47b9fcbe168ed72c90661a58119c78ce85903bd789991c0ad827febb9388cc` |
| `0014.tflite` | 40,194,464 | Word IDs, type IDs, mask | `ca3987f0bb9aa085622b9376dfa109478beb5e2bab5e741a5c2355da2a89fd7e` |
| `0016.tflite` | 80,340,128 | `compute_logits_from_decoder_outputs_w_argmax_decoder_outputs:0` | `ee7a936afca33ef4e14a7847c5773baf28510906421ee975c4d7f9ccada65b47` |
| `0017.tflite` | 89,241,344 | Embedded encoder input and input tokens | `b24cd5af9f0e397752ad371f8a1bf2bb0d27b0cfbdf3a8eef11c32b412dfe80e` |
| `0018.tflite` | 60,322,976 | Decoder token/embedding inputs; cached key/value and index tensors for layers 0–5 | `bf1ee3171c3a2ab333b695cd93e663b93fe7ab2d7fdadfcaf13d4427cbb96eef` |
| `0019.tflite` | 3,934,584 | `compute_kv_cache` encoder/decoder input tokens | `08a2b3a54789eef7dd0060203af7943a9149058973c28d775f0cd008e1012fc9` |
| `0020.tflite` | 76,929,480 | `decoder_embed` and `encoder_embed` subgraphs | `c38517cc6fd34da0bb088f090544e0c36066db39698749675a313e12a00e6447` |

All eleven were parsed for FlatBuffer description, custom operation names,
metadata names, subgraph names, and input/output tensor names. None of the
inspected metadata named Gemini Nano or supplied an AICore feature mapping.

The same public model directory contained small static label files. Only `.txt`
files smaller than 1,000 bytes were read:

- `0005.txt`: `O`, `B-KEYWORD`, `I-KEYWORD`, `B-DATETIME`, `I-DATETIME`.
- `0022.txt`: document/entity categories including contacts, flights,
  identity documents and loyalty cards.
- `0024.txt`: document/entity categories including articles, contacts,
  receipts, recipes and media.
- `0025.txt`: `Retrieval`, `Unknown`, `OOS`, `Sensitive`.

These are model label names, not observed user information. The tensor names
and labels support feature-specific encoder/classifier/detector and
encoder-decoder interpretations. They do not identify the encoder-decoder as
Nano. No inference was attempted with these assets.

## Existing loader evidence checked

The earlier provisioning analysis is preserved in
[OSTADIX-AICORE-INTEGRATION.md](../pixel-ai-20260915/OSTADIX-AICORE-INTEGRATION.md),
under “Provisioning cause and factory payload.” This inspection read that
analysis and selected existing decompilation at:

```text
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/com/google/android/apps/aicore/app/preload/PreloadModelWorker.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/bni.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/bwn.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/bsf.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/bst.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/bss.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/can.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/caj.java
/data/local/tmp/ostadix-ai-audit-20260915/aicore-jadx/sources/p000/cak.java
```

`bni` obtains the configured preload feature through AICore before preparing it.
`can` explicitly expects `preloadedfile:sha1:<checksum>` and resolves it through
the preloaded file map. Existing `bwn` decompilation has control-flow warnings;
its reconstructed branch conditions are not treated as independently verified
bytecode truth. No new supported catalog-independent loading entry point was
identified.

## Read-only methods and reproduction

The inspection used Python `pathlib`, `os.walk`, `stat`, `hashlib.sha256`,
`mmap.ACCESS_READ`, and `struct.unpack_from`, plus these targeted commands:

```bash
cat /vendor/bin/storage_intelligence.sh
/system/bin/device_config list aicore | /data/data/com.termux/files/usr/bin/rg 'preloaded|preload|base_model'
/data/data/com.termux/files/usr/bin/rg -n 'intelligence' /proc/mounts
```

Factory inventory/header counts and the six hashes above can be reproduced
without modifying the device:

```python
from pathlib import Path
from collections import Counter
import hashlib

root = Path('/data/vendor/intelligence')
files = sorted(p for p in root.iterdir() if p.is_file())
print(len(files), sum(p.stat().st_size for p in files))
counts = Counter()
for path in files:
    with path.open('rb') as stream:
        header = stream.read(16)
    counts['TFL3' if header[4:8] == b'TFL3' else 'other'] += 1
    if header[4:8] == b'TFL3':
        print(path, path.stat().st_size)
print(counts)
for name in ('manifest.binarypb', 'config.binarypb', 'checkpoint.binarypb',
             'cross_layer_0-graph-custom_op.tflite',
             'decode_softmax-graph-custom_op.tflite',
             'image_encoder-graph-custom_op.tflite'):
    path = root / name
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    print(path, path.stat().st_size, digest.hexdigest())
```

The FlatBuffer inspection used the little-endian root offset and table vtables,
then read these standard TFLite schema fields by index:

| Table | Fields inspected |
|---|---|
| Model | 1 operator codes, 2 subgraphs, 3 description, 6 metadata |
| OperatorCode | 1 custom code |
| Metadata | 0 name |
| SubGraph | 0 tensors, 1 inputs, 2 outputs, 4 name |
| Tensor | 3 name |

Strings and vectors were read through their relative offsets. Input/output
integer vectors indexed the subgraph's tensor vector. Factory inspection
reported up to twelve tensor names per subgraph; Pixel Agent inspection reported
input/output tensor names and up to three subgraphs. This was a metadata parser,
not a complete model validator or model execution.

## Unverified claims and limits

- No exact Nano release identity or feature-636-to-file mapping was recovered.
- No complete independently usable Nano bundle, plaintext feature catalog, or
  supported local bootstrap was demonstrated.
- A valid TFLite header and readable metadata do not prove every component or
  parameter needed for inference is available and usable.
- Files without a `TFL3` header were not all classified as encrypted.
- The Pixel Agent encoder-decoder assets were not identified as Nano.
- These directory scans do not establish that there are zero models globally,
  or that every possible storage location and representation was inspected.
- No supported next step using these artifacts alone was found that resolves
  the previously observed AICore catalog/provisioning barrier. This is an
  inspection result, not proof that no such mechanism can exist.
