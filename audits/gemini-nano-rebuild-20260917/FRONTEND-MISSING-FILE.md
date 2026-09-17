# Missing audio frontend graph

## Implementation evidence

The recovered factory manifest has 192 payload records, 191 of which were
available and subsequently verified. None names `frontend.tflite`; the known
missing manifest entry is `dvfs_manager_params.binarypb`, a different file.
The decoded configuration contains audio settings under variant-3 field 6,
including field 6.10 `audio_adapter-graph-custom_op.tflite`. It contains no
literal `frontend.tflite` reference.

An exact ZIP-directory inspection found no frontend, audio, or `.tflite` asset
in any of the five installed AICore APKs or the factory AICore APK. Searching
the complete available AICore Java decompilation found no `frontend` reference.
These checks do not support a claim that stock Java copies a bundled frontend
asset into this model directory.

The native code does implement an audio-disabled configuration path. The
`GemConfigV2Plus` serializer at `0x2df5490` reads presence bits at object
offset `0x10`; bit 6 controls its audio submessage at offset `0x60`, emitted
as wire field 6 at `0x2df557c`. The resource builder tests the same bit at
`0x2dfda88`: absence constructs `NoAudioEncoder`, while presence enters the
audio loader. Thus omitting variant-3 field 6 is a precise configuration
change corresponding to a compiled native branch. It would create a derived
configuration, not retain the factory configuration's manifest hash.

## Live observations

Request `local-model-reclaimed-20260917-1714`, PID 7088, UID 10173, progressed
through native model loading and recorded successful offline-compiled TPU
graph loads. It then returned `NOT_FOUND` for the factory model prefix followed
by `/frontend.tflite`. Its native source trace identifies
`v3/multi_modal/audio_encoder.cc` lines 62, 123, and 337, followed by
`model_loading_utils.cc:649`. This establishes the missing resource arose in
the native audio loader. It does not establish complete model initialization
or inference.

## Unverified claims

No exact compatible replacement frontend graph has been established by this
asset search. The discovered audio-disabled branch has not been exercised by
this investigation; its static existence does not prove the resulting model
will initialize or generate text. The absence of a manifest entry is not
proof that this runtime/model version pair is otherwise complete. Substituting
an unrelated frontend graph would not be a verified repair.

## Evidence

- `frontend-apk-asset-search.json`
- `aicore-model-reclaimed-memory.logcat`, especially lines 59–72
- `manifest-decoded-metadata.json`
- `decoded-bundle-structure.json`
- `modality-loader-xrefs.json`
- `audio-config-field-disassembly.txt`
