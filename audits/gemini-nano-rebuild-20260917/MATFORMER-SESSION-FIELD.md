# Session matformer selection

## Implementation evidence

The installed Java schema maps `cfe.f5690e` to protobuf field **9**, a string
whose default is empty. Stock `cjj` copies `hfw.f18292B` into that field only
when the feature configuration's corresponding presence bit is set.

The installed native binary confirms that this field is the session's
`matformer_signature`; this conclusion is supported by matching object offsets
and serializer field numbers:

- `nativeCreateSession` at `0x3860228` parses a message initialized by
  `0x301e208`. Its string member at offset `0x30` is serialized by
  `0x301e684` using field number 9.
- The native session constructor copies the same protobuf using `0x2d735cc`
  into session offset `0x88` (`0x2d733b8` advances the pointer by `0x70`, then
  `0x2d733bc` adds `0x18`). The destructor also destroys this protobuf at
  offset `0x88` using `0x301e290`.
- The assertion at `0x2d79634` reads session offset `0xb8`, equal to
  `0x88 + 0x30`, and compares it under the literal diagnostic
  `state.matformer_signature() == session_config_.matformer_signature()`.

The decoded factory variant-3 configuration contains exactly two field-13
strings: `matformer_0` and `matformer_1`. Field-17 records also name those two
signatures. Thus these are configuration-declared choices, rather than names
invented from another model's documentation.

## Live observations

The configuration was recovered using the installed Trusty service and its
decoded bytes match the factory manifest's expected size and SHA-1. This
signature investigation invoked no model-loading or generation operation.

## Unverified claims

Neither an omitted field 9 nor either explicit signature has been demonstrated
in a successfully created session against this factory model. Empty is the
protobuf default; it is not proven to mean `matformer_0` at runtime. The
presence of those two factory choices does not establish their memory costs,
quality differences, or public Gemini Nano identity.

## Evidence

- `matformer-session-field-disassembly.txt`
- `matformer-native-xrefs.json`, produced by `inspect_matformer_xrefs.py`
- `decoded-bundle-structure.json`
- Installed decompiled Java `cfe`, `cjj`, `bum`, and `hfw` in the earlier
  AICore audit directory
