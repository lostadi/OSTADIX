# Ordinary Gemini assistant boundaries — 2026-09-17

This bounded review identifies concrete installed-code submission and rendering
methods. It does **not** establish a working ordinary-assistant-to-local-model
adapter. Fresh assistant-turn creation, publication, cancellation and verified
suppression of online dispatch remain missing.

## Implementation inspected

No hook, adapter or application change was implemented by this review. Existing
decompilation was inspected, and selected classes from already extracted DEX
files were decompiled under `/data/local/tmp/ostadix-gsa-nano-dex/`. No proprietary
source or model payload was copied into the repository.

The class names below are the actual DEX names. Jadx's `defpackage.` prefix is
synthetic and must not be included in a runtime `Class.forName` target.

### Query submission

The recovered path is:

```text
bfaw.m(j$.time.Duration, boolean)
  -> bjka.j(CharSequence, boolean, gasx, askv, Duration,
            boolean, String, Duration, boolean, aude)
  -> bjka.p(...) builds auja
  -> atla.a(ChatControllerId, auja, asgm)
  -> implementation atma.a(...)
  -> atma.c(...)
  -> asws.b(auja, asgm)
```

`bfaw` has synchronous and coroutine send branches; this is not a claim that
every flag configuration follows an identical immediate call sequence.
`bjka` labels the final dispatch `conversationController.sendMessage`.
`auja.a` is the query's `String` text, explicitly identified by its
`MessageInput(text=...)` representation. It is an ordinary Java field, not an
established network protobuf field number.

The concrete hook candidate is the public method:

```text
Latma;->a(Lcom/google/android/apps/search/assistant/surfaces/voice/robin/data/ChatControllerId;Lauja;Lasgm;)V
```

`atma.c` resolves per-chat state with `this.h.i(chatControllerId).a`, then obtains
an `asws` controller and invokes its `b` method. `asws.b` normalizes the send mode,
commits an existing matching-chat job through `aswr` when applicable, or calls
`asut.b(auja, asgm)`. It exposes no recovered local-response argument or reply
callback. Suppressing `atma.a` has not been shown to leave a correctly created
user turn, loading state or cancellable local operation.

### Conversation state and response content

| Object / field | Meaning established from inspected code |
|---|---|
| `aszg.a` | `ChatControllerId` |
| `aszg.n` | Mutable `heed` state containing an `aszq` conversation snapshot |
| `aszq.c` | List of `aszl` turn records |
| `aszl.a`, `aszl.b` | User `atab` and assistant `ataa` objects respectively |
| `ataa.c` | Original `auja` query input |
| `ataa.d` | `auds` response content; its `.a` field is the block list |
| `aufs.b` | Text of a response text block |
| `ataa.i` | `audq` request state; `audq.c` is declared `DONE` |

`aszq.m(aude, Function1, Function1, Function1): aszq` transforms the response
content, shareable content and TTS content of an **existing matching assistant
message**. Its initial identity check can return the snapshot unchanged. It is
not a recovered fresh-reply append API, and returning a new snapshot is not
itself proof that the correct store published it.

`audu`, named `SendMessageResponse` in its representation, carries identifiers,
interaction status and an error. It does not carry the displayed answer text.

### Display boundary

The exact text-block renderer is:

```text
Lbiso;->A(Laufs;ZLgbhu;Lbijo;)V
```

The method reads `aufs.b`, builds a `SpannableStringBuilder`, then calls
`this.z.setText(..., TextView.BufferType.SPANNABLE)`. Its constructor obtains
that `TextView` using resource ID `2131432275`. This establishes a rendering
boundary, not a completed-response callback or a safe place to create a new
conversation turn. The method's boolean and `bijo` arguments were not mapped
to a proven final-response condition in this review.

### Source proof locations

The following files remain local analysis artifacts outside Git:

- [bfaw-simple.java:1038](/data/local/tmp/ostadix-gsa-nano-dex/bfaw-simple.java:1038): send branches and text extraction.
- [bjka.java:395](/data/local/tmp/ostadix-gsa-nano-dex/bjka.java:395): message construction and conversation-controller dispatch.
- [atma.java:51](/data/local/tmp/ostadix-gsa-nano-dex/atma.java:51): concrete submission implementation; `c` begins at line 79.
- [asws.java:53](/data/local/tmp/ostadix-gsa-nano-dex/asws.java:53): commit/send behavior.
- [auja.java:441](/data/local/tmp/gsa-classes2-jadx-full/sources/defpackage/auja.java:441): text field identification.
- [aszg.java:8](/data/local/tmp/gsa-classes2-jadx-full/sources/defpackage/aszg.java:8): chat identity and state ownership.
- [ataa.java:275](/data/local/tmp/gsa-classes2-jadx-full/sources/defpackage/ataa.java:275): assistant-message field meanings.
- [aszq.java:590](/data/local/tmp/gsa-classes2-jadx-full/sources/defpackage/aszq.java:590): existing-message content transformation.
- [audq.java:18](/data/local/tmp/ostadix-ai-audit-20260915/lang-paths/googleapp/jadx-base/sources/defpackage/audq.java:18): declared `DONE` state.
- [biso-simple.java:1208](/data/local/tmp/ostadix-gsa-nano-dex/biso-simple.java:1208): renderer; actual `setText` call is at line 1408.

## Live observations

This review made file comparisons only. It did not type or send a query,
install a hook, execute inference, contact a cloud endpoint or observe these
methods handling a live ordinary assistant request.

The earlier [routing audit](../gemini-nano-ostadix-20260917/assistant-route-findings.md)
records the base APK SHA-256
`c227beb9468f1740c395e457d5f06fb780f288a89156d8487ef069953c1c359a`.
This review compared the two focused extracted DEX files byte-for-byte with
members of that installed APK at:

```text
/data/app/~~9fZb6Q9HYF7DNY7pMFubGQ==/com.google.android.googlequicksearchbox-iPBfzurbJ98pcm3Op8ZjXQ==/base.apk
```

| APK member | Exact match | SHA-256 |
|---|---|---|
| `classes12.dex` | yes | `ae2af0120562130a1610228055e06889703808235ae147eac177b5a84fdfaa4b` |
| `classes13.dex` | yes | `ac21007ab74e82cb9937eda153b7d3d99fa3a2cfc331d36cac570a40c94fa6eb` |

Separately, controlled local-model tests now record model-generated Python,
Rust and Bash `.O` execution returning **26**, after two model repairs and
deterministic removal of an outer Markdown wrapper. The model subsequently
consumed the actual result and returned the correct shipment summary. See
[MCP execution evidence](nano-program-mcp-result.json),
[result-consumption events](canonical-nano-result.stdout) and
[result-consumption run](canonical-nano-result.json). Those harness-controlled
tests do not establish that the ordinary Gemini submission and display paths
identified here participated in that tool cycle.

## Unverified claims and required connection

- Live reachability of these methods from the user's ordinary assistant
  invocation, including active flag branches and request correlation.
- Construction of a fresh, correctly identified user/assistant turn when
  original submission is suppressed, with preservation of existing history.
- Publication of generated content through the correct per-chat state owner,
  completion transition, persistence and downstream display consumers.
- Cancellation and failure handling covering the local model, Ostadix request
  and conversation state, without duplicate dispatch or stale replies.
- Suppression of every online-dispatch path for that same request. No code
  change or observation here demonstrates that property.
- Exact public Gemini Nano model identity and an ordinary assistant interaction
  completing the local-model/Ostadix/result-consumption chain.

The renderer alone does not close these gaps. No complete local-reply
construction/publication contract was recovered in this bounded review.
