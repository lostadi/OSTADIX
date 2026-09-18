# Local assistant: validation, availability and visible result history

Date: 2026-09-18. Repository: `lostadi/OSTADIX`.
See [daily use and repeatable deployment](../../apps/aicore-ostadix-extension/ASSISTANT-USE.md).

## Implementation

- The owned extension now has an **Ostadix Results** launcher activity with
  durable private history, actual output, original request, source/evidence
  details and copy controls. A notification opens the corresponding record.
  No Google cloud conversation identifiers are invented.
- A write-only content provider checks the Google caller's UID/package,
  installed version, APK hash and signer. External read/query/update/delete
  APIs are denied. The activity reads its own private files.
- The hook saves a pending record before generation, the actual native result
  before interpretation, and a terminal answer/error record. Successful native
  output can survive a subsequent explanation/delivery failure. History save
  failures are reported when an answer can still be delivered.
- `local-all-v1` selects ordinary nonempty text turns without a special prefix.
  `local-o-v1` retains the earlier prefix selection. Existing activation,
  compatibility and thermal gates still apply.
- The host checks Nano's complete source through primary MCP `o_execute`
  `action: check`. A confirmed parse rejection, or absence of an executable
  language block marker after parse success, can cause one model correction
  and another check. The source-contract check is a negative marker check, not
  a parser or proof of semantic correctness. Actual execution dispatch remains
  at most once. Transport failures, cancellation and runtime errors are not
  automatically retried. The host retains credentials, deadlines and placement.
- Actual OValue output and its result identity are formatted by the host.
  Nano receives the actual result for explanation; that explanation is labeled
  not independently verified. UTF-8 OText values are decoded for display.
- The service supervisor launches the HTTPS host as Termux UID 10402 and
  restarts it after exit without replaying requests. A root-owned KernelSU boot
  entry waits for unlocked configuration. Deployment and history recovery are
  in tracked scripts. Existing credentials are preserved.
- ASI's bounded replacement seam and its original-method delegation are
  unchanged. Google's Nano weights and AICore native binaries were not rebuilt.

## Live observations

### Reported failure and source checks

`reported-failure.json` records the reported unclosed final Python block.
`rejected-program.O` is the exact invalid generated document. Nano had also
generated sum rather than sum-of-squares logic in that example. Correct syntax
alone therefore would not have established the requested computation.

`parse-boundary-regression.json` records real native checks over pinned HTTPS:
a valid program with a marker-file effect did not create the marker during
check; invalid source was rejected during check; one subsequent execute created
exactly one marker and returned 2. The test marker was removed afterward.

### Heterogeneous execution without a prefix (v12)

`live-input.json` distinguishes intended input, actual GSA-received input and
Codex UI actions. The received input had a trailing comma. Codex invoked the
ordinary assistant, typed and tapped Send; this was not a user-sent test.

`live-turn.json`, `generated-program.O` and `live-native.events.jsonl` record
local Nano generation, native Python/Rust/Bash execution, and local Nano result
consumption. The actual result was **276 = 174 + 100 + 2**. Native execution
took **1209 ms**; the recorded turn to `answer_ready` took **48937 ms**.
There were two MCP calls (check, execute), one actual execution dispatch and
zero correction attempts. Both Nano requests reached cleanup completion.

Result identity:
`3f6a2137568075a5f63bfdf0591651b856a003ec9a044f29d04bee0927acb657`.
This is a content identity, not a signed Google attestation.

### History, notifications and model errors (v13/v14)

`install-v13.json` records recovery of **12 earlier records**, without model or
program execution. The actual 276 output was visually observed in the installed
viewer. `history-recovery.json` retains a screenshot hash; private screenshots
and unrelated recovered prompts were not added to the repository.

An ordinary prefix-free request asking for seventeen plus twenty five created
a new record automatically. `history-live-record.json` and
`history-notification.json` establish a terminal record and posted notification.
However, Nano duplicated the arithmetic in Python and Rust and added the two
values, yielding actual **84**. This proves history delivery, not correctness
of the requested calculation. The erroneous program/output are preserved.

After changing generation guidance, v14 returned fenced bare Python. Native O
accepted it as text and returned that text; Nano then claimed 42 in its
explanation without a numeric tool result. `history-v14-turn.json` preserves
this negative observation. Version 15 therefore adds the missing-executable
marker rejection and explicitly labels explanations unverified. Neither failed
semantic test was concealed or rewritten as successful numeric execution.

### Corrected program and saved answer (v15)

The same ordinary request was submitted as a fresh Codex UI test after the
source-contract change. `history-v15-turn.json` records bare Python being
rejected by the contract after a successful native parse check. Nano's one
correction returned this complete document:

```text
python^(a, b = 17, 25; __oval_result__ = a + b)_python
```

The corrected source passed validation and executed once, returning actual
**42**. There were **3 MCP calls**, **1 correction**, and **1 execution dispatch**.
Native execution took **212 ms**; the recorded turn took **32530 ms**.
`history-v15-record.json` has the identical final answer;
`history-v15-observation.json` records that match and the posted notification.
Result identity: `f8f7d9a5c91ed45766da3e1021a41f7ab04442d0e4b72756bbe047fa5b7c7967`.

The installed v15 APK hash is
`00b76088ad41816821455529e979adf60112739ec63c85862ba300d0a109f763`.
This observed correction demonstrates the bounded recovery path; it does not
establish general semantic correctness. The v13/v14 negative cases above remain
part of the evidence.

### Service availability

`service-recovery.json` records successful boot-entry invocation while already
unlocked, a deliberately killed idle host being relaunched after **2425 ms**,
and a fresh request returning 2 afterward. Repeated start retained the same
running host. This did not interrupt an active execution or replay a request.

### Checks

- Six focused Python host tests passed, including source preservation,
  parse-only forwarding, input rejection and deadline cancellation without retry.
- The six-stage extension builds passed through v15, including signature,
  pinned native closure and package policy verification.
- Existing result-replacement and ASI delegation self-tests passed.
- Source preparation tests covered valid input, one correction, remaining
  rejection, transport failure, cancellation boundaries, default selection and
  the observed bare-Python contract failure.
- JVM tests with pinned real `org.json` checked numeric/text output, identity,
  long output, failure streams, durable record roundtrip and missing-explanation
  recovery. These are JVM tests; they are not mislabeled Android instrumentation.
- The installed viewer and successful GSA-to-provider writes were observed on
  Android. An attempted unauthorized-writer check using the Android `content`
  CLI did not execute successfully in this shell; rejection of that caller is
  therefore a code-level property here, not a claimed live test result.
- After integrating the newer upstream source changes, language-source
  manifest validation passed for 232 files and all 88 registered HTML exports
  matched. The full parse sweep could not start because `target/release/ocorec`
  is absent. The focused native O parse/execution observations above are separate.
- A fresh service check after integration returned actual 2 with execution
  evidence (`final-service-check.json`), and all six host tests still passed.

## Unverified claims and limits

- Stock Gemini cloud chat-history persistence is not fixed by this change.
  **Ostadix Results** is the reliable place to revisit saved local records.
- “Always works for anything” is not established. The recorded Nano semantic
  failures directly disprove a universal correctness claim. Parse success is
  not intent validation, and an execution identity is not an answer-quality proof.
- A physical reboot with this newly installed supervisor, notifications after
  reboot, process death during a write, voice/Live/attachment routes and Google
  APK or firmware updates have not been exercised in this follow-up.
- Reproduction requires the existing pinned device configuration and private
  model/host assets; these procedures are not a fresh-phone provisioning claim.
- A process killed before a terminal save may leave only its last stage.
  Data clearing/uninstallation removes app-private history. Android notification
  permissions/channel settings can suppress notifications; the launcher remains.
- Current per-turn limits and lack of conversational context are documented in
  the usage guide. No inference quality benchmark or broad task acceptance
  suite has been passed.
