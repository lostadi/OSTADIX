# Canonical checkout and local Nano execution continuity

## Implementation

The canonical repository is `https://github.com/lostadi/OSTADIX`, checked out
at `/data/data/com.termux/files/home/OSTADIX`.

Task source and bounded evidence were imported directly from the existing
local `Ostadix-lang` checkout first. The original checkout was retained.
[The import manifest](local-first-import.json) records the imported file
identities; these are import-time hashes, not claims about subsequent edits.
The local checkpoint is `48f79466`, retained on the local branch
`local-import-before-attribution-reconcile-20260917`.

GitHub had rewritten history to remove non-owner attribution. The task changes
were transplanted onto `363e987d` instead of merging the old history back.
The resulting import commit is `83f4718b`. Author and committer are both
Lee Daghlar Ostadi, `ostadi.lee@gmail.com`; no assistant co-author was added.

The newer canonical MCP already had a primary `o_execute` operation. Its
source/path/actions/jobs/placement interface was retained. The older duplicate
embedded MCP handler was not carried forward. RuntimeRequest remains the
separate runtime embedding API. The primary MCP invokes the native tools and
preserves their actual structured results and job evidence.

The owned Android extension and probe were rebuilt. Google's original native
libraries and factory model payloads are reused; this is not a rebuild of
Google's proprietary model training code or all of AICore. Factory payloads,
private host credentials, SDK downloads and raw session exports are excluded
from this import.

## Live observations

- [Canonical extension installation](canonical-generation-install.json)
  replaced only the owned extension and restarted the AICore process.
  The seven reused native OSTADIX artifacts passed their pinned hash checks.
- [The first text-generation attempt](canonical-nano-text.json) ran in the
  real AICore process, UID 10173. It returned an arithmetic completion beginning
  with ` 5.`; the 32-token output repeated the sentence and hit its limit.
  Native generation took 5,109 ms; the complete monitored load/generate/cleanup
  attempt took 34,619 ms. All 191 model descriptors were closed.
- [The raw program prompt](canonical-nano-o.json) returned an explicitly empty
  candidate, finish enum 1. Native completion and cleanup succeeded; program
  synthesis did not. Stock response telemetry reports 651 input tokens and
  zero output tokens. The precise native stopping token is unverified.
- [The turn-framed prompt](canonical-nano-o-chat.json) returned
  [this unchanged program](nano-generated-shipment-chat.txt). Native aliases
  establish `ctrl99`/`ctrl100` as turn boundaries. The `user`/`model` framing
  was a tested hypothesis, not a recovered feature-specific stock template.
- [One primary MCP invocation](nano-chat-exact-mcp-result.json) submitted that
  entire unchanged response. OSTADIX accepted its fenced O document and
  returned a real Python evaluation failure: the model used the builtin
  `input` as a CSV string. The native executable hash used for this attempt
  is retained in the record. No successful result is claimed for this run.
- Two model repair responses followed the actual runtime errors. The first
  repaired the missing CSV but failed with Python indentation. The second
  executed its computations, but its closing Markdown fence became the final
  literal O value. All failed and mismatched attempts remain recorded.
- The host then extracted exactly one outer Markdown fence, preserving the
  generated program body unchanged. [The resulting one-call execution](nano-program-mcp-result.json)
  returned the actual typed map: IDs `[2, 3, 8, 13]`, depot totals north `13`
  and south `13`, total units `26`. Native O execution took **802 ms**; that
  excludes model generation, repairs and loading. Source, OIR, plan, analyzed
  graph, evidence, admitted graph, admission and result identities are retained.
  [Independent result validation](nano-program-acceptance.json) passed for
  this input; the general zero-unit-depot case was not verified.
- [A subsequent actual model request](canonical-nano-result.json) consumed
  that returned result and produced [this matching answer](nano-result-consumption-response.txt).
  The controlled host orchestrated the calls; this is not proof that Nano
  independently selected a registered function or used a public tool API.
- The Android loopback broker was moved to the canonical checkout and rebuilt
  MCP. Its first UID-10402 test failed because Termux's system-linker wrapper
  made native executable admission identify `linker64` instead of O. The fix
  disables that wrapper only for the verified `u:r:ksu:s0` host context before
  MCP starts; native admission remains intact. [The full program retest](nano-program-canonical-broker-fixed-result.json)
  returned the same typed result in **787 ms**, with matching source and result
  identities. The caller was a controlled HTTPS client, not Android's
  AppFunction framework or Gemini. The host is not boot-persistent.

These requests were dispatched by the controlled test host. They were not
ordinary Gemini assistant requests.

## Unverified

The ordinary assistant invocation → local model → complete O source → primary
MCP execution → model result consumption → same assistant response chain has
not been demonstrated. Neither schema inventory injection nor a shell test
caller proves that chain. The exact public Nano release/API family matching
the factory `feature_234` build `10745` bundle is also unverified.

No all-network-disabled experiment has been performed. Local factory inference
has now worked without obtaining a new server manifest, but that does not
establish that the whole Gemini assistant can operate without Google servers.
