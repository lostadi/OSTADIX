# Assistant dispatch and pending-turn boundary

Historical v4 observer report. The subsequent v10 implementation and successful
ordinary assistant → local Nano → Ostadix result are recorded in
[LOCAL-ASSISTANT-RESULT.md](LOCAL-ASSISTANT-RESULT.md). Open items below describe
the earlier observation stage, not the final v10 status.

This continues [the initial boundary review](ASSISTANT-BOUNDARIES.md).
It does not establish a working ordinary Gemini → local Nano → `o_execute`
interaction. The prior goal turn made progress: it recovered a deeper stock
contract, implemented a diagnostic observer, and verified its registration
inside the real Google search process.

## Implementation

The owned extension now includes `GeminiRouteObservation`. It observes ten
version-pinned methods only when `ostadix_gemini_route_probe_sha256` contains a
host-selected SHA-256 and the input text matches that digest. Records include
method, input digest, object identities, PID/UID, pending-turn presence and
complete-turn count. They contain no raw prompt or conversation history.

The observer calls each original method once, with unchanged arguments, using
the framework's `PASSTHROUGH` exception mode. It does not execute Nano, call MCP,
replace a response, or suppress stock dispatch. A `returned` event means the
Java method returned; a coroutine may have returned its suspension marker.
That event is not inference completion.

The existing package, signer, firmware and activation checks remain in place.
Direct Android startup diagnostics were added because earlier log collection
did not establish observer initialization. The successful startup does not
support the suspected explanation of a spoof-induced gate rejection.

### Recovered installed-code contract

An interface scan of the installed Google APK found two `asut` implementations:
`ayko` and `ayld`, both in `classes12.dex`. Their factories include `wjb` and
`wjd` in `classes5.dex`, plus `wpt` and `wpv` in `classes.dex`.

```text
atma.a → asws.b → ayko.b → aykm → ayiz.b
                 ayld.b → aylb → ayiz.b

aykm execution → asuo.d → asuo.e → asuo.c → asuo.a
              → asvw.c → asvq coroutine
              → publish pending user turn
              → invoke supplied asue callback
              → asew.f returns the stock response flow
```

The coroutine variants of the senders also start those query objects. These
are static paths; the active ordinary-assistant branch still needs live proof.

`ayiz.b` rejects a second start of the same query instance. The query manager's
`ayii` coroutine cancels the previous query, waits for termination and publishes
the new active query. `asuh` separately installs the sending coroutine in
`aszg.g`, cancels the previous sending job when requested, and clears ownership
on success or exception.

The useful new boundary is inside `asvq`:

1. It creates the actual `atab` user message using `aszr.f(audl)` and the original
   `auja` input.
2. It creates the pending response flow and updates `aszg.n` through a
   compare-and-set loop using `aszq.G(...)` or `aszq.d(...)`, according to mode.
3. It builds `asux` and invokes the supplied `hdne` callback, concretely `asue`.
4. The callback's result is cast to **`heab`**, then passed through the original
   response-processing flows. Subsequent inspection establishes that `heab` is
   an interface exposing `jw(heac, hdkj)`, and `heac` exposes `a(Object, hdkj)`.
   A proxy can implement this exact interface; a proxy for `hdzx` alone cannot.
5. The original `asue` constructs the stock request and calls `asew.f(...)`.

This makes the callback after pending-turn publication a candidate for local
model substitution. It still requires a correctly typed, cancellable response
flow. Replacing an early submit method or a TextView would skip this contract.

Local decompilation evidence (kept outside Git):

- `/data/local/tmp/ostadix-gsa-nano-dex/ayko.java`, `ayld.java`, `ayiz.java`
- `/data/local/tmp/gsa-classes2-jadx-full/sources/defpackage/ayii.java`
- `/data/local/tmp/ostadix-gsa-nano-dex/asuh-simple.java`
- `/data/local/tmp/ostadix-gsa-nano-dex/asvq-simple.java`: pending publication
  around lines 500–580; concrete `heab` cast around line 355; user construction
  around line 938.
- `/data/local/tmp/ostadix-gsa-nano-dex/asue-simple.java`: `asew.f` dispatch
  around lines 288–315.

## Live observations

The final observer build passed all six packaging stages, including the
existing result-replacement and ASI delegation self-tests. The installed APK
was read back and its SHA-256 matched the built artifact:

`f4c92a0f73ef5a36f59ef518f783313da7eb41a7bf4b2386c8fa57ab4c1dff39`

[Installed identity](assistant-route-current-install.json) records version 4,
`0.4.0-assistant-route-observation`. [Captured startup events](assistant-route-current-startup.logcat)
show PID 16884, UID 10191, both gates accepted, and ten registered observer hooks.
The installed Google base APK was rehashed and still matched the pin
`c227beb9468f1740c395e457d5f06fb780f288a89156d8487ef069953c1c359a`.

Two initial injected assistant/power key events did not establish a Gemini
request. The screen was changing independently through accessibility settings;
UI input was paused and screen availability was requested. No synthetic prompt
was typed or sent in this attempt. Subsequent deployment checks restarted only
the background Google search process, with PID and UID validation and a pidfd.

### Subsequent ordinary-assistant test

After resuming, `KEYCODE_ASSIST` opened the stock Gemini `FloatyActivity`.
Focus and the empty text field were inspected before typing. Codex typed and
tapped Send for the synthetic prompt recorded in
[the input record](assistant-route-live-input.json); no user-send action is
claimed for this test. Gemini displayed **ready**.

[Correlated events](assistant-route-live-events.logcat) prove the same input
digest, input object `82399563` and chat-store object `153003816` reached
`asuo.d`, `asuo.e`, `asuo.c`, `asvw.c`, and `asue.invoke` in PID 16884 / UID 10191.
The store had `pending=false` at `asvw.c` entry and **`pending=true` at
`asue.invoke` entry**, with zero complete turns at both points. This establishes
ordinary-assistant reachability of the callback after pending publication.
The earlier `atma` / sender / query-manager hooks did not log this request;
their use in this active configuration is not inferred.

The coroutine methods returned `hdkt` (suspension), not completed answers.
Four later null-input resume calls caused contained observer errors; stock
execution still displayed the requested response. The source now skips these
null placeholders; that correction is not part of the APK used for this trace.
[Result record](assistant-route-live-result.json) retains the screenshot hash;
the screenshot itself remains local. This request used the original model
dispatch, with model identity unverified. It invoked neither the local Nano
probe nor MCP.

## Unverified and next work

- The active upper sender/query-manager branch; the deeper response callback
  is now observed for an ordinary assistant request.
- A local Nano-backed replacement for `asue` that returns a valid `heab` flow,
  preserves cancellation and produces the original handler's expected values.
- The same ordinary assistant interaction producing fresh `.O`, invoking the
  existing primary `o_execute`, consuming its actual result and displaying it.
- Prevention of stock online dispatch for a locally handled request.
- General model reliability and the factory bundle's public Nano release name.

The MCP/runtime and preserved ASI work retain their earlier evidence. No new
remote execution, public Nano tool API or completed assistant integration is
claimed here.
