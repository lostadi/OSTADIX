# Using local Nano and Ostadix on the configured Pixel

## Daily use

1. Invoke Gemini with the usual assistant gesture or power button.
2. Type a complete request and tap Send. The enabled `local-all-v1` route
   selects ordinary text requests without requiring a “Use Ostadix” prefix.
3. Open **Ostadix Results** from the app drawer, or tap its result notification.
   The saved output appears first. **All results** opens earlier requests.
4. **Copy answer** copies the displayed answer. **Show program and execution
   details** reveals the generated source, actual tool result and evidence.

The viewer is local history. It does not populate Google's cloud conversation
history. Closing Gemini does not delete saved records. A cancelled request can
save a stopped/error record; cancellation does not guarantee rollback of effects.
An interrupted process may leave its last recorded stage without a final result.
Records persist across app restarts/updates until app data is cleared or the app
is uninstalled. They are excluded from Android backup.

The displayed **Ostadix output** comes from the runtime. **Nano's explanation**
is generated separately. A program can execute successfully and still calculate
the wrong thing: the September 18 test caught Nano duplicating `17 + 25` and
adding the copies. Its actual output, 84, remains in history; the host did not
replace it with an expected answer. Generation guidance was subsequently changed.
Another generated document was bare Python, which O returned as text. The adapter
now rejects missing executable block delimiters before execution and can request
its one correction. Model explanations are explicitly labeled unverified.

The adapter gives Nano the current request text. Saving history does not yet
make earlier conversations available as model context. State the needed inputs
in each request. Voice, attachments, Gemini Live, arbitrary external services,
and unrestricted task correctness have not been established by the text tests.

## Rebuild and redeploy this configuration

This is a repeatable procedure for the **already configured, pinned Pixel**,
not an installer for an arbitrary phone. It requires the existing Vector module
scope and activation, recovered Nano factory assets, original compatible Google
packages, private host configuration, native artifacts, and signing keystore.
Google's model and AICore binaries are reused; this does not rebuild them.

Use the canonical checkout, not the older `Ostadix-lang` directory:

```bash
cd /data/data/com.termux/files/home/OSTADIX
bash apps/aicore-ostadix-extension/build.sh
bash apps/aicore-ostadix-extension/test-result-output.sh
python -m unittest discover -s tests -p test_appfunction_host.py -v
```

The build verifies Android SDK/tool availability, compile-only libxposed API
102's hash, all seven native files, Google package policy and APK signing. Its
native closure comes from the existing Android terminal build. Follow that
app's build instructions if those artifacts are absent; changed hashes require
compatibility investigation, not blindly updating the pins.

From the authorized root terminal, after requests have finished:

```bash
python scripts/ostadix_assistant_results.py install
python scripts/ostadix_assistant_service.py install
python scripts/ostadix_assistant_service.py start
python scripts/ostadix_assistant_service.py check
python scripts/ostadix_assistant_results.py open
```

The result installer requires recorded Nano cleanup and a terminal assistant
turn before replacing the APK. It grants result notifications, verifies the
installed APK hash, restarts only the identified AICore/GSA experiment processes,
and recovers earlier private turn records without executing them. Recovery can
be run again with `python scripts/ostadix_assistant_results.py recover`.

The service installer preserves existing credentials. The root-owned boot
entry waits for boot completion and unlocked Termux storage, then launches the
MCP host as the configuration owner's Termux UID. Its supervisor restarts a
crashed host, but never resubmits requests. Repeating installation with identical
scripts and repeating start are supported. Upgrading deployed host scripts while
the old supervisor is running is refused. Physical reboot recovery remains a
separate check; invoking the boot entry on an unlocked phone has been tested.

`check` executes a new harmless `1 + 1` program over pinned local HTTPS and prints
the actual typed result and execution evidence. It does not test Nano generation.

## Diagnosis and disabling the route

```bash
python scripts/ostadix_assistant_service.py status
python scripts/ostadix_assistant_service.py check
python scripts/ostadix_assistant_service.py disable
```

`disable` removes local selection for future assistant requests and leaves the
MCP service and saved results available. `start` enables selection again. It
does not revoke an already executing request. The existing explicit activation,
version/hash/signature, thermal and cancellation gates still apply.

Service metadata and logs are in `~/.config/ostadix/gemini/`; configuration there
contains credentials and must not be shared. Boot files are
`/data/adb/service.d/40-ostadix-assistant.sh` and
`/data/local/ostadix-assistant/`. History is private app data; other apps do not
receive a read API. Its writer verifies the pinned GSA identity. Notifications
respect Android notification/channel settings.

## Execution behavior and limits

Nano returns a complete source document. The host uses primary MCP `o_execute`
for parse-only validation, then executes once. A confirmed parse rejection or
missing executable-language-block marker
can request one corrected source from Nano and validate it again. Execution
errors, transport errors and timeouts do not cause automatic execution retries.
A normal turn therefore has two MCP calls (check, execute); a corrected turn
has three (check, check, execute). These are not extra execution attempts.

The host owns deadlines, credentials and placement. Current generation is
bounded to 512 tokens, parse checking to 15 seconds and execution to 120 seconds;
this assistant adapter is not proof that every Ostadix workload fits those limits.
History records are limited to 16 MiB and a save failure is reported in the
answer when delivery is possible. Notification previews are abbreviated; the
viewer keeps the full saved answer. Model-generated code runs with the existing
host permissions. Parse validation checks syntax, not intent or safety.

See [the dated evidence report](../../audits/nano-source-validation-20260918/STATUS.md)
for implementation, observations and unverified claims separately.
