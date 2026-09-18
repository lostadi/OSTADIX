# Pixel AI audit artifacts

- `REPORT.md` — evidence-backed findings, capability paths, blockers, measurements, and rollback.
- `collect-readonly.sh` — repeatable package/split/hash/service/model/runtime inventory.
- `measure-foreground.sh` — one-route-at-a-time ML Kit probe measurement with lock/focus refusal,
  private Edge TPU trace instance, counters, power, memory, and thermal snapshots.
- `check-aicore-runtime-readiness.sh` — read-only live service/model/inference readiness check.
- `check-aicore-hook-coexistence.sh` — proves from live process mappings that Vector and the
  pinned OSTADIX runtime are loaded in AS.OSS, then requires simultaneous AICore model or
  inference readiness before allowing the correlated system replay.
- `AICORE-HOOK-COEXISTENCE-20260917.txt` — recorded live gate: hook and activation true,
  AICore model state false, exit 4.
- `check-extension-compatibility.sh` — live AICore/AS.OSS version, APK, and signer gate.
- `extension-compatibility-policy.sh` — pure fail-closed snapshot decision policy.
- `test-extension-compatibility-policy.sh` — compatible, malformed, and per-field drift tests.
- `stock-attestation-replay-20260917T004712Z/` — clean reboot evidence with TEESimulator absent;
  the kernel reports unlocked/orange verified boot while rewritten properties report
  locked/green, ProtectedDownload remained `PERMISSION_DENIED`, provider 25 returned no reply,
  and the candidate end-to-end result is `incomplete`.
- `run-stock-attestation-replay.sh`, `arm-stock-attestation-replay.sh`, and
  `analyze-stock-attestation-replay.py` — one-shot reboot verifier, arming helper, and strict
  correlation analyzer for the system-request chain.
- `native/edgetpu_sb_probe.c` — minimal root-context `libedgetpu_litert.so` initialization probe.
- `native/build-and-run.sh` — builds and runs that native probe.
- `../../apps/pixel-ai-probe/` — source, tests, build instructions, and signed foreground Android
  demonstrator.

The currently installed Android artifact is version `0.1.1` (`versionCode=2`), SHA-256
`da54cae70993a62b1a52257dda36707cff4e5d0920ff9ea8d4f088cc62f9d50e`.

The probe later ran unlocked and reached AICore preparation, but prompt 636,
image 627, and summary 622 all failed with `FEATURE_NOT_FOUND`. The read-only
runtime gate currently reports no inference records, no model payload or mapping,
and an enqueued preload worker after 11 attempts. If provisioning later becomes
ready, leave **Pixel on-device AI probe** visible and run one route at a time:

```bash
audits/pixel-ai-20260915/measure-foreground.sh prompt
```

Rollback:

```bash
pm uninstall org.ostadix.pixelai.probe
```

This removes only the external measurement probe. No internal AICore extension
is installed. Any future extension must pass `check-extension-compatibility.sh`
and implement the policy's `disable_experimental_extension_only` action without
disabling or clearing AICore itself.
