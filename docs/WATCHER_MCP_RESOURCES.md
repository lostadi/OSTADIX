# Watcher measurements, interpretations and qualification over MCP

The MCP server publishes four fixed, read-only resources:

| URI | Published data |
| --- | --- |
| `ostadix://watcher/measurements` | Producer-reported scalar measurements, their observation times, collection methods and evidence digests. |
| `ostadix://watcher/findings` | Model, rule or human interpretations linked to exact measurement IDs. Decisions distinguish alerts, informational findings and abstentions. |
| `ostadix://watcher/actions` | Proposals linked to exact finding IDs. Their only accepted state is `proposed`. |
| `ostadix://watcher/qualification` | Producer-supplied ground truth and review labels, with explicit false-alarm, missed-incident and abstention accounting. |

There is no watcher collector or model invocation in this implementation. These
resources are an import/publication boundary for an existing external watcher's
explicit export. Reading a resource never runs a process, invokes a model,
fetches a URL, collects telemetry or executes a proposal. Interpretations and
proposals remain data under the consuming agent's existing user instructions.

Without a configured export, each resource returns `status: "not_configured"`,
with `data: null` and `snapshot: null`. A missing, malformed, unsafe or oversized
configured file returns `status: "unavailable"` with a stable reason code. Neither
state means that a machine is healthy, that no incidents occurred, or that a
watcher has been qualified.

## Operator configuration

Set `OSTADIX_WATCHER_STATE_DIR` in the **server's** environment to an absolute
directory containing `watcher-snapshot.json`. The resources do not accept paths,
query strings, resource templates or per-client root overrides. This does not
scan a repository, home directory, arbitrary logs or client configuration files.

The directory is explicitly selected by the operator. Publish only curated data
that the server's authorized MCP clients may read; omit secrets and unrelated
private content. Evidence `reference` strings name the producer's artifacts but
are never fetched or opened by the server. A hash/reference is not a verified
provenance, execution, freshness or authenticity proof.

On Linux and macOS, the reader pins the canonical directory components with
directory descriptors and opens only the fixed filename relative to that root.
It rejects final symlinks, directories, FIFOs and other special files. The file
is opened without following a swapped symlink or blocking on a swapped FIFO.
Non-Unix snapshot imports fail closed with `snapshot_platform_unsupported`;
the server's other MCP capabilities are unaffected.

Write a new snapshot to a separate temporary file in that directory, validate
it, and replace `watcher-snapshot.json` atomically. Do not append JSON records or
rewrite a live file in place. Each read loads one complete file; different
resource reads can observe different replacements. Consumers must compare
`snapshot_id` **and** `file_sha256` before joining their results.

Input and serialized resource output each have a 1 MiB budget. An oversized
response fails as `resource_response_too_large`; records are never silently
truncated or sampled. Use a declared evaluation window and a bounded export
rather than treating this snapshot resource as an unbounded historical store.

## Versioned import contract

The authoritative snapshot coordinate is
`ostadix.watcher-snapshot/v1` (`SNAPSHOT_SCHEMA_V1` in
`mcp/ostadix_lang_mcp_server/src/watcher_resources.rs`). The resource wrapper is
`ostadix.watcher-resource/v1` (`RESOURCE_SCHEMA_V1`). Unknown coordinates and
unknown fields are rejected, including fields claiming an action was executed.
This contract does not modify OIR, admission, Information records, runtime
placement or existing MCP tool schemas.

The complete test-only example is
[`tests/fixtures/watcher-snapshot-v1.json`](../tests/fixtures/watcher-snapshot-v1.json).
It deliberately uses fabricated fixture observations and digest placeholders;
it is a protocol test, not hardware telemetry or a qualified watcher result.

The snapshot contains these fields:

| Field | Contract |
| --- | --- |
| `schema` | Exactly `ostadix.watcher-snapshot/v1`. |
| `snapshot_id` | Producer's identifier for this complete snapshot. |
| `captured_at_unix_ms` | Producer's capture/publication time, as an unsigned integer number of milliseconds since the Unix epoch. |
| `producer` | Nonempty `id` and `revision` identifying the exporter implementation/configuration. |
| `scope` | `device_id`, `window_start_unix_ms`, `window_end_unix_ms`. Start must not exceed end; end must not exceed capture time. |
| `measurements` | At least one `Measurement` below. |
| `findings` | Zero or more `Finding` records below. Empty means none were published, not that no incidents exist. |
| `proposed_actions` | Zero or more `ProposedAction` records below. |
| `qualification` | A `Qualification` record below, or `null`/absent when no evaluation is supplied. |

Record IDs are nonempty and at most 128 ASCII characters from
`A-Z a-z 0-9 . _ - :`. IDs must be distinct within each record collection.
References within a snapshot must exist and cannot be duplicated in a reference
list. Text fields are nonempty, at most 4096 UTF-8 bytes, and cannot contain NUL.
All times are unsigned integer Unix milliseconds. Future-clock skew is not
independently assessed or corrected by the server.

Every measurement has `id`, `observed_at_unix_ms`, `subject`, `metric`, `value`,
`unit`, `method`, and `evidence`. `value` is a finite number, Boolean or nonempty
string, never an arbitrary nested object. Its observation must fall within the
declared window. `method` describes how the producer obtained the value.
`evidence` contains a nonempty `reference` and a 64-character lowercase
hexadecimal `sha256`. The digest names the producer's supporting bytes; this
reader verifies the **export file's** digest, not those referenced artifacts.

Every finding has `id`, `interpreted_at_unix_ms`, nonempty `measurement_ids`,
`interpretation`, `method`, and `decision`. Its `method` is an object with `kind`
(`model`, `rule` or `human`), `id`, and `revision`. Its decision is `alert`,
`informational` or `abstain`. The interpretation time cannot exceed capture time.

Every proposal has `id`, `proposed_at_unix_ms`, nonempty `finding_ids`, `proposal`,
`proposer` (the same method object shape), and `state: "proposed"`. Its timestamp
cannot exceed capture time. A successful resource read does not establish that
an action is appropriate, approved, attempted or completed.

## Qualification and error accounting

`Qualification` contains:

- `corpus_id`, `reviewed_at_unix_ms`, `reviewed_by`, and `method`: the declared
  evaluation corpus/window, review time, reviewer and labeling procedure.
- `ground_truth_complete`: the producer's explicit completeness claim for this
  snapshot's declared window. The server does not independently verify it.
- `ground_truth_incidents`: records with `id`, `observed_at_unix_ms` within the
  window, and `evidence` in the shape above.
- `finding_reviews`: one optional review per alert finding, with `finding_id`,
  `classification` and `incident_id`. A classification is `true_positive`,
  `false_alarm` or `unreviewed`. A true positive must reference an existing
  ground-truth incident. The other classifications must have null/absent
  `incident_id`. Informational findings and abstentions cannot be reviewed as
  alert detections.

The qualification resource retains those annotations and computes only their
descriptive accounting:

- False alarms are explicitly reviewed alert findings labeled `false_alarm`.
- Unreviewed alerts include both missing reviews and explicit `unreviewed`
  labels. They do not count as correct detections or false alarms.
- Distinct detected incidents are ground-truth incident IDs referenced by true
  positives. Multiple positive alerts for one incident count as one detected
  incident while remaining multiple alert findings.
- Missed incidents are ground-truth incidents without a true-positive alert.
  Their count, IDs and fraction remain **null** unless ground truth is declared
  complete **and** every alert finding has been reviewed. An abstention is
  reported separately and does not count as detection of an incident.
- `false_alarm_fraction_among_reviewed_alerts` is false alarms divided by
  reviewed alerts. It is not the conventional false-positive rate: this export
  does not provide a denominator of independently labeled negative trials.
- `missed_incident_fraction` is missed distinct incidents divided by reported
  ground-truth incidents, only under the completeness conditions above. A zero
  denominator gives null, rather than an invented zero rate.

With no qualification record, counts and rates are null and the qualification
status is `not_evaluated`. A supplied evaluation has status
`producer_reported_evaluation` and `independent_verification: "not_performed"`.
No schema-valid file is automatically labeled qualified or healthy. A snapshot
with no reported alerts or incidents establishes only that particular declared,
annotated export; it is not universal watcher coverage.

## Resource provenance and invalidation

Available resources include the producer, declared scope and capture time,
exact imported file SHA-256 and byte length, server read time, and an age
computed using the server's clock where possible. `freshness_verified` is always
false. The age is null if the server clock cannot order the capture timestamp.
This is diagnostic context, not a freshness SLA or proof that the producer's
clock is correct.

Changing any source byte changes `file_sha256`; changing a measurement ID,
finding ID, review label or evidence digest requires a new producer snapshot
identity. Broken references, duplicate IDs, unknown versions/fields, invalid
values or times outside the declared measurement/incident window invalidate
the entire import. No partial record set is promoted to a valid resource.
Version 0 or unknown records are not upgraded into V1. Original files may be
retained by their owner for archival inspection, but this resource does not
project or admit them.

The implementation's Rust unit tests cover separation, references, mutation
rejection, incomplete qualification, duplicate incident detections, abstentions,
file bounds and symlink/FIFO rejection. The fixture is suitable for MCP
integration tests when explicitly labeled as fixture import rather than actual
watcher collection.
