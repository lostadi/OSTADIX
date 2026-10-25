//! Read-only publication of explicitly exported watcher observations.
//!
//! There is no watcher collector in this crate. An operator may publish one
//! versioned snapshot; importing it does not verify its claims or authorize an
//! action. Fixed resources never execute a probe, model, or proposed action.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const STATE_DIR_ENV: &str = "OSTADIX_WATCHER_STATE_DIR";
pub(crate) const SNAPSHOT_SCHEMA_V1: &str = "ostadix.watcher-snapshot/v1";
pub(crate) const RESOURCE_SCHEMA_V1: &str = "ostadix.watcher-resource/v1";
const SNAPSHOT_FILE: &str = "watcher-snapshot.json";
const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;

pub(crate) const RESOURCES: &[(&str, &str)] = &[
    (
        "ostadix://watcher/measurements",
        "Watcher producer-reported measurements",
    ),
    (
        "ostadix://watcher/findings",
        "Watcher interpretations linked to measurements",
    ),
    (
        "ostadix://watcher/actions",
        "Watcher proposed actions (never dispatched by this resource)",
    ),
    (
        "ostadix://watcher/qualification",
        "Watcher reported false-alarm and missed-incident accounting",
    ),
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotV1 {
    schema: String,
    snapshot_id: String,
    captured_at_unix_ms: u64,
    producer: Producer,
    scope: Scope,
    measurements: Vec<Measurement>,
    findings: Vec<Finding>,
    proposed_actions: Vec<ProposedAction>,
    qualification: Option<Qualification>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Producer {
    id: String,
    revision: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    device_id: String,
    window_start_unix_ms: u64,
    window_end_unix_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRef {
    reference: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum MeasuredValue {
    Number(serde_json::Number),
    Boolean(bool),
    Text(String),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Measurement {
    id: String,
    observed_at_unix_ms: u64,
    subject: String,
    metric: String,
    value: MeasuredValue,
    unit: String,
    method: String,
    evidence: EvidenceRef,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum InterpretationKind {
    Model,
    Rule,
    Human,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InterpretationMethod {
    kind: InterpretationKind,
    id: String,
    revision: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FindingDecision {
    Alert,
    Informational,
    Abstain,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Finding {
    id: String,
    interpreted_at_unix_ms: u64,
    measurement_ids: Vec<String>,
    interpretation: String,
    method: InterpretationMethod,
    decision: FindingDecision,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProposalState {
    Proposed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProposedAction {
    id: String,
    proposed_at_unix_ms: u64,
    finding_ids: Vec<String>,
    proposal: String,
    proposer: InterpretationMethod,
    state: ProposalState,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GroundTruthIncident {
    id: String,
    observed_at_unix_ms: u64,
    evidence: EvidenceRef,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Classification {
    TruePositive,
    FalseAlarm,
    Unreviewed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FindingReview {
    finding_id: String,
    classification: Classification,
    incident_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    corpus_id: String,
    reviewed_at_unix_ms: u64,
    reviewed_by: String,
    method: String,
    ground_truth_complete: bool,
    ground_truth_incidents: Vec<GroundTruthIncident>,
    finding_reviews: Vec<FindingReview>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotError {
    InvalidConfiguration,
    Missing,
    Unreadable,
    UnsafeFile,
    TooLarge,
    InvalidData,
    #[cfg(not(unix))]
    UnsupportedPlatform,
}

impl SnapshotError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::Missing => "snapshot_missing",
            Self::Unreadable => "snapshot_unreadable",
            Self::UnsafeFile => "snapshot_not_regular_or_is_symlink",
            Self::TooLarge => "snapshot_too_large",
            Self::InvalidData => "snapshot_schema_or_references_invalid",
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "snapshot_platform_unsupported",
        }
    }
}

fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.contains('\0')
}

fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn evidence(value: &EvidenceRef) -> bool {
    text(&value.reference)
        && value.sha256.len() == 64
        && value
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn interpretation_method(value: &InterpretationMethod) -> bool {
    text(&value.id) && text(&value.revision)
}

fn distinct_ids<'a>(values: impl Iterator<Item = &'a str>) -> Option<BTreeSet<&'a str>> {
    let mut result = BTreeSet::new();
    for value in values {
        if !id(value) || !result.insert(value) {
            return None;
        }
    }
    Some(result)
}

fn references(values: &[String], known: &BTreeSet<&str>) -> bool {
    !values.is_empty()
        && distinct_ids(values.iter().map(String::as_str))
            .is_some_and(|ids| ids.iter().all(|value| known.contains(value)))
}

fn validate(snapshot: &SnapshotV1) -> bool {
    if snapshot.schema != SNAPSHOT_SCHEMA_V1
        || !id(&snapshot.snapshot_id)
        || !text(&snapshot.producer.id)
        || !text(&snapshot.producer.revision)
        || !id(&snapshot.scope.device_id)
        || snapshot.scope.window_start_unix_ms > snapshot.scope.window_end_unix_ms
        || snapshot.scope.window_end_unix_ms > snapshot.captured_at_unix_ms
        || snapshot.measurements.is_empty()
    {
        return false;
    }
    let Some(measurements) =
        distinct_ids(snapshot.measurements.iter().map(|value| value.id.as_str()))
    else {
        return false;
    };
    let Some(findings) = distinct_ids(snapshot.findings.iter().map(|value| value.id.as_str()))
    else {
        return false;
    };
    if distinct_ids(
        snapshot
            .proposed_actions
            .iter()
            .map(|value| value.id.as_str()),
    )
    .is_none()
    {
        return false;
    }
    let in_window =
        |at| snapshot.scope.window_start_unix_ms <= at && at <= snapshot.scope.window_end_unix_ms;
    if snapshot.measurements.iter().any(|value| {
        !in_window(value.observed_at_unix_ms)
            || !text(&value.subject)
            || !text(&value.metric)
            || !text(&value.unit)
            || !text(&value.method)
            || !evidence(&value.evidence)
            || match &value.value {
                MeasuredValue::Number(value) => {
                    value.as_f64().is_none_or(|number| !number.is_finite())
                }
                MeasuredValue::Text(value) => !text(value),
                MeasuredValue::Boolean(_) => false,
            }
    }) || snapshot.findings.iter().any(|value| {
        value.interpreted_at_unix_ms > snapshot.captured_at_unix_ms
            || !references(&value.measurement_ids, &measurements)
            || !text(&value.interpretation)
            || !interpretation_method(&value.method)
    }) || snapshot.proposed_actions.iter().any(|value| {
        value.proposed_at_unix_ms > snapshot.captured_at_unix_ms
            || !references(&value.finding_ids, &findings)
            || !text(&value.proposal)
            || !interpretation_method(&value.proposer)
    }) {
        return false;
    }
    let Some(qualification) = &snapshot.qualification else {
        return true;
    };
    let Some(incidents) = distinct_ids(
        qualification
            .ground_truth_incidents
            .iter()
            .map(|value| value.id.as_str()),
    ) else {
        return false;
    };
    if !text(&qualification.corpus_id)
        || !text(&qualification.reviewed_by)
        || !text(&qualification.method)
        || qualification.reviewed_at_unix_ms > snapshot.captured_at_unix_ms
        || qualification
            .ground_truth_incidents
            .iter()
            .any(|value| !in_window(value.observed_at_unix_ms) || !evidence(&value.evidence))
        || distinct_ids(
            qualification
                .finding_reviews
                .iter()
                .map(|value| value.finding_id.as_str()),
        )
        .is_none()
    {
        return false;
    }
    let alerts: BTreeSet<&str> = snapshot
        .findings
        .iter()
        .filter(|value| value.decision == FindingDecision::Alert)
        .map(|value| value.id.as_str())
        .collect();
    qualification.finding_reviews.iter().all(|review| {
        alerts.contains(review.finding_id.as_str())
            && match review.classification {
                Classification::TruePositive => review
                    .incident_id
                    .as_deref()
                    .is_some_and(|value| incidents.contains(value)),
                Classification::FalseAlarm | Classification::Unreviewed => {
                    review.incident_id.is_none()
                }
            }
    })
}

fn open_snapshot(root: &Path) -> Result<File, SnapshotError> {
    if !root.is_absolute() {
        return Err(SnapshotError::InvalidConfiguration);
    }
    let approved = root.canonicalize().map_err(|_| SnapshotError::Unreadable)?;
    if !approved.is_dir() {
        return Err(SnapshotError::InvalidConfiguration);
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::path::Component;
        // Pin every canonical directory component. A replacement parent or final
        // symlink cannot redirect the subsequent fixed-name open outside it.
        let mut directory = File::open("/").map_err(|_| SnapshotError::Unreadable)?;
        for component in approved.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(component) => {
                    let component = CString::new(component.as_bytes())
                        .map_err(|_| SnapshotError::InvalidConfiguration)?;
                    let descriptor = unsafe {
                        libc::openat(
                            directory.as_raw_fd(),
                            component.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if descriptor < 0 {
                        return Err(SnapshotError::UnsafeFile);
                    }
                    directory = unsafe { File::from_raw_fd(descriptor) };
                }
                _ => return Err(SnapshotError::InvalidConfiguration),
            }
        }
        let name = CString::new(SNAPSHOT_FILE).expect("fixed snapshot filename");
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                    SnapshotError::Missing
                } else {
                    SnapshotError::UnsafeFile
                },
            );
        }
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
    #[cfg(not(unix))]
    {
        // Do not provide a weaker race-prone path fallback on an unqualified
        // platform. Other MCP resources remain available.
        Err(SnapshotError::UnsupportedPlatform)
    }
}

fn read_snapshot(root: &Path) -> Result<(SnapshotV1, String, usize), SnapshotError> {
    let mut file = open_snapshot(root)?;
    let metadata = file.metadata().map_err(|_| SnapshotError::Unreadable)?;
    if !metadata.is_file() {
        return Err(SnapshotError::UnsafeFile);
    }
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SnapshotError::Unreadable)?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    let snapshot: SnapshotV1 =
        serde_json::from_slice(&bytes).map_err(|_| SnapshotError::InvalidData)?;
    if !validate(&snapshot) {
        return Err(SnapshotError::InvalidData);
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((snapshot, digest, bytes.len()))
}

fn qualification(snapshot: &SnapshotV1) -> Value {
    let Some(qualification) = &snapshot.qualification else {
        return json!({
            "status": "not_evaluated",
            "annotations": null,
            "counts": null,
            "false_alarm_fraction_among_reviewed_alerts": null,
            "missed_incident_fraction": null,
            "independent_verification": "not_performed"
        });
    };
    let alert_count = snapshot
        .findings
        .iter()
        .filter(|value| value.decision == FindingDecision::Alert)
        .count();
    let abstentions = snapshot
        .findings
        .iter()
        .filter(|value| value.decision == FindingDecision::Abstain)
        .count();
    let true_positive_count = qualification
        .finding_reviews
        .iter()
        .filter(|value| value.classification == Classification::TruePositive)
        .count();
    let false_alarms: Vec<&str> = qualification
        .finding_reviews
        .iter()
        .filter(|value| value.classification == Classification::FalseAlarm)
        .map(|value| value.finding_id.as_str())
        .collect();
    let reviewed = true_positive_count + false_alarms.len();
    let detected_incidents: BTreeSet<&str> = qualification
        .finding_reviews
        .iter()
        .filter(|value| value.classification == Classification::TruePositive)
        .filter_map(|value| value.incident_id.as_deref())
        .collect();
    let complete = qualification.ground_truth_complete && reviewed == alert_count;
    let missed: Option<Vec<&str>> = complete.then(|| {
        qualification
            .ground_truth_incidents
            .iter()
            .filter(|value| !detected_incidents.contains(value.id.as_str()))
            .map(|value| value.id.as_str())
            .collect()
    });
    let miss_fraction = missed.as_ref().and_then(|missed| {
        (!qualification.ground_truth_incidents.is_empty())
            .then(|| missed.len() as f64 / qualification.ground_truth_incidents.len() as f64)
    });
    json!({
        "status": "producer_reported_evaluation",
        "annotations": qualification,
        "counts": {
            "alert_findings": alert_count,
            "abstentions": abstentions,
            "informational_findings": snapshot.findings.len() - alert_count - abstentions,
            "reviewed_alerts": reviewed,
            "unreviewed_alerts": alert_count - reviewed,
            "true_positive_alerts": true_positive_count,
            "false_alarms": false_alarms.len(),
            "reported_ground_truth_incidents": qualification.ground_truth_incidents.len(),
            "detected_distinct_incidents": detected_incidents.len(),
            "missed_incidents": missed.as_ref().map(Vec::len)
        },
        "false_alarm_finding_ids": false_alarms,
        "missed_incident_ids": missed,
        "false_alarm_fraction_among_reviewed_alerts": (reviewed > 0).then(|| false_alarms.len() as f64 / reviewed as f64),
        "missed_incident_fraction": miss_fraction,
        "missed_incidents_computable": complete,
        "independent_verification": "not_performed",
        "scope": "Only this snapshot's declared window, published alert findings and producer-supplied ground-truth/review annotations."
    })
}

fn read_from_root(uri: &str, root: Option<&Path>) -> Option<Value> {
    let kind = RESOURCES
        .iter()
        .find(|(known, _)| *known == uri)?
        .0
        .rsplit('/')
        .next()?;
    let mut response = json!({
        "schema": RESOURCE_SCHEMA_V1,
        "uri": uri,
        "status": "not_configured",
        "standing": "descriptive_only",
        "collection_performed": false,
        "model_invoked": false,
        "action_dispatched": false,
        "data": null,
        "snapshot": null,
        "notice": "Measurements, interpretations, proposals and review labels are producer-reported; importing this file does not verify truth, freshness or authority."
    });
    let Some(root) = root else {
        response["configuration"] = json!({
            "state_directory_environment": STATE_DIR_ENV,
            "snapshot_filename": SNAPSHOT_FILE,
            "snapshot_schema": SNAPSHOT_SCHEMA_V1
        });
        return Some(response);
    };
    match read_snapshot(root) {
        Ok((snapshot, sha256, bytes)) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|duration| u64::try_from(duration.as_millis()).ok());
            response["status"] = json!("available");
            response["snapshot"] = json!({
                "schema": snapshot.schema,
                "snapshot_id": snapshot.snapshot_id,
                "captured_at_unix_ms": snapshot.captured_at_unix_ms,
                "producer": snapshot.producer,
                "scope": snapshot.scope,
                "file_sha256": sha256,
                "file_bytes": bytes,
                "read_at_unix_ms": now,
                "age_ms_by_server_clock": now.and_then(|now| now.checked_sub(snapshot.captured_at_unix_ms)),
                "freshness_verified": false
            });
            response["data"] = match kind {
                "measurements" => json!({"measurements": snapshot.measurements}),
                "findings" => json!({"interpretations": snapshot.findings}),
                "actions" => json!({"proposed_actions": snapshot.proposed_actions}),
                "qualification" => qualification(&snapshot),
                _ => unreachable!("fixed watcher resource table"),
            };
        }
        Err(error) => {
            response["status"] = json!("unavailable");
            response["reason"] = json!(error.code());
        }
    }
    if serde_json::to_vec(&response).is_ok_and(|bytes| bytes.len() as u64 > MAX_SNAPSHOT_BYTES) {
        return Some(json!({
            "schema": RESOURCE_SCHEMA_V1,
            "uri": uri,
            "status": "unavailable",
            "reason": "resource_response_too_large",
            "standing": "descriptive_only",
            "collection_performed": false,
            "model_invoked": false,
            "action_dispatched": false,
            "data": null,
            "snapshot": null
        }));
    }
    Some(response)
}

pub(crate) fn read_resource(uri: &str) -> Option<Value> {
    let configured = std::env::var_os(STATE_DIR_ENV);
    read_from_root(uri, configured.as_deref().map(Path::new))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let value = std::env::temp_dir().join(format!(
                "ostadix-watcher-resource-test-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&value).unwrap();
            Self(value)
        }

        fn publish(&self, value: &Value) {
            fs::write(
                self.0.join(SNAPSHOT_FILE),
                serde_json::to_vec(value).unwrap(),
            )
            .unwrap();
        }

        fn read(&self, kind: &str) -> Value {
            read_from_root(&format!("ostadix://watcher/{kind}"), Some(&self.0)).unwrap()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn fixture() -> Value {
        json!({
            "schema": SNAPSHOT_SCHEMA_V1,
            "snapshot_id": "test-snapshot",
            "captured_at_unix_ms": 2000,
            "producer": {"id": "fixture-exporter", "revision": "test-only"},
            "scope": {"device_id": "test-device", "window_start_unix_ms": 1000, "window_end_unix_ms": 1800},
            "measurements": [{"id": "m1", "observed_at_unix_ms": 1100, "subject": "test-worker", "metric": "cpu", "value": 0.8, "unit": "ratio", "method": "test fixture", "evidence": {"reference": "fixture:cpu", "sha256": "a".repeat(64)}}],
            "findings": [
                {"id": "f1", "interpreted_at_unix_ms": 1200, "measurement_ids": ["m1"], "interpretation": "test incident candidate", "method": {"kind": "model", "id": "fixture-model", "revision": "test-only"}, "decision": "alert"},
                {"id": "f2", "interpreted_at_unix_ms": 1201, "measurement_ids": ["m1"], "interpretation": "test false alarm", "method": {"kind": "rule", "id": "fixture-rule", "revision": "test-only"}, "decision": "alert"}
            ],
            "proposed_actions": [{"id": "a1", "proposed_at_unix_ms": 1300, "finding_ids": ["f1"], "proposal": "Inspect the test worker", "proposer": {"kind": "human", "id": "fixture-reviewer", "revision": "test-only"}, "state": "proposed"}],
            "qualification": {
                "corpus_id": "test-only-window", "reviewed_at_unix_ms": 1900, "reviewed_by": "fixture-reviewer", "method": "fixture labels", "ground_truth_complete": true,
                "ground_truth_incidents": [
                    {"id": "i1", "observed_at_unix_ms": 1100, "evidence": {"reference": "fixture:incident1", "sha256": "b".repeat(64)}},
                    {"id": "i2", "observed_at_unix_ms": 1500, "evidence": {"reference": "fixture:incident2", "sha256": "c".repeat(64)}}
                ],
                "finding_reviews": [
                    {"finding_id": "f1", "classification": "true_positive", "incident_id": "i1"},
                    {"finding_id": "f2", "classification": "false_alarm", "incident_id": null}
                ]
            }
        })
    }

    #[test]
    fn absent_configuration_and_unknown_uri_do_not_claim_healthy_measurements() {
        let value = read_from_root(RESOURCES[0].0, None).unwrap();
        assert_eq!(value["status"], "not_configured");
        assert!(value["data"].is_null());
        assert!(value["snapshot"].is_null());
        assert_eq!(value["collection_performed"], false);
        assert!(read_from_root("ostadix://watcher/../../secret", None).is_none());
        assert!(read_from_root("ostadix://watcher/measurements?path=/secret", None).is_none());
    }

    #[test]
    fn resources_keep_measurements_interpretations_proposals_and_reviews_separate() {
        let root = TestDirectory::new();
        root.publish(&fixture());
        let mut hashes = BTreeSet::new();
        for (uri, _) in RESOURCES {
            let value = read_from_root(uri, Some(&root.0)).unwrap();
            assert_eq!(value["status"], "available");
            assert_eq!(value["standing"], "descriptive_only");
            assert_eq!(value["model_invoked"], false);
            assert_eq!(value["action_dispatched"], false);
            hashes.insert(
                value["snapshot"]["file_sha256"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes.first().unwrap(),
            &format!(
                "{:x}",
                Sha256::digest(fs::read(root.0.join(SNAPSHOT_FILE)).unwrap())
            )
        );
        let measurements = root.read("measurements");
        assert!(measurements["data"].get("interpretations").is_none());
        assert!(measurements["data"].get("proposed_actions").is_none());
        assert_eq!(measurements["data"]["measurements"][0]["value"], 0.8);
        assert_eq!(
            root.read("findings")["data"]["interpretations"][0]["method"]["kind"],
            "model"
        );
        assert_eq!(
            root.read("actions")["data"]["proposed_actions"][0]["state"],
            "proposed"
        );
    }

    #[test]
    fn reported_reviews_count_false_alarms_and_missed_distinct_incidents() {
        let root = TestDirectory::new();
        root.publish(&fixture());
        let q = root.read("qualification")["data"].clone();
        assert_eq!(q["counts"]["true_positive_alerts"], 1);
        assert_eq!(q["counts"]["false_alarms"], 1);
        assert_eq!(q["counts"]["detected_distinct_incidents"], 1);
        assert_eq!(q["counts"]["missed_incidents"], 1);
        assert_eq!(q["missed_incident_ids"], json!(["i2"]));
        assert_eq!(q["false_alarm_fraction_among_reviewed_alerts"], 0.5);
        assert_eq!(q["missed_incident_fraction"], 0.5);
        assert_eq!(q["independent_verification"], "not_performed");
    }

    #[test]
    fn integer_measurements_retain_exact_u64_values_above_float_precision() {
        let root = TestDirectory::new();
        let mut value = fixture();
        value["measurements"][0]["value"] = json!(u64::MAX);
        root.publish(&value);
        assert_eq!(
            root.read("measurements")["data"]["measurements"][0]["value"],
            json!(u64::MAX)
        );
    }

    #[test]
    fn absent_evaluation_does_not_turn_missing_labels_into_zero_errors() {
        let root = TestDirectory::new();
        let mut value = fixture();
        value["qualification"] = Value::Null;
        root.publish(&value);
        let q = root.read("qualification")["data"].clone();
        assert_eq!(q["status"], "not_evaluated");
        assert!(q["counts"].is_null());
        assert!(q["missed_incident_fraction"].is_null());
    }

    #[test]
    fn incomplete_ground_truth_or_unreviewed_alerts_leave_misses_unknown() {
        let root = TestDirectory::new();
        let mut value = fixture();
        value["qualification"]["ground_truth_complete"] = json!(false);
        root.publish(&value);
        assert!(root.read("qualification")["data"]["counts"]["missed_incidents"].is_null());
        value["qualification"]["ground_truth_complete"] = json!(true);
        value["qualification"]["finding_reviews"][1]["classification"] = json!("unreviewed");
        root.publish(&value);
        let q = root.read("qualification")["data"].clone();
        assert!(q["counts"]["missed_incidents"].is_null());
        assert_eq!(q["counts"]["unreviewed_alerts"], 1);
        assert_eq!(q["false_alarm_fraction_among_reviewed_alerts"], 0.0);
    }

    #[test]
    fn several_positive_alerts_do_not_double_count_one_detected_incident() {
        let root = TestDirectory::new();
        let mut value = fixture();
        value["qualification"]["finding_reviews"][1] =
            json!({"finding_id": "f2", "classification": "true_positive", "incident_id": "i1"});
        root.publish(&value);
        let q = root.read("qualification")["data"].clone();
        assert_eq!(q["counts"]["true_positive_alerts"], 2);
        assert_eq!(q["counts"]["detected_distinct_incidents"], 1);
        assert_eq!(q["counts"]["missed_incidents"], 1);
    }

    #[test]
    fn abstentions_remain_separate_and_do_not_count_as_incident_detection() {
        let root = TestDirectory::new();
        let mut value = fixture();
        value["findings"][1]["decision"] = json!("abstain");
        value["qualification"]["finding_reviews"]
            .as_array_mut()
            .unwrap()
            .pop();
        root.publish(&value);
        let q = root.read("qualification")["data"].clone();
        assert_eq!(q["counts"]["alert_findings"], 1);
        assert_eq!(q["counts"]["abstentions"], 1);
        assert_eq!(q["counts"]["missed_incidents"], 1);
        assert_eq!(q["counts"]["detected_distinct_incidents"], 1);
    }

    #[test]
    fn references_versions_duplicate_ids_and_unknown_fields_fail_closed() {
        let root = TestDirectory::new();
        let mut mutations = Vec::new();
        let mut value = fixture();
        value["schema"] = json!("ostadix.watcher-snapshot/v0");
        mutations.push(value);
        let mut value = fixture();
        value["findings"][0]["measurement_ids"] = json!(["missing"]);
        mutations.push(value);
        let mut value = fixture();
        value["proposed_actions"][0]["finding_ids"] = json!(["missing"]);
        mutations.push(value);
        let mut value = fixture();
        value["findings"][1]["id"] = json!("f1");
        mutations.push(value);
        let mut value = fixture();
        value["qualification"]["finding_reviews"][0]["incident_id"] = json!("missing");
        mutations.push(value);
        let mut value = fixture();
        value["qualification"]["finding_reviews"][1]["finding_id"] = json!("f1");
        mutations.push(value);
        let mut value = fixture();
        value["qualification"]["finding_reviews"][1]["incident_id"] = json!("i1");
        mutations.push(value);
        let mut value = fixture();
        value["measurements"][0]["evidence"]["sha256"] = json!("not-a-digest");
        mutations.push(value);
        let mut value = fixture();
        value["proposed_actions"][0]["state"] = json!("executed");
        mutations.push(value);
        let mut value = fixture();
        value["private_extra"] = json!("do-not-publish-this");
        mutations.push(value);
        let mut value = fixture();
        value["measurements"][0]["value"] = json!({"unbounded": "nested-data"});
        mutations.push(value);
        for value in mutations {
            root.publish(&value);
            let response = root.read("measurements");
            assert_eq!(response["status"], "unavailable");
            assert_eq!(response["reason"], "snapshot_schema_or_references_invalid");
            assert!(response["data"].is_null());
            assert!(!response.to_string().contains("do-not-publish-this"));
        }
    }

    #[test]
    fn missing_malformed_and_oversized_files_have_bounded_sanitized_errors() {
        let root = TestDirectory::new();
        assert_eq!(root.read("measurements")["reason"], "snapshot_missing");
        fs::write(root.0.join(SNAPSHOT_FILE), b"private-invalid-json").unwrap();
        let value = root.read("measurements");
        assert!(!value.to_string().contains("private-invalid-json"));
        fs::write(
            root.0.join(SNAPSHOT_FILE),
            vec![b' '; (MAX_SNAPSHOT_BYTES + 1) as usize],
        )
        .unwrap();
        assert_eq!(root.read("measurements")["reason"], "snapshot_too_large");
        assert_eq!(
            read_from_root(RESOURCES[0].0, Some(Path::new("relative"))).unwrap()["reason"],
            "invalid_configuration"
        );
    }

    #[test]
    fn no_alerts_and_no_ground_truth_has_no_invented_rate_denominator() {
        let root = TestDirectory::new();
        let mut value = fixture();
        value["findings"] = json!([]);
        value["proposed_actions"] = json!([]);
        value["qualification"]["ground_truth_incidents"] = json!([]);
        value["qualification"]["finding_reviews"] = json!([]);
        root.publish(&value);
        let q = root.read("qualification")["data"].clone();
        assert_eq!(q["counts"]["missed_incidents"], 0);
        assert!(q["false_alarm_fraction_among_reviewed_alerts"].is_null());
        assert!(q["missed_incident_fraction"].is_null());
        assert_eq!(q["status"], "producer_reported_evaluation");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_directories_and_fifos_are_not_read_as_snapshots() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        let root = TestDirectory::new();
        let elsewhere = TestDirectory::new();
        elsewhere.publish(&fixture());
        let path = root.0.join(SNAPSHOT_FILE);
        symlink(elsewhere.0.join(SNAPSHOT_FILE), &path).unwrap();
        assert_eq!(
            root.read("measurements")["reason"],
            "snapshot_not_regular_or_is_symlink"
        );
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert_eq!(
            root.read("measurements")["reason"],
            "snapshot_not_regular_or_is_symlink"
        );
        fs::remove_dir(&path).unwrap();
        let path_c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
        assert_eq!(
            root.read("measurements")["reason"],
            "snapshot_not_regular_or_is_symlink"
        );
    }
}
