//! Hub-owned fan-out and aggregation of ordinary delegation children.
//!
//! A matrix is durable orchestration metadata, not another work queue. Every
//! lane is submitted, leased, executed, collected, and integrated through the
//! existing delegation and fleet authorities.

use crate::{api::current_timestamp, delegation, store, STORE_FILE_NAME};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "coven.delegation-matrix.v1";
pub const RESULT_PROTOCOL_VERSION: &str = "coven.delegation-matrix-result.v1";
const MAX_AXES: usize = 32;
const MAX_CAPABILITIES_PER_AXIS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum FailureMode {
    AllRequired,
    AllowPartial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailurePolicy {
    pub mode: FailureMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_successful: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MatrixAxis {
    pub key: String,
    #[serde(default)]
    pub requirements: Vec<String>,
    #[serde(default)]
    pub preferences: Vec<String>,
    pub result_locator: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MatrixRequest {
    pub protocol_version: String,
    #[serde(default)]
    pub matrix_id: Option<String>,
    #[serde(default)]
    pub parent_session_id: Option<String>,
    pub parent_repo: PathBuf,
    pub base_revision: String,
    pub task: String,
    pub workspace_driver: String,
    pub base_checkpoint: Value,
    pub axes: Vec<MatrixAxis>,
    #[serde(default = "default_harness")]
    pub harness: String,
    pub failure_policy: FailurePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixLaneStatus {
    pub axis_key: String,
    pub delegation_id: String,
    pub child_id: String,
    pub job_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<crate::result_integration::IntegrationPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<crate::fleet::FleetFailureEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platform_evidence: Vec<crate::result_integration::PlatformEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixCounts {
    pub total: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub pending: usize,
    pub conflicted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixStatus {
    pub protocol_version: String,
    pub matrix_id: String,
    pub base_revision: String,
    pub state: String,
    pub failure_policy: FailurePolicy,
    pub lanes: Vec<MatrixLaneStatus>,
    pub counts: MatrixCounts,
    pub partial: bool,
    pub aggregate_digest: String,
}

fn default_harness() -> String {
    "fake".into()
}

fn open(coven_home: &Path) -> Result<Connection> {
    let conn = store::open_store(&coven_home.join(STORE_FILE_NAME))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS fleet_delegation_matrices (
            matrix_id TEXT PRIMARY KEY NOT NULL,
            base_revision TEXT NOT NULL,
            request_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fleet_delegation_matrix_lanes (
            matrix_id TEXT NOT NULL,
            axis_key TEXT NOT NULL,
            ordinal INTEGER NOT NULL,
            delegation_id TEXT NOT NULL UNIQUE,
            PRIMARY KEY (matrix_id, axis_key),
            UNIQUE (matrix_id, ordinal),
            FOREIGN KEY (matrix_id) REFERENCES fleet_delegation_matrices(matrix_id)
        );",
    )?;
    Ok(conn)
}

pub fn start(coven_home: &Path, mut request: MatrixRequest) -> Result<MatrixStatus> {
    normalize_and_validate(&mut request)?;
    let matrix_id = request
        .matrix_id
        .clone()
        .unwrap_or_else(|| format!("mx_{}", Uuid::new_v4().simple()));
    validate_id(&matrix_id, "matrixId")?;
    request.matrix_id = Some(matrix_id.clone());
    let encoded = serde_json::to_string(&request)?;
    let now = current_timestamp();
    let mut conn = open(coven_home)?;
    let tx = conn.transaction()?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO fleet_delegation_matrices
         (matrix_id,base_revision,request_json,created_at,updated_at)
         VALUES (?1,?2,?3,?4,?4)",
        params![matrix_id, request.base_revision, encoded, now],
    )?;
    if inserted == 0 {
        let stored: String = tx.query_row(
            "SELECT request_json FROM fleet_delegation_matrices WHERE matrix_id=?1",
            params![matrix_id],
            |row| row.get(0),
        )?;
        if stored != encoded {
            bail!("matrix id replay changed immutable request fields");
        }
    }
    for (ordinal, axis) in request.axes.iter().enumerate() {
        let delegation_id = lane_delegation_id(&matrix_id, axis)?;
        let changed = tx.execute(
            "INSERT OR IGNORE INTO fleet_delegation_matrix_lanes
             (matrix_id,axis_key,ordinal,delegation_id) VALUES (?1,?2,?3,?4)",
            params![matrix_id, axis.key, i64::try_from(ordinal)?, delegation_id],
        )?;
        if changed == 0 {
            let stored: (i64, String) = tx.query_row(
                "SELECT ordinal,delegation_id FROM fleet_delegation_matrix_lanes
                 WHERE matrix_id=?1 AND axis_key=?2",
                params![matrix_id, axis.key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if stored != (i64::try_from(ordinal)?, delegation_id) {
                bail!("matrix lane replay changed immutable linkage");
            }
        }
    }
    tx.commit()?;
    ensure_children(coven_home, &request)?;
    status(coven_home, &matrix_id)
}

pub fn status(coven_home: &Path, matrix_id: &str) -> Result<MatrixStatus> {
    validate_id(matrix_id, "matrixId")?;
    let conn = open(coven_home)?;
    let raw: String = conn
        .query_row(
            "SELECT request_json FROM fleet_delegation_matrices WHERE matrix_id=?1",
            params![matrix_id],
            |row| row.get(0),
        )
        .context("delegation matrix was not found")?;
    let request: MatrixRequest = serde_json::from_str(&raw)?;
    let mut statement = conn.prepare(
        "SELECT axis_key,delegation_id FROM fleet_delegation_matrix_lanes
         WHERE matrix_id=?1 ORDER BY ordinal",
    )?;
    let links = statement
        .query_map(params![matrix_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let mut lanes = Vec::with_capacity(links.len());
    for (axis_key, delegation_id) in links {
        let child = delegation::status(coven_home, &delegation_id)?;
        let result: Option<(String, String)> = conn
            .query_row(
                "SELECT result_digest,bundle_json FROM fleet_delegation_results
                 WHERE delegation_id=?1",
                params![delegation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (result_digest, platform_evidence) = match result {
            Some((digest, raw)) => {
                let bundle: crate::result_integration::DelegationResultBundle =
                    serde_json::from_str(&raw)?;
                (
                    Some(digest),
                    bundle
                        .artifacts
                        .into_iter()
                        .map(|artifact| artifact.platform)
                        .collect(),
                )
            }
            None => (None, Vec::new()),
        };
        lanes.push(MatrixLaneStatus {
            axis_key,
            delegation_id,
            child_id: child.child_id,
            job_id: child.job_id,
            state: child.state,
            node_id: child.assigned_node_id,
            preview: child.preview,
            failure: child.failure,
            result_digest,
            platform_evidence,
        });
    }
    aggregate(
        matrix_id,
        &request.base_revision,
        &request.failure_policy,
        lanes,
    )
}

pub fn reconcile(coven_home: &Path, matrix_id: &str) -> Result<MatrixStatus> {
    let request = load_request(coven_home, matrix_id)?;
    ensure_children(coven_home, &request)?;
    for axis in &request.axes {
        let delegation_id = lane_delegation_id(matrix_id, axis)?;
        delegation::collect(coven_home, &delegation_id)?;
    }
    status(coven_home, matrix_id)
}

pub fn reconcile_all(coven_home: &Path) -> Result<()> {
    let conn = open(coven_home)?;
    let mut statement =
        conn.prepare("SELECT matrix_id FROM fleet_delegation_matrices ORDER BY matrix_id")?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    drop(conn);
    for matrix_id in ids {
        if let Err(error) = reconcile(coven_home, &matrix_id) {
            eprintln!("coven daemon: delegation matrix {matrix_id} recovery: {error:#}");
        }
    }
    Ok(())
}

fn load_request(coven_home: &Path, matrix_id: &str) -> Result<MatrixRequest> {
    let conn = open(coven_home)?;
    let raw: String = conn
        .query_row(
            "SELECT request_json FROM fleet_delegation_matrices WHERE matrix_id=?1",
            params![matrix_id],
            |row| row.get(0),
        )
        .context("delegation matrix was not found")?;
    Ok(serde_json::from_str(&raw)?)
}

fn ensure_children(coven_home: &Path, request: &MatrixRequest) -> Result<()> {
    let matrix_id = request
        .matrix_id
        .as_deref()
        .context("matrix omitted matrixId")?;
    for axis in &request.axes {
        delegation::start(
            coven_home,
            delegation::DelegationRequest {
                protocol_version: delegation::PROTOCOL_VERSION.into(),
                delegation_id: Some(lane_delegation_id(matrix_id, axis)?),
                parent_session_id: request.parent_session_id.clone(),
                parent_repo: request.parent_repo.clone(),
                base_revision: request.base_revision.clone(),
                task: request.task.clone(),
                workspace_driver: request.workspace_driver.clone(),
                base_checkpoint: request.base_checkpoint.clone(),
                result_locator: axis.result_locator.clone(),
                requirements: axis.requirements.clone(),
                preferences: axis.preferences.clone(),
                harness: request.harness.clone(),
            },
        )?;
    }
    Ok(())
}

fn normalize_and_validate(request: &mut MatrixRequest) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION {
        bail!("unsupported delegation matrix protocol");
    }
    if request.axes.is_empty() || request.axes.len() > MAX_AXES {
        bail!("delegation matrix must contain between 1 and {MAX_AXES} axes");
    }
    match request.failure_policy.mode {
        FailureMode::AllRequired if request.failure_policy.min_successful.is_some() => {
            bail!("allRequired does not accept minSuccessful")
        }
        FailureMode::AllowPartial => {
            let minimum = request
                .failure_policy
                .min_successful
                .context("allowPartial requires minSuccessful")?;
            if minimum == 0 || minimum > request.axes.len() {
                bail!("minSuccessful is outside the matrix bounds");
            }
        }
        _ => {}
    }
    for axis in &mut request.axes {
        validate_id(&axis.key, "axis key")?;
        if axis.requirements.len() > MAX_CAPABILITIES_PER_AXIS
            || axis.preferences.len() > MAX_CAPABILITIES_PER_AXIS
        {
            bail!("matrix axis capability input exceeds limits");
        }
        normalize_strings(&mut axis.requirements)?;
        normalize_strings(&mut axis.preferences)?;
    }
    request.axes.sort_by(|left, right| left.key.cmp(&right.key));
    if request
        .axes
        .windows(2)
        .any(|pair| pair[0].key == pair[1].key)
    {
        bail!("matrix axis keys must be unique");
    }
    Ok(())
}

fn normalize_strings(values: &mut Vec<String>) -> Result<()> {
    if values
        .iter()
        .any(|value| value.is_empty() || value.len() > 256)
    {
        bail!("matrix capability is invalid");
    }
    values.sort();
    values.dedup();
    Ok(())
}

fn lane_delegation_id(matrix_id: &str, axis: &MatrixAxis) -> Result<String> {
    let canonical = json!({
        "matrixId": matrix_id,
        "axisKey": axis.key,
        "requirements": axis.requirements,
        "preferences": axis.preferences,
    });
    let digest = Sha256::digest(serde_json::to_vec(&canonical)?);
    Ok(format!("mxdlg_{}", hex_prefix(&digest)))
}

fn aggregate(
    matrix_id: &str,
    base_revision: &str,
    policy: &FailurePolicy,
    mut lanes: Vec<MatrixLaneStatus>,
) -> Result<MatrixStatus> {
    lanes.sort_by(|left, right| left.axis_key.cmp(&right.axis_key));
    let pending = lanes
        .iter()
        .filter(|lane| lane_pending(&lane.state))
        .count();
    let failed = lanes.iter().filter(|lane| lane_failed(&lane.state)).count();
    let conflicted = lanes
        .iter()
        .filter(|lane| lane.state == "conflicted")
        .count();
    let succeeded = lanes.len() - pending - failed;
    let minimum = match policy.mode {
        FailureMode::AllRequired => lanes.len(),
        FailureMode::AllowPartial => policy.min_successful.unwrap_or(lanes.len()),
    };
    let state = if pending > 0 {
        "pending"
    } else if succeeded < minimum {
        "failed"
    } else if succeeded < lanes.len() {
        "ready_partial"
    } else {
        "ready"
    };
    let partial = pending == 0 && succeeded >= minimum && succeeded < lanes.len();
    let evidence: Vec<Value> = lanes
        .iter()
        .map(|lane| {
            json!({"axisKey":lane.axis_key,"delegationId":lane.delegation_id,
                "childId":lane.child_id,"jobId":lane.job_id,"state":lane.state,
                "nodeId":lane.node_id,"preview":lane.preview,"failure":lane.failure,
                "resultDigest":lane.result_digest,"platformEvidence":lane.platform_evidence})
        })
        .collect();
    let canonical = json!({"protocolVersion":RESULT_PROTOCOL_VERSION,"matrixId":matrix_id,
        "baseRevision":base_revision,"failurePolicy":policy,"lanes":evidence});
    let aggregate_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&canonical)?));
    Ok(MatrixStatus {
        protocol_version: RESULT_PROTOCOL_VERSION.into(),
        matrix_id: matrix_id.into(),
        base_revision: base_revision.into(),
        state: state.into(),
        failure_policy: policy.clone(),
        counts: MatrixCounts {
            total: lanes.len(),
            succeeded,
            failed,
            pending,
            conflicted,
        },
        lanes,
        partial,
        aggregate_digest,
    })
}

fn lane_pending(state: &str) -> bool {
    matches!(
        state,
        "queued"
            | "cancel_requested"
            | "applying"
            | "cleanup_queued"
            | "cancel_cleanup_queued"
            | "failure_cleanup_queued"
    )
}

fn lane_failed(state: &str) -> bool {
    matches!(state, "failed" | "cancelled" | "recovery_conflict")
}

fn validate_id(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{field} is invalid");
    }
    Ok(())
}

fn hex_prefix(digest: &[u8]) -> String {
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_integration::{
        ArtifactEvidence, DelegationResultBundle, PlatformEvidence, VerificationEvidence,
    };
    use std::process::Command;

    fn git(repo: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git").args(args).current_dir(repo).output()?;
        if !output.status.success() {
            bail!("git command failed")
        }
        Ok(String::from_utf8(output.stdout)?.trim().into())
    }

    fn git_raw(repo: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git").args(args).current_dir(repo).output()?;
        if !output.status.success() {
            bail!("git command failed")
        }
        Ok(String::from_utf8(output.stdout)?)
    }

    fn response_json(response: crate::api::ApiResponse, expected: u16) -> Result<Value> {
        assert_eq!(response.status, expected, "{}", response.body);
        Ok(serde_json::from_str(&response.body)?)
    }

    fn enroll_node(home: &Path, node_id: &str, capabilities: &Value) -> Result<String> {
        let issued = response_json(crate::fleet::issue_enrollment(home, Some("{}"))?, 201)?;
        let redeemed = response_json(
            crate::fleet::redeem_enrollment(
                home,
                Some(
                    &json!({
                        "enrollmentCode": issued["enrollmentCode"],
                        "nodeId": node_id,
                        "capabilities": capabilities,
                    })
                    .to_string(),
                ),
            )?,
            201,
        )?;
        Ok(redeemed["nodeSecret"].as_str().unwrap().into())
    }

    fn fixture() -> Result<(tempfile::TempDir, tempfile::TempDir, MatrixRequest)> {
        let home = tempfile::tempdir()?;
        let repo = tempfile::tempdir()?;
        git(repo.path(), &["init", "-q"])?;
        git(
            repo.path(),
            &["config", "user.email", "matrix@example.invalid"],
        )?;
        git(repo.path(), &["config", "user.name", "Matrix Test"])?;
        std::fs::write(repo.path().join("base.txt"), "base\n")?;
        git(repo.path(), &["add", "base.txt"])?;
        git(repo.path(), &["commit", "-qm", "base"])?;
        let request = MatrixRequest {
            protocol_version: PROTOCOL_VERSION.into(),
            matrix_id: Some("matrix-one".into()),
            parent_session_id: None,
            parent_repo: repo.path().into(),
            base_revision: git(repo.path(), &["rev-parse", "HEAD"])?,
            task: "work".into(),
            workspace_driver: "filesystem".into(),
            base_checkpoint: json!({}),
            axes: vec![
                MatrixAxis {
                    key: "windows".into(),
                    requirements: vec!["os:windows".into(), "arch:x86_64".into()],
                    preferences: vec!["gpu:nvidia".into()],
                    result_locator: json!({"path":"windows"}),
                },
                MatrixAxis {
                    key: "linux".into(),
                    requirements: vec!["os:linux".into(), "arch:x86_64".into(), "os:linux".into()],
                    preferences: vec![],
                    result_locator: json!({"path":"linux"}),
                },
            ],
            harness: "fake".into(),
            failure_policy: FailurePolicy {
                mode: FailureMode::AllRequired,
                min_successful: None,
            },
        };
        Ok((home, repo, request))
    }

    #[test]
    fn start_normalizes_order_and_replays_without_duplicate_children() -> Result<()> {
        let (home, _repo, request) = fixture()?;
        let first = start(home.path(), request.clone())?;
        assert_eq!(
            first
                .lanes
                .iter()
                .map(|lane| lane.axis_key.as_str())
                .collect::<Vec<_>>(),
            vec!["linux", "windows"]
        );
        let mut replay = request;
        replay.axes.reverse();
        replay.axes[1].requirements.reverse();
        let second = start(home.path(), replay)?;
        assert_eq!(first.aggregate_digest, second.aggregate_digest);
        let conn = open(home.path())?;
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM fleet_delegation_matrix_lanes",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM fleet_delegations", [], |row| row
                .get::<_, i64>(0))?,
            2
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM hub_jobs", [], |row| row
                .get::<_, i64>(0))?,
            2
        );
        Ok(())
    }

    fn lane(key: &str, state: &str) -> MatrixLaneStatus {
        MatrixLaneStatus {
            axis_key: key.into(),
            delegation_id: format!("d-{key}"),
            child_id: format!("c-{key}"),
            job_id: format!("j-{key}"),
            state: state.into(),
            node_id: None,
            preview: None,
            failure: None,
            result_digest: None,
            platform_evidence: vec![],
        }
    }

    #[test]
    fn aggregate_is_order_independent_and_partial_is_terminal_only() -> Result<()> {
        let policy = FailurePolicy {
            mode: FailureMode::AllowPartial,
            min_successful: Some(1),
        };
        let pending = aggregate(
            "m",
            "base",
            &policy,
            vec![lane("b", "failed"), lane("a", "queued")],
        )?;
        assert_eq!(pending.state, "pending");
        assert!(!pending.partial);
        let first = aggregate(
            "m",
            "base",
            &policy,
            vec![lane("b", "failed"), lane("a", "ready_to_integrate")],
        )?;
        let second = aggregate(
            "m",
            "base",
            &policy,
            vec![lane("a", "ready_to_integrate"), lane("b", "failed")],
        )?;
        assert_eq!(first.state, "ready_partial");
        assert!(first.partial);
        assert_eq!(first.aggregate_digest, second.aggregate_digest);
        assert_eq!(
            first.counts,
            MatrixCounts {
                total: 2,
                succeeded: 1,
                failed: 1,
                pending: 0,
                conflicted: 0
            }
        );
        let required = FailurePolicy {
            mode: FailureMode::AllRequired,
            min_successful: None,
        };
        assert_eq!(
            aggregate("m", "base", &required, first.lanes)?.state,
            "failed"
        );
        Ok(())
    }

    #[test]
    fn aggregate_retains_and_digests_lane_platform_evidence() -> Result<()> {
        let policy = FailurePolicy {
            mode: FailureMode::AllRequired,
            min_successful: None,
        };
        let mut linux = lane("linux", "ready_to_integrate");
        linux.result_digest = Some("result-linux".into());
        linux
            .platform_evidence
            .push(crate::result_integration::PlatformEvidence {
                os: "linux".into(),
                architecture: "x86_64".into(),
                platform_version: Some("test".into()),
                gpu: None,
                runtimes: std::collections::BTreeMap::from([("rust".into(), "1.95.0".into())]),
                placement_observation_digest: URL_SAFE_NO_PAD
                    .encode(Sha256::digest(b"linux-observation")),
            });
        let first = aggregate("m", "base", &policy, vec![linux.clone()])?;
        assert_eq!(first.lanes[0].platform_evidence[0].os, "linux");
        linux.platform_evidence[0].os = "windows".into();
        let changed = aggregate("m", "base", &policy, vec![linux])?;
        assert_ne!(first.aggregate_digest, changed.aggregate_digest);
        Ok(())
    }

    #[test]
    fn five_lane_heterogeneous_fan_out_is_completion_order_independent() -> Result<()> {
        let policy = FailurePolicy {
            mode: FailureMode::AllRequired,
            min_successful: None,
        };
        let specifications = [
            (
                "windows-x64",
                "node-win",
                "windows",
                "x86_64",
                "dotnet",
                "9.0",
            ),
            ("linux-gpu", "node-gpu", "linux", "x86_64", "cuda", "12.4"),
            (
                "macos-arm",
                "node-mac-arm",
                "macos",
                "aarch64",
                "xcode",
                "16.2",
            ),
            (
                "linux-arm",
                "node-linux-arm",
                "linux",
                "aarch64",
                "rust",
                "1.95.0",
            ),
            (
                "macos-intel",
                "node-mac-intel",
                "macos",
                "x86_64",
                "node",
                "24.0.0",
            ),
        ];
        // Deliberately model completion in a different order than axis key.
        let completion_order = specifications
            .into_iter()
            .map(|(axis, node, os, architecture, runtime, version)| {
                let mut completed = lane(axis, "ready_to_integrate");
                completed.node_id = Some(node.into());
                completed.result_digest =
                    Some(URL_SAFE_NO_PAD.encode(Sha256::digest(format!("result:{axis}:{node}"))));
                completed.platform_evidence = vec![crate::result_integration::PlatformEvidence {
                    os: os.into(),
                    architecture: architecture.into(),
                    platform_version: Some("proof-fixture".into()),
                    gpu: (axis == "linux-gpu").then(|| crate::result_integration::GpuEvidence {
                        vendor: "nvidia".into(),
                        model: "l4".into(),
                        driver_version: Some("550.54".into()),
                    }),
                    runtimes: std::collections::BTreeMap::from([(runtime.into(), version.into())]),
                    placement_observation_digest: URL_SAFE_NO_PAD
                        .encode(Sha256::digest(format!("observation:{axis}:{node}"))),
                }];
                completed
            })
            .collect::<Vec<_>>();

        let first = aggregate("matrix-five", "base", &policy, completion_order.clone())?;
        let mut opposite_completion_order = completion_order;
        opposite_completion_order.reverse();
        let second = aggregate("matrix-five", "base", &policy, opposite_completion_order)?;

        assert_eq!(first.state, "ready");
        assert!(!first.partial);
        assert_eq!(
            first.counts,
            MatrixCounts {
                total: 5,
                succeeded: 5,
                failed: 0,
                pending: 0,
                conflicted: 0,
            }
        );
        assert_eq!(first.aggregate_digest, second.aggregate_digest);
        assert_eq!(
            first
                .lanes
                .iter()
                .map(|lane| (
                    lane.axis_key.as_str(),
                    lane.node_id.as_deref().unwrap(),
                    lane.platform_evidence[0].os.as_str(),
                    lane.platform_evidence[0].architecture.as_str(),
                ))
                .collect::<Vec<_>>(),
            vec![
                ("linux-arm", "node-linux-arm", "linux", "aarch64"),
                ("linux-gpu", "node-gpu", "linux", "x86_64"),
                ("macos-arm", "node-mac-arm", "macos", "aarch64"),
                ("macos-intel", "node-mac-intel", "macos", "x86_64"),
                ("windows-x64", "node-win", "windows", "x86_64"),
            ]
        );
        assert_eq!(
            first
                .lanes
                .iter()
                .filter(|lane| lane.platform_evidence[0].gpu.is_some())
                .map(|lane| lane.axis_key.as_str())
                .collect::<Vec<_>>(),
            vec!["linux-gpu"]
        );
        Ok(())
    }

    #[test]
    fn five_lane_matrix_claims_matching_nodes_and_aggregates_bound_results() -> Result<()> {
        let (home, repo, mut request) = fixture()?;
        request.matrix_id = Some("matrix-five-integrated".into());
        request.axes = vec![
            MatrixAxis {
                key: "windows-x64".into(),
                requirements: vec!["os:windows".into(), "arch:x86_64".into()],
                preferences: vec![],
                result_locator: json!({"path":"windows-x64"}),
            },
            MatrixAxis {
                key: "linux-gpu".into(),
                requirements: vec![
                    "os:linux".into(),
                    "arch:x86_64".into(),
                    "gpu-vendor:nvidia".into(),
                ],
                preferences: vec![],
                result_locator: json!({"path":"linux-gpu"}),
            },
            MatrixAxis {
                key: "macos-arm".into(),
                requirements: vec!["os:macos".into(), "arch:aarch64".into()],
                preferences: vec![],
                result_locator: json!({"path":"macos-arm"}),
            },
            MatrixAxis {
                key: "linux-arm".into(),
                requirements: vec!["os:linux".into(), "arch:aarch64".into()],
                preferences: vec![],
                result_locator: json!({"path":"linux-arm"}),
            },
            MatrixAxis {
                key: "macos-intel".into(),
                requirements: vec!["os:macos".into(), "arch:x86_64".into()],
                preferences: vec![],
                result_locator: json!({"path":"macos-intel"}),
            },
        ];

        std::fs::write(repo.path().join("base.txt"), "delegated\n")?;
        let patch = git_raw(repo.path(), &["diff", "--binary", "--full-index"])?;
        git(repo.path(), &["checkout", "--", "base.txt"])?;
        let started = start(home.path(), request)?;

        let nodes = [
            ("linux-arm", "node-linux-arm", "linux", "aarch64", None),
            ("windows-x64", "node-win", "windows", "x86_64", None),
            ("macos-intel", "node-mac-intel", "macos", "x86_64", None),
            (
                "linux-gpu",
                "node-gpu",
                "linux",
                "x86_64",
                Some(("nvidia", "l4")),
            ),
            ("macos-arm", "node-mac-arm", "macos", "aarch64", None),
        ];
        let mut claimed = Vec::new();
        for (axis, node_id, os, architecture, gpu) in nodes {
            let mut capabilities = json!({
                "protocols": {"executor":[1], "workspaceDriver":[1], "harnessHost":[1]},
                "platform": {"os":os, "architecture":architecture, "version":"proof"},
                "resources": {"cpuCores":8, "memoryBytes":16000000000_u64},
                "runtimes": {"node":["24.0.0"]},
                "harnesses": ["fake"],
                "workspaceDrivers": ["filesystem"],
                "tools": []
            });
            if let Some((vendor, model)) = gpu {
                capabilities["gpu"] =
                    json!({"vendor":vendor,"model":model,"memoryBytes":24000000000_u64});
            }
            let node_credential = enroll_node(home.path(), node_id, &capabilities)?;
            let authorization = format!("Bearer {node_credential}");
            let claim = response_json(
                crate::fleet::claim_job(home.path(), node_id, Some(&authorization), 0)?,
                200,
            )?;
            let expected_job = started
                .lanes
                .iter()
                .find(|lane| lane.axis_key == axis)
                .unwrap();
            assert_eq!(claim["job"]["jobId"], expected_job.job_id);
            assert!(claim["job"]["requiredCapabilities"].is_object());
            assert_eq!(
                claim["job"]["payload"]["placementObservationDigest"]
                    .as_str()
                    .unwrap()
                    .len(),
                43
            );
            claimed.push((axis, node_id, os, architecture, gpu, authorization, claim));
        }

        // Complete in the reverse of claim order to exercise collection order independence.
        for (axis, node_id, os, architecture, gpu, authorization, claim) in
            claimed.into_iter().rev()
        {
            let job = &claim["job"];
            let observation = job["payload"]["placementObservationDigest"]
                .as_str()
                .unwrap();
            let mut bundle = DelegationResultBundle {
                protocol_version: crate::result_integration::RESULT_PROTOCOL_VERSION.into(),
                delegation_id: started
                    .lanes
                    .iter()
                    .find(|lane| lane.axis_key == axis)
                    .unwrap()
                    .delegation_id
                    .clone(),
                child_id: started
                    .lanes
                    .iter()
                    .find(|lane| lane.axis_key == axis)
                    .unwrap()
                    .child_id
                    .clone(),
                attempt_id: job["attemptId"].as_str().unwrap().into(),
                node_id: node_id.into(),
                base_revision: started.base_revision.clone(),
                post_workspace_revision: format!("checkpoint-{axis}"),
                patch: patch.clone(),
                patch_sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(patch.as_bytes())),
                artifacts: vec![ArtifactEvidence {
                    name: "workspace-checkpoint".into(),
                    sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(format!("artifact:{axis}"))),
                    size_bytes: 1,
                    platform: PlatformEvidence {
                        os: os.into(),
                        architecture: architecture.into(),
                        platform_version: Some("proof".into()),
                        gpu: gpu.map(|(vendor, model)| crate::result_integration::GpuEvidence {
                            vendor: vendor.into(),
                            model: model.into(),
                            driver_version: Some("proof".into()),
                        }),
                        runtimes: std::collections::BTreeMap::from([(
                            "node".into(),
                            "24.0.0".into(),
                        )]),
                        placement_observation_digest: observation.into(),
                    },
                }],
                verification: vec![VerificationEvidence {
                    command: "git diff --check".into(),
                    status: "passed".into(),
                }],
                memory_proposals: vec![],
                result_digest: String::new(),
            };
            bundle.result_digest = crate::result_integration::bundle_digest(&bundle)?;
            let completion = json!({
                "attemptId": job["attemptId"], "leaseToken": job["leaseToken"],
                "completionKey": format!("complete-{axis}"), "result": bundle,
            });
            response_json(
                crate::fleet::complete_job(
                    home.path(),
                    job["jobId"].as_str().unwrap(),
                    Some(&authorization),
                    Some(&completion.to_string()),
                )?,
                200,
            )?;
        }

        let aggregated = reconcile(home.path(), "matrix-five-integrated")?;
        assert_eq!(aggregated.state, "ready");
        assert_eq!(aggregated.counts.succeeded, 5);
        assert_eq!(aggregated.counts.total, 5);
        assert!(aggregated
            .lanes
            .iter()
            .all(|lane| lane.state == "ready_to_integrate"
                && lane.node_id.is_some()
                && lane.platform_evidence.len() == 1));
        assert_eq!(
            aggregated
                .lanes
                .iter()
                .filter(|lane| lane.platform_evidence[0].gpu.is_some())
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn replay_rejects_changed_immutable_axis() -> Result<()> {
        let (home, _repo, request) = fixture()?;
        start(home.path(), request.clone())?;
        let mut changed = request;
        changed.axes[0].result_locator = json!({"path":"changed"});
        assert!(start(home.path(), changed)
            .unwrap_err()
            .to_string()
            .contains("immutable request"));
        Ok(())
    }
}
