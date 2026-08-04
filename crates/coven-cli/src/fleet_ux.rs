//! Redacted, read-only fleet projection for untrusted presentation clients.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    api::{current_timestamp, json_response, ApiResponse},
    result_integration::DelegationResultBundle,
    session_authority::RoamRecord,
    STORE_FILE_NAME,
};

pub const PROTOCOL_VERSION: &str = "coven.fleet-ux.v1";
const MAX_NODES: usize = 256;
const MAX_DELEGATIONS: usize = 256;
const MAX_MATRICES: usize = 64;
const MAX_LANES: usize = 128;
const MAX_CAPABILITY_NAMES: usize = 32;
const NODE_FRESHNESS_SECONDS: i64 = 90;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FleetUxSnapshot {
    protocol_version: &'static str,
    generated_at: String,
    snapshot_digest: String,
    health: HealthSummary,
    nodes: Vec<NodeSummary>,
    delegations: Vec<DelegationSummary>,
    matrices: Vec<MatrixSummary>,
    roams: Vec<RoamSummary>,
    truncated: TruncationSummary,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthSummary {
    online: usize,
    busy: usize,
    stale: usize,
    offline: usize,
    failed: usize,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct TruncationSummary {
    nodes: bool,
    delegations: bool,
    matrices: bool,
    lanes: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeSummary {
    node_id: String,
    status: String,
    last_seen_at: String,
    queue_pressure_band: &'static str,
    current_platform: CurrentPlatform,
    harnesses: Vec<String>,
    workspace_drivers: Vec<String>,
    runtime_names: Vec<String>,
    active_work_count: usize,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct CurrentPlatform {
    os: String,
    architecture: String,
    version: Option<String>,
    gpu: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DelegationSummary {
    delegation_id: String,
    parent_session_id: Option<String>,
    state: String,
    selected_node_id: Option<String>,
    claimed_platform: Option<ClaimedPlatform>,
    integration: IntegrationSummary,
    failure: Option<FailureSummary>,
    actions: Vec<&'static str>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaimedPlatform {
    os: String,
    architecture: String,
    version: Option<String>,
    gpu: bool,
    runtime_names: Vec<String>,
    observation_digest: String,
    result_digest: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct IntegrationSummary {
    state: &'static str,
    conflict_code: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FailureSummary {
    code: String,
    category: &'static str,
    retryable: bool,
    user_message: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MatrixSummary {
    matrix_id: String,
    state: String,
    counts: MatrixCounts,
    partial: bool,
    lanes: Vec<MatrixLaneSummary>,
    summary_digest: String,
    actions: Vec<&'static str>,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct MatrixCounts {
    total: usize,
    succeeded: usize,
    failed: usize,
    pending: usize,
    conflicted: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MatrixLaneSummary {
    axis_key: String,
    state: String,
    selected_node_id: Option<String>,
    claimed_platform: Option<ClaimedPlatform>,
    failure: Option<FailureSummary>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoamSummary {
    session_id: String,
    generation: u64,
    state: String,
    source_node_id: String,
    target_node_id: Option<String>,
    phase: String,
    updated_at: String,
    failure: Option<FailureSummary>,
    actions: Vec<&'static str>,
}

pub fn snapshot(coven_home: &Path, session_id: Option<&str>) -> Result<ApiResponse> {
    if session_id.is_some_and(|id| !valid_id(id)) {
        return crate::api::api_error(400, "invalid_session_id", "sessionId is invalid.", None);
    }
    let mut conn = Connection::open(coven_home.join(STORE_FILE_NAME))?;
    let tx = conn.transaction()?;
    let mut truncated = TruncationSummary::default();
    let nodes = read_nodes(&tx, &mut truncated)?;
    let delegations = read_delegations(&tx, session_id, &mut truncated)?;
    let matrices = read_matrices(&tx, session_id, &mut truncated)?;
    let roams = read_roams(&tx, session_id)?;
    let health = health(&nodes, &delegations, &matrices, &roams);
    let mut value = FleetUxSnapshot {
        protocol_version: PROTOCOL_VERSION,
        generated_at: current_timestamp(),
        snapshot_digest: String::new(),
        health,
        nodes,
        delegations,
        matrices,
        roams,
        truncated,
    };
    let mut canonical = serde_json::to_value(&value)?;
    canonical.as_object_mut().unwrap().remove("generatedAt");
    canonical.as_object_mut().unwrap().remove("snapshotDigest");
    value.snapshot_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&canonical)?));
    tx.commit()?;
    json_response(200, &value)
}

fn read_nodes(tx: &Transaction<'_>, truncated: &mut TruncationSummary) -> Result<Vec<NodeSummary>> {
    if !table_exists(tx, "node_registry")? {
        return Ok(Vec::new());
    }
    let columns = columns(tx, "node_registry")?;
    let observation = if columns.contains("capability_observation_json") {
        "capability_observation_json"
    } else {
        "'{}'"
    };
    let revoked = if columns.contains("revoked_at") {
        "revoked_at"
    } else {
        "NULL"
    };
    let lease_expires = if columns.contains("fleet_lease_expires_at") {
        "fleet_lease_expires_at"
    } else {
        "NULL"
    };
    let capabilities_observed = if columns.contains("capabilities_observed_at") {
        "capabilities_observed_at"
    } else {
        "last_health_at"
    };
    let sql = format!("SELECT node_id,available,queue_pressure,last_health_at,{revoked},{observation},{lease_expires},{capabilities_observed} FROM node_registry ORDER BY node_id LIMIT {}", MAX_NODES + 1);
    let mut statement = tx.prepare(&sql)?;
    let active_counts = active_work_counts(tx)?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, bool>(1)?,
            row.get::<_, u32>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;
    let mut result = Vec::new();
    for row in rows {
        let (
            node_id,
            available,
            pressure,
            last_seen,
            revoked_at,
            raw,
            lease_expires_at,
            capabilities_observed_at,
        ) = row?;
        let capabilities = serde_json::from_str::<Value>(&raw).unwrap_or(Value::Null);
        let platform = &capabilities["platform"];
        let now = chrono::Utc::now();
        let stale_lease = lease_expires_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .is_none_or(|expires| expires <= now);
        let stale_observation = capabilities_observed_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .is_none_or(|observed| {
                observed + chrono::Duration::seconds(NODE_FRESHNESS_SECONDS) <= now
            });
        let stale = stale_lease || stale_observation;
        let status = if revoked_at.is_some() || !available {
            "offline"
        } else if stale {
            "stale"
        } else if active_counts.get(&node_id).copied().unwrap_or(0) > 0 {
            "busy"
        } else {
            "online"
        };
        result.push(NodeSummary {
            node_id: node_id.clone(),
            status: status.into(),
            last_seen_at: last_seen,
            queue_pressure_band: pressure_band(pressure),
            current_platform: CurrentPlatform {
                os: safe_platform(platform["os"].as_str()),
                architecture: safe_platform(platform["architecture"].as_str()),
                version: safe_optional(platform["version"].as_str(), 64),
                gpu: capabilities["gpu"].is_object(),
            },
            harnesses: safe_names(&capabilities["harnesses"]),
            workspace_drivers: safe_names(&capabilities["workspaceDrivers"]),
            runtime_names: capabilities["runtimes"]
                .as_object()
                .map(|v| bounded_names(v.keys().cloned()))
                .unwrap_or_default(),
            active_work_count: active_counts.get(&node_id).copied().unwrap_or(0),
        });
    }
    if result.len() > MAX_NODES {
        result.truncate(MAX_NODES);
        truncated.nodes = true;
    }
    Ok(result)
}

fn read_delegations(
    tx: &Transaction<'_>,
    session_id: Option<&str>,
    truncated: &mut TruncationSummary,
) -> Result<Vec<DelegationSummary>> {
    if !table_exists(tx, "fleet_delegations")? {
        return Ok(Vec::new());
    }
    let sql = "SELECT delegation_id,parent_session_id,state,assigned_node_id,preview_json,failure_json FROM fleet_delegations WHERE (?1 IS NULL OR parent_session_id=?1) ORDER BY delegation_id LIMIT ?2";
    let mut statement = tx.prepare(sql)?;
    let rows = statement.query_map(params![session_id, (MAX_DELEGATIONS + 1) as i64], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
        ))
    })?;
    let mut result = Vec::new();
    for row in rows {
        let (id, parent, state, node, preview, failure) = row?;
        let normalized = delegation_state(&state).to_string();
        let (claimed, _) = claimed_platform(tx, &id)?;
        let conflict_code = preview
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|v| v["conflict"]["code"].as_str().map(redacted_code));
        result.push(DelegationSummary {
            delegation_id: id,
            parent_session_id: parent,
            state: normalized.clone(),
            selected_node_id: node,
            claimed_platform: claimed,
            integration: IntegrationSummary {
                state: integration_state(&normalized),
                conflict_code,
            },
            failure: failure_summary(failure.as_deref()),
            actions: delegation_actions(&normalized),
        });
    }
    if result.len() > MAX_DELEGATIONS {
        result.truncate(MAX_DELEGATIONS);
        truncated.delegations = true;
    }
    Ok(result)
}

fn claimed_platform(
    tx: &Transaction<'_>,
    delegation_id: &str,
) -> Result<(Option<ClaimedPlatform>, Option<String>)> {
    if !table_exists(tx, "fleet_delegation_results")? {
        return Ok((None, None));
    }
    let row: Option<(String, String)> = tx
        .query_row(
            "SELECT result_digest,bundle_json FROM fleet_delegation_results WHERE delegation_id=?1",
            params![delegation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((result_digest, raw)) = row else {
        return Ok((None, None));
    };
    let bundle: DelegationResultBundle = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Ok((None, Some(result_digest))),
    };
    let Some(platform) = bundle.artifacts.first().map(|a| &a.platform) else {
        return Ok((None, Some(result_digest)));
    };
    Ok((
        Some(ClaimedPlatform {
            os: safe_platform(Some(&platform.os)),
            architecture: safe_platform(Some(&platform.architecture)),
            version: safe_optional(platform.platform_version.as_deref(), 64),
            gpu: platform.gpu.is_some(),
            runtime_names: bounded_names(platform.runtimes.keys().cloned()),
            observation_digest: platform.placement_observation_digest.clone(),
            result_digest: result_digest.clone(),
        }),
        Some(result_digest),
    ))
}

fn read_matrices(
    tx: &Transaction<'_>,
    session_id: Option<&str>,
    truncated: &mut TruncationSummary,
) -> Result<Vec<MatrixSummary>> {
    if !table_exists(tx, "fleet_delegation_matrices")?
        || !table_exists(tx, "fleet_delegation_matrix_lanes")?
    {
        return Ok(Vec::new());
    }
    let mut statement = tx.prepare(
        "SELECT matrix_id,request_json FROM fleet_delegation_matrices ORDER BY matrix_id LIMIT ?1",
    )?;
    let rows = statement.query_map(params![(MAX_MATRICES + 1) as i64], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut result = Vec::new();
    for row in rows {
        let (matrix_id, raw) = row?;
        let request: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        if session_id.is_some() && request["parentSessionId"].as_str() != session_id {
            continue;
        }
        let allow_partial = request["failurePolicy"]["mode"] == "allowPartial";
        let minimum = request["failurePolicy"]["minSuccessful"]
            .as_u64()
            .map(|v| v as usize);
        let mut lanes = read_lanes(tx, &matrix_id, truncated)?;
        lanes.sort_by(|a, b| a.axis_key.cmp(&b.axis_key));
        let counts = matrix_counts(&lanes);
        let required = if allow_partial {
            minimum.unwrap_or(lanes.len())
        } else {
            lanes.len()
        };
        let state = if counts.pending > 0 {
            "pending"
        } else if counts.succeeded < required {
            "failed"
        } else if counts.succeeded < lanes.len() {
            "ready_partial"
        } else {
            "ready"
        };
        let partial = state == "ready_partial";
        let canonical = serde_json::json!({"matrixId":matrix_id,"state":state,"counts":&counts,"partial":partial,"lanes":&lanes});
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&canonical)?));
        result.push(MatrixSummary {
            matrix_id,
            state: state.into(),
            counts,
            partial,
            lanes,
            summary_digest: digest,
            actions: vec![],
        });
    }
    if result.len() > MAX_MATRICES {
        result.truncate(MAX_MATRICES);
        truncated.matrices = true
    }
    Ok(result)
}

fn read_lanes(
    tx: &Transaction<'_>,
    matrix_id: &str,
    truncated: &mut TruncationSummary,
) -> Result<Vec<MatrixLaneSummary>> {
    let mut statement=tx.prepare("SELECT l.axis_key,l.delegation_id,d.state,d.assigned_node_id,d.failure_json FROM fleet_delegation_matrix_lanes l JOIN fleet_delegations d ON d.delegation_id=l.delegation_id WHERE l.matrix_id=?1 ORDER BY l.ordinal LIMIT ?2")?;
    let rows = statement.query_map(params![matrix_id, (MAX_LANES + 1) as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })?;
    let mut lanes = Vec::new();
    for row in rows {
        let (axis, id, state, node, failure) = row?;
        let (claimed, _) = claimed_platform(tx, &id)?;
        lanes.push(MatrixLaneSummary {
            axis_key: axis,
            state: delegation_state(&state).into(),
            selected_node_id: node,
            claimed_platform: claimed,
            failure: failure_summary(failure.as_deref()),
        })
    }
    if lanes.len() > MAX_LANES {
        lanes.truncate(MAX_LANES);
        truncated.lanes = true
    }
    Ok(lanes)
}

fn read_roams(tx: &Transaction<'_>, session_id: Option<&str>) -> Result<Vec<RoamSummary>> {
    if !table_exists(tx, "session_roams")? {
        return Ok(Vec::new());
    }
    let mut statement=tx.prepare("SELECT session_id,record_json,updated_at FROM session_roams WHERE (?1 IS NULL OR session_id=?1) ORDER BY session_id LIMIT 257")?;
    let rows = statement.query_map(params![session_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut result = Vec::new();
    for row in rows {
        let (id, raw, updated) = row?;
        let Ok(record) = serde_json::from_str::<RoamRecord>(&raw) else {
            result.push(RoamSummary {
                session_id: id,
                generation: 0,
                state: "unknown".into(),
                source_node_id: "unknown".into(),
                target_node_id: None,
                phase: "unknown".into(),
                updated_at: updated,
                failure: None,
                actions: vec![],
            });
            continue;
        };
        let state = roam_state(record.state.as_str());
        let failure = if state == "failed" {
            roam_failure(tx, &id)?.or_else(|| Some(unknown_failure()))
        } else {
            None
        };
        result.push(RoamSummary {
            session_id: id,
            generation: record.generation,
            state: state.into(),
            source_node_id: record.source_node_id,
            target_node_id: record.target_node_id,
            phase: state.into(),
            updated_at: updated,
            failure,
            actions: if state == "failed" {
                vec!["retry"]
            } else {
                vec![]
            },
        })
    }
    result.truncate(256);
    Ok(result)
}

fn roam_failure(tx: &Transaction<'_>, session_id: &str) -> Result<Option<FailureSummary>> {
    if !table_exists(tx, "session_roam_sagas")? {
        return Ok(None);
    }
    let raw: Option<String> = tx
        .query_row(
            "SELECT error_json FROM session_roam_sagas WHERE session_id=?1 AND error_json IS NOT NULL ORDER BY generation DESC LIMIT 1",
            params![session_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(failure_summary(raw.as_deref()))
}

fn active_work_counts(tx: &Transaction<'_>) -> Result<BTreeMap<String, usize>> {
    let mut result = BTreeMap::new();
    if !table_exists(tx, "hub_jobs")? {
        return Ok(result);
    }
    let mut s=tx.prepare("SELECT assigned_node_id,COUNT(*) FROM hub_jobs WHERE state='leased' AND assigned_node_id IS NOT NULL GROUP BY assigned_node_id")?;
    for row in s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (id, count) = row?;
        result.insert(id, count.max(0) as usize);
    }
    Ok(result)
}
fn matrix_counts(lanes: &[MatrixLaneSummary]) -> MatrixCounts {
    let pending = lanes
        .iter()
        .filter(|l| matches!(l.state.as_str(), "queued" | "running" | "cleanup_pending"))
        .count();
    let failed = lanes
        .iter()
        .filter(|l| matches!(l.state.as_str(), "failed" | "cancelled" | "unknown"))
        .count();
    let conflicted = lanes.iter().filter(|l| l.state == "conflicted").count();
    MatrixCounts {
        total: lanes.len(),
        succeeded: lanes.len() - pending - failed,
        failed,
        pending,
        conflicted,
    }
}
fn health(
    nodes: &[NodeSummary],
    delegations: &[DelegationSummary],
    matrices: &[MatrixSummary],
    roams: &[RoamSummary],
) -> HealthSummary {
    HealthSummary {
        online: nodes.iter().filter(|n| n.status == "online").count(),
        busy: nodes.iter().filter(|n| n.status == "busy").count(),
        stale: nodes.iter().filter(|n| n.status == "stale").count(),
        offline: nodes.iter().filter(|n| n.status == "offline").count(),
        failed: delegations.iter().filter(|v| v.state == "failed").count()
            + matrices.iter().filter(|v| v.state == "failed").count()
            + roams.iter().filter(|v| v.state == "failed").count(),
    }
}
fn table_exists(tx: &Transaction<'_>, name: &str) -> Result<bool> {
    Ok(tx
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            params![name],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}
fn columns(tx: &Transaction<'_>, table: &str) -> Result<BTreeSet<String>> {
    let mut s = tx.prepare(&format!("PRAGMA table_info({table})"))?;
    let values = s
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(values)
}
fn safe_names(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| bounded_names(a.iter().filter_map(Value::as_str).map(str::to_string)))
        .unwrap_or_default()
}
fn bounded_names(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v = values
        .into_iter()
        .filter(|s| valid_name(s))
        .collect::<Vec<_>>();
    v.sort();
    v.dedup();
    v.truncate(MAX_CAPABILITY_NAMES);
    v
}
fn safe_platform(v: Option<&str>) -> String {
    v.filter(|s| valid_name(s))
        .unwrap_or("unknown")
        .to_ascii_lowercase()
}
fn safe_optional(v: Option<&str>, max: usize) -> Option<String> {
    v.filter(|s| !s.is_empty() && s.len() <= max && s.chars().all(|c| !c.is_control()))
        .map(str::to_string)
}
fn valid_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn valid_id(v: &str) -> bool {
    valid_name(v)
}
fn pressure_band(v: u32) -> &'static str {
    match v {
        0 => "idle",
        1..=25 => "low",
        26..=75 => "medium",
        _ => "high",
    }
}
fn delegation_state(v: &str) -> &'static str {
    match v {
        "queued" => "queued",
        "cancel_requested" => "running",
        "ready_to_integrate" => "ready",
        "integrated" | "finalized" => "completed",
        "applying" => "running",
        "conflicted" | "recovery_conflict" => "conflicted",
        "cleanup_queued" | "cancel_cleanup_queued" | "failure_cleanup_queued" => "cleanup_pending",
        "cancelled" => "cancelled",
        "failed" => "failed",
        _ => "unknown",
    }
}
fn integration_state(v: &str) -> &'static str {
    match v {
        "ready" => "ready",
        "completed" => "applied",
        "conflicted" => "conflicted",
        _ => "not_ready",
    }
}
fn delegation_actions(v: &str) -> Vec<&'static str> {
    match v {
        "ready" => vec!["integrate", "cancel"],
        "conflicted" => vec!["cancel", "review"],
        _ => vec![],
    }
}
fn roam_state(v: &str) -> &'static str {
    match v {
        "preparing" => "preparing",
        "checkpointed" => "checkpointed",
        "restoring" => "restoring",
        "starting" => "starting",
        "active" => "active",
        "failed" => "failed",
        "cancelled" => "cancelled",
        _ => "unknown",
    }
}
fn redacted_code(v: &str) -> String {
    if valid_name(v) {
        v.to_ascii_lowercase()
    } else {
        "unknown".into()
    }
}
fn failure_summary(raw: Option<&str>) -> Option<FailureSummary> {
    let value: Value = serde_json::from_str(raw?).ok()?;
    Some(failure_from_code(
        value["code"].as_str().unwrap_or("unknown"),
    ))
}
fn failure_from_code(code: &str) -> FailureSummary {
    match code {
        "execution_failed" => FailureSummary {
            code: code.into(),
            category: "execution",
            retryable: true,
            user_message: "Execution failed on the selected executor.",
        },
        "lease_expired" => FailureSummary {
            code: code.into(),
            category: "availability",
            retryable: true,
            user_message: "The executor lease expired.",
        },
        _ => unknown_failure(),
    }
}
fn unknown_failure() -> FailureSummary {
    FailureSummary {
        code: "unknown_failure".into(),
        category: "unknown",
        retryable: false,
        user_message: "Fleet work failed. Review daemon diagnostics.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;

    const SECRET: &str = "UX_CANARY_SECRET_TOKEN";
    const PATH_CANARY: &str = "/private/ux-canary/workspace";
    const URL_CANARY: &str = "https://storage.invalid/presigned?credential=UX_CANARY";

    fn add_column(conn: &Connection, sql: &str) {
        let _ = conn.execute(sql, []);
    }

    fn fixture() -> Result<tempfile::TempDir> {
        let home = tempfile::tempdir()?;
        let conn = store::open_store(&home.path().join(STORE_FILE_NAME))?;
        add_column(
            &conn,
            "ALTER TABLE node_registry ADD COLUMN capability_observation_json TEXT",
        );
        add_column(
            &conn,
            "ALTER TABLE node_registry ADD COLUMN revoked_at TEXT",
        );
        add_column(
            &conn,
            "ALTER TABLE node_registry ADD COLUMN fleet_lease_expires_at TEXT",
        );
        add_column(
            &conn,
            "ALTER TABLE node_registry ADD COLUMN capabilities_observed_at TEXT",
        );
        let capabilities = |os: &str, arch: &str| {
            serde_json::json!({
            "protocols":{"executor":[1]}, "platform":{"os":os,"architecture":arch,"version":"proof"},
            "gpu":null,"runtimes":{"node":["24.0.0"]},"harnesses":["fake"],
            "workspaceDrivers":["filesystem"],"tools":[]
        }).to_string()
        };
        for (id, os, arch, pressure) in [
            ("node-z", "windows", "x86_64", 80),
            ("node-a", "linux", "aarch64", 0),
        ] {
            conn.execute("INSERT INTO node_registry(node_id,role,transport,transport_config_json,capabilities_json,available,queue_pressure,last_health_at,last_error,registered_at,updated_at,capability_observation_json,capabilities_observed_at,fleet_lease_expires_at) VALUES(?1,'compute-executor','fleet-pull',?2,'[]',1,?3,'2026-01-01T00:00:00Z',?2,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',?4,'2999-01-01T00:00:00Z','2999-01-01T00:00:00Z')",params![id,SECRET,pressure,capabilities(os,arch)])?;
        }
        conn.execute(
            "UPDATE node_registry SET capabilities_observed_at='2026-01-01T00:00:00Z' WHERE node_id='node-z'",
            [],
        )?;
        conn.execute("INSERT INTO hub_jobs(job_id,state,priority,required_capabilities_json,assigned_node_id,target_node_id,loop_id,payload_json,created_at,updated_at) VALUES('job-secret','leased',0,'{}','node-a',NULL,NULL,?1,'2026-01-01','2026-01-01')",params![format!("{{\"task\":\"{SECRET}\"}}")])?;
        conn.execute_batch("CREATE TABLE fleet_delegations(delegation_id TEXT PRIMARY KEY,parent_session_id TEXT,state TEXT,assigned_node_id TEXT,preview_json TEXT,failure_json TEXT);
            CREATE TABLE fleet_delegation_results(delegation_id TEXT PRIMARY KEY,result_digest TEXT,bundle_json TEXT);
            CREATE TABLE fleet_delegation_matrices(matrix_id TEXT PRIMARY KEY,request_json TEXT);
            CREATE TABLE fleet_delegation_matrix_lanes(matrix_id TEXT,axis_key TEXT,ordinal INTEGER,delegation_id TEXT);")?;
        conn.execute("INSERT INTO fleet_delegations VALUES('delegation-z','session-other','queued',NULL,NULL,NULL)",[])?;
        conn.execute("INSERT INTO fleet_delegations VALUES('delegation-b','session-one','mystery_state','node-z',NULL,NULL)",[])?;
        conn.execute("INSERT INTO fleet_delegations VALUES('delegation-a','session-one','failed','node-a',NULL,?1)",params![serde_json::json!({"protocolVersion":"coven.fleet-failure.v1","code":"execution_failed","message":format!("{SECRET} {PATH_CANARY}")}).to_string()])?;
        conn.execute("INSERT INTO fleet_delegation_matrices VALUES('matrix-a',?1)",params![serde_json::json!({"parentSessionId":"session-one","task":SECRET,"baseCheckpoint":{"locator":URL_CANARY},"failurePolicy":{"mode":"allRequired"}}).to_string()])?;
        conn.execute("INSERT INTO fleet_delegation_matrix_lanes VALUES('matrix-a','axis-a',0,'delegation-a')",[])?;
        conn.execute("INSERT INTO sessions(id,project_root,harness,title,status,created_at,updated_at) VALUES('session-one',?1,'fake','proof','running','2026-01-01','2026-01-01')",params![PATH_CANARY])?;
        let roam = serde_json::json!({"protocolVersion":"coven.roam.v1","sessionId":"session-one","generation":2,"state":"failed","sourceNodeId":"node-a","targetNodeId":"node-z","sourceHarness":"fake","targetHarness":"fake","workspace":{"driver":"s3-checkpoint","locator":{"getUrl":URL_CANARY}},"handoffEventId":null,"checkpointRef":{"locator":URL_CANARY},"dispatchJobId":"job-secret","error":SECRET,"createdAt":"2026-01-01","updatedAt":"2026-01-01"});
        conn.execute("INSERT INTO session_roams(session_id,generation,state,record_json,updated_at) VALUES('session-one',2,'failed',?1,'2026-01-01')",params![roam.to_string()])?;
        Ok(home)
    }

    fn document(home: &Path, session: Option<&str>) -> Result<Value> {
        let response = snapshot(home, session)?;
        assert_eq!(response.status, 200);
        Ok(serde_json::from_str(&response.body)?)
    }

    #[test]
    fn snapshot_schema_is_redacted_bounded_and_fail_closed() -> Result<()> {
        let home = fixture()?;
        let value = document(home.path(), Some("session-one"))?;
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "protocolVersion",
                "generatedAt",
                "snapshotDigest",
                "health",
                "nodes",
                "delegations",
                "matrices",
                "roams",
                "truncated"
            ])
        );
        assert_eq!(value["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(value["delegations"].as_array().unwrap().len(), 2);
        assert_eq!(value["delegations"][0]["delegationId"], "delegation-a");
        assert_eq!(
            value["delegations"][0]["failure"]["userMessage"],
            "Execution failed on the selected executor."
        );
        assert!(value["delegations"][0]["actions"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(value["delegations"][1]["state"], "unknown");
        assert!(value["delegations"][1]["actions"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(value["roams"][0]["actions"], serde_json::json!(["retry"]));
        let bytes = serde_json::to_string(&value)?;
        for forbidden in [
            SECRET,
            PATH_CANARY,
            URL_CANARY,
            "parentRepo",
            "jobId",
            "actorId",
            "leaseToken",
            "finalizationKey",
            "checkpointRef",
            "locator",
            "message",
        ] {
            assert!(!bytes.contains(forbidden), "leaked {forbidden}");
        }
        Ok(())
    }

    #[test]
    fn snapshot_is_deterministic_filtered_and_has_no_side_effects() -> Result<()> {
        let home = fixture()?;
        let db = home.path().join(STORE_FILE_NAME);
        let before = std::fs::read(&db)?;
        let first = document(home.path(), None)?;
        let second = document(home.path(), None)?;
        assert_eq!(first["snapshotDigest"], second["snapshotDigest"]);
        assert_eq!(first["nodes"][0]["nodeId"], "node-a");
        assert_eq!(first["nodes"][0]["status"], "busy");
        assert_eq!(first["nodes"][1]["nodeId"], "node-z");
        assert_eq!(first["nodes"][1]["status"], "stale");
        let filtered = document(home.path(), Some("session-one"))?;
        assert!(filtered["delegations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["parentSessionId"] == "session-one"));
        assert_eq!(
            before,
            std::fs::read(&db)?,
            "GET projection mutated SQLite state"
        );
        Ok(())
    }

    #[test]
    fn action_mapping_advertises_only_existing_authority_commands() {
        assert_eq!(delegation_actions("ready"), vec!["integrate", "cancel"]);
        assert_eq!(delegation_actions("conflicted"), vec!["cancel", "review"]);
        assert!(delegation_actions("failed").is_empty());
        assert!(delegation_actions("unknown").is_empty());
    }
}
