//! Hub-owned remote child delegation saga.

use crate::{
    api::current_timestamp,
    fleet,
    result_integration::{self, DelegationResultBundle, IntegrationPreview},
    store, STORE_FILE_NAME,
};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "coven.delegation.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationRequest {
    pub protocol_version: String,
    #[serde(default)]
    pub delegation_id: Option<String>,
    #[serde(default)]
    pub parent_session_id: Option<String>,
    pub parent_repo: PathBuf,
    pub base_revision: String,
    pub task: String,
    pub workspace_driver: String,
    pub base_checkpoint: Value,
    pub result_locator: Value,
    #[serde(default)]
    pub requirements: Vec<String>,
    #[serde(default)]
    pub preferences: Vec<String>,
    #[serde(default = "default_harness")]
    pub harness: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationStatus {
    pub protocol_version: String,
    pub delegation_id: String,
    pub child_id: String,
    pub job_id: String,
    pub state: String,
    pub base_revision: String,
    pub parent_repo: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<IntegrationPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalization_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_job_id: Option<String>,
    pub cleanup_acknowledged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<fleet::FleetFailureEvidence>,
}

fn default_harness() -> String {
    "fake".into()
}

fn open(coven_home: &Path) -> Result<Connection> {
    let conn = store::open_store(&coven_home.join(STORE_FILE_NAME))?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS fleet_delegations (
        delegation_id TEXT PRIMARY KEY NOT NULL, parent_session_id TEXT, child_id TEXT NOT NULL UNIQUE,
        child_job_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL, base_revision TEXT NOT NULL,
        parent_repo TEXT NOT NULL, assigned_node_id TEXT, request_json TEXT NOT NULL,
        preview_json TEXT, finalization_key TEXT, cleanup_job_id TEXT, failure_json TEXT,
        failed_attempt_id TEXT,
        cleanup_ack_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS fleet_delegation_results (
        delegation_id TEXT PRIMARY KEY NOT NULL, result_digest TEXT NOT NULL UNIQUE,
        attempt_id TEXT NOT NULL, node_id TEXT NOT NULL, bundle_json TEXT NOT NULL,
        state TEXT NOT NULL, finalized_at TEXT,
        FOREIGN KEY (delegation_id) REFERENCES fleet_delegations(delegation_id));")?;
    ensure_column(
        &conn,
        "fleet_delegations",
        "cleanup_job_id",
        "ALTER TABLE fleet_delegations ADD COLUMN cleanup_job_id TEXT",
    )?;
    ensure_column(
        &conn,
        "fleet_delegations",
        "failed_attempt_id",
        "ALTER TABLE fleet_delegations ADD COLUMN failed_attempt_id TEXT",
    )?;
    ensure_column(
        &conn,
        "fleet_delegations",
        "failure_json",
        "ALTER TABLE fleet_delegations ADD COLUMN failure_json TEXT",
    )?;
    ensure_column(
        &conn,
        "fleet_delegations",
        "cleanup_ack_at",
        "ALTER TABLE fleet_delegations ADD COLUMN cleanup_ack_at TEXT",
    )?;
    Ok(conn)
}

fn ensure_column(conn: &Connection, table: &str, column: &str, sql: &str) -> Result<()> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let present = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter()
        .any(|name| name == column);
    if !present {
        conn.execute(sql, [])?;
    }
    Ok(())
}

fn stable_id(prefix: &str, value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let suffix = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{prefix}_{suffix}")
}

pub fn start(coven_home: &Path, request: DelegationRequest) -> Result<DelegationStatus> {
    validate_request(&request)?;
    let head = git_stdout(
        &request.parent_repo,
        &["rev-parse", "--verify", "HEAD^{commit}"],
    )?;
    if head != request.base_revision {
        bail!("parent HEAD does not match baseRevision");
    }
    if !git_stdout(&request.parent_repo, &["status", "--porcelain=v1"])?.is_empty() {
        bail!("parent workspace must be clean when delegation starts");
    }
    let delegation_id = request
        .delegation_id
        .clone()
        .unwrap_or_else(|| format!("dlg_{}", Uuid::new_v4().simple()));
    validate_id(&delegation_id, "delegationId")?;
    let child_id = stable_id("child", &delegation_id);
    let payload = json!({"protocolVersion": PROTOCOL_VERSION, "delegationId": delegation_id,
        "childId": child_id, "baseRevision": request.base_revision, "task": request.task,
        "harness": request.harness, "actorId": format!("actor_{child_id}"), "generation": 1});
    let mut payload = payload;
    payload["workspaceDriver"] = request.workspace_driver.clone().into();
    payload["baseCheckpoint"] = request.base_checkpoint.clone();
    payload["resultLocator"] = request.result_locator.clone();
    let mut required = request.requirements.clone();
    required.extend([
        "protocol:workspace-driver:1".into(),
        "protocol:harness-host:1".into(),
        format!("runtime:{}", request.harness),
    ]);
    required.sort();
    required.dedup();
    let placement = fleet::placement_request_from_legacy(&required, &request.preferences)?;
    let job_id = stable_id("delegate", &delegation_id);
    let now = current_timestamp();
    let conn = open(coven_home)?;
    let tx = conn.unchecked_transaction()?;
    fleet::submit_job_with_placement_on_connection(&tx, &job_id, &payload, &placement, None)?;
    let encoded_request = serde_json::to_string(&request)?;
    let inserted = tx.execute("INSERT OR IGNORE INTO fleet_delegations (delegation_id,parent_session_id,child_id,child_job_id,state,base_revision,parent_repo,request_json,created_at,updated_at) VALUES (?1,?2,?3,?4,'queued',?5,?6,?7,?8,?8)",
        params![delegation_id, request.parent_session_id, child_id, job_id, request.base_revision,
        request.parent_repo.to_string_lossy(), encoded_request, now])?;
    if inserted == 0 {
        let stored: (String,String,String,String,String) = tx.query_row("SELECT child_id,child_job_id,base_revision,parent_repo,request_json FROM fleet_delegations WHERE delegation_id=?1", params![delegation_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        if stored
            != (
                child_id.clone(),
                job_id.clone(),
                request.base_revision.clone(),
                request.parent_repo.to_string_lossy().into_owned(),
                encoded_request,
            )
        {
            bail!("delegation id replay changed immutable request fields");
        }
    }
    tx.commit()?;
    status(coven_home, &delegation_id)
}

pub fn collect(coven_home: &Path, delegation_id: &str) -> Result<DelegationStatus> {
    let current = status(coven_home, delegation_id)?;
    if matches!(
        current.state.as_str(),
        "cleanup_queued"
            | "cancel_cleanup_queued"
            | "failure_cleanup_queued"
            | "finalized"
            | "cancelled"
            | "failed"
    ) {
        reconcile_cleanup(coven_home, delegation_id)?;
        return status(coven_home, delegation_id);
    }
    if matches!(
        current.state.as_str(),
        "integrated" | "applying" | "conflicted"
    ) {
        return Ok(current);
    }
    let conn = open(coven_home)?;
    let (job_id, child_id, base_revision, parent_repo): (String,String,String,String) = conn.query_row(
        "SELECT child_job_id,child_id,base_revision,parent_repo FROM fleet_delegations WHERE delegation_id=?1",
        params![delegation_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).context("delegation was not found")?;
    let Some(completed) = fleet::completed_job(coven_home, &job_id)? else {
        if let Some(failed) = fleet::failed_job(coven_home, &job_id)? {
            let tx = conn.unchecked_transaction()?;
            let cleanup_job_id = schedule_cleanup(&tx, delegation_id, &child_id, &failed.node_id)?;
            let state = if current.state == "cancel_requested" {
                "cancel_cleanup_queued"
            } else {
                "failure_cleanup_queued"
            };
            tx.execute(
                "UPDATE fleet_delegations SET state=?2,assigned_node_id=?3,failure_json=?4,
                 cleanup_job_id=?5,failed_attempt_id=?6,updated_at=?7 WHERE delegation_id=?1
                 AND state IN ('queued','cancel_requested')",
                params![
                    delegation_id,
                    state,
                    failed.node_id,
                    serde_json::to_string(&failed.failure)?,
                    cleanup_job_id,
                    failed.attempt_id,
                    current_timestamp()
                ],
            )?;
            tx.commit()?;
        }
        return status(coven_home, delegation_id);
    };
    let bundle: DelegationResultBundle =
        serde_json::from_value(completed.result).context("invalid delegation result")?;
    if bundle.delegation_id != delegation_id
        || bundle.child_id != child_id
        || bundle.base_revision != base_revision
        || bundle.attempt_id != completed.attempt_id
        || bundle.node_id != completed.node_id
    {
        bail!("delegation result authority binding mismatch");
    }
    let expected_observation =
        fleet::attempt_placement_observation_digest(&conn, &job_id, &completed.attempt_id)?
            .context("delegation attempt omitted placement observation evidence")?;
    if bundle.artifacts.is_empty()
        || bundle
            .artifacts
            .iter()
            .any(|artifact| artifact.platform.placement_observation_digest != expected_observation)
    {
        bail!("delegation platform evidence did not match the claimed placement observation");
    }
    result_integration::validate_bundle(&bundle)?;
    let preview = result_integration::preview(Path::new(&parent_repo), &bundle)?;
    let state = if current.state == "cancel_requested" {
        "cancel_cleanup_queued"
    } else if preview.clean {
        "ready_to_integrate"
    } else {
        "conflicted"
    };
    let transaction = conn.unchecked_transaction()?;
    let existing: Option<(String, String)> = transaction
        .query_row(
            "SELECT result_digest,bundle_json FROM fleet_delegation_results WHERE delegation_id=?1",
            params![delegation_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let encoded = serde_json::to_string(&bundle)?;
    if let Some((digest, stored)) = existing {
        if digest != bundle.result_digest || stored != encoded {
            bail!("delegation result replay changed immutable evidence");
        }
    } else {
        transaction.execute("INSERT INTO fleet_delegation_results (delegation_id,result_digest,attempt_id,node_id,bundle_json,state) VALUES (?1,?2,?3,?4,?5,'provisional')", params![delegation_id,bundle.result_digest,completed.attempt_id,completed.node_id,encoded])?;
    }
    let cleanup_job_id = if state == "cancel_cleanup_queued" {
        Some(schedule_cleanup(
            &transaction,
            delegation_id,
            &child_id,
            &completed.node_id,
        )?)
    } else {
        None
    };
    transaction.execute("UPDATE fleet_delegations SET state=?2,assigned_node_id=?3,preview_json=?4,cleanup_job_id=COALESCE(?5,cleanup_job_id),updated_at=?6 WHERE delegation_id=?1", params![delegation_id,state,completed.node_id,serde_json::to_string(&preview)?,cleanup_job_id,current_timestamp()])?;
    transaction.commit()?;
    status(coven_home, delegation_id)
}

pub fn cancel(coven_home: &Path, delegation_id: &str) -> Result<DelegationStatus> {
    let current = status(coven_home, delegation_id)?;
    match current.state.as_str() {
        "cancelled" => return Ok(current),
        "cancel_cleanup_queued" => {
            reconcile_cleanup(coven_home, delegation_id)?;
            return status(coven_home, delegation_id);
        }
        "applying" | "recovery_conflict" | "cleanup_queued" | "finalized" => {
            bail!("delegation integration has already been acknowledged")
        }
        "ready_to_integrate" | "conflicted" => {
            let conn = open(coven_home)?;
            let node_id: String = conn.query_row(
                "SELECT node_id FROM fleet_delegation_results WHERE delegation_id=?1",
                params![delegation_id],
                |row| row.get(0),
            )?;
            let tx = conn.unchecked_transaction()?;
            let cleanup_job_id = schedule_cleanup(&tx, delegation_id, &current.child_id, &node_id)?;
            tx.execute("UPDATE fleet_delegations SET state='cancel_cleanup_queued',cleanup_job_id=?2,updated_at=?3 WHERE delegation_id=?1 AND state IN ('ready_to_integrate','conflicted')", params![delegation_id,cleanup_job_id,current_timestamp()])?;
            tx.commit()?;
            return status(coven_home, delegation_id);
        }
        "cancel_requested" => return Ok(current),
        _ => {}
    }
    let conn = open(coven_home)?;
    let job_state: String = conn.query_row(
        "SELECT state FROM hub_jobs WHERE job_id=?1",
        params![current.job_id],
        |row| row.get(0),
    )?;
    if job_state == "completed" {
        drop(conn);
        collect(coven_home, delegation_id)?;
        return cancel(coven_home, delegation_id);
    }
    let tx = conn.unchecked_transaction()?;
    if job_state == "queued" {
        tx.execute("UPDATE hub_jobs SET state='cancelled',updated_at=?2 WHERE job_id=?1 AND state='queued'", params![current.job_id,current_timestamp()])?;
        tx.execute(
            "UPDATE fleet_delegations SET state='cancelled',updated_at=?2 WHERE delegation_id=?1",
            params![delegation_id, current_timestamp()],
        )?;
    } else if job_state == "leased" {
        tx.execute("UPDATE fleet_delegations SET state='cancel_requested',updated_at=?2 WHERE delegation_id=?1", params![delegation_id,current_timestamp()])?;
    } else {
        bail!("delegation job cannot be cancelled from {job_state}");
    }
    tx.commit()?;
    status(coven_home, delegation_id)
}

pub fn integrate(
    coven_home: &Path,
    delegation_id: &str,
    finalization_key: &str,
) -> Result<DelegationStatus> {
    validate_id(finalization_key, "finalizationKey")?;
    let conn = open(coven_home)?;
    let (state, repo, preview_json, stored_key, bundle_json): (String,String,Option<String>,Option<String>,String) = conn.query_row(
        "SELECT d.state,d.parent_repo,d.preview_json,d.finalization_key,r.bundle_json FROM fleet_delegations d JOIN fleet_delegation_results r USING(delegation_id) WHERE d.delegation_id=?1",
        params![delegation_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).context("delegation has no provisional result")?;
    if matches!(state.as_str(), "cleanup_queued" | "finalized") {
        if stored_key.as_deref() == Some(finalization_key) {
            reconcile_cleanup(coven_home, delegation_id)?;
            return status(coven_home, delegation_id);
        }
        bail!("delegation was finalized with another idempotency key");
    }
    if !matches!(state.as_str(), "ready_to_integrate" | "applying") {
        bail!("delegation is not ready to integrate");
    }
    let bundle: DelegationResultBundle = serde_json::from_str(&bundle_json)?;
    let preview: IntegrationPreview = serde_json::from_str(
        preview_json
            .as_deref()
            .context("delegation preview missing")?,
    )?;
    if state == "ready_to_integrate" {
        let changed = conn.execute("UPDATE fleet_delegations SET state='applying',finalization_key=?2,updated_at=?3 WHERE delegation_id=?1 AND state='ready_to_integrate'", params![delegation_id,finalization_key,current_timestamp()])?;
        if changed != 1 {
            bail!("delegation integration authority changed");
        }
        result_integration::apply(Path::new(&repo), &bundle, &preview.parent_revision)?;
    } else if stored_key.as_deref() != Some(finalization_key) {
        bail!("delegation apply is owned by another finalization key");
    } else if !result_integration::patch_is_applied(Path::new(&repo), &bundle)? {
        let recovery = result_integration::preview(Path::new(&repo), &bundle)?;
        if recovery.clean && recovery.parent_revision == preview.parent_revision {
            result_integration::apply(Path::new(&repo), &bundle, &preview.parent_revision)?;
        } else {
            conn.execute("UPDATE fleet_delegations SET state='recovery_conflict',preview_json=?2,updated_at=?3 WHERE delegation_id=?1 AND state='applying'", params![delegation_id,serde_json::to_string(&recovery)?,current_timestamp()])?;
            bail!("delegation apply recovery found parent divergence")
        }
    }
    let (child_id, node_id): (String,String) = conn.query_row("SELECT d.child_id,r.node_id FROM fleet_delegations d JOIN fleet_delegation_results r USING(delegation_id) WHERE d.delegation_id=?1", params![delegation_id], |r| Ok((r.get(0)?,r.get(1)?)))?;
    let tx = conn.unchecked_transaction()?;
    let cleanup_job_id = schedule_cleanup(&tx, delegation_id, &child_id, &node_id)?;
    tx.execute("UPDATE fleet_delegations SET state='cleanup_queued',cleanup_job_id=?2,updated_at=?3 WHERE delegation_id=?1 AND state='applying'", params![delegation_id,cleanup_job_id,current_timestamp()])?;
    tx.execute("UPDATE fleet_delegation_results SET state='integrated',finalized_at=?2 WHERE delegation_id=?1", params![delegation_id,current_timestamp()])?;
    tx.commit()?;
    status(coven_home, delegation_id)
}

pub fn status(coven_home: &Path, delegation_id: &str) -> Result<DelegationStatus> {
    let conn = open(coven_home)?;
    conn.query_row("SELECT delegation_id,child_id,child_job_id,state,base_revision,parent_repo,assigned_node_id,preview_json,finalization_key,cleanup_job_id,cleanup_ack_at,failure_json FROM fleet_delegations WHERE delegation_id=?1", params![delegation_id], |r| {
        let raw: Option<String> = r.get(7)?;
        let failure: Option<String> = r.get(11)?;
        Ok(DelegationStatus { protocol_version: PROTOCOL_VERSION.into(), delegation_id:r.get(0)?, child_id:r.get(1)?, job_id:r.get(2)?, state:r.get(3)?, base_revision:r.get(4)?, parent_repo:PathBuf::from(r.get::<_,String>(5)?), assigned_node_id:r.get(6)?, preview:raw.and_then(|v|serde_json::from_str(&v).ok()), finalization_key:r.get(8)?, cleanup_job_id:r.get(9)?, cleanup_acknowledged:r.get::<_,Option<String>>(10)?.is_some(), failure:failure.and_then(|v|serde_json::from_str(&v).ok()) })
    }).context("delegation was not found")
}

pub fn reconcile_all(coven_home: &Path) -> Result<()> {
    let conn = open(coven_home)?;
    let mut statement = conn.prepare(
        "SELECT delegation_id,state,finalization_key FROM fleet_delegations
         WHERE state IN ('queued','cancel_requested','applying','cleanup_queued','cancel_cleanup_queued','failure_cleanup_queued')",
    )?;
    let pending = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    drop(conn);
    for (delegation_id, state, finalization_key) in pending {
        let outcome = match state.as_str() {
            "applying" => match finalization_key {
                Some(key) => integrate(coven_home, &delegation_id, &key).map(|_| ()),
                None => Err(anyhow::anyhow!(
                    "applying delegation omitted finalization key"
                )),
            },
            "cleanup_queued" | "cancel_cleanup_queued" | "failure_cleanup_queued" => {
                reconcile_cleanup(coven_home, &delegation_id)
            }
            _ => collect(coven_home, &delegation_id).map(|_| ()),
        };
        if let Err(error) = outcome {
            eprintln!("coven daemon: delegation {delegation_id} recovery: {error:#}");
        }
    }
    Ok(())
}

fn reconcile_cleanup(coven_home: &Path, delegation_id: &str) -> Result<()> {
    let current = status(coven_home, delegation_id)?;
    if !matches!(
        current.state.as_str(),
        "cleanup_queued" | "cancel_cleanup_queued" | "failure_cleanup_queued"
    ) {
        return Ok(());
    }
    let job_id = current
        .cleanup_job_id
        .context("cleanup job linkage missing")?;
    let Some(completed) = fleet::completed_job(coven_home, &job_id)? else {
        return Ok(());
    };
    if completed.node_id != current.assigned_node_id.as_deref().unwrap_or_default()
        || completed.result["protocolVersion"] != crate::delegation_cleanup::PROTOCOL_VERSION
        || completed.result["delegationId"] != delegation_id
        || completed.result["childId"] != current.child_id
        || completed.result["released"] != true
    {
        bail!("delegation cleanup acknowledgement binding mismatch");
    }
    let conn = open(coven_home)?;
    let terminal = match current.state.as_str() {
        "cancel_cleanup_queued" => "cancelled",
        "failure_cleanup_queued" => "failed",
        _ => "finalized",
    };
    conn.execute("UPDATE fleet_delegations SET state=?2,cleanup_ack_at=?3,updated_at=?3 WHERE delegation_id=?1 AND state IN ('cleanup_queued','cancel_cleanup_queued','failure_cleanup_queued')", params![delegation_id,terminal,current_timestamp()])?;
    Ok(())
}

fn schedule_cleanup(
    conn: &Connection,
    delegation_id: &str,
    child_id: &str,
    node_id: &str,
) -> Result<String> {
    let cleanup_job_id = stable_id("cleanup", delegation_id);
    let payload = json!({"protocolVersion":crate::delegation_cleanup::PROTOCOL_VERSION,"delegationId":delegation_id,"childId":child_id,"actorId":format!("actor_{child_id}"),"generation":1});
    fleet::submit_job_on_connection(
        conn,
        &cleanup_job_id,
        &payload,
        &["protocol:harness-host:1".into()],
        Some(node_id),
    )?;
    Ok(cleanup_job_id)
}

fn validate_request(r: &DelegationRequest) -> Result<()> {
    if r.protocol_version != PROTOCOL_VERSION {
        bail!("unsupported delegation protocol");
    }
    if r.task.trim().is_empty() || r.task.len() > 256 * 1024 {
        bail!("delegation task is invalid");
    }
    if r.base_revision.len() != 40 || !r.base_revision.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("baseRevision must be a full SHA-1 commit OID");
    }
    if r.requirements.len() > 128 || r.preferences.len() > 128 {
        bail!("placement input exceeds limits");
    }
    if r.harness != "fake" {
        bail!("only the deterministic fake harness is enabled");
    }
    if !matches!(r.workspace_driver.as_str(), "filesystem" | "s3-checkpoint") {
        bail!("unsupported workspace driver");
    }
    Ok(())
}
fn validate_id(v: &str, field: &str) -> Result<()> {
    if v.is_empty()
        || v.len() > 128
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("{field} has an invalid format");
    }
    Ok(())
}
fn git_stdout(repo: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git").args(args).current_dir(repo).output()?;
    if !o.status.success() {
        bail!("git failed: {}", String::from_utf8_lossy(&o.stderr).trim())
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn start_is_async_and_persists_linkage() -> Result<()> {
        let h = tempfile::tempdir()?;
        let r = tempfile::tempdir()?;
        git_stdout(r.path(), &["init", "-q"])?;
        git_stdout(r.path(), &["config", "user.email", "test@example.invalid"])?;
        git_stdout(r.path(), &["config", "user.name", "Test"])?;
        std::fs::write(r.path().join("base.txt"), "base\n")?;
        git_stdout(r.path(), &["add", "base.txt"])?;
        git_stdout(r.path(), &["commit", "-qm", "base"])?;
        let base = git_stdout(r.path(), &["rev-parse", "HEAD"])?;
        let s = start(
            h.path(),
            DelegationRequest {
                protocol_version: PROTOCOL_VERSION.into(),
                delegation_id: Some("delegation-1".into()),
                parent_session_id: None,
                parent_repo: r.path().into(),
                base_revision: base,
                task: "work".into(),
                workspace_driver: "filesystem".into(),
                base_checkpoint: json!({}),
                result_locator: json!({}),
                requirements: vec![],
                preferences: vec![],
                harness: "fake".into(),
            },
        )?;
        assert_eq!(s.state, "queued");
        assert!(s.job_id.starts_with("delegate_"));
        Ok(())
    }

    #[test]
    fn queued_cancellation_is_terminal_and_replay_safe() -> Result<()> {
        let home = tempfile::tempdir()?;
        let repo = tempfile::tempdir()?;
        git_stdout(repo.path(), &["init", "-q"])?;
        git_stdout(
            repo.path(),
            &["config", "user.email", "test@example.invalid"],
        )?;
        git_stdout(repo.path(), &["config", "user.name", "Test"])?;
        std::fs::write(repo.path().join("base.txt"), "base\n")?;
        git_stdout(repo.path(), &["add", "base.txt"])?;
        git_stdout(repo.path(), &["commit", "-qm", "base"])?;
        let request = DelegationRequest {
            protocol_version: PROTOCOL_VERSION.into(),
            delegation_id: Some("cancel-queued".into()),
            parent_session_id: None,
            parent_repo: repo.path().into(),
            base_revision: git_stdout(repo.path(), &["rev-parse", "HEAD"])?,
            task: "work".into(),
            workspace_driver: "filesystem".into(),
            base_checkpoint: json!({}),
            result_locator: json!({}),
            requirements: vec![],
            preferences: vec![],
            harness: "fake".into(),
        };
        let started = start(home.path(), request.clone())?;
        assert_eq!(
            cancel(home.path(), &started.delegation_id)?.state,
            "cancelled"
        );
        assert_eq!(
            cancel(home.path(), &started.delegation_id)?.state,
            "cancelled"
        );
        let conn = open(home.path())?;
        let job_state: String = conn.query_row(
            "SELECT state FROM hub_jobs WHERE job_id=?1",
            params![started.job_id],
            |row| row.get(0),
        )?;
        assert_eq!(job_state, "cancelled");
        drop(conn);
        let mut changed = request;
        changed.task = "changed".into();
        assert!(start(home.path(), changed).is_err());
        Ok(())
    }

    #[test]
    fn leased_cancellation_waits_for_provisional_result_before_cleanup() -> Result<()> {
        let home = tempfile::tempdir()?;
        let repo = tempfile::tempdir()?;
        git_stdout(repo.path(), &["init", "-q"])?;
        git_stdout(
            repo.path(),
            &["config", "user.email", "test@example.invalid"],
        )?;
        git_stdout(repo.path(), &["config", "user.name", "Test"])?;
        std::fs::write(repo.path().join("base.txt"), "base\n")?;
        git_stdout(repo.path(), &["add", "base.txt"])?;
        git_stdout(repo.path(), &["commit", "-qm", "base"])?;
        let started = start(
            home.path(),
            DelegationRequest {
                protocol_version: PROTOCOL_VERSION.into(),
                delegation_id: Some("cancel-leased".into()),
                parent_session_id: None,
                parent_repo: repo.path().into(),
                base_revision: git_stdout(repo.path(), &["rev-parse", "HEAD"])?,
                task: "work".into(),
                workspace_driver: "filesystem".into(),
                base_checkpoint: json!({}),
                result_locator: json!({}),
                requirements: vec![],
                preferences: vec![],
                harness: "fake".into(),
            },
        )?;
        let conn = open(home.path())?;
        conn.execute(
            "UPDATE hub_jobs SET state='leased',assigned_node_id='node-a' WHERE job_id=?1",
            params![started.job_id],
        )?;
        drop(conn);
        let cancelled = cancel(home.path(), &started.delegation_id)?;
        assert_eq!(cancelled.state, "cancel_requested");
        assert!(cancelled.cleanup_job_id.is_none());
        assert_eq!(
            cancel(home.path(), &started.delegation_id)?.state,
            "cancel_requested"
        );
        Ok(())
    }

    #[test]
    fn provisional_cancellation_queues_cleanup_on_producing_node() -> Result<()> {
        let home = tempfile::tempdir()?;
        let repo = tempfile::tempdir()?;
        git_stdout(repo.path(), &["init", "-q"])?;
        git_stdout(
            repo.path(),
            &["config", "user.email", "test@example.invalid"],
        )?;
        git_stdout(repo.path(), &["config", "user.name", "Test"])?;
        std::fs::write(repo.path().join("base.txt"), "base\n")?;
        git_stdout(repo.path(), &["add", "base.txt"])?;
        git_stdout(repo.path(), &["commit", "-qm", "base"])?;
        let started = start(
            home.path(),
            DelegationRequest {
                protocol_version: PROTOCOL_VERSION.into(),
                delegation_id: Some("cancel-provisional".into()),
                parent_session_id: None,
                parent_repo: repo.path().into(),
                base_revision: git_stdout(repo.path(), &["rev-parse", "HEAD"])?,
                task: "work".into(),
                workspace_driver: "filesystem".into(),
                base_checkpoint: json!({}),
                result_locator: json!({}),
                requirements: vec![],
                preferences: vec![],
                harness: "fake".into(),
            },
        )?;
        let conn = open(home.path())?;
        conn.execute("INSERT INTO fleet_delegation_results (delegation_id,result_digest,attempt_id,node_id,bundle_json,state) VALUES (?1,'digest','attempt-a','node-a','{}','provisional')", params![started.delegation_id])?;
        conn.execute("UPDATE fleet_delegations SET state='ready_to_integrate',assigned_node_id='node-a' WHERE delegation_id=?1", params![started.delegation_id])?;
        drop(conn);
        let cancelled = cancel(home.path(), &started.delegation_id)?;
        assert_eq!(cancelled.state, "cancel_cleanup_queued");
        let conn = open(home.path())?;
        let target: String = conn.query_row(
            "SELECT target_node_id FROM hub_jobs WHERE job_id=?1",
            params![cancelled.cleanup_job_id],
            |row| row.get(0),
        )?;
        assert_eq!(target, "node-a");
        assert!(!repo.path().join("result.txt").exists());
        Ok(())
    }

    #[test]
    fn failed_child_retains_resources_until_pinned_cleanup_ack() -> Result<()> {
        let home = tempfile::tempdir()?;
        let repo = tempfile::tempdir()?;
        git_stdout(repo.path(), &["init", "-q"])?;
        git_stdout(
            repo.path(),
            &["config", "user.email", "test@example.invalid"],
        )?;
        git_stdout(repo.path(), &["config", "user.name", "Test"])?;
        std::fs::write(repo.path().join("base.txt"), "base\n")?;
        git_stdout(repo.path(), &["add", "base.txt"])?;
        git_stdout(repo.path(), &["commit", "-qm", "base"])?;
        let started = start(
            home.path(),
            DelegationRequest {
                protocol_version: PROTOCOL_VERSION.into(),
                delegation_id: Some("failed-child".into()),
                parent_session_id: None,
                parent_repo: repo.path().into(),
                base_revision: git_stdout(repo.path(), &["rev-parse", "HEAD"])?,
                task: "work".into(),
                workspace_driver: "filesystem".into(),
                base_checkpoint: json!({}),
                result_locator: json!({}),
                requirements: vec![],
                preferences: vec![],
                harness: "fake".into(),
            },
        )?;
        let failure = fleet::FleetFailureEvidence {
            protocol_version: fleet::FAILURE_PROTOCOL_VERSION.into(),
            code: "execution_failed".into(),
            message: "runner stopped".into(),
        };
        let _ = fleet::failed_job(home.path(), &started.job_id)?;
        let conn = open(home.path())?;
        let now = current_timestamp();
        conn.execute(
            "UPDATE hub_jobs SET state='failed',assigned_node_id='node-a',updated_at=?2
             WHERE job_id=?1",
            params![started.job_id, now],
        )?;
        conn.execute(
            "INSERT INTO fleet_job_attempts
             (job_id,attempt_id,node_id,state,lease_verifier,lease_expires_at,completion_key,result_json,created_at,updated_at)
             VALUES (?1,'attempt-a','node-a','failed','verifier','2099-01-01T00:00:00Z','fail:attempt-a',?2,?3,?3)",
            params![started.job_id, serde_json::to_string(&failure)?, now],
        )?;
        drop(conn);

        let collecting = collect(home.path(), &started.delegation_id)?;
        assert_eq!(collecting.state, "failure_cleanup_queued");
        assert_eq!(collecting.assigned_node_id.as_deref(), Some("node-a"));
        assert_eq!(collecting.failure, Some(failure));
        assert!(!collecting.cleanup_acknowledged);
        let cleanup_job_id = collecting.cleanup_job_id.clone().unwrap();
        let conn = open(home.path())?;
        let target: String = conn.query_row(
            "SELECT target_node_id FROM hub_jobs WHERE job_id=?1",
            params![cleanup_job_id],
            |row| row.get(0),
        )?;
        assert_eq!(target, "node-a");
        let cleanup_result = json!({
            "protocolVersion": crate::delegation_cleanup::PROTOCOL_VERSION,
            "delegationId": started.delegation_id,
            "childId": started.child_id,
            "released": true,
        });
        conn.execute(
            "UPDATE hub_jobs SET state='completed',assigned_node_id='node-a' WHERE job_id=?1",
            params![cleanup_job_id],
        )?;
        conn.execute(
            "INSERT INTO fleet_job_attempts
             (job_id,attempt_id,node_id,state,lease_verifier,lease_expires_at,completion_key,result_json,created_at,updated_at)
             VALUES (?1,'cleanup-attempt','node-a','completed','verifier','2099-01-01T00:00:00Z','complete:cleanup',?2,?3,?3)",
            params![cleanup_job_id, cleanup_result.to_string(), current_timestamp()],
        )?;
        drop(conn);
        let failed = collect(home.path(), &started.delegation_id)?;
        assert_eq!(failed.state, "failed");
        assert!(failed.cleanup_acknowledged);
        assert!(!repo.path().join("result.txt").exists());
        Ok(())
    }
}
