//! Coven Fleet trust and Coven Discovery protocol.
//!
//! Tailscale is deliberately absent from this authority module. A client may
//! use its bounded peer inventory to find addresses, but every peer remains
//! unauthorized until this module enrolls it. Secrets are represented only by
//! hashes in the hub store and are returned exactly once to the enrolling node.

use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::{api_error, json_response, parse_body, ApiResponse};

const PROTOCOL: &str = "coven.fleet.v1";
const MAX_ENROLLMENT_TTL_SECONDS: i64 = 600;
const DEFAULT_ENROLLMENT_TTL_SECONDS: i64 = 300;
const CHALLENGE_TTL_SECONDS: i64 = 60;
const JOB_LEASE_TTL_SECONDS: i64 = 60;
const MAX_REMOTE_TURN_PROMPT_BYTES: usize = 256 * 1024;
const MAX_REMOTE_TURN_CONTEXT_MESSAGES: usize = 256;
const MAX_REMOTE_TURN_CONTEXT_BYTES: usize = 768 * 1024;
const MAX_REMOTE_TURN_ATTACHMENTS: usize = 8;
const MAX_REMOTE_TURN_ATTACHMENT_BYTES: usize = 768 * 1024;
const MAX_REMOTE_TURN_WORKSPACE_BYTES: usize = 768 * 1024;
const MAX_REMOTE_TURN_ENCODED_BINARY_BYTES: usize = MAX_REMOTE_TURN_WORKSPACE_BYTES.div_ceil(3) * 4;
const MAX_REMOTE_TURN_UNTRACKED_FILES: usize = 256;
const MAX_REMOTE_TURN_FIELD_BYTES: usize = 4096;

fn store_path(home: &Path) -> std::path::PathBuf {
    home.join("coven.sqlite3")
}

fn open(home: &Path) -> Result<Connection> {
    let conn = crate::store::open_store(&store_path(home))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS fleet_enrollments (
            token_hash TEXT PRIMARY KEY NOT NULL, expires_at TEXT NOT NULL,
            used_at TEXT, created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS fleet_trusted_nodes (
            node_id TEXT PRIMARY KEY NOT NULL, credential_hash TEXT NOT NULL,
            enrolled_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
            revoked_at TEXT
         );
         CREATE TABLE IF NOT EXISTS fleet_challenges (
            node_id TEXT NOT NULL, nonce_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL, used_at TEXT,
            PRIMARY KEY (node_id, nonce_hash)
         );
         CREATE TABLE IF NOT EXISTS fleet_pairing_requests (
            request_id TEXT PRIMARY KEY NOT NULL, node_id TEXT NOT NULL,
            request_secret_hash TEXT NOT NULL, protocol_version TEXT NOT NULL,
            state TEXT NOT NULL, expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL, decided_at TEXT, delivered_at TEXT
         );
         CREATE TABLE IF NOT EXISTS fleet_local_credentials (
            hub_id TEXT PRIMARY KEY NOT NULL, node_id TEXT NOT NULL,
            node_credential TEXT NOT NULL, stored_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS fleet_local_node (
            singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
            device_id TEXT NOT NULL, role TEXT NOT NULL,
            lifecycle TEXT NOT NULL, executor_shared INTEGER NOT NULL,
            capabilities_json TEXT NOT NULL, generation INTEGER NOT NULL,
            updated_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS fleet_lifecycle_operations (
            operation_id TEXT PRIMARY KEY NOT NULL, action TEXT NOT NULL,
            created_at TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS fleet_jobs (
            job_id TEXT PRIMARY KEY NOT NULL, target_node_id TEXT NOT NULL,
            spec_json TEXT NOT NULL, state TEXT NOT NULL,
            lease_id TEXT, result_json TEXT,
            created_at TEXT NOT NULL, leased_at TEXT, lease_expires_at TEXT,
            completed_at TEXT
         );
         CREATE TABLE IF NOT EXISTS fleet_execution_receipts (
            job_id TEXT PRIMARY KEY NOT NULL, spec_hash TEXT NOT NULL,
            state TEXT NOT NULL, result_json TEXT,
            started_at TEXT NOT NULL, completed_at TEXT
         );
         CREATE TABLE IF NOT EXISTS fleet_job_events (
            job_id TEXT NOT NULL, sequence INTEGER NOT NULL,
            chunk_base64 TEXT NOT NULL, created_at TEXT NOT NULL,
            PRIMARY KEY (job_id, sequence)
         );",
    )
    .context("failed to initialize fleet trust schema")?;
    // Additive migration for executors enrolled before capability heartbeats.
    let _ = conn.execute(
        "ALTER TABLE fleet_trusted_nodes ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '[]'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE fleet_trusted_nodes ADD COLUMN display_name TEXT",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE fleet_trusted_nodes ADD COLUMN executor_availability TEXT NOT NULL DEFAULT 'unknown'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE fleet_trusted_nodes ADD COLUMN workspace_inventory_json TEXT",
        [],
    );
    Ok(conn)
}

const ROLE_HUB: &str = "hub";
const ROLE_EXECUTOR: &str = "executor";
const ROLE_BOTH: &str = "both";
const LIFECYCLE_STOPPED: &str = "stopped";
const LIFECYCLE_RUNNING: &str = "running";
const LIFECYCLE_DRAINING: &str = "draining";

#[derive(Debug)]
struct LocalNode {
    device_id: String,
    role: String,
    lifecycle: String,
    executor_shared: bool,
    capabilities_json: String,
    generation: i64,
    updated_at: String,
}

fn load_or_create_local_node(conn: &Connection) -> Result<LocalNode> {
    let existing = conn
        .query_row(
            "SELECT device_id, role, lifecycle, executor_shared, capabilities_json,
                    generation, updated_at FROM fleet_local_node WHERE singleton=1",
            [],
            |row| {
                Ok(LocalNode {
                    device_id: row.get(0)?,
                    role: row.get(1)?,
                    lifecycle: row.get(2)?,
                    executor_shared: row.get(3)?,
                    capabilities_json: row.get(4)?,
                    generation: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()?;
    if let Some(node) = existing {
        return Ok(node);
    }
    let node = LocalNode {
        device_id: format!("node_{}", Uuid::new_v4().simple()),
        role: ROLE_HUB.to_string(),
        lifecycle: LIFECYCLE_STOPPED.to_string(),
        executor_shared: false,
        capabilities_json: "[]".to_string(),
        generation: 0,
        updated_at: Utc::now().to_rfc3339(),
    };
    conn.execute(
        "INSERT INTO fleet_local_node
         (singleton, device_id, role, lifecycle, executor_shared, capabilities_json,
          generation, updated_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            node.device_id,
            node.role,
            node.lifecycle,
            node.executor_shared,
            node.capabilities_json,
            node.generation,
            node.updated_at
        ],
    )?;
    Ok(node)
}

fn role_has_executor(role: &str) -> bool {
    role == ROLE_EXECUTOR || role == ROLE_BOTH
}

fn local_node_response(node: &LocalNode) -> Value {
    let capabilities: Vec<String> =
        serde_json::from_str(&node.capabilities_json).unwrap_or_default();
    let accepting_jobs = role_has_executor(&node.role)
        && node.executor_shared
        && node.lifecycle == LIFECYCLE_RUNNING;
    let next_action = match node.lifecycle.as_str() {
        LIFECYCLE_STOPPED => "start",
        LIFECYCLE_DRAINING => "resume-or-stop",
        _ if role_has_executor(&node.role) && !node.executor_shared => "enable-sharing",
        _ => "none",
    };
    json!({
        "deviceId": node.device_id,
        "role": node.role,
        "lifecycle": node.lifecycle,
        "executorShared": node.executor_shared,
        "capabilities": capabilities,
        "acceptingJobs": accepting_jobs,
        "generation": node.generation,
        "updatedAt": node.updated_at,
        "nextAction": next_action
    })
}

pub fn local_node_status(home: &Path) -> Result<ApiResponse> {
    let conn = open(home)?;
    let node = load_or_create_local_node(&conn)?;
    json_response(200, &local_node_response(&node))
}

#[derive(Deserialize)]
struct ConfigureRole {
    role: String,
    #[serde(default)]
    capabilities: Vec<String>,
}

pub fn configure_local_role(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: ConfigureRole = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if ![ROLE_HUB, ROLE_EXECUTOR, ROLE_BOTH].contains(&request.role.as_str()) {
        return api_error(
            400,
            "invalid_fleet_role",
            "role must be hub, executor, or both.",
            Some(json!({"supported": [ROLE_HUB, ROLE_EXECUTOR, ROLE_BOTH]})),
        );
    }
    let conn = open(home)?;
    let mut node = load_or_create_local_node(&conn)?;
    node.role = request.role;
    node.capabilities_json = serde_json::to_string(&request.capabilities)?;
    if !role_has_executor(&node.role) {
        node.executor_shared = false;
        if node.lifecycle == LIFECYCLE_DRAINING {
            node.lifecycle = LIFECYCLE_RUNNING.to_string();
        }
    }
    node.updated_at = Utc::now().to_rfc3339();
    persist_local_node(&conn, &node)?;
    json_response(200, &local_node_response(&node))
}

#[derive(Deserialize)]
struct SharingRequest {
    enabled: bool,
}

pub fn configure_local_sharing(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: SharingRequest = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let conn = open(home)?;
    let mut node = load_or_create_local_node(&conn)?;
    if request.enabled && !role_has_executor(&node.role) {
        return api_error(
            409,
            "executor_role_required",
            "Choose executor or both before enabling executor sharing.",
            Some(json!({"currentRole": node.role, "nextAction": "configure-role"})),
        );
    }
    node.executor_shared = request.enabled;
    node.updated_at = Utc::now().to_rfc3339();
    persist_local_node(&conn, &node)?;
    json_response(200, &local_node_response(&node))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LifecycleRequest {
    #[serde(default)]
    operation_id: Option<String>,
}

pub fn local_lifecycle(home: &Path, action: &str, body: Option<&str>) -> Result<ApiResponse> {
    let request = if body.is_some() {
        match parse::<LifecycleRequest>(body) {
            Ok(value) => value,
            Err(response) => return Ok(response),
        }
    } else {
        LifecycleRequest::default()
    };
    let conn = open(home)?;
    let mut node = load_or_create_local_node(&conn)?;
    if action == "restart" && request.operation_id.as_deref().is_none_or(str::is_empty) {
        return api_error(
            400,
            "operation_id_required",
            "Restart requires operationId so retries are idempotent.",
            Some(json!({"action": action})),
        );
    }
    if let Some(operation_id) = request.operation_id.as_deref() {
        let prior: Option<String> = conn
            .query_row(
                "SELECT action FROM fleet_lifecycle_operations WHERE operation_id=?1",
                [operation_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(prior_action) = prior {
            if prior_action != action {
                return api_error(
                    409,
                    "operation_id_conflict",
                    "operationId was already used for a different lifecycle action.",
                    Some(json!({"operationId": operation_id, "priorAction": prior_action})),
                );
            }
            return json_response(200, &local_node_response(&node));
        }
    }
    match action {
        "start" => node.lifecycle = LIFECYCLE_RUNNING.to_string(),
        "stop" => node.lifecycle = LIFECYCLE_STOPPED.to_string(),
        "restart" => {
            node.lifecycle = LIFECYCLE_RUNNING.to_string();
            node.generation += 1;
        }
        "drain" => {
            if !role_has_executor(&node.role) {
                return api_error(
                    409,
                    "executor_role_required",
                    "Only an executor can drain work.",
                    Some(json!({"currentRole": node.role, "nextAction": "configure-role"})),
                );
            }
            node.lifecycle = LIFECYCLE_DRAINING.to_string();
        }
        "resume" => node.lifecycle = LIFECYCLE_RUNNING.to_string(),
        _ => {
            return api_error(
                404,
                "fleet_lifecycle_action_not_found",
                "Fleet lifecycle action was not found.",
                Some(json!({"action": action})),
            )
        }
    }
    node.updated_at = Utc::now().to_rfc3339();
    persist_local_node(&conn, &node)?;
    if let Some(operation_id) = request.operation_id {
        conn.execute(
            "INSERT INTO fleet_lifecycle_operations (operation_id, action, created_at)
             VALUES (?1, ?2, ?3)",
            params![operation_id, action, Utc::now().to_rfc3339()],
        )?;
    }
    json_response(200, &local_node_response(&node))
}

fn persist_local_node(conn: &Connection, node: &LocalNode) -> Result<()> {
    conn.execute(
        "UPDATE fleet_local_node SET role=?1, lifecycle=?2, executor_shared=?3,
         capabilities_json=?4, generation=?5, updated_at=?6 WHERE singleton=1",
        params![
            node.role,
            node.lifecycle,
            node.executor_shared,
            node.capabilities_json,
            node.generation,
            node.updated_at
        ],
    )?;
    Ok(())
}

/// Executor-side projection of the configured fleet policy. `None` preserves
/// the pre-fleet headless defaults until a user explicitly configures roles in
/// Cave or through the API.
pub(crate) fn executor_policy(home: &Path) -> Result<Option<(Vec<String>, bool)>> {
    let conn = open(home)?;
    let node = conn
        .query_row(
            "SELECT role, lifecycle, executor_shared, capabilities_json
             FROM fleet_local_node WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((role, lifecycle, shared, capabilities_json)) = node else {
        return Ok(None);
    };
    let capabilities = serde_json::from_str(&capabilities_json)
        .context("failed to parse local fleet capabilities")?;
    let available = role_has_executor(&role) && shared && lifecycle == LIFECYCLE_RUNNING;
    Ok(Some((capabilities, available)))
}

fn secret(prefix: &str) -> String {
    format!(
        "{prefix}_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn hash(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
fn proof(credential: &str, nonce: &str) -> String {
    hash(&format!("{PROTOCOL}\0{}\0{nonce}", hash(credential)))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

pub fn advertisement(home: &Path) -> Result<ApiResponse> {
    let conn = open(home)?;
    let local = load_or_create_local_node(&conn)?;
    let pairing_available: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM fleet_enrollments WHERE used_at IS NULL AND expires_at > ?1)",
        [Utc::now().to_rfc3339()],
        |row| row.get(0),
    )?;
    // Intentionally exclude hub id, node registry, capabilities, queue state,
    // usernames, and paths. An untrusted probe learns only compatibility and
    // whether an explicit enrollment window exists.
    json_response(
        200,
        &json!({
            "service": "coven-fleet", "protocolVersions": [PROTOCOL],
            "roles": [local.role], "pairingAvailable": pairing_available
        }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Negotiate {
    protocol_versions: Vec<String>,
}

pub fn negotiate(body: Option<&str>) -> Result<ApiResponse> {
    let request: Negotiate = match parse(body) {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if request.protocol_versions.iter().any(|v| v == PROTOCOL) {
        json_response(200, &json!({ "protocolVersion": PROTOCOL }))
    } else {
        api_error(
            409,
            "fleet_version_mismatch",
            "No mutually supported Coven Fleet protocol version.",
            Some(json!({ "supported": [PROTOCOL] })),
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentOptions {
    #[serde(default)]
    ttl_seconds: Option<i64>,
}

pub fn create_enrollment(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let options: EnrollmentOptions = match parse(body) {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let ttl = options
        .ttl_seconds
        .unwrap_or(DEFAULT_ENROLLMENT_TTL_SECONDS);
    if !(1..=MAX_ENROLLMENT_TTL_SECONDS).contains(&ttl) {
        return api_error(
            400,
            "invalid_request",
            "ttlSeconds must be between 1 and 600.",
            None,
        );
    }
    let token = secret("cvenroll");
    let now = Utc::now();
    let expires = now + Duration::seconds(ttl);
    open(home)?.execute(
        "INSERT INTO fleet_enrollments (token_hash, expires_at, used_at, created_at) VALUES (?1, ?2, NULL, ?3)",
        params![hash(&token), expires.to_rfc3339(), now.to_rfc3339()],
    )?;
    json_response(
        201,
        &json!({ "credential": token, "expiresAt": expires.to_rfc3339(), "singleUse": true }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Enroll {
    node_id: String,
    enrollment_credential: String,
    protocol_version: String,
}

pub fn enroll(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: Enroll = match parse(body) {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if request.node_id.trim().is_empty() {
        return api_error(400, "invalid_request", "nodeId is required.", None);
    }
    if request.protocol_version != PROTOCOL {
        return api_error(
            409,
            "fleet_version_mismatch",
            "Unsupported Coven Fleet protocol version.",
            Some(json!({"supported": [PROTOCOL]})),
        );
    }
    let mut conn = open(home)?;
    let tx = conn.transaction()?;
    let token_hash = hash(&request.enrollment_credential);
    let row: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT expires_at, used_at FROM fleet_enrollments WHERE token_hash = ?1",
            [&token_hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((expires_at, used_at)) = row else {
        return api_error(
            401,
            "enrollment_invalid",
            "Enrollment credential is invalid.",
            None,
        );
    };
    if used_at.is_some() {
        return api_error(
            409,
            "enrollment_used",
            "Enrollment credential has already been used.",
            None,
        );
    }
    if parse_time(&expires_at)? <= Utc::now() {
        return api_error(
            410,
            "enrollment_expired",
            "Enrollment credential has expired.",
            None,
        );
    }
    let credential = secret("cvnode");
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE fleet_enrollments SET used_at = ?1 WHERE token_hash = ?2 AND used_at IS NULL",
        params![now, token_hash],
    )?;
    tx.execute(
        "INSERT INTO fleet_trusted_nodes (node_id, credential_hash, enrolled_at, last_seen_at, revoked_at)
         VALUES (?1, ?2, ?3, ?3, NULL)
         ON CONFLICT(node_id) DO UPDATE SET credential_hash=excluded.credential_hash, enrolled_at=excluded.enrolled_at, last_seen_at=excluded.last_seen_at, revoked_at=NULL",
        params![request.node_id, hash(&credential), now],
    )?;
    tx.commit()?;
    json_response(
        201,
        &json!({ "nodeId": request.node_id, "nodeCredential": credential, "protocolVersion": PROTOCOL }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairingRequest {
    node_id: String,
    protocol_version: String,
}

pub fn request_pairing(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: PairingRequest = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if request.node_id.trim().is_empty() {
        return api_error(400, "invalid_request", "nodeId is required.", None);
    }
    if request.protocol_version != PROTOCOL {
        return api_error(
            409,
            "fleet_version_mismatch",
            "Unsupported Coven Fleet protocol version.",
            Some(json!({"supported": [PROTOCOL]})),
        );
    }
    let request_id = format!("pair_{}", Uuid::new_v4().simple());
    let request_secret = secret("cvpair");
    let now = Utc::now();
    let expires = now + Duration::seconds(DEFAULT_ENROLLMENT_TTL_SECONDS);
    open(home)?.execute(
        "INSERT INTO fleet_pairing_requests
         (request_id, node_id, request_secret_hash, protocol_version, state, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)",
        params![
            request_id,
            request.node_id,
            hash(&request_secret),
            PROTOCOL,
            expires.to_rfc3339(),
            now.to_rfc3339()
        ],
    )?;
    json_response(
        202,
        &json!({
            "requestId": request_id,
            "requestSecret": request_secret,
            "state": "pending",
            "expiresAt": expires.to_rfc3339()
        }),
    )
}

pub fn list_pairing_requests(home: &Path) -> Result<ApiResponse> {
    let conn = open(home)?;
    let mut statement = conn.prepare(
        "SELECT request_id, node_id, state, expires_at, created_at, decided_at
         FROM fleet_pairing_requests WHERE state='pending' AND expires_at > ?1
         ORDER BY created_at",
    )?;
    let requests = statement
        .query_map([Utc::now().to_rfc3339()], |row| {
            Ok(json!({
                "requestId": row.get::<_, String>(0)?,
                "nodeId": row.get::<_, String>(1)?,
                "state": row.get::<_, String>(2)?,
                "expiresAt": row.get::<_, String>(3)?,
                "createdAt": row.get::<_, String>(4)?,
                "decidedAt": row.get::<_, Option<String>>(5)?
            }))
        })?
        .collect::<rusqlite::Result<Vec<Value>>>()?;
    json_response(200, &json!({"requests": requests}))
}

pub fn decide_pairing(home: &Path, request_id: &str, approve: bool) -> Result<ApiResponse> {
    let conn = open(home)?;
    let existing: Option<(String, String)> = conn
        .query_row(
            "SELECT state, expires_at FROM fleet_pairing_requests WHERE request_id=?1",
            [request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((state, expires_at)) = existing else {
        return api_error(
            404,
            "pairing_request_not_found",
            "Pairing request was not found.",
            None,
        );
    };
    if parse_time(&expires_at)? <= Utc::now() {
        return api_error(
            410,
            "pairing_request_expired",
            "Pairing request has expired.",
            None,
        );
    }
    let target = if approve { "approved" } else { "denied" };
    if state != "pending" && state != target {
        return api_error(
            409,
            "pairing_request_decided",
            "Pairing request already has a different decision.",
            None,
        );
    }
    conn.execute(
        "UPDATE fleet_pairing_requests SET state=?1, decided_at=COALESCE(decided_at, ?2)
         WHERE request_id=?3",
        params![target, Utc::now().to_rfc3339(), request_id],
    )?;
    json_response(200, &json!({"requestId": request_id, "state": target}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimPairing {
    request_secret: String,
}

pub fn claim_pairing(home: &Path, request_id: &str, body: Option<&str>) -> Result<ApiResponse> {
    let request: ClaimPairing = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let mut conn = open(home)?;
    let tx = conn.transaction()?;
    let record: Option<(String, String, String, String, Option<String>)> = tx
        .query_row(
            "SELECT node_id, request_secret_hash, state, expires_at, delivered_at
             FROM fleet_pairing_requests WHERE request_id=?1",
            [request_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((node_id, secret_hash, state, expires_at, delivered_at)) = record else {
        return api_error(
            404,
            "pairing_request_not_found",
            "Pairing request was not found.",
            None,
        );
    };
    if !constant_time_equal(&hash(&request.request_secret), &secret_hash) {
        return api_error(
            401,
            "pairing_request_unauthorized",
            "Pairing request proof is invalid.",
            None,
        );
    }
    if parse_time(&expires_at)? <= Utc::now() {
        return api_error(
            410,
            "pairing_request_expired",
            "Pairing request has expired.",
            None,
        );
    }
    if state == "pending" {
        return json_response(202, &json!({"requestId": request_id, "state": "pending"}));
    }
    if state == "denied" {
        return api_error(
            403,
            "pairing_request_denied",
            "Pairing request was denied.",
            None,
        );
    }
    if delivered_at.is_some() {
        return api_error(
            409,
            "pairing_credential_delivered",
            "Pairing credential has already been delivered.",
            None,
        );
    }
    let credential = secret("cvnode");
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE fleet_pairing_requests SET delivered_at=?1 WHERE request_id=?2 AND delivered_at IS NULL",
        params![now, request_id],
    )?;
    tx.execute(
        "INSERT INTO fleet_trusted_nodes (node_id, credential_hash, enrolled_at, last_seen_at, revoked_at)
         VALUES (?1, ?2, ?3, ?3, NULL)
         ON CONFLICT(node_id) DO UPDATE SET credential_hash=excluded.credential_hash,
         enrolled_at=excluded.enrolled_at, last_seen_at=excluded.last_seen_at, revoked_at=NULL",
        params![node_id, hash(&credential), now],
    )?;
    tx.commit()?;
    json_response(
        200,
        &json!({
            "requestId": request_id, "state": "approved", "nodeId": node_id,
            "nodeCredential": credential, "protocolVersion": PROTOCOL
        }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoreLocalCredential {
    hub_id: String,
    node_id: String,
    node_credential: String,
}

pub fn store_local_credential(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: StoreLocalCredential = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if [
        request.hub_id.as_str(),
        request.node_id.as_str(),
        request.node_credential.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return api_error(
            400,
            "invalid_request",
            "hubId, nodeId, and nodeCredential are required.",
            None,
        );
    }
    open(home)?.execute(
        "INSERT INTO fleet_local_credentials (hub_id, node_id, node_credential, stored_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(hub_id) DO UPDATE SET node_id=excluded.node_id,
         node_credential=excluded.node_credential, stored_at=excluded.stored_at",
        params![
            request.hub_id,
            request.node_id,
            request.node_credential,
            Utc::now().to_rfc3339()
        ],
    )?;
    json_response(
        200,
        &json!({"hubId": request.hub_id, "nodeId": request.node_id, "stored": true}),
    )
}

#[derive(Deserialize)]
struct LocalProofRequest {
    nonce: String,
}

pub fn local_proof(home: &Path, hub_id: &str, body: Option<&str>) -> Result<ApiResponse> {
    let request: LocalProofRequest = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let conn = open(home)?;
    let local: Option<(String, String)> = conn
        .query_row(
            "SELECT node_id, node_credential FROM fleet_local_credentials WHERE hub_id=?1",
            [hub_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((node_id, credential)) = local else {
        return api_error(
            404,
            "local_credential_not_found",
            "No local credential exists for this hub.",
            None,
        );
    };
    let derived = hash(&format!(
        "{PROTOCOL}\0{}\0{}",
        hash(&credential),
        request.nonce
    ));
    json_response(
        200,
        &json!({"hubId": hub_id, "nodeId": node_id, "nonce": request.nonce, "proof": derived}),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeRequest {
    node_id: String,
}

pub fn create_challenge(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: NodeRequest = match parse(body) {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let conn = open(home)?;
    let trusted: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM fleet_trusted_nodes WHERE node_id=?1 AND revoked_at IS NULL)",
        [&request.node_id],
        |r| r.get(0),
    )?;
    if !trusted {
        return api_error(401, "node_untrusted", "Node is not trusted.", None);
    }
    let nonce = secret("cvchallenge");
    let expires = Utc::now() + Duration::seconds(CHALLENGE_TTL_SECONDS);
    conn.execute("INSERT INTO fleet_challenges (node_id, nonce_hash, expires_at, used_at) VALUES (?1, ?2, ?3, NULL)", params![request.node_id, hash(&nonce), expires.to_rfc3339()])?;
    json_response(
        201,
        &json!({ "nonce": nonce, "expiresAt": expires.to_rfc3339(), "singleUse": true }),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reconnect {
    node_id: String,
    nonce: String,
    proof: String,
}

pub fn reconnect(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: Reconnect = match parse(body) {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let mut conn = open(home)?;
    let tx = conn.transaction()?;
    let stored: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT credential_hash, revoked_at FROM fleet_trusted_nodes WHERE node_id=?1",
            [&request.node_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((credential_hash, revoked)) = stored else {
        return api_error(401, "node_untrusted", "Node is not trusted.", None);
    };
    if revoked.is_some() {
        return api_error(
            403,
            "node_revoked",
            "Node credential has been revoked.",
            None,
        );
    }
    let expected_proof = hash(&format!("{PROTOCOL}\0{credential_hash}\0{}", request.nonce));
    if !constant_time_equal(&request.proof, &expected_proof) {
        return api_error(
            401,
            "node_authentication_failed",
            "Node credential proof is invalid.",
            None,
        );
    }
    let challenge: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT expires_at, used_at FROM fleet_challenges WHERE node_id=?1 AND nonce_hash=?2",
            params![request.node_id, hash(&request.nonce)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((expires, used)) = challenge else {
        return api_error(
            401,
            "challenge_invalid",
            "Reconnect challenge is invalid.",
            None,
        );
    };
    if used.is_some() {
        return api_error(
            409,
            "challenge_used",
            "Reconnect challenge has already been used.",
            None,
        );
    }
    if parse_time(&expires)? <= Utc::now() {
        return api_error(
            410,
            "challenge_expired",
            "Reconnect challenge has expired.",
            None,
        );
    }
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "UPDATE fleet_challenges SET used_at=?1 WHERE node_id=?2 AND nonce_hash=?3",
        params![now, request.node_id, hash(&request.nonce)],
    )?;
    tx.execute(
        "UPDATE fleet_trusted_nodes SET last_seen_at=?1 WHERE node_id=?2",
        params![now, request.node_id],
    )?;
    tx.commit()?;
    json_response(
        200,
        &json!({ "authenticated": true, "nodeId": request.node_id }),
    )
}

pub fn revoke(home: &Path, node_id: &str) -> Result<ApiResponse> {
    let changed = open(home)?.execute(
        "UPDATE fleet_trusted_nodes SET revoked_at=COALESCE(revoked_at, ?1) WHERE node_id=?2",
        params![Utc::now().to_rfc3339(), node_id],
    )?;
    if changed == 0 {
        return api_error(404, "node_not_found", "Trusted node was not found.", None);
    }
    json_response(200, &json!({ "nodeId": node_id, "revoked": true }))
}

pub fn list_trusted_nodes(home: &Path) -> Result<ApiResponse> {
    let conn = open(home)?;
    let mut statement = conn.prepare("SELECT node_id, enrolled_at, last_seen_at, revoked_at, display_name, capabilities_json, executor_availability FROM fleet_trusted_nodes ORDER BY enrolled_at")?;
    let nodes = statement.query_map([], |r| Ok(json!({"nodeId": r.get::<_, String>(0)?, "enrolledAt": r.get::<_, String>(1)?, "lastSeenAt": r.get::<_, String>(2)?, "revokedAt": r.get::<_, Option<String>>(3)?, "displayName": r.get::<_, Option<String>>(4)?, "capabilities": serde_json::from_str::<Vec<String>>(&r.get::<_, String>(5)?).unwrap_or_default(), "executorAvailability": r.get::<_, String>(6)?})))?.collect::<rusqlite::Result<Vec<Value>>>()?;
    json_response(200, &json!({ "nodes": nodes }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueueFleetJob {
    target_node_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueueRemoteTurn {
    turn_id: String,
    target_node_id: String,
    familiar_id: String,
    harness: String,
    #[serde(default)]
    model: Option<String>,
    workspace: RemoteTurnWorkspace,
    prompt: String,
    #[serde(default)]
    context_messages: Vec<RemoteTurnMessage>,
    #[serde(default)]
    attachments: Vec<RemoteTurnAttachment>,
    permission_mode: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteTurnWorkspace {
    root: String,
    #[serde(default)]
    project_name: Option<String>,
    #[serde(default)]
    repository_url: Option<String>,
    #[serde(default)]
    checkpoint: Option<String>,
    #[serde(default)]
    subdirectory: Option<String>,
    #[serde(default)]
    overlay: Option<RemoteTurnWorkspaceOverlay>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteTurnWorkspaceOverlay {
    patch_base64: String,
    digest: String,
    #[serde(default)]
    untracked_files: Vec<RemoteTurnWorkspaceFile>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteTurnWorkspaceFile {
    path: String,
    data_base64: String,
    #[serde(default)]
    executable: bool,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteTurnMessage {
    role: String,
    text: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteTurnAttachment {
    name: String,
    mime_type: String,
    data_base64: String,
}

fn bounded_remote_field(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_REMOTE_TURN_FIELD_BYTES
}

fn valid_remote_identifier(value: &str) -> bool {
    bounded_remote_field(value)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
}

fn valid_remote_token(value: &str) -> bool {
    bounded_remote_field(value)
        && value != "."
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_remote_turn(request: &QueueRemoteTurn) -> std::result::Result<(), &'static str> {
    if !valid_remote_token(&request.turn_id)
        || !valid_remote_token(&request.target_node_id)
        || !valid_remote_token(&request.familiar_id)
        || !valid_remote_token(&request.harness)
        || request
            .model
            .as_deref()
            .is_some_and(|value| !valid_remote_identifier(value))
    {
        return Err("remote turn identifiers are invalid");
    }
    if request.prompt.trim().is_empty() || request.prompt.len() > MAX_REMOTE_TURN_PROMPT_BYTES {
        return Err("remote turn prompt is empty or too large");
    }
    if !bounded_remote_field(&request.workspace.root)
        || request
            .workspace
            .project_name
            .as_deref()
            .is_some_and(|value| !bounded_remote_field(value))
        || request
            .workspace
            .repository_url
            .as_deref()
            .is_some_and(|value| !bounded_remote_field(value))
        || request
            .workspace
            .checkpoint
            .as_deref()
            .is_some_and(|value| !valid_remote_token(value))
        || request
            .workspace
            .subdirectory
            .as_deref()
            .is_some_and(|value| {
                !bounded_remote_field(value)
                    || value.starts_with('/')
                    || value.starts_with('\\')
                    || value.split(['/', '\\']).any(|part| part == "..")
            })
    {
        return Err("remote turn workspace is invalid");
    }
    if let Some(overlay) = request.workspace.overlay.as_ref() {
        let encoded_bytes = overlay.patch_base64.len()
            + overlay
                .untracked_files
                .iter()
                .map(|file| file.data_base64.len())
                .sum::<usize>();
        if !valid_remote_token(&overlay.digest)
            || overlay.untracked_files.len() > MAX_REMOTE_TURN_UNTRACKED_FILES
            || encoded_bytes > MAX_REMOTE_TURN_ENCODED_BINARY_BYTES
            || overlay.untracked_files.iter().any(|file| {
                !bounded_remote_field(&file.path)
                    || file.path.starts_with('/')
                    || file.path.starts_with('\\')
                    || file.path.split(['/', '\\']).any(|part| part == "..")
            })
        {
            return Err("remote turn workspace overlay is invalid");
        }
    }
    if !matches!(request.permission_mode.as_str(), "read" | "full") {
        return Err("remote turn permission mode is invalid");
    }
    if request.context_messages.len() > MAX_REMOTE_TURN_CONTEXT_MESSAGES
        || request.attachments.len() > MAX_REMOTE_TURN_ATTACHMENTS
        || request
            .timeout_seconds
            .is_some_and(|seconds| !(1..=3600).contains(&seconds))
    {
        return Err("remote turn bounds were exceeded");
    }
    if request.context_messages.iter().any(|message| {
        !matches!(message.role.as_str(), "user" | "assistant" | "system")
            || message.text.len() > MAX_REMOTE_TURN_PROMPT_BYTES
    }) {
        return Err("remote turn context is invalid");
    }
    if request
        .context_messages
        .iter()
        .map(|message| message.text.len())
        .sum::<usize>()
        > MAX_REMOTE_TURN_CONTEXT_BYTES
    {
        return Err("remote turn context is too large");
    }
    if request.attachments.iter().any(|attachment| {
        !bounded_remote_field(&attachment.name) || !bounded_remote_field(&attachment.mime_type)
    }) || request
        .attachments
        .iter()
        .map(|attachment| attachment.data_base64.len())
        .sum::<usize>()
        > MAX_REMOTE_TURN_ENCODED_BINARY_BYTES
    {
        return Err("remote turn attachment is invalid");
    }
    Ok(())
}

pub fn queue_remote_turn_job(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: QueueRemoteTurn = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if let Err(message) = validate_remote_turn(&request) {
        return api_error(400, "invalid_remote_turn", message, None);
    }
    let conn = open(home)?;
    let trusted: Option<(String, String, String)> = conn.query_row(
        "SELECT last_seen_at, capabilities_json, executor_availability FROM fleet_trusted_nodes WHERE node_id=?1 AND revoked_at IS NULL",
        [&request.target_node_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    let Some((last_seen_at, capabilities_json, executor_availability)) = trusted else {
        return api_error(
            404,
            "node_untrusted",
            "Choose an approved Fleet device.",
            None,
        );
    };
    let recently_seen = DateTime::parse_from_rfc3339(&last_seen_at)
        .map(|seen| {
            Utc::now().signed_duration_since(seen.with_timezone(&Utc)) <= Duration::seconds(15)
        })
        .unwrap_or(false);
    if !recently_seen {
        return api_error(
            409,
            "executor_offline",
            "The selected Fleet executor is offline. Open Cave on that device and wait for it to reconnect.",
            Some(json!({"nodeId": request.target_node_id, "lastSeenAt": last_seen_at})),
        );
    }
    let capabilities: Vec<String> = serde_json::from_str(&capabilities_json).unwrap_or_default();
    if !capabilities
        .iter()
        .any(|value| value == "fleet-managed-workspace-v1")
    {
        return api_error(
            409,
            "executor_incompatible",
            "Update Coven on the selected Fleet executor, then let it reconnect.",
            Some(json!({"requiredCapability": "fleet-managed-workspace-v1"})),
        );
    }
    let unavailable = match executor_availability.as_str() {
        "available" | "unknown" => None,
        "draining" => Some((
            "executor_draining",
            "The selected Fleet executor is draining. Resume it before dispatching another turn.",
        )),
        "unshared" => Some((
            "executor_unshared",
            "The selected Fleet executor is not shared. Enable executor sharing on that device.",
        )),
        "stopped" => Some((
            "executor_stopped",
            "The selected Fleet executor is stopped. Start it on that device before retrying.",
        )),
        "not-executor" => Some((
            "executor_unavailable",
            "The selected Fleet device is not configured as an executor.",
        )),
        _ => Some((
            "executor_unavailable",
            "The selected Fleet executor is not accepting work.",
        )),
    };
    if let Some((code, message)) = unavailable {
        return api_error(
            409,
            code,
            message,
            Some(json!({"nodeId": request.target_node_id, "availability": executor_availability})),
        );
    }
    let job_id = format!("fleetturn_{}", request.turn_id);
    let existing: Option<(String, String)> = conn
        .query_row(
            "SELECT target_node_id, spec_json FROM fleet_jobs WHERE job_id=?1",
            [&job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let context = json!({
        "kind": "fleet-chat-turn",
        "schemaVersion": "coven.fleet.chat-turn.v1",
        "turnId": request.turn_id,
        "familiarId": request.familiar_id,
        "harness": request.harness,
        "model": request.model,
        "workspace": request.workspace,
        "prompt": request.prompt,
        "contextMessages": request.context_messages,
        "attachments": request.attachments,
        "permissionMode": request.permission_mode,
        "serviceAdvertisements": []
    });
    let spec = json!({
        "protocolVersion": crate::executor_node::EXECUTOR_PROTOCOL_VERSION,
        "jobId": job_id,
        "hubId": load_or_create_local_node(&conn)?.device_id,
        "requiredCapabilities": ["shell", "fleet-chat-turn-v1", "fleet-managed-workspace-v1"],
        "command": ["coven:fleet-chat-turn"],
        "env": {},
        "context": context,
        "timeoutSeconds": request.timeout_seconds.unwrap_or(900)
    });
    if let Some((target_node_id, prior_spec)) = existing {
        if target_node_id != request.target_node_id || prior_spec != spec.to_string() {
            return api_error(
                409,
                "remote_turn_conflict",
                "This turn id was already dispatched with different execution details.",
                Some(json!({"turnId": request.turn_id})),
            );
        }
        let state: String = conn.query_row(
            "SELECT state FROM fleet_jobs WHERE job_id=?1",
            [&job_id],
            |row| row.get(0),
        )?;
        return json_response(
            200,
            &json!({
                "jobId": job_id, "turnId": request.turn_id,
                "targetNodeId": request.target_node_id, "state": state,
                "idempotent": true
            }),
        );
    }
    let created_at = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO fleet_jobs
         (job_id, target_node_id, spec_json, state, created_at)
         VALUES (?1, ?2, ?3, 'queued', ?4)",
        params![job_id, request.target_node_id, spec.to_string(), created_at],
    )?;
    json_response(
        201,
        &json!({
            "jobId": job_id, "turnId": request.turn_id,
            "targetNodeId": request.target_node_id, "state": "queued",
            "createdAt": created_at, "idempotent": false
        }),
    )
}

pub fn cancel_fleet_job(home: &Path, job_id: &str) -> Result<ApiResponse> {
    if !valid_remote_token(job_id) {
        return api_error(400, "invalid_fleet_job", "Fleet job id is invalid.", None);
    }
    let conn = open(home)?;
    let state: Option<String> = conn
        .query_row(
            "SELECT state FROM fleet_jobs WHERE job_id=?1",
            [job_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(state) = state else {
        return api_error(404, "fleet_job_not_found", "Fleet job was not found.", None);
    };
    if matches!(state.as_str(), "completed" | "failed" | "cancelled") {
        return json_response(200, &json!({"jobId": job_id, "state": state}));
    }
    conn.execute(
        "UPDATE fleet_jobs SET state='cancelled', completed_at=?1
         WHERE job_id=?2 AND state IN ('queued', 'leased')",
        params![Utc::now().to_rfc3339(), job_id],
    )?;
    json_response(200, &json!({"jobId": job_id, "state": "cancelled"}))
}

pub fn queue_system_info_job(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: QueueFleetJob = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let conn = open(home)?;
    let trusted: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM fleet_trusted_nodes WHERE node_id=?1 AND revoked_at IS NULL)",
        [&request.target_node_id],
        |row| row.get(0),
    )?;
    if !trusted {
        return api_error(
            404,
            "node_untrusted",
            "Choose an approved Fleet device.",
            None,
        );
    }
    let job_id = format!("fleetjob_{}", Uuid::new_v4().simple());
    let spec = json!({
        "protocolVersion": crate::executor_node::EXECUTOR_PROTOCOL_VERSION,
        "jobId": job_id,
        "hubId": load_or_create_local_node(&conn)?.device_id,
        "requiredCapabilities": ["shell"],
        "command": ["coven:fleet-system-info"],
        "env": {},
        "context": {"kind": "fleet-system-info"},
        "timeoutSeconds": 30
    });
    let created_at = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO fleet_jobs
         (job_id, target_node_id, spec_json, state, created_at)
         VALUES (?1, ?2, ?3, 'queued', ?4)",
        params![job_id, request.target_node_id, spec.to_string(), created_at],
    )?;
    json_response(
        201,
        &json!({
            "jobId": job_id, "targetNodeId": request.target_node_id,
            "state": "queued", "createdAt": created_at
        }),
    )
}

pub fn list_fleet_jobs(home: &Path) -> Result<ApiResponse> {
    let conn = open(home)?;
    let mut statement = conn.prepare(
        "SELECT job_id, target_node_id, state, result_json, created_at, leased_at, completed_at
         FROM fleet_jobs ORDER BY created_at DESC LIMIT 50",
    )?;
    let jobs = statement
        .query_map([], |row| {
            let result: Option<String> = row.get(3)?;
            Ok(json!({
                "jobId": row.get::<_, String>(0)?,
                "targetNodeId": row.get::<_, String>(1)?,
                "state": row.get::<_, String>(2)?,
                "result": result.and_then(|value| serde_json::from_str::<Value>(&value).ok()),
                "createdAt": row.get::<_, String>(4)?,
                "leasedAt": row.get::<_, Option<String>>(5)?,
                "completedAt": row.get::<_, Option<String>>(6)?
            }))
        })?
        .collect::<rusqlite::Result<Vec<Value>>>()?;
    json_response(200, &json!({"jobs": jobs}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticatedFleetRequest {
    node_id: String,
    nonce: String,
    proof: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    accepting_jobs: Option<bool>,
    #[serde(default)]
    availability_reason: Option<String>,
    #[serde(default)]
    workspaces: Option<Vec<FleetWorkspaceAdvertisement>>,
}

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct FleetWorkspaceAdvertisement {
    #[serde(default)]
    project_name: Option<String>,
    #[serde(default)]
    repository_url: Option<String>,
    #[serde(default)]
    checkpoint: Option<String>,
}

fn valid_workspace_inventory(inventory: &[FleetWorkspaceAdvertisement]) -> bool {
    inventory.len() <= 128
        && inventory.iter().all(|workspace| {
            (workspace.project_name.is_some() || workspace.repository_url.is_some())
                && workspace
                    .project_name
                    .as_deref()
                    .is_none_or(bounded_remote_field)
                && workspace
                    .repository_url
                    .as_deref()
                    .is_none_or(bounded_remote_field)
                && workspace
                    .checkpoint
                    .as_deref()
                    .is_none_or(valid_remote_token)
        })
}

fn authenticate_fleet_request(
    home: &Path,
    request: &AuthenticatedFleetRequest,
) -> Result<Option<ApiResponse>> {
    let body = json!({
        "nodeId": request.node_id,
        "nonce": request.nonce,
        "proof": request.proof
    })
    .to_string();
    let response = reconnect(home, Some(&body))?;
    Ok((response.status != 200).then_some(response))
}

pub fn claim_fleet_job(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: AuthenticatedFleetRequest = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if let Some(response) = authenticate_fleet_request(home, &request)? {
        return Ok(response);
    }
    let mut conn = open(home)?;
    let mut advertised = request.capabilities;
    advertised.sort();
    advertised.dedup();
    advertised.retain(|value| valid_remote_identifier(value));
    if request
        .workspaces
        .as_deref()
        .is_some_and(|inventory| !valid_workspace_inventory(inventory))
    {
        return api_error(
            400,
            "invalid_workspace_inventory",
            "Fleet workspace inventory is invalid.",
            None,
        );
    }
    conn.execute(
        "UPDATE fleet_trusted_nodes SET capabilities_json=?1, display_name=COALESCE(?2, display_name), executor_availability=?3, workspace_inventory_json=COALESCE(?4, workspace_inventory_json) WHERE node_id=?5",
        params![
            serde_json::to_string(&advertised)?,
            request.display_name.as_deref().filter(|value| bounded_remote_field(value)),
            request.availability_reason.as_deref().filter(|value| matches!(*value, "available" | "draining" | "unshared" | "stopped" | "not-executor")).unwrap_or(if request.accepting_jobs == Some(false) { "unavailable" } else { "available" }),
            request.workspaces.as_ref().map(serde_json::to_string).transpose()?,
            request.node_id
        ],
    )?;
    if request.accepting_jobs == Some(false) {
        return json_response(
            200,
            &json!({"job": null, "availability": request.availability_reason.unwrap_or_else(|| "unavailable".to_string())}),
        );
    }
    let tx = conn.transaction()?;
    let queued: Option<(String, String)> = tx
        .query_row(
            "SELECT job_id, spec_json FROM fleet_jobs
             WHERE target_node_id=?1 AND
             (state='queued' OR (state='leased' AND lease_expires_at <= ?2))
             ORDER BY created_at LIMIT 1",
            params![request.node_id, Utc::now().to_rfc3339()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((job_id, spec_json)) = queued else {
        tx.commit()?;
        return json_response(200, &json!({"job": null}));
    };
    let lease_id = format!("lease_{}", Uuid::new_v4().simple());
    let now = Utc::now();
    let leased_at = now.to_rfc3339();
    let requested_timeout = serde_json::from_str::<Value>(&spec_json)
        .ok()
        .and_then(|spec| spec.get("timeoutSeconds").and_then(Value::as_u64))
        .unwrap_or(JOB_LEASE_TTL_SECONDS as u64)
        .clamp(JOB_LEASE_TTL_SECONDS as u64, 3600);
    let lease_expires_at =
        (now + Duration::seconds(requested_timeout as i64 + JOB_LEASE_TTL_SECONDS)).to_rfc3339();
    let changed = tx.execute(
        "UPDATE fleet_jobs SET state='leased', lease_id=?1, leased_at=?2, lease_expires_at=?3
         WHERE job_id=?4 AND (state='queued' OR (state='leased' AND lease_expires_at <= ?2))",
        params![lease_id, leased_at, lease_expires_at, job_id],
    )?;
    if changed != 1 {
        tx.commit()?;
        return json_response(200, &json!({"job": null}));
    }
    tx.commit()?;
    let spec: Value = serde_json::from_str(&spec_json)?;
    json_response(200, &json!({"job": spec, "leaseId": lease_id}))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompleteFleetJob {
    node_id: String,
    nonce: String,
    proof: String,
    job_id: String,
    lease_id: String,
    result: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FleetJobStatusRequest {
    node_id: String,
    nonce: String,
    proof: String,
    job_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppendFleetJobEvents {
    node_id: String,
    nonce: String,
    proof: String,
    job_id: String,
    events: Vec<FleetJobEventInput>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FleetJobEventInput {
    sequence: i64,
    chunk_base64: String,
}

pub fn append_authenticated_fleet_job_events(
    home: &Path,
    body: Option<&str>,
) -> Result<ApiResponse> {
    let request: AppendFleetJobEvents = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if request.events.len() > 128
        || request
            .events
            .iter()
            .any(|event| event.sequence < 1 || event.chunk_base64.len() > 32 * 1024)
    {
        return api_error(
            400,
            "invalid_fleet_events",
            "Fleet event batch is invalid.",
            None,
        );
    }
    let auth = AuthenticatedFleetRequest {
        node_id: request.node_id.clone(),
        nonce: request.nonce,
        proof: request.proof,
        capabilities: Vec::new(),
        display_name: None,
        accepting_jobs: None,
        availability_reason: None,
        workspaces: None,
    };
    if let Some(response) = authenticate_fleet_request(home, &auth)? {
        return Ok(response);
    }
    let mut conn = open(home)?;
    let owned: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM fleet_jobs WHERE job_id=?1 AND target_node_id=?2)",
        params![request.job_id, request.node_id],
        |row| row.get(0),
    )?;
    if !owned {
        return api_error(404, "fleet_job_not_found", "Fleet job was not found.", None);
    }
    let tx = conn.transaction()?;
    for event in &request.events {
        tx.execute(
            "INSERT OR IGNORE INTO fleet_job_events (job_id, sequence, chunk_base64, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                request.job_id,
                event.sequence,
                event.chunk_base64,
                Utc::now().to_rfc3339()
            ],
        )?;
    }
    tx.commit()?;
    json_response(
        200,
        &json!({"jobId": request.job_id, "accepted": request.events.len()}),
    )
}

pub fn list_local_fleet_job_events(home: &Path, job_id: &str) -> Result<ApiResponse> {
    if !valid_remote_token(job_id) {
        return api_error(400, "invalid_fleet_job", "Fleet job id is invalid.", None);
    }
    let conn = open(home)?;
    let mut statement = conn.prepare(
        "SELECT sequence, chunk_base64 FROM fleet_job_events
         WHERE job_id=?1 ORDER BY sequence LIMIT 4096",
    )?;
    let events = statement
        .query_map([job_id], |row| {
            Ok(json!({
                "sequence": row.get::<_, i64>(0)?,
                "chunkBase64": row.get::<_, String>(1)?
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    json_response(200, &json!({"jobId": job_id, "events": events}))
}

pub fn authenticated_fleet_job_status(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: FleetJobStatusRequest = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let auth = AuthenticatedFleetRequest {
        node_id: request.node_id.clone(),
        nonce: request.nonce,
        proof: request.proof,
        capabilities: Vec::new(),
        display_name: None,
        accepting_jobs: None,
        availability_reason: None,
        workspaces: None,
    };
    if let Some(response) = authenticate_fleet_request(home, &auth)? {
        return Ok(response);
    }
    let state: Option<String> = open(home)?
        .query_row(
            "SELECT state FROM fleet_jobs WHERE job_id=?1 AND target_node_id=?2",
            params![request.job_id, request.node_id],
            |row| row.get(0),
        )
        .optional()?;
    match state {
        Some(state) => json_response(200, &json!({"jobId": request.job_id, "state": state})),
        None => api_error(404, "fleet_job_not_found", "Fleet job was not found.", None),
    }
}

pub fn complete_fleet_job(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: CompleteFleetJob = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let auth = AuthenticatedFleetRequest {
        node_id: request.node_id.clone(),
        nonce: request.nonce.clone(),
        proof: request.proof.clone(),
        capabilities: Vec::new(),
        display_name: None,
        accepting_jobs: None,
        availability_reason: None,
        workspaces: None,
    };
    if let Some(response) = authenticate_fleet_request(home, &auth)? {
        return Ok(response);
    }
    let conn = open(home)?;
    let current: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT state, lease_id FROM fleet_jobs WHERE job_id=?1 AND target_node_id=?2",
            params![request.job_id, request.node_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((state, lease_id)) = current else {
        return api_error(404, "fleet_job_not_found", "Fleet job was not found.", None);
    };
    if matches!(state.as_str(), "completed" | "failed" | "cancelled") {
        return json_response(200, &json!({"jobId": request.job_id, "state": state}));
    }
    if state != "leased" || lease_id.as_deref() != Some(request.lease_id.as_str()) {
        return api_error(
            409,
            "fleet_job_lease_invalid",
            "Fleet job lease is invalid.",
            None,
        );
    }
    let result_state = if request.result.get("status").and_then(Value::as_str) == Some("completed")
    {
        "completed"
    } else {
        "failed"
    };
    conn.execute(
        "UPDATE fleet_jobs SET state=?1, result_json=?2, completed_at=?3
         WHERE job_id=?4 AND target_node_id=?5 AND lease_id=?6 AND state='leased'",
        params![
            result_state,
            request.result.to_string(),
            Utc::now().to_rfc3339(),
            request.job_id,
            request.node_id,
            request.lease_id
        ],
    )?;
    json_response(
        200,
        &json!({"jobId": request.job_id, "state": result_state}),
    )
}

fn remote_turn_attachment_name(name: &str, index: usize) -> String {
    let safe: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .take(96)
        .collect();
    format!(
        "{index:02}-{}",
        if safe.is_empty() { "attachment" } else { &safe }
    )
}

fn valid_github_repository_url(value: &str) -> bool {
    let Some(slug) = value.strip_prefix("https://github.com/") else {
        return false;
    };
    if slug.contains(['?', '#', '@']) || slug.ends_with(".git") {
        return false;
    }
    let mut parts = slug.split('/');
    let owner = parts.next().unwrap_or_default();
    let repository = parts.next().unwrap_or_default();
    parts.next().is_none()
        && !owner.is_empty()
        && owner.len() <= 39
        && !owner.starts_with('-')
        && !owner.ends_with('-')
        && owner
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !repository.is_empty()
        && repository.len() <= 100
        && repository
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && repository != "."
        && repository != ".."
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(*byte) >> 4] as char);
        encoded.push(HEX[usize::from(*byte) & 0x0f] as char);
    }
    encoded
}

fn managed_turn_directory(turn_id: &str) -> String {
    let digest = Sha256::digest(turn_id.as_bytes());
    format!("turn-{}", &hex_bytes(&digest)[..32])
}

fn safe_workspace_relative_path(value: &str) -> Option<PathBuf> {
    if value.trim().is_empty() || value.contains('\\') {
        return None;
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return None;
    }
    Some(path.to_path_buf())
}

fn git_ok(cwd: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn git_stdout(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn fleet_workspace_error(code: &str, message: &str, turn_id: &str) -> ApiResponse {
    api_error(409, code, message, Some(json!({"turnId": turn_id})))
        .expect("serialize Fleet workspace error")
}

fn prepare_remote_turn_workspace(
    home: &Path,
    workspace_value: &Value,
    turn_id: &str,
) -> std::result::Result<PathBuf, ApiResponse> {
    let workspace: RemoteTurnWorkspace =
        serde_json::from_value(workspace_value.clone()).map_err(|_| {
            fleet_workspace_error(
                "remote_workspace_invalid",
                "The hub supplied an invalid Fleet workspace specification.",
                turn_id,
            )
        })?;
    let repository_url = workspace.repository_url.as_deref().filter(|value| {
        valid_github_repository_url(value)
    }).ok_or_else(|| {
        fleet_workspace_error(
            "remote_repository_required",
            "This project has no supported GitHub remote. Add a GitHub remote on the hub, then retry.",
            turn_id,
        )
    })?;
    let checkpoint = workspace
        .checkpoint
        .as_deref()
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| {
            fleet_workspace_error(
            "remote_checkpoint_required",
            "This project has no portable Git checkpoint. Commit the project state, then retry.",
            turn_id,
        )
        })?;
    let mut repository_digest = Sha256::new();
    repository_digest.update(repository_url.as_bytes());
    let repository_key = hex_bytes(&repository_digest.finalize());
    let managed_root = home.join("fleet-workspaces").join(&repository_key[..32]);
    let checkout = managed_root.join(managed_turn_directory(turn_id));
    fs::create_dir_all(&managed_root).map_err(|_| {
        fleet_workspace_error(
            "remote_workspace_prepare_failed",
            "Fleet could not create its managed workspace on this executor.",
            turn_id,
        )
    })?;
    let git_dir = checkout.join(".git");
    if !git_dir.is_dir() {
        if checkout.exists() {
            fs::remove_dir_all(&checkout).map_err(|_| {
                fleet_workspace_error(
                    "remote_workspace_prepare_failed",
                    "Fleet could not reset its managed workspace on this executor.",
                    turn_id,
                )
            })?;
        }
        let cloned = Command::new("git")
            .args(["clone", "--no-checkout", repository_url])
            .arg(&checkout)
            .current_dir(&managed_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !cloned {
            return Err(fleet_workspace_error(
                "remote_repository_unavailable",
                "Fleet could not prepare this repository on the executor. Sign in to Git for this repository on that device, then retry.",
                turn_id,
            ));
        }
    }
    if git_stdout(&checkout, &["config", "--get", "remote.origin.url"]).as_deref()
        != Some(repository_url)
    {
        return Err(fleet_workspace_error(
            "remote_workspace_identity_mismatch",
            "Fleet's managed checkout does not match this repository. Retry after removing the stale managed checkout.",
            turn_id,
        ));
    }
    if !git_ok(&checkout, &["fetch", "--prune", "--no-tags", "origin"])
        || !git_ok(&checkout, &["checkout", "--detach", "--force", checkpoint])
        || !git_ok(&checkout, &["clean", "-ffdx"])
    {
        return Err(fleet_workspace_error(
            "remote_repository_unavailable",
            "Fleet could not prepare this repository on the executor. Sign in to Git for this repository on that device, then retry.",
            turn_id,
        ));
    }

    if let Some(overlay) = workspace.overlay {
        let patch = base64::engine::general_purpose::STANDARD
            .decode(&overlay.patch_base64)
            .map_err(|_| {
                fleet_workspace_error(
                    "remote_workspace_integrity_failed",
                    "The Fleet workspace changes failed integrity verification. Retry the turn from the hub.",
                    turn_id,
                )
            })?;
        let mut decoded_files = Vec::with_capacity(overlay.untracked_files.len());
        let mut decoded_bytes = patch.len();
        let mut digest = Sha256::new();
        digest.update(&patch);
        for file in overlay.untracked_files {
            let Some(relative) = safe_workspace_relative_path(&file.path) else {
                return Err(fleet_workspace_error(
                    "remote_workspace_unsafe_path",
                    "The Fleet workspace contains an unsafe path.",
                    turn_id,
                ));
            };
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&file.data_base64)
                .map_err(|_| {
                    fleet_workspace_error(
                        "remote_workspace_integrity_failed",
                        "The Fleet workspace changes failed integrity verification. Retry the turn from the hub.",
                        turn_id,
                    )
                })?;
            decoded_bytes = decoded_bytes.saturating_add(bytes.len());
            digest.update([0]);
            digest.update(file.path.as_bytes());
            digest.update([u8::from(file.executable)]);
            digest.update(&bytes);
            decoded_files.push((relative, bytes, file.executable));
        }
        if decoded_bytes > MAX_REMOTE_TURN_WORKSPACE_BYTES
            || format!("sha256-{}", hex_bytes(&digest.finalize())) != overlay.digest
        {
            return Err(fleet_workspace_error(
                "remote_workspace_integrity_failed",
                "The Fleet workspace changes failed integrity verification. Retry the turn from the hub.",
                turn_id,
            ));
        }
        if !patch.is_empty() {
            let mut child = Command::new("git")
                .args(["apply", "--binary", "--whitespace=nowarn", "-"])
                .current_dir(&checkout)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| {
                    fleet_workspace_error(
                        "remote_workspace_apply_failed",
                        "Fleet could not apply the hub workspace changes safely. Commit or reduce the changes, then retry.",
                        turn_id,
                    )
                })?;
            let wrote = child
                .stdin
                .as_mut()
                .is_some_and(|stdin| stdin.write_all(&patch).is_ok());
            let applied = child.wait().is_ok_and(|status| status.success());
            if !wrote || !applied {
                return Err(fleet_workspace_error(
                    "remote_workspace_apply_failed",
                    "Fleet could not apply the hub workspace changes safely. Commit or reduce the changes, then retry.",
                    turn_id,
                ));
            }
        }
        for (relative, bytes, executable) in decoded_files {
            let destination = checkout.join(&relative);
            let mut cursor = checkout.clone();
            if let Some(parent) = relative.parent() {
                for component in parent.components() {
                    cursor.push(component.as_os_str());
                    if cursor.exists() {
                        if fs::symlink_metadata(&cursor)
                            .is_ok_and(|metadata| metadata.file_type().is_symlink())
                        {
                            return Err(fleet_workspace_error(
                                "remote_workspace_unsafe_path",
                                "The Fleet workspace contains an unsafe path.",
                                turn_id,
                            ));
                        }
                    } else {
                        fs::create_dir(&cursor).map_err(|_| {
                            fleet_workspace_error(
                                "remote_workspace_apply_failed",
                                "Fleet could not apply the hub workspace changes safely. Commit or reduce the changes, then retry.",
                                turn_id,
                            )
                        })?;
                    }
                }
            }
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut output = options.open(&destination).map_err(|_| {
                fleet_workspace_error(
                    "remote_workspace_apply_failed",
                    "Fleet could not apply the hub workspace changes safely. Commit or reduce the changes, then retry.",
                    turn_id,
                )
            })?;
            output.write_all(&bytes).map_err(|_| {
                fleet_workspace_error(
                    "remote_workspace_apply_failed",
                    "Fleet could not apply the hub workspace changes safely. Commit or reduce the changes, then retry.",
                    turn_id,
                )
            })?;
            #[cfg(unix)]
            if executable {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).map_err(
                    |_| {
                        fleet_workspace_error(
                            "remote_workspace_apply_failed",
                            "Fleet could not apply the hub workspace changes safely. Commit or reduce the changes, then retry.",
                            turn_id,
                        )
                    },
                )?;
            }
        }
    }
    let cwd = if let Some(subdirectory) = workspace.subdirectory.as_deref() {
        checkout.join(safe_workspace_relative_path(subdirectory).ok_or_else(|| {
            fleet_workspace_error(
                "remote_workspace_unsafe_path",
                "The Fleet workspace contains an unsafe subdirectory.",
                turn_id,
            )
        })?)
    } else {
        checkout.clone()
    };
    let checkout_canonical = checkout.canonicalize().map_err(|_| {
        fleet_workspace_error(
            "remote_workspace_prepare_failed",
            "Fleet could not verify its managed workspace on this executor.",
            turn_id,
        )
    })?;
    let cwd_canonical = cwd.canonicalize().map_err(|_| {
        fleet_workspace_error(
            "remote_workspace_subdirectory_missing",
            "The selected project folder does not exist at this repository revision.",
            turn_id,
        )
    })?;
    if !cwd_canonical.starts_with(&checkout_canonical) || !cwd_canonical.is_dir() {
        return Err(fleet_workspace_error(
            "remote_workspace_unsafe_path",
            "The Fleet workspace contains an unsafe subdirectory.",
            turn_id,
        ));
    }
    Ok(cwd_canonical)
}

fn remote_turn_execution_job(
    home: &Path,
    spec: &crate::executor_node::ExecutorJob,
) -> std::result::Result<(crate::executor_node::ExecutorJob, std::path::PathBuf), ApiResponse> {
    let context = spec.context.as_ref().ok_or_else(|| {
        api_error(
            400,
            "remote_turn_context_required",
            "Remote turn context is required.",
            None,
        )
        .expect("serialize API error")
    })?;
    if context.get("schemaVersion").and_then(Value::as_str) != Some("coven.fleet.chat-turn.v1")
        || context.get("kind").and_then(Value::as_str) != Some("fleet-chat-turn")
    {
        return Err(api_error(
            400,
            "remote_turn_protocol_mismatch",
            "The remote turn protocol is not supported.",
            None,
        )
        .expect("serialize API error"));
    }
    let required = |field: &str| {
        context
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| bounded_remote_field(value))
            .ok_or_else(|| {
                api_error(
                    400,
                    "invalid_remote_turn",
                    "Remote turn execution details are incomplete.",
                    Some(json!({"field": field})),
                )
                .expect("serialize API error")
            })
    };
    let turn_id = required("turnId")?;
    let familiar_id = required("familiarId")?;
    let harness = required("harness")?;
    let prompt = required("prompt")?;
    let permission = match required("permissionMode")? {
        "read" => "read-only",
        "full" => "full",
        _ => {
            return Err(api_error(
                400,
                "invalid_remote_turn",
                "Remote turn permission mode is invalid.",
                None,
            )
            .expect("serialize API error"))
        }
    };
    let workspace = context.get("workspace").ok_or_else(|| {
        api_error(
            400,
            "remote_workspace_required",
            "The remote turn needs a workspace on this executor.",
            None,
        )
        .expect("serialize API error")
    })?;
    let workspace_path = prepare_remote_turn_workspace(home, workspace, turn_id)?;

    let attachments = context
        .get("attachments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut decoded_attachments = Vec::new();
    let mut decoded_bytes = 0usize;
    for (index, attachment) in attachments.iter().enumerate() {
        let name = attachment
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("attachment");
        let encoded = attachment
            .get("dataBase64")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                api_error(
                    400,
                    "invalid_remote_attachment",
                    "A remote turn attachment is malformed.",
                    None,
                )
                .expect("serialize API error")
            })?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| {
                api_error(
                    400,
                    "invalid_remote_attachment",
                    "A remote turn attachment is malformed.",
                    None,
                )
                .expect("serialize API error")
            })?;
        decoded_bytes = decoded_bytes.saturating_add(bytes.len());
        if decoded_bytes > MAX_REMOTE_TURN_ATTACHMENT_BYTES {
            return Err(api_error(
                413,
                "remote_attachment_too_large",
                "Remote turn attachments are too large.",
                None,
            )
            .expect("serialize API error"));
        }
        decoded_attachments.push((remote_turn_attachment_name(name, index), bytes));
    }

    let model = context.get("model").and_then(Value::as_str);
    if model.is_some_and(|value| !valid_remote_identifier(value)) {
        return Err(api_error(
            400,
            "invalid_remote_turn",
            "The remote turn model is invalid.",
            None,
        )
        .expect("serialize API error"));
    }

    let attachment_root = home
        .join("fleet-turns")
        .join(managed_turn_directory(&spec.job_id));
    if attachment_root.exists() {
        fs::remove_dir_all(&attachment_root).map_err(|_| {
            api_error(
                500,
                "remote_attachment_cleanup_failed",
                "Could not prepare remote turn attachments.",
                None,
            )
            .expect("serialize API error")
        })?;
    }
    fs::create_dir_all(&attachment_root).map_err(|_| {
        api_error(
            500,
            "remote_attachment_store_failed",
            "Could not prepare remote turn attachments.",
            None,
        )
        .expect("serialize API error")
    })?;
    let mut attachment_paths = Vec::new();
    for (name, bytes) in decoded_attachments {
        let path = attachment_root.join(name);
        fs::write(&path, bytes).map_err(|_| {
            api_error(
                500,
                "remote_attachment_store_failed",
                "Could not prepare remote turn attachments.",
                None,
            )
            .expect("serialize API error")
        })?;
        attachment_paths.push(path);
    }

    let mut portable_prompt = String::from(
        "The following transcript is canonical context from the hub. Continue it; do not claim that machine-local session state is authoritative.\n\n",
    );
    if let Some(messages) = context.get("contextMessages").and_then(Value::as_array) {
        for message in messages {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("system");
            let text = message
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            portable_prompt.push_str(&format!("[{role}]\n{text}\n\n"));
        }
    }
    portable_prompt.push_str("[current user turn]\n");
    portable_prompt.push_str(prompt);
    if !attachment_paths.is_empty() {
        portable_prompt
            .push_str("\n\nAttachments are available on this executor at these paths:\n");
        for path in &attachment_paths {
            portable_prompt.push_str("- ");
            portable_prompt.push_str(&path.to_string_lossy());
            portable_prompt.push('\n');
        }
    }

    let executable = std::env::current_exe().map_err(|_| {
        api_error(
            500,
            "remote_executor_unavailable",
            "Could not resolve Coven on this executor.",
            None,
        )
        .expect("serialize API error")
    })?;
    let mut command = vec![
        executable.to_string_lossy().to_string(),
        "run".to_string(),
        harness.to_string(),
        "--stream-json".to_string(),
        "--permission".to_string(),
        permission.to_string(),
    ];
    if let Some(model) = model {
        command.extend(["--model".to_string(), model.to_string()]);
    }
    command.extend(["--".to_string(), portable_prompt]);
    let mut execution = spec.clone();
    execution.command = command;
    execution.cwd = Some(workspace_path.to_string_lossy().to_string());
    let local_device_id = open(home)
        .and_then(|conn| load_or_create_local_node(&conn))
        .map(|node| node.device_id)
        .map_err(|_| {
            api_error(
                500,
                "fleet_store_unavailable",
                "Fleet state is unavailable.",
                None,
            )
            .expect("serialize API error")
        })?;
    execution.context = Some(json!({
        "kind": "fleet-chat-turn-result",
        "schemaVersion": "coven.fleet.chat-turn-result.v1",
        "turnId": turn_id,
        "familiarId": familiar_id,
        "executorProvenance": {"deviceId": local_device_id},
        "serviceAdvertisements": []
    }));
    Ok((execution, attachment_root))
}

pub fn run_local_fleet_job(home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let mut spec: crate::executor_node::ExecutorJob = match parse(body) {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let conn = open(home)?;
    let node = load_or_create_local_node(&conn)?;
    if !role_has_executor(&node.role)
        || !node.executor_shared
        || node.lifecycle != LIFECYCLE_RUNNING
    {
        return api_error(
            409,
            "executor_unavailable",
            "This executor is not running and shared.",
            None,
        );
    }
    let declared_capabilities: Vec<String> =
        serde_json::from_str(&node.capabilities_json).unwrap_or_default();
    let supports = |capability: &str| {
        matches!(
            capability,
            "shell" | "fleet-chat-turn-v1" | "fleet-managed-workspace-v1"
        ) || declared_capabilities
            .iter()
            .any(|value| value == capability)
    };
    if let Some(missing) = spec
        .required_capabilities
        .iter()
        .find(|capability| !supports(capability))
    {
        return api_error(
            409,
            "executor_capability_missing",
            "This executor cannot run the requested Fleet job.",
            Some(json!({"requiredCapability": missing})),
        );
    }
    if spec.command == ["coven:fleet-system-info"] {
        spec.command = if cfg!(windows) {
            vec![
                "cmd.exe".into(),
                "/D".into(),
                "/S".into(),
                "/C".into(),
                "ver & echo Computer: %COMPUTERNAME% & echo User: %USERNAME%".into(),
            ]
        } else {
            vec![
                "sh".into(),
                "-c".into(),
                "uname -a; hostname; whoami".into(),
            ]
        };
    } else if spec.command == ["coven:fleet-chat-turn"] {
        if !valid_remote_token(&spec.job_id) {
            return api_error(400, "invalid_fleet_job", "Fleet job id is invalid.", None);
        }
        let spec_json = serde_json::to_string(&spec)?;
        let spec_hash = hash(&spec_json);
        let prior: Option<(String, String, Option<String>)> = conn
            .query_row(
                "SELECT spec_hash, state, result_json FROM fleet_execution_receipts WHERE job_id=?1",
                [&spec.job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((prior_hash, state, result_json)) = prior {
            if prior_hash != spec_hash {
                return api_error(
                    409,
                    "executor_job_conflict",
                    "This Fleet job id was already used with different execution details.",
                    None,
                );
            }
            if state == "completed" {
                let result: Value = serde_json::from_str(result_json.as_deref().unwrap_or("{}"))?;
                return json_response(200, &result);
            }
            return api_error(
                409,
                "executor_job_in_doubt",
                "This Fleet turn already started on the executor. It will not be run twice.",
                Some(json!({"jobId": spec.job_id, "state": state})),
            );
        }
        conn.execute(
            "INSERT INTO fleet_execution_receipts
             (job_id, spec_hash, state, started_at) VALUES (?1, ?2, 'running', ?3)",
            params![spec.job_id, spec_hash, Utc::now().to_rfc3339()],
        )?;
        let (execution, attachment_root) = match remote_turn_execution_job(home, &spec) {
            Ok(value) => value,
            Err(response) => {
                conn.execute(
                    "UPDATE fleet_execution_receipts SET state='rejected', completed_at=?1
                     WHERE job_id=?2",
                    params![Utc::now().to_rfc3339(), spec.job_id],
                )?;
                return Ok(response);
            }
        };
        let event_sequence = Arc::new(AtomicI64::new(0));
        let event_home = home.to_path_buf();
        let event_job_id = spec.job_id.clone();
        let result = crate::executor_node::run_job_observed(
            &execution,
            || {
                conn.query_row(
                    "SELECT state='cancel_requested' FROM fleet_execution_receipts WHERE job_id=?1",
                    [&spec.job_id],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap_or(false)
            },
            move |chunk| {
                let sequence = event_sequence.fetch_add(1, Ordering::Relaxed) + 1;
                let encoded = base64::engine::general_purpose::STANDARD.encode(chunk);
                if let Ok(event_conn) = open(&event_home) {
                    let _ = event_conn.execute(
                        "INSERT OR IGNORE INTO fleet_job_events
                     (job_id, sequence, chunk_base64, created_at) VALUES (?1, ?2, ?3, ?4)",
                        params![event_job_id, sequence, encoded, Utc::now().to_rfc3339()],
                    );
                }
            },
        );
        let _ = fs::remove_dir_all(attachment_root);
        let result = serde_json::to_value(result)?;
        let receipt_state = if result.get("status").and_then(Value::as_str)
            == Some(crate::executor_node::RESULT_STATUS_CANCELLED)
        {
            "cancelled"
        } else {
            "completed"
        };
        conn.execute(
            "UPDATE fleet_execution_receipts SET state=?1, result_json=?2,
             completed_at=?3 WHERE job_id=?4 AND state IN ('running','cancel_requested')",
            params![
                receipt_state,
                result.to_string(),
                Utc::now().to_rfc3339(),
                spec.job_id
            ],
        )?;
        return json_response(200, &result);
    }
    let result = crate::executor_node::run_job(&spec);
    json_response(200, &serde_json::to_value(result)?)
}

pub fn cancel_local_fleet_execution(home: &Path, job_id: &str) -> Result<ApiResponse> {
    if !valid_remote_token(job_id) {
        return api_error(400, "invalid_fleet_job", "Fleet job id is invalid.", None);
    }
    let conn = open(home)?;
    let changed = conn.execute(
        "UPDATE fleet_execution_receipts SET state='cancel_requested'
         WHERE job_id=?1 AND state='running'",
        [job_id],
    )?;
    let state: Option<String> = conn
        .query_row(
            "SELECT state FROM fleet_execution_receipts WHERE job_id=?1",
            [job_id],
            |row| row.get(0),
        )
        .optional()?;
    match state {
        Some(state) => json_response(
            200,
            &json!({"jobId": job_id, "state": state, "changed": changed == 1}),
        ),
        None => api_error(
            404,
            "fleet_execution_not_found",
            "Fleet execution was not found.",
            None,
        ),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(body: Option<&str>) -> std::result::Result<T, ApiResponse> {
    let payload = parse_body(body).map_err(|e| {
        api_error(400, "invalid_request", &e.to_string(), None).expect("serialize API error")
    })?;
    serde_json::from_value(payload).map_err(|e| {
        api_error(400, "invalid_request", &e.to_string(), None).expect("serialize API error")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(response: ApiResponse) -> Value {
        serde_json::from_str(&response.body).unwrap()
    }

    fn advertise_remote_turn_capability(home: &Path, node_id: &str) -> Result<()> {
        open(home)?.execute(
            "UPDATE fleet_trusted_nodes SET capabilities_json=?1, last_seen_at=?2, workspace_inventory_json=?3 WHERE node_id=?4",
            params![
                r#"["shell","fleet-chat-turn-v1","fleet-managed-workspace-v1"]"#,
                Utc::now().to_rfc3339(),
                r#"[{"projectName":"Cave","checkpoint":"abc123"}]"#,
                node_id
            ],
        )?;
        Ok(())
    }

    fn fixture_git(cwd: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git").args(args).current_dir(cwd).output()?;
        anyhow::ensure!(
            output.status.success(),
            "fixture git command failed: {args:?}"
        );
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn managed_workspace_fixture(home: &Path) -> Result<(String, String, PathBuf, PathBuf)> {
        let repository_url = "https://github.com/example/fleet-managed-fixture".to_string();
        let bare = home.join("fixture-remote.git");
        let seed = home.join("fixture-seed");
        fs::create_dir_all(seed.join("packages/app"))?;
        fixture_git(home, &["init", "--bare", bare.to_string_lossy().as_ref()])?;
        fixture_git(&seed, &["init"])?;
        fixture_git(&seed, &["config", "user.name", "Fleet Test"])?;
        fixture_git(&seed, &["config", "user.email", "fleet@example.test"])?;
        fs::write(seed.join("packages/app/tracked.txt"), "base\n")?;
        fixture_git(&seed, &["add", "."])?;
        fixture_git(&seed, &["commit", "-m", "base"])?;
        let checkpoint = fixture_git(&seed, &["rev-parse", "HEAD"])?;
        fixture_git(
            &seed,
            &["remote", "add", "origin", bare.to_string_lossy().as_ref()],
        )?;
        fixture_git(&seed, &["push", "origin", "HEAD:refs/heads/main"])?;
        let mut digest = Sha256::new();
        digest.update(repository_url.as_bytes());
        let key = hex_bytes(&digest.finalize());
        let managed_root = home.join("fleet-workspaces").join(&key[..32]);
        let checkout = managed_root.join(managed_turn_directory("turn_prepare"));
        fs::create_dir_all(&managed_root)?;
        fixture_git(
            &managed_root,
            &[
                "clone",
                "--no-checkout",
                bare.to_string_lossy().as_ref(),
                checkout.to_string_lossy().as_ref(),
            ],
        )?;
        fixture_git(&checkout, &["remote", "set-url", "origin", &repository_url])?;
        let bare_slashes = bare.to_string_lossy().replace('\\', "/");
        let bare_url = if bare_slashes.starts_with('/') {
            format!("file://{bare_slashes}")
        } else {
            format!("file:///{bare_slashes}")
        };
        fixture_git(
            &checkout,
            &[
                "config",
                &format!("url.{bare_url}.insteadOf"),
                &repository_url,
            ],
        )?;
        Ok((repository_url, checkpoint, seed, checkout))
    }

    #[test]
    fn discovery_discloses_only_protocol_and_pairing_state() -> Result<()> {
        let home = tempfile::tempdir()?;
        let value = body(advertisement(home.path())?);
        assert_eq!(
            value,
            json!({"service":"coven-fleet","protocolVersions":[PROTOCOL],"roles":["hub"],"pairingAvailable":false})
        );
        Ok(())
    }

    #[test]
    fn enrollment_is_single_use_and_revocation_blocks_reconnect() -> Result<()> {
        let home = tempfile::tempdir()?;
        let issued = body(create_enrollment(
            home.path(),
            Some(r#"{"ttlSeconds":60}"#),
        )?);
        let token = issued["credential"].as_str().unwrap();
        let enroll_body = json!({"nodeId":"node_windows","enrollmentCredential":token,"protocolVersion":PROTOCOL}).to_string();
        let enrolled = body(enroll(home.path(), Some(&enroll_body))?);
        let credential = enrolled["nodeCredential"].as_str().unwrap();
        assert_eq!(enroll(home.path(), Some(&enroll_body))?.status, 409);
        let challenge = body(create_challenge(
            home.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        let nonce = challenge["nonce"].as_str().unwrap();
        let reconnect_body =
            json!({"nodeId":"node_windows","nonce":nonce,"proof":proof(credential, nonce)})
                .to_string();
        assert_eq!(reconnect(home.path(), Some(&reconnect_body))?.status, 200);
        assert_eq!(reconnect(home.path(), Some(&reconnect_body))?.status, 409);
        let pending = body(create_challenge(
            home.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        let pending_nonce = pending["nonce"].as_str().unwrap();
        let pending_reconnect = json!({"nodeId":"node_windows","nonce":pending_nonce,"proof":proof(credential, pending_nonce)}).to_string();
        assert_eq!(revoke(home.path(), "node_windows")?.status, 200);
        assert_eq!(revoke(home.path(), "node_windows")?.status, 200);
        let revoked = body(reconnect(home.path(), Some(&pending_reconnect))?);
        assert_eq!(revoked["error"]["code"], "node_revoked");
        let second = body(create_challenge(
            home.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        assert_eq!(second["error"]["code"], "node_untrusted");
        Ok(())
    }

    #[test]
    fn expired_enrollment_fails_closed() -> Result<()> {
        let home = tempfile::tempdir()?;
        let issued = body(create_enrollment(home.path(), Some(r#"{"ttlSeconds":1}"#))?);
        let token = issued["credential"].as_str().unwrap();
        open(home.path())?.execute(
            "UPDATE fleet_enrollments SET expires_at=?1 WHERE token_hash=?2",
            params![
                (Utc::now() - Duration::seconds(1)).to_rfc3339(),
                hash(token)
            ],
        )?;
        let request = json!({"nodeId":"node_windows","enrollmentCredential":token,"protocolVersion":PROTOCOL}).to_string();
        let expired = body(enroll(home.path(), Some(&request))?);
        assert_eq!(expired["error"]["code"], "enrollment_expired");
        Ok(())
    }

    #[test]
    fn explicit_approval_delivers_once_and_local_custody_reconnects() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let executor = tempfile::tempdir()?;
        let requested = body(request_pairing(
            hub.path(),
            Some(r#"{"nodeId":"node_windows","protocolVersion":"coven.fleet.v1"}"#),
        )?);
        let request_id = requested["requestId"].as_str().unwrap();
        let request_secret = requested["requestSecret"].as_str().unwrap();
        let pending = body(claim_pairing(
            hub.path(),
            request_id,
            Some(&json!({"requestSecret": request_secret}).to_string()),
        )?);
        assert_eq!(pending["state"], "pending");
        assert_eq!(decide_pairing(hub.path(), request_id, true)?.status, 200);
        assert_eq!(decide_pairing(hub.path(), request_id, true)?.status, 200);
        let claimed = body(claim_pairing(
            hub.path(),
            request_id,
            Some(&json!({"requestSecret": request_secret}).to_string()),
        )?);
        let credential = claimed["nodeCredential"].as_str().unwrap();
        assert_eq!(
            claim_pairing(
                hub.path(),
                request_id,
                Some(&json!({"requestSecret": request_secret}).to_string())
            )?
            .status,
            409
        );

        let stored = body(store_local_credential(
            executor.path(),
            Some(
                &json!({"hubId":"hub_mac","nodeId":"node_windows","nodeCredential":credential})
                    .to_string(),
            ),
        )?);
        assert_eq!(
            stored,
            json!({"hubId":"hub_mac","nodeId":"node_windows","stored":true})
        );
        assert!(!stored.to_string().contains(credential));

        let challenge = body(create_challenge(
            hub.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        let local = body(local_proof(
            executor.path(),
            "hub_mac",
            Some(&json!({"nonce": challenge["nonce"]}).to_string()),
        )?);
        assert_eq!(local["nodeId"], "node_windows");
        assert!(!local.to_string().contains(credential));
        let reconnect_request = json!({
            "nodeId": local["nodeId"], "nonce": local["nonce"], "proof": local["proof"]
        })
        .to_string();
        assert_eq!(reconnect(hub.path(), Some(&reconnect_request))?.status, 200);
        Ok(())
    }

    #[test]
    fn trusted_executor_claims_and_completes_one_pulled_job() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let executor = tempfile::tempdir()?;
        let enrollment = body(create_enrollment(hub.path(), Some("{}"))?);
        let enrolled = body(enroll(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "enrollmentCredential": enrollment["credential"],
                    "protocolVersion": PROTOCOL
                })
                .to_string(),
            ),
        )?);
        let credential = enrolled["nodeCredential"].as_str().unwrap();
        let queued = body(queue_system_info_job(
            hub.path(),
            Some(r#"{"targetNodeId":"node_windows"}"#),
        )?);
        let job_id = queued["jobId"].as_str().unwrap();

        let challenge = body(create_challenge(
            hub.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        let nonce = challenge["nonce"].as_str().unwrap();
        let claimed = body(claim_fleet_job(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "nonce": nonce,
                    "proof": proof(credential, nonce)
                })
                .to_string(),
            ),
        )?);
        assert_eq!(claimed["job"]["jobId"], job_id);
        let lease_id = claimed["leaseId"].as_str().unwrap();

        configure_local_role(
            executor.path(),
            Some(r#"{"role":"executor","capabilities":["shell"]}"#),
        )?;
        configure_local_sharing(executor.path(), Some(r#"{"enabled":true}"#))?;
        local_lifecycle(executor.path(), "start", None)?;
        let result = body(run_local_fleet_job(
            executor.path(),
            Some(&claimed["job"].to_string()),
        )?);
        assert_eq!(result["status"], "completed");

        let challenge = body(create_challenge(
            hub.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        let nonce = challenge["nonce"].as_str().unwrap();
        let completed = body(complete_fleet_job(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "nonce": nonce,
                    "proof": proof(credential, nonce),
                    "jobId": job_id,
                    "leaseId": lease_id,
                    "result": result
                })
                .to_string(),
            ),
        )?);
        assert_eq!(completed["state"], "completed");
        let jobs = body(list_fleet_jobs(hub.path())?);
        assert_eq!(jobs["jobs"][0]["state"], "completed");
        assert_eq!(jobs["jobs"][0]["result"]["jobId"], job_id);
        Ok(())
    }

    #[test]
    fn remote_turn_dispatch_is_typed_bounded_and_idempotent() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let enrollment = body(create_enrollment(hub.path(), Some("{}"))?);
        body(enroll(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "enrollmentCredential": enrollment["credential"],
                    "protocolVersion": PROTOCOL
                })
                .to_string(),
            ),
        )?);
        advertise_remote_turn_capability(hub.path(), "node_windows")?;
        let request = json!({
            "turnId": "turn_123",
            "targetNodeId": "node_windows",
            "familiarId": "sage",
            "harness": "codex",
            "model": "openai/gpt-5.6",
            "workspace": {
                "root": ".",
                "projectName": "Cave",
                "repositoryUrl": "https://github.com/OpenCoven/coven-cave",
                "checkpoint": "abc123",
                "subdirectory": "packages/app",
                "overlay": {
                    "patchBase64": "ZGlmZg==",
                    "digest": "sha256-abc123",
                    "untrackedFiles": [{"path": "packages/app/new.txt", "dataBase64": "bmV3", "executable": false}]
                }
            },
            "prompt": "Continue the existing conversation on this executor.",
            "contextMessages": [
                {"role": "user", "text": "Earlier question"},
                {"role": "assistant", "text": "Earlier answer"}
            ],
            "attachments": [],
            "permissionMode": "read",
            "timeoutSeconds": 120
        })
        .to_string();
        let queued = body(queue_remote_turn_job(hub.path(), Some(&request))?);
        assert_eq!(queued["state"], "queued");
        assert_eq!(queued["idempotent"], false);
        assert_eq!(queued["jobId"], "fleetturn_turn_123");

        let replay = body(queue_remote_turn_job(hub.path(), Some(&request))?);
        assert_eq!(replay["jobId"], queued["jobId"]);
        assert_eq!(replay["idempotent"], true);

        let jobs = body(list_fleet_jobs(hub.path())?);
        assert_eq!(jobs["jobs"].as_array().unwrap().len(), 1);
        let spec_json: String = open(hub.path())?.query_row(
            "SELECT spec_json FROM fleet_jobs WHERE job_id='fleetturn_turn_123'",
            [],
            |row| row.get(0),
        )?;
        let spec: Value = serde_json::from_str(&spec_json)?;
        assert_eq!(spec["command"], json!(["coven:fleet-chat-turn"]));
        assert_eq!(spec["context"]["schemaVersion"], "coven.fleet.chat-turn.v1");
        assert_eq!(spec["context"]["workspace"]["root"], ".");
        assert_eq!(
            spec["context"]["workspace"]["overlay"]["untrackedFiles"][0]["path"],
            "packages/app/new.txt"
        );
        assert_eq!(
            spec["requiredCapabilities"],
            json!(["shell", "fleet-chat-turn-v1", "fleet-managed-workspace-v1"])
        );
        Ok(())
    }

    #[test]
    fn remote_turn_rejects_conflicts_and_cancel_is_terminal() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let enrollment = body(create_enrollment(hub.path(), Some("{}"))?);
        body(enroll(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "enrollmentCredential": enrollment["credential"],
                    "protocolVersion": PROTOCOL
                })
                .to_string(),
            ),
        )?);
        advertise_remote_turn_capability(hub.path(), "node_windows")?;
        let request = |prompt: &str| {
            json!({
                "turnId": "turn_cancel",
                "targetNodeId": "node_windows",
                "familiarId": "sage",
                "harness": "codex",
                "workspace": {"root": "C:/work/project", "projectName": "Cave"},
                "prompt": prompt,
                "permissionMode": "full"
            })
            .to_string()
        };
        let queued = body(queue_remote_turn_job(hub.path(), Some(&request("one")))?);
        assert_eq!(queued["state"], "queued");
        let conflict = body(queue_remote_turn_job(hub.path(), Some(&request("two")))?);
        assert_eq!(conflict["error"]["code"], "remote_turn_conflict");

        let cancelled = body(cancel_fleet_job(hub.path(), "fleetturn_turn_cancel")?);
        assert_eq!(cancelled["state"], "cancelled");
        let cancelled_again = body(cancel_fleet_job(hub.path(), "fleetturn_turn_cancel")?);
        assert_eq!(cancelled_again["state"], "cancelled");
        assert_eq!(
            body(list_fleet_jobs(hub.path())?)["jobs"][0]["state"],
            "cancelled"
        );
        Ok(())
    }

    #[test]
    fn remote_turn_fails_before_dispatch_for_offline_or_incompatible_executor() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let enrollment = body(create_enrollment(hub.path(), Some("{}"))?);
        body(enroll(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "enrollmentCredential": enrollment["credential"],
                    "protocolVersion": PROTOCOL
                })
                .to_string(),
            ),
        )?);
        let request = json!({
            "turnId": "turn_preflight",
            "targetNodeId": "node_windows",
            "familiarId": "sage",
            "harness": "codex",
            "workspace": {"root": "C:/work/project", "projectName": "Cave", "checkpoint": "abc123"},
            "prompt": "hello",
            "permissionMode": "read"
        })
        .to_string();
        let incompatible = body(queue_remote_turn_job(hub.path(), Some(&request))?);
        assert_eq!(incompatible["error"]["code"], "executor_incompatible");
        advertise_remote_turn_capability(hub.path(), "node_windows")?;
        open(hub.path())?.execute(
            "UPDATE fleet_trusted_nodes SET last_seen_at=?1 WHERE node_id='node_windows'",
            [(Utc::now() - Duration::seconds(30)).to_rfc3339()],
        )?;
        let offline = body(queue_remote_turn_job(hub.path(), Some(&request))?);
        assert_eq!(offline["error"]["code"], "executor_offline");
        for (availability, expected) in [
            ("draining", "executor_draining"),
            ("unshared", "executor_unshared"),
            ("stopped", "executor_stopped"),
            ("not-executor", "executor_unavailable"),
        ] {
            open(hub.path())?.execute(
                "UPDATE fleet_trusted_nodes SET last_seen_at=?1, executor_availability=?2 WHERE node_id='node_windows'",
                params![Utc::now().to_rfc3339(), availability],
            )?;
            let unavailable = body(queue_remote_turn_job(hub.path(), Some(&request))?);
            assert_eq!(unavailable["error"]["code"], expected);
        }
        open(hub.path())?.execute(
            "UPDATE fleet_trusted_nodes SET executor_availability='available', workspace_inventory_json='[]' WHERE node_id='node_windows'",
            [],
        )?;
        let managed_workspace = body(queue_remote_turn_job(hub.path(), Some(&request))?);
        assert_eq!(managed_workspace["state"], "queued");
        let jobs = body(list_fleet_jobs(hub.path())?);
        assert_eq!(jobs["jobs"].as_array().unwrap().len(), 1);
        Ok(())
    }

    #[test]
    fn unavailable_executor_heartbeat_updates_state_without_claiming_work() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let enrollment = body(create_enrollment(hub.path(), Some("{}"))?);
        let enrolled = body(enroll(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "enrollmentCredential": enrollment["credential"],
                    "protocolVersion": PROTOCOL
                })
                .to_string(),
            ),
        )?);
        let credential = enrolled["nodeCredential"].as_str().unwrap();
        advertise_remote_turn_capability(hub.path(), "node_windows")?;
        let queued = body(queue_remote_turn_job(
            hub.path(),
            Some(
                &json!({
                    "turnId": "turn_waiting",
                    "targetNodeId": "node_windows",
                    "familiarId": "sage",
                    "harness": "codex",
                    "workspace": {"root": "C:/work/project", "projectName": "Cave"},
                    "prompt": "wait for sharing",
                    "permissionMode": "read"
                })
                .to_string(),
            ),
        )?);
        let challenge = body(create_challenge(
            hub.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        let nonce = challenge["nonce"].as_str().unwrap();
        let claim = body(claim_fleet_job(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "nonce": nonce,
                    "proof": proof(credential, nonce),
                    "capabilities": ["shell", "fleet-chat-turn-v1"],
                    "acceptingJobs": false,
                    "availabilityReason": "unshared"
                })
                .to_string(),
            ),
        )?);
        assert!(claim["job"].is_null());
        assert_eq!(claim["availability"], "unshared");
        assert_eq!(
            body(list_fleet_jobs(hub.path())?)["jobs"][0]["state"],
            "queued"
        );
        assert_eq!(
            body(list_trusted_nodes(hub.path())?)["nodes"][0]["executorAvailability"],
            "unshared"
        );
        assert_eq!(queued["state"], "queued");
        Ok(())
    }

    #[test]
    fn remote_turn_events_are_authenticated_ordered_and_idempotent() -> Result<()> {
        let hub = tempfile::tempdir()?;
        let enrollment = body(create_enrollment(hub.path(), Some("{}"))?);
        let enrolled = body(enroll(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "enrollmentCredential": enrollment["credential"],
                    "protocolVersion": PROTOCOL
                })
                .to_string(),
            ),
        )?);
        let credential = enrolled["nodeCredential"].as_str().unwrap();
        advertise_remote_turn_capability(hub.path(), "node_windows")?;
        let queued = body(queue_remote_turn_job(
            hub.path(),
            Some(
                &json!({
                    "turnId": "turn_events",
                    "targetNodeId": "node_windows",
                    "familiarId": "sage",
                    "harness": "codex",
                    "workspace": {"root": "C:/work/project", "projectName": "Cave"},
                    "prompt": "hello",
                    "permissionMode": "read"
                })
                .to_string(),
            ),
        )?);
        let challenge = body(create_challenge(
            hub.path(),
            Some(r#"{"nodeId":"node_windows"}"#),
        )?);
        let nonce = challenge["nonce"].as_str().unwrap();
        let claimed = body(claim_fleet_job(
            hub.path(),
            Some(
                &json!({
                    "nodeId": "node_windows",
                    "nonce": nonce,
                    "proof": proof(credential, nonce),
                    "capabilities": ["shell", "fleet-chat-turn-v1"]
                })
                .to_string(),
            ),
        )?);
        assert_eq!(claimed["job"]["jobId"], queued["jobId"]);

        let append = || -> Result<ApiResponse> {
            let challenge = body(create_challenge(
                hub.path(),
                Some(r#"{"nodeId":"node_windows"}"#),
            )?);
            let nonce = challenge["nonce"].as_str().unwrap();
            append_authenticated_fleet_job_events(
                hub.path(),
                Some(
                    &json!({
                        "nodeId": "node_windows",
                        "nonce": nonce,
                        "proof": proof(credential, nonce),
                        "jobId": queued["jobId"],
                        "events": [{
                            "sequence": 1,
                            "chunkBase64": base64::engine::general_purpose::STANDARD.encode(b"{\"type\":\"assistant\"}\n")
                        }]
                    })
                    .to_string(),
                ),
            )
        };
        assert_eq!(append()?.status, 200);
        assert_eq!(append()?.status, 200);
        let events = body(list_local_fleet_job_events(
            hub.path(),
            queued["jobId"].as_str().unwrap(),
        )?);
        assert_eq!(events["events"].as_array().unwrap().len(), 1);
        assert_eq!(events["events"][0]["sequence"], 1);
        Ok(())
    }

    #[test]
    fn remote_turn_validation_rejects_unbounded_or_unsafe_fields() -> Result<()> {
        let home = tempfile::tempdir()?;
        let invalid = body(queue_remote_turn_job(
            home.path(),
            Some(
                &json!({
                    "turnId": "turn\r\nheader",
                    "targetNodeId": "node_windows",
                    "familiarId": "sage",
                    "harness": "codex",
                    "workspace": {"root": "C:/work/project", "projectName": "Cave"},
                    "prompt": "hello",
                    "permissionMode": "full"
                })
                .to_string(),
            ),
        )?);
        assert_eq!(invalid["error"]["code"], "invalid_remote_turn");
        let dot_id = body(queue_remote_turn_job(
            home.path(),
            Some(
                &json!({
                    "turnId": ".",
                    "targetNodeId": "node_windows",
                    "familiarId": "sage",
                    "harness": "codex",
                    "workspace": {"root": "."},
                    "prompt": "hello",
                    "permissionMode": "full"
                })
                .to_string(),
            ),
        )?);
        assert_eq!(dot_id["error"]["code"], "invalid_remote_turn");
        let unsafe_overlay = body(queue_remote_turn_job(
            home.path(),
            Some(
                &json!({
                    "turnId": "turn_overlay",
                    "targetNodeId": "node_windows",
                    "familiarId": "sage",
                    "harness": "codex",
                    "workspace": {
                        "root": ".",
                        "repositoryUrl": "https://github.com/OpenCoven/coven-cave",
                        "checkpoint": "abc123",
                        "overlay": {
                            "patchBase64": "",
                            "digest": "sha256-abc123",
                            "untrackedFiles": [{"path": "../escape", "dataBase64": "eA=="}]
                        }
                    },
                    "prompt": "hello",
                    "permissionMode": "full"
                })
                .to_string(),
            ),
        )?);
        assert_eq!(unsafe_overlay["error"]["code"], "invalid_remote_turn");
        Ok(())
    }

    #[test]
    fn denied_pairing_never_creates_trust() -> Result<()> {
        let home = tempfile::tempdir()?;
        let requested = body(request_pairing(
            home.path(),
            Some(r#"{"nodeId":"node_untrusted","protocolVersion":"coven.fleet.v1"}"#),
        )?);
        let id = requested["requestId"].as_str().unwrap();
        let secret = requested["requestSecret"].as_str().unwrap();
        assert_eq!(decide_pairing(home.path(), id, false)?.status, 200);
        let denied = body(claim_pairing(
            home.path(),
            id,
            Some(&json!({"requestSecret": secret}).to_string()),
        )?);
        assert_eq!(denied["error"]["code"], "pairing_request_denied");
        assert!(body(list_trusted_nodes(home.path())?)["nodes"]
            .as_array()
            .unwrap()
            .is_empty());
        Ok(())
    }

    #[test]
    fn role_lifecycle_and_sharing_are_idempotent_and_actionable() -> Result<()> {
        let home = tempfile::tempdir()?;
        let initial = body(local_node_status(home.path())?);
        assert_eq!(initial["role"], "hub");
        assert_eq!(initial["lifecycle"], "stopped");
        assert_eq!(initial["nextAction"], "start");
        let device_id = initial["deviceId"].as_str().unwrap().to_string();

        let rejected = body(configure_local_sharing(
            home.path(),
            Some(r#"{"enabled":true}"#),
        )?);
        assert_eq!(rejected["error"]["code"], "executor_role_required");

        let configured = body(configure_local_role(
            home.path(),
            Some(r#"{"role":"both","capabilities":["shell","browser"]}"#),
        )?);
        assert_eq!(configured["deviceId"], device_id);
        assert_eq!(configured["role"], "both");
        assert_eq!(configured["capabilities"], json!(["shell", "browser"]));

        let shared = body(configure_local_sharing(
            home.path(),
            Some(r#"{"enabled":true}"#),
        )?);
        assert_eq!(shared["executorShared"], true);
        assert_eq!(shared["acceptingJobs"], false);
        assert!(!crate::executor_node::build_probe(home.path())?.available);

        let started = body(local_lifecycle(home.path(), "start", None)?);
        assert_eq!(started["lifecycle"], "running");
        assert_eq!(started["acceptingJobs"], true);
        assert!(crate::executor_node::build_probe(home.path())?.available);
        assert_eq!(
            crate::executor_node::build_probe(home.path())?.capabilities,
            vec!["shell", "browser"]
        );
        assert_eq!(local_lifecycle(home.path(), "start", None)?.status, 200);

        let drained = body(local_lifecycle(home.path(), "drain", None)?);
        assert_eq!(drained["lifecycle"], "draining");
        assert_eq!(drained["acceptingJobs"], false);
        assert!(!crate::executor_node::build_probe(home.path())?.available);
        assert_eq!(local_lifecycle(home.path(), "drain", None)?.status, 200);

        let resumed = body(local_lifecycle(home.path(), "resume", None)?);
        assert_eq!(resumed["acceptingJobs"], true);
        assert_eq!(local_lifecycle(home.path(), "restart", None)?.status, 400);
        let operation = Some(r#"{"operationId":"restart-1"}"#);
        let restarted = body(local_lifecycle(home.path(), "restart", operation)?);
        assert_eq!(restarted["generation"], 1);
        let restarted_again = body(local_lifecycle(home.path(), "restart", operation)?);
        assert_eq!(restarted_again["generation"], 1);

        let stopped = body(local_lifecycle(home.path(), "stop", None)?);
        assert_eq!(stopped["lifecycle"], "stopped");
        assert_eq!(stopped["acceptingJobs"], false);
        assert!(!crate::executor_node::build_probe(home.path())?.available);
        assert_eq!(local_lifecycle(home.path(), "stop", None)?.status, 200);
        Ok(())
    }

    #[test]
    fn versioned_router_exposes_every_cave_lifecycle_operation() -> Result<()> {
        let home = tempfile::tempdir()?;
        let request = |method, path, payload| {
            crate::api::handle_request_with_body(method, path, home.path(), None, payload)
        };
        assert_eq!(
            request("GET", "/api/v1/fleet/local-node", None)?.status,
            200
        );
        assert_eq!(
            request(
                "PUT",
                "/api/v1/fleet/local-node/role",
                Some(r#"{"role":"executor","capabilities":["shell"]}"#)
            )?
            .status,
            200
        );
        assert_eq!(
            request(
                "PUT",
                "/api/v1/fleet/local-node/sharing",
                Some(r#"{"enabled":true}"#)
            )?
            .status,
            200
        );
        for action in ["start", "drain", "resume", "stop"] {
            let route = format!("/api/v1/fleet/local-node/lifecycle/{action}");
            assert_eq!(
                crate::api::handle_request_with_body("POST", &route, home.path(), None, None)?
                    .status,
                200
            );
        }
        assert_eq!(
            request(
                "POST",
                "/api/v1/fleet/local-node/lifecycle/restart",
                Some(r#"{"operationId":"router-restart"}"#)
            )?
            .status,
            200
        );
        assert_eq!(
            request(
                "POST",
                "/api/v1/fleet/local-node/lifecycle/restart",
                Some(r#"{"operationId":"router-restart"}"#)
            )?
            .status,
            200
        );
        Ok(())
    }

    #[test]
    fn version_mismatch_fails_closed() -> Result<()> {
        assert_eq!(
            negotiate(Some(r#"{"protocolVersions":["coven.fleet.v2"]}"#))?.status,
            409
        );
        Ok(())
    }

    #[test]
    fn remote_turn_preparation_materializes_bounded_portable_context() -> Result<()> {
        let home = tempfile::tempdir()?;
        let (repository_url, checkpoint, seed, checkout) = managed_workspace_fixture(home.path())?;
        fs::write(seed.join("packages/app/tracked.txt"), "changed\n")?;
        let patch = Command::new("git")
            .args(["diff", "--binary", "--full-index", "HEAD"])
            .current_dir(&seed)
            .output()?;
        anyhow::ensure!(patch.status.success());
        let untracked = b"portable\n";
        let mut overlay_digest = Sha256::new();
        overlay_digest.update(&patch.stdout);
        overlay_digest.update([0]);
        overlay_digest.update(b"packages/app/untracked.txt");
        overlay_digest.update([0]);
        overlay_digest.update(untracked);
        let spec = crate::executor_node::ExecutorJob {
            protocol_version: crate::executor_node::EXECUTOR_PROTOCOL_VERSION.to_string(),
            job_id: "fleetturn_prepare".to_string(),
            hub_id: Some("hub_mac".to_string()),
            required_capabilities: vec![
                "shell".to_string(),
                "fleet-chat-turn-v1".to_string(),
                "fleet-managed-workspace-v1".to_string(),
            ],
            command: vec!["coven:fleet-chat-turn".to_string()],
            cwd: None,
            env: Default::default(),
            stdin: None,
            timeout_seconds: Some(120),
            context: Some(json!({
                "kind": "fleet-chat-turn",
                "schemaVersion": "coven.fleet.chat-turn.v1",
                "turnId": "turn_prepare",
                "familiarId": "sage",
                "harness": "codex",
                "workspace": {
                    "root": ".",
                    "repositoryUrl": repository_url,
                    "checkpoint": checkpoint,
                    "subdirectory": "packages/app",
                    "overlay": {
                        "patchBase64": base64::engine::general_purpose::STANDARD.encode(&patch.stdout),
                        "digest": format!("sha256-{}", hex_bytes(&overlay_digest.finalize())),
                        "untrackedFiles": [{
                            "path": "packages/app/untracked.txt",
                            "dataBase64": base64::engine::general_purpose::STANDARD.encode(untracked)
                        }]
                    }
                },
                "prompt": "Current question",
                "contextMessages": [{"role": "assistant", "text": "Prior answer"}],
                "attachments": [{
                    "name": "../notes.txt",
                    "mimeType": "text/plain",
                    "dataBase64": base64::engine::general_purpose::STANDARD.encode(b"hello")
                }],
                "permissionMode": "read"
            })),
        };
        let (execution, attachment_root) = remote_turn_execution_job(home.path(), &spec)
            .map_err(|response| anyhow::anyhow!(response.body))?;
        assert_eq!(
            execution.cwd.as_deref(),
            Some(
                checkout
                    .join("packages/app")
                    .canonicalize()?
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert_eq!(
            fs::read_to_string(checkout.join("packages/app/tracked.txt"))?,
            "changed\n"
        );
        assert_eq!(
            fs::read(checkout.join("packages/app/untracked.txt"))?,
            untracked
        );
        assert!(execution
            .command
            .iter()
            .any(|arg| arg.contains("Prior answer")));
        assert!(execution
            .command
            .iter()
            .any(|arg| arg.contains("Current question")));
        assert!(!execution.command.iter().any(|arg| arg == "--familiar"));
        assert_eq!(
            execution
                .context
                .as_ref()
                .and_then(|value| value["familiarId"].as_str()),
            Some("sage")
        );
        let files = fs::read_dir(&attachment_root)?.collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(files.len(), 1);
        assert_eq!(fs::read(files[0].path())?, b"hello");
        assert!(!files[0].file_name().to_string_lossy().contains('/'));
        fs::remove_dir_all(attachment_root)?;
        Ok(())
    }

    #[test]
    fn completed_remote_turn_receipt_is_replayed_without_execution() -> Result<()> {
        let home = tempfile::tempdir()?;
        configure_local_role(
            home.path(),
            Some(
                r#"{"role":"executor","capabilities":["shell","fleet-chat-turn-v1","fleet-managed-workspace-v1"]}"#,
            ),
        )?;
        configure_local_sharing(home.path(), Some(r#"{"enabled":true}"#))?;
        local_lifecycle(home.path(), "start", None)?;
        let spec = json!({
            "protocolVersion": crate::executor_node::EXECUTOR_PROTOCOL_VERSION,
            "jobId": "fleetturn_replay",
            "requiredCapabilities": ["shell", "fleet-chat-turn-v1", "fleet-managed-workspace-v1"],
            "command": ["coven:fleet-chat-turn"],
            "env": {},
            "context": {"kind": "fleet-chat-turn"}
        });
        let parsed_spec: crate::executor_node::ExecutorJob = serde_json::from_value(spec.clone())?;
        let spec_hash = hash(&serde_json::to_string(&parsed_spec)?);
        let cached = json!({
            "protocolVersion": crate::executor_node::EXECUTOR_PROTOCOL_VERSION,
            "jobId": "fleetturn_replay",
            "status": "completed",
            "exitCode": 0,
            "stdout": "cached",
            "stderr": "",
            "startedAt": "2026-08-14T00:00:00Z",
            "finishedAt": "2026-08-14T00:00:01Z",
            "durationMs": 1000
        });
        open(home.path())?.execute(
            "INSERT INTO fleet_execution_receipts
             (job_id, spec_hash, state, result_json, started_at, completed_at)
             VALUES (?1, ?2, 'completed', ?3, ?4, ?4)",
            params![
                "fleetturn_replay",
                spec_hash,
                cached.to_string(),
                Utc::now().to_rfc3339()
            ],
        )?;
        let replayed = body(run_local_fleet_job(home.path(), Some(&spec.to_string()))?);
        assert_eq!(replayed["stdout"], "cached");
        Ok(())
    }
}
