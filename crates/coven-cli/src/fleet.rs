//! Coven Fleet trust and Coven Discovery protocol.
//!
//! Tailscale is deliberately absent from this authority module. A client may
//! use its bounded peer inventory to find addresses, but every peer remains
//! unauthorized until this module enrolls it. Secrets are represented only by
//! hashes in the hub store and are returned exactly once to the enrolling node.

use std::path::Path;

use anyhow::{Context, Result};
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
         );",
    )
    .context("failed to initialize fleet trust schema")?;
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
    let mut statement = conn.prepare("SELECT node_id, enrolled_at, last_seen_at, revoked_at FROM fleet_trusted_nodes ORDER BY enrolled_at")?;
    let nodes = statement.query_map([], |r| Ok(json!({"nodeId": r.get::<_, String>(0)?, "enrolledAt": r.get::<_, String>(1)?, "lastSeenAt": r.get::<_, String>(2)?, "revokedAt": r.get::<_, Option<String>>(3)?})))?.collect::<rusqlite::Result<Vec<Value>>>()?;
    json_response(200, &json!({ "nodes": nodes }))
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
}
