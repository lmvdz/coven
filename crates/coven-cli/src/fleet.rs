//! Hub-authoritative fleet enrollment, capability observations, and leased work.
//!
//! This module owns the security-sensitive pull-executor boundary. Network
//! reachability is never identity: enrolled nodes authenticate every mutation
//! with a node-scoped bearer secret, while job mutations additionally require a
//! short-lived lease token. Only verifiers are persisted.

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api::{api_error, current_timestamp, json_response, parse_body, ApiResponse},
    placement_scheduler::{
        self, GpuRequirement, HardConstraints, LeafConstraint, PlacementCandidate,
        PlacementDecision, PlacementRequest, WeightedPreference,
    },
    store,
};

pub const FLEET_PROTOCOL_VERSION: &str = "coven.fleet.v1";
const ENROLLMENT_TTL_MINUTES: i64 = 10;
const NODE_FRESHNESS_SECONDS: i64 = 90;
const DEFAULT_LEASE_SECONDS: i64 = 30;
const MAX_CAPABILITY_ITEMS: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolCapabilities {
    #[serde(default)]
    pub executor: Vec<u16>,
    #[serde(default)]
    pub workspace_driver: Vec<u16>,
    #[serde(default)]
    pub harness_host: Vec<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformCapabilities {
    pub os: String,
    pub architecture: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceCapabilities {
    #[serde(default)]
    pub cpu_cores: u32,
    #[serde(default)]
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GpuCapability {
    pub vendor: String,
    pub model: String,
    #[serde(default)]
    pub memory_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeCapabilities {
    #[serde(default)]
    pub protocols: ProtocolCapabilities,
    pub platform: PlatformCapabilities,
    #[serde(default)]
    pub resources: ResourceCapabilities,
    #[serde(default)]
    pub gpu: Option<GpuCapability>,
    #[serde(default)]
    pub runtimes: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub harnesses: Vec<String>,
    #[serde(default)]
    pub workspace_drivers: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueEnrollmentRequest {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RedeemEnrollmentRequest {
    enrollment_code: String,
    node_id: String,
    #[serde(default)]
    label: Option<String>,
    capabilities: NodeCapabilities,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HeartbeatRequest {
    connection_epoch: u64,
    capabilities: NodeCapabilities,
    #[serde(default)]
    queue_pressure: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LeaseMutationRequest {
    attempt_id: String,
    lease_token: String,
    #[serde(default)]
    completion_key: Option<String>,
    #[serde(default)]
    result: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FailJobRequest {
    attempt_id: String,
    lease_token: String,
    completion_key: String,
    failure: FleetFailureEvidence,
}

pub const FAILURE_PROTOCOL_VERSION: &str = "coven.fleet-failure.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FleetFailureEvidence {
    pub protocol_version: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct FailedFleetJob {
    pub attempt_id: String,
    pub node_id: String,
    pub failure: FleetFailureEvidence,
}

struct AttemptValidation {
    state: String,
    completion_key: Option<String>,
    result_json: Option<String>,
}

struct AttemptRow {
    attempt_id: String,
    node_id: String,
    state: String,
    lease_verifier: String,
    completion_key: Option<String>,
    result_json: Option<String>,
}

fn store_path(coven_home: &Path) -> std::path::PathBuf {
    coven_home.join(crate::STORE_FILE_NAME)
}

fn open(coven_home: &Path) -> Result<Connection> {
    let conn = store::open_store(&store_path(coven_home))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS fleet_enrollments (
            enrollment_id TEXT PRIMARY KEY NOT NULL,
            code_verifier TEXT NOT NULL UNIQUE,
            label TEXT,
            expires_at TEXT NOT NULL,
            redeemed_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS fleet_job_attempts (
            job_id TEXT PRIMARY KEY NOT NULL,
            attempt_id TEXT NOT NULL UNIQUE,
            node_id TEXT NOT NULL,
            state TEXT NOT NULL,
            lease_verifier TEXT NOT NULL,
            lease_expires_at TEXT NOT NULL,
            completion_key TEXT,
            result_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_fleet_attempts_node
            ON fleet_job_attempts(node_id, state, lease_expires_at);
        CREATE TABLE IF NOT EXISTS fleet_harness_actors (
            actor_id TEXT PRIMARY KEY NOT NULL,
            node_id TEXT NOT NULL,
            generation INTEGER NOT NULL,
            state TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
    )
    .context("failed to initialize fleet schema")?;
    ensure_node_column(
        &conn,
        "fleet_label",
        "ALTER TABLE node_registry ADD COLUMN fleet_label TEXT",
    )?;
    ensure_node_column(
        &conn,
        "node_secret_verifier",
        "ALTER TABLE node_registry ADD COLUMN node_secret_verifier TEXT",
    )?;
    ensure_node_column(
        &conn,
        "revoked_at",
        "ALTER TABLE node_registry ADD COLUMN revoked_at TEXT",
    )?;
    ensure_node_column(
        &conn,
        "connection_epoch",
        "ALTER TABLE node_registry ADD COLUMN connection_epoch INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_node_column(
        &conn,
        "capability_observation_json",
        "ALTER TABLE node_registry ADD COLUMN capability_observation_json TEXT",
    )?;
    ensure_node_column(
        &conn,
        "capabilities_observed_at",
        "ALTER TABLE node_registry ADD COLUMN capabilities_observed_at TEXT",
    )?;
    ensure_node_column(
        &conn,
        "fleet_lease_expires_at",
        "ALTER TABLE node_registry ADD COLUMN fleet_lease_expires_at TEXT",
    )?;
    for (column, sql) in [
        (
            "placement_observation_digest",
            "ALTER TABLE fleet_job_attempts ADD COLUMN placement_observation_digest TEXT",
        ),
        (
            "placement_connection_epoch",
            "ALTER TABLE fleet_job_attempts ADD COLUMN placement_connection_epoch INTEGER",
        ),
        (
            "placement_observed_at",
            "ALTER TABLE fleet_job_attempts ADD COLUMN placement_observed_at TEXT",
        ),
        (
            "placement_capabilities_json",
            "ALTER TABLE fleet_job_attempts ADD COLUMN placement_capabilities_json TEXT",
        ),
        (
            "placement_match_evidence_json",
            "ALTER TABLE fleet_job_attempts ADD COLUMN placement_match_evidence_json TEXT",
        ),
    ] {
        ensure_table_column(&conn, "fleet_job_attempts", column, sql)?;
    }
    Ok(conn)
}

fn ensure_node_column(conn: &Connection, column: &str, sql: &str) -> Result<()> {
    ensure_table_column(conn, "node_registry", column, sql)
}

fn ensure_table_column(conn: &Connection, table: &str, column: &str, sql: &str) -> Result<()> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !columns.iter().any(|candidate| candidate == column) {
        conn.execute(sql, [])?;
    }
    Ok(())
}

fn random_secret(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{prefix}_{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn verifier(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn bearer(authorization: Option<&str>) -> Option<&str> {
    authorization?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .context("stored fleet timestamp is invalid")?
        .with_timezone(&Utc))
}

fn validate_id(value: &str, field: &str) -> std::result::Result<(), ApiResponse> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(api_error_value(
            400,
            "invalid_request",
            &format!("{field} has an invalid format."),
        ))
    }
}

fn api_error_value(status: u16, code: &str, message: &str) -> ApiResponse {
    api_error(status, code, message, None).expect("serializing static fleet error cannot fail")
}

fn validate_capabilities(capabilities: &NodeCapabilities) -> std::result::Result<(), ApiResponse> {
    if capabilities.platform.os.trim().is_empty()
        || capabilities.platform.architecture.trim().is_empty()
    {
        return Err(api_error_value(
            400,
            "invalid_capabilities",
            "platform.os and platform.architecture are required.",
        ));
    }
    let count = capabilities.harnesses.len()
        + capabilities.workspace_drivers.len()
        + capabilities.tools.len()
        + capabilities.runtimes.values().map(Vec::len).sum::<usize>();
    if count > MAX_CAPABILITY_ITEMS {
        return Err(api_error_value(
            400,
            "invalid_capabilities",
            "Capability observation exceeds the item limit.",
        ));
    }
    let strings = capabilities
        .harnesses
        .iter()
        .chain(capabilities.workspace_drivers.iter())
        .chain(capabilities.tools.iter())
        .chain(capabilities.runtimes.keys())
        .chain(capabilities.runtimes.values().flatten());
    if strings
        .into_iter()
        .any(|value| value.is_empty() || value.len() > 128)
    {
        return Err(api_error_value(
            400,
            "invalid_capabilities",
            "Capability values must contain 1 to 128 characters.",
        ));
    }
    Ok(())
}

fn authenticate_node(
    conn: &Connection,
    node_id: &str,
    authorization: Option<&str>,
) -> std::result::Result<(), ApiResponse> {
    let Some(secret) = bearer(authorization) else {
        return Err(api_error_value(
            401,
            "node_auth_required",
            "A node bearer credential is required.",
        ));
    };
    let row: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT node_secret_verifier, revoked_at FROM node_registry WHERE node_id = ?1",
            params![node_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| api_error_value(500, "fleet_store_error", "Fleet identity lookup failed."))?;
    let Some((stored, revoked_at)) = row else {
        return Err(api_error_value(
            401,
            "node_auth_invalid",
            "Node credential is invalid.",
        ));
    };
    if revoked_at.is_some() || !constant_time_eq(&stored, &verifier(secret)) {
        return Err(api_error_value(
            401,
            "node_auth_invalid",
            "Node credential is invalid.",
        ));
    }
    Ok(())
}

pub fn issue_enrollment(coven_home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: IssueEnrollmentRequest = match parse_body(body)
        .and_then(|value| serde_json::from_value(value).context("invalid enrollment request"))
    {
        Ok(request) => request,
        Err(error) => return api_error(400, "invalid_request", &error.to_string(), None),
    };
    if request
        .label
        .as_ref()
        .is_some_and(|label| label.len() > 128)
    {
        return api_error(
            400,
            "invalid_request",
            "label exceeds 128 characters.",
            None,
        );
    }
    let conn = open(coven_home)?;
    let code = random_secret("cvenroll");
    let enrollment_id = format!("enr_{}", Uuid::new_v4().simple());
    let now = Utc::now();
    let expires = now + Duration::minutes(ENROLLMENT_TTL_MINUTES);
    conn.execute(
        "INSERT INTO fleet_enrollments
         (enrollment_id, code_verifier, label, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            enrollment_id,
            verifier(&code),
            request.label,
            expires.to_rfc3339_opts(SecondsFormat::Millis, true),
            now.to_rfc3339_opts(SecondsFormat::Millis, true),
        ],
    )?;
    json_response(
        201,
        &json!({
            "protocolVersion": FLEET_PROTOCOL_VERSION,
            "enrollmentId": enrollment_id,
            "enrollmentCode": code,
            "expiresAt": expires.to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
    )
}

pub fn redeem_enrollment(coven_home: &Path, body: Option<&str>) -> Result<ApiResponse> {
    let request: RedeemEnrollmentRequest = match parse_body(body)
        .and_then(|value| serde_json::from_value(value).context("invalid enrollment redemption"))
    {
        Ok(request) => request,
        Err(error) => return api_error(400, "invalid_request", &error.to_string(), None),
    };
    if let Err(response) = validate_id(&request.node_id, "nodeId") {
        return Ok(response);
    }
    if let Err(response) = validate_capabilities(&request.capabilities) {
        return Ok(response);
    }
    let mut conn = open(coven_home)?;
    let transaction = conn.transaction()?;
    let code_hash = verifier(&request.enrollment_code);
    let enrollment: Option<(String, Option<String>, String)> = transaction
        .query_row(
            "SELECT enrollment_id, redeemed_at, expires_at FROM fleet_enrollments
             WHERE code_verifier = ?1",
            params![code_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((enrollment_id, redeemed_at, expires_at)) = enrollment else {
        return api_error(
            401,
            "enrollment_invalid",
            "Enrollment code is invalid.",
            None,
        );
    };
    if redeemed_at.is_some() || parse_time(&expires_at)? <= Utc::now() {
        return api_error(
            401,
            "enrollment_invalid",
            "Enrollment code is invalid or expired.",
            None,
        );
    }
    let node_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM node_registry WHERE node_id = ?1)",
        params![request.node_id],
        |row| row.get(0),
    )?;
    if node_exists {
        return api_error(409, "node_exists", "Node id is already enrolled.", None);
    }
    let issued_credential = random_secret("cvnode");
    let now = current_timestamp();
    let lease_expires = (Utc::now() + Duration::seconds(NODE_FRESHNESS_SECONDS))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let tags = capability_tags(&request.capabilities);
    store::upsert_node(
        &transaction,
        &store::NodeRecord {
            node_id: request.node_id.clone(),
            role: crate::executor_node::ROLE_COMPUTE_EXECUTOR.to_string(),
            transport: "fleet-pull".to_string(),
            transport_config_json: None,
            capabilities_json: serde_json::to_string(&tags)?,
            available: true,
            queue_pressure: 0,
            last_health_at: now.clone(),
            last_error: None,
            registered_at: now.clone(),
            updated_at: now.clone(),
        },
    )?;
    transaction.execute(
        "UPDATE node_registry SET fleet_label = ?2, node_secret_verifier = ?3,
         capability_observation_json = ?4, capabilities_observed_at = ?5,
         fleet_lease_expires_at = ?6 WHERE node_id = ?1",
        params![
            request.node_id,
            request.label,
            verifier(&issued_credential),
            serde_json::to_string(&request.capabilities)?,
            now,
            lease_expires,
        ],
    )?;
    transaction.execute(
        "UPDATE fleet_enrollments SET redeemed_at = ?2 WHERE enrollment_id = ?1 AND redeemed_at IS NULL",
        params![enrollment_id, now],
    )?;
    transaction.commit()?;
    json_response(
        201,
        &json!({
            "protocolVersion": FLEET_PROTOCOL_VERSION,
            "nodeId": request.node_id,
            "nodeSecret": issued_credential,
            "leaseExpiresAt": lease_expires,
        }),
    )
}

pub fn heartbeat(
    coven_home: &Path,
    node_id: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Result<ApiResponse> {
    if let Err(response) = validate_id(node_id, "nodeId") {
        return Ok(response);
    }
    let request: HeartbeatRequest = match parse_body(body)
        .and_then(|value| serde_json::from_value(value).context("invalid heartbeat"))
    {
        Ok(request) => request,
        Err(error) => return api_error(400, "invalid_request", &error.to_string(), None),
    };
    if let Err(response) = validate_capabilities(&request.capabilities) {
        return Ok(response);
    }
    let conn = open(coven_home)?;
    if let Err(response) = authenticate_node(&conn, node_id, authorization) {
        return Ok(response);
    }
    let current_epoch: i64 = conn.query_row(
        "SELECT connection_epoch FROM node_registry WHERE node_id = ?1",
        params![node_id],
        |row| row.get(0),
    )?;
    let Ok(connection_epoch) = i64::try_from(request.connection_epoch) else {
        return api_error(
            400,
            "invalid_request",
            "connectionEpoch exceeds the supported range.",
            None,
        );
    };
    if connection_epoch < current_epoch {
        return api_error(
            409,
            "stale_connection_epoch",
            "Heartbeat connection epoch is stale.",
            None,
        );
    }
    let observed_at = current_timestamp();
    let lease_expires_at = (Utc::now() + Duration::seconds(NODE_FRESHNESS_SECONDS))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    conn.execute(
        "UPDATE node_registry SET connection_epoch = ?2, capability_observation_json = ?3,
         capabilities_json = ?4, queue_pressure = ?5, capabilities_observed_at = ?6,
         fleet_lease_expires_at = ?7, last_health_at = ?6, available = 1, updated_at = ?6
         WHERE node_id = ?1 AND revoked_at IS NULL",
        params![
            node_id,
            connection_epoch,
            serde_json::to_string(&request.capabilities)?,
            serde_json::to_string(&capability_tags(&request.capabilities))?,
            request.queue_pressure,
            observed_at,
            lease_expires_at,
        ],
    )?;
    json_response(
        200,
        &json!({
            "protocolVersion": FLEET_PROTOCOL_VERSION,
            "nodeId": node_id,
            "connectionEpoch": request.connection_epoch,
            "leaseExpiresAt": lease_expires_at,
        }),
    )
}

pub fn revoke_node(coven_home: &Path, node_id: &str) -> Result<ApiResponse> {
    if let Err(response) = validate_id(node_id, "nodeId") {
        return Ok(response);
    }
    let conn = open(coven_home)?;
    let now = current_timestamp();
    let changed = conn.execute(
        "UPDATE node_registry SET revoked_at = ?2, available = 0, updated_at = ?2
         WHERE node_id = ?1 AND revoked_at IS NULL",
        params![node_id, now],
    )?;
    if changed == 0 {
        return api_error(
            404,
            "node_not_found",
            "Active fleet node was not found.",
            None,
        );
    }
    json_response(200, &json!({"nodeId": node_id, "revokedAt": now}))
}

fn capability_tags(capabilities: &NodeCapabilities) -> Vec<String> {
    let mut tags = capabilities.tools.clone();
    tags.extend(
        capabilities
            .harnesses
            .iter()
            .map(|value| format!("runtime:{value}")),
    );
    tags.extend(
        capabilities
            .protocols
            .harness_host
            .iter()
            .map(|version| format!("protocol:harness-host:{version}")),
    );
    tags.extend(
        capabilities
            .workspace_drivers
            .iter()
            .map(|value| format!("workspace:{value}")),
    );
    tags.push(format!("os:{}", capabilities.platform.os));
    tags.push(format!("arch:{}", capabilities.platform.architecture));
    tags.extend(
        capabilities
            .protocols
            .workspace_driver
            .iter()
            .map(|version| format!("protocol:workspace-driver:{version}")),
    );
    tags
}

fn node_is_fresh(observed_at: &str, lease_expires_at: &str) -> Result<bool> {
    let now = Utc::now();
    Ok(parse_time(lease_expires_at)? > now
        && parse_time(observed_at)? + Duration::seconds(NODE_FRESHNESS_SECONDS) > now)
}

fn eligible_node_ids(
    transaction: &Transaction<'_>,
    request: &PlacementRequest,
) -> Result<Vec<PlacementDecision>> {
    let mut statement = transaction.prepare(
        "SELECT n.node_id,n.capability_observation_json,n.queue_pressure,
         n.capabilities_observed_at,n.fleet_lease_expires_at,n.connection_epoch,n.available,
         (SELECT COUNT(*) FROM fleet_job_attempts a WHERE a.node_id=n.node_id AND a.state='leased')
         FROM node_registry n WHERE n.revoked_at IS NULL
         AND n.node_secret_verifier IS NOT NULL ORDER BY n.queue_pressure,n.node_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u32>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, bool>(6)?,
            row.get::<_, u32>(7)?,
        ))
    })?;
    let mut candidates = Vec::new();
    for row in rows {
        let (node_id, raw, pressure, observed_at, lease_expires_at, epoch, available, active) =
            row?;
        let fresh = node_is_fresh(&observed_at, &lease_expires_at)?;
        let capabilities: NodeCapabilities = serde_json::from_str(&raw)?;
        let observation_id = observation_digest(&node_id, epoch, &observed_at, &raw)?;
        candidates.push(PlacementCandidate {
            node_id,
            observation_id,
            fresh,
            available,
            queue_pressure: active
                .saturating_mul(1_000_000)
                .saturating_add(pressure.min(999_999)),
            capabilities,
        });
    }
    placement_scheduler::rank(request, candidates)
}

pub(crate) fn select_node_for_requirements(
    coven_home: &Path,
    required: &[String],
    excluded_node_id: &str,
    explicit_node_id: Option<&str>,
) -> Result<Option<String>> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction()?;
    let request = decode_placement_request(&serde_json::to_string(required)?)?;
    let ranked = eligible_node_ids(&tx, &request)?;
    let selected = match explicit_node_id {
        Some(explicit) => ranked.into_iter().find(|candidate| {
            candidate.node_id == explicit && candidate.node_id != excluded_node_id
        }),
        None => ranked
            .into_iter()
            .find(|candidate| candidate.node_id != excluded_node_id),
    };
    tx.commit()?;
    Ok(selected.map(|candidate| candidate.node_id))
}

fn observation_digest(node_id: &str, epoch: i64, observed_at: &str, raw: &str) -> Result<String> {
    Ok(
        URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&json!({
            "nodeId":node_id,"connectionEpoch":epoch,"observedAt":observed_at,
            "capabilities":serde_json::from_str::<Value>(raw)?
        }))?)),
    )
}

fn decode_placement_request(raw: &str) -> Result<PlacementRequest> {
    let value: Value = serde_json::from_str(raw)?;
    if value.is_object() {
        return Ok(serde_json::from_value(value)?);
    }
    let tags: Vec<String> = serde_json::from_value(value)?;
    placement_request_from_legacy(&tags, &[])
}

pub(crate) fn placement_request_from_legacy(
    required_tags: &[String],
    preferred_tags: &[String],
) -> Result<PlacementRequest> {
    let mut required = HardConstraints::default();
    for tag in required_tags {
        if let Some(value) = tag.strip_prefix("os:") {
            required.os = Some(value.into())
        } else if let Some(value) = tag.strip_prefix("arch:") {
            required.architecture = Some(value.into())
        } else if let Some(value) = tag.strip_prefix("cpu-cores>=") {
            required.min_cpu_cores = value.parse()?
        } else if let Some(value) = tag.strip_prefix("memory-bytes>=") {
            required.min_memory_bytes = value.parse()?
        } else if tag == "gpu" {
            required.gpu.get_or_insert_with(GpuRequirement::default);
        } else if let Some(value) = tag.strip_prefix("gpu-vendor:") {
            required
                .gpu
                .get_or_insert_with(GpuRequirement::default)
                .vendor = Some(value.into())
        } else if let Some(value) = tag.strip_prefix("gpu-model:") {
            required
                .gpu
                .get_or_insert_with(GpuRequirement::default)
                .model = Some(value.into())
        } else if let Some(value) = tag.strip_prefix("gpu-memory-bytes>=") {
            required
                .gpu
                .get_or_insert_with(GpuRequirement::default)
                .min_memory_bytes = value.parse()?
        } else if let Some(value) = tag.strip_prefix("runtime:") {
            if let Some((runtime, version)) = value.split_once('=') {
                required
                    .runtimes
                    .push(placement_scheduler::ExactRuntimeRequirement {
                        runtime: runtime.into(),
                        version: version.into(),
                    })
            } else {
                // Compatibility: runtime:<harness> was the original harness tag.
                required.harnesses.push(value.into())
            }
        } else if let Some(value) = tag.strip_prefix("harness:") {
            required.harnesses.push(value.into())
        } else if let Some(value) = tag.strip_prefix("tool:") {
            required.tools.push(value.into())
        } else if let Some(value) = tag.strip_prefix("workspace:") {
            required.workspace_drivers.push(value.into())
        } else if let Some(value) = tag.strip_prefix("protocol:executor:") {
            required.protocols.executor.push(value.parse()?)
        } else if let Some(value) = tag.strip_prefix("protocol:workspace-driver:") {
            required.protocols.workspace_driver.push(value.parse()?)
        } else if let Some(value) = tag.strip_prefix("protocol:harness-host:") {
            required.protocols.harness_host.push(value.parse()?)
        } else {
            required.tools.push(tag.clone())
        }
    }
    let mut request = PlacementRequest {
        required,
        preferred: preferred_tags
            .iter()
            .map(|tag| {
                Ok(WeightedPreference {
                    weight: 1,
                    constraint: preference_leaf(tag)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    request = placement_scheduler::normalize_request(&request)?;
    Ok(request)
}

fn preference_leaf(tag: &str) -> Result<LeafConstraint> {
    let leaf = if let Some(value) = tag.strip_prefix("os:") {
        LeafConstraint::Os {
            value: value.into(),
        }
    } else if let Some(value) = tag.strip_prefix("arch:") {
        LeafConstraint::Architecture {
            value: value.into(),
        }
    } else if let Some(value) = tag.strip_prefix("cpu-cores>=") {
        LeafConstraint::MinCpuCores {
            value: value.parse()?,
        }
    } else if let Some(value) = tag.strip_prefix("memory-bytes>=") {
        LeafConstraint::MinMemoryBytes {
            value: value.parse()?,
        }
    } else if let Some(value) = tag.strip_prefix("gpu-vendor:") {
        LeafConstraint::GpuVendor {
            value: value.into(),
        }
    } else if let Some(value) = tag.strip_prefix("gpu-model:") {
        LeafConstraint::GpuModel {
            value: value.into(),
        }
    } else if let Some(value) = tag.strip_prefix("gpu-memory-bytes>=") {
        LeafConstraint::MinGpuMemoryBytes {
            value: value.parse()?,
        }
    } else if let Some(value) = tag.strip_prefix("runtime:") {
        let (runtime, version) = value
            .split_once('=')
            .context("runtime preferences require runtime:<name>=<version>")?;
        LeafConstraint::RuntimeExact {
            runtime: runtime.into(),
            version: version.into(),
        }
    } else if let Some(value) = tag.strip_prefix("harness:") {
        LeafConstraint::Harness { name: value.into() }
    } else if let Some(value) = tag.strip_prefix("workspace:") {
        LeafConstraint::WorkspaceDriver { name: value.into() }
    } else if let Some(value) = tag.strip_prefix("tool:") {
        LeafConstraint::Tool { name: value.into() }
    } else {
        LeafConstraint::Tool { name: tag.into() }
    };
    Ok(leaf)
}

pub fn claim_job(
    coven_home: &Path,
    node_id: &str,
    authorization: Option<&str>,
    wait_seconds: u64,
) -> Result<ApiResponse> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_seconds.min(25));
    loop {
        let response = claim_job_once(coven_home, node_id, authorization)?;
        if response.status != 204 || std::time::Instant::now() >= deadline {
            return Ok(response);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn claim_job_once(
    coven_home: &Path,
    node_id: &str,
    authorization: Option<&str>,
) -> Result<ApiResponse> {
    let mut conn = open(coven_home)?;
    if let Err(response) = authenticate_node(&conn, node_id, authorization) {
        return Ok(response);
    }
    let transaction = conn.transaction()?;
    let now = current_timestamp();
    transaction.execute(
        "UPDATE hub_jobs SET state = 'queued', assigned_node_id = NULL, updated_at = ?1
         WHERE job_id IN (
             SELECT job_id FROM fleet_job_attempts
             WHERE state = 'leased' AND lease_expires_at <= ?1
         ) AND state = 'leased'",
        params![now],
    )?;
    transaction.execute(
        "UPDATE fleet_job_attempts SET state = 'expired', updated_at = ?1
         WHERE state = 'leased' AND lease_expires_at <= ?1",
        params![now],
    )?;
    let jobs = store::list_hub_jobs(&transaction, Some("queued"))?;
    let mut selected = None;
    for job in jobs {
        if job
            .target_node_id
            .as_deref()
            .is_some_and(|assigned| assigned != node_id)
        {
            continue;
        }
        let request = decode_placement_request(&job.required_capabilities_json)?;
        let eligible = eligible_node_ids(&transaction, &request)?;
        let chosen = if job.target_node_id.is_some() {
            eligible
                .iter()
                .find(|candidate| candidate.node_id == node_id)
        } else {
            eligible
                .first()
                .filter(|candidate| candidate.node_id == node_id)
        };
        if let Some(decision) = chosen {
            selected = Some((job, decision.clone()));
            break;
        }
    }
    let Some((job, decision)) = selected else {
        transaction.commit()?;
        return json_response(204, &json!({}));
    };
    let attempt_id = format!("att_{}", Uuid::new_v4().simple());
    let lease_token = random_secret("cvlease");
    let lease_expires_at = (Utc::now() + Duration::seconds(DEFAULT_LEASE_SECONDS))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let changed = transaction.execute(
        "UPDATE hub_jobs SET state = 'leased', assigned_node_id = ?2, updated_at = ?3
         WHERE job_id = ?1 AND state = 'queued'",
        params![job.job_id, node_id, now],
    )?;
    if changed != 1 {
        return api_error(409, "claim_conflict", "Job was claimed concurrently.", None);
    }
    let (observation_epoch, observation_time, observation_capabilities): (i64,String,String) = transaction.query_row(
        "SELECT connection_epoch,capabilities_observed_at,capability_observation_json FROM node_registry
         WHERE node_id=?1 AND revoked_at IS NULL", params![node_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    transaction.execute(
        "INSERT INTO fleet_job_attempts
         (job_id,attempt_id,node_id,state,lease_verifier,lease_expires_at,created_at,updated_at,
          placement_observation_digest,placement_connection_epoch,placement_observed_at,
          placement_capabilities_json,placement_match_evidence_json)
         VALUES (?1,?2,?3,'leased',?4,?5,?6,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(job_id) DO UPDATE SET
             attempt_id = excluded.attempt_id,
             node_id = excluded.node_id,
             state = excluded.state,
             lease_verifier = excluded.lease_verifier,
             lease_expires_at = excluded.lease_expires_at,
             completion_key = NULL,
             result_json = NULL,
             placement_observation_digest=excluded.placement_observation_digest,
             placement_connection_epoch=excluded.placement_connection_epoch,
             placement_observed_at=excluded.placement_observed_at,
             placement_capabilities_json=excluded.placement_capabilities_json,
             placement_match_evidence_json=excluded.placement_match_evidence_json,
             updated_at = excluded.updated_at",
        params![
            job.job_id,
            attempt_id,
            node_id,
            verifier(&lease_token),
            lease_expires_at,
            now,
            decision.observation_id,
            observation_epoch,
            observation_time,
            observation_capabilities,
            serde_json::to_string(&decision.evidence)?
        ],
    )?;
    transaction.commit()?;
    let mut payload: Value = serde_json::from_str(&job.payload_json)?;
    if payload["protocolVersion"] == crate::delegation::PROTOCOL_VERSION {
        payload["placementObservationDigest"] = decision.observation_id.clone().into();
    }
    json_response(
        200,
        &json!({
            "protocolVersion": FLEET_PROTOCOL_VERSION,
            "job": {
                "jobId": job.job_id,
                "attemptId": attempt_id,
                "leaseToken": lease_token,
                "leaseExpiresAt": lease_expires_at,
                "requiredCapabilities": serde_json::from_str::<Value>(&job.required_capabilities_json)?,
                "payload": payload,
            }
        }),
    )
}

fn validate_attempt(
    conn: &Connection,
    job_id: &str,
    node_id: &str,
    request: &LeaseMutationRequest,
    require_live_lease: bool,
) -> Result<std::result::Result<AttemptValidation, ApiResponse>> {
    let row: Option<AttemptRow> = conn
        .query_row(
            "SELECT attempt_id, node_id, state, lease_verifier, completion_key, result_json
             FROM fleet_job_attempts WHERE job_id = ?1",
            params![job_id],
            |row| {
                Ok(AttemptRow {
                    attempt_id: row.get(0)?,
                    node_id: row.get(1)?,
                    state: row.get(2)?,
                    lease_verifier: row.get(3)?,
                    completion_key: row.get(4)?,
                    result_json: row.get(5)?,
                })
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(Err(api_error_value(
            404,
            "attempt_not_found",
            "Fleet job attempt was not found.",
        )));
    };
    if row.attempt_id != request.attempt_id || row.node_id != node_id {
        return Ok(Err(api_error_value(
            409,
            "attempt_mismatch",
            "Attempt is not assigned to this node.",
        )));
    }
    if !constant_time_eq(&row.lease_verifier, &verifier(&request.lease_token)) {
        return Ok(Err(api_error_value(
            401,
            "lease_invalid",
            "Lease credential is invalid.",
        )));
    }
    if require_live_lease {
        let expires_at: String = conn.query_row(
            "SELECT lease_expires_at FROM fleet_job_attempts WHERE job_id = ?1",
            params![job_id],
            |row| row.get(0),
        )?;
        if parse_time(&expires_at)? <= Utc::now() {
            return Ok(Err(api_error_value(
                409,
                "lease_expired",
                "Job lease has expired.",
            )));
        }
    }
    Ok(Ok(AttemptValidation {
        state: row.state,
        completion_key: row.completion_key,
        result_json: row.result_json,
    }))
}

pub fn renew_lease(
    coven_home: &Path,
    job_id: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Result<ApiResponse> {
    let request: LeaseMutationRequest = match parse_body(body)
        .and_then(|value| serde_json::from_value(value).context("invalid lease renewal"))
    {
        Ok(request) => request,
        Err(error) => return api_error(400, "invalid_request", &error.to_string(), None),
    };
    let conn = open(coven_home)?;
    let node_id: Option<String> = conn
        .query_row(
            "SELECT node_id FROM fleet_job_attempts WHERE job_id = ?1",
            params![job_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(node_id) = node_id else {
        return api_error(
            404,
            "attempt_not_found",
            "Fleet job attempt was not found.",
            None,
        );
    };
    if let Err(response) = authenticate_node(&conn, &node_id, authorization) {
        return Ok(response);
    }
    let attempt = match validate_attempt(&conn, job_id, &node_id, &request, true)? {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    if attempt.state != "leased" {
        return api_error(
            409,
            "attempt_terminal",
            "Only a live leased attempt can renew.",
            None,
        );
    }
    let lease_expires_at = (Utc::now() + Duration::seconds(DEFAULT_LEASE_SECONDS))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let now = current_timestamp();
    let changed = conn.execute(
        "UPDATE fleet_job_attempts SET lease_expires_at = ?2, updated_at = ?3
         WHERE job_id = ?1 AND attempt_id = ?4 AND node_id = ?5 AND state = 'leased'
         AND lease_verifier = ?6 AND lease_expires_at > ?3",
        params![
            job_id,
            lease_expires_at,
            now,
            request.attempt_id,
            node_id,
            verifier(&request.lease_token)
        ],
    )?;
    if changed != 1 {
        return api_error(
            409,
            "renewal_conflict",
            "Lease renewal lost an authority race; reload the attempt state.",
            None,
        );
    }
    json_response(
        200,
        &json!({"jobId": job_id, "attemptId": request.attempt_id, "leaseExpiresAt": lease_expires_at}),
    )
}

pub fn complete_job(
    coven_home: &Path,
    job_id: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Result<ApiResponse> {
    let request: LeaseMutationRequest = match parse_body(body)
        .and_then(|value| serde_json::from_value(value).context("invalid job completion"))
    {
        Ok(request) => request,
        Err(error) => return api_error(400, "invalid_request", &error.to_string(), None),
    };
    let Some(completion_key) = request
        .completion_key
        .as_deref()
        .filter(|key| !key.is_empty())
    else {
        return api_error(400, "invalid_request", "completionKey is required.", None);
    };
    let Some(result) = request.result.as_ref() else {
        return api_error(400, "invalid_request", "result is required.", None);
    };
    let mut conn = open(coven_home)?;
    let transaction = conn.transaction()?;
    let node_id: Option<String> = transaction
        .query_row(
            "SELECT node_id FROM fleet_job_attempts WHERE job_id = ?1",
            params![job_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(node_id) = node_id else {
        return api_error(
            404,
            "attempt_not_found",
            "Fleet job attempt was not found.",
            None,
        );
    };
    if let Err(response) = authenticate_node(&transaction, &node_id, authorization) {
        return Ok(response);
    }
    let attempt = match validate_attempt(&transaction, job_id, &node_id, &request, false)? {
        Ok(attempt) => attempt,
        Err(response) => return Ok(response),
    };
    if attempt.state == "completed" {
        if attempt.completion_key.as_deref() == Some(completion_key) {
            transaction.commit()?;
            return json_response(
                200,
                &json!({
                    "jobId": job_id,
                    "attemptId": request.attempt_id,
                    "state": "completed",
                    "result": attempt.result_json.and_then(|value| serde_json::from_str::<Value>(&value).ok()),
                    "replayed": true,
                }),
            );
        }
        return api_error(
            409,
            "completion_conflict",
            "Attempt already completed with another idempotency key.",
            None,
        );
    }
    let expires_at: String = transaction.query_row(
        "SELECT lease_expires_at FROM fleet_job_attempts WHERE job_id = ?1",
        params![job_id],
        |row| row.get(0),
    )?;
    if parse_time(&expires_at)? <= Utc::now() {
        return api_error(409, "lease_expired", "Job lease has expired.", None);
    }
    let now = current_timestamp();
    let attempt_changed = transaction.execute(
        "UPDATE fleet_job_attempts SET state = 'completed', completion_key = ?2,
         result_json = ?3, updated_at = ?4 WHERE job_id = ?1 AND state = 'leased'
         AND attempt_id = ?5 AND node_id = ?6 AND lease_verifier = ?7
         AND lease_expires_at > ?4",
        params![
            job_id,
            completion_key,
            serde_json::to_string(result)?,
            now,
            request.attempt_id,
            node_id,
            verifier(&request.lease_token)
        ],
    )?;
    let job_changed = transaction.execute(
        "UPDATE hub_jobs SET state = 'completed', updated_at = ?2
         WHERE job_id = ?1 AND state = 'leased' AND assigned_node_id = ?3",
        params![job_id, now, node_id],
    )?;
    if attempt_changed != 1 || job_changed != 1 {
        return api_error(
            409,
            "completion_conflict",
            "Job completion lost an authority race; reload the attempt state.",
            None,
        );
    }
    transaction.commit()?;
    if let Err(error) = crate::session_roam::reconcile_for_job(coven_home, job_id) {
        eprintln!("coven daemon: session roam reconciliation deferred after `{job_id}`: {error:#}");
    }
    json_response(
        200,
        &json!({
            "jobId": job_id,
            "attemptId": request.attempt_id,
            "state": "completed",
            "result": result,
            "replayed": false,
        }),
    )
}

pub fn fail_job(
    coven_home: &Path,
    job_id: &str,
    authorization: Option<&str>,
    body: Option<&str>,
) -> Result<ApiResponse> {
    let request: FailJobRequest = match parse_body(body)
        .and_then(|value| serde_json::from_value(value).context("invalid job failure"))
    {
        Ok(request) => request,
        Err(error) => return api_error(400, "invalid_request", &error.to_string(), None),
    };
    let failure_key = request.completion_key.as_str();
    if failure_key.is_empty() {
        return api_error(400, "invalid_request", "completionKey is required.", None);
    }
    let evidence = &request.failure;
    if evidence.protocol_version != FAILURE_PROTOCOL_VERSION
        || evidence.code != "execution_failed"
        || evidence.message.is_empty()
        || evidence.message.chars().count() > 1024
    {
        return api_error(
            400,
            "invalid_failure_evidence",
            "Failure evidence must use coven.fleet-failure.v1, execution_failed, and a message of at most 1024 characters.",
            None,
        );
    }
    let mut conn = open(coven_home)?;
    let tx = conn.transaction()?;
    let node_id: Option<String> = tx
        .query_row(
            "SELECT node_id FROM fleet_job_attempts WHERE job_id=?1",
            params![job_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(node_id) = node_id else {
        return api_error(
            404,
            "attempt_not_found",
            "Fleet job attempt was not found.",
            None,
        );
    };
    if let Err(response) = authenticate_node(&tx, &node_id, authorization) {
        return Ok(response);
    }
    let validation = LeaseMutationRequest {
        attempt_id: request.attempt_id.clone(),
        lease_token: request.lease_token.clone(),
        completion_key: Some(request.completion_key.clone()),
        result: Some(serde_json::to_value(evidence)?),
    };
    let attempt = match validate_attempt(&tx, job_id, &node_id, &validation, false)? {
        Ok(attempt) => attempt,
        Err(response) => return Ok(response),
    };
    if attempt.state == "failed" {
        if attempt.completion_key.as_deref() == Some(failure_key) {
            let stored: FleetFailureEvidence = serde_json::from_str(
                attempt
                    .result_json
                    .as_deref()
                    .context("failed attempt omitted evidence")?,
            )?;
            if &stored != evidence {
                return api_error(
                    409,
                    "failure_conflict",
                    "Failure replay changed immutable evidence.",
                    None,
                );
            }
            tx.commit()?;
            return json_response(
                200,
                &json!({"jobId":job_id,"attemptId":request.attempt_id,"attemptState":"failed","jobState":"failed","disposition":"terminal","failure":stored,"replayed":true}),
            );
        }
        return api_error(
            409,
            "failure_conflict",
            "Attempt already failed with another idempotency key.",
            None,
        );
    }
    if attempt.state != "leased" {
        return api_error(
            409,
            "attempt_terminal",
            "Only a live leased attempt can fail.",
            None,
        );
    }
    let now = current_timestamp();
    let changed = tx.execute(
        "UPDATE fleet_job_attempts SET state='failed',completion_key=?2,result_json=?3,updated_at=?4
         WHERE job_id=?1 AND attempt_id=?5 AND node_id=?6 AND state='leased' AND lease_verifier=?7 AND lease_expires_at>?4",
        params![job_id,failure_key,serde_json::to_string(evidence)?,now,request.attempt_id,node_id,verifier(&request.lease_token)],
    )?;
    if changed != 1 {
        return api_error(
            409,
            "failure_conflict",
            "Job failure lost an authority race.",
            None,
        );
    }
    let changed = tx.execute(
        "UPDATE hub_jobs SET state='failed',updated_at=?2 WHERE job_id=?1 AND state='leased' AND assigned_node_id=?3",
        params![job_id,now,node_id],
    )?;
    if changed != 1 {
        return api_error(
            409,
            "failure_conflict",
            "Job failure lost hub authority.",
            None,
        );
    }
    tx.commit()?;
    if let Err(error) = crate::session_roam::reconcile_for_job(coven_home, job_id) {
        eprintln!("coven daemon: session roam failure reconciliation deferred after `{job_id}`: {error:#}");
    }
    json_response(
        200,
        &json!({"jobId":job_id,"attemptId":request.attempt_id,"attemptState":"failed","jobState":"failed","disposition":"terminal","failure":evidence,"replayed":false}),
    )
}

pub fn offload_tool(
    coven_home: &Path,
    command: Vec<String>,
    cwd: Option<&Path>,
    timeout_seconds: u64,
    wait_timeout: std::time::Duration,
) -> Result<crate::executor_node::ExecutorResultEnvelope> {
    if command.is_empty() {
        anyhow::bail!("offloaded command must not be empty");
    }
    let conn = open(coven_home)?;
    let job_id = format!("job_{}", Uuid::new_v4().simple());
    let now = current_timestamp();
    let payload = crate::executor_node::ExecutorJob {
        protocol_version: crate::executor_node::EXECUTOR_PROTOCOL_VERSION.to_string(),
        job_id: job_id.clone(),
        hub_id: None,
        required_capabilities: vec!["shell".to_string()],
        command,
        cwd: cwd.map(|path| path.to_string_lossy().into_owned()),
        env: Default::default(),
        stdin: None,
        timeout_seconds: Some(timeout_seconds),
        context: None,
    };
    store::upsert_hub_job(
        &conn,
        &store::HubJobRecord {
            job_id: job_id.to_string(),
            state: "queued".to_string(),
            priority: 0,
            required_capabilities_json: serde_json::to_string(&payload.required_capabilities)?,
            assigned_node_id: None,
            target_node_id: None,
            loop_id: None,
            payload_json: serde_json::to_string(&payload)?,
            created_at: now.clone(),
            updated_at: now,
        },
    )?;
    let deadline = std::time::Instant::now() + wait_timeout;
    loop {
        let result_json: Option<String> = conn
            .query_row(
                "SELECT result_json FROM fleet_job_attempts
                 WHERE job_id = ?1 AND state = 'completed'",
                params![job_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if let Some(result_json) = result_json {
            return serde_json::from_str(&result_json)
                .context("fleet completion was not a coven.executor.v1 result envelope");
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for fleet job {job_id}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[derive(Debug, Clone)]
pub struct CompletedFleetJob {
    pub attempt_id: String,
    pub node_id: String,
    pub result: Value,
}

pub(crate) fn submit_job_on_connection(
    conn: &Connection,
    job_id: &str,
    payload: &Value,
    required_capabilities: &[String],
    assigned_node_id: Option<&str>,
) -> Result<String> {
    if serde_json::to_vec(payload)?.len() > 1024 * 1024 {
        anyhow::bail!("fleet job payload exceeds 1 MiB");
    }
    if contains_serialized_credential(payload) {
        anyhow::bail!("fleet job payload must not contain credential material");
    }
    validate_id(job_id, "jobId").map_err(|response| anyhow::anyhow!(response.body))?;
    let encoded_payload = serde_json::to_string(payload)?;
    let encoded_required = serde_json::to_string(required_capabilities)?;
    if let Some(existing) = store::get_hub_job(conn, job_id)? {
        if existing.payload_json != encoded_payload
            || existing.required_capabilities_json != encoded_required
            || existing.target_node_id.as_deref() != assigned_node_id
        {
            anyhow::bail!("fleet job id replay changed immutable submission fields");
        }
        return Ok(job_id.to_string());
    }
    let now = current_timestamp();
    store::upsert_hub_job(
        conn,
        &store::HubJobRecord {
            job_id: job_id.to_string(),
            state: "queued".into(),
            priority: 0,
            required_capabilities_json: encoded_required,
            assigned_node_id: assigned_node_id.map(str::to_string),
            target_node_id: assigned_node_id.map(str::to_string),
            loop_id: None,
            payload_json: encoded_payload,
            created_at: now.clone(),
            updated_at: now,
        },
    )?;
    Ok(job_id.to_string())
}

pub(crate) fn submit_job_with_placement_on_connection(
    conn: &Connection,
    job_id: &str,
    payload: &Value,
    placement: &PlacementRequest,
    assigned_node_id: Option<&str>,
) -> Result<String> {
    if serde_json::to_vec(payload)?.len() > 1024 * 1024 {
        anyhow::bail!("fleet job payload exceeds 1 MiB");
    }
    if contains_serialized_credential(payload) {
        anyhow::bail!("fleet job payload must not contain credential material");
    }
    validate_id(job_id, "jobId").map_err(|response| anyhow::anyhow!(response.body))?;
    let encoded_payload = serde_json::to_string(payload)?;
    let encoded_required =
        serde_json::to_string(&placement_scheduler::normalize_request(placement)?)?;
    if let Some(existing) = store::get_hub_job(conn, job_id)? {
        if existing.payload_json != encoded_payload
            || existing.required_capabilities_json != encoded_required
            || existing.target_node_id.as_deref() != assigned_node_id
        {
            anyhow::bail!("fleet job id replay changed immutable submission fields");
        }
        return Ok(job_id.to_string());
    }
    let now = current_timestamp();
    store::upsert_hub_job(
        conn,
        &store::HubJobRecord {
            job_id: job_id.to_string(),
            state: "queued".into(),
            priority: 0,
            required_capabilities_json: encoded_required,
            assigned_node_id: assigned_node_id.map(str::to_string),
            target_node_id: assigned_node_id.map(str::to_string),
            loop_id: None,
            payload_json: encoded_payload,
            created_at: now.clone(),
            updated_at: now,
        },
    )?;
    Ok(job_id.to_string())
}

pub fn completed_job(coven_home: &Path, job_id: &str) -> Result<Option<CompletedFleetJob>> {
    let conn = open(coven_home)?;
    completed_job_on_connection(&conn, job_id)
}

pub(crate) fn completed_job_on_connection(
    conn: &Connection,
    job_id: &str,
) -> Result<Option<CompletedFleetJob>> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT attempt_id, node_id, result_json FROM fleet_job_attempts
             WHERE job_id = ?1 AND state = 'completed'",
            params![job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(attempt_id, node_id, result)| {
        Ok(CompletedFleetJob {
            attempt_id,
            node_id,
            result: serde_json::from_str(&result)?,
        })
    })
    .transpose()
}

pub(crate) fn attempt_placement_observation_digest(
    conn: &Connection,
    job_id: &str,
    attempt_id: &str,
) -> Result<Option<String>> {
    conn.query_row(
        "SELECT placement_observation_digest FROM fleet_job_attempts
         WHERE job_id=?1 AND attempt_id=?2 AND state='completed'",
        params![job_id, attempt_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

pub fn failed_job(coven_home: &Path, job_id: &str) -> Result<Option<FailedFleetJob>> {
    let conn = open(coven_home)?;
    failed_job_on_connection(&conn, job_id)
}

pub(crate) fn failed_job_on_connection(
    conn: &Connection,
    job_id: &str,
) -> Result<Option<FailedFleetJob>> {
    let row: Option<(String, String, String)> = conn
        .query_row(
            "SELECT attempt_id, node_id, result_json FROM fleet_job_attempts
             WHERE job_id = ?1 AND state = 'failed'",
            params![job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(attempt_id, node_id, failure)| {
        Ok(FailedFleetJob {
            attempt_id,
            node_id,
            failure: serde_json::from_str(&failure)?,
        })
    })
    .transpose()
}

pub fn offload_workspace(
    coven_home: &Path,
    request: Value,
    wait_timeout: std::time::Duration,
) -> Result<Value> {
    if request["protocolVersion"] != crate::workspace_mobility::PROTOCOL_VERSION {
        anyhow::bail!("workspace request must use coven.workspace-driver.v1");
    }
    if serde_json::to_vec(&request)?.len() > 1024 * 1024 {
        anyhow::bail!("workspace request exceeds 1 MiB");
    }
    let operation = request["operation"]
        .as_str()
        .context("workspace request omitted operation")?;
    if !matches!(operation, "checkpoint" | "restore" | "release" | "acquire") {
        anyhow::bail!("only checkpoint, restore, release, and acquire may be leased");
    }
    if contains_serialized_credential(&request) {
        anyhow::bail!("workspace requests must not contain long-lived credentials");
    }
    let driver = request["driver"]
        .as_str()
        .context("workspace request omitted driver")?;
    let driver = if driver == "tailscale-s3" {
        "s3-checkpoint"
    } else {
        driver
    };
    let conn = open(coven_home)?;
    let job_id = format!("job_{}", Uuid::new_v4().simple());
    let now = current_timestamp();
    let required = vec![
        format!("workspace:{driver}"),
        "protocol:workspace-driver:1".into(),
    ];
    store::upsert_hub_job(
        &conn,
        &store::HubJobRecord {
            job_id: job_id.clone(),
            state: "queued".into(),
            priority: 0,
            required_capabilities_json: serde_json::to_string(&required)?,
            assigned_node_id: None,
            target_node_id: None,
            loop_id: None,
            payload_json: serde_json::to_string(&request)?,
            created_at: now.clone(),
            updated_at: now,
        },
    )?;
    let deadline = std::time::Instant::now() + wait_timeout;
    loop {
        let result: Option<String> = conn.query_row(
            "SELECT result_json FROM fleet_job_attempts WHERE job_id = ?1 AND state = 'completed'",
            params![job_id], |row| row.get(0)).optional()?.flatten();
        if let Some(result) = result {
            return serde_json::from_str(&result).context("invalid workspace completion");
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for workspace job {job_id}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn contains_serialized_credential(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "accesskeyid"
                    | "secretaccesskey"
                    | "apikey"
                    | "oauthtoken"
                    | "authorization"
                    | "accesstoken"
                    | "refreshtoken"
                    | "nodesecret"
            ) || contains_serialized_credential(value)
        }),
        Value::Array(values) => values.iter().any(contains_serialized_credential),
        _ => false,
    }
}

pub fn offload_harness(
    coven_home: &Path,
    request: Value,
    wait_timeout: std::time::Duration,
) -> Result<Value> {
    if request["protocolVersion"] != crate::harness_host::PROTOCOL_VERSION {
        anyhow::bail!("harness request must use coven.harness-host.v1");
    }
    if serde_json::to_vec(&request)?.len() > 512 * 1024 {
        anyhow::bail!("harness request exceeds 512 KiB");
    }
    if contains_serialized_credential(&request) {
        anyhow::bail!("harness requests must not contain credential material");
    }
    let harness = request["harness"].as_str().unwrap_or("fake");
    let actor_id = request["actorId"]
        .as_str()
        .context("harness request omitted actorId")?;
    let operation = request["operation"]
        .as_str()
        .context("harness request omitted operation")?;
    let conn = open(coven_home)?;
    let assigned_node_id: Option<String> = if operation == "start" {
        None
    } else {
        Some(
            conn.query_row(
                "SELECT node_id FROM fleet_harness_actors WHERE actor_id = ?1",
                params![actor_id],
                |row| row.get(0),
            )
            .context("harness actor has no fleet owner")?,
        )
    };
    let job_id = format!("job_{}", Uuid::new_v4().simple());
    let now = current_timestamp();
    let required = vec![
        format!("runtime:{harness}"),
        "protocol:harness-host:1".into(),
    ];
    store::upsert_hub_job(
        &conn,
        &store::HubJobRecord {
            job_id: job_id.clone(),
            state: "queued".into(),
            priority: 0,
            required_capabilities_json: serde_json::to_string(&required)?,
            target_node_id: assigned_node_id.clone(),
            assigned_node_id,
            loop_id: None,
            payload_json: serde_json::to_string(&request)?,
            created_at: now.clone(),
            updated_at: now,
        },
    )?;
    let deadline = std::time::Instant::now() + wait_timeout;
    loop {
        let result: Option<String> = conn.query_row("SELECT result_json FROM fleet_job_attempts WHERE job_id = ?1 AND state = 'completed'", params![job_id], |row| row.get(0)).optional()?.flatten();
        if let Some(result) = result {
            let result: Value =
                serde_json::from_str(&result).context("invalid harness completion")?;
            let node_id: String = conn.query_row(
                "SELECT node_id FROM fleet_job_attempts WHERE job_id = ?1",
                params![job_id],
                |row| row.get(0),
            )?;
            let generation = result["generation"]
                .as_u64()
                .context("harness completion omitted generation")?;
            let generation =
                i64::try_from(generation).context("harness generation exceeds supported range")?;
            let state = result["state"]
                .as_str()
                .context("harness completion omitted state")?;
            conn.execute("INSERT INTO fleet_harness_actors (actor_id, node_id, generation, state, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(actor_id) DO UPDATE SET node_id = excluded.node_id, generation = excluded.generation, state = excluded.state, updated_at = excluded.updated_at", params![actor_id, node_id, generation, state, current_timestamp()])?;
            return Ok(result);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for harness job {job_id}");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{handle_request_with_runtime_and_auth, NoopSessionRuntime};

    fn post(home: &Path, path: &str, body: &str, bearer: Option<&str>) -> Result<(u16, Value)> {
        let authorization = bearer.map(|secret| format!("Bearer {secret}"));
        let response = handle_request_with_runtime_and_auth(
            "POST",
            path,
            home,
            None,
            Some(body),
            &NoopSessionRuntime,
            crate::api::RequestSecurity {
                authorization: authorization.as_deref(),
                local_transport: true,
            },
        )?;
        let value = if response.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&response.body)?
        };
        Ok((response.status, value))
    }

    fn capabilities() -> Value {
        json!({
            "protocols": {"executor": [1], "workspaceDriver": [1]},
            "platform": {"os": "linux", "architecture": "x86_64", "version": "test"},
            "resources": {"cpuCores": 8, "memoryBytes": 16000000000_u64},
            "harnesses": ["fake"],
            "workspaceDrivers": ["filesystem"],
            "tools": ["shell", "cargo"]
        })
    }

    fn enroll(home: &Path, node_id: &str) -> Result<String> {
        let (status, issued) = post(home, "/api/v1/fleet/enrollments", "{}", None)?;
        assert_eq!(status, 201);
        let body = json!({
            "enrollmentCode": issued["enrollmentCode"],
            "nodeId": node_id,
            "capabilities": capabilities(),
        });
        let (status, redeemed) = post(
            home,
            "/api/v1/fleet/enrollments/redeem",
            &body.to_string(),
            None,
        )?;
        assert_eq!(status, 201);
        Ok(redeemed["nodeSecret"].as_str().unwrap().to_string())
    }

    #[test]
    fn enrollment_is_single_use_and_store_contains_only_verifiers() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (status, issued) = post(temp.path(), "/api/v1/fleet/enrollments", "{}", None)?;
        assert_eq!(status, 201);
        let code = issued["enrollmentCode"].as_str().unwrap();
        let request =
            json!({"enrollmentCode": code, "nodeId": "node-a", "capabilities": capabilities()});
        let (status, redeemed) = post(
            temp.path(),
            "/api/v1/fleet/enrollments/redeem",
            &request.to_string(),
            None,
        )?;
        assert_eq!(status, 201);
        let secret = redeemed["nodeSecret"].as_str().unwrap();
        let (status, _) = post(
            temp.path(),
            "/api/v1/fleet/enrollments/redeem",
            &request.to_string(),
            None,
        )?;
        assert_eq!(status, 401);
        let conn = open(temp.path())?;
        let stored_code: String =
            conn.query_row("SELECT code_verifier FROM fleet_enrollments", [], |row| {
                row.get(0)
            })?;
        let stored_secret: String = conn.query_row(
            "SELECT node_secret_verifier FROM node_registry",
            [],
            |row| row.get(0),
        )?;
        assert_ne!(stored_code, code);
        assert_ne!(stored_secret, secret);
        Ok(())
    }

    #[test]
    fn enrollment_issuance_requires_the_local_transport() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let response = handle_request_with_runtime_and_auth(
            "POST",
            "/api/v1/fleet/enrollments",
            temp.path(),
            None,
            Some("{}"),
            &NoopSessionRuntime,
            crate::api::RequestSecurity {
                authorization: None,
                local_transport: false,
            },
        )?;
        assert_eq!(response.status, 403);
        Ok(())
    }

    #[test]
    fn heartbeat_requires_node_identity_and_rejects_stale_epoch() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let node_credential = enroll(temp.path(), "node-a")?;
        let body = json!({"connectionEpoch": 2, "capabilities": capabilities()}).to_string();
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/node-a/heartbeat",
                &body,
                None
            )?
            .0,
            401
        );
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/node-a/heartbeat",
                &body,
                Some(&node_credential)
            )?
            .0,
            200
        );
        let stale = json!({"connectionEpoch": 1, "capabilities": capabilities()}).to_string();
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/node-a/heartbeat",
                &stale,
                Some(&node_credential)
            )?
            .0,
            409
        );
        Ok(())
    }

    #[test]
    fn revoked_and_stale_nodes_fail_closed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let node_credential = enroll(temp.path(), "node-a")?;
        assert_eq!(
            post(temp.path(), "/api/v1/fleet/nodes/node-a/revoke", "{}", None)?.0,
            200
        );
        let body = json!({"connectionEpoch": 1, "capabilities": capabilities()}).to_string();
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/node-a/heartbeat",
                &body,
                Some(&node_credential)
            )?
            .0,
            401
        );

        let node_credential = enroll(temp.path(), "node-b")?;
        let conn = open(temp.path())?;
        conn.execute(
            "UPDATE node_registry SET capabilities_observed_at = '2000-01-01T00:00:00Z', fleet_lease_expires_at = '2000-01-01T00:00:00Z' WHERE node_id = 'node-b'",
            [],
        )?;
        let now = current_timestamp();
        store::upsert_hub_job(
            &conn,
            &store::HubJobRecord {
                job_id: "stale-job".into(),
                state: "queued".into(),
                priority: 1,
                required_capabilities_json: serde_json::to_string(&vec!["shell"])?,
                assigned_node_id: None,
                target_node_id: None,
                loop_id: None,
                payload_json: "{}".into(),
                created_at: now.clone(),
                updated_at: now,
            },
        )?;
        drop(conn);
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/node-b/jobs/claim",
                "{}",
                Some(&node_credential)
            )?
            .0,
            204
        );
        Ok(())
    }

    #[test]
    fn claim_lease_completion_and_replay_are_fenced() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let secret_a = enroll(temp.path(), "node-a")?;
        let secret_b = enroll(temp.path(), "node-b")?;
        let conn = open(temp.path())?;
        let now = current_timestamp();
        store::upsert_hub_job(
            &conn,
            &store::HubJobRecord {
                job_id: "job-1".into(),
                state: "queued".into(),
                priority: 10,
                required_capabilities_json: serde_json::to_string(&vec!["shell"])?,
                assigned_node_id: None,
                target_node_id: None,
                loop_id: None,
                payload_json:
                    json!({"protocolVersion":"coven.executor.v1","command":["printf","ok"]})
                        .to_string(),
                created_at: now.clone(),
                updated_at: now,
            },
        )?;
        drop(conn);
        let (status, claim) = post(
            temp.path(),
            "/api/v1/fleet/nodes/node-a/jobs/claim",
            "{}",
            Some(&secret_a),
        )?;
        assert_eq!(status, 200);
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/node-b/jobs/claim",
                "{}",
                Some(&secret_b)
            )?
            .0,
            204
        );
        let completion = json!({
            "attemptId": claim["job"]["attemptId"],
            "leaseToken": claim["job"]["leaseToken"],
            "completionKey": "complete-1",
            "result": {"status":"completed","stdout":"ok"}
        });
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/job-1/complete",
                &completion.to_string(),
                Some(&secret_b)
            )?
            .0,
            401
        );
        let (status, first) = post(
            temp.path(),
            "/api/v1/fleet/jobs/job-1/complete",
            &completion.to_string(),
            Some(&secret_a),
        )?;
        assert_eq!(status, 200);
        assert_eq!(first["replayed"], false);
        let (status, replay) = post(
            temp.path(),
            "/api/v1/fleet/jobs/job-1/complete",
            &completion.to_string(),
            Some(&secret_a),
        )?;
        assert_eq!(status, 200);
        assert_eq!(replay["replayed"], true);
        Ok(())
    }

    #[test]
    fn failure_is_typed_terminal_replay_bound_and_lease_fenced() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let node_credential = enroll(temp.path(), "node-a")?;
        let conn = open(temp.path())?;
        let now = current_timestamp();
        store::upsert_hub_job(
            &conn,
            &store::HubJobRecord {
                job_id: "failing-job".into(),
                state: "queued".into(),
                priority: 10,
                required_capabilities_json: serde_json::to_string(&vec!["shell"])?,
                assigned_node_id: None,
                target_node_id: None,
                loop_id: None,
                payload_json: json!({"protocolVersion":"unsupported"}).to_string(),
                created_at: now.clone(),
                updated_at: now,
            },
        )?;
        drop(conn);
        let (_, claim) = post(
            temp.path(),
            "/api/v1/fleet/nodes/node-a/jobs/claim",
            "{}",
            Some(&node_credential),
        )?;
        let failure = json!({
            "attemptId": claim["job"]["attemptId"],
            "leaseToken": claim["job"]["leaseToken"],
            "completionKey": format!("fail:{}", claim["job"]["attemptId"].as_str().unwrap()),
            "failure": {"protocolVersion":FAILURE_PROTOCOL_VERSION,"code":"execution_failed","message":"runner stopped"},
        });
        let (status, first) = post(
            temp.path(),
            "/api/v1/fleet/jobs/failing-job/fail",
            &failure.to_string(),
            Some(&node_credential),
        )?;
        assert_eq!(status, 200);
        assert_eq!(first["disposition"], "terminal");
        assert_eq!(first["failure"], failure["failure"]);

        let (_, replay) = post(
            temp.path(),
            "/api/v1/fleet/jobs/failing-job/fail",
            &failure.to_string(),
            Some(&node_credential),
        )?;
        assert_eq!(replay["replayed"], true);
        let mut changed = failure.clone();
        changed["failure"]["message"] = "changed".into();
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/failing-job/fail",
                &changed.to_string(),
                Some(&node_credential),
            )?
            .0,
            409
        );
        changed["completionKey"] = "different".into();
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/failing-job/fail",
                &changed.to_string(),
                Some(&node_credential),
            )?
            .0,
            409
        );
        let conn = open(temp.path())?;
        assert_eq!(
            conn.query_row(
                "SELECT state FROM hub_jobs WHERE job_id='failing-job'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "failed"
        );
        assert_eq!(
            conn.query_row(
                "SELECT state FROM fleet_job_attempts WHERE job_id='failing-job'",
                [],
                |row| row.get::<_, String>(0)
            )?,
            "failed"
        );
        Ok(())
    }

    #[test]
    fn expired_lease_cannot_renew_or_complete() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let node_credential = enroll(temp.path(), "node-a")?;
        let conn = open(temp.path())?;
        let now = current_timestamp();
        store::upsert_hub_job(
            &conn,
            &store::HubJobRecord {
                job_id: "expiring-job".into(),
                state: "queued".into(),
                priority: 1,
                required_capabilities_json: serde_json::to_string(&vec!["shell"])?,
                assigned_node_id: None,
                target_node_id: None,
                loop_id: None,
                payload_json: "{}".into(),
                created_at: now.clone(),
                updated_at: now,
            },
        )?;
        drop(conn);
        let (_, claim) = post(
            temp.path(),
            "/api/v1/fleet/nodes/node-a/jobs/claim",
            "{}",
            Some(&node_credential),
        )?;
        let conn = open(temp.path())?;
        conn.execute(
            "UPDATE fleet_job_attempts SET lease_expires_at = '2000-01-01T00:00:00Z' WHERE job_id = 'expiring-job'",
            [],
        )?;
        drop(conn);
        let mutation = json!({
            "attemptId": claim["job"]["attemptId"],
            "leaseToken": claim["job"]["leaseToken"],
        });
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/expiring-job/renew",
                &mutation.to_string(),
                Some(&node_credential),
            )?
            .0,
            409
        );
        let completion = json!({
            "attemptId": claim["job"]["attemptId"],
            "leaseToken": claim["job"]["leaseToken"],
            "completionKey": "late",
            "result": {"status":"completed"},
        });
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/expiring-job/complete",
                &completion.to_string(),
                Some(&node_credential),
            )?
            .0,
            409
        );
        let (_, retry) = post(
            temp.path(),
            "/api/v1/fleet/nodes/node-a/jobs/claim",
            "{}",
            Some(&node_credential),
        )?;
        assert_eq!(retry["job"]["jobId"], "expiring-job");
        assert_ne!(retry["job"]["attemptId"], claim["job"]["attemptId"]);
        assert_ne!(retry["job"]["leaseToken"], claim["job"]["leaseToken"]);
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/expiring-job/complete",
                &completion.to_string(),
                Some(&node_credential),
            )?
            .0,
            409
        );
        Ok(())
    }

    #[test]
    fn expired_node_pinned_job_can_only_be_reclaimed_by_its_target() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let secret_a = enroll(temp.path(), "node-a")?;
        let secret_b = enroll(temp.path(), "node-b")?;
        let conn = open(temp.path())?;
        let now = current_timestamp();
        store::upsert_hub_job(
            &conn,
            &store::HubJobRecord {
                job_id: "pinned-job".into(),
                state: "queued".into(),
                priority: 1,
                required_capabilities_json: serde_json::to_string(&vec!["shell"])?,
                assigned_node_id: Some("node-a".into()),
                target_node_id: Some("node-a".into()),
                loop_id: None,
                payload_json: "{}".into(),
                created_at: now.clone(),
                updated_at: now,
            },
        )?;
        drop(conn);
        let (status, first) = post(
            temp.path(),
            "/api/v1/fleet/nodes/node-a/jobs/claim",
            "{}",
            Some(&secret_a),
        )?;
        assert_eq!(status, 200);
        let conn = open(temp.path())?;
        conn.execute("UPDATE fleet_job_attempts SET lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id='pinned-job'", [])?;
        drop(conn);
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/node-b/jobs/claim",
                "{}",
                Some(&secret_b)
            )?
            .0,
            204
        );
        let (status, second) = post(
            temp.path(),
            "/api/v1/fleet/nodes/node-a/jobs/claim",
            "{}",
            Some(&secret_a),
        )?;
        assert_eq!(status, 200);
        assert_ne!(first["job"]["attemptId"], second["job"]["attemptId"]);
        let conn = open(temp.path())?;
        assert_eq!(
            store::get_hub_job(&conn, "pinned-job")?
                .unwrap()
                .target_node_id
                .as_deref(),
            Some("node-a")
        );
        Ok(())
    }

    #[test]
    fn legacy_and_typed_placement_requests_decode() -> Result<()> {
        let legacy = decode_placement_request(
            r#"["os:linux","arch:amd64","shell","runtime:fake","workspace:filesystem","protocol:harness-host:1"]"#,
        )?;
        assert_eq!(legacy.required.os.as_deref(), Some("linux"));
        assert_eq!(legacy.required.architecture.as_deref(), Some("x86_64"));
        assert_eq!(legacy.required.tools, vec!["shell"]);
        assert_eq!(legacy.required.harnesses, vec!["fake"]);
        assert_eq!(legacy.required.protocols.harness_host, vec![1]);
        let typed = PlacementRequest {
            required: HardConstraints {
                os: Some("windows".into()),
                min_cpu_cores: 4,
                ..Default::default()
            },
            preferred: vec![],
        };
        assert_eq!(
            decode_placement_request(&serde_json::to_string(&typed)?)?,
            typed
        );
        Ok(())
    }

    #[test]
    fn claim_binds_observation_snapshot_and_delegation_digest() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let node_credential = enroll(temp.path(), "snapshot-node")?;
        let conn = open(temp.path())?;
        let request = PlacementRequest {
            required: HardConstraints {
                os: Some("linux".into()),
                architecture: Some("x86_64".into()),
                min_cpu_cores: 8,
                min_memory_bytes: 8_000_000_000,
                tools: vec!["cargo".into()],
                ..Default::default()
            },
            preferred: vec![],
        };
        let now = current_timestamp();
        store::upsert_hub_job(
            &conn,
            &store::HubJobRecord {
                job_id: "typed-snapshot".into(),
                state: "queued".into(),
                priority: 0,
                required_capabilities_json: serde_json::to_string(&request)?,
                assigned_node_id: None,
                target_node_id: None,
                loop_id: None,
                payload_json: json!({"protocolVersion":crate::delegation::PROTOCOL_VERSION})
                    .to_string(),
                created_at: now.clone(),
                updated_at: now,
            },
        )?;
        drop(conn);
        let (status, claim) = post(
            temp.path(),
            "/api/v1/fleet/nodes/snapshot-node/jobs/claim",
            "{}",
            Some(&node_credential),
        )?;
        assert_eq!(status, 200);
        let digest = claim["job"]["payload"]["placementObservationDigest"]
            .as_str()
            .context("delegation claim omitted observation digest")?;
        let conn = open(temp.path())?;
        let stored: (String, i64, String, String, String) = conn.query_row("SELECT placement_observation_digest,placement_connection_epoch,placement_observed_at,placement_capabilities_json,placement_match_evidence_json FROM fleet_job_attempts WHERE job_id='typed-snapshot'", [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
        assert_eq!(stored.0, digest);
        assert!(!stored.2.is_empty());
        assert_eq!(
            serde_json::from_str::<Value>(&stored.3)?["platform"]["os"],
            "linux"
        );
        assert_eq!(serde_json::from_str::<Value>(&stored.4)?["eligible"], true);
        Ok(())
    }

    fn insert_shell_job(home: &Path, job_id: &str) -> Result<()> {
        let conn = open(home)?;
        let now = current_timestamp();
        store::upsert_hub_job(
            &conn,
            &store::HubJobRecord {
                job_id: job_id.into(),
                state: "queued".into(),
                priority: 1,
                required_capabilities_json: serde_json::to_string(&vec!["shell"])?,
                assigned_node_id: None,
                target_node_id: None,
                loop_id: None,
                payload_json:
                    json!({"protocolVersion":"coven.executor.v1","command":["printf","ok"]})
                        .to_string(),
                created_at: now.clone(),
                updated_at: now,
            },
        )?;
        Ok(())
    }

    #[test]
    fn successful_renewal_extends_same_attempt_and_it_completes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let node_credential = enroll(temp.path(), "renew-node")?;
        insert_shell_job(temp.path(), "renew-job")?;
        let (_, claim) = post(
            temp.path(),
            "/api/v1/fleet/nodes/renew-node/jobs/claim",
            "{}",
            Some(&node_credential),
        )?;
        let attempt_id = claim["job"]["attemptId"]
            .as_str()
            .context("claim omitted attempt")?;
        let lease_token = claim["job"]["leaseToken"]
            .as_str()
            .context("claim omitted token")?;
        let conn = open(temp.path())?;
        let baseline =
            (Utc::now() + Duration::seconds(1)).to_rfc3339_opts(SecondsFormat::Millis, true);
        conn.execute(
            "UPDATE fleet_job_attempts SET lease_expires_at=?2 WHERE job_id=?1",
            params!["renew-job", baseline],
        )?;
        drop(conn);
        let mutation = json!({"attemptId":attempt_id,"leaseToken":lease_token});
        let (status, renewed) = post(
            temp.path(),
            "/api/v1/fleet/jobs/renew-job/renew",
            &mutation.to_string(),
            Some(&node_credential),
        )?;
        assert_eq!(status, 200);
        assert_eq!(renewed["attemptId"], attempt_id);
        assert!(parse_time(renewed["leaseExpiresAt"].as_str().unwrap())? > parse_time(&baseline)?);
        let completion = json!({"attemptId":attempt_id,"leaseToken":lease_token,"completionKey":"renew-complete","result":{"status":"completed"}});
        let (status, completed) = post(
            temp.path(),
            "/api/v1/fleet/jobs/renew-job/complete",
            &completion.to_string(),
            Some(&node_credential),
        )?;
        assert_eq!(status, 200);
        assert_eq!(completed["replayed"], false);
        Ok(())
    }

    #[test]
    fn hub_reopen_preserves_live_lease_then_expiry_allows_one_replacement() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let node_credential = enroll(temp.path(), "restart-node")?;
        insert_shell_job(temp.path(), "restart-job")?;
        let (_, first) = post(
            temp.path(),
            "/api/v1/fleet/nodes/restart-node/jobs/claim",
            "{}",
            Some(&node_credential),
        )?;
        let first_attempt = first["job"]["attemptId"].as_str().unwrap().to_string();
        let first_token = first["job"]["leaseToken"].as_str().unwrap().to_string();

        // A fresh store connection models hub process reconstruction. Durable
        // lease authority must still prevent a duplicate claim.
        drop(open(temp.path())?);
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/restart-node/jobs/claim",
                "{}",
                Some(&node_credential)
            )?
            .0,
            204
        );

        let conn = open(temp.path())?;
        conn.execute("UPDATE fleet_job_attempts SET lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id='restart-job'", [])?;
        drop(conn);
        let (_, replacement) = post(
            temp.path(),
            "/api/v1/fleet/nodes/restart-node/jobs/claim",
            "{}",
            Some(&node_credential),
        )?;
        let replacement_attempt = replacement["job"]["attemptId"].as_str().unwrap();
        assert_ne!(replacement_attempt, first_attempt);
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/restart-node/jobs/claim",
                "{}",
                Some(&node_credential)
            )?
            .0,
            204
        );
        let old = json!({"attemptId":first_attempt,"leaseToken":first_token,"completionKey":"old","result":{"status":"completed"}});
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/restart-job/complete",
                &old.to_string(),
                Some(&node_credential)
            )?
            .0,
            409
        );
        let replacement_completion = json!({"attemptId":replacement_attempt,"leaseToken":replacement["job"]["leaseToken"],"completionKey":"replacement","result":{"status":"completed"}});
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/restart-job/complete",
                &replacement_completion.to_string(),
                Some(&node_credential)
            )?
            .0,
            200
        );
        Ok(())
    }

    #[test]
    fn revocation_fences_live_attempt_and_expiry_recovers_on_another_node() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let secret_a = enroll(temp.path(), "a-revoked-node")?;
        let secret_b = enroll(temp.path(), "b-recovery-node")?;
        insert_shell_job(temp.path(), "revoked-job")?;
        let (_, claim) = post(
            temp.path(),
            "/api/v1/fleet/nodes/a-revoked-node/jobs/claim",
            "{}",
            Some(&secret_a),
        )?;
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/nodes/a-revoked-node/revoke",
                "{}",
                None
            )?
            .0,
            200
        );
        let mutation =
            json!({"attemptId":claim["job"]["attemptId"],"leaseToken":claim["job"]["leaseToken"]});
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/revoked-job/renew",
                &mutation.to_string(),
                Some(&secret_a)
            )?
            .0,
            401
        );
        let completion = json!({"attemptId":claim["job"]["attemptId"],"leaseToken":claim["job"]["leaseToken"],"completionKey":"revoked","result":{"status":"completed"}});
        assert_eq!(
            post(
                temp.path(),
                "/api/v1/fleet/jobs/revoked-job/complete",
                &completion.to_string(),
                Some(&secret_a)
            )?
            .0,
            401
        );
        let conn = open(temp.path())?;
        conn.execute("UPDATE fleet_job_attempts SET lease_expires_at='2000-01-01T00:00:00Z' WHERE job_id='revoked-job'", [])?;
        drop(conn);
        let (status, replacement) = post(
            temp.path(),
            "/api/v1/fleet/nodes/b-recovery-node/jobs/claim",
            "{}",
            Some(&secret_b),
        )?;
        assert_eq!(status, 200);
        assert_eq!(replacement["job"]["jobId"], "revoked-job");
        assert_ne!(replacement["job"]["attemptId"], claim["job"]["attemptId"]);
        Ok(())
    }
}
