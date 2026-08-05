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
         );",
    )
    .context("failed to initialize fleet trust schema")?;
    Ok(conn)
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
            "pairingAvailable": pairing_available
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
            json!({"service":"coven-fleet","protocolVersions":[PROTOCOL],"pairingAvailable":false})
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
    fn version_mismatch_fails_closed() -> Result<()> {
        assert_eq!(
            negotiate(Some(r#"{"protocolVersions":["coven.fleet.v2"]}"#))?.status,
            409
        );
        Ok(())
    }
}
