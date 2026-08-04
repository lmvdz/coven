//! Executor-local managed harness actors.
//!
//! The hub may lease actor operations, but actor process/state authority stays
//! on the executor that owns provider credentials.

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{api::current_timestamp, store, STORE_FILE_NAME};

pub const PROTOCOL_VERSION: &str = "coven.harness-host.v1";

fn open(coven_home: &Path) -> Result<Connection> {
    let conn = store::open_store(&coven_home.join(STORE_FILE_NAME))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS harness_actors (
            actor_id TEXT PRIMARY KEY NOT NULL,
            harness TEXT NOT NULL,
            binding_json TEXT NOT NULL DEFAULT '{}',
            state TEXT NOT NULL,
            generation INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS harness_actor_events (
            actor_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            kind TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (actor_id, sequence)
        );
        CREATE TABLE IF NOT EXISTS harness_actor_commands (
            actor_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            generation INTEGER NOT NULL,
            input_digest TEXT NOT NULL,
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (actor_id, idempotency_key),
            FOREIGN KEY (actor_id) REFERENCES harness_actors(actor_id)
        );",
    )?;
    ensure_column(
        &conn,
        "harness_actors",
        "binding_json",
        "ALTER TABLE harness_actors ADD COLUMN binding_json TEXT NOT NULL DEFAULT '{}'",
    )?;
    Ok(conn)
}

fn ensure_column(conn: &Connection, table: &str, column: &str, sql: &str) -> Result<()> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !columns.iter().any(|candidate| candidate == column) {
        conn.execute(sql, [])?;
    }
    Ok(())
}

fn required<'a>(request: &'a Value, field: &str) -> Result<&'a str> {
    request[field]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("harness request omitted {field}"))
}

fn valid_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn contains_credential(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "apikey"
                    | "oauthtoken"
                    | "authorization"
                    | "accesstoken"
                    | "refreshtoken"
                    | "nodesecret"
            ) || contains_credential(value)
        }),
        Value::Array(values) => values.iter().any(contains_credential),
        _ => false,
    }
}

pub fn invoke(coven_home: &Path, request: &Value) -> Result<Value> {
    if request["protocolVersion"] != PROTOCOL_VERSION {
        bail!("harness request uses an unsupported protocol version");
    }
    if contains_credential(request) {
        bail!("harness requests must reference executor-local credentials, not serialize them");
    }
    let request_id = required(request, "requestId")?;
    let operation = required(request, "operation")?;
    if operation == "probe" {
        return Ok(
            json!({"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "ok": true, "harnesses": ["fake"]}),
        );
    }
    let actor_id = required(request, "actorId")?;
    if !valid_id(actor_id) {
        bail!("actorId has an invalid format");
    }
    let mut conn = open(coven_home)?;
    let now = current_timestamp();
    match operation {
        "start" => {
            let harness = required(request, "harness")?;
            if harness != "fake" {
                bail!("harness is not available on this executor");
            }
            let generation = request["generation"]
                .as_u64()
                .context("generation must be a positive integer")?;
            if generation == 0 || generation > i64::MAX as u64 {
                bail!("generation must be a positive integer");
            }
            let binding = actor_binding(request.get("binding"))?;
            let encoded_binding = serde_json::to_string(&binding)?;
            let existing: Option<(String, String, i64, String)> = conn
                .query_row(
                    "SELECT state,harness,generation,binding_json FROM harness_actors WHERE actor_id = ?1",
                    params![actor_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            if let Some((state, stored_harness, stored_generation, stored_binding)) = existing {
                if stored_generation != generation as i64
                    || stored_harness != harness
                    || stored_binding != encoded_binding
                {
                    bail!("actor immutable binding conflict");
                }
                return response(request_id, actor_id, &state, generation, true, None);
            }
            conn.execute("INSERT INTO harness_actors (actor_id,harness,binding_json,state,generation,created_at,updated_at) VALUES (?1,?2,?3,'ready',?4,?5,?5)", params![actor_id,harness,encoded_binding,generation as i64,now])?;
            append_event(
                &conn,
                actor_id,
                "ready",
                &json!({"generation": generation}),
                &now,
            )?;
            response(request_id, actor_id, "ready", generation, false, None)
        }
        "send" => {
            let input = required(request, "input")?;
            let idempotency_key = required(request, "idempotencyKey")?;
            if !valid_id(idempotency_key) {
                bail!("idempotencyKey has an invalid format");
            }
            if input.len() > 256 * 1024 {
                bail!("actor input exceeds 256 KiB");
            }
            let generation = request["generation"]
                .as_u64()
                .filter(|generation| *generation > 0 && *generation <= i64::MAX as u64)
                .context("generation must be a positive integer")?;
            let input_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()));
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let stored: Option<(i64, String, String)> = tx
                .query_row(
                    "SELECT generation,input_digest,result_json FROM harness_actor_commands
                     WHERE actor_id=?1 AND idempotency_key=?2",
                    params![actor_id, idempotency_key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if let Some((stored_generation, stored_digest, raw)) = stored {
                if stored_generation != generation as i64 || stored_digest != input_digest {
                    bail!("actor command idempotency conflict");
                }
                let mut replay: Value = serde_json::from_str(&raw)?;
                replay["replayed"] = true.into();
                tx.commit()?;
                return Ok(replay);
            }
            let actual_generation = require_ready(&tx, actor_id)?;
            if actual_generation != generation {
                bail!("actor generation conflict");
            }
            append_event(&tx, actor_id, "input", &event_evidence(input), &now)?;
            let output = format!("fake:{input}");
            append_event(&tx, actor_id, "output", &event_evidence(&output), &now)?;
            let result = response(
                request_id,
                actor_id,
                "ready",
                generation,
                false,
                Some(output),
            )?;
            tx.execute(
                "INSERT INTO harness_actor_commands
                 (actor_id,idempotency_key,generation,input_digest,result_json,created_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    actor_id,
                    idempotency_key,
                    generation as i64,
                    input_digest,
                    serde_json::to_string(&result)?,
                    now
                ],
            )?;
            tx.commit()?;
            Ok(result)
        }
        "status" => {
            let (state, generation): (String, i64) = conn
                .query_row(
                    "SELECT state, generation FROM harness_actors WHERE actor_id = ?1",
                    params![actor_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context("harness actor was not found")?;
            let events: i64 = conn.query_row(
                "SELECT COUNT(*) FROM harness_actor_events WHERE actor_id = ?1",
                params![actor_id],
                |row| row.get(0),
            )?;
            let mut value = response(request_id, actor_id, &state, generation as u64, false, None)?;
            value["eventCount"] = events.into();
            Ok(value)
        }
        "stop" => {
            let requested_generation = request["generation"]
                .as_u64()
                .context("generation must be a positive integer")?;
            let generation: i64 = conn
                .query_row(
                    "SELECT generation FROM harness_actors WHERE actor_id = ?1",
                    params![actor_id],
                    |row| row.get(0),
                )
                .context("harness actor was not found")?;
            if requested_generation == 0 || requested_generation != generation as u64 {
                bail!("actor generation conflict");
            }
            let state: String = conn.query_row(
                "SELECT state FROM harness_actors WHERE actor_id = ?1",
                params![actor_id],
                |row| row.get(0),
            )?;
            if state == "stopped" {
                return response(
                    request_id,
                    actor_id,
                    "stopped",
                    generation as u64,
                    true,
                    None,
                );
            }
            conn.execute(
                "UPDATE harness_actors SET state = 'stopped', updated_at = ?2 WHERE actor_id = ?1",
                params![actor_id, now],
            )?;
            append_event(&conn, actor_id, "stopped", &json!({}), &now)?;
            response(
                request_id,
                actor_id,
                "stopped",
                generation as u64,
                false,
                None,
            )
        }
        _ => bail!("unsupported harness operation"),
    }
}

fn actor_binding(value: Option<&Value>) -> Result<Value> {
    let Some(value) = value else {
        return Ok(json!({}));
    };
    let object = value
        .as_object()
        .context("actor binding must be an object")?;
    let allowed = ["kind", "sessionId", "placementId", "workspacePath"];
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || object.get("kind").and_then(Value::as_str) != Some("session-placement")
    {
        bail!("actor binding is invalid");
    }
    for field in ["sessionId", "placementId"] {
        let id = object
            .get(field)
            .and_then(Value::as_str)
            .filter(|candidate| valid_id(candidate))
            .with_context(|| format!("actor binding omitted or invalid {field}"))?;
        if id.is_empty() {
            bail!("actor binding omitted or invalid {field}");
        }
    }
    let workspace = object
        .get("workspacePath")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .context("actor binding omitted workspacePath")?;
    if !Path::new(workspace).is_absolute() {
        bail!("actor binding workspacePath must be absolute");
    }
    Ok(value.clone())
}

fn event_evidence(value: &str) -> Value {
    json!({"sizeBytes": value.len(), "sha256Base64": URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))})
}

fn require_ready(conn: &Connection, actor_id: &str) -> Result<u64> {
    let (state, generation): (String, i64) = conn
        .query_row(
            "SELECT state, generation FROM harness_actors WHERE actor_id = ?1",
            params![actor_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("harness actor was not found")?;
    if state != "ready" {
        bail!("harness actor is not ready");
    }
    Ok(generation as u64)
}

fn append_event(
    conn: &Connection,
    actor_id: &str,
    kind: &str,
    payload: &Value,
    now: &str,
) -> Result<()> {
    conn.execute("INSERT INTO harness_actor_events (actor_id, sequence, kind, payload_json, created_at) VALUES (?1, COALESCE((SELECT MAX(sequence) + 1 FROM harness_actor_events WHERE actor_id = ?1), 1), ?2, ?3, ?4)", params![actor_id, kind, serde_json::to_string(payload)?, now])?;
    Ok(())
}

fn response(
    request_id: &str,
    actor_id: &str,
    state: &str,
    generation: u64,
    replayed: bool,
    output: Option<String>,
) -> Result<Value> {
    Ok(
        json!({"protocolVersion": PROTOCOL_VERSION, "requestId": request_id, "ok": true, "actorId": actor_id, "state": state, "generation": generation, "ready": state == "ready", "replayed": replayed, "output": output}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fake_actor_survives_reopen_accepts_input_and_stops() -> Result<()> {
        let home = tempfile::tempdir()?;
        let base = |operation: &str| json!({"protocolVersion": PROTOCOL_VERSION, "requestId": operation, "operation": operation, "actorId": "actor-1"});
        let started = invoke(
            home.path(),
            &json!({"protocolVersion": PROTOCOL_VERSION, "requestId": "start", "operation": "start", "actorId": "actor-1", "harness": "fake", "generation": 1}),
        )?;
        assert_eq!(started["state"], "ready");
        assert_eq!(
            invoke(
                home.path(),
                &json!({"protocolVersion": PROTOCOL_VERSION, "requestId": "send", "operation": "send", "actorId": "actor-1", "generation": 1, "idempotencyKey": "input-1", "input": "hello"})
            )?["output"],
            "fake:hello"
        );
        let conn = open(home.path())?;
        let persisted: String = conn.query_row(
            "SELECT GROUP_CONCAT(payload_json, '') FROM harness_actor_events",
            [],
            |row| row.get(0),
        )?;
        assert!(!persisted.contains("hello"));
        assert_eq!(invoke(home.path(), &base("status"))?["eventCount"], 3);
        let replay = invoke(
            home.path(),
            &json!({"protocolVersion": PROTOCOL_VERSION, "requestId": "send", "operation": "send", "actorId": "actor-1", "generation": 1, "idempotencyKey": "input-1", "input": "hello"}),
        )?;
        assert_eq!(replay["output"], "fake:hello");
        assert_eq!(replay["replayed"], true);
        assert_eq!(invoke(home.path(), &base("status"))?["eventCount"], 3);
        assert!(invoke(
            home.path(),
            &json!({"protocolVersion": PROTOCOL_VERSION, "requestId": "changed", "operation": "send", "actorId": "actor-1", "generation": 1, "idempotencyKey": "input-1", "input": "changed"}),
        )
        .is_err());
        assert_eq!(
            invoke(
                home.path(),
                &json!({"protocolVersion": PROTOCOL_VERSION, "requestId": "stop", "operation": "stop", "actorId": "actor-1", "generation": 1})
            )?["state"],
            "stopped"
        );
        assert!(invoke(home.path(), &json!({"protocolVersion": PROTOCOL_VERSION, "requestId": "send2", "operation": "send", "actorId": "actor-1", "generation": 1, "idempotencyKey": "input-2", "input": "again"})).is_err());
        Ok(())
    }

    #[test]
    fn actor_start_replay_requires_the_exact_immutable_binding() -> Result<()> {
        let home = tempfile::tempdir()?;
        let binding = json!({
            "kind": "session-placement",
            "sessionId": "session-1",
            "placementId": "placement-1",
            "workspacePath": home.path().join("workspace"),
        });
        let request = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": "start-1",
            "operation": "start",
            "actorId": "actor-bound",
            "harness": "fake",
            "generation": 2,
            "binding": binding,
        });
        assert_eq!(invoke(home.path(), &request)?["replayed"], false);
        assert_eq!(invoke(home.path(), &request)?["replayed"], true);

        let mut changed = request.clone();
        changed["binding"]["placementId"] = "placement-2".into();
        assert!(invoke(home.path(), &changed)
            .unwrap_err()
            .to_string()
            .contains("immutable binding conflict"));

        let conn = open(home.path())?;
        let stored: (String, String, i64) = conn.query_row(
            "SELECT harness,binding_json,generation FROM harness_actors WHERE actor_id='actor-bound'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(stored.0, "fake");
        assert_eq!(serde_json::from_str::<Value>(&stored.1)?, binding);
        assert_eq!(stored.2, 2);
        Ok(())
    }

    #[test]
    fn provider_auth_remains_executor_local_and_serialized_credentials_fail_closed() -> Result<()> {
        let home = tempfile::tempdir()?;
        let auth = home.path().join("provider-auth");
        std::fs::create_dir(&auth)?;
        let sentinel = "provider-oauth-secret-release-proof";
        std::fs::write(auth.join("claude.oauth"), sentinel)?;
        let request = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": "local-auth-start",
            "operation": "start",
            "actorId": "actor-local-auth",
            "harness": "fake",
            "generation": 1,
        });
        assert_eq!(invoke(home.path(), &request)?["state"], "ready");
        let store_bytes = std::fs::read(home.path().join(STORE_FILE_NAME))?;
        assert!(!store_bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel.as_bytes()));
        assert_eq!(
            std::fs::read_to_string(auth.join("claude.oauth"))?,
            sentinel
        );

        for field in ["oauthToken", "apiKey", "authorization", "nodeSecret"] {
            let mut rejected = request.clone();
            rejected["requestId"] = format!("reject-{field}").into();
            rejected[field] = sentinel.into();
            assert!(invoke(home.path(), &rejected)
                .unwrap_err()
                .to_string()
                .contains("executor-local credentials"));
        }
        Ok(())
    }
}
