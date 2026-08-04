//! Executor-local composite steps for automatic session roam.

use crate::{fleet_executor::AttemptCancellation, harness_host, workspace_mobility};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

pub const PROTOCOL_VERSION: &str = "coven.session-roam.v1";
pub const RESULT_PROTOCOL_VERSION: &str = "coven.session-roam-result.v1";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    protocol_version: String,
    operation: String,
    roam_id: String,
    session_id: String,
    placement_id: String,
    generation: u64,
    attempt_id: String,
    node_id: String,
    #[serde(default)]
    workspace_driver: Option<String>,
    #[serde(default)]
    checkpoint_locator: Option<Value>,
    #[serde(default)]
    checkpoint: Option<Value>,
    #[serde(default)]
    harness: Option<String>,
    #[serde(default)]
    actor_id: Option<String>,
    #[serde(default)]
    input_id: Option<String>,
    #[serde(default)]
    sequence: Option<u64>,
    #[serde(default)]
    input: Option<Value>,
}

pub(crate) fn placement_workspace(
    coven_home: &Path,
    session_id: &str,
    placement_id: &str,
) -> Result<PathBuf> {
    validate_id(session_id, "sessionId")?;
    validate_id(placement_id, "placementId")?;
    Ok(coven_home
        .join("session-placements")
        .join(session_id)
        .join(placement_id)
        .join("workspace"))
}

pub(crate) fn run(
    coven_home: &Path,
    value: &Value,
    workspace_binary: Option<&OsStr>,
    cancellation: &AttemptCancellation,
) -> Result<Value> {
    if contains_credential(value) {
        bail!("session roam payload must not contain credential material");
    }
    let payload: Payload =
        serde_json::from_value(value.clone()).context("invalid session roam payload")?;
    validate(&payload)?;
    cancellation.check()?;
    let attempt_root = coven_home
        .join("session-roam-attempts")
        .join(&payload.roam_id)
        .join(&payload.attempt_id);
    ensure_confined_root(coven_home, &attempt_root)?;
    fs::create_dir_all(&attempt_root)?;
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(value)?));
    let digest_path = attempt_root.join("request.sha256");
    match fs::read_to_string(&digest_path) {
        Ok(stored) if stored != digest => bail!("session roam attempt payload changed"),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::write(&digest_path, &digest)?;
        }
        Err(error) => return Err(error.into()),
    }
    let result_path = attempt_root.join("result.json");
    if let Ok(bytes) = fs::read(&result_path) {
        cancellation.check()?;
        return serde_json::from_slice(&bytes).context("stored session roam result is invalid");
    }
    let (result, cleanup_actor) = match payload.operation.as_str() {
        "checkpoint-source" => (
            checkpoint_source(coven_home, &payload, workspace_binary, cancellation)?,
            None,
        ),
        "prepare-target" => prepare_target(
            coven_home,
            &payload,
            workspace_binary,
            cancellation,
            &attempt_root,
        )?,
        "deliver-input" => (deliver_input(coven_home, &payload, cancellation)?, None),
        _ => bail!("unsupported session roam operation"),
    };
    if let Err(error) = cancellation.check() {
        cleanup_new_actor(coven_home, cleanup_actor.as_ref());
        return Err(error);
    }
    let temporary = attempt_root.join(format!(".result-{}.tmp", std::process::id()));
    fs::write(&temporary, serde_json::to_vec(&result)?)?;
    if let Err(error) = cancellation.check() {
        let _ = fs::remove_file(&temporary);
        cleanup_new_actor(coven_home, cleanup_actor.as_ref());
        return Err(error);
    }
    fs::rename(temporary, result_path)?;
    Ok(result)
}

fn checkpoint_source(
    coven_home: &Path,
    payload: &Payload,
    workspace_binary: Option<&OsStr>,
    cancellation: &AttemptCancellation,
) -> Result<Value> {
    let driver = required_string(&payload.workspace_driver, "workspaceDriver")?;
    let locator = payload
        .checkpoint_locator
        .as_ref()
        .context("checkpoint-source omitted checkpointLocator")?;
    let workspace = placement_workspace(coven_home, &payload.session_id, &payload.placement_id)?;
    ensure_regular_directory(&workspace)?;
    let response = invoke_workspace(
        &json!({
            "protocolVersion": workspace_mobility::PROTOCOL_VERSION,
            "requestId": format!("checkpoint-{}", payload.roam_id),
            "driver": driver,
            "operation": "checkpoint",
            "workspacePath": workspace,
            "generation": payload.generation,
            "locator": locator,
            "excludePaths": workspace_mobility::portable_generated_exclusions(),
        }),
        workspace_binary,
    )?;
    cancellation.check()?;
    let checkpoint = response["checkpoint"].clone();
    validate_checkpoint(&checkpoint, driver, payload.generation)?;
    result(payload, json!({"checkpoint": checkpoint}))
}

fn prepare_target(
    coven_home: &Path,
    payload: &Payload,
    workspace_binary: Option<&OsStr>,
    cancellation: &AttemptCancellation,
    attempt_root: &Path,
) -> Result<(Value, Option<(String, u64)>)> {
    let driver = required_string(&payload.workspace_driver, "workspaceDriver")?;
    let checkpoint = payload
        .checkpoint
        .as_ref()
        .context("prepare-target omitted checkpoint")?;
    validate_checkpoint(checkpoint, driver, payload.generation.saturating_sub(1))?;
    let harness = required_string(&payload.harness, "harness")?;
    let actor_id = required_string(&payload.actor_id, "actorId")?;
    validate_id(actor_id, "actorId")?;
    let workspace = placement_workspace(coven_home, &payload.session_id, &payload.placement_id)?;
    let placement_root = workspace
        .parent()
        .context("placement workspace has no parent")?;
    ensure_confined_root(coven_home, placement_root)?;
    let placement_parent = placement_root
        .parent()
        .context("placement root has no parent")?;
    ensure_confined_root(coven_home, placement_parent)?;
    fs::create_dir_all(placement_parent)?;
    let manifest = json!({
        "roamId": payload.roam_id,
        "sessionId": payload.session_id,
        "placementId": payload.placement_id,
        "generation": payload.generation,
        "nodeId": payload.node_id,
        "workspaceDriver": driver,
        "checkpointSha256": checkpoint["sha256"],
        "harness": harness,
        "actorId": actor_id,
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_path = placement_root.join("manifest.json");
    if workspace.exists() {
        if fs::read(&manifest_path).context("prepared placement omitted manifest")?
            != manifest_bytes
        {
            bail!("prepared placement manifest conflict");
        }
        ensure_regular_directory(&workspace)?;
    } else {
        if placement_root.exists() {
            bail!("prepared placement is incomplete");
        }
        let staging_root = attempt_root.join("staging-placement");
        if staging_root.exists() {
            fs::remove_dir_all(&staging_root)?;
        }
        fs::create_dir_all(&staging_root)?;
        let staging = staging_root.join("workspace");
        invoke_workspace(
            &json!({
                "protocolVersion": workspace_mobility::PROTOCOL_VERSION,
                "requestId": format!("restore-{}", payload.roam_id),
                "driver": driver,
                "operation": "restore",
                "destinationPath": staging,
                "generation": checkpoint["generation"],
                "checkpoint": checkpoint,
            }),
            workspace_binary,
        )?;
        cancellation.check()?;
        ensure_regular_directory(&staging)?;
        write_synced_file(&staging_root.join("manifest.json"), &manifest_bytes)?;
        fs::rename(&staging_root, placement_root)?;
    }
    let actor = harness_host::invoke(
        coven_home,
        &json!({
            "protocolVersion": harness_host::PROTOCOL_VERSION,
            "requestId": format!("start-{}", payload.roam_id),
            "operation": "start",
            "actorId": actor_id,
            "harness": harness,
            "generation": payload.generation,
            "binding": {
                "kind": "session-placement",
                "sessionId": payload.session_id,
                "placementId": payload.placement_id,
                "workspacePath": workspace,
            },
        }),
    )?;
    let newly_started = actor["replayed"] != true;
    let readiness = (|| -> Result<Value> {
        cancellation.check()?;
        if actor["actorId"] != actor_id
            || actor["generation"] != payload.generation
            || actor["state"] != "ready"
            || actor["ready"] != true
        {
            bail!("target harness readiness evidence did not match placement");
        }
        result(
            payload,
            json!({
                "workspace": {
                    "driver": driver,
                    "checkpointSha256": checkpoint["sha256"],
                    "manifestSha256": URL_SAFE_NO_PAD.encode(Sha256::digest(&manifest_bytes)),
                },
                "actor": actor,
            }),
        )
    })();
    match readiness {
        Ok(value) => Ok((
            value,
            newly_started.then(|| (actor_id.to_string(), payload.generation)),
        )),
        Err(error) => {
            cleanup_new_actor(
                coven_home,
                newly_started
                    .then(|| (actor_id.to_string(), payload.generation))
                    .as_ref(),
            );
            Err(error)
        }
    }
}

fn write_synced_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn cleanup_new_actor(coven_home: &Path, actor: Option<&(String, u64)>) {
    let Some((actor_id, generation)) = actor else {
        return;
    };
    let _ = harness_host::invoke(
        coven_home,
        &json!({
            "protocolVersion": harness_host::PROTOCOL_VERSION,
            "requestId": format!("cancel-{actor_id}-{generation}"),
            "operation": "stop",
            "actorId": actor_id,
            "generation": generation,
        }),
    );
}

fn deliver_input(
    coven_home: &Path,
    payload: &Payload,
    cancellation: &AttemptCancellation,
) -> Result<Value> {
    let actor_id = required_string(&payload.actor_id, "actorId")?;
    let input_id = required_string(&payload.input_id, "inputId")?;
    validate_id(actor_id, "actorId")?;
    validate_id(input_id, "inputId")?;
    let sequence = payload
        .sequence
        .filter(|value| *value > 0)
        .context("invalid input sequence")?;
    let input = payload
        .input
        .as_ref()
        .context("deliver-input omitted input")?;
    let data = input["data"]
        .as_str()
        .context("deliver-input requires input.data")?;
    cancellation.check()?;
    let actor = harness_host::invoke(
        coven_home,
        &json!({
            "protocolVersion": harness_host::PROTOCOL_VERSION,
            "requestId": format!("input-{input_id}"),
            "operation": "send",
            "actorId": actor_id,
            "generation": payload.generation,
            "idempotencyKey": input_id,
            "input": data,
        }),
    )?;
    cancellation.check()?;
    let output = actor["output"]
        .as_str()
        .context("harness input completion omitted output")?;
    result(
        payload,
        json!({
            "inputId": input_id,
            "sequence": sequence,
            "delivery": {
                "actorId": actor_id,
                "inputSha256": URL_SAFE_NO_PAD.encode(Sha256::digest(data.as_bytes())),
                "output": {"data": output},
                "outputSha256": URL_SAFE_NO_PAD.encode(Sha256::digest(output.as_bytes())),
            },
        }),
    )
}

fn result(payload: &Payload, evidence: Value) -> Result<Value> {
    let mut value = json!({
        "protocolVersion": RESULT_PROTOCOL_VERSION,
        "operation": payload.operation,
        "roamId": payload.roam_id,
        "sessionId": payload.session_id,
        "placementId": payload.placement_id,
        "generation": payload.generation,
        "attemptId": payload.attempt_id,
        "nodeId": payload.node_id,
        "evidence": evidence,
    });
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&value)?));
    value["resultDigest"] = digest.into();
    Ok(value)
}

fn validate(payload: &Payload) -> Result<()> {
    if payload.protocol_version != PROTOCOL_VERSION || payload.generation == 0 {
        bail!("unsupported session roam payload");
    }
    for (value, name) in [
        (&payload.roam_id, "roamId"),
        (&payload.session_id, "sessionId"),
        (&payload.placement_id, "placementId"),
        (&payload.attempt_id, "attemptId"),
        (&payload.node_id, "nodeId"),
    ] {
        validate_id(value, name)?;
    }
    let valid_shape = match payload.operation.as_str() {
        "checkpoint-source" => {
            payload.workspace_driver.is_some()
                && payload.checkpoint_locator.is_some()
                && payload.checkpoint.is_none()
                && payload.harness.is_none()
                && payload.actor_id.is_none()
                && payload.input_id.is_none()
                && payload.sequence.is_none()
                && payload.input.is_none()
        }
        "prepare-target" => {
            payload.workspace_driver.is_some()
                && payload.checkpoint_locator.is_none()
                && payload.checkpoint.is_some()
                && payload.harness.is_some()
                && payload.actor_id.is_some()
                && payload.input_id.is_none()
                && payload.sequence.is_none()
                && payload.input.is_none()
        }
        "deliver-input" => {
            payload.workspace_driver.is_none()
                && payload.checkpoint_locator.is_none()
                && payload.checkpoint.is_none()
                && payload.harness.is_none()
                && payload.actor_id.is_some()
                && payload.input_id.is_some()
                && payload.sequence.is_some()
                && payload.input.is_some()
        }
        _ => false,
    };
    if !valid_shape {
        bail!("session roam operation fields are invalid");
    }
    if let Some(input) = payload.input.as_ref() {
        let object = input
            .as_object()
            .context("session roam input must be an object")?;
        if object.len() != 1 || object.get("data").and_then(Value::as_str).is_none() {
            bail!("deliver-input accepts only input.data");
        }
    }
    Ok(())
}

fn validate_id(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{name} has an invalid format");
    }
    Ok(())
}

fn required_string<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .with_context(|| format!("session roam payload omitted {name}"))
}

fn validate_checkpoint(checkpoint: &Value, driver: &str, generation: u64) -> Result<()> {
    if checkpoint["driver"] != driver
        || checkpoint["generation"].as_u64() != Some(generation)
        || checkpoint["sha256"].as_str().is_none_or(str::is_empty)
        || checkpoint["sizeBytes"].as_u64().is_none()
        || !checkpoint["locator"].is_object()
    {
        bail!("workspace checkpoint evidence is incomplete or mismatched");
    }
    Ok(())
}

fn invoke_workspace(request: &Value, binary: Option<&OsStr>) -> Result<Value> {
    match binary {
        Some(program) => workspace_mobility::invoke_with_binary(request, program),
        None => workspace_mobility::invoke(request),
    }
}

fn ensure_regular_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("session roam workspace {} is unavailable", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("session roam workspace is not a regular directory");
    }
    Ok(())
}

fn ensure_confined_root(coven_home: &Path, path: &Path) -> Result<()> {
    if !path.starts_with(coven_home) {
        bail!("session roam allocation escaped executor home");
    }
    let mut cursor = coven_home.to_path_buf();
    if let Ok(metadata) = fs::symlink_metadata(&cursor) {
        if metadata.file_type().is_symlink() {
            bail!("executor home must not be a symlink");
        }
    }
    if let Ok(relative) = path.strip_prefix(coven_home) {
        for component in relative.components() {
            cursor.push(component);
            match fs::symlink_metadata(&cursor) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    bail!("session roam allocation contains a symlink ancestor")
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
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
                    | "secretaccesskey"
            ) || contains_credential(value)
        }),
        Value::Array(values) => values.iter().any(contains_credential),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common(operation: &str) -> Value {
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "operation": operation,
            "roamId": "roam-1",
            "sessionId": "session-1",
            "placementId": "placement-1",
            "generation": 2,
            "attemptId": "attempt-1",
            "nodeId": "node-1",
        })
    }

    #[test]
    fn operation_validation_rejects_fields_from_another_variant() -> Result<()> {
        let mut value = common("deliver-input");
        value["actorId"] = "actor-1".into();
        value["inputId"] = "input-1".into();
        value["sequence"] = 1.into();
        value["input"] = json!({"data":"hello"});
        let payload: Payload = serde_json::from_value(value.clone())?;
        validate(&payload)?;

        value["workspaceDriver"] = "filesystem".into();
        let payload: Payload = serde_json::from_value(value)?;
        assert!(validate(&payload).is_err());

        let mut extra_input = common("deliver-input");
        extra_input["actorId"] = "actor-1".into();
        extra_input["inputId"] = "input-1".into();
        extra_input["sequence"] = 1.into();
        extra_input["input"] = json!({"data":"hello","unexpected":true});
        let payload: Payload = serde_json::from_value(extra_input)?;
        assert!(validate(&payload).is_err());
        Ok(())
    }
}
