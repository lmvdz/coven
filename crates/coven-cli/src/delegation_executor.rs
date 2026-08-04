//! Executor-owned composite runner for `coven.delegation.v1`.

use crate::{
    delegation,
    fleet_executor::AttemptCancellation,
    harness_host,
    result_integration::{
        self, ArtifactEvidence, DelegationResultBundle, PlatformEvidence, VerificationEvidence,
    },
    workspace_mobility,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    protocol_version: String,
    delegation_id: String,
    child_id: String,
    attempt_id: String,
    node_id: String,
    base_revision: String,
    task: String,
    harness: String,
    actor_id: String,
    generation: u64,
    workspace_driver: String,
    base_checkpoint: Value,
    result_locator: Value,
    #[serde(default)]
    placement_observation_digest: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FakeTask {
    #[serde(default)]
    write_files: Vec<FakeWrite>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FakeWrite {
    path: String,
    content: String,
}

pub fn run(
    coven_home: &Path,
    value: &Value,
    workspace_binary: Option<&OsStr>,
    cancellation: &AttemptCancellation,
) -> Result<Value> {
    cancellation.check()?;
    let p: Payload = serde_json::from_value(value.clone()).context("invalid delegation payload")?;
    validate(&p)?;
    let allocation = coven_home
        .join("delegations")
        .join(&p.delegation_id)
        .join(&p.child_id);
    let attempt_root = allocation.join("attempts").join(&p.attempt_id);
    let workspace = attempt_root.join("workspace");
    let result_path = attempt_root.join("result.json");
    fs::create_dir_all(&attempt_root)?;
    let payload_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(value)?));
    let payload_digest_path = attempt_root.join("payload.sha256");
    match fs::read_to_string(&payload_digest_path) {
        Ok(stored) if stored != payload_digest => {
            bail!("delegation replay changed immutable payload")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::write(&payload_digest_path, &payload_digest)?
        }
        Err(error) => return Err(error.into()),
    }
    if let Ok(bytes) = fs::read(&result_path) {
        cancellation.check()?;
        return serde_json::from_slice(&bytes).context("stored delegation result invalid");
    }
    if workspace.exists() {
        fs::remove_dir_all(&workspace)?;
    }
    invoke_workspace(
        &json!({"protocolVersion":workspace_mobility::PROTOCOL_VERSION,"requestId":format!("restore-{}",p.child_id),
        "driver":p.workspace_driver,"operation":"restore","destinationPath":workspace,"generation":1,"checkpoint":p.base_checkpoint}),
        workspace_binary,
    )?;
    cancellation.check()?;
    git(&workspace, &["init", "-q"])?;
    git(
        &workspace,
        &["config", "user.email", "delegation@example.invalid"],
    )?;
    git(&workspace, &["config", "user.name", "Coven Delegation"])?;
    git(&workspace, &["add", "-A"])?;
    git(&workspace, &["commit", "-qm", "delegation base"])?;
    harness_host::invoke(
        coven_home,
        &json!({"protocolVersion":harness_host::PROTOCOL_VERSION,"requestId":format!("start-{}",p.child_id),
        "operation":"start","actorId":p.actor_id,"harness":p.harness,"generation":p.generation}),
    )?;
    check_or_stop(coven_home, &p, cancellation)?;
    harness_host::invoke(
        coven_home,
        &json!({"protocolVersion":harness_host::PROTOCOL_VERSION,"requestId":format!("send-{}",p.child_id),
        "operation":"send","actorId":p.actor_id,"generation":p.generation,
        "idempotencyKey":format!("input-{}",p.child_id),"input":p.task}),
    )?;
    check_or_stop(coven_home, &p, cancellation)?;
    let task: FakeTask =
        serde_json::from_str(&p.task).context("fake delegation task must be JSON")?;
    if task.write_files.len() > 256 {
        bail!("fake delegation task exceeds file limit")
    }
    for write in task.write_files {
        check_or_stop(coven_home, &p, cancellation)?;
        if write.content.len() > 1024 * 1024 {
            bail!("delegation content exceeds 1 MiB")
        };
        let target = workspace.join(confined_relative(&write.path)?);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?
        }
        ensure_no_symlink_ancestors(&workspace, &target)?;
        fs::write(target, write.content)?;
    }
    git(&workspace, &["add", "-N", "-A"])?;
    let verified = git_output(&workspace, &["diff", "--check"])?;
    if !verified.status.success() {
        bail!("delegation verification failed")
    }
    let patch =
        String::from_utf8(git_output(&workspace, &["diff", "--binary", "--full-index"])?.stdout)?;
    let patch_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(patch.as_bytes()));
    check_or_stop(coven_home, &p, cancellation)?;
    let checkpoint = invoke_workspace(
        &json!({"protocolVersion":workspace_mobility::PROTOCOL_VERSION,"requestId":format!("checkpoint-{}",p.child_id),
        "driver":p.workspace_driver,"operation":"checkpoint","workspacePath":workspace,"generation":1,"locator":p.result_locator,
        "excludePaths":workspace_mobility::portable_generated_exclusions()}),
        workspace_binary,
    )?;
    check_or_stop(coven_home, &p, cancellation)?;
    let reference = &checkpoint["checkpoint"];
    let sha = reference["sha256"]
        .as_str()
        .context("checkpoint omitted sha256")?;
    let mut bundle = DelegationResultBundle {
        protocol_version: result_integration::RESULT_PROTOCOL_VERSION.into(),
        delegation_id: p.delegation_id.clone(),
        child_id: p.child_id.clone(),
        attempt_id: p.attempt_id.clone(),
        node_id: p.node_id.clone(),
        base_revision: p.base_revision.clone(),
        post_workspace_revision: sha.into(),
        patch,
        patch_sha256,
        artifacts: vec![ArtifactEvidence {
            name: "workspace-checkpoint".into(),
            sha256: sha.into(),
            size_bytes: reference["sizeBytes"]
                .as_u64()
                .context("checkpoint omitted size")?,
            platform: PlatformEvidence {
                os: std::env::consts::OS.into(),
                architecture: std::env::consts::ARCH.into(),
                platform_version: None,
                gpu: None,
                runtimes: Default::default(),
                placement_observation_digest: placement_observation_digest(&p),
            },
        }],
        verification: vec![VerificationEvidence {
            command: "git diff --check".into(),
            status: "passed".into(),
        }],
        memory_proposals: vec![],
        result_digest: String::new(),
    };
    bundle.result_digest = result_integration::bundle_digest(&bundle)?;
    let result = serde_json::to_value(bundle)?;
    check_or_stop(coven_home, &p, cancellation)?;
    let temporary_result = attempt_root.join(format!(".result-{}.tmp", std::process::id()));
    fs::write(&temporary_result, serde_json::to_vec(&result)?)?;
    if let Err(error) = cancellation.check() {
        let _ = fs::remove_file(&temporary_result);
        let _ = stop_actor(coven_home, &p);
        return Err(error);
    }
    fs::rename(temporary_result, result_path)?;
    Ok(result)
}

fn check_or_stop(
    coven_home: &Path,
    payload: &Payload,
    cancellation: &AttemptCancellation,
) -> Result<()> {
    if let Err(error) = cancellation.check() {
        let _ = stop_actor(coven_home, payload);
        return Err(error);
    }
    Ok(())
}

fn stop_actor(coven_home: &Path, payload: &Payload) -> Result<Value> {
    harness_host::invoke(
        coven_home,
        &json!({"protocolVersion":harness_host::PROTOCOL_VERSION,"requestId":format!("cancel-stop-{}",payload.child_id),
        "operation":"stop","actorId":payload.actor_id,"generation":payload.generation}),
    )
}
fn invoke_workspace(r: &Value, b: Option<&OsStr>) -> Result<Value> {
    match b {
        Some(p) => workspace_mobility::invoke_with_binary(r, p),
        None => workspace_mobility::invoke(r),
    }
}
fn validate(p: &Payload) -> Result<()> {
    if p.protocol_version != delegation::PROTOCOL_VERSION {
        bail!("unsupported delegation protocol")
    };
    for (v, n) in [
        (&p.delegation_id, "delegationId"),
        (&p.child_id, "childId"),
        (&p.actor_id, "actorId"),
    ] {
        if v.is_empty()
            || v.len() > 128
            || !v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            bail!("{n} invalid")
        }
    }
    if p.generation == 0 || p.harness != "fake" {
        bail!("invalid harness generation")
    }
    let platform = PlatformEvidence {
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        platform_version: None,
        gpu: None,
        runtimes: Default::default(),
        placement_observation_digest: placement_observation_digest(p),
    };
    result_integration::validate_platform_evidence(&platform)?;
    Ok(())
}

fn placement_observation_digest(payload: &Payload) -> String {
    payload
        .placement_observation_digest
        .clone()
        .unwrap_or_else(|| {
            // Compatibility for delegation producers predating placement claims. The
            // domain separation makes this distinguishable from an observed claim.
            URL_SAFE_NO_PAD.encode(Sha256::digest(format!(
                "coven.legacy-unbound-placement.v1\n{}\n{}",
                payload.node_id, payload.attempt_id
            )))
        })
}
fn confined_relative(v: &str) -> Result<PathBuf> {
    let p = Path::new(v);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        bail!("delegation path escapes child root")
    }
    Ok(p.into())
}
fn ensure_no_symlink_ancestors(root: &Path, target: &Path) -> Result<()> {
    let mut c = root.to_path_buf();
    for part in target.strip_prefix(root)?.components() {
        c.push(part);
        if c.exists() && fs::symlink_metadata(&c)?.file_type().is_symlink() {
            bail!("delegation path crosses symlink")
        }
    }
    Ok(())
}
fn git(repo: &Path, args: &[&str]) -> Result<()> {
    let o = git_output(repo, args)?;
    if !o.status.success() {
        bail!("git failed: {}", String::from_utf8_lossy(&o.stderr).trim())
    }
    Ok(())
}
fn git_output(repo: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new("git").args(args).current_dir(repo).output()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(observation_digest: &str) -> Payload {
        Payload {
            protocol_version: delegation::PROTOCOL_VERSION.into(),
            delegation_id: "delegation-1".into(),
            child_id: "child-1".into(),
            attempt_id: "attempt-1".into(),
            node_id: "node-1".into(),
            base_revision: "base-1".into(),
            task: "{}".into(),
            harness: "fake".into(),
            actor_id: "actor-1".into(),
            generation: 1,
            workspace_driver: "filesystem".into(),
            base_checkpoint: json!({}),
            result_locator: json!({}),
            placement_observation_digest: Some(observation_digest.into()),
        }
    }

    #[test]
    fn requires_a_canonical_placement_observation_digest() {
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(b"placement-observation"));
        assert!(validate(&payload(&digest)).is_ok());
        assert!(validate(&payload("not-a-digest")).is_err());
    }

    #[test]
    fn legacy_payload_gets_a_deterministic_unbound_compatibility_digest() {
        let value = json!({
            "protocolVersion": delegation::PROTOCOL_VERSION,
            "delegationId": "delegation-1",
            "childId": "child-1",
            "attemptId": "attempt-1",
            "nodeId": "node-1",
            "baseRevision": "base-1",
            "task": "{}",
            "harness": "fake",
            "actorId": "actor-1",
            "generation": 1,
            "workspaceDriver": "filesystem",
            "baseCheckpoint": {},
            "resultLocator": {}
        });
        let payload: Payload = serde_json::from_value(value).unwrap();
        assert!(validate(&payload).is_ok());
        let first = placement_observation_digest(&payload);
        assert_eq!(first, placement_observation_digest(&payload));
        assert_eq!(first.len(), 43);
    }
}
