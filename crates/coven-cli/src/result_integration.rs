//! Hub-owned validation and integration of provisional delegation results.

use std::{collections::BTreeMap, path::Path, process::Command};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const RESULT_PROTOCOL_VERSION: &str = "coven.delegation-result.v1";
const MAX_PATCH_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACTS: usize = 128;
const MAX_MEMORY_PROPOSALS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationResultBundle {
    pub protocol_version: String,
    pub delegation_id: String,
    pub child_id: String,
    pub attempt_id: String,
    pub node_id: String,
    pub base_revision: String,
    pub post_workspace_revision: String,
    pub patch: String,
    pub patch_sha256: String,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEvidence>,
    #[serde(default)]
    pub verification: Vec<VerificationEvidence>,
    #[serde(default)]
    pub memory_proposals: Vec<Value>,
    pub result_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactEvidence {
    pub name: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub platform: PlatformEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlatformEvidence {
    pub os: String,
    pub architecture: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuEvidence>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub runtimes: BTreeMap<String, String>,
    pub placement_observation_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GpuEvidence {
    pub vendor: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationEvidence {
    pub command: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrationPreview {
    pub delegation_id: String,
    pub base_revision: String,
    pub parent_revision: String,
    pub patch_sha256: String,
    pub clean: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<IntegrationConflict>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrationConflict {
    pub code: String,
    pub message: String,
}

pub fn bundle_digest(bundle: &DelegationResultBundle) -> Result<String> {
    let canonical = serde_json::json!({
        "protocolVersion": bundle.protocol_version,
        "delegationId": bundle.delegation_id,
        "childId": bundle.child_id,
        "attemptId": bundle.attempt_id,
        "nodeId": bundle.node_id,
        "baseRevision": bundle.base_revision,
        "postWorkspaceRevision": bundle.post_workspace_revision,
        "patch": bundle.patch,
        "patchSha256": bundle.patch_sha256,
        "artifacts": bundle.artifacts,
        "verification": bundle.verification,
        "memoryProposals": bundle.memory_proposals,
    });
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&canonical)?)))
}

pub fn validate_bundle(bundle: &DelegationResultBundle) -> Result<()> {
    if bundle.protocol_version != RESULT_PROTOCOL_VERSION {
        bail!("delegation result uses an unsupported protocol version");
    }
    for (value, field) in [
        (&bundle.delegation_id, "delegationId"),
        (&bundle.child_id, "childId"),
        (&bundle.attempt_id, "attemptId"),
        (&bundle.node_id, "nodeId"),
        (&bundle.base_revision, "baseRevision"),
        (&bundle.post_workspace_revision, "postWorkspaceRevision"),
    ] {
        if value.is_empty() || value.len() > 256 {
            bail!("{field} is invalid");
        }
    }
    if bundle.patch.len() > MAX_PATCH_BYTES {
        bail!("delegation patch exceeds {MAX_PATCH_BYTES} bytes");
    }
    let patch_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(bundle.patch.as_bytes()));
    if patch_digest != bundle.patch_sha256 {
        bail!("delegation patch digest mismatch");
    }
    if bundle.artifacts.len() > MAX_ARTIFACTS
        || bundle.memory_proposals.len() > MAX_MEMORY_PROPOSALS
    {
        bail!("delegation result exceeds evidence limits");
    }
    if bundle.artifacts.iter().any(|artifact| {
        artifact.name.is_empty()
            || artifact.name.len() > 256
            || artifact.size_bytes > 1024 * 1024 * 1024
            || !is_content_sha256(&artifact.sha256)
            || validate_platform_evidence(&artifact.platform).is_err()
    }) {
        bail!("delegation artifact evidence is invalid");
    }
    if bundle.verification.is_empty()
        || bundle
            .verification
            .iter()
            .any(|item| item.status != "passed")
    {
        bail!("delegation verification did not pass");
    }
    if bundle_digest(bundle)? != bundle.result_digest {
        bail!("delegation result digest mismatch");
    }
    Ok(())
}

pub fn validate_platform_evidence(platform: &PlatformEvidence) -> Result<()> {
    if !matches!(platform.os.as_str(), "linux" | "macos" | "windows") {
        bail!("platform OS is not canonical");
    }
    if !matches!(platform.architecture.as_str(), "x86_64" | "aarch64") {
        bail!("platform architecture is not canonical");
    }
    if !is_sha256_digest(&platform.placement_observation_digest) {
        bail!("placement observation digest is invalid");
    }
    if platform
        .platform_version
        .as_deref()
        .is_some_and(|value| !is_bounded_fact(value, 128))
    {
        bail!("platform version is invalid");
    }
    if let Some(gpu) = &platform.gpu {
        if !is_bounded_identifier(&gpu.vendor, 64)
            || !is_bounded_fact(&gpu.model, 128)
            || gpu
                .driver_version
                .as_deref()
                .is_some_and(|value| !is_bounded_fact(value, 64))
        {
            bail!("GPU evidence is invalid");
        }
    }
    if platform.runtimes.len() > 32
        || platform.runtimes.iter().any(|(name, version)| {
            !is_bounded_identifier(name, 64) || !is_bounded_fact(version, 128)
        })
    {
        bail!("runtime evidence is invalid");
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_content_sha256(value: &str) -> bool {
    is_sha256_digest(value)
        || (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn is_bounded_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn is_bounded_fact(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.chars().all(|character| !character.is_control())
}

pub fn preview(repo: &Path, bundle: &DelegationResultBundle) -> Result<IntegrationPreview> {
    validate_bundle(bundle)?;
    let parent_revision = git_stdout(repo, &["rev-parse", "HEAD"])?;
    if parent_revision != bundle.base_revision {
        return Ok(conflict_preview(
            bundle,
            parent_revision,
            "diverged_parent",
            "Parent revision changed after delegation started.",
        ));
    }
    if !git_stdout(repo, &["status", "--porcelain"])?.is_empty() {
        return Ok(conflict_preview(
            bundle,
            parent_revision,
            "dirty_parent",
            "Parent workspace has uncommitted changes.",
        ));
    }
    let checked = git_with_stdin(
        repo,
        &["apply", "--check", "--whitespace=error-all", "-"],
        bundle.patch.as_bytes(),
    )?;
    if !checked.status.success() {
        return Ok(conflict_preview(
            bundle,
            parent_revision,
            "patch_conflict",
            &bounded_stderr(&checked.stderr),
        ));
    }
    Ok(IntegrationPreview {
        delegation_id: bundle.delegation_id.clone(),
        base_revision: bundle.base_revision.clone(),
        parent_revision,
        patch_sha256: bundle.patch_sha256.clone(),
        clean: true,
        conflict: None,
    })
}

pub fn apply(
    repo: &Path,
    bundle: &DelegationResultBundle,
    expected_parent_revision: &str,
) -> Result<()> {
    let preview = preview(repo, bundle)?;
    if !preview.clean {
        bail!("delegation result is no longer cleanly applicable");
    }
    if preview.parent_revision != expected_parent_revision {
        bail!("parent revision changed after integration preview");
    }
    let output = git_with_stdin(
        repo,
        &["apply", "--whitespace=error-all", "-"],
        bundle.patch.as_bytes(),
    )?;
    if !output.status.success() {
        bail!("git apply failed: {}", bounded_stderr(&output.stderr));
    }
    Ok(())
}

pub fn patch_is_applied(repo: &Path, bundle: &DelegationResultBundle) -> Result<bool> {
    validate_bundle(bundle)?;
    if git_stdout(repo, &["rev-parse", "HEAD"])? != bundle.base_revision {
        return Ok(false);
    }
    let output = git_with_stdin(
        repo,
        &["apply", "--reverse", "--check", "-"],
        bundle.patch.as_bytes(),
    )?;
    Ok(output.status.success())
}

fn conflict_preview(
    bundle: &DelegationResultBundle,
    parent_revision: String,
    code: &str,
    message: &str,
) -> IntegrationPreview {
    IntegrationPreview {
        delegation_id: bundle.delegation_id.clone(),
        base_revision: bundle.base_revision.clone(),
        parent_revision,
        patch_sha256: bundle.patch_sha256.clone(),
        clean: false,
        conflict: Some(IntegrationConflict {
            code: code.into(),
            message: message.into(),
        }),
    }
}

fn git_stdout(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").args(args).current_dir(repo).output()?;
    if !output.status.success() {
        bail!("git command failed: {}", bounded_stderr(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn git_with_stdin(repo: &Path, args: &[&str], stdin: &[u8]) -> Result<std::process::Output> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("git")
        .args(args)
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .context("git stdin unavailable")?
        .write_all(stdin)?;
    drop(child.stdin.take());
    Ok(child.wait_with_output()?)
}

fn bounded_stderr(stderr: &[u8]) -> String {
    String::from_utf8_lossy(&stderr[..stderr.len().min(4096)])
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn git(repo: &Path, args: &[&str]) -> Result<String> {
        git_stdout(repo, args)
    }

    fn git_raw(repo: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git").args(args).current_dir(repo).output()?;
        if !output.status.success() {
            bail!(
                "git test command failed: {}",
                bounded_stderr(&output.stderr)
            );
        }
        Ok(String::from_utf8(output.stdout)?)
    }

    fn fixture() -> Result<(tempfile::TempDir, DelegationResultBundle)> {
        let temp = tempfile::tempdir()?;
        git(temp.path(), &["init", "-q"])?;
        git(
            temp.path(),
            &["config", "user.email", "test@example.invalid"],
        )?;
        git(temp.path(), &["config", "user.name", "Test"])?;
        fs::write(temp.path().join("work.txt"), "before\n")?;
        git(temp.path(), &["add", "work.txt"])?;
        git(temp.path(), &["commit", "-qm", "base"])?;
        let base = git(temp.path(), &["rev-parse", "HEAD"])?;
        fs::write(temp.path().join("work.txt"), "after\n")?;
        let patch = git_raw(temp.path(), &["diff", "--binary", "--full-index"])?;
        git(temp.path(), &["checkout", "--", "work.txt"])?;
        let patch_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(patch.as_bytes()));
        let mut bundle = DelegationResultBundle {
            protocol_version: RESULT_PROTOCOL_VERSION.into(),
            delegation_id: "delegation-1".into(),
            child_id: "child-1".into(),
            attempt_id: "attempt-1".into(),
            node_id: "node-1".into(),
            base_revision: base,
            post_workspace_revision: "child-tree-1".into(),
            patch,
            patch_sha256,
            artifacts: vec![],
            verification: vec![VerificationEvidence {
                command: "test".into(),
                status: "passed".into(),
            }],
            memory_proposals: vec![serde_json::json!({"text": "proposal only"})],
            result_digest: String::new(),
        };
        bundle.result_digest = bundle_digest(&bundle)?;
        Ok((temp, bundle))
    }

    #[test]
    fn previews_and_applies_only_against_the_exact_base() -> Result<()> {
        let (temp, bundle) = fixture()?;
        let preview = preview(temp.path(), &bundle)?;
        assert!(preview.clean, "{:?}", preview.conflict);
        apply(temp.path(), &bundle, &preview.parent_revision)?;
        assert_eq!(fs::read_to_string(temp.path().join("work.txt"))?, "after\n");
        Ok(())
    }

    #[test]
    fn divergence_is_explicit_and_does_not_mutate_parent() -> Result<()> {
        let (temp, bundle) = fixture()?;
        fs::write(temp.path().join("parent.txt"), "parent\n")?;
        git(temp.path(), &["add", "parent.txt"])?;
        git(temp.path(), &["commit", "-qm", "parent advanced"])?;
        let preview = preview(temp.path(), &bundle)?;
        assert!(!preview.clean);
        assert_eq!(preview.conflict.unwrap().code, "diverged_parent");
        assert_eq!(
            fs::read_to_string(temp.path().join("work.txt"))?,
            "before\n"
        );
        Ok(())
    }

    #[test]
    fn apply_cas_rejects_parent_advance_after_clean_preview() -> Result<()> {
        let (temp, bundle) = fixture()?;
        let preview = preview(temp.path(), &bundle)?;
        assert!(preview.clean);
        fs::write(temp.path().join("parent.txt"), "parent\n")?;
        git(temp.path(), &["add", "parent.txt"])?;
        git(
            temp.path(),
            &["commit", "-qm", "parent advanced after preview"],
        )?;
        assert!(apply(temp.path(), &bundle, &preview.parent_revision).is_err());
        assert_eq!(
            fs::read_to_string(temp.path().join("work.txt"))?,
            "before\n"
        );
        Ok(())
    }

    #[test]
    fn rejects_tampered_patch_or_failed_verification() -> Result<()> {
        let (_, mut bundle) = fixture()?;
        bundle.patch.push_str("tampered");
        assert!(validate_bundle(&bundle).is_err());
        let (_, mut bundle) = fixture()?;
        bundle.verification[0].status = "failed".into();
        bundle.result_digest = bundle_digest(&bundle)?;
        assert!(validate_bundle(&bundle).is_err());
        Ok(())
    }

    #[test]
    fn platform_evidence_is_canonical_and_bound_into_result_digest() -> Result<()> {
        let (_, mut bundle) = fixture()?;
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(b"placement-observation"));
        bundle.artifacts.push(ArtifactEvidence {
            name: "workspace-checkpoint".into(),
            sha256: URL_SAFE_NO_PAD.encode(Sha256::digest(b"artifact")),
            size_bytes: 8,
            platform: PlatformEvidence {
                os: "linux".into(),
                architecture: "x86_64".into(),
                platform_version: Some("6.8.0".into()),
                gpu: Some(GpuEvidence {
                    vendor: "nvidia".into(),
                    model: "L4".into(),
                    driver_version: Some("550.54".into()),
                }),
                runtimes: BTreeMap::from([("cuda".into(), "12.4".into())]),
                placement_observation_digest: digest,
            },
        });
        bundle.result_digest = bundle_digest(&bundle)?;
        validate_bundle(&bundle)?;

        bundle.artifacts[0].platform.architecture = "arm64".into();
        assert!(validate_bundle(&bundle).is_err());
        bundle.artifacts[0].platform.architecture = "aarch64".into();
        assert!(
            validate_bundle(&bundle).is_err(),
            "platform mutation must invalidate digest"
        );

        bundle.result_digest = bundle_digest(&bundle)?;
        validate_bundle(&bundle)?;
        bundle.artifacts[0].platform.placement_observation_digest = "not-a-digest".into();
        bundle.result_digest = bundle_digest(&bundle)?;
        assert!(validate_bundle(&bundle).is_err());
        Ok(())
    }
}
