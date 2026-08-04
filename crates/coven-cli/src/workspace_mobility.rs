//! Process boundary for the portable `coven.workspace-driver.v1` protocol.

use std::{
    ffi::OsStr,
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "coven.workspace-driver.v1";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Generated dependency and native-build caches are never part of a portable
/// source checkpoint. Drivers add their own secret/VCS exclusions as well.
pub(crate) fn portable_generated_exclusions() -> Vec<&'static str> {
    vec![
        "node_modules",
        "target",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".gradle",
        "DerivedData",
        ".next",
    ]
}

fn binary() -> String {
    std::env::var("COVEN_WORKSPACE_DRIVER_BIN").unwrap_or_else(|_| "coven-roam".into())
}

pub fn invoke(request: &Value) -> Result<Value> {
    invoke_with_binary(request, OsStr::new(&binary()))
}

pub(crate) fn invoke_with_binary(request: &Value, program: &OsStr) -> Result<Value> {
    if request["protocolVersion"] != PROTOCOL_VERSION {
        bail!("workspace payload uses an unsupported protocol version");
    }
    let request_id = request["requestId"]
        .as_str()
        .filter(|value| !value.is_empty())
        .context("workspace payload omitted requestId")?;
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("coven-roam is unavailable; install it or set COVEN_WORKSPACE_DRIVER_BIN")?;
    serde_json::to_writer(
        child
            .stdin
            .as_mut()
            .context("workspace driver stdin unavailable")?,
        request,
    )?;
    child.stdin.as_mut().unwrap().write_all(b"\n")?;
    drop(child.stdin.take());
    let output = child.wait_with_output()?;
    if output.stdout.len() > MAX_RESPONSE_BYTES {
        bail!("workspace driver response exceeded {MAX_RESPONSE_BYTES} bytes");
    }
    let response: Value = serde_json::from_slice(&output.stdout).with_context(|| {
        let stderr = String::from_utf8_lossy(&output.stderr);
        format!("workspace driver returned invalid JSON: {}", stderr.trim())
    })?;
    if response["protocolVersion"] != PROTOCOL_VERSION || response["requestId"] != request_id {
        bail!("workspace driver response did not match its request");
    }
    if !output.status.success() || response["ok"] != true {
        bail!(
            "workspace driver failed: {}",
            response["error"]["message"]
                .as_str()
                .unwrap_or("unknown driver error")
        );
    }
    Ok(response)
}

pub fn probe() -> Vec<String> {
    ["filesystem", "s3-checkpoint"]
        .into_iter()
        .filter(|driver| {
            invoke(&json!({
                "protocolVersion": PROTOCOL_VERSION,
                "requestId": format!("probe-{driver}"),
                "driver": driver,
                "operation": "probe"
            }))
            .is_ok()
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_policy_excludes_cross_platform_generated_caches() {
        let exclusions = portable_generated_exclusions();
        for required in ["node_modules", "target", ".venv", ".gradle", "DerivedData"] {
            assert!(exclusions.contains(&required));
        }
        assert!(!exclusions.contains(&"src"));
    }

    #[cfg(unix)]
    #[test]
    fn invokes_a_protocol_adapter_and_rejects_mismatched_responses() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        let adapter = temp.path().join("adapter");
        std::fs::write(&adapter, "#!/bin/sh\nread body\nprintf '%s\\n' \"$body\"\n")?;
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o700))?;
        let request = json!({"protocolVersion": PROTOCOL_VERSION, "requestId": "r1", "driver": "filesystem", "operation": "release", "ok": true});
        assert_eq!(
            invoke_with_binary(&request, adapter.as_os_str())?["requestId"],
            "r1"
        );
        Ok(())
    }
}
