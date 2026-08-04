//! Black-box contract coverage for executor-local delegation cleanup.
//!
//! The cleanup runner is compiled here against a deliberately small Harness
//! Host double so its filesystem and protocol behavior can be tested without
//! widening production module visibility.

use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

mod harness_host {
    use super::*;

    pub const PROTOCOL_VERSION: &str = "coven.harness-host.v1";
    const STATE_FILE: &str = "test-harness-actor.json";

    pub fn seed(coven_home: &Path, actor_id: &str, generation: u64) -> Result<()> {
        fs::create_dir_all(coven_home)?;
        fs::write(
            coven_home.join(STATE_FILE),
            serde_json::to_vec(&json!({
                "actorId": actor_id,
                "generation": generation,
                "state": "ready",
                "stopTransitions": 0,
            }))?,
        )?;
        Ok(())
    }

    pub fn state(coven_home: &Path) -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(
            coven_home.join(STATE_FILE),
        )?)?)
    }

    pub fn invoke(coven_home: &Path, request: &Value) -> Result<Value> {
        let mut actor = state(coven_home).context("harness actor was not found")?;
        if request["actorId"] != actor["actorId"] {
            bail!("harness actor was not found");
        }
        match request["operation"].as_str() {
            Some("status") => Ok(actor),
            Some("stop") => {
                if request["generation"] != actor["generation"] {
                    bail!("actor generation conflict");
                }
                if actor["state"] != "stopped" {
                    actor["state"] = "stopped".into();
                    actor["stopTransitions"] =
                        (actor["stopTransitions"].as_u64().unwrap_or(0) + 1).into();
                    fs::write(coven_home.join(STATE_FILE), serde_json::to_vec(&actor)?)?;
                }
                Ok(actor)
            }
            _ => bail!("unsupported harness operation"),
        }
    }
}

#[path = "../src/delegation_cleanup.rs"]
mod delegation_cleanup;

fn request(generation: u64) -> Value {
    json!({
        "protocolVersion": delegation_cleanup::PROTOCOL_VERSION,
        "delegationId": "delegation-1",
        "childId": "child-1",
        "actorId": "actor-child-1",
        "generation": generation,
    })
}

fn allocation(coven_home: &Path) -> std::path::PathBuf {
    coven_home
        .join("delegations")
        .join("delegation-1")
        .join("child-1")
}

#[test]
fn cleanup_replay_stops_once_and_releases_the_child_allocation() -> Result<()> {
    let home = tempfile::tempdir()?;
    harness_host::seed(home.path(), "actor-child-1", 7)?;
    fs::create_dir_all(allocation(home.path()).join("workspace"))?;
    fs::write(allocation(home.path()).join("result.json"), b"retained")?;

    let first = delegation_cleanup::run(home.path(), &request(7))?;
    assert_eq!(first["released"], true);
    assert!(!allocation(home.path()).exists());
    assert_eq!(harness_host::state(home.path())?["state"], "stopped");
    assert_eq!(
        harness_host::state(home.path())?["stopTransitions"],
        1,
        "cleanup must perform only one actor state transition"
    );

    let replay = delegation_cleanup::run(home.path(), &request(7))?;
    assert_eq!(replay, first);
    assert_eq!(harness_host::state(home.path())?["stopTransitions"], 1);
    Ok(())
}

#[test]
fn generation_mismatch_retains_actor_and_workspace() -> Result<()> {
    let home = tempfile::tempdir()?;
    harness_host::seed(home.path(), "actor-child-1", 8)?;
    fs::create_dir_all(allocation(home.path()).join("workspace"))?;

    let error = delegation_cleanup::run(home.path(), &request(7))
        .expect_err("a stale cleanup generation must be fenced");
    assert!(error.to_string().contains("actor generation conflict"));
    assert!(allocation(home.path()).exists());
    assert_eq!(harness_host::state(home.path())?["state"], "ready");
    assert_eq!(harness_host::state(home.path())?["stopTransitions"], 0);
    Ok(())
}
