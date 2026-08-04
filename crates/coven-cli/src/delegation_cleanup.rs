//! Node-pinned release after hub integration acknowledgement.

use crate::harness_host;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{fs, path::Path};

pub const PROTOCOL_VERSION: &str = "coven.delegation-cleanup.v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    protocol_version: String,
    delegation_id: String,
    child_id: String,
    actor_id: String,
    generation: u64,
}

pub fn run(coven_home: &Path, value: &Value) -> Result<Value> {
    let request: Request =
        serde_json::from_value(value.clone()).context("invalid delegation cleanup")?;
    if request.protocol_version != PROTOCOL_VERSION || request.generation == 0 {
        bail!("invalid delegation cleanup protocol")
    }
    for value in [&request.delegation_id, &request.child_id, &request.actor_id] {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            bail!("invalid delegation cleanup identity")
        }
    }
    let allocation = coven_home
        .join("delegations")
        .join(&request.delegation_id)
        .join(&request.child_id);
    let actor = harness_host::invoke(
        coven_home,
        &json!({"protocolVersion":harness_host::PROTOCOL_VERSION,"requestId":format!("cleanup-status-{}",request.child_id),"operation":"status","actorId":request.actor_id}),
    );
    if let Ok(actor) = actor {
        if actor["generation"].as_u64() != Some(request.generation) {
            bail!("actor generation conflict")
        }
        harness_host::invoke(
            coven_home,
            &json!({"protocolVersion":harness_host::PROTOCOL_VERSION,"requestId":format!("cleanup-{}",request.child_id),"operation":"stop","actorId":request.actor_id,"generation":request.generation}),
        )?;
    }
    if allocation.exists() {
        fs::remove_dir_all(&allocation)?;
    }
    Ok(
        json!({"protocolVersion":PROTOCOL_VERSION,"delegationId":request.delegation_id,"childId":request.child_id,"released":true}),
    )
}
