//! Hub-owned orchestration for automatic generation-fenced session roam.

use crate::{
    api::current_timestamp,
    fleet,
    session_authority::{self, PlacementLease, RoamAdvance, RoamRecord, RoamState},
    session_roam_executor, store, STORE_FILE_NAME,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug)]
struct Saga {
    saga_id: String,
    session_id: String,
    generation: u64,
    state: String,
    source_placement_id: String,
    source_node_id: String,
    source_generation: u64,
    target_placement_id: String,
    target_node_id: String,
    actor_id: String,
    workspace_driver: String,
    target_harness: String,
    checkpoint_job_id: String,
    prepare_job_id: String,
    input_job_id: Option<String>,
    input_id: Option<String>,
}

pub fn start(
    coven_home: &Path,
    record: RoamRecord,
    next_action: Option<&str>,
) -> Result<RoamRecord> {
    let mut conn = store::open_store(&coven_home.join(STORE_FILE_NAME))?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record = session_authority::begin_roam_transfer_tx(&tx, coven_home, record, next_action)?;
    let generation_db = i64::try_from(record.generation)?;
    let row: (String, i64, String, String, String) = tx.query_row(
        "SELECT source.placement_id,source.generation,target.placement_id,target.node_id,target.actor_id
         FROM session_lifecycles lifecycle
         JOIN session_placements source ON source.placement_id=lifecycle.active_placement_id
         JOIN session_placements target ON target.placement_id=lifecycle.pending_placement_id
         WHERE lifecycle.session_id=?1 AND lifecycle.pending_generation=?2
         AND source.node_id=?3 AND source.state='active' AND target.state='starting'",
        params![record.session_id, generation_db, record.source_node_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
    ).context("roam requires an authoritative active source placement")?;
    let source_generation = u64::try_from(row.1)?;
    let saga_id = stable_id(
        "roam",
        &[&record.session_id, &record.generation.to_string()],
    );
    let checkpoint_job_id = stable_id("roamchk", &[&saga_id]);
    let prepare_job_id = stable_id("roamprep", &[&saga_id]);
    let checkpoint_payload = json!({
        "protocolVersion": session_roam_executor::PROTOCOL_VERSION,
        "operation": "checkpoint-source", "roamId": saga_id,
        "sessionId": record.session_id, "placementId": row.0,
        "generation": source_generation, "attemptId": "pending",
        "nodeId": record.source_node_id, "workspaceDriver": record.workspace.driver,
        "checkpointLocator": record.workspace.locator,
    });
    let required = vec![
        format!("workspace:{}", record.workspace.driver),
        "protocol:workspace-driver:1".into(),
    ];
    fleet::submit_job_on_connection(
        &tx,
        &checkpoint_job_id,
        &checkpoint_payload,
        &required,
        Some(&record.source_node_id),
    )?;
    let request_digest = digest_value(
        &json!({"record":record,"sourcePlacementId":row.0,"targetPlacementId":row.2}),
    )?;
    let now = current_timestamp();
    tx.execute(
        "INSERT INTO session_roam_sagas
         (saga_id,session_id,generation,request_digest,state,source_placement_id,source_node_id,
          source_generation,target_placement_id,target_node_id,actor_id,workspace_driver,
          checkpoint_locator_json,target_harness,checkpoint_job_id,prepare_job_id,created_at,updated_at)
         VALUES (?1,?2,?3,?4,'checkpoint_queued',?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16)",
        params![saga_id,record.session_id,generation_db,request_digest,row.0,record.source_node_id,row.1,row.2,row.3,row.4,
            record.workspace.driver,serde_json::to_string(&record.workspace.locator)?,record.target_harness,
            checkpoint_job_id,prepare_job_id,now],
    )?;
    let record = session_authority::bind_roam_dispatch_tx(
        &tx,
        &record.session_id,
        record.generation,
        RoamState::Preparing,
        &checkpoint_job_id,
    )?;
    tx.commit()?;
    Ok(record)
}

pub fn reconcile_for_job(coven_home: &Path, job_id: &str) -> Result<()> {
    let conn = store::open_store(&coven_home.join(STORE_FILE_NAME))?;
    let session_id: Option<String> = conn.query_row(
        "SELECT session_id FROM session_roam_sagas WHERE checkpoint_job_id=?1 OR prepare_job_id=?1 OR input_job_id=?1",
        params![job_id], |row| row.get(0)).optional()?;
    drop(conn);
    if let Some(session_id) = session_id {
        reconcile_session(coven_home, &session_id)?;
    }
    Ok(())
}

pub fn reconcile_all(coven_home: &Path) -> Result<()> {
    let conn = store::open_store(&coven_home.join(STORE_FILE_NAME))?;
    let mut statement = conn.prepare("SELECT DISTINCT session_id FROM session_roam_sagas WHERE state IN ('checkpoint_queued','prepare_queued','active')")?;
    let sessions = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    drop(conn);
    for session in sessions {
        reconcile_session(coven_home, &session)?;
    }
    Ok(())
}

pub fn reconcile_session(coven_home: &Path, session_id: &str) -> Result<()> {
    loop {
        let mut conn = store::open_store(&coven_home.join(STORE_FILE_NAME))?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(saga) = load_saga(&tx, session_id)? else {
            tx.commit()?;
            return Ok(());
        };
        let progressed = match saga.state.as_str() {
            "checkpoint_queued" => reconcile_checkpoint(&tx, &saga)?,
            "prepare_queued" => reconcile_prepare(&tx, &saga)?,
            "active" => reconcile_input(&tx, coven_home, &saga)?,
            _ => false,
        };
        tx.commit()?;
        if !progressed {
            return Ok(());
        }
    }
}

fn reconcile_checkpoint(tx: &Transaction<'_>, saga: &Saga) -> Result<bool> {
    if let Some(failed) = fleet::failed_job_on_connection(tx, &saga.checkpoint_job_id)? {
        return compensate_failure(tx, saga, &failed, true);
    }
    let Some(completed) = fleet::completed_job_on_connection(tx, &saga.checkpoint_job_id)? else {
        return Ok(false);
    };
    validate_result(&completed, saga, "checkpoint-source", true)?;
    let checkpoint = completed.result["evidence"]["checkpoint"].clone();
    validate_checkpoint(&checkpoint, &saga.workspace_driver, saga.source_generation)?;
    let prepare_payload = json!({
        "protocolVersion":session_roam_executor::PROTOCOL_VERSION,"operation":"prepare-target",
        "roamId":saga.saga_id,"sessionId":saga.session_id,"placementId":saga.target_placement_id,
        "generation":saga.generation,"attemptId":"pending","nodeId":saga.target_node_id,
        "workspaceDriver":saga.workspace_driver,"checkpoint":checkpoint,"harness":saga.target_harness,"actorId":saga.actor_id,
    });
    let required = vec![
        format!("workspace:{}", saga.workspace_driver),
        "protocol:workspace-driver:1".into(),
        format!("runtime:{}", saga.target_harness),
        "protocol:harness-host:1".into(),
    ];
    fleet::submit_job_on_connection(
        tx,
        &saga.prepare_job_id,
        &prepare_payload,
        &required,
        Some(&saga.target_node_id),
    )?;
    session_authority::advance_roam_tx(
        tx,
        &saga.session_id,
        RoamAdvance {
            generation: saga.generation,
            node_id: saga.source_node_id.clone(),
            state: RoamState::Checkpointed,
            checkpoint_ref: Some(checkpoint.clone()),
            dispatch_job_id: Some(saga.prepare_job_id.clone()),
            error: None,
        },
    )?;
    if tx.execute("UPDATE session_roam_sagas SET state='prepare_queued',checkpoint_json=?2,updated_at=?3 WHERE saga_id=?1 AND state='checkpoint_queued'",
        params![saga.saga_id,serde_json::to_string(&checkpoint)?,current_timestamp()])? != 1 { bail!("checkpoint reconciliation lost saga authority"); }
    Ok(true)
}

fn reconcile_prepare(tx: &Transaction<'_>, saga: &Saga) -> Result<bool> {
    if let Some(failed) = fleet::failed_job_on_connection(tx, &saga.prepare_job_id)? {
        return compensate_failure(tx, saga, &failed, false);
    }
    let Some(completed) = fleet::completed_job_on_connection(tx, &saga.prepare_job_id)? else {
        return Ok(false);
    };
    validate_result(&completed, saga, "prepare-target", false)?;
    let actor = &completed.result["evidence"]["actor"];
    if actor["actorId"] != saga.actor_id
        || actor["generation"].as_u64() != Some(saga.generation)
        || actor["state"] != "ready"
        || actor["ready"] != true
    {
        bail!("target readiness evidence did not match the reserved placement");
    }
    for state in [RoamState::Restoring, RoamState::Starting, RoamState::Active] {
        session_authority::advance_roam_tx(
            tx,
            &saga.session_id,
            RoamAdvance {
                generation: saga.generation,
                node_id: saga.target_node_id.clone(),
                state,
                checkpoint_ref: None,
                dispatch_job_id: Some(saga.prepare_job_id.clone()),
                error: None,
            },
        )?;
    }
    if tx.execute("UPDATE session_roam_sagas SET state='active',updated_at=?2 WHERE saga_id=?1 AND state='prepare_queued'",
        params![saga.saga_id,current_timestamp()])? != 1 { bail!("target activation lost saga authority"); }
    schedule_next_input(tx, saga)?;
    Ok(true)
}

fn compensate_failure(
    tx: &Transaction<'_>,
    saga: &Saga,
    failed: &fleet::FailedFleetJob,
    source: bool,
) -> Result<bool> {
    let expected_node = if source {
        &saga.source_node_id
    } else {
        &saga.target_node_id
    };
    if failed.node_id != *expected_node
        || failed.failure.protocol_version != fleet::FAILURE_PROTOCOL_VERSION
        || failed.failure.code.is_empty()
        || failed.failure.message.is_empty()
    {
        bail!("fleet failure did not match session roam authority");
    }
    let evidence = serde_json::to_value(&failed.failure)?;
    session_authority::advance_roam_tx(
        tx,
        &saga.session_id,
        RoamAdvance {
            generation: saga.generation,
            node_id: expected_node.clone(),
            state: RoamState::Failed,
            checkpoint_ref: None,
            dispatch_job_id: None,
            error: Some(failed.failure.message.clone()),
        },
    )?;
    if tx.execute(
        "UPDATE session_roam_sagas SET state='failed',error_json=?2,updated_at=?3
         WHERE saga_id=?1 AND state IN ('checkpoint_queued','prepare_queued')",
        params![
            saga.saga_id,
            serde_json::to_string(&evidence)?,
            current_timestamp()
        ],
    )? != 1
    {
        bail!("fleet failure compensation lost saga authority");
    }
    Ok(true)
}

fn reconcile_input(tx: &Transaction<'_>, coven_home: &Path, saga: &Saga) -> Result<bool> {
    let Some(job_id) = saga.input_job_id.as_deref() else {
        return schedule_next_input(tx, saga);
    };
    if let Some(failed) = fleet::failed_job_on_connection(tx, job_id)? {
        if failed.node_id != saga.target_node_id
            || failed.failure.protocol_version != fleet::FAILURE_PROTOCOL_VERSION
            || failed.failure.code.is_empty()
            || failed.failure.message.is_empty()
        {
            bail!("fleet input failure did not match session roam authority");
        }
        let input_id = saga
            .input_id
            .as_deref()
            .context("input saga omitted input id")?;
        let placement = target_placement(saga);
        session_authority::retry_input_delivery_tx(tx, input_id, &placement)?;
        if tx.execute(
            "UPDATE session_roam_sagas SET input_job_id=NULL,input_id=NULL,updated_at=?2
             WHERE saga_id=?1 AND state='active' AND input_job_id=?3 AND input_id=?4",
            params![saga.saga_id, current_timestamp(), job_id, input_id],
        )? != 1
        {
            bail!("input failure reconciliation lost saga authority");
        }
        let refreshed = load_saga(tx, &saga.session_id)?.context("active saga disappeared")?;
        return schedule_next_input_after(tx, &refreshed, Some(&failed.attempt_id));
    }
    let Some(completed) = fleet::completed_job_on_connection(tx, job_id)? else {
        return Ok(false);
    };
    validate_result(&completed, saga, "deliver-input", false)?;
    let input_id = saga
        .input_id
        .as_deref()
        .context("input saga omitted input id")?;
    if completed.result["evidence"]["inputId"] != input_id {
        bail!("input completion did not match the claimed input");
    }
    let placement = target_placement(saga);
    session_authority::ack_input_delivery_tx(
        tx,
        coven_home,
        &saga.session_id,
        input_id,
        &placement,
    )?;
    session_authority::append_actor_output_tx(
        tx,
        coven_home,
        &saga.session_id,
        &placement,
        &completed.result["evidence"]["delivery"]["output"],
    )?;
    if tx.execute("UPDATE session_roam_sagas SET input_job_id=NULL,input_id=NULL,updated_at=?2 WHERE saga_id=?1 AND input_job_id=?3 AND input_id=?4",
        params![saga.saga_id,current_timestamp(),job_id,input_id])? != 1 {bail!("input completion lost saga authority");}
    let refreshed = load_saga(tx, &saga.session_id)?.context("active saga disappeared")?;
    schedule_next_input(tx, &refreshed)?;
    Ok(true)
}

fn schedule_next_input(tx: &Transaction<'_>, saga: &Saga) -> Result<bool> {
    schedule_next_input_after(tx, saga, None)
}

fn schedule_next_input_after(
    tx: &Transaction<'_>,
    saga: &Saga,
    failed_attempt_id: Option<&str>,
) -> Result<bool> {
    let placement = target_placement(saga);
    let Some(delivery) = session_authority::claim_next_input_tx(tx, &saga.session_id, &placement)?
    else {
        return Ok(false);
    };
    let sequence = delivery.sequence.to_string();
    let mut identity = vec![
        saga.saga_id.as_str(),
        delivery.input_id.as_str(),
        sequence.as_str(),
    ];
    if let Some(attempt_id) = failed_attempt_id {
        identity.push(attempt_id);
    }
    let job_id = stable_id("roamin", &identity);
    let payload = json!({"protocolVersion":session_roam_executor::PROTOCOL_VERSION,"operation":"deliver-input","roamId":saga.saga_id,
        "sessionId":saga.session_id,"placementId":saga.target_placement_id,"generation":saga.generation,"attemptId":"pending",
        "nodeId":saga.target_node_id,"actorId":saga.actor_id,"inputId":delivery.input_id,"sequence":delivery.sequence,"input":delivery.payload});
    let required = vec![
        format!("runtime:{}", saga.target_harness),
        "protocol:harness-host:1".into(),
    ];
    fleet::submit_job_on_connection(tx, &job_id, &payload, &required, Some(&saga.target_node_id))?;
    if tx.execute("UPDATE session_roam_sagas SET input_job_id=?2,input_id=?3,updated_at=?4 WHERE saga_id=?1 AND state='active' AND input_job_id IS NULL",
        params![saga.saga_id,job_id,delivery.input_id,current_timestamp()])? != 1 {bail!("input scheduling lost saga authority");}
    Ok(true)
}

fn target_placement(saga: &Saga) -> PlacementLease {
    PlacementLease {
        placement_id: saga.target_placement_id.clone(),
        session_id: saga.session_id.clone(),
        generation: saga.generation,
        node_id: saga.target_node_id.clone(),
        actor_id: saga.actor_id.clone(),
        state: "active".into(),
    }
}

fn validate_result(
    completed: &fleet::CompletedFleetJob,
    saga: &Saga,
    operation: &str,
    source: bool,
) -> Result<()> {
    let expected_node = if source {
        &saga.source_node_id
    } else {
        &saga.target_node_id
    };
    let expected_placement = if source {
        &saga.source_placement_id
    } else {
        &saga.target_placement_id
    };
    let expected_generation = if source {
        saga.source_generation
    } else {
        saga.generation
    };
    let result = &completed.result;
    if completed.node_id != *expected_node
        || result["protocolVersion"] != session_roam_executor::RESULT_PROTOCOL_VERSION
        || result["operation"] != operation
        || result["roamId"] != saga.saga_id
        || result["sessionId"] != saga.session_id
        || result["placementId"] != *expected_placement
        || result["generation"].as_u64() != Some(expected_generation)
        || result["attemptId"] != completed.attempt_id
        || result["nodeId"] != *expected_node
        || !digest_matches(result)?
    {
        bail!("fleet completion did not match session roam authority");
    }
    Ok(())
}

fn validate_checkpoint(checkpoint: &Value, driver: &str, generation: u64) -> Result<()> {
    if checkpoint["driver"] != driver
        || checkpoint["generation"].as_u64() != Some(generation)
        || checkpoint["sha256"].as_str().is_none_or(str::is_empty)
        || checkpoint["sizeBytes"].as_u64().is_none()
        || !checkpoint["locator"].is_object()
    {
        bail!("checkpoint completion evidence was incomplete or mismatched");
    }
    Ok(())
}

type SagaRow = (
    String,
    String,
    i64,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);
fn load_saga(tx: &Transaction<'_>, session_id: &str) -> Result<Option<Saga>> {
    let row:Option<SagaRow>=tx.query_row("SELECT saga_id,session_id,generation,state,source_placement_id,source_node_id,source_generation,
        target_placement_id,target_node_id,actor_id,workspace_driver,target_harness,
        checkpoint_job_id,prepare_job_id,input_job_id,input_id FROM session_roam_sagas WHERE session_id=?1 ORDER BY generation DESC LIMIT 1",
        params![session_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,
            r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?))).optional()?;
    row.map(|r| {
        Ok(Saga {
            saga_id: r.0,
            session_id: r.1,
            generation: u64::try_from(r.2)?,
            state: r.3,
            source_placement_id: r.4,
            source_node_id: r.5,
            source_generation: u64::try_from(r.6)?,
            target_placement_id: r.7,
            target_node_id: r.8,
            actor_id: r.9,
            workspace_driver: r.10,
            target_harness: r.11,
            checkpoint_job_id: r.12,
            prepare_job_id: r.13,
            input_job_id: r.14,
            input_id: r.15,
        })
    })
    .transpose()
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(prefix.as_bytes());
    for part in parts {
        digest.update([0]);
        digest.update(part.as_bytes());
    }
    let encoded = URL_SAFE_NO_PAD.encode(digest.finalize());
    format!("{prefix}_{}", &encoded[..22])
}
fn digest_value(value: &Value) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(value)?)))
}
fn digest_matches(value: &Value) -> Result<bool> {
    let Some(expected) = value["resultDigest"].as_str() else {
        return Ok(false);
    };
    let mut canonical = value.clone();
    canonical
        .as_object_mut()
        .context("result is not an object")?
        .remove("resultDigest");
    Ok(digest_value(&canonical)? == expected)
}
