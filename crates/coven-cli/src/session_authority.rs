//! Hub-owned logical-session, placement, run, input, and finalization authority.

use crate::{api::current_timestamp, store, STORE_FILE_NAME};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

pub const ROAM_PROTOCOL_VERSION: &str = "coven.roam.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoamState {
    Preparing,
    Checkpointed,
    Restoring,
    Starting,
    Active,
    Failed,
    Cancelled,
}

impl RoamState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Checkpointed => "checkpointed",
            Self::Restoring => "restoring",
            Self::Starting => "starting",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Preparing,
                Self::Checkpointed | Self::Failed | Self::Cancelled
            ) | (
                Self::Checkpointed,
                Self::Restoring | Self::Failed | Self::Cancelled
            ) | (
                Self::Restoring,
                Self::Starting | Self::Failed | Self::Cancelled
            ) | (
                Self::Starting,
                Self::Active | Self::Failed | Self::Cancelled
            ) | (Self::Failed, Self::Preparing | Self::Cancelled)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRef {
    pub driver: String,
    pub locator: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoamRecord {
    pub protocol_version: String,
    pub session_id: String,
    pub generation: u64,
    pub state: RoamState,
    pub source_node_id: String,
    pub target_node_id: Option<String>,
    pub source_harness: String,
    pub target_harness: String,
    pub workspace: WorkspaceRef,
    pub handoff_event_id: Option<String>,
    pub checkpoint_ref: Option<Value>,
    pub dispatch_job_id: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl RoamRecord {
    pub fn accepts_result(&self, generation: u64, node_id: &str) -> bool {
        self.state == RoamState::Active
            && self.generation == generation
            && self.target_node_id.as_deref() == Some(node_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlacementLease {
    pub placement_id: String,
    pub session_id: String,
    pub generation: u64,
    pub node_id: String,
    pub actor_id: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputDisposition {
    Queued {
        input_id: String,
        sequence: u64,
    },
    Route {
        input_id: String,
        sequence: u64,
        placement: PlacementLease,
    },
}

#[derive(Debug, Clone)]
pub struct InputDelivery {
    pub input_id: String,
    pub sequence: u64,
    pub payload: Value,
    pub placement: PlacementLease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizationEvidence {
    pub result_digest: String,
    pub result: Value,
    pub revision: Value,
    pub artifacts: Value,
    pub verification: Value,
}

pub struct RoamAdvance {
    pub generation: u64,
    pub node_id: String,
    pub state: RoamState,
    pub checkpoint_ref: Option<Value>,
    pub dispatch_job_id: Option<String>,
    pub error: Option<String>,
}

pub struct RunExit<'a> {
    pub placement_id: &'a str,
    pub generation: u64,
    pub node_id: &'a str,
    pub completion_key: &'a str,
    pub exit_code: Option<i32>,
    pub result_ref: Option<&'a Value>,
}

struct LifecyclePlacementPointers {
    active_generation: i64,
    active_placement_id: Option<String>,
    pending_generation: Option<i64>,
    pending_placement_id: Option<String>,
    fenced_placement_id: Option<String>,
    finalizing_placement_id: Option<String>,
}

pub fn finalization_digest(evidence: &FinalizationEvidence) -> Result<String> {
    let canonical = serde_json::json!({
        "result": evidence.result,
        "revision": evidence.revision,
        "artifacts": evidence.artifacts,
        "verification": evidence.verification,
    });
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(&canonical)?)))
}

fn open(coven_home: &Path) -> Result<Connection> {
    store::open_store(&coven_home.join(STORE_FILE_NAME))
}

fn ensure_migrated_tx(tx: &Transaction<'_>, session_id: &str) -> Result<()> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_lifecycles WHERE session_id=?1)",
        params![session_id],
        |row| row.get(0),
    )?;
    if exists {
        return Ok(());
    }
    let session: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT status,archived_at FROM sessions WHERE id=?1",
            params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (_legacy_process_status, archived_at) = session.context("session was not found")?;
    let now = current_timestamp();
    let roam: Option<(i64, String, String)> = tx
        .query_row(
            "SELECT generation,state,record_json FROM session_roams WHERE session_id=?1",
            params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    // Legacy `sessions.status` describes the last harness process, not the
    // durable conversation. Only explicit archival closes logical authority.
    let logical_state = if archived_at.is_some() {
        "closed"
    } else {
        "open"
    };
    let Some((generation, state_column, raw)) = roam else {
        tx.execute(
            "INSERT INTO session_lifecycles
             (session_id,logical_state,active_generation,next_input_seq,created_at,updated_at)
             VALUES (?1,?2,0,1,?3,?3)",
            params![session_id, logical_state, now],
        )?;
        return Ok(());
    };
    let generation_u64 = u64::try_from(generation).context("legacy roam generation is negative")?;
    let record: RoamRecord = serde_json::from_str(&raw)?;
    if record.protocol_version != ROAM_PROTOCOL_VERSION
        || record.session_id != session_id
        || record.generation != generation_u64
        || record.state.as_str() != state_column
    {
        bail!("legacy roam columns do not match the stored protocol record")
    }
    if logical_state == "closed" {
        tx.execute(
            "INSERT INTO session_lifecycles
             (session_id,logical_state,active_generation,next_input_seq,created_at,updated_at)
             VALUES (?1,'closed',?2,1,?3,?3)",
            params![session_id, generation, now],
        )?;
        return Ok(());
    }
    let workspace = serde_json::to_string(&record.workspace)?;
    let legacy_actor = format!("actor_legacy_{session_id}");
    if record.state == RoamState::Active {
        let node_id = record
            .target_node_id
            .as_deref()
            .context("active legacy roam omitted target node")?;
        let placement_id = format!("plc_legacy_{session_id}_{generation}");
        tx.execute(
            "INSERT INTO session_lifecycles
             (session_id,logical_state,active_generation,active_placement_id,next_input_seq,created_at,updated_at)
             VALUES (?1,'open',?2,?3,1,?4,?4)",
            params![session_id, generation, placement_id, now],
        )?;
        tx.execute(
            "INSERT INTO session_placements
             (placement_id,session_id,generation,node_id,actor_id,state,workspace_ref_json,created_at,activated_at)
             VALUES (?1,?2,?3,?4,?5,'active',?6,?7,?7)",
            params![placement_id,session_id,generation,node_id,legacy_actor,workspace,now],
        )?;
        return Ok(());
    }
    if generation == 0 {
        bail!("in-flight legacy roam requires a positive generation")
    }
    let source_generation = generation - 1;
    let source_id = format!("plc_legacy_{session_id}_{source_generation}");
    let target_id = format!("plc_legacy_{session_id}_{generation}");
    let source_fenced = matches!(
        record.state,
        RoamState::Checkpointed | RoamState::Restoring | RoamState::Starting
    ) || (matches!(record.state, RoamState::Failed | RoamState::Cancelled)
        && record.checkpoint_ref.is_some());
    let terminal = matches!(record.state, RoamState::Failed | RoamState::Cancelled);
    let target_node = record
        .target_node_id
        .as_deref()
        .context("legacy roam omitted target node")?;
    let (active_id, fenced_id, pending_generation, pending_id) = if terminal {
        (
            (!source_fenced).then_some(source_id.as_str()),
            source_fenced.then_some(source_id.as_str()),
            None,
            None,
        )
    } else {
        (
            (!source_fenced).then_some(source_id.as_str()),
            source_fenced.then_some(source_id.as_str()),
            Some(generation),
            Some(target_id.as_str()),
        )
    };
    tx.execute(
        "INSERT INTO session_lifecycles
         (session_id,logical_state,active_generation,active_placement_id,pending_generation,
          pending_placement_id,fenced_placement_id,next_input_seq,created_at,updated_at)
         VALUES (?1,'open',?2,?3,?4,?5,?6,1,?7,?7)",
        params![
            session_id,
            source_generation,
            active_id,
            pending_generation,
            pending_id,
            fenced_id,
            now
        ],
    )?;
    tx.execute(
        "INSERT INTO session_placements
         (placement_id,session_id,generation,node_id,actor_id,state,workspace_ref_json,created_at,activated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8)",
        params![source_id,session_id,source_generation,record.source_node_id,legacy_actor,if source_fenced {"fenced"} else {"active"},workspace,now],
    )?;
    tx.execute(
        "INSERT INTO session_placements
         (placement_id,session_id,generation,node_id,actor_id,state,workspace_ref_json,created_at,released_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![target_id,session_id,generation,target_node,format!("actor_legacy_{session_id}_{generation}"),if terminal {record.state.as_str()} else {"starting"},workspace,now,terminal.then_some(now.as_str())],
    )?;
    Ok(())
}

fn reserve_transfer_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    node_id: &str,
    actor_id: &str,
    workspace: &Value,
) -> Result<PlacementLease> {
    ensure_migrated_tx(tx, session_id)?;
    let (active_generation, active_placement, pending_placement, finalizing_placement): (
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = tx.query_row(
        "SELECT active_generation,active_placement_id,pending_placement_id,finalizing_placement_id
         FROM session_lifecycles WHERE session_id=?1 AND logical_state='open'",
        params![session_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if pending_placement.is_some() {
        bail!("a session transfer is already pending")
    }
    if finalizing_placement.is_some() {
        bail!("session resources await finalization acknowledgment")
    }
    let highest_generation: i64 = tx.query_row(
        "SELECT MAX(generation) FROM session_placements WHERE session_id=?1",
        params![session_id],
        |row| Ok(row.get::<_, Option<i64>>(0)?.unwrap_or(active_generation)),
    )?;
    let generation_db = highest_generation
        .checked_add(1)
        .context("session generation overflow")?;
    let placement_id = format!("plc_{}", Uuid::new_v4().simple());
    let now = current_timestamp();
    tx.execute(
        "INSERT INTO session_placements
         (placement_id,session_id,generation,node_id,actor_id,state,workspace_ref_json,created_at)
         VALUES (?1,?2,?3,?4,?5,'starting',?6,?7)",
        params![
            placement_id,
            session_id,
            generation_db,
            node_id,
            actor_id,
            serde_json::to_string(workspace)?,
            now
        ],
    )?;
    let changed = tx.execute(
        "UPDATE session_lifecycles SET pending_generation=?2,pending_placement_id=?3,updated_at=?4
         WHERE session_id=?1 AND active_generation=?5 AND active_placement_id IS ?6
         AND pending_placement_id IS NULL",
        params![
            session_id,
            generation_db,
            placement_id,
            now,
            active_generation,
            active_placement
        ],
    )?;
    if changed != 1 {
        bail!("session transfer reservation lost authority")
    }
    Ok(PlacementLease {
        placement_id,
        session_id: session_id.into(),
        generation: u64::try_from(generation_db).context("session generation is negative")?,
        node_id: node_id.into(),
        actor_id: actor_id.into(),
        state: "starting".into(),
    })
}

pub fn begin_transfer(
    coven_home: &Path,
    session_id: &str,
    node_id: &str,
    actor_id: &str,
    workspace: &Value,
) -> Result<PlacementLease> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let placement = reserve_transfer_tx(&tx, session_id, node_id, actor_id, workspace)?;
    tx.commit()?;
    Ok(placement)
}

pub fn begin_roam_transfer(
    coven_home: &Path,
    record: RoamRecord,
    next_action: Option<&str>,
) -> Result<RoamRecord> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record = begin_roam_transfer_tx(&tx, coven_home, record, next_action)?;
    tx.commit()?;
    Ok(record)
}

pub(crate) fn begin_roam_transfer_tx(
    tx: &Transaction<'_>,
    coven_home: &Path,
    mut record: RoamRecord,
    next_action: Option<&str>,
) -> Result<RoamRecord> {
    let target_node = record
        .target_node_id
        .as_deref()
        .context("roam target node is required")?;
    let placement = reserve_transfer_tx(
        tx,
        &record.session_id,
        target_node,
        &format!("actor_{}", record.session_id),
        &serde_json::to_value(&record.workspace)?,
    )?;
    let actor_id = format!("actor_{}", placement.placement_id);
    let changed = tx.execute(
        "UPDATE session_placements SET actor_id=?2
         WHERE placement_id=?1 AND state='starting'",
        params![placement.placement_id, actor_id],
    )?;
    if changed != 1 {
        bail!("roam actor binding lost placement authority")
    }
    let session = store::get_session(tx, &record.session_id)?
        .context("session disappeared during roam reservation")?;
    record.handoff_event_id = Some(crate::handoff::ensure_for_roam(
        tx,
        coven_home,
        &session,
        &record.target_harness,
        next_action,
    )?);
    record.generation = placement.generation;
    let previous: Option<i64> = tx
        .query_row(
            "SELECT generation FROM session_roams WHERE session_id=?1",
            params![record.session_id],
            |row| row.get(0),
        )
        .optional()?;
    let now = current_timestamp();
    record.created_at = tx
        .query_row(
            "SELECT json_extract(record_json,'$.createdAt') FROM session_roams WHERE session_id=?1",
            params![record.session_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| now.clone());
    record.updated_at = now.clone();
    let changed = match previous {
        None => tx.execute(
            "INSERT OR IGNORE INTO session_roams(session_id,generation,state,record_json,updated_at)
             VALUES (?1,?2,?3,?4,?5)",
            params![record.session_id,i64::try_from(record.generation)?,record.state.as_str(),serde_json::to_string(&record)?,now],
        )?,
        Some(previous) => tx.execute(
            "UPDATE session_roams SET generation=?2,state=?3,record_json=?4,updated_at=?5
             WHERE session_id=?1 AND generation=?6",
            params![record.session_id,i64::try_from(record.generation)?,record.state.as_str(),serde_json::to_string(&record)?,now,previous],
        )?,
    };
    if changed != 1 {
        bail!("roam generation changed; reload and retry")
    }
    Ok(record)
}

pub(crate) fn bind_roam_dispatch_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    generation: u64,
    state: RoamState,
    job_id: &str,
) -> Result<RoamRecord> {
    let raw: String = tx.query_row(
        "SELECT record_json FROM session_roams
         WHERE session_id=?1 AND generation=?2 AND state=?3",
        params![session_id, i64::try_from(generation)?, state.as_str()],
        |row| row.get(0),
    )?;
    let mut record: RoamRecord = serde_json::from_str(&raw)?;
    record.dispatch_job_id = Some(job_id.into());
    record.updated_at = current_timestamp();
    let changed = tx.execute(
        "UPDATE session_roams SET record_json=?4,updated_at=?5
         WHERE session_id=?1 AND generation=?2 AND state=?3",
        params![
            session_id,
            i64::try_from(generation)?,
            state.as_str(),
            serde_json::to_string(&record)?,
            record.updated_at
        ],
    )?;
    if changed != 1 {
        bail!("roam dispatch binding lost projection authority")
    }
    Ok(record)
}

pub fn advance_roam(
    coven_home: &Path,
    session_id: &str,
    advance: RoamAdvance,
) -> Result<RoamRecord> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let record = advance_roam_tx(&tx, session_id, advance)?;
    tx.commit()?;
    Ok(record)
}

pub(crate) fn advance_roam_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    advance: RoamAdvance,
) -> Result<RoamRecord> {
    let RoamAdvance {
        generation,
        node_id,
        state,
        checkpoint_ref,
        dispatch_job_id,
        error,
    } = advance;
    ensure_migrated_tx(tx, session_id)?;
    let raw: String = tx
        .query_row(
            "SELECT record_json FROM session_roams WHERE session_id=?1",
            params![session_id],
            |row| row.get(0),
        )
        .context("roam was not found")?;
    let mut record: RoamRecord = serde_json::from_str(&raw)?;
    if generation != record.generation {
        bail!("stale_generation")
    }
    if !record.state.can_transition_to(state) {
        bail!("invalid_roam_transition")
    }
    let expected_node = match state {
        RoamState::Checkpointed => Some(record.source_node_id.as_str()),
        RoamState::Restoring | RoamState::Starting | RoamState::Active => {
            record.target_node_id.as_deref()
        }
        RoamState::Failed | RoamState::Cancelled => {
            if node_id != record.source_node_id
                && record.target_node_id.as_deref() != Some(node_id.as_str())
            {
                bail!("wrong_executor")
            }
            None
        }
        RoamState::Preparing => None,
    };
    if expected_node.is_some_and(|expected| expected != node_id) {
        bail!("wrong_executor")
    }
    if state == RoamState::Checkpointed {
        let source: Option<String> = tx.query_row(
            "SELECT active_placement_id FROM session_lifecycles WHERE session_id=?1",
            params![session_id],
            |row| row.get(0),
        )?;
        if let Some(source) = source {
            let changed = tx.execute(
                "UPDATE session_placements SET state='fenced'
                 WHERE placement_id=?1 AND session_id=?2 AND state='active'",
                params![source, session_id],
            )?;
            if changed != 1 {
                bail!("source placement fence lost authority")
            }
            let changed = tx.execute(
                "UPDATE session_lifecycles SET active_placement_id=NULL,fenced_placement_id=?2,updated_at=?3
                 WHERE session_id=?1 AND active_placement_id=?2 AND pending_generation=?4",
                params![session_id,source,current_timestamp(),i64::try_from(generation)?],
            )?;
            if changed != 1 {
                bail!("source placement fence lost lifecycle authority")
            }
        }
    }
    if state == RoamState::Active {
        activate_pending_tx(tx, session_id, generation, &node_id, None)?;
    }
    if matches!(state, RoamState::Failed | RoamState::Cancelled) {
        compensate_failed_transfer_tx(tx, session_id, generation, state)?;
    }
    record.state = state;
    if checkpoint_ref.is_some() {
        record.checkpoint_ref = checkpoint_ref;
    }
    if dispatch_job_id.is_some() {
        record.dispatch_job_id = dispatch_job_id;
    }
    record.error = error;
    record.updated_at = current_timestamp();
    let changed = tx.execute(
        "UPDATE session_roams SET state=?3,record_json=?4,updated_at=?5
         WHERE session_id=?1 AND generation=?2",
        params![
            session_id,
            i64::try_from(generation)?,
            state.as_str(),
            serde_json::to_string(&record)?,
            record.updated_at
        ],
    )?;
    if changed != 1 {
        bail!("roam generation changed; reload and retry")
    }
    Ok(record)
}

fn compensate_failed_transfer_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    generation: u64,
    terminal: RoamState,
) -> Result<()> {
    let terminal_state = match terminal {
        RoamState::Failed => "failed",
        RoamState::Cancelled => "cancelled",
        _ => bail!("transfer compensation requires a terminal state"),
    };
    let pending: Option<String> = tx.query_row(
        "SELECT pending_placement_id FROM session_lifecycles
         WHERE session_id=?1 AND pending_generation=?2",
        params![session_id, i64::try_from(generation)?],
        |row| row.get(0),
    )?;
    let pending = pending.context("terminal transfer has no pending placement")?;
    let changed = tx.execute(
        "UPDATE session_placements SET state=?2,released_at=?3
         WHERE placement_id=?1 AND session_id=?4 AND generation=?5 AND state='starting'",
        params![
            pending,
            terminal_state,
            current_timestamp(),
            session_id,
            i64::try_from(generation)?
        ],
    )?;
    if changed != 1 {
        bail!("terminal transfer lost pending placement authority")
    }
    let fenced: Option<String> = tx.query_row(
        "SELECT fenced_placement_id FROM session_lifecycles
         WHERE session_id=?1 AND pending_generation=?2 AND pending_placement_id=?3",
        params![session_id, i64::try_from(generation)?, pending],
        |row| row.get(0),
    )?;
    if let Some(source) = fenced.as_deref() {
        let changed = tx.execute(
            "UPDATE session_placements SET state='active',released_at=NULL
             WHERE placement_id=?1 AND session_id=?2 AND state='fenced'",
            params![source, session_id],
        )?;
        if changed != 1 {
            bail!("terminal transfer lost fenced source authority")
        }
    }
    let changed = tx.execute(
        "UPDATE session_lifecycles SET active_placement_id=COALESCE(fenced_placement_id,active_placement_id),
         pending_generation=NULL,pending_placement_id=NULL,fenced_placement_id=NULL,updated_at=?3
         WHERE session_id=?1 AND pending_generation=?2 AND pending_placement_id=?4",
        params![
            session_id,
            i64::try_from(generation)?,
            current_timestamp(),
            pending
        ],
    )?;
    if changed != 1 {
        bail!("terminal transfer lost lifecycle authority")
    }
    Ok(())
}

fn activate_pending_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    generation: u64,
    node_id: &str,
    expected_placement_id: Option<&str>,
) -> Result<PlacementLease> {
    let row = tx.query_row(
        "SELECT active_generation,active_placement_id,pending_generation,pending_placement_id,fenced_placement_id,finalizing_placement_id
         FROM session_lifecycles WHERE session_id=?1 AND logical_state='open'",
        params![session_id],
        |row| Ok(LifecyclePlacementPointers {
            active_generation: row.get(0)?,
            active_placement_id: row.get(1)?,
            pending_generation: row.get(2)?,
            pending_placement_id: row.get(3)?,
            fenced_placement_id: row.get(4)?,
            finalizing_placement_id: row.get(5)?,
        }),
    )?;
    if row.finalizing_placement_id.is_some() {
        bail!("session resources await finalization acknowledgment")
    }
    let generation_db = i64::try_from(generation)?;
    if row.pending_generation != Some(generation_db) {
        bail!("placement generation is not pending")
    }
    let placement_id = row
        .pending_placement_id
        .context("pending placement is missing")?;
    if expected_placement_id.is_some_and(|expected| expected != placement_id) {
        bail!("pending placement does not match")
    }
    let target: (String, String) = tx
        .query_row(
            "SELECT node_id,actor_id FROM session_placements
         WHERE placement_id=?1 AND session_id=?2 AND generation=?3 AND state='starting'",
            params![placement_id, session_id, generation_db],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("active placement reservation was not found")?;
    if target.0 != node_id {
        bail!("wrong executor for pending placement")
    }
    let source = row
        .fenced_placement_id
        .clone()
        .or(row.active_placement_id.clone());
    if let Some(source) = source.as_deref() {
        let changed = tx.execute(
            "UPDATE session_placements SET state='released',released_at=?2
             WHERE placement_id=?1 AND session_id=?3 AND state IN ('active','fenced')",
            params![source, current_timestamp(), session_id],
        )?;
        if changed != 1 {
            bail!("source placement release lost authority")
        }
    }
    let changed=tx.execute(
        "UPDATE session_placements SET state='active',activated_at=?2
         WHERE placement_id=?1 AND session_id=?3 AND generation=?4 AND node_id=?5 AND state='starting'",
        params![placement_id,current_timestamp(),session_id,generation_db,node_id],
    )?;
    if changed != 1 {
        bail!("placement activation lost authority")
    }
    let changed = tx.execute(
        "UPDATE session_lifecycles SET active_generation=?2,active_placement_id=?3,
         pending_generation=NULL,pending_placement_id=NULL,fenced_placement_id=NULL,updated_at=?4
         WHERE session_id=?1 AND active_generation=?5 AND active_placement_id IS ?6
         AND pending_generation=?2 AND pending_placement_id=?3 AND fenced_placement_id IS ?7
         AND finalizing_placement_id IS NULL",
        params![
            session_id,
            generation_db,
            placement_id,
            current_timestamp(),
            row.active_generation,
            row.active_placement_id,
            row.fenced_placement_id
        ],
    )?;
    if changed != 1 {
        bail!("placement activation lost lifecycle authority")
    }
    Ok(PlacementLease {
        placement_id,
        session_id: session_id.into(),
        generation,
        node_id: node_id.into(),
        actor_id: target.1,
        state: "active".into(),
    })
}

pub fn activate_placement(
    coven_home: &Path,
    session_id: &str,
    placement_id: &str,
    generation: u64,
    node_id: &str,
) -> Result<PlacementLease> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let placement = activate_pending_tx(&tx, session_id, generation, node_id, Some(placement_id))?;
    tx.commit()?;
    Ok(placement)
}

pub fn accept_output(
    coven_home: &Path,
    session_id: &str,
    placement_id: &str,
    generation: u64,
    node_id: &str,
) -> Result<()> {
    let conn = open(coven_home)?;
    let accepted: bool = conn.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM session_lifecycles l JOIN session_placements p ON p.placement_id=l.active_placement_id
           WHERE l.session_id=?1 AND l.logical_state='open' AND l.active_generation=?3
           AND p.placement_id=?2 AND p.generation=?3 AND p.node_id=?4 AND p.state='active')",
        params![session_id,placement_id,i64::try_from(generation)?,node_id],
        |row| row.get(0),
    )?;
    if !accepted {
        bail!("stale or unauthorized session output")
    }
    Ok(())
}

pub fn append_output(
    coven_home: &Path,
    session_id: &str,
    run_id: &str,
    placement_id: &str,
    generation: u64,
    node_id: &str,
    payload: &Value,
) -> Result<()> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let authoritative:bool=tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_lifecycles l
         JOIN session_placements p ON p.placement_id=l.active_placement_id
         JOIN session_runs r ON r.placement_id=p.placement_id
         WHERE l.session_id=?1 AND l.logical_state='open' AND l.active_generation=?4
         AND p.placement_id=?3 AND p.generation=?4 AND p.node_id=?5 AND p.state='active'
         AND r.run_id=?2 AND r.session_id=?1 AND r.generation=?4 AND r.node_id=?5 AND r.state='running')",
        params![session_id,run_id,placement_id,i64::try_from(generation)?,node_id],|row|row.get(0))?;
    if !authoritative {
        bail!("stale or unauthorized session output")
    }
    store::insert_event_with_privacy(
        &tx,
        coven_home,
        &store::EventRecord {
            seq: 0,
            id: Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            kind: "output".into(),
            payload_json: serde_json::to_string(payload)?,
            created_at: current_timestamp(),
        },
    )?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn append_actor_output_tx(
    tx: &Transaction<'_>,
    coven_home: &Path,
    session_id: &str,
    placement: &PlacementLease,
    payload: &Value,
) -> Result<()> {
    let authoritative: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_lifecycles l
         JOIN session_placements p ON p.placement_id=l.active_placement_id
         WHERE l.session_id=?1 AND l.logical_state='open' AND l.active_generation=?3
         AND p.placement_id=?2 AND p.generation=?3 AND p.node_id=?4
         AND p.actor_id=?5 AND p.state='active')",
        params![
            session_id,
            placement.placement_id,
            i64::try_from(placement.generation)?,
            placement.node_id,
            placement.actor_id
        ],
        |row| row.get(0),
    )?;
    if !authoritative {
        bail!("stale or unauthorized session output")
    }
    store::insert_event_with_privacy(
        tx,
        coven_home,
        &store::EventRecord {
            seq: 0,
            id: Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            kind: "output".into(),
            payload_json: serde_json::to_string(payload)?,
            created_at: current_timestamp(),
        },
    )?;
    Ok(())
}

pub fn queue_or_route_input(
    coven_home: &Path,
    session_id: &str,
    payload: &Value,
) -> Result<InputDisposition> {
    persist_input(coven_home, session_id, payload, true)
}

/// Persist user input at the hub without assuming the active executor is local.
/// Executor orchestration subsequently claims and acknowledges it using the
/// full placement tuple.
pub fn queue_input(
    coven_home: &Path,
    session_id: &str,
    payload: &Value,
) -> Result<InputDisposition> {
    persist_input(coven_home, session_id, payload, false)
}

fn persist_input(
    coven_home: &Path,
    session_id: &str,
    payload: &Value,
    route_active: bool,
) -> Result<InputDisposition> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_migrated_tx(&tx, session_id)?;
    let active: Option<(String, i64, String, String)> = tx
        .query_row(
            "SELECT p.placement_id,p.generation,p.node_id,p.actor_id FROM session_lifecycles l
         JOIN session_placements p ON p.placement_id=l.active_placement_id
         WHERE l.session_id=?1 AND l.logical_state='open' AND p.state='active'
         AND l.pending_placement_id IS NULL AND l.fenced_placement_id IS NULL",
            params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let sequence_db: i64 = tx.query_row(
        "SELECT next_input_seq FROM session_lifecycles WHERE session_id=?1",
        params![session_id],
        |row| row.get(0),
    )?;
    let input_id = format!("inp_{}", Uuid::new_v4().simple());
    let route = route_active.then_some(active).flatten();
    let generation = route.as_ref().map(|row| row.1);
    let state = if route.is_some() {
        "delivering"
    } else {
        "queued"
    };
    tx.execute("INSERT INTO session_queued_inputs (input_id,session_id,sequence,payload_json,state,generation) VALUES (?1,?2,?3,?4,?5,?6)",
        params![input_id,session_id,sequence_db,serde_json::to_string(payload)?,state,generation])?;
    tx.execute("UPDATE session_lifecycles SET next_input_seq=next_input_seq+1,updated_at=?2 WHERE session_id=?1",params![session_id,current_timestamp()])?;
    tx.commit()?;
    let sequence = u64::try_from(sequence_db)?;
    match route {
        Some((placement_id, generation, node_id, actor_id)) => Ok(InputDisposition::Route {
            input_id,
            sequence,
            placement: PlacementLease {
                placement_id,
                session_id: session_id.into(),
                generation: u64::try_from(generation)?,
                node_id,
                actor_id,
                state: "active".into(),
            },
        }),
        None => Ok(InputDisposition::Queued { input_id, sequence }),
    }
}

pub fn is_managed(coven_home: &Path, session_id: &str) -> Result<bool> {
    let conn = open(coven_home)?;
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_lifecycles WHERE session_id=?1)",
        params![session_id],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub fn has_live_run(coven_home: &Path, session_id: &str) -> Result<bool> {
    let conn = open(coven_home)?;
    conn.query_row("SELECT EXISTS(SELECT 1 FROM session_runs WHERE session_id=?1 AND state IN ('queued','running'))",params![session_id],|row|row.get(0)).map_err(Into::into)
}

pub fn active_placement(coven_home: &Path, session_id: &str) -> Result<Option<PlacementLease>> {
    let conn = open(coven_home)?;
    let row: Option<(String, i64, String, String)> = conn
        .query_row(
            "SELECT p.placement_id,p.generation,p.node_id,p.actor_id FROM session_lifecycles l
         JOIN session_placements p ON p.placement_id=l.active_placement_id
         WHERE l.session_id=?1 AND p.state='active'",
            params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(placement_id, generation, node_id, actor_id)| {
        Ok(PlacementLease {
            placement_id,
            session_id: session_id.into(),
            generation: u64::try_from(generation)?,
            node_id,
            actor_id,
            state: "active".into(),
        })
    })
    .transpose()
}

#[derive(Debug, Clone)]
pub(crate) struct ActivePlacementContext {
    pub placement: PlacementLease,
    pub workspace: WorkspaceRef,
}

/// Read the active placement and its private workspace binding for hub-owned
/// orchestration. The workspace locator is intentionally not serializable and
/// must never be copied into client-facing status responses.
pub(crate) fn active_placement_context(
    coven_home: &Path,
    session_id: &str,
) -> Result<Option<ActivePlacementContext>> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ensure_migrated_tx(&tx, session_id)?;
    let row: Option<(String, i64, String, String, String)> = tx
        .query_row(
            "SELECT p.placement_id,p.generation,p.node_id,p.actor_id,p.workspace_ref_json
             FROM session_lifecycles l
             JOIN session_placements p ON p.placement_id=l.active_placement_id
             WHERE l.session_id=?1 AND l.logical_state='open' AND p.state='active'
             AND l.pending_placement_id IS NULL AND l.fenced_placement_id IS NULL",
            params![session_id],
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
    let context = row.map(|(placement_id, generation, node_id, actor_id, workspace)| -> Result<ActivePlacementContext> {
        Ok(ActivePlacementContext {
            placement: PlacementLease {
                placement_id,
                session_id: session_id.into(),
                generation: u64::try_from(generation)?,
                node_id,
                actor_id,
                state: "active".into(),
            },
            workspace: serde_json::from_str(&workspace)?,
        })
    })
    .transpose()?;
    tx.commit()?;
    Ok(context)
}

pub fn ack_input_delivery(
    coven_home: &Path,
    session_id: &str,
    input_id: &str,
    placement: &PlacementLease,
) -> Result<()> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    ack_input_delivery_tx(&tx, coven_home, session_id, input_id, placement)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn ack_input_delivery_tx(
    tx: &Transaction<'_>,
    coven_home: &Path,
    session_id: &str,
    input_id: &str,
    placement: &PlacementLease,
) -> Result<()> {
    let payload: String = tx
        .query_row(
            "SELECT payload_json FROM session_queued_inputs i
         WHERE i.input_id=?1 AND i.session_id=?2 AND i.state='delivering' AND i.generation=?3
         AND EXISTS(SELECT 1 FROM session_lifecycles l WHERE l.session_id=?2
          AND l.active_generation=?3 AND l.active_placement_id=?4)",
            params![
                input_id,
                session_id,
                i64::try_from(placement.generation)?,
                placement.placement_id
            ],
            |row| row.get(0),
        )
        .context("input delivery lost placement authority")?;
    let changed=tx.execute("UPDATE session_queued_inputs SET state='delivered' WHERE input_id=?1 AND state='delivering'",params![input_id])?;
    if changed != 1 {
        bail!("input delivery acknowledgment lost authority")
    }
    store::insert_event_with_privacy(
        tx,
        coven_home,
        &store::EventRecord {
            seq: 0,
            id: Uuid::new_v4().to_string(),
            session_id: session_id.into(),
            kind: "input".into(),
            payload_json: payload,
            created_at: current_timestamp(),
        },
    )?;
    Ok(())
}

pub fn retry_input_delivery(
    coven_home: &Path,
    input_id: &str,
    placement: &PlacementLease,
) -> Result<()> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    retry_input_delivery_tx(&tx, input_id, placement)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn retry_input_delivery_tx(
    tx: &Transaction<'_>,
    input_id: &str,
    placement: &PlacementLease,
) -> Result<()> {
    let changed = tx.execute(
        "UPDATE session_queued_inputs SET state='queued',generation=NULL
         WHERE input_id=?1 AND session_id=?3 AND state='delivering' AND generation=?2
         AND EXISTS(SELECT 1 FROM session_lifecycles WHERE session_id=?3
          AND active_generation=?2 AND active_placement_id=?4)",
        params![
            input_id,
            i64::try_from(placement.generation)?,
            placement.session_id,
            placement.placement_id
        ],
    )?;
    if changed != 1 {
        bail!("input retry lost placement authority")
    }
    Ok(())
}

pub fn claim_next_input(
    coven_home: &Path,
    session_id: &str,
    placement: &PlacementLease,
) -> Result<Option<InputDelivery>> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let delivery = claim_next_input_tx(&tx, session_id, placement)?;
    tx.commit()?;
    Ok(delivery)
}

pub(crate) fn claim_next_input_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    placement: &PlacementLease,
) -> Result<Option<InputDelivery>> {
    let authoritative: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_lifecycles l
         JOIN session_placements p ON p.placement_id=l.active_placement_id
         WHERE l.session_id=?1 AND l.active_generation=?2 AND l.active_placement_id=?3
         AND l.logical_state='open' AND p.generation=?2 AND p.node_id=?4
         AND p.actor_id=?5 AND p.state='active')",
        params![
            session_id,
            i64::try_from(placement.generation)?,
            placement.placement_id,
            placement.node_id,
            placement.actor_id
        ],
        |row| row.get(0),
    )?;
    if !authoritative {
        bail!("input claim lost placement authority")
    }
    let row: Option<(String, i64, String, String, Option<i64>)> = tx
        .query_row(
            "SELECT input_id,sequence,payload_json,state,generation FROM session_queued_inputs
         WHERE session_id=?1 AND state IN ('queued','delivering') ORDER BY sequence LIMIT 1",
            params![session_id],
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
    let Some((input_id, sequence, payload, state, delivery_generation)) = row else {
        return Ok(None);
    };
    let generation_db = i64::try_from(placement.generation)?;
    let changed = if state == "queued" {
        tx.execute(
            "UPDATE session_queued_inputs SET state='delivering',generation=?2
             WHERE input_id=?1 AND state='queued'",
            params![input_id, generation_db],
        )?
    } else if delivery_generation == Some(generation_db) {
        1
    } else {
        tx.execute(
            "UPDATE session_queued_inputs SET generation=?2
             WHERE input_id=?1 AND state='delivering' AND generation IS ?3",
            params![input_id, generation_db, delivery_generation],
        )?
    };
    if changed != 1 {
        bail!("input claim lost delivery authority")
    }
    Ok(Some(InputDelivery {
        input_id,
        sequence: u64::try_from(sequence)?,
        payload: serde_json::from_str(&payload)?,
        placement: placement.clone(),
    }))
}

pub fn queued_inputs(coven_home: &Path, session_id: &str) -> Result<Vec<(u64, Value)>> {
    let conn = open(coven_home)?;
    let mut statement = conn.prepare("SELECT sequence,payload_json FROM session_queued_inputs WHERE session_id=?1 AND state='queued' ORDER BY sequence")?;
    let rows = statement
        .query_map(params![session_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .map(|row| {
            let (sequence, raw) = row?;
            Ok((u64::try_from(sequence)?, serde_json::from_str(&raw)?))
        })
        .collect();
    rows
}

pub fn begin_run(
    coven_home: &Path,
    session_id: &str,
    placement_id: &str,
    generation: u64,
    node_id: &str,
) -> Result<String> {
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let run_id = format!("run_{}", Uuid::new_v4().simple());
    let changed = tx.execute(
        "INSERT INTO session_runs
         (run_id,session_id,placement_id,generation,node_id,state,started_at)
         SELECT ?1,?2,?3,?4,?5,'running',?6
         FROM session_lifecycles l JOIN session_placements p ON p.placement_id=l.active_placement_id
         WHERE l.session_id=?2 AND l.logical_state='open' AND l.active_generation=?4
         AND l.pending_placement_id IS NULL AND l.fenced_placement_id IS NULL
         AND p.placement_id=?3 AND p.generation=?4 AND p.node_id=?5 AND p.state='active'",
        params![
            run_id,
            session_id,
            placement_id,
            i64::try_from(generation)?,
            node_id,
            current_timestamp()
        ],
    )?;
    if changed != 1 {
        bail!("run start lost placement authority")
    }
    tx.commit()?;
    Ok(run_id)
}

pub fn record_run_exit(
    coven_home: &Path,
    session_id: &str,
    run_id: &str,
    exit: RunExit<'_>,
) -> Result<()> {
    let RunExit {
        placement_id,
        generation,
        node_id,
        completion_key,
        exit_code,
        result_ref,
    } = exit;
    if completion_key.is_empty() {
        bail!("run completion key is required")
    }
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state = if exit_code == Some(0) {
        "succeeded"
    } else {
        "failed"
    };
    let now = current_timestamp();
    let encoded_result = result_ref.map(serde_json::to_string).transpose()?;
    let existing: (String, Option<String>, Option<i32>, Option<String>) = tx
        .query_row(
            "SELECT state,completion_key,exit_code,result_ref_json FROM session_runs
         WHERE run_id=?1 AND session_id=?2 AND placement_id=?3 AND generation=?4 AND node_id=?5",
            params![
                run_id,
                session_id,
                placement_id,
                i64::try_from(generation)?,
                node_id
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .context("run authority tuple was not found")?;
    if existing.0 != "running" {
        if existing.1.as_deref() == Some(completion_key)
            && existing.2 == exit_code
            && existing.3 == encoded_result
        {
            tx.commit()?;
            return Ok(());
        }
        bail!("run completion replay changed immutable evidence")
    }
    let changed = tx.execute(
        "UPDATE session_runs SET state=?7,exited_at=?8,exit_code=?9,result_ref_json=?10,completion_key=?6
         WHERE run_id=?1 AND session_id=?2 AND placement_id=?3 AND generation=?4 AND node_id=?5 AND state='running'",
        params![
            run_id,
            session_id,
            placement_id,
            i64::try_from(generation)?,
            node_id,
            completion_key,
            state,
            now,
            exit_code,
            encoded_result,
        ],
    )?;
    if changed != 1 {
        bail!("run exit lost session authority")
    }
    let changed=tx.execute(
        "UPDATE session_placements SET state='finalizing' WHERE placement_id=?1 AND session_id=?2 AND generation=?3 AND node_id=?4 AND state='active'",
        params![placement_id,session_id,i64::try_from(generation)?,node_id],
    )?;
    if changed != 1 {
        bail!("run exit lost placement authority")
    }
    let changed=tx.execute(
        "UPDATE session_lifecycles SET active_placement_id=NULL,finalizing_placement_id=?2,updated_at=?3
         WHERE session_id=?1 AND active_placement_id=?2 AND active_generation=?4 AND logical_state='open'",
        params![session_id,placement_id,now,i64::try_from(generation)?],
    )?;
    if changed != 1 {
        bail!("run exit lost lifecycle authority")
    }
    tx.commit()?;
    Ok(())
}

pub fn stage_finalization(
    coven_home: &Path,
    session_id: &str,
    run_id: &str,
    placement_id: &str,
    generation: u64,
    node_id: &str,
    evidence: &FinalizationEvidence,
) -> Result<String> {
    let verification_passes = evidence.verification.as_array().is_some_and(|items| {
        !items.is_empty() && items.iter().all(|item| item["status"] == "passed")
    });
    if evidence.result_digest != finalization_digest(evidence)?
        || !verification_passes
        || evidence.artifacts.is_null()
        || evidence.revision.is_null()
    {
        bail!("finalization evidence is incomplete")
    }
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let authoritative: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_runs r JOIN session_placements p USING(placement_id)
         JOIN session_lifecycles l ON l.session_id=r.session_id
         WHERE r.run_id=?1 AND r.session_id=?2 AND r.placement_id=?3 AND r.generation=?4
         AND r.state IN ('succeeded','failed') AND p.node_id=?5 AND p.state='finalizing'
         AND l.logical_state='open' AND l.active_generation=?4 AND l.finalizing_placement_id=?3)",
        params![
            run_id,
            session_id,
            placement_id,
            i64::try_from(generation)?,
            node_id
        ],
        |row| row.get(0),
    )?;
    if !authoritative {
        bail!("finalization evidence is stale or unauthorized")
    }
    let existing: Option<(String, String, String, String, String, String)> = tx
        .query_row(
            "SELECT finalization_id,result_digest,result_json,revision_json,artifacts_json,verification_json
             FROM session_finalizations WHERE run_id=?1",
            params![run_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        )
        .optional()?;
    let encoded_result = serde_json::to_string(&evidence.result)?;
    let encoded_revision = serde_json::to_string(&evidence.revision)?;
    let encoded_artifacts = serde_json::to_string(&evidence.artifacts)?;
    let encoded_verification = serde_json::to_string(&evidence.verification)?;
    if let Some((id, digest, result, revision, artifacts, verification)) = existing {
        if digest != evidence.result_digest
            || result != encoded_result
            || revision != encoded_revision
            || artifacts != encoded_artifacts
            || verification != encoded_verification
        {
            bail!("finalization replay changed immutable evidence")
        }
        tx.commit()?;
        return Ok(id);
    }
    let finalization_id = format!(
        "fin_{}",
        URL_SAFE_NO_PAD.encode(&Sha256::digest(run_id.as_bytes())[..16])
    );
    tx.execute("INSERT INTO session_finalizations
        (finalization_id,run_id,session_id,placement_id,generation,node_id,result_digest,result_json,revision_json,artifacts_json,verification_json,state,created_at)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'provisional',?12)",
        params![finalization_id,run_id,session_id,placement_id,i64::try_from(generation)?,node_id,evidence.result_digest,encoded_result,encoded_revision,encoded_artifacts,encoded_verification,current_timestamp()])?;
    tx.commit()?;
    Ok(finalization_id)
}

pub fn ack_finalization(
    coven_home: &Path,
    finalization_id: &str,
    idempotency_key: &str,
) -> Result<()> {
    if idempotency_key.is_empty() {
        bail!("finalization key is required")
    }
    let mut conn = open(coven_home)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: (String, String, i64, String, String, Option<String>, String) = tx
        .query_row(
            "SELECT session_id,placement_id,generation,node_id,state,idempotency_key,revision_json
         FROM session_finalizations WHERE finalization_id=?1",
            params![finalization_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .context("finalization was not found")?;
    if row.4 == "committed" {
        if row.5.as_deref() == Some(idempotency_key) {
            tx.commit()?;
            return Ok(());
        }
        bail!("finalization was acknowledged with another key")
    }
    let now = current_timestamp();
    let authoritative: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_lifecycles l JOIN session_placements p ON p.placement_id=l.finalizing_placement_id
         WHERE l.session_id=?1 AND l.logical_state='open' AND l.active_generation=?3
         AND l.finalizing_placement_id=?2 AND p.generation=?3 AND p.node_id=?4 AND p.state='finalizing')",
        params![row.0,row.1,row.2,row.3],
        |query| query.get(0),
    )?;
    if !authoritative {
        bail!("finalization acknowledgment is stale")
    }
    let changed = tx.execute(
        "UPDATE session_finalizations SET state='committed',idempotency_key=?2,committed_at=?3
         WHERE finalization_id=?1 AND state='provisional'",
        params![finalization_id, idempotency_key, now],
    )?;
    if changed != 1 {
        bail!("finalization acknowledgment lost authority")
    }
    let changed = tx.execute(
        "UPDATE session_lifecycles SET committed_revision_json=?2,updated_at=?3,finalizing_placement_id=NULL
         WHERE session_id=?1 AND logical_state='open' AND active_generation=?4 AND finalizing_placement_id=?5",
        params![row.0,row.6,now,row.2,row.1],
    )?;
    if changed != 1 {
        bail!("finalization acknowledgment lost lifecycle authority")
    }
    let changed = tx.execute(
        "UPDATE session_placements SET state='released',released_at=?2
         WHERE placement_id=?1 AND state='finalizing'",
        params![row.1, now],
    )?;
    if changed != 1 {
        bail!("finalization acknowledgment lost placement authority")
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<(tempfile::TempDir, String)> {
        let home = tempfile::tempdir()?;
        let conn = store::open_store(&home.path().join(STORE_FILE_NAME))?;
        let now = current_timestamp();
        store::insert_session(
            &conn,
            &store::SessionRecord {
                id: "session-1".into(),
                project_root: "/workspace".into(),
                harness: "fake".into(),
                title: "session".into(),
                status: "idle".into(),
                exit_code: None,
                archived_at: None,
                created_at: now.clone(),
                updated_at: now,
                conversation_id: None,
                familiar_id: None,
                labels: vec![],
                visibility: "private".into(),
                external: false,
                transcript_path: None,
            },
        )?;
        Ok((home, "session-1".into()))
    }

    fn roam_record(session_id: &str, source: &str, target: &str) -> RoamRecord {
        let now = current_timestamp();
        RoamRecord {
            protocol_version: ROAM_PROTOCOL_VERSION.into(),
            session_id: session_id.into(),
            generation: 0,
            state: RoamState::Preparing,
            source_node_id: source.into(),
            target_node_id: Some(target.into()),
            source_harness: "fake".into(),
            target_harness: "fake".into(),
            workspace: WorkspaceRef {
                driver: "filesystem".into(),
                locator: serde_json::json!({}),
            },
            handoff_event_id: None,
            checkpoint_ref: None,
            dispatch_job_id: None,
            error: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[test]
    fn legacy_active_roam_migrates_once_into_authoritative_placement() -> Result<()> {
        let (home, session) = fixture()?;
        let conn = open(home.path())?;
        let now = current_timestamp();
        let record = RoamRecord {
            protocol_version: ROAM_PROTOCOL_VERSION.into(),
            session_id: session.clone(),
            generation: 4,
            state: RoamState::Active,
            source_node_id: "node-a".into(),
            target_node_id: Some("node-b".into()),
            source_harness: "fake".into(),
            target_harness: "fake".into(),
            workspace: WorkspaceRef {
                driver: "filesystem".into(),
                locator: serde_json::json!({"root":"workspace"}),
            },
            handoff_event_id: None,
            checkpoint_ref: None,
            dispatch_job_id: None,
            error: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        conn.execute(
            "INSERT INTO session_roams(session_id,generation,state,record_json,updated_at)
             VALUES (?1,?2,'active',?3,?4)",
            params![session, 4_i64, serde_json::to_string(&record)?, now],
        )?;
        drop(conn);

        for _ in 0..2 {
            let mut conn = open(home.path())?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_migrated_tx(&tx, &session)?;
            tx.commit()?;
        }

        let active = active_placement(home.path(), &session)?.context("active placement")?;
        assert_eq!(active.generation, 4);
        assert_eq!(active.node_id, "node-b");
        let conn = open(home.path())?;
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM session_placements WHERE session_id=?1",
                params![session],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        assert!(store::update_session_status(
            &conn,
            &session,
            "completed",
            Some(0),
            &current_timestamp()
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn legacy_inflight_roam_reconstructs_fenced_source_and_pending_target() -> Result<()> {
        let (home, session) = fixture()?;
        let conn = open(home.path())?;
        let now = current_timestamp();
        let mut record = roam_record(&session, "node-a", "node-b");
        record.generation = 4;
        record.state = RoamState::Restoring;
        record.checkpoint_ref = Some(serde_json::json!({"digest":"sha256:abc"}));
        conn.execute(
            "INSERT INTO session_roams(session_id,generation,state,record_json,updated_at)
             VALUES (?1,4,'restoring',?2,?3)",
            params![session, serde_json::to_string(&record)?, now],
        )?;
        drop(conn);

        assert!(matches!(
            queue_input(home.path(), &session, &serde_json::json!({"data":"wait"}))?,
            InputDisposition::Queued { sequence: 1, .. }
        ));
        let conn = open(home.path())?;
        let row: (i64, Option<String>, Option<i64>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT active_generation,active_placement_id,pending_generation,pending_placement_id,fenced_placement_id
                 FROM session_lifecycles WHERE session_id=?1",
                params![session],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
            )?;
        assert_eq!(row.0, 3);
        assert!(row.1.is_none());
        assert_eq!(row.2, Some(4));
        assert_eq!(row.3.as_deref(), Some("plc_legacy_session-1_4"));
        assert_eq!(row.4.as_deref(), Some("plc_legacy_session-1_3"));
        drop(conn);

        advance_roam(
            home.path(),
            &session,
            RoamAdvance {
                generation: 4,
                node_id: "node-b".into(),
                state: RoamState::Starting,
                checkpoint_ref: None,
                dispatch_job_id: None,
                error: None,
            },
        )?;
        advance_roam(
            home.path(),
            &session,
            RoamAdvance {
                generation: 4,
                node_id: "node-b".into(),
                state: RoamState::Active,
                checkpoint_ref: None,
                dispatch_job_id: None,
                error: None,
            },
        )?;
        let active = active_placement(home.path(), &session)?.context("active placement")?;
        assert_eq!(active.generation, 4);
        assert_eq!(active.node_id, "node-b");
        Ok(())
    }

    #[test]
    fn transfer_fences_old_output_and_only_one_placement_activates() -> Result<()> {
        let (home, session) = fixture()?;
        let first = begin_transfer(
            home.path(),
            &session,
            "node-a",
            "actor-a",
            &serde_json::json!({}),
        )?;
        activate_placement(
            home.path(),
            &session,
            &first.placement_id,
            first.generation,
            "node-a",
        )?;
        accept_output(
            home.path(),
            &session,
            &first.placement_id,
            first.generation,
            "node-a",
        )?;
        let second = begin_transfer(
            home.path(),
            &session,
            "node-b",
            "actor-b",
            &serde_json::json!({}),
        )?;
        accept_output(
            home.path(),
            &session,
            &first.placement_id,
            first.generation,
            "node-a",
        )?;
        activate_placement(
            home.path(),
            &session,
            &second.placement_id,
            second.generation,
            "node-b",
        )?;
        assert!(accept_output(
            home.path(),
            &session,
            &first.placement_id,
            first.generation,
            "node-a"
        )
        .is_err());
        assert!(activate_placement(
            home.path(),
            &session,
            &second.placement_id,
            second.generation,
            "node-b"
        )
        .is_err());
        accept_output(
            home.path(),
            &session,
            &second.placement_id,
            second.generation,
            "node-b",
        )?;
        Ok(())
    }

    #[test]
    fn failed_transfer_compensates_pending_target_and_preserves_recovery_source() -> Result<()> {
        let (home, session) = fixture()?;
        let source = begin_transfer(
            home.path(),
            &session,
            "node-a",
            "actor-a",
            &serde_json::json!({}),
        )?;
        let source = activate_placement(
            home.path(),
            &session,
            &source.placement_id,
            source.generation,
            "node-a",
        )?;

        let first =
            begin_roam_transfer(home.path(), roam_record(&session, "node-a", "node-b"), None)?;
        advance_roam(
            home.path(),
            &session,
            RoamAdvance {
                generation: first.generation,
                node_id: "node-b".into(),
                state: RoamState::Failed,
                checkpoint_ref: None,
                dispatch_job_id: None,
                error: Some("prepare failed".into()),
            },
        )?;
        assert_eq!(
            active_placement(home.path(), &session)?,
            Some(source.clone())
        );

        let second =
            begin_roam_transfer(home.path(), roam_record(&session, "node-a", "node-b"), None)?;
        advance_roam(
            home.path(),
            &session,
            RoamAdvance {
                generation: second.generation,
                node_id: "node-a".into(),
                state: RoamState::Checkpointed,
                checkpoint_ref: Some(serde_json::json!({"digest":"sha256:abc"})),
                dispatch_job_id: None,
                error: None,
            },
        )?;
        advance_roam(
            home.path(),
            &session,
            RoamAdvance {
                generation: second.generation,
                node_id: "node-b".into(),
                state: RoamState::Failed,
                checkpoint_ref: None,
                dispatch_job_id: None,
                error: Some("restore failed".into()),
            },
        )?;
        assert_eq!(
            active_placement(home.path(), &session)?,
            Some(source.clone())
        );
        let retry =
            begin_roam_transfer(home.path(), roam_record(&session, "node-a", "node-c"), None)?;
        assert!(retry.generation > second.generation);
        let conn = open(home.path())?;
        let pointers: (Option<String>, Option<String>) = conn.query_row(
            "SELECT fenced_placement_id,finalizing_placement_id FROM session_lifecycles WHERE session_id=?1",
            params![session],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert!(pointers.0.is_none());
        assert!(pointers.1.is_none());
        Ok(())
    }

    #[test]
    fn rejected_roam_reservation_does_not_orphan_handoff_event() -> Result<()> {
        let (home, session) = fixture()?;
        begin_transfer(
            home.path(),
            &session,
            "node-b",
            "actor-b",
            &serde_json::json!({}),
        )?;
        assert!(begin_roam_transfer(
            home.path(),
            roam_record(&session, "node-a", "node-c"),
            Some("continue")
        )
        .is_err());
        let conn = open(home.path())?;
        assert!(store::list_events(&conn, &session)?
            .into_iter()
            .all(|event| event.kind != "handoff"));
        Ok(())
    }

    #[test]
    fn cutover_inputs_are_durable_and_ordered() -> Result<()> {
        let (home, session) = fixture()?;
        let source = begin_transfer(
            home.path(),
            &session,
            "node-a",
            "actor-a",
            &serde_json::json!({}),
        )?;
        activate_placement(
            home.path(),
            &session,
            &source.placement_id,
            source.generation,
            "node-a",
        )?;
        let placement = begin_transfer(
            home.path(),
            &session,
            "node-b",
            "actor-b",
            &serde_json::json!({}),
        )?;
        for value in ["one", "two", "three"] {
            assert!(matches!(
                queue_or_route_input(home.path(), &session, &serde_json::json!({"data":value}))?,
                InputDisposition::Queued { .. }
            ));
        }
        let queued = queued_inputs(home.path(), &session)?;
        assert_eq!(
            queued.iter().map(|row| row.0).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(queued[2].1["data"], "three");
        activate_placement(
            home.path(),
            &session,
            &placement.placement_id,
            placement.generation,
            "node-b",
        )?;
        for expected in ["one", "two", "three"] {
            let delivery = claim_next_input(home.path(), &session, &placement)?
                .context("queued input was not claimed")?;
            assert_eq!(delivery.payload["data"], expected);
            ack_input_delivery(home.path(), &session, &delivery.input_id, &placement)?;
        }
        assert!(claim_next_input(home.path(), &session, &placement)?.is_none());
        let conn = open(home.path())?;
        let inputs = store::list_events(&conn, &session)?
            .into_iter()
            .filter(|event| event.kind == "input")
            .collect::<Vec<_>>();
        assert_eq!(inputs.len(), 3);
        assert_eq!(
            serde_json::from_str::<Value>(&inputs[2].payload_json)?["data"],
            "three"
        );
        Ok(())
    }

    #[test]
    fn oldest_unacknowledged_input_replays_before_later_sequences() -> Result<()> {
        let (home, session) = fixture()?;
        let placement = begin_transfer(
            home.path(),
            &session,
            "node-b",
            "actor-b",
            &serde_json::json!({}),
        )?;
        for value in ["one", "two"] {
            assert!(matches!(
                queue_or_route_input(home.path(), &session, &serde_json::json!({"data":value}))?,
                InputDisposition::Queued { .. }
            ));
        }
        activate_placement(
            home.path(),
            &session,
            &placement.placement_id,
            placement.generation,
            "node-b",
        )?;
        let first = claim_next_input(home.path(), &session, &placement)?.context("first input")?;
        assert_eq!(first.sequence, 1);

        // Every call reopens the durable store. A lost ACK therefore replays
        // the same delivery key instead of allowing sequence two to overtake.
        let replay = claim_next_input(home.path(), &session, &placement)?.context("replay")?;
        assert_eq!(replay.input_id, first.input_id);
        assert_eq!(replay.sequence, 1);
        ack_input_delivery(home.path(), &session, &replay.input_id, &placement)?;
        let second =
            claim_next_input(home.path(), &session, &placement)?.context("second input")?;
        assert_eq!(second.sequence, 2);
        Ok(())
    }

    #[test]
    fn process_exit_keeps_logical_session_open_until_finalization_ack_releases() -> Result<()> {
        let (home, session) = fixture()?;
        let placement = begin_transfer(
            home.path(),
            &session,
            "node-b",
            "actor-b",
            &serde_json::json!({}),
        )?;
        activate_placement(
            home.path(),
            &session,
            &placement.placement_id,
            placement.generation,
            "node-b",
        )?;
        let run = begin_run(
            home.path(),
            &session,
            &placement.placement_id,
            placement.generation,
            "node-b",
        )?;
        append_output(
            home.path(),
            &session,
            &run,
            &placement.placement_id,
            placement.generation,
            "node-b",
            &serde_json::json!({"data":"authorized"}),
        )?;
        record_run_exit(
            home.path(),
            &session,
            &run,
            RunExit {
                placement_id: &placement.placement_id,
                generation: placement.generation,
                node_id: "node-b",
                completion_key: "complete-1",
                exit_code: Some(0),
                result_ref: Some(&serde_json::json!({"ok":true})),
            },
        )?;
        record_run_exit(
            home.path(),
            &session,
            &run,
            RunExit {
                placement_id: &placement.placement_id,
                generation: placement.generation,
                node_id: "node-b",
                completion_key: "complete-1",
                exit_code: Some(0),
                result_ref: Some(&serde_json::json!({"ok":true})),
            },
        )?;
        assert!(record_run_exit(
            home.path(),
            &session,
            &run,
            RunExit {
                placement_id: &placement.placement_id,
                generation: placement.generation,
                node_id: "node-b",
                completion_key: "different",
                exit_code: Some(0),
                result_ref: Some(&serde_json::json!({"ok":true}))
            }
        )
        .is_err());
        assert!(append_output(
            home.path(),
            &session,
            &run,
            &placement.placement_id,
            placement.generation,
            "node-b",
            &serde_json::json!({"data":"stale"}),
        )
        .is_err());
        let conn = open(home.path())?;
        assert_eq!(
            conn.query_row(
                "SELECT logical_state FROM session_lifecycles WHERE session_id=?1",
                params![session],
                |row| row.get::<_, String>(0)
            )?,
            "open"
        );
        assert_eq!(
            conn.query_row(
                "SELECT state FROM session_placements WHERE placement_id=?1",
                params![placement.placement_id],
                |row| row.get::<_, String>(0)
            )?,
            "finalizing"
        );
        drop(conn);
        let mut evidence = FinalizationEvidence {
            result_digest: String::new(),
            result: serde_json::json!({"ok":true}),
            revision: serde_json::json!({"head":"abc"}),
            artifacts: serde_json::json!([]),
            verification: serde_json::json!([{"status":"passed"}]),
        };
        evidence.result_digest = finalization_digest(&evidence)?;
        let finalization = stage_finalization(
            home.path(),
            &session,
            &run,
            &placement.placement_id,
            placement.generation,
            "node-b",
            &evidence,
        )?;
        assert_eq!(
            stage_finalization(
                home.path(),
                &session,
                &run,
                &placement.placement_id,
                placement.generation,
                "node-b",
                &evidence
            )?,
            finalization
        );
        let mut changed = evidence.clone();
        changed.result = serde_json::json!({"ok":false});
        changed.result_digest = finalization_digest(&changed)?;
        assert!(stage_finalization(
            home.path(),
            &session,
            &run,
            &placement.placement_id,
            placement.generation,
            "node-b",
            &changed
        )
        .is_err());
        assert!(begin_transfer(
            home.path(),
            &session,
            "node-c",
            "actor-c",
            &serde_json::json!({})
        )
        .is_err());
        assert_eq!(
            open(home.path())?.query_row(
                "SELECT state FROM session_placements WHERE placement_id=?1",
                params![placement.placement_id],
                |row| row.get::<_, String>(0)
            )?,
            "finalizing"
        );
        ack_finalization(home.path(), &finalization, "ack-1")?;
        ack_finalization(home.path(), &finalization, "ack-1")?;
        assert!(ack_finalization(home.path(), &finalization, "ack-2").is_err());
        let conn = open(home.path())?;
        assert_eq!(
            conn.query_row(
                "SELECT state FROM session_placements WHERE placement_id=?1",
                params![placement.placement_id],
                |row| row.get::<_, String>(0)
            )?,
            "released"
        );
        assert_eq!(
            conn.query_row(
                "SELECT logical_state FROM session_lifecycles WHERE session_id=?1",
                params![session],
                |row| row.get::<_, String>(0)
            )?,
            "open"
        );
        Ok(())
    }
}
