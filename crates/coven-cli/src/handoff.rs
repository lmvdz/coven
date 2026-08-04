use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

pub const HANDOFF_SCHEMA: &str = "coven.handoff.v1";
pub const MAX_HANDOFF_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffTrigger {
    HarnessInitiated,
    UserInitiated,
    DaemonFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffEndpoint {
    pub harness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskContext {
    pub original_goal: String,
    #[serde(default)]
    pub constraints: Vec<String>,
    #[serde(default)]
    pub scope_notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentState {
    pub last_action: String,
    #[serde(default)]
    pub loaded_context_summary: String,
    #[serde(default)]
    pub open_questions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTouched {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_file_artifact_id: Option<String>,
    #[serde(default)]
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffRisk {
    pub kind: String,
    pub detail: String,
    #[serde(default)]
    pub blocking_for_next_step: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationBlock {
    #[serde(default)]
    pub latest_verdicts: Vec<serde_json::Value>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextAction {
    pub instruction: String,
    #[serde(default)]
    pub do_not_do: Vec<String>,
    #[serde(default)]
    pub expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffMeta {
    pub session_id: String,
    pub created_at: i64,
    #[serde(default = "default_redaction_version")]
    pub redaction_version: u32,
}

const fn default_redaction_version() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffPacketV1 {
    pub schema: String,
    pub trigger: HandoffTrigger,
    pub from: HandoffEndpoint,
    pub to: HandoffEndpoint,
    pub task_context: TaskContext,
    pub current_state: CurrentState,
    #[serde(default)]
    pub files_touched: Vec<FileTouched>,
    #[serde(default)]
    pub risks: Vec<HandoffRisk>,
    pub verification: VerificationBlock,
    pub next_action: NextAction,
    pub meta: HandoffMeta,
}

impl HandoffPacketV1 {
    pub fn validate(&self, expected_session_id: &str) -> Result<(), &'static str> {
        if self.schema != HANDOFF_SCHEMA {
            return Err("schema");
        }
        if self.meta.session_id != expected_session_id {
            return Err("meta.session_id");
        }
        for (field, value) in [
            ("from.harness", self.from.harness.as_str()),
            ("to.harness", self.to.harness.as_str()),
            (
                "task_context.original_goal",
                self.task_context.original_goal.as_str(),
            ),
            (
                "current_state.last_action",
                self.current_state.last_action.as_str(),
            ),
            (
                "next_action.instruction",
                self.next_action.instruction.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(field);
            }
        }
        if self.risks.iter().any(|risk| risk.detail.trim().is_empty()) {
            return Err("risks[].detail");
        }
        Ok(())
    }
}

pub fn emit(
    coven_home: &std::path::Path,
    session_id: &str,
    body: Option<&str>,
) -> anyhow::Result<crate::api::ApiResponse> {
    let Some(raw) = body else {
        return crate::api::api_error(
            400,
            "invalid_request",
            "A handoff packet is required.",
            None,
        );
    };
    if raw.len() > MAX_HANDOFF_BYTES {
        return crate::api::api_error(
            413,
            "too_large",
            "Handoff packet exceeds 64 KiB.",
            Some(json!({ "limitBytes": MAX_HANDOFF_BYTES })),
        );
    }
    let packet: HandoffPacketV1 = match serde_json::from_str(raw) {
        Ok(packet) => packet,
        Err(error) => {
            return crate::api::api_error(400, "invalid_request", &error.to_string(), None)
        }
    };
    if let Err(field) = packet.validate(session_id) {
        return crate::api::api_error(
            400,
            "invalid_handoff",
            "Handoff packet validation failed.",
            Some(json!({ "field": field })),
        );
    }
    let conn = crate::store::open_store(&coven_home.join(crate::STORE_FILE_NAME))?;
    if crate::store::get_session(&conn, session_id)?.is_none() {
        return crate::api::api_error(
            404,
            "session_not_found",
            "Session was not found.",
            Some(json!({ "sessionId": session_id })),
        );
    }
    let event_id = format!("evt_{}", Uuid::new_v4());
    let created_at = crate::api::current_timestamp();
    crate::store::insert_event_with_privacy(
        &conn,
        coven_home,
        &crate::store::EventRecord {
            seq: 0,
            id: event_id.clone(),
            session_id: session_id.to_string(),
            kind: "handoff".to_string(),
            payload_json: serde_json::to_string(&packet)?,
            created_at,
        },
    )?;
    let stored = crate::store::list_events(&conn, session_id)?
        .into_iter()
        .find(|event| event.id == event_id)
        .and_then(|event| serde_json::from_str::<serde_json::Value>(&event.payload_json).ok())
        .unwrap_or(serde_json::Value::Null);
    crate::api::json_response(201, &json!({ "eventId": event_id, "packet": stored }))
}

pub fn list(
    coven_home: &std::path::Path,
    session_id: &str,
    latest: bool,
) -> anyhow::Result<crate::api::ApiResponse> {
    let conn = crate::store::open_store(&coven_home.join(crate::STORE_FILE_NAME))?;
    if crate::store::get_session(&conn, session_id)?.is_none() {
        return crate::api::api_error(
            404,
            "session_not_found",
            "Session was not found.",
            Some(json!({ "sessionId": session_id })),
        );
    }
    let mut packets: Vec<serde_json::Value> = crate::store::list_events(&conn, session_id)?
        .into_iter()
        .filter(|event| event.kind == "handoff")
        .filter_map(|event| serde_json::from_str(&event.payload_json).ok())
        .collect();
    if latest && packets.len() > 1 {
        packets.drain(..packets.len() - 1);
    }
    crate::api::json_response(200, &json!({ "handoffs": packets }))
}

pub fn ensure_for_roam(
    conn: &rusqlite::Connection,
    coven_home: &std::path::Path,
    session: &crate::store::SessionRecord,
    target_harness: &str,
    next_instruction: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(existing) = crate::store::list_events(conn, &session.id)?
        .into_iter()
        .rev()
        .find(|event| event.kind == "handoff")
    {
        return Ok(existing.id);
    }
    let packet = HandoffPacketV1 {
        schema: HANDOFF_SCHEMA.into(),
        trigger: HandoffTrigger::DaemonFallback,
        from: HandoffEndpoint {
            harness: session.harness.clone(),
            run_id: session.conversation_id.clone(),
            ended_at: None,
            hint: None,
        },
        to: HandoffEndpoint {
            harness: target_harness.into(),
            run_id: None,
            ended_at: None,
            hint: Some("portable executor transfer".into()),
        },
        task_context: TaskContext {
            original_goal: session.title.clone(),
            constraints: vec!["Continue within the declared workspace and Coven session.".into()],
            scope_notes: String::new(),
        },
        current_state: CurrentState {
            last_action: format!(
                "The prior {} turn ended with status {}.",
                session.harness, session.status
            ),
            loaded_context_summary: "Review the session ledger and workspace before editing."
                .into(),
            open_questions: vec![],
        },
        files_touched: vec![],
        risks: vec![],
        verification: VerificationBlock {
            latest_verdicts: vec![],
            stale: true,
            notes: "No portable verification artifact was supplied at handoff.".into(),
        },
        next_action: NextAction {
            instruction: next_instruction
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("Inspect the workspace and continue the original goal.")
                .into(),
            do_not_do: vec![
                "Do not reuse credentials or native session tokens from the source executor."
                    .into(),
            ],
            expected_outcome: "Continue safely on the target executor.".into(),
        },
        meta: HandoffMeta {
            session_id: session.id.clone(),
            created_at: chrono::Utc::now().timestamp(),
            redaction_version: 1,
        },
    };
    packet.validate(&session.id).map_err(anyhow::Error::msg)?;
    let event_id = format!("evt_{}", Uuid::new_v4());
    crate::store::insert_event_with_privacy(
        conn,
        coven_home,
        &crate::store::EventRecord {
            seq: 0,
            id: event_id.clone(),
            session_id: session.id.clone(),
            kind: "handoff".into(),
            payload_json: serde_json::to_string(&packet)?,
            created_at: crate::api::current_timestamp(),
        },
    )?;
    Ok(event_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> HandoffPacketV1 {
        HandoffPacketV1 {
            schema: HANDOFF_SCHEMA.into(),
            trigger: HandoffTrigger::UserInitiated,
            from: HandoffEndpoint {
                harness: "claude".into(),
                run_id: None,
                ended_at: None,
                hint: None,
            },
            to: HandoffEndpoint {
                harness: "codex".into(),
                run_id: None,
                ended_at: None,
                hint: None,
            },
            task_context: TaskContext {
                original_goal: "Continue the migration".into(),
                constraints: vec![],
                scope_notes: String::new(),
            },
            current_state: CurrentState {
                last_action: "Added the schema".into(),
                loaded_context_summary: String::new(),
                open_questions: vec![],
            },
            files_touched: vec![],
            risks: vec![],
            verification: VerificationBlock {
                latest_verdicts: vec![],
                stale: false,
                notes: String::new(),
            },
            next_action: NextAction {
                instruction: "Implement the reader".into(),
                do_not_do: vec![],
                expected_outcome: String::new(),
            },
            meta: HandoffMeta {
                session_id: "session-1".into(),
                created_at: 1,
                redaction_version: 1,
            },
        }
    }

    #[test]
    fn round_trips_and_validates() {
        let original = packet();
        original.validate("session-1").unwrap();
        let encoded = serde_json::to_string(&original).unwrap();
        assert_eq!(
            serde_json::from_str::<HandoffPacketV1>(&encoded).unwrap(),
            original
        );
    }

    #[test]
    fn rejects_wrong_session_and_empty_required_fields() {
        assert_eq!(packet().validate("session-2"), Err("meta.session_id"));
        let mut invalid = packet();
        invalid.next_action.instruction.clear();
        assert_eq!(
            invalid.validate("session-1"),
            Err("next_action.instruction")
        );
    }
}
