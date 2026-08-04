use serde::Deserialize;
use serde_json::json;

pub use crate::session_authority::{RoamRecord, RoamState, WorkspaceRef, ROAM_PROTOCOL_VERSION};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartRoamRequest {
    source_node_id: String,
    #[serde(default)]
    target_node_id: Option<String>,
    target_harness: String,
    workspace: WorkspaceRef,
    #[serde(default)]
    next_action: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AutomaticRoamRequest {
    #[serde(default)]
    target_node_id: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgressRoamRequest {
    generation: u64,
    node_id: String,
    state: RoamState,
    #[serde(default)]
    checkpoint_ref: Option<serde_json::Value>,
    #[serde(default)]
    dispatch_job_id: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn select_target(
    conn: &rusqlite::Connection,
    source_node_id: &str,
    target_harness: &str,
    driver: &str,
) -> anyhow::Result<Option<String>> {
    let required = [
        "session-turn".to_string(),
        format!("runtime:{target_harness}"),
        format!("workspace:{driver}"),
    ];
    let mut matches: Vec<_> = crate::store::list_nodes(conn)?
        .into_iter()
        .filter(|node| node.available && node.node_id != source_node_id)
        .filter(|node| {
            let capabilities: Vec<String> =
                serde_json::from_str(&node.capabilities_json).unwrap_or_default();
            required
                .iter()
                .all(|required| capabilities.contains(required))
        })
        .collect();
    matches.sort_by(|left, right| {
        left.queue_pressure
            .cmp(&right.queue_pressure)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    Ok(matches.into_iter().next().map(|node| node.node_id))
}

pub fn start(
    coven_home: &std::path::Path,
    session_id: &str,
    body: Option<&str>,
) -> anyhow::Result<crate::api::ApiResponse> {
    let request: StartRoamRequest = match body.and_then(|raw| serde_json::from_str(raw).ok()) {
        Some(request) => request,
        None => {
            return crate::api::api_error(
                400,
                "invalid_request",
                "A valid roam request is required.",
                None,
            )
        }
    };
    if request.source_node_id.trim().is_empty()
        || request.target_harness.trim().is_empty()
        || request.workspace.driver.trim().is_empty()
    {
        return crate::api::api_error(
            400,
            "invalid_request",
            "sourceNodeId, targetHarness, and workspace.driver are required.",
            None,
        );
    }
    let conn = crate::store::open_store(&coven_home.join(crate::STORE_FILE_NAME))?;
    let Some(session) = crate::store::get_session(&conn, session_id)? else {
        return crate::api::api_error(
            404,
            "session_not_found",
            "Session was not found.",
            Some(json!({ "sessionId": session_id })),
        );
    };
    let turn_in_progress = if crate::session_authority::is_managed(coven_home, session_id)? {
        crate::session_authority::has_live_run(coven_home, session_id)?
    } else {
        session.status == "running"
    };
    if turn_in_progress {
        return crate::api::api_error(
            409,
            "turn_in_progress",
            "Finish or cancel the active turn before roaming.",
            None,
        );
    }
    if let Some(active) = crate::session_authority::active_placement(coven_home, session_id)? {
        if request.source_node_id != active.node_id {
            return crate::api::api_error(
                409,
                "wrong_executor",
                "sourceNodeId does not match the active placement.",
                None,
            );
        }
    }
    let target_node_id = match request
        .target_node_id
        .filter(|value| !value.trim().is_empty())
    {
        Some(node) => Some(node),
        None => select_target(
            &conn,
            &request.source_node_id,
            &request.target_harness,
            &request.workspace.driver,
        )?,
    };
    let Some(target_node_id) = target_node_id else {
        return crate::api::api_error(
            409,
            "no_compatible_executor",
            "No available executor satisfies the roam capabilities.",
            None,
        );
    };
    let now = crate::api::current_timestamp();
    drop(conn);
    let record = RoamRecord {
        protocol_version: ROAM_PROTOCOL_VERSION.into(),
        session_id: session_id.into(),
        generation: 0,
        state: RoamState::Preparing,
        source_node_id: request.source_node_id,
        target_node_id: Some(target_node_id),
        source_harness: session.harness,
        target_harness: request.target_harness,
        workspace: request.workspace,
        handoff_event_id: None,
        checkpoint_ref: None,
        dispatch_job_id: None,
        error: None,
        created_at: now.clone(),
        updated_at: now,
    };
    let record =
        match crate::session_roam::start(coven_home, record, request.next_action.as_deref()) {
            Ok(record) => record,
            Err(error) => {
                return crate::api::api_error(409, "roam_conflict", &error.to_string(), None)
            }
        };
    crate::api::json_response(202, &record)
}

pub fn start_automatic(
    coven_home: &std::path::Path,
    session_id: &str,
    body: Option<&str>,
) -> anyhow::Result<crate::api::ApiResponse> {
    let request: AutomaticRoamRequest = match body.and_then(|raw| serde_json::from_str(raw).ok()) {
        Some(request) => request,
        None => {
            return crate::api::api_error(
                400,
                "invalid_request",
                "A valid automatic roam request is required.",
                None,
            )
        }
    };
    if request
        .target_node_id
        .as_deref()
        .is_some_and(|node| node.trim().is_empty())
    {
        return crate::api::api_error(
            400,
            "invalid_request",
            "targetNodeId must not be empty.",
            None,
        );
    }
    let conn = crate::store::open_store(&coven_home.join(crate::STORE_FILE_NAME))?;
    let Some(session) = crate::store::get_session(&conn, session_id)? else {
        return crate::api::api_error(404, "session_not_found", "Session was not found.", None);
    };
    drop(conn);
    if !crate::session_authority::is_managed(coven_home, session_id)? {
        return crate::api::api_error(
            409,
            "session_unmanaged",
            "Session has no managed active placement.",
            None,
        );
    }
    if crate::session_authority::has_live_run(coven_home, session_id)? {
        return crate::api::api_error(
            409,
            "turn_in_progress",
            "Finish or cancel the active turn before roaming.",
            None,
        );
    }
    let Some(active) = crate::session_authority::active_placement_context(coven_home, session_id)?
    else {
        return crate::api::api_error(
            409,
            "no_active_placement",
            "Session has no authoritative active placement.",
            None,
        );
    };
    let required = vec![
        format!("runtime:{}", session.harness),
        format!("workspace:{}", active.workspace.driver),
        "protocol:workspace-driver:1".into(),
        "protocol:harness-host:1".into(),
    ];
    let target = crate::fleet::select_node_for_requirements(
        coven_home,
        &required,
        &active.placement.node_id,
        request.target_node_id.as_deref(),
    )?;
    let Some(target_node_id) = target else {
        return crate::api::api_error(
            409,
            "no_compatible_executor",
            "No fresh executor satisfies the session requirements.",
            None,
        );
    };
    let now = crate::api::current_timestamp();
    let record = RoamRecord {
        protocol_version: ROAM_PROTOCOL_VERSION.into(),
        session_id: session_id.into(),
        generation: 0,
        state: RoamState::Preparing,
        source_node_id: active.placement.node_id,
        target_node_id: Some(target_node_id),
        source_harness: session.harness.clone(),
        target_harness: session.harness,
        workspace: active.workspace,
        handoff_event_id: None,
        checkpoint_ref: None,
        dispatch_job_id: None,
        error: None,
        created_at: now.clone(),
        updated_at: now,
    };
    match crate::session_roam::start(coven_home, record, None) {
        Ok(record) => crate::api::json_response(202, &record),
        Err(error) => crate::api::api_error(409, "roam_conflict", &error.to_string(), None),
    }
}

#[cfg(test)]
pub fn progress(
    coven_home: &std::path::Path,
    session_id: &str,
    body: Option<&str>,
) -> anyhow::Result<crate::api::ApiResponse> {
    let request: ProgressRoamRequest = match body.and_then(|raw| serde_json::from_str(raw).ok()) {
        Some(request) => request,
        None => {
            return crate::api::api_error(
                400,
                "invalid_request",
                "A valid roam progress request is required.",
                None,
            )
        }
    };
    let record = match crate::session_authority::advance_roam(
        coven_home,
        session_id,
        crate::session_authority::RoamAdvance {
            generation: request.generation,
            node_id: request.node_id,
            state: request.state,
            checkpoint_ref: request.checkpoint_ref,
            dispatch_job_id: request.dispatch_job_id,
            error: request.error,
        },
    ) {
        Ok(record) => record,
        Err(error) => {
            let code = match error.to_string().as_str() {
                "stale_generation" => "stale_generation",
                "invalid_roam_transition" => "invalid_roam_transition",
                "wrong_executor" => "wrong_executor",
                _ => "roam_conflict",
            };
            return crate::api::api_error(409, code, &error.to_string(), None);
        }
    };
    crate::api::json_response(200, &record)
}

pub fn get(
    coven_home: &std::path::Path,
    session_id: &str,
) -> anyhow::Result<crate::api::ApiResponse> {
    let conn = crate::store::open_store(&coven_home.join(crate::STORE_FILE_NAME))?;
    match crate::store::get_roam(&conn, session_id)? {
        Some(record) => crate::api::json_response(200, &record),
        None => crate::api::api_error(
            404,
            "roam_not_found",
            "No roam exists for this session.",
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    fn enroll_fleet_node(home: &std::path::Path, node_id: &str) -> anyhow::Result<()> {
        let issued = crate::fleet::issue_enrollment(home, Some("{}"))?;
        let issued: serde_json::Value = serde_json::from_str(&issued.body)?;
        let capabilities = serde_json::json!({
            "protocols":{"executor":[1],"workspaceDriver":[1],"harnessHost":[1]},
            "platform":{"os":"linux","architecture":"x86_64"},
            "resources":{"cpuCores":8,"memoryBytes":16000000000_u64},
            "harnesses":["claude"],"workspaceDrivers":["filesystem"],"tools":["shell"]
        });
        let redeemed = crate::fleet::redeem_enrollment(
            home,
            Some(&serde_json::json!({"enrollmentCode":issued["enrollmentCode"],"nodeId":node_id,"capabilities":capabilities}).to_string()),
        )?;
        anyhow::ensure!(redeemed.status == 201, "node enrollment failed");
        Ok(())
    }

    fn automatic_fixture() -> anyhow::Result<tempfile::TempDir> {
        let home = tempfile::tempdir()?;
        let conn = crate::store::open_store(&home.path().join(crate::STORE_FILE_NAME))?;
        let now = crate::api::current_timestamp();
        crate::store::insert_session(&conn, &session(&now))?;
        drop(conn);
        let workspace = WorkspaceRef {
            driver: "filesystem".into(),
            locator: serde_json::json!({"privateObject":"checkpoint-source"}),
        };
        let source = crate::session_authority::begin_transfer(
            home.path(),
            "s1",
            "source-node",
            "source-actor",
            &serde_json::to_value(workspace)?,
        )?;
        crate::session_authority::activate_placement(
            home.path(),
            "s1",
            &source.placement_id,
            source.generation,
            "source-node",
        )?;
        enroll_fleet_node(home.path(), "target-a")?;
        enroll_fleet_node(home.path(), "target-b")?;
        Ok(home)
    }

    fn session(now: &str) -> crate::store::SessionRecord {
        crate::store::SessionRecord {
            id: "s1".into(),
            project_root: "/workspace".into(),
            harness: "claude".into(),
            title: "Portable work".into(),
            status: "completed".into(),
            exit_code: Some(0),
            archived_at: None,
            created_at: now.into(),
            updated_at: now.into(),
            conversation_id: None,
            familiar_id: None,
            labels: vec![],
            visibility: "private".into(),
            external: false,
            transcript_path: None,
        }
    }

    fn node(id: &str, pressure: i64, now: &str) -> crate::store::NodeRecord {
        crate::store::NodeRecord {
            node_id: id.into(),
            role: "compute_executor".into(),
            transport: "ssh".into(),
            transport_config_json: None,
            capabilities_json: serde_json::json!([
                "session-turn",
                "runtime:codex",
                "workspace:filesystem"
            ])
            .to_string(),
            available: true,
            queue_pressure: pressure,
            last_health_at: now.into(),
            last_error: None,
            registered_at: now.into(),
            updated_at: now.into(),
        }
    }

    #[test]
    fn state_machine_is_fail_closed() {
        assert!(RoamState::Preparing.can_transition_to(RoamState::Checkpointed));
        assert!(RoamState::Starting.can_transition_to(RoamState::Active));
        assert!(!RoamState::Preparing.can_transition_to(RoamState::Active));
        assert!(!RoamState::Active.can_transition_to(RoamState::Preparing));
    }

    #[test]
    fn active_generation_fences_stale_source_results() {
        let record = RoamRecord {
            protocol_version: ROAM_PROTOCOL_VERSION.into(),
            session_id: "s1".into(),
            generation: 2,
            state: RoamState::Active,
            source_node_id: "a".into(),
            target_node_id: Some("b".into()),
            source_harness: "claude".into(),
            target_harness: "codex".into(),
            workspace: WorkspaceRef {
                driver: "fake".into(),
                locator: serde_json::json!({}),
            },
            handoff_event_id: None,
            checkpoint_ref: None,
            dispatch_job_id: None,
            error: None,
            created_at: "now".into(),
            updated_at: "now".into(),
        };
        assert!(record.accepts_result(2, "b"));
        assert!(!record.accepts_result(1, "a"));
        assert!(!record.accepts_result(2, "a"));
    }

    #[test]
    fn deterministic_a_to_b_transfer_selects_target_and_rejects_stale_a() -> anyhow::Result<()> {
        let home = tempfile::tempdir()?;
        let conn = crate::store::open_store(&home.path().join(crate::STORE_FILE_NAME))?;
        let now = crate::api::current_timestamp();
        crate::store::insert_session(&conn, &session(&now))?;
        crate::store::upsert_node(&conn, &node("b-slow", 4, &now))?;
        crate::store::upsert_node(&conn, &node("b-fast", 0, &now))?;
        drop(conn);
        let source = crate::session_authority::begin_transfer(
            home.path(),
            "s1",
            "a",
            "actor-a",
            &serde_json::json!({}),
        )?;
        crate::session_authority::activate_placement(
            home.path(),
            "s1",
            &source.placement_id,
            source.generation,
            "a",
        )?;

        let started = start(
            home.path(),
            "s1",
            Some(
                &serde_json::json!({
                    "sourceNodeId": "a",
                    "targetHarness": "codex",
                    "workspace": { "driver": "filesystem", "locator": { "archivePath": "/checkpoint" } }
                })
                .to_string(),
            ),
        )?;
        assert_eq!(started.status, 202);
        let started: serde_json::Value = serde_json::from_str(&started.body)?;
        assert_eq!(started["targetNodeId"], "b-fast");
        assert_eq!(started["generation"], 2);

        for (state, node_id) in [
            ("checkpointed", "a"),
            ("restoring", "b-fast"),
            ("starting", "b-fast"),
            ("active", "b-fast"),
        ] {
            let result = progress(
                home.path(),
                "s1",
                Some(
                    &serde_json::json!({
                        "generation": 2,
                        "nodeId": node_id,
                        "state": state,
                        "checkpointRef": (state == "checkpointed").then(|| serde_json::json!({ "sha256": "abc" }))
                    })
                    .to_string(),
                ),
            )?;
            assert_eq!(result.status, 200, "transition to {state}: {}", result.body);
        }

        let stale = progress(
            home.path(),
            "s1",
            Some(r#"{"generation":1,"nodeId":"a","state":"failed"}"#),
        )?;
        assert_eq!(stale.status, 409);
        assert!(stale.body.contains("stale_generation"));
        Ok(())
    }

    #[test]
    fn automatic_roam_derives_private_authority_and_honors_explicit_target() -> anyhow::Result<()> {
        let home = automatic_fixture()?;
        let response = start_automatic(home.path(), "s1", Some(r#"{"targetNodeId":"target-b"}"#))?;
        assert_eq!(response.status, 202, "{}", response.body);
        let record: serde_json::Value = serde_json::from_str(&response.body)?;
        assert_eq!(record["sourceNodeId"], "source-node");
        assert_eq!(record["targetNodeId"], "target-b");
        assert_eq!(record["sourceHarness"], "claude");
        assert_eq!(record["targetHarness"], "claude");
        assert_eq!(record["workspace"]["driver"], "filesystem");
        assert_eq!(
            record["workspace"]["locator"]["privateObject"],
            "checkpoint-source"
        );
        Ok(())
    }

    #[test]
    fn automatic_roam_uses_deterministic_scheduler_and_rejects_unknown_input() -> anyhow::Result<()>
    {
        let home = automatic_fixture()?;
        let rejected = start_automatic(home.path(), "s1", Some(r#"{"projectRoot":"/leak"}"#))?;
        assert_eq!(rejected.status, 400);
        let conn = crate::store::open_store(&home.path().join(crate::STORE_FILE_NAME))?;
        assert!(crate::store::get_roam(&conn, "s1")?.is_none());
        drop(conn);
        let response = start_automatic(home.path(), "s1", Some("{}"))?;
        assert_eq!(response.status, 202, "{}", response.body);
        let record: serde_json::Value = serde_json::from_str(&response.body)?;
        assert_eq!(record["targetNodeId"], "target-a");
        Ok(())
    }

    #[test]
    fn automatic_roam_rejections_are_stable_and_do_not_mutate() -> anyhow::Result<()> {
        let unmanaged = tempfile::tempdir()?;
        let conn = crate::store::open_store(&unmanaged.path().join(crate::STORE_FILE_NAME))?;
        let now = crate::api::current_timestamp();
        crate::store::insert_session(&conn, &session(&now))?;
        drop(conn);
        let response = start_automatic(unmanaged.path(), "s1", Some("{}"))?;
        assert_eq!(response.status, 409);
        assert!(response.body.contains("session_unmanaged"));
        let conn = crate::store::open_store(&unmanaged.path().join(crate::STORE_FILE_NAME))?;
        assert!(crate::store::get_roam(&conn, "s1")?.is_none());
        drop(conn);

        let busy = automatic_fixture()?;
        let active = crate::session_authority::active_placement(busy.path(), "s1")?
            .context("fixture omitted active placement")?;
        crate::session_authority::begin_run(
            busy.path(),
            "s1",
            &active.placement_id,
            active.generation,
            &active.node_id,
        )?;
        let response = start_automatic(busy.path(), "s1", Some("{}"))?;
        assert_eq!(response.status, 409);
        assert!(response.body.contains("turn_in_progress"));
        let conn = crate::store::open_store(&busy.path().join(crate::STORE_FILE_NAME))?;
        assert!(crate::store::get_roam(&conn, "s1")?.is_none());
        drop(conn);

        let incompatible = automatic_fixture()?;
        let conn = crate::store::open_store(&incompatible.path().join(crate::STORE_FILE_NAME))?;
        conn.execute(
            "UPDATE node_registry SET revoked_at=?1,available=0 WHERE node_id IN ('target-a','target-b')",
            [crate::api::current_timestamp()],
        )?;
        drop(conn);
        let response = start_automatic(incompatible.path(), "s1", Some("{}"))?;
        assert_eq!(response.status, 409);
        assert!(response.body.contains("no_compatible_executor"));
        let conn = crate::store::open_store(&incompatible.path().join(crate::STORE_FILE_NAME))?;
        assert!(crate::store::get_roam(&conn, "s1")?.is_none());
        Ok(())
    }
}
